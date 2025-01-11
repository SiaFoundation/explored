package sqlite

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/wallet"
	"go.sia.tech/explored/explorer"
)

// Events returns the events with the given event IDs. If an event is not found,
// it is skipped.
func (s *Store) Events(eventIDs []types.Hash256) (events []explorer.Event, err error) {
	err = s.transaction(func(tx *txn) error {
		// sqlite doesn't have easy support for IN clauses, use a statement since
		// the number of event IDs is likely to be small instead of dynamically
		// building the query
		const query = `
WITH last_chain_index (height) AS (
    SELECT MAX(height) FROM blocks
)
SELECT 
	ev.id, 
	ev.event_id, 
	ev.maturity_height, 
	ev.date_created, 
	b.height, 
	b.id, 
	CASE 
		WHEN last_chain_index.height < b.height THEN 0
		ELSE last_chain_index.height - b.height
	END AS confirmations,
	ev.event_type
FROM events ev
INNER JOIN event_addresses ea ON (ev.id = ea.event_id)
INNER JOIN address_balance sa ON (ea.address_id = sa.id)
INNER JOIN blocks b ON (ev.block_id = b.id)
CROSS JOIN last_chain_index
WHERE ev.event_id = $1`

		stmt, err := tx.Prepare(query)
		if err != nil {
			return fmt.Errorf("failed to prepare statement: %w", err)
		}
		defer stmt.Close()

		events = make([]explorer.Event, 0, len(eventIDs))
		for _, id := range eventIDs {
			event, _, err := scanEvent(tx, stmt.QueryRow(encode(id)))
			if errors.Is(err, sql.ErrNoRows) {
				continue
			} else if err != nil {
				return fmt.Errorf("failed to query transaction %q: %w", id, err)
			}
			events = append(events, event)
		}
		return nil
	})
	return
}

func scanEvent(tx *txn, s scanner) (ev explorer.Event, eventID int64, err error) {
	err = s.Scan(&eventID, decode(&ev.ID), &ev.MaturityHeight, decode(&ev.Timestamp), &ev.Index.Height, decode(&ev.Index.ID), &ev.Confirmations, &ev.Type)
	if err != nil {
		return
	}

	switch ev.Type {
	case wallet.EventTypeV1Transaction:
		var txnID int64
		err = tx.QueryRow(`SELECT transaction_id FROM v1_transaction_events WHERE event_id = ?`, eventID).Scan(&txnID)
		if err != nil {
			return explorer.Event{}, 0, fmt.Errorf("failed to fetch v1 transaction ID: %w", err)
		}
		txns, err := getTransactions(tx, map[int64]transactionID{0: {dbID: txnID, id: types.TransactionID(ev.ID)}})
		if err != nil || len(txns) == 0 {
			return explorer.Event{}, 0, fmt.Errorf("failed to fetch v1 transaction: %w", err)
		}
		ev.Data = explorer.EventV1Transaction{
			Transaction: txns[0],
		}
	case wallet.EventTypeV2Transaction:
		txns, err := getV2Transactions(tx, []types.TransactionID{types.TransactionID(ev.ID)})
		if err != nil || len(txns) == 0 {
			return explorer.Event{}, 0, fmt.Errorf("failed to fetch v2 transaction: %w", err)
		}
		ev.Data = explorer.EventV2Transaction(txns[0])
	case wallet.EventTypeV1ContractResolution:
		var resolution explorer.EventV1ContractResolution
		fce, sce := &resolution.Parent, &resolution.SiacoinElement
		err := tx.QueryRow(`SELECT sce.output_id, sce.leaf_index, sce.maturity_height, sce.address, sce.value, fce.contract_id, fce.filesize, fce.file_merkle_root, fce.window_start, fce.window_end, fce.payout, fce.unlock_hash, fce.revision_number, ev.missed
			FROM v1_contract_resolution_events ev
			JOIN siacoin_elements sce ON ev.output_id = sce.id
			JOIN file_contract_elements fce ON ev.parent_id = fce.id
			WHERE ev.event_id = ?`, eventID).Scan(decode(&sce.ID), decode(&sce.StateElement.LeafIndex), decode(&sce.MaturityHeight), decode(&sce.SiacoinOutput.Address), decode(&sce.SiacoinOutput.Value), decode(&fce.ID), decode(&fce.Filesize), decode(&fce.FileMerkleRoot), decode(&fce.WindowStart), decode(&fce.WindowEnd), decode(&fce.Payout), decode(&fce.UnlockHash), decode(&fce.RevisionNumber), &resolution.Missed)
		if err != nil {
			return explorer.Event{}, 0, fmt.Errorf("failed to retrieve v1 resolution event: %w", err)
		}
		ev.Data = resolution
	case wallet.EventTypeV2ContractResolution:
		var resolution explorer.EventV2ContractResolution
		var parentContractID types.FileContractID
		var resolutionTransactionID types.TransactionID
		sce := &resolution.SiacoinElement
		err := tx.QueryRow(`SELECT sce.output_id, sce.leaf_index, sce.maturity_height, sce.address, sce.value, rev.contract_id, rev.resolution_transaction_id, ev.missed
			FROM v2_contract_resolution_events ev
			JOIN siacoin_elements sce ON ev.output_id = sce.id
			JOIN v2_file_contract_elements fce ON ev.parent_id = fce.id
 			JOIN v2_last_contract_revision rev ON fce.contract_id = rev.contract_id
			WHERE ev.event_id = ?`, eventID).Scan(decode(&sce.ID), decode(&sce.StateElement.LeafIndex), decode(&sce.MaturityHeight), decode(&sce.SiacoinOutput.Address), decode(&sce.SiacoinOutput.Value), decode(&parentContractID), decode(&resolutionTransactionID), &resolution.Missed)
		if err != nil {
			return explorer.Event{}, 0, fmt.Errorf("failed to retrieve v2 resolution event: %w", err)
		}

		resolutionTxns, err := getV2Transactions(tx, []types.TransactionID{resolutionTransactionID})
		if err != nil {
			return explorer.Event{}, 0, fmt.Errorf("failed to get transaction with v2 resolution: %w", err)
		} else if len(resolutionTxns) == 0 {
			return explorer.Event{}, 0, fmt.Errorf("v2 resolution transaction not found")
		}
		txn := resolutionTxns[0]

		found := false
		for _, fcr := range txn.FileContractResolutions {
			if fcr.Parent.ID == parentContractID {
				found = true
				resolution.Resolution = fcr
				break
			}
		}
		if !found {
			return explorer.Event{}, 0, fmt.Errorf("failed to find resolution in v2 resolution transaction")
		}

		ev.Data = resolution
	case wallet.EventTypeSiafundClaim, wallet.EventTypeMinerPayout, wallet.EventTypeFoundationSubsidy:
		var payout explorer.EventPayout
		sce := &payout.SiacoinElement
		err := tx.QueryRow(`SELECT sce.output_id, sce.leaf_index, sce.maturity_height, sce.address, sce.value
			FROM payout_events ev
			JOIN siacoin_elements sce ON ev.output_id = sce.id
			WHERE ev.event_id = ?`, eventID).Scan(decode(&sce.ID), decode(&sce.StateElement.LeafIndex), decode(&sce.MaturityHeight), decode(&sce.SiacoinOutput.Address), decode(&sce.SiacoinOutput.Value))
		if err != nil {
			return explorer.Event{}, 0, fmt.Errorf("failed to retrieve payout event: %w", err)
		}
		ev.Data = payout
	default:
		return explorer.Event{}, 0, fmt.Errorf("unknown event type: %q", ev.Type)
	}

	return
}

// UnconfirmedEvents annotates a list of unconfirmed transactions.
func (s *Store) UnconfirmedEvents(index types.ChainIndex, timestamp time.Time, v1 []types.Transaction, v2 []types.V2Transaction) (events []explorer.Event, err error) {
	addEvent := func(id types.Hash256, maturityHeight uint64, eventType string, v explorer.EventData, relevant []types.Address) {
		// dedup relevant addresses
		seen := make(map[types.Address]bool)
		unique := relevant[:0]
		for _, addr := range relevant {
			if !seen[addr] {
				unique = append(unique, addr)
				seen[addr] = true
			}
		}

		events = append(events, explorer.Event{
			ID:             id,
			Timestamp:      timestamp,
			Index:          index,
			MaturityHeight: maturityHeight,
			Relevant:       unique,
			Type:           eventType,
			Data:           v,
		})
	}

	var scIDs []types.SiacoinOutputID
	for _, txn := range v1 {
		for _, sci := range txn.SiacoinInputs {
			scIDs = append(scIDs, sci.ParentID)
		}
	}
	sces, err := s.SiacoinElements(scIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve sces: %w", err)
	}
	sceCache := make(map[types.SiacoinOutputID]explorer.SiacoinOutput)
	for _, sce := range sces {
		sceCache[sce.ID] = sce
	}

	var sfIDs []types.SiafundOutputID
	for _, txn := range v1 {
		for _, sfi := range txn.SiafundInputs {
			sfIDs = append(sfIDs, sfi.ParentID)
		}
	}
	sfes, err := s.SiafundElements(sfIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve sfes: %w", err)
	}

	sfeCache := make(map[types.SiafundOutputID]explorer.SiafundOutput)
	for _, sfe := range sfes {
		sfeCache[sfe.ID] = sfe
	}

	for _, txn := range v1 {
		id := txn.ID()
		evTxn := explorer.CoreToExplorerV1Transaction(txn)
		for i := range evTxn.SiacoinInputs {
			sci := &evTxn.SiacoinInputs[i]
			sce, ok := sceCache[sci.ParentID]
			if !ok {
				// We could have an ephemeral output, which SiacoinElements
				// won't return because it hasn't been in a block yet.  In
				// which case this is not erroneous, and we should just leave
				// these details unfilled.
				continue
			}
			sci.Address = sce.SiacoinElement.SiacoinOutput.Address
			sci.Value = sce.SiacoinElement.SiacoinOutput.Value
		}
		for i := range evTxn.SiafundInputs {
			sfi := &evTxn.SiafundInputs[i]
			sfe, ok := sfeCache[sfi.ParentID]
			if !ok {
				// We could have an ephemeral output, which SiacoinElements
				// won't return because it hasn't been in a block yet.  In
				// which case this is not erroneous, and we should just leave
				// these details unfilled.
				continue
			}
			sfi.Address = sfe.SiafundElement.SiafundOutput.Address
			sfi.Value = sfe.SiafundElement.SiafundOutput.Value
		}
		for i := range evTxn.FileContracts {
			fc := &evTxn.FileContracts[i]
			fc.ConfirmationIndex = index
			fc.ConfirmationTransactionID = id
		}
		for i := range evTxn.FileContractRevisions {
			fcr := &evTxn.FileContractRevisions[i]
			fcr.ExtendedFileContract.ConfirmationIndex = index
			fcr.ExtendedFileContract.ConfirmationTransactionID = id
		}
		relevant := explorer.RelevantAddressesV1(txn)
		ev := explorer.EventV1Transaction{Transaction: evTxn}
		addEvent(types.Hash256(txn.ID()), index.Height, wallet.EventTypeV1Transaction, ev, relevant) // transaction maturity height is the current block height
	}

	// handle v2 transactions
	for _, txn := range v2 {
		id := txn.ID()
		evTxn := explorer.CoreToExplorerV2Transaction(txn)
		for i := range evTxn.FileContracts {
			fc := &evTxn.FileContracts[i]
			fc.ConfirmationIndex = index
			fc.ConfirmationTransactionID = id
		}
		for i := range evTxn.FileContractRevisions {
			fcr := &evTxn.FileContractRevisions[i]
			fcr.Revision.ConfirmationIndex = index
			fcr.Revision.ConfirmationTransactionID = id
		}

		relevant := explorer.RelevantAddressesV2(txn)
		ev := explorer.EventV2Transaction(evTxn)
		addEvent(types.Hash256(txn.ID()), index.Height, wallet.EventTypeV2Transaction, ev, relevant) // transaction maturity height is the current block height
	}

	return
}
