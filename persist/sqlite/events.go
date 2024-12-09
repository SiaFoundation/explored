package sqlite

import (
	"database/sql"
	"errors"
	"fmt"
	"reflect"

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

func explorerToTypesV2Resolution(e explorer.V2FileContractResolution) (fcr types.V2FileContractResolution) {
	fcr.Parent = e.Parent.V2FileContractElement

	switch v := e.Resolution.(type) {
	case *explorer.V2FileContractRenewal:
		fcr.Resolution = &types.V2FileContractRenewal{
			FinalRenterOutput: v.FinalRenterOutput,
			FinalHostOutput:   v.FinalHostOutput,
			RenterRollover:    v.RenterRollover,
			HostRollover:      v.HostRollover,
			NewContract:       v.NewContract.V2FileContractElement.V2FileContract,
			RenterSignature:   v.RenterSignature,
			HostSignature:     v.HostSignature,
		}
	case *types.V2StorageProof:
		fcr.Resolution = v
	case *types.V2FileContractExpiration:
		fcr.Resolution = v
	default:
		panic(fmt.Errorf("unexpected revision type: %v", reflect.TypeOf(v)))
	}
	return
}

func explorerToEventV1Transaction(e explorer.Transaction) (ev wallet.EventV1Transaction) {
	extendedFCToTypes := func(fc explorer.ExtendedFileContract) types.FileContract {
		result := types.FileContract{
			Filesize:       fc.Filesize,
			FileMerkleRoot: fc.FileMerkleRoot,
			WindowStart:    fc.WindowStart,
			WindowEnd:      fc.WindowEnd,
			Payout:         fc.Payout,
			UnlockHash:     fc.UnlockHash,
			RevisionNumber: fc.RevisionNumber,
		}
		for _, vpo := range fc.ValidProofOutputs {
			result.ValidProofOutputs = append(result.ValidProofOutputs, vpo.SiacoinOutput)
		}
		for _, mpo := range fc.MissedProofOutputs {
			result.MissedProofOutputs = append(result.MissedProofOutputs, mpo.SiacoinOutput)
		}
		return result
	}

	txn := &ev.Transaction
	for _, sci := range e.SiacoinInputs {
		txn.SiacoinInputs = append(txn.SiacoinInputs, sci.SiacoinInput)
	}
	for _, sco := range e.SiacoinOutputs {
		txn.SiacoinOutputs = append(txn.SiacoinOutputs, sco.SiacoinOutput)
	}
	for _, sfi := range e.SiafundInputs {
		txn.SiafundInputs = append(txn.SiafundInputs, sfi.SiafundInput)
	}
	for _, sfo := range e.SiafundOutputs {
		txn.SiafundOutputs = append(txn.SiafundOutputs, sfo.SiafundOutput)
	}
	for _, fc := range e.FileContracts {
		txn.FileContracts = append(txn.FileContracts, extendedFCToTypes(fc))
	}
	for _, fcr := range e.FileContractRevisions {
		txn.FileContractRevisions = append(txn.FileContractRevisions, types.FileContractRevision{
			ParentID:         fcr.ParentID,
			UnlockConditions: fcr.UnlockConditions,
			FileContract:     extendedFCToTypes(fcr.ExtendedFileContract),
		})
	}
	for _, sp := range e.StorageProofs {
		txn.StorageProofs = append(txn.StorageProofs, sp)
	}
	for _, fee := range e.MinerFees {
		txn.MinerFees = append(txn.MinerFees, fee)
	}
	for _, arb := range e.ArbitraryData {
		txn.ArbitraryData = append(txn.ArbitraryData, arb)
	}
	for _, sig := range e.Signatures {
		txn.Signatures = append(txn.Signatures, sig)
	}

	return
}

func explorerToEventV2Transaction(e explorer.V2Transaction) (txn wallet.EventV2Transaction) {
	for _, sci := range e.SiacoinInputs {
		txn.SiacoinInputs = append(txn.SiacoinInputs, sci)
	}
	for _, sco := range e.SiacoinOutputs {
		txn.SiacoinOutputs = append(txn.SiacoinOutputs, sco.SiacoinOutput)
	}
	for _, sfi := range e.SiafundInputs {
		txn.SiafundInputs = append(txn.SiafundInputs, sfi)
	}
	for _, sfo := range e.SiafundOutputs {
		txn.SiafundOutputs = append(txn.SiafundOutputs, sfo.SiafundOutput)
	}
	for _, fc := range e.FileContracts {
		txn.FileContracts = append(txn.FileContracts, fc.V2FileContractElement.V2FileContract)
	}
	for _, fcr := range e.FileContractRevisions {
		txn.FileContractRevisions = append(txn.FileContractRevisions, types.V2FileContractRevision{
			Parent:   fcr.Parent.V2FileContractElement,
			Revision: fcr.Revision.V2FileContractElement.V2FileContract,
		})
	}
	for _, fcr := range e.FileContractResolutions {
		txn.FileContractResolutions = append(txn.FileContractResolutions, explorerToTypesV2Resolution(fcr))
	}
	for _, a := range e.Attestations {
		txn.Attestations = append(txn.Attestations, a)
	}
	for _, arb := range e.ArbitraryData {
		txn.ArbitraryData = append(txn.ArbitraryData, arb)
	}
	txn.NewFoundationAddress = e.NewFoundationAddress
	txn.MinerFee = e.MinerFee

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
		ev.Data = explorerToEventV1Transaction(txns[0])
	case wallet.EventTypeV2Transaction:
		txns, err := getV2Transactions(tx, []types.TransactionID{types.TransactionID(ev.ID)})
		if err != nil || len(txns) == 0 {
			return explorer.Event{}, 0, fmt.Errorf("failed to fetch v2 transaction: %w", err)
		}
		ev.Data = explorerToEventV2Transaction(txns[0])
	case wallet.EventTypeV1ContractResolution:
		var resolution wallet.EventV1ContractResolution
		fce, sce := &resolution.Parent, &resolution.SiacoinElement
		err := tx.QueryRow(`SELECT sce.output_id, sce.leaf_index, sce.maturity_height, sce.address, sce.value, fce.contract_id, fce.leaf_index, fce.filesize, fce.file_merkle_root, fce.window_start, fce.window_end, fce.payout, fce.unlock_hash, fce.revision_number, ev.missed
			FROM v1_contract_resolution_events ev
			JOIN siacoin_elements sce ON ev.output_id = sce.id
			JOIN file_contract_elements fce ON ev.parent_id = fce.id
			WHERE ev.event_id = ?`, eventID).Scan(decode(&sce.ID), decode(&sce.StateElement.LeafIndex), decode(&sce.MaturityHeight), decode(&sce.SiacoinOutput.Address), decode(&sce.SiacoinOutput.Value), decode(&fce.ID), decode(&fce.StateElement.LeafIndex), decode(&fce.FileContract.Filesize), decode(&fce.FileContract.FileMerkleRoot), decode(&fce.FileContract.WindowStart), decode(&fce.FileContract.WindowEnd), decode(&fce.FileContract.Payout), decode(&fce.FileContract.UnlockHash), decode(&fce.FileContract.RevisionNumber), &resolution.Missed)
		if err != nil {
			return wallet.Event{}, 0, fmt.Errorf("failed to retrieve v1 resolution event: %w", err)
		}
		ev.Data = resolution
	case wallet.EventTypeV2ContractResolution:
		var resolution wallet.EventV2ContractResolution
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
			return wallet.Event{}, 0, fmt.Errorf("failed to retrieve v2 resolution event: %w", err)
		}

		resolutionTxns, err := getV2Transactions(tx, []types.TransactionID{resolutionTransactionID})
		if err != nil {
			return wallet.Event{}, 0, fmt.Errorf("failed to get transaction with v2 resolution: %w", err)
		} else if len(resolutionTxns) == 0 {
			return wallet.Event{}, 0, fmt.Errorf("v2 resolution transaction not found")
		}
		txn := resolutionTxns[0]

		found := false
		for _, fcr := range txn.FileContractResolutions {
			if fcr.Parent.ID == parentContractID {
				found = true
				resolution.Resolution = explorerToTypesV2Resolution(fcr)
				break
			}
		}
		if !found {
			return wallet.Event{}, 0, fmt.Errorf("failed to find resolution in v2 resolution transaction")
		}

		ev.Data = resolution
	case wallet.EventTypeSiafundClaim, wallet.EventTypeMinerPayout, wallet.EventTypeFoundationSubsidy:
		var payout wallet.EventPayout
		sce := &payout.SiacoinElement
		err := tx.QueryRow(`SELECT sce.output_id, sce.leaf_index, sce.maturity_height, sce.address, sce.value
			FROM payout_events ev
			JOIN siacoin_elements sce ON ev.output_id = sce.id
			WHERE ev.event_id = ?`, eventID).Scan(decode(&sce.ID), decode(&sce.StateElement.LeafIndex), decode(&sce.MaturityHeight), decode(&sce.SiacoinOutput.Address), decode(&sce.SiacoinOutput.Value))
		if err != nil {
			return wallet.Event{}, 0, fmt.Errorf("failed to retrieve payout event: %w", err)
		}
		ev.Data = payout
	default:
		return wallet.Event{}, 0, fmt.Errorf("unknown event type: %q", ev.Type)
	}

	return
}
