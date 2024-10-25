package sqlite

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/chain"
	"go.sia.tech/explored/explorer"
)

type updateTx struct {
	tx *txn
}

func addBlock(tx *txn, b types.Block, height uint64) error {
	// nonce is encoded because database/sql doesn't support uint64 with high bit set
	var v2Height any
	var v2Commitment any
	if b.V2 != nil {
		v2Height = encode(b.V2.Height)
		v2Commitment = encode(b.V2.Commitment)
	}
	_, err := tx.Exec("INSERT INTO blocks(id, height, parent_id, nonce, timestamp, v2_height, v2_commitment) VALUES (?, ?, ?, ?, ?, ?, ?);", encode(b.ID()), height, encode(b.ParentID), encode(b.Nonce), encode(b.Timestamp), v2Height, v2Commitment)
	return err
}

func addMinerPayouts(tx *txn, bid types.BlockID, scos []types.SiacoinOutput, dbIDs map[types.SiacoinOutputID]int64) error {
	stmt, err := tx.Prepare(`INSERT INTO miner_payouts(block_id, block_order, output_id) VALUES (?, ?, ?);`)
	if err != nil {
		return fmt.Errorf("addMinerPayouts: failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for i := range scos {
		dbID, ok := dbIDs[bid.MinerOutputID(i)]
		if !ok {
			return errors.New("addMinerPayouts: dbID not in map")
		}

		if _, err := stmt.Exec(encode(bid), i, dbID); err != nil {
			return fmt.Errorf("addMinerPayouts: failed to execute statement: %w", err)
		}
	}
	return nil
}

func addMinerFees(tx *txn, id int64, txn types.Transaction) error {
	stmt, err := tx.Prepare(`INSERT INTO transaction_miner_fees(transaction_id, transaction_order, fee) VALUES (?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addMinerFees: failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for i, fee := range txn.MinerFees {
		if _, err := stmt.Exec(id, i, encode(fee)); err != nil {
			return fmt.Errorf("addMinerFees: failed to execute statement: %w", err)
		}
	}
	return nil
}

func addArbitraryData(tx *txn, id int64, txn types.Transaction) error {
	stmt, err := tx.Prepare(`INSERT INTO transaction_arbitrary_data(transaction_id, transaction_order, data) VALUES (?, ?, ?)`)

	if err != nil {
		return fmt.Errorf("addArbitraryData: failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for i, arbitraryData := range txn.ArbitraryData {
		if _, err := stmt.Exec(id, i, arbitraryData); err != nil {
			return fmt.Errorf("addArbitraryData: failed to execute statement: %w", err)
		}
	}
	return nil
}

func addSignatures(tx *txn, id int64, txn types.Transaction) error {
	stmt, err := tx.Prepare(`INSERT INTO transaction_signatures(transaction_id, transaction_order, parent_id, public_key_index, timelock, covered_fields, signature) VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addMinerFees: failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for i, sig := range txn.Signatures {
		if _, err := stmt.Exec(id, i, encode(sig.ParentID), sig.PublicKeyIndex, encode(sig.Timelock), encode(sig.CoveredFields), sig.Signature); err != nil {
			return fmt.Errorf("addMinerFees: failed to execute statement: %w", err)
		}
	}
	return nil
}

func addSiacoinInputs(tx *txn, id int64, txn types.Transaction, dbIDs map[types.SiacoinOutputID]int64) error {
	stmt, err := tx.Prepare(`INSERT INTO transaction_siacoin_inputs(transaction_id, transaction_order, parent_id, unlock_conditions) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addSiacoinInputs: failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for i, sci := range txn.SiacoinInputs {
		dbID, ok := dbIDs[sci.ParentID]
		if !ok {
			return errors.New("addSiacoinOutputs: dbID not in map")
		}

		if _, err := stmt.Exec(id, i, dbID, encode(sci.UnlockConditions)); err != nil {
			return fmt.Errorf("addSiacoinInputs: failed to execute statement: %w", err)
		}
	}
	return nil
}

func addSiacoinOutputs(tx *txn, id int64, txn types.Transaction, dbIDs map[types.SiacoinOutputID]int64) error {
	stmt, err := tx.Prepare(`INSERT INTO transaction_siacoin_outputs(transaction_id, transaction_order, output_id) VALUES (?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addSiacoinOutputs: failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for i := range txn.SiacoinOutputs {
		dbID, ok := dbIDs[txn.SiacoinOutputID(i)]
		if !ok {
			return errors.New("addSiacoinOutputs: dbID not in map")
		}

		if _, err := stmt.Exec(id, i, dbID); err != nil {
			return fmt.Errorf("addSiacoinOutputs: failed to execute statement: %w", err)
		}
	}
	return nil
}

func addSiafundInputs(tx *txn, id int64, txn types.Transaction, dbIDs map[types.SiafundOutputID]int64) error {
	stmt, err := tx.Prepare(`INSERT INTO transaction_siafund_inputs(transaction_id, transaction_order, parent_id, unlock_conditions, claim_address) VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addSiafundInputs: failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for i, sfi := range txn.SiafundInputs {
		dbID, ok := dbIDs[sfi.ParentID]
		if !ok {
			return errors.New("addSiafundOutputs: dbID not in map")
		}

		if _, err := stmt.Exec(id, i, dbID, encode(sfi.UnlockConditions), encode(sfi.ClaimAddress)); err != nil {
			return fmt.Errorf("addSiafundInputs: failed to execute statement: %w", err)
		}
	}

	return nil
}

func addSiafundOutputs(tx *txn, id int64, txn types.Transaction, dbIDs map[types.SiafundOutputID]int64) error {
	stmt, err := tx.Prepare(`INSERT INTO transaction_siafund_outputs(transaction_id, transaction_order, output_id) VALUES (?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addSiafundOutputs: failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for i := range txn.SiafundOutputs {
		dbID, ok := dbIDs[txn.SiafundOutputID(i)]
		if !ok {
			return errors.New("addSiafundOutputs: dbID not in map")
		}

		if _, err := stmt.Exec(id, i, dbID); err != nil {
			return fmt.Errorf("addSiafundOutputs: failed to execute statement: %w", err)
		}
	}
	return nil
}

func addFileContracts(tx *txn, id int64, txn types.Transaction, fcDBIds map[explorer.DBFileContract]int64) error {
	stmt, err := tx.Prepare(`INSERT INTO transaction_file_contracts(transaction_id, transaction_order, contract_id) VALUES (?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addFileContracts: failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for i := range txn.FileContracts {
		dbID, ok := fcDBIds[explorer.DBFileContract{ID: txn.FileContractID(i), RevisionNumber: 0}]
		if !ok {
			return errors.New("addFileContracts: fcDbID not in map")
		}

		if _, err := stmt.Exec(id, i, dbID); err != nil {
			return fmt.Errorf("addFileContracts: failed to execute transaction_file_contracts statement: %w", err)
		}
	}
	return nil
}

func addFileContractRevisions(tx *txn, id int64, txn types.Transaction, dbIDs map[explorer.DBFileContract]int64) error {
	stmt, err := tx.Prepare(`INSERT INTO transaction_file_contract_revisions(transaction_id, transaction_order, contract_id, parent_id, unlock_conditions) VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addFileContractRevisions: failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for i := range txn.FileContractRevisions {
		fcr := &txn.FileContractRevisions[i]
		dbID, ok := dbIDs[explorer.DBFileContract{ID: fcr.ParentID, RevisionNumber: fcr.FileContract.RevisionNumber}]
		if !ok {
			return errors.New("addFileContractRevisions: dbID not in map")
		}

		if _, err := stmt.Exec(id, i, dbID, encode(fcr.ParentID), encode(fcr.UnlockConditions)); err != nil {
			return fmt.Errorf("addFileContractRevisions: failed to execute statement: %w", err)
		}
	}

	return nil
}

func addStorageProofs(tx *txn, id int64, txn types.Transaction) error {
	stmt, err := tx.Prepare(`INSERT INTO transaction_storage_proofs(transaction_id, transaction_order, parent_id, leaf, proof) VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addStorageProofs: failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for i, proof := range txn.StorageProofs {
		if _, err := stmt.Exec(id, i, encode(proof.ParentID), proof.Leaf[:], encode(proof.Proof)); err != nil {
			return fmt.Errorf("addStorageProofs: failed to execute statement: %w", err)
		}
	}
	return nil
}

type txnDBId struct {
	id    int64
	exist bool
}

func addTransactions(tx *txn, bid types.BlockID, txns []types.Transaction) (map[types.TransactionID]txnDBId, error) {
	checkTransactionStmt, err := tx.Prepare(`SELECT id FROM transactions WHERE transaction_id = ?`)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare check transaction statement: %v", err)
	}
	defer checkTransactionStmt.Close()

	insertTransactionStmt, err := tx.Prepare(`INSERT INTO transactions (transaction_id) VALUES (?)`)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare insert transaction statement: %v", err)
	}
	defer insertTransactionStmt.Close()

	blockTransactionsStmt, err := tx.Prepare(`INSERT INTO block_transactions(block_id, transaction_id, block_order) VALUES (?, ?, ?);`)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare block_transactions statement: %w", err)
	}
	defer blockTransactionsStmt.Close()

	txnDBIds := make(map[types.TransactionID]txnDBId)
	for i, txn := range txns {
		var exist bool
		var txnID int64
		if err := checkTransactionStmt.QueryRow(encode(txn.ID())).Scan(&txnID); err != nil && err != sql.ErrNoRows {
			return nil, fmt.Errorf("failed to insert transaction ID: %w", err)
		} else if err == nil {
			exist = true
		}

		if !exist {
			result, err := insertTransactionStmt.Exec(encode(txn.ID()))
			if err != nil {
				return nil, fmt.Errorf("failed to insert into transactions: %w", err)
			}
			txnID, err = result.LastInsertId()
			if err != nil {
				return nil, fmt.Errorf("failed to get transaction ID: %w", err)
			}
		}
		txnDBIds[txn.ID()] = txnDBId{id: txnID, exist: exist}

		if _, err := blockTransactionsStmt.Exec(encode(bid), txnID, i); err != nil {
			return nil, fmt.Errorf("failed to insert into block_transactions: %w", err)
		}
	}

	return txnDBIds, nil
}

func addTransactionFields(tx *txn, txns []types.Transaction, scDBIds map[types.SiacoinOutputID]int64, sfDBIds map[types.SiafundOutputID]int64, fcDBIds map[explorer.DBFileContract]int64, txnDBIds map[types.TransactionID]txnDBId) error {
	for _, txn := range txns {
		dbID, ok := txnDBIds[txn.ID()]
		if !ok {
			panic(fmt.Errorf("txn %v should be in txnDBIds", txn.ID()))
		}

		// transaction already exists, don't reinsert its fields
		if dbID.exist {
			continue
		}

		if err := addMinerFees(tx, dbID.id, txn); err != nil {
			return fmt.Errorf("failed to add miner fees: %w", err)
		} else if err := addArbitraryData(tx, dbID.id, txn); err != nil {
			return fmt.Errorf("failed to add arbitrary data: %w", err)
		} else if err := addSignatures(tx, dbID.id, txn); err != nil {
			return fmt.Errorf("failed to add signatures: %w", err)
		} else if err := addSiacoinInputs(tx, dbID.id, txn, scDBIds); err != nil {
			return fmt.Errorf("failed to add siacoin inputs: %w", err)
		} else if err := addSiacoinOutputs(tx, dbID.id, txn, scDBIds); err != nil {
			return fmt.Errorf("failed to add siacoin outputs: %w", err)
		} else if err := addSiafundInputs(tx, dbID.id, txn, sfDBIds); err != nil {
			return fmt.Errorf("failed to add siafund inputs: %w", err)
		} else if err := addSiafundOutputs(tx, dbID.id, txn, sfDBIds); err != nil {
			return fmt.Errorf("failed to add siafund outputs: %w", err)
		} else if err := addFileContracts(tx, dbID.id, txn, fcDBIds); err != nil {
			return fmt.Errorf("failed to add file contract: %w", err)
		} else if err := addFileContractRevisions(tx, dbID.id, txn, fcDBIds); err != nil {
			return fmt.Errorf("failed to add file contract revisions: %w", err)
		} else if err := addStorageProofs(tx, dbID.id, txn); err != nil {
			return fmt.Errorf("failed to add storage proofs: %w", err)
		}
	}

	return nil
}

type balance struct {
	sc         types.Currency
	immatureSC types.Currency
	sf         uint64
}

func updateBalances(tx *txn, height uint64, spentSiacoinElements, newSiacoinElements []explorer.SiacoinOutput, spentSiafundElements, newSiafundElements []types.SiafundElement) error {
	addresses := make(map[types.Address]balance)
	for _, sce := range spentSiacoinElements {
		addresses[sce.SiacoinOutput.Address] = balance{}
	}
	for _, sce := range newSiacoinElements {
		addresses[sce.SiacoinOutput.Address] = balance{}
	}
	for _, sfe := range spentSiafundElements {
		addresses[sfe.SiafundOutput.Address] = balance{}
	}
	for _, sfe := range newSiafundElements {
		addresses[sfe.SiafundOutput.Address] = balance{}
	}

	balanceRowsStmt, err := tx.Prepare(`SELECT siacoin_balance, immature_siacoin_balance, siafund_balance
        FROM address_balance
        WHERE address = ?`)
	if err != nil {
		return fmt.Errorf("updateBalances: failed to prepare address_balance statement: %w", err)
	}
	defer balanceRowsStmt.Close()

	for addr := range addresses {
		var bal balance
		if err := balanceRowsStmt.QueryRow(encode(addr)).Scan(decode(&bal.sc), decode(&bal.immatureSC), decode(&bal.sf)); err != nil && err != sql.ErrNoRows {
			return fmt.Errorf("updateBalances: failed to scan balance: %w", err)
		}
		addresses[addr] = bal
	}

	for _, sce := range newSiacoinElements {
		bal := addresses[sce.SiacoinOutput.Address]
		if sce.MaturityHeight <= height {
			bal.sc = bal.sc.Add(sce.SiacoinOutput.Value)
		} else {
			bal.immatureSC = bal.immatureSC.Add(sce.SiacoinOutput.Value)
		}
		addresses[sce.SiacoinOutput.Address] = bal
	}
	for _, sce := range spentSiacoinElements {
		bal := addresses[sce.SiacoinOutput.Address]
		if sce.MaturityHeight < height {
			bal.sc = bal.sc.Sub(sce.SiacoinOutput.Value)
		} else {
			bal.immatureSC = bal.immatureSC.Sub(sce.SiacoinOutput.Value)
		}
		addresses[sce.SiacoinOutput.Address] = bal
	}

	for _, sfe := range newSiafundElements {
		bal := addresses[sfe.SiafundOutput.Address]
		bal.sf += sfe.SiafundOutput.Value
		addresses[sfe.SiafundOutput.Address] = bal
	}
	for _, sfe := range spentSiafundElements {
		bal := addresses[sfe.SiafundOutput.Address]
		if bal.sf < sfe.SiafundOutput.Value {
			panic("sf underflow")
		}
		bal.sf -= sfe.SiafundOutput.Value
		addresses[sfe.SiafundOutput.Address] = bal
	}

	stmt, err := tx.Prepare(`INSERT INTO address_balance(address, siacoin_balance, immature_siacoin_balance, siafund_balance)
       VALUES (?, ?, ?, ?)
       ON CONFLICT(address)
       DO UPDATE set siacoin_balance = ?, immature_siacoin_balance = ?, siafund_balance = ?`)
	if err != nil {
		return fmt.Errorf("updateBalances: failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for addr, bal := range addresses {
		if _, err := stmt.Exec(encode(addr), encode(bal.sc), encode(bal.immatureSC), encode(bal.sf), encode(bal.sc), encode(bal.immatureSC), encode(bal.sf)); err != nil {
			return fmt.Errorf("updateBalances: failed to exec statement: %w", err)
		}
		// log.Println(addr, "=", bal.sc)
	}

	return nil
}

func updateMaturedBalances(tx *txn, revert bool, height uint64) error {
	// Prevent double counting - outputs with a maturity height of 0 are
	// handled in updateBalances
	if height == 0 {
		return nil
	}

	rows, err := tx.Query(`SELECT address, value
			FROM siacoin_elements
			WHERE maturity_height = ?`, height)
	if err != nil {
		return fmt.Errorf("updateMaturedBalances: failed to query siacoin_elements: %w", err)
	}
	defer rows.Close()

	var scos []types.SiacoinOutput
	addressList := make(map[types.Address]struct{})
	for rows.Next() {
		var sco types.SiacoinOutput
		if err := rows.Scan(decode(&sco.Address), decode(&sco.Value)); err != nil {
			return fmt.Errorf("updateMaturedBalances: failed to scan maturing outputs: %w", err)
		}
		scos = append(scos, sco)
		addressList[sco.Address] = struct{}{}
	}

	balanceRowsStmt, err := tx.Prepare(`SELECT siacoin_balance, immature_siacoin_balance
		FROM address_balance
		WHERE address = ?`)
	if err != nil {
		return fmt.Errorf("updateMaturedBalances: failed to prepare address_balance statement: %w", err)
	}
	defer balanceRowsStmt.Close()

	addresses := make(map[types.Address]balance)
	for addr := range addressList {
		var bal balance
		if err := balanceRowsStmt.QueryRow(encode(addr)).Scan(decode(&bal.sc), decode(&bal.immatureSC)); err != nil {
			return fmt.Errorf("updateMaturedBalances: failed to scan balance: %w", err)
		}
		addresses[addr] = bal
	}

	// If the update is an apply update then we add the amounts.
	// If we are reverting then we subtract them.
	for _, sco := range scos {
		bal := addresses[sco.Address]
		if revert {
			bal.sc = bal.sc.Sub(sco.Value)
			bal.immatureSC = bal.immatureSC.Add(sco.Value)
		} else {
			bal.sc = bal.sc.Add(sco.Value)
			bal.immatureSC = bal.immatureSC.Sub(sco.Value)
		}
		addresses[sco.Address] = bal
	}

	stmt, err := tx.Prepare(`INSERT INTO address_balance(address, siacoin_balance, immature_siacoin_balance, siafund_balance)
	VALUES (?, ?, ?, ?)
	ON CONFLICT(address)
	DO UPDATE set siacoin_balance = ?, immature_siacoin_balance = ?`)
	if err != nil {
		return fmt.Errorf("updateMaturedBalances: failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	initialSF := encode(uint64(0))
	for addr, bal := range addresses {
		if _, err := stmt.Exec(encode(addr), encode(bal.sc), encode(bal.immatureSC), initialSF, encode(bal.sc), encode(bal.immatureSC)); err != nil {
			return fmt.Errorf("updateMaturedBalances: failed to exec statement: %w", err)
		}
	}

	return nil
}

func updateStateTree(tx *txn, changes []explorer.TreeNodeUpdate) error {
	stmt, err := tx.Prepare(`INSERT INTO state_tree (row, column, value) VALUES($1, $2, $3) ON CONFLICT (row, column) DO UPDATE SET value=EXCLUDED.value;`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, change := range changes {
		_, err := stmt.Exec(change.Row, change.Column, encode(change.Hash))
		if err != nil {
			return fmt.Errorf("failed to execute statement: %w", err)
		}
	}
	return nil
}

func addSiacoinElements(tx *txn, index types.ChainIndex, spentElements, newElements []explorer.SiacoinOutput) (map[types.SiacoinOutputID]int64, error) {
	scDBIds := make(map[types.SiacoinOutputID]int64)
	if len(newElements) > 0 {
		stmt, err := tx.Prepare(`INSERT INTO siacoin_elements(output_id, block_id, leaf_index, source, maturity_height, address, value)
				VALUES (?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT (output_id)
				DO UPDATE SET leaf_index = ?, spent_index = NULL
                RETURNING id;`)
		if err != nil {
			return nil, fmt.Errorf("addSiacoinElements: failed to prepare siacoin_elements statement: %w", err)
		}
		defer stmt.Close()

		for _, sce := range newElements {
			var dbID int64
			if err := stmt.QueryRow(encode(sce.ID), encode(index.ID), encode(sce.LeafIndex), int(sce.Source), sce.MaturityHeight, encode(sce.SiacoinOutput.Address), encode(sce.SiacoinOutput.Value), encode(sce.StateElement.LeafIndex)).Scan(&dbID); err != nil {
				return nil, fmt.Errorf("addSiacoinElements: failed to execute siacoin_elements statement: %w", err)
			}

			scDBIds[types.SiacoinOutputID(sce.ID)] = dbID
		}
	}
	if len(spentElements) > 0 {
		stmt, err := tx.Prepare(`INSERT INTO siacoin_elements(output_id, block_id, leaf_index, spent_index, source, maturity_height, address, value)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (output_id)
                DO UPDATE SET spent_index = ?, leaf_index = ?
                RETURNING id;`)
		if err != nil {
			return nil, fmt.Errorf("addSiacoinElements: failed to prepare siacoin_elements statement: %w", err)
		}
		defer stmt.Close()

		for _, sce := range spentElements {
			var dbID int64
			if err := stmt.QueryRow(encode(sce.ID), encode(index.ID), encode(sce.StateElement.LeafIndex), encode(index), int(sce.Source), sce.MaturityHeight, encode(sce.SiacoinOutput.Address), encode(sce.SiacoinOutput.Value), encode(index), encode(sce.StateElement.LeafIndex)).Scan(&dbID); err != nil {
				return nil, fmt.Errorf("addSiacoinElements: failed to execute siacoin_elements statement: %w", err)
			}

			scDBIds[types.SiacoinOutputID(sce.ID)] = dbID
		}
	}

	return scDBIds, nil
}

func addSiafundElements(tx *txn, index types.ChainIndex, spentElements, newElements []types.SiafundElement) (map[types.SiafundOutputID]int64, error) {
	sfDBIds := make(map[types.SiafundOutputID]int64)
	if len(newElements) > 0 {
		stmt, err := tx.Prepare(`INSERT INTO siafund_elements(output_id, block_id, leaf_index, claim_start, address, value)
			VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT
			DO UPDATE SET leaf_index = ?, spent_index = NULL
			RETURNING id;`)
		if err != nil {
			return nil, fmt.Errorf("addSiafundElements: failed to prepare siafund_elements statement: %w", err)
		}
		defer stmt.Close()

		for _, sfe := range newElements {
			var dbID int64
			if err := stmt.QueryRow(encode(sfe.ID), encode(index.ID), encode(sfe.StateElement.LeafIndex), encode(sfe.ClaimStart), encode(sfe.SiafundOutput.Address), encode(sfe.SiafundOutput.Value), encode(sfe.StateElement.LeafIndex)).Scan(&dbID); err != nil {
				return nil, fmt.Errorf("addSiafundElements: failed to execute siafund_elements statement: %w", err)
			}

			sfDBIds[types.SiafundOutputID(sfe.ID)] = dbID
		}
	}
	if len(spentElements) > 0 {
		stmt, err := tx.Prepare(`INSERT INTO siafund_elements(output_id, block_id, leaf_index, spent_index, claim_start, address, value)
			VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT
			DO UPDATE SET leaf_index = ?, spent_index = ?
			RETURNING id;`)
		if err != nil {
			return nil, fmt.Errorf("addSiafundElements: failed to prepare siafund_elements statement: %w", err)
		}
		defer stmt.Close()

		for _, sfe := range spentElements {
			var dbID int64
			if err := stmt.QueryRow(encode(sfe.ID), encode(index.ID), encode(sfe.StateElement.LeafIndex), encode(index), encode(sfe.ClaimStart), encode(sfe.SiafundOutput.Address), encode(sfe.SiafundOutput.Value), encode(sfe.StateElement.LeafIndex), encode(index)).Scan(&dbID); err != nil {
				return nil, fmt.Errorf("addSiafundElements: failed to execute siafund_elements statement: %w", err)
			}

			sfDBIds[types.SiafundOutputID(sfe.ID)] = dbID
		}
	}
	return sfDBIds, nil
}

func addEvents(tx *txn, scDBIds map[types.SiacoinOutputID]int64, fcDBIds map[explorer.DBFileContract]int64, txnDBIds map[types.TransactionID]txnDBId, v2TxnDBIds map[types.TransactionID]txnDBId, events []explorer.Event) error {
	if len(events) == 0 {
		return nil
	}

	insertEventStmt, err := tx.Prepare(`INSERT INTO events (event_id, maturity_height, date_created, event_type, block_id, height) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (event_id) DO NOTHING RETURNING id`)
	if err != nil {
		return fmt.Errorf("failed to prepare event statement: %w", err)
	}
	defer insertEventStmt.Close()

	addrStmt, err := tx.Prepare(`INSERT INTO address_balance (address, siacoin_balance, immature_siacoin_balance, siafund_balance) VALUES ($1, $2, $3, 0) ON CONFLICT (address) DO UPDATE SET address=EXCLUDED.address RETURNING id`)
	if err != nil {
		return fmt.Errorf("failed to prepare address statement: %w", err)
	}
	defer addrStmt.Close()

	relevantAddrStmt, err := tx.Prepare(`INSERT INTO event_addresses (event_id, address_id) VALUES ($1, $2) ON CONFLICT (event_id, address_id) DO NOTHING`)
	if err != nil {
		return fmt.Errorf("failed to prepare relevant address statement: %w", err)
	}
	defer relevantAddrStmt.Close()

	transactionEventStmt, err := tx.Prepare(`INSERT INTO transaction_events (event_id, transaction_id, fee) VALUES (?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("failed to prepare transaction event statement: %w", err)
	}
	defer transactionEventStmt.Close()

	v2TransactionEventStmt, err := tx.Prepare(`INSERT INTO v2_transaction_events (event_id, transaction_id, fee) VALUES (?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("failed to prepare v2 transaction event statement: %w", err)
	}
	defer v2TransactionEventStmt.Close()

	hostAnnouncementStmt, err := tx.Prepare(`INSERT INTO host_announcements (transaction_id, transaction_order, public_key, net_address) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("failed to prepare host anonouncement statement: %w", err)
	}
	defer hostAnnouncementStmt.Close()

	v2HostAnnouncementStmt, err := tx.Prepare(`INSERT INTO v2_host_announcements (transaction_id, transaction_order, public_key, net_address) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("failed to prepare host anonouncement statement: %w", err)
	}
	defer v2HostAnnouncementStmt.Close()

	minerPayoutEventStmt, err := tx.Prepare(`INSERT INTO miner_payout_events (event_id, output_id) VALUES (?, ?)`)
	if err != nil {
		return fmt.Errorf("failed to prepare miner payout event statement: %w", err)
	}
	defer minerPayoutEventStmt.Close()

	contractPayoutEventStmt, err := tx.Prepare(`INSERT INTO contract_payout_events (event_id, output_id, contract_id, missed) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("failed to prepare contract payout event statement: %w", err)
	}
	defer contractPayoutEventStmt.Close()

	foundationSubsidyEventStmt, err := tx.Prepare(`INSERT INTO foundation_subsidy_events (event_id, output_id) VALUES (?, ?)`)
	if err != nil {
		return fmt.Errorf("failed to prepare foundation subsidy event statement: %w", err)
	}
	defer foundationSubsidyEventStmt.Close()

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, event := range events {
		buf.Reset()
		if err := enc.Encode(event.Data); err != nil {
			return fmt.Errorf("failed to encode event: %w", err)
		}

		var eventID int64
		err = insertEventStmt.QueryRow(encode(event.ID), event.MaturityHeight, encode(event.Timestamp), event.Data.EventType(), encode(event.Index.ID), event.Index.Height).Scan(&eventID)
		if errors.Is(err, sql.ErrNoRows) {
			continue // skip if the event already exists
		} else if err != nil {
			return fmt.Errorf("failed to add event: %w", err)
		}

		switch v := event.Data.(type) {
		case *explorer.EventTransaction:
			dbID := txnDBIds[types.TransactionID(event.ID)].id
			if _, err = transactionEventStmt.Exec(eventID, dbID, encode(v.Fee)); err != nil {
				return fmt.Errorf("failed to insert transaction event: %w", err)
			}
			var hosts []explorer.Host
			for i, announcement := range v.HostAnnouncements {
				if _, err = hostAnnouncementStmt.Exec(dbID, i, encode(announcement.PublicKey), announcement.NetAddress); err != nil {
					return fmt.Errorf("failed to insert host announcement: %w", err)
				}
				hosts = append(hosts, explorer.Host{
					PublicKey:  announcement.PublicKey,
					NetAddress: announcement.NetAddress,

					KnownSince:       event.Timestamp,
					LastAnnouncement: event.Timestamp,
				})
			}
			if len(hosts) > 0 {
				if err := addHosts(tx, hosts); err != nil {
					return fmt.Errorf("failed to insert host info: %w", err)
				}
			}
		case *explorer.EventV2Transaction:
			dbID := v2TxnDBIds[types.TransactionID(event.ID)].id
			if _, err = v2TransactionEventStmt.Exec(eventID, dbID, encode(v.Fee)); err != nil {
				return fmt.Errorf("failed to insert transaction event: %w", err)
			}
			var hosts []explorer.Host
			for i, announcement := range v.HostAnnouncements {
				if _, err = hostAnnouncementStmt.Exec(dbID, i, encode(announcement.PublicKey), announcement.NetAddress); err != nil {
					return fmt.Errorf("failed to insert host announcement: %w", err)
				}
				hosts = append(hosts, explorer.Host{
					PublicKey:  announcement.PublicKey,
					NetAddress: announcement.NetAddress,

					KnownSince:       event.Timestamp,
					LastAnnouncement: event.Timestamp,
				})
			}
			if len(hosts) > 0 {
				if err := addHosts(tx, hosts); err != nil {
					return fmt.Errorf("failed to insert host info: %w", err)
				}
			}
		case *explorer.EventMinerPayout:
			_, err = minerPayoutEventStmt.Exec(eventID, scDBIds[types.SiacoinOutputID(event.ID)])
		case *explorer.EventContractPayout:
			_, err = contractPayoutEventStmt.Exec(eventID, scDBIds[v.SiacoinOutput.ID], fcDBIds[explorer.DBFileContract{ID: v.FileContract.ID, RevisionNumber: v.FileContract.FileContract.RevisionNumber}], v.Missed)
		case *explorer.EventFoundationSubsidy:
			_, err = foundationSubsidyEventStmt.Exec(eventID, scDBIds[types.SiacoinOutputID(event.ID)])
		default:
			return errors.New("unknown event type")
		}
		if err != nil {
			return fmt.Errorf("failed to insert %s event: %w", event.Data.EventType(), err)
		}

		used := make(map[types.Address]bool)
		for _, addr := range event.Addresses {
			if used[addr] {
				continue
			}

			var addressID int64
			err = addrStmt.QueryRow(encode(addr), encode(types.ZeroCurrency), encode(types.ZeroCurrency)).Scan(&addressID)
			if err != nil {
				return fmt.Errorf("failed to get address: %w", err)
			}

			_, err = relevantAddrStmt.Exec(eventID, addressID)
			if err != nil {
				return fmt.Errorf("failed to add relevant address: %w", err)
			}

			used[addr] = true
		}
	}
	return nil
}

func deleteBlock(tx *txn, bid types.BlockID) error {
	_, err := tx.Exec("DELETE FROM blocks WHERE id = ?", encode(bid))
	return err
}

func updateFileContractElements(tx *txn, revert bool, b types.Block, fces []explorer.FileContractUpdate) (map[explorer.DBFileContract]int64, error) {
	stmt, err := tx.Prepare(`INSERT INTO file_contract_elements(contract_id, block_id, transaction_id, leaf_index, resolved, valid, filesize, file_merkle_root, window_start, window_end, payout, unlock_hash, revision_number)
		VALUES (?, ?, ?, ?, FALSE, FALSE, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (contract_id, revision_number)
		DO UPDATE SET resolved = ?, valid = ?, leaf_index = ?
		RETURNING id;`)
	if err != nil {
		return nil, fmt.Errorf("updateFileContractElements: failed to prepare main statement: %w", err)
	}
	defer stmt.Close()

	revisionStmt, err := tx.Prepare(`INSERT INTO last_contract_revision(contract_id, contract_element_id, ed25519_renter_key, ed25519_host_key)
	VALUES (?, ?, ?, ?)
	ON CONFLICT (contract_id)
	DO UPDATE SET contract_element_id = ?, ed25519_renter_key = COALESCE(?, ed25519_renter_key), ed25519_host_key = COALESCE(?, ed25519_host_key)`)
	if err != nil {
		return nil, fmt.Errorf("updateFileContractElements: failed to prepare last_contract_revision statement: %w", err)
	}
	defer revisionStmt.Close()

	validOutputsStmt, err := tx.Prepare(`INSERT INTO file_contract_valid_proof_outputs(contract_id, contract_order, id, address, value) VALUES (?, ?, ?, ?, ?) ON CONFLICT DO NOTHING`)
	if err != nil {
		return nil, fmt.Errorf("addFileContracts: failed to prepare valid proof outputs statement: %w", err)
	}
	defer validOutputsStmt.Close()

	missedOutputsStmt, err := tx.Prepare(`INSERT INTO file_contract_missed_proof_outputs(contract_id, contract_order, id, address, value) VALUES (?, ?, ?, ?, ?)  ON CONFLICT DO NOTHING`)
	if err != nil {
		return nil, fmt.Errorf("addFileContracts: failed to prepare missed proof outputs statement: %w", err)
	}
	defer missedOutputsStmt.Close()

	fcKeys := make(map[explorer.DBFileContract][2]types.PublicKey)
	// populate fcKeys using revision UnlockConditions fields
	for _, txn := range b.Transactions {
		for _, fcr := range txn.FileContractRevisions {
			fc := fcr.FileContract
			uc := fcr.UnlockConditions
			dbFC := explorer.DBFileContract{ID: fcr.ParentID, RevisionNumber: fc.RevisionNumber}

			// check for 2 ed25519 keys
			ok := true
			var result [2]types.PublicKey
			for i := 0; i < 2; i++ {
				// fewer than 2 keys
				if i >= len(uc.PublicKeys) {
					ok = false
					break
				}

				if uc.PublicKeys[i].Algorithm == types.SpecifierEd25519 {
					result[i] = types.PublicKey(uc.PublicKeys[i].Key)
				} else {
					// not an ed25519 key
					ok = false
				}
			}
			if ok {
				fcKeys[dbFC] = result
			}
		}
	}

	fcTxns := make(map[explorer.DBFileContract]types.TransactionID)
	for _, txn := range b.Transactions {
		id := txn.ID()

		for i, fc := range txn.FileContracts {
			fcTxns[explorer.DBFileContract{
				ID:             txn.FileContractID(i),
				RevisionNumber: fc.RevisionNumber,
			}] = id
		}
		for _, fcr := range txn.FileContractRevisions {
			fcTxns[explorer.DBFileContract{
				ID:             fcr.ParentID,
				RevisionNumber: fcr.FileContract.RevisionNumber,
			}] = id
		}
	}

	fcDBIds := make(map[explorer.DBFileContract]int64)
	addFC := func(fcID types.FileContractID, leafIndex uint64, fc types.FileContract, resolved, valid, lastRevision bool) error {
		var dbID int64
		dbFC := explorer.DBFileContract{ID: fcID, RevisionNumber: fc.RevisionNumber}
		err := stmt.QueryRow(encode(fcID), encode(b.ID()), encode(fcTxns[dbFC]), encode(leafIndex), encode(fc.Filesize), encode(fc.FileMerkleRoot), encode(fc.WindowStart), encode(fc.WindowEnd), encode(fc.Payout), encode(fc.UnlockHash), encode(fc.RevisionNumber), resolved, valid, encode(leafIndex)).Scan(&dbID)
		if err != nil {
			return fmt.Errorf("failed to execute file_contract_elements statement: %w", err)
		}

		for i, sco := range fc.ValidProofOutputs {
			if _, err := validOutputsStmt.Exec(dbID, i, encode(fcID.ValidOutputID(i)), encode(sco.Address), encode(sco.Value)); err != nil {
				return fmt.Errorf("updateFileContractElements: failed to execute valid proof outputs statement: %w", err)
			}
		}
		for i, sco := range fc.MissedProofOutputs {
			if _, err := missedOutputsStmt.Exec(dbID, i, encode(fcID.MissedOutputID(i)), encode(sco.Address), encode(sco.Value)); err != nil {
				return fmt.Errorf("updateFileContractElements: failed to execute missed proof outputs statement: %w", err)
			}
		}

		// only update if it's the most recent revision which will come from
		// running ForEachFileContractElement on the update
		if lastRevision {
			var renterKey, hostKey []byte
			if keys, ok := fcKeys[dbFC]; ok {
				renterKey = encode(keys[0]).([]byte)
				hostKey = encode(keys[1]).([]byte)
			}

			if _, err := revisionStmt.Exec(encode(fcID), dbID, renterKey, hostKey, dbID, renterKey, hostKey); err != nil {
				return fmt.Errorf("failed to update last revision number: %w", err)
			}
		}

		fcDBIds[dbFC] = dbID
		return nil
	}

	for _, update := range fces {
		var fce *types.FileContractElement

		if revert {
			// Reverting
			if update.Revision != nil {
				// Contract revision reverted.
				// We are reverting the revision, so get the contract before
				// the revision.
				fce = &update.FileContractElement
			} else {
				// Contract formation reverted.
				// The contract update has no revision, therefore it refers
				// to the original contract formation.
				continue
			}
		} else {
			// Applying
			fce = &update.FileContractElement
			if update.Revision != nil {
				// Contract is revised.
				// We want last_contract_revision to refer to the latest
				// revision, so use the revision FCE if there is one.
				fce = update.Revision
			}
		}

		if err := addFC(
			fce.ID,
			fce.StateElement.LeafIndex,
			fce.FileContract,
			update.Resolved,
			update.Valid,
			true,
		); err != nil {
			return nil, fmt.Errorf("updateFileContractElements: %w", err)
		}
	}

	if revert {
		return fcDBIds, nil
	}

	for _, txn := range b.Transactions {
		for j, fc := range txn.FileContracts {
			fcID := txn.FileContractID(j)
			dbFC := explorer.DBFileContract{ID: txn.FileContractID(j), RevisionNumber: fc.RevisionNumber}
			if _, exists := fcDBIds[dbFC]; exists {
				continue
			}

			if err := addFC(fcID, 0, fc, false, false, false); err != nil {
				return nil, fmt.Errorf("updateFileContractElements: %w", err)
			}
		}
		for _, fcr := range txn.FileContractRevisions {
			fc := fcr.FileContract
			dbFC := explorer.DBFileContract{ID: fcr.ParentID, RevisionNumber: fc.RevisionNumber}
			if _, exists := fcDBIds[dbFC]; exists {
				continue
			}

			if err := addFC(fcr.ParentID, 0, fc, false, false, false); err != nil {
				return nil, fmt.Errorf("updateFileContractElements: %w", err)
			}
		}
	}

	return fcDBIds, nil
}

func updateFileContractIndices(tx *txn, revert bool, index types.ChainIndex, fces []explorer.FileContractUpdate) error {
	confirmationIndexStmt, err := tx.Prepare(`UPDATE last_contract_revision SET confirmation_index = ?, confirmation_transaction_id = ? WHERE contract_id = ?`)
	if err != nil {
		return fmt.Errorf("updateFileContractIndices: failed to prepare confirmation index statement: %w", err)
	}
	defer confirmationIndexStmt.Close()

	proofIndexStmt, err := tx.Prepare(`UPDATE last_contract_revision SET proof_index = ?, proof_transaction_id = ? WHERE contract_id = ?`)
	if err != nil {
		return fmt.Errorf("updateFileContractIndices: failed to prepare proof index statement: %w", err)
	}
	defer proofIndexStmt.Close()

	for _, update := range fces {
		// id stays the same even if revert happens so we don't need to check that here
		fcID := update.FileContractElement.ID

		if revert {
			if update.ConfirmationTransactionID != nil {
				if _, err := confirmationIndexStmt.Exec(nil, nil, encode(fcID)); err != nil {
					return fmt.Errorf("updateFileContractIndices: failed to update confirmation index: %w", err)
				}
			}
			if update.ProofTransactionID != nil {
				if _, err := proofIndexStmt.Exec(nil, nil, encode(fcID)); err != nil {
					return fmt.Errorf("updateFileContractIndices: failed to update proof index: %w", err)
				}
			}
		} else {
			if update.ConfirmationTransactionID != nil {
				if _, err := confirmationIndexStmt.Exec(encode(index), encode(update.ConfirmationTransactionID), encode(fcID)); err != nil {
					return fmt.Errorf("updateFileContractIndices: failed to update confirmation index: %w", err)
				}
			}
			if update.ProofTransactionID != nil {
				if _, err := proofIndexStmt.Exec(encode(index), encode(update.ProofTransactionID), encode(fcID)); err != nil {
					return fmt.Errorf("updateFileContractIndices: failed to update proof index: %w", err)
				}
			}
		}
	}

	return nil
}

func addMetrics(tx *txn, s explorer.UpdateState) error {
	_, err := tx.Exec(`INSERT INTO network_metrics(block_id, height, difficulty, siafund_pool, num_leaves, total_hosts, active_contracts, failed_contracts, successful_contracts, storage_utilization, circulating_supply, contract_revenue) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		encode(s.Metrics.Index.ID),
		s.Metrics.Index.Height,
		encode(s.Metrics.Difficulty),
		encode(s.Metrics.SiafundPool),
		encode(s.Metrics.NumLeaves),
		s.Metrics.TotalHosts,
		s.Metrics.ActiveContracts,
		s.Metrics.FailedContracts,
		s.Metrics.SuccessfulContracts,
		s.Metrics.StorageUtilization,
		encode(s.Metrics.CirculatingSupply),
		encode(s.Metrics.ContractRevenue),
	)
	return err
}

func (ut *updateTx) HostExists(pubkey types.PublicKey) (exists bool, err error) {
	err = ut.tx.QueryRow(`SELECT EXISTS(SELECT public_key FROM host_announcements WHERE public_key = ?)`, encode(pubkey)).Scan(&exists)
	return
}

func (ut *updateTx) Metrics(height uint64) (explorer.Metrics, error) {
	var metrics explorer.Metrics
	if err := ut.tx.QueryRow("SELECT total_hosts, active_contracts, failed_contracts, successful_contracts, storage_utilization, circulating_supply, contract_revenue from network_metrics WHERE height = ?", height).Scan(&metrics.TotalHosts, &metrics.ActiveContracts, &metrics.FailedContracts, &metrics.SuccessfulContracts, &metrics.StorageUtilization, decode(&metrics.CirculatingSupply), decode(&metrics.ContractRevenue)); err != nil && err != sql.ErrNoRows {
		return explorer.Metrics{}, err
	}
	return metrics, nil
}

func (ut *updateTx) ApplyIndex(state explorer.UpdateState) error {
	if err := addBlock(ut.tx, state.Block, state.Metrics.Index.Height); err != nil {
		return fmt.Errorf("ApplyIndex: failed to add block: %w", err)
	} else if err := updateMaturedBalances(ut.tx, false, state.Metrics.Index.Height); err != nil {
		return fmt.Errorf("ApplyIndex: failed to update matured balances: %w", err)
	}

	txnDBIds, err := addTransactions(ut.tx, state.Block.ID(), state.Block.Transactions)
	if err != nil {
		return fmt.Errorf("ApplyIndex: failed to add transactions: %w", err)
	}

	v2TxnDBIds, err := addV2Transactions(ut.tx, state.Block.ID(), state.Block.V2Transactions())
	if err != nil {
		return fmt.Errorf("ApplyIndex: failed to add v2 transactions: %w", err)
	}

	scDBIds, err := addSiacoinElements(
		ut.tx,
		state.Metrics.Index,
		append(state.SpentSiacoinElements, state.EphemeralSiacoinElements...),
		state.NewSiacoinElements,
	)
	if err != nil {
		return fmt.Errorf("ApplyIndex: failed to add siacoin outputs: %w", err)
	}
	sfDBIds, err := addSiafundElements(
		ut.tx,
		state.Metrics.Index,
		append(state.SpentSiafundElements, state.EphemeralSiafundElements...),
		state.NewSiafundElements,
	)
	if err != nil {
		return fmt.Errorf("ApplyIndex: failed to add siafund outputs: %w", err)
	}
	fcDBIds, err := updateFileContractElements(ut.tx, false, state.Block, state.FileContractElements)
	if err != nil {
		return fmt.Errorf("ApplyIndex: failed to add file contracts: %w", err)
	}

	v2FcDBIds, err := updateV2FileContractElements(ut.tx, false, state.Block, state.V2FileContractElements)
	if err != nil {
		return fmt.Errorf("ApplyIndex: failed to add v2 file contracts: %w", err)
	}

	if err := addTransactionFields(ut.tx, state.Block.Transactions, scDBIds, sfDBIds, fcDBIds, txnDBIds); err != nil {
		return fmt.Errorf("ApplyIndex: failed to add transaction fields: %w", err)
	} else if err := addV2TransactionFields(ut.tx, state.Block.V2Transactions(), scDBIds, sfDBIds, v2FcDBIds, v2TxnDBIds); err != nil {
		return fmt.Errorf("ApplyIndex: failed to add v2 transaction fields: %w", err)
	} else if err := updateBalances(ut.tx, state.Metrics.Index.Height, state.SpentSiacoinElements, state.NewSiacoinElements, state.SpentSiafundElements, state.NewSiafundElements); err != nil {
		return fmt.Errorf("ApplyIndex: failed to update balances: %w", err)
	} else if err := addMinerPayouts(ut.tx, state.Block.ID(), state.Block.MinerPayouts, scDBIds); err != nil {
		return fmt.Errorf("ApplyIndex: failed to add miner payouts: %w", err)
	} else if err := updateStateTree(ut.tx, state.TreeUpdates); err != nil {
		return fmt.Errorf("ApplyIndex: failed to update state tree: %w", err)
	} else if err := addMetrics(ut.tx, state); err != nil {
		return fmt.Errorf("ApplyIndex: failed to update metrics: %w", err)
	} else if err := addEvents(ut.tx, scDBIds, fcDBIds, txnDBIds, v2TxnDBIds, state.Events); err != nil {
		return fmt.Errorf("ApplyIndex: failed to add events: %w", err)
	} else if err := updateFileContractIndices(ut.tx, false, state.Metrics.Index, state.FileContractElements); err != nil {
		return fmt.Errorf("ApplyIndex: failed to update file contract element indices: %w", err)
	} else if err := updateV2FileContractIndices(ut.tx, false, state.Metrics.Index, state.V2FileContractElements); err != nil {
		return fmt.Errorf("ApplyIndex: failed to update v2 file contract element indices: %w", err)
	}

	return nil
}

func (ut *updateTx) RevertIndex(state explorer.UpdateState) error {
	if err := updateMaturedBalances(ut.tx, true, state.Metrics.Index.Height); err != nil {
		return fmt.Errorf("RevertIndex: failed to update matured balances: %w", err)
	} else if _, err := addSiacoinElements(
		ut.tx,
		state.Metrics.Index,
		state.SpentSiacoinElements,
		append(state.NewSiacoinElements, state.EphemeralSiacoinElements...),
	); err != nil {
		return fmt.Errorf("RevertIndex: failed to update siacoin output state: %w", err)
	} else if _, err := addSiafundElements(
		ut.tx,
		state.Metrics.Index,
		state.SpentSiafundElements,
		append(state.NewSiafundElements, state.EphemeralSiafundElements...),
	); err != nil {
		return fmt.Errorf("RevertIndex: failed to update siafund output state: %w", err)
	} else if err := updateBalances(ut.tx, state.Metrics.Index.Height, state.SpentSiacoinElements, state.NewSiacoinElements, state.SpentSiafundElements, state.NewSiafundElements); err != nil {
		return fmt.Errorf("RevertIndex: failed to update balances: %w", err)
	} else if _, err := updateFileContractElements(ut.tx, true, state.Block, state.FileContractElements); err != nil {
		return fmt.Errorf("RevertIndex: failed to update file contract state: %w", err)
	} else if err := deleteBlock(ut.tx, state.Block.ID()); err != nil {
		return fmt.Errorf("RevertIndex: failed to delete block: %w", err)
	} else if err := updateStateTree(ut.tx, state.TreeUpdates); err != nil {
		return fmt.Errorf("RevertIndex: failed to update state tree: %w", err)
	} else if err := updateFileContractIndices(ut.tx, true, state.Metrics.Index, state.FileContractElements); err != nil {
		return fmt.Errorf("RevertIndex: failed to update file contract element indices: %w", err)
	}

	return nil
}

func addHosts(tx *txn, scans []explorer.Host) error {
	stmt, err := tx.Prepare(`INSERT INTO host_info(public_key, net_address, country_code, known_since, last_scan, last_scan_successful, last_announcement, total_scans, successful_interactions, failed_interactions, settings_accepting_contracts, settings_max_download_batch_size, settings_max_duration, settings_max_revise_batch_size, settings_net_address, settings_remaining_storage, settings_sector_size, settings_total_storage, settings_address, settings_window_size, settings_collateral, settings_max_collateral, settings_base_rpc_price, settings_contract_price, settings_download_bandwidth_price, settings_sector_access_price, settings_storage_price, settings_upload_bandwidth_price, settings_ephemeral_account_expiry, settings_max_ephemeral_account_balance, settings_revision_number, settings_version, settings_release, settings_sia_mux_port, price_table_uid, price_table_validity, price_table_host_block_height, price_table_update_price_table_cost, price_table_account_balance_cost, price_table_fund_account_cost, price_table_latest_revision_cost, price_table_subscription_memory_cost, price_table_subscription_notification_cost, price_table_init_base_cost, price_table_memory_time_cost, price_table_download_bandwidth_cost, price_table_upload_bandwidth_cost, price_table_drop_sectors_base_cost, price_table_drop_sectors_unit_cost, price_table_has_sector_base_cost, price_table_read_base_cost, price_table_read_length_cost, price_table_renew_contract_cost, price_table_revision_base_cost, price_table_swap_sector_base_cost, price_table_write_base_cost, price_table_write_length_cost, price_table_write_store_cost, price_table_txn_fee_min_recommended, price_table_txn_fee_max_recommended, price_table_contract_price, price_table_collateral_cost, price_table_max_collateral, price_table_max_duration, price_table_window_size, price_table_registry_entries_left, price_table_registry_entries_total) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35,$36,$37,$38,$39,$40,$41,$42,$43,$44,$45,$46,$47,$48,$49,$50,$51,$52,$53,$54,$55,$56,$57,$58,$59,$60,$61,$62,$63,$64,$65,$66,$67) ON CONFLICT (public_key) DO UPDATE SET net_address = $2, country_code = $3, last_scan = $5, last_scan_successful = $6, last_announcement = CASE WHEN $7 > 0 THEN last_announcement ELSE $7 END, total_scans = $8, successful_interactions = $9, failed_interactions = failed_interactions + $10, settings_accepting_contracts = $11, settings_max_download_batch_size = $12, settings_max_duration = $13, settings_max_revise_batch_size = $14 , settings_net_address = $15, settings_remaining_storage = $16, settings_sector_size = $17, settings_total_storage = $18, settings_address = $19, settings_window_size = $20, settings_collateral = $21, settings_max_collateral = $22, settings_base_rpc_price = $23, settings_contract_price = $24, settings_download_bandwidth_price = $25, settings_sector_access_price = $26, settings_storage_price = $27, settings_upload_bandwidth_price = $28, settings_ephemeral_account_expiry = $29, settings_max_ephemeral_account_balance = $30, settings_revision_number = $31, settings_version = $32, settings_release = $33, settings_sia_mux_port = $34, price_table_uid = $35, price_table_validity = $36, price_table_host_block_height = $37, price_table_update_price_table_cost = $38, price_table_account_balance_cost = $39, price_table_fund_account_cost = $40, price_table_latest_revision_cost = $41, price_table_subscription_memory_cost = $42, price_table_subscription_notification_cost = $43, price_table_init_base_cost = $44, price_table_memory_time_cost = $45, price_table_download_bandwidth_cost = $46, price_table_upload_bandwidth_cost = $47, price_table_drop_sectors_base_cost = $48, price_table_drop_sectors_unit_cost = $49, price_table_has_sector_base_cost = $50, price_table_read_base_cost = $51, price_table_read_length_cost = $52, price_table_renew_contract_cost = $53, price_table_revision_base_cost = $54, price_table_swap_sector_base_cost = $55, price_table_write_base_cost = $56, price_table_write_length_cost = $57, price_table_write_store_cost = $58, price_table_txn_fee_min_recommended = $59, price_table_txn_fee_max_recommended = $60, price_table_contract_price = $61, price_table_collateral_cost = $62, price_table_max_collateral = $63, price_table_max_duration = $64, price_table_window_size = $65, price_table_registry_entries_left = $66, price_table_registry_entries_total = $67`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, scan := range scans {
		s, p := scan.Settings, scan.PriceTable
		if _, err := stmt.Exec(encode(scan.PublicKey), scan.NetAddress, scan.CountryCode, encode(scan.KnownSince), encode(scan.LastScan), scan.LastScanSuccessful, encode(scan.LastAnnouncement), scan.TotalScans, scan.SuccessfulInteractions, scan.FailedInteractions, s.AcceptingContracts, encode(s.MaxDownloadBatchSize), encode(s.MaxDuration), encode(s.MaxReviseBatchSize), s.NetAddress, encode(s.RemainingStorage), encode(s.SectorSize), encode(s.TotalStorage), encode(s.Address), encode(s.WindowSize), encode(s.Collateral), encode(s.MaxCollateral), encode(s.BaseRPCPrice), encode(s.ContractPrice), encode(s.DownloadBandwidthPrice), encode(s.SectorAccessPrice), encode(s.StoragePrice), encode(s.UploadBandwidthPrice), s.EphemeralAccountExpiry, encode(s.MaxEphemeralAccountBalance), encode(s.RevisionNumber), s.Version, s.Release, s.SiaMuxPort, encode(p.UID), p.Validity, encode(p.HostBlockHeight), encode(p.UpdatePriceTableCost), encode(p.AccountBalanceCost), encode(p.FundAccountCost), encode(p.LatestRevisionCost), encode(p.SubscriptionMemoryCost), encode(p.SubscriptionNotificationCost), encode(p.InitBaseCost), encode(p.MemoryTimeCost), encode(p.DownloadBandwidthCost), encode(p.UploadBandwidthCost), encode(p.DropSectorsBaseCost), encode(p.DropSectorsUnitCost), encode(p.HasSectorBaseCost), encode(p.ReadBaseCost), encode(p.ReadLengthCost), encode(p.RenewContractCost), encode(p.RevisionBaseCost), encode(p.SwapSectorBaseCost), encode(p.WriteBaseCost), encode(p.WriteLengthCost), encode(p.WriteStoreCost), encode(p.TxnFeeMinRecommended), encode(p.TxnFeeMaxRecommended), encode(p.ContractPrice), encode(p.CollateralCost), encode(p.MaxCollateral), encode(p.MaxDuration), encode(p.WindowSize), encode(p.RegistryEntriesLeft), encode(p.RegistryEntriesTotal)); err != nil {
			return err
		}
	}
	return nil
}

func addHostScans(tx *txn, scans []explorer.HostScan) error {
	stmt, err := tx.Prepare(`UPDATE host_info SET country_code = ?, last_scan = ?, last_scan_successful = ?, total_scans = total_scans + 1, successful_interactions = successful_interactions + ?, failed_interactions = failed_interactions + ?, settings_accepting_contracts = ?, settings_max_download_batch_size = ?, settings_max_duration = ?, settings_max_revise_batch_size = ?, settings_net_address = ?, settings_remaining_storage = ?, settings_sector_size = ?, settings_total_storage = ?, settings_address = ?, settings_window_size = ?, settings_collateral = ?, settings_max_collateral = ?, settings_base_rpc_price = ?, settings_contract_price = ?, settings_download_bandwidth_price = ?, settings_sector_access_price = ?, settings_storage_price = ?, settings_upload_bandwidth_price = ?, settings_ephemeral_account_expiry = ?, settings_max_ephemeral_account_balance = ?, settings_revision_number = ?, settings_version = ?, settings_release = ?, settings_sia_mux_port = ?, price_table_uid = ?, price_table_validity = ?, price_table_host_block_height = ?, price_table_update_price_table_cost = ?, price_table_account_balance_cost = ?, price_table_fund_account_cost = ?, price_table_latest_revision_cost = ?, price_table_subscription_memory_cost = ?, price_table_subscription_notification_cost = ?, price_table_init_base_cost = ?, price_table_memory_time_cost = ?, price_table_download_bandwidth_cost = ?, price_table_upload_bandwidth_cost = ?, price_table_drop_sectors_base_cost = ?, price_table_drop_sectors_unit_cost = ?, price_table_has_sector_base_cost = ?, price_table_read_base_cost = ?, price_table_read_length_cost = ?, price_table_renew_contract_cost = ?, price_table_revision_base_cost = ?, price_table_swap_sector_base_cost = ?, price_table_write_base_cost = ?, price_table_write_length_cost = ?, price_table_write_store_cost = ?, price_table_txn_fee_min_recommended = ?, price_table_txn_fee_max_recommended = ?, price_table_contract_price = ?, price_table_collateral_cost = ?, price_table_max_collateral = ?, price_table_max_duration = ?, price_table_window_size = ?, price_table_registry_entries_left = ?, price_table_registry_entries_total = ? WHERE public_key = ?`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, scan := range scans {
		successful, failed := 1, 0
		if !scan.Success {
			successful, failed = 0, 1
		}

		s, p := scan.Settings, scan.PriceTable
		if _, err := stmt.Exec(scan.CountryCode, encode(scan.Timestamp), scan.Success, successful, failed, s.AcceptingContracts, encode(s.MaxDownloadBatchSize), encode(s.MaxDuration), encode(s.MaxReviseBatchSize), s.NetAddress, encode(s.RemainingStorage), encode(s.SectorSize), encode(s.TotalStorage), encode(s.Address), encode(s.WindowSize), encode(s.Collateral), encode(s.MaxCollateral), encode(s.BaseRPCPrice), encode(s.ContractPrice), encode(s.DownloadBandwidthPrice), encode(s.SectorAccessPrice), encode(s.StoragePrice), encode(s.UploadBandwidthPrice), s.EphemeralAccountExpiry, encode(s.MaxEphemeralAccountBalance), encode(s.RevisionNumber), s.Version, s.Release, s.SiaMuxPort, encode(p.UID), p.Validity, encode(p.HostBlockHeight), encode(p.UpdatePriceTableCost), encode(p.AccountBalanceCost), encode(p.FundAccountCost), encode(p.LatestRevisionCost), encode(p.SubscriptionMemoryCost), encode(p.SubscriptionNotificationCost), encode(p.InitBaseCost), encode(p.MemoryTimeCost), encode(p.DownloadBandwidthCost), encode(p.UploadBandwidthCost), encode(p.DropSectorsBaseCost), encode(p.DropSectorsUnitCost), encode(p.HasSectorBaseCost), encode(p.ReadBaseCost), encode(p.ReadLengthCost), encode(p.RenewContractCost), encode(p.RevisionBaseCost), encode(p.SwapSectorBaseCost), encode(p.WriteBaseCost), encode(p.WriteLengthCost), encode(p.WriteStoreCost), encode(p.TxnFeeMinRecommended), encode(p.TxnFeeMaxRecommended), encode(p.ContractPrice), encode(p.CollateralCost), encode(p.MaxCollateral), encode(p.MaxDuration), encode(p.WindowSize), encode(p.RegistryEntriesLeft), encode(p.RegistryEntriesTotal), encode(scan.PublicKey)); err != nil {
			return err
		}
	}
	return nil
}

// AddHostScans implements explorer.Store
func (s *Store) AddHostScans(scans []explorer.HostScan) error {
	return s.transaction(func(tx *txn) error {
		return addHostScans(tx, scans)
	})
}

// UpdateChainState implements explorer.Store
func (s *Store) UpdateChainState(reverted []chain.RevertUpdate, applied []chain.ApplyUpdate) error {
	return s.transaction(func(tx *txn) error {
		utx := &updateTx{
			tx: tx,
		}

		if err := explorer.UpdateChainState(utx, reverted, applied); err != nil {
			return fmt.Errorf("failed to update chain state: %w", err)
		}
		return nil
	})
}

// Tip implements explorer.Store.
func (s *Store) Tip() (result types.ChainIndex, err error) {
	const query = `SELECT id, height FROM blocks ORDER BY height DESC LIMIT 1`
	err = s.transaction(func(dbTxn *txn) error {
		return dbTxn.QueryRow(query).Scan(decode(&result.ID), &result.Height)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return types.ChainIndex{}, explorer.ErrNoTip
	}
	return
}
