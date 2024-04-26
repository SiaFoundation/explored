package sqlite

import (
	"database/sql"
	"errors"
	"fmt"

	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/chain"
	"go.sia.tech/explored/explorer"
)

type updateTx struct {
	tx                *txn
	relevantAddresses map[types.Address]bool
}

func (ut *updateTx) addBlock(b types.Block, height uint64) error {
	// nonce is encoded because database/sql doesn't support uint64 with high bit set
	_, err := ut.tx.Exec("INSERT INTO blocks(id, height, parent_id, nonce, timestamp) VALUES (?, ?, ?, ?, ?);", encode(b.ID()), height, encode(b.ParentID), encode(b.Nonce), encode(b.Timestamp))
	return err
}

func (ut *updateTx) addMinerPayouts(bid types.BlockID, height uint64, scos []types.SiacoinOutput, dbIDs map[types.SiacoinOutputID]int64) error {
	stmt, err := ut.tx.Prepare(`INSERT INTO miner_payouts(block_id, block_order, output_id) VALUES (?, ?, ?);`)
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

func (ut *updateTx) addArbitraryData(id int64, txn types.Transaction) error {
	stmt, err := ut.tx.Prepare(`INSERT INTO transaction_arbitrary_data(transaction_id, transaction_order, data) VALUES (?, ?, ?)`)

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

func (ut *updateTx) addSiacoinInputs(id int64, txn types.Transaction) error {
	stmt, err := ut.tx.Prepare(`INSERT INTO transaction_siacoin_inputs(transaction_id, transaction_order, parent_id, unlock_conditions) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addSiacoinInputs: failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for i, sci := range txn.SiacoinInputs {
		if _, err := stmt.Exec(id, i, encode(sci.ParentID), encode(sci.UnlockConditions)); err != nil {
			return fmt.Errorf("addSiacoinInputs: failed to execute statement: %w", err)
		}
	}
	return nil
}

func (ut *updateTx) addSiacoinOutputs(id int64, txn types.Transaction, dbIDs map[types.SiacoinOutputID]int64) error {
	stmt, err := ut.tx.Prepare(`INSERT INTO transaction_siacoin_outputs(transaction_id, transaction_order, output_id) VALUES (?, ?, ?)`)
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

func (ut *updateTx) addSiafundInputs(id int64, txn types.Transaction) error {
	stmt, err := ut.tx.Prepare(`INSERT INTO transaction_siafund_inputs(transaction_id, transaction_order, parent_id, unlock_conditions, claim_address) VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addSiafundInputs: failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for i, sci := range txn.SiafundInputs {
		if _, err := stmt.Exec(id, i, encode(sci.ParentID), encode(sci.UnlockConditions), encode(sci.ClaimAddress)); err != nil {
			return fmt.Errorf("addSiafundInputs: failed to execute statement: %w", err)
		}
	}
	return nil
}

func (ut *updateTx) addSiafundOutputs(id int64, txn types.Transaction, dbIDs map[types.SiafundOutputID]int64) error {
	stmt, err := ut.tx.Prepare(`INSERT INTO transaction_siafund_outputs(transaction_id, transaction_order, output_id) VALUES (?, ?, ?)`)
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

func (ut *updateTx) addFileContracts(id int64, txn types.Transaction, fcDBIds map[explorer.DBFileContract]int64) error {
	stmt, err := ut.tx.Prepare(`INSERT INTO transaction_file_contracts(transaction_id, transaction_order, contract_id) VALUES (?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addFileContracts: failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	validOutputsStmt, err := ut.tx.Prepare(`INSERT INTO file_contract_valid_proof_outputs(contract_id, contract_order, address, value) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addFileContracts: failed to prepare valid proof outputs statement: %w", err)
	}
	defer validOutputsStmt.Close()

	missedOutputsStmt, err := ut.tx.Prepare(`INSERT INTO file_contract_missed_proof_outputs(contract_id, contract_order, address, value) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addFileContracts: failed to prepare missed proof outputs statement: %w", err)
	}
	defer missedOutputsStmt.Close()

	for i := range txn.FileContracts {
		dbID, ok := fcDBIds[explorer.DBFileContract{ID: txn.FileContractID(i), RevisionNumber: 0}]
		if !ok {
			return errors.New("addFileContracts: fcDbID not in map")
		}

		if _, err := stmt.Exec(id, i, dbID); err != nil {
			return fmt.Errorf("addFileContracts: failed to execute transaction_file_contracts statement: %w", err)
		}

		for j, sco := range txn.FileContracts[i].ValidProofOutputs {
			if _, err := validOutputsStmt.Exec(dbID, j, encode(sco.Address), encode(sco.Value)); err != nil {
				return fmt.Errorf("addFileContracts: failed to execute valid proof outputs statement: %w", err)
			}
		}

		for j, sco := range txn.FileContracts[i].MissedProofOutputs {
			if _, err := missedOutputsStmt.Exec(dbID, j, encode(sco.Address), encode(sco.Value)); err != nil {
				return fmt.Errorf("addFileContracts: failed to execute missed proof outputs statement: %w", err)
			}
		}
	}
	return nil
}

func (ut *updateTx) addFileContractRevisions(id int64, txn types.Transaction, dbIDs map[explorer.DBFileContract]int64) error {
	stmt, err := ut.tx.Prepare(`INSERT INTO transaction_file_contract_revisions(transaction_id, transaction_order, contract_id, parent_id, unlock_conditions) VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addFileContractRevisions: failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	validOutputsStmt, err := ut.tx.Prepare(`INSERT INTO file_contract_valid_proof_outputs(contract_id, contract_order, address, value) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addFileContracts: failed to prepare valid proof outputs statement: %w", err)
	}
	defer validOutputsStmt.Close()

	missedOutputsStmt, err := ut.tx.Prepare(`INSERT INTO file_contract_missed_proof_outputs(contract_id, contract_order, address, value) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addFileContracts: failed to prepare missed proof outputs statement: %w", err)
	}
	defer missedOutputsStmt.Close()

	for i := range txn.FileContractRevisions {
		fcr := &txn.FileContractRevisions[i]
		dbID, ok := dbIDs[explorer.DBFileContract{ID: fcr.ParentID, RevisionNumber: fcr.FileContract.RevisionNumber}]
		if !ok {
			return errors.New("addFileContractRevisions: dbID not in map")
		}

		if _, err := stmt.Exec(id, i, dbID, encode(fcr.ParentID), encode(fcr.UnlockConditions)); err != nil {
			return fmt.Errorf("addFileContractRevisions: failed to execute statement: %w", err)
		}

		for j, sco := range txn.FileContractRevisions[i].ValidProofOutputs {
			if _, err := validOutputsStmt.Exec(dbID, j, encode(sco.Address), encode(sco.Value)); err != nil {
				return fmt.Errorf("addFileContractRevisions: failed to execute valid proof outputs statement: %w", err)
			}
		}

		for j, sco := range txn.FileContractRevisions[i].MissedProofOutputs {
			if _, err := missedOutputsStmt.Exec(dbID, j, encode(sco.Address), encode(sco.Value)); err != nil {
				return fmt.Errorf("addFileContractRevisions: failed to execute missed proof outputs statement: %w", err)
			}
		}
	}

	return nil
}

func (ut *updateTx) addTransactions(bid types.BlockID, txns []types.Transaction, scDBIds map[types.SiacoinOutputID]int64, sfDBIds map[types.SiafundOutputID]int64, fcDBIds map[explorer.DBFileContract]int64) error {
	insertTransactionStmt, err := ut.tx.Prepare(`INSERT INTO transactions (transaction_id) VALUES (?)
	ON CONFLICT (transaction_id) DO UPDATE SET transaction_id=EXCLUDED.transaction_id -- technically a no-op, but necessary for the RETURNING clause
	RETURNING id;`)
	if err != nil {
		return fmt.Errorf("failed to prepare insert transaction statement: %v", err)
	}
	defer insertTransactionStmt.Close()

	blockTransactionsStmt, err := ut.tx.Prepare(`INSERT INTO block_transactions(block_id, transaction_id, block_order) VALUES (?, ?, ?);`)
	if err != nil {
		return fmt.Errorf("failed to prepare block_transactions statement: %w", err)
	}
	defer blockTransactionsStmt.Close()

	for i, txn := range txns {
		var txnID int64
		err := insertTransactionStmt.QueryRow(encode(txn.ID())).Scan(&txnID)
		if err != nil {
			return fmt.Errorf("failed to insert into transactions: %w", err)
		}

		if _, err := blockTransactionsStmt.Exec(encode(bid), txnID, i); err != nil {
			return fmt.Errorf("failed to insert into block_transactions: %w", err)
		} else if err := ut.addArbitraryData(txnID, txn); err != nil {
			return fmt.Errorf("failed to add arbitrary data: %w", err)
		} else if err := ut.addSiacoinInputs(txnID, txn); err != nil {
			return fmt.Errorf("failed to add siacoin inputs: %w", err)
		} else if err := ut.addSiacoinOutputs(txnID, txn, scDBIds); err != nil {
			return fmt.Errorf("failed to add siacoin outputs: %w", err)
		} else if err := ut.addSiafundInputs(txnID, txn); err != nil {
			return fmt.Errorf("failed to add siafund inputs: %w", err)
		} else if err := ut.addSiafundOutputs(txnID, txn, sfDBIds); err != nil {
			return fmt.Errorf("failed to add siafund outputs: %w", err)
		} else if err := ut.addFileContracts(txnID, txn, fcDBIds); err != nil {
			return fmt.Errorf("failed to add file contract: %w", err)
		} else if err := ut.addFileContractRevisions(txnID, txn, fcDBIds); err != nil {
			return fmt.Errorf("failed to add file contract revisions: %w", err)
		}
	}
	return nil
}

type balance struct {
	sc         types.Currency
	immatureSC types.Currency
	sf         uint64
}

func (ut *updateTx) updateBalances(height uint64, spentSiacoinElements, newSiacoinElements []explorer.SiacoinOutput, spentSiafundElements, newSiafundElements []types.SiafundElement) error {
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

	var addressList []any
	for address := range addresses {
		addressList = append(addressList, encode(address))
	}

	rows, err := ut.tx.Query(`SELECT address, siacoin_balance, immature_siacoin_balance, siafund_balance
               FROM address_balance
               WHERE address IN (`+queryPlaceHolders(len(addressList))+`)`, addressList...)
	if err != nil {
		return fmt.Errorf("updateBalances: failed to query address_balance: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var bal balance
		var address types.Address
		if err := rows.Scan(decode(&address), decode(&bal.sc), decode(&bal.immatureSC), decode(&bal.sf)); err != nil {
			return err
		}
		addresses[address] = bal
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

	stmt, err := ut.tx.Prepare(`INSERT INTO address_balance(address, siacoin_balance, immature_siacoin_balance, siafund_balance)
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

func (ut *updateTx) updateMaturedBalances(revert bool, height uint64) error {
	// Prevent double counting - outputs with a maturity height of 0 are
	// handled in updateBalances
	if height == 0 {
		return nil
	}

	rows, err := ut.tx.Query(`SELECT address, value
			FROM siacoin_elements
			WHERE maturity_height = ?`, height)
	if err != nil {
		return fmt.Errorf("updateMaturedBalances: failed to query siacoin_elements: %w", err)
	}
	defer rows.Close()

	var addressList []any
	var scos []types.SiacoinOutput
	for rows.Next() {
		var sco types.SiacoinOutput
		if err := rows.Scan(decode(&sco.Address), decode(&sco.Value)); err != nil {
			return fmt.Errorf("updateMaturedBalances: failed to scan maturing outputs: %w", err)
		}
		scos = append(scos, sco)
		addressList = append(addressList, encode(sco.Address))
	}

	balanceRows, err := ut.tx.Query(`SELECT address, siacoin_balance, immature_siacoin_balance
		FROM address_balance
		WHERE address IN (`+queryPlaceHolders(len(addressList))+`)`, addressList...)
	if err != nil {
		return fmt.Errorf("updateMaturedBalances: failed to query address_balance: %w", err)
	}
	defer balanceRows.Close()

	addresses := make(map[types.Address]balance)
	for balanceRows.Next() {
		var address types.Address
		var bal balance
		if err := balanceRows.Scan(decode(&address), decode(&bal.sc), decode(&bal.immatureSC)); err != nil {
			return fmt.Errorf("updateMaturedBalances: failed to scan balance: %w", err)
		}
		addresses[address] = bal
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

	stmt, err := ut.tx.Prepare(`INSERT INTO address_balance(address, siacoin_balance, immature_siacoin_balance, siafund_balance)
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

func (ut *updateTx) updateStateTree(changes []explorer.TreeNodeUpdate) error {
	stmt, err := ut.tx.Prepare(`INSERT INTO state_tree (row, column, value) VALUES($1, $2, $3) ON CONFLICT (row, column) DO UPDATE SET value=EXCLUDED.value;`)
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

func (ut *updateTx) addSiacoinElements(bid types.BlockID, spentElements, newElements []explorer.SiacoinOutput) (map[types.SiacoinOutputID]int64, error) {
	stmt, err := ut.tx.Prepare(`INSERT INTO siacoin_elements(output_id, block_id, leaf_index, spent, source, maturity_height, address, value)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (output_id)
			DO UPDATE SET spent = ?, leaf_index = ?`)
	if err != nil {
		return nil, fmt.Errorf("addSiacoinElements: failed to prepare siacoin_elements statement: %w", err)
	}
	defer stmt.Close()

	scDBIds := make(map[types.SiacoinOutputID]int64)
	for _, sce := range newElements {
		result, err := stmt.Exec(encode(sce.StateElement.ID), encode(bid), encode(sce.StateElement.LeafIndex), false, int(sce.Source), sce.MaturityHeight, encode(sce.SiacoinOutput.Address), encode(sce.SiacoinOutput.Value), false, encode(sce.StateElement.LeafIndex))
		if err != nil {
			return nil, fmt.Errorf("addSiacoinElements: failed to execute siacoin_elements statement: %w", err)
		}

		dbID, err := result.LastInsertId()
		if err != nil {
			return nil, fmt.Errorf("addSiacoinElements: failed to get last insert ID: %w", err)
		}

		scDBIds[types.SiacoinOutputID(sce.StateElement.ID)] = dbID
	}
	for _, sce := range spentElements {
		result, err := stmt.Exec(encode(sce.StateElement.ID), encode(bid), encode(sce.StateElement.LeafIndex), true, int(sce.Source), sce.MaturityHeight, encode(sce.SiacoinOutput.Address), encode(sce.SiacoinOutput.Value), true, encode(sce.StateElement.LeafIndex))
		if err != nil {
			return nil, fmt.Errorf("addSiacoinElements: failed to execute siacoin_elements statement: %w", err)
		}

		dbID, err := result.LastInsertId()
		if err != nil {
			return nil, fmt.Errorf("addSiacoinElements: failed to get last insert ID: %w", err)
		}

		scDBIds[types.SiacoinOutputID(sce.StateElement.ID)] = dbID
	}

	return scDBIds, nil
}

func (ut *updateTx) addSiafundElements(bid types.BlockID, spentElements, newElements []types.SiafundElement) (map[types.SiafundOutputID]int64, error) {
	stmt, err := ut.tx.Prepare(`INSERT INTO siafund_elements(output_id, block_id, leaf_index, spent, claim_start, address, value)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT
		DO UPDATE SET spent = ?, leaf_index = ?`)
	if err != nil {
		return nil, fmt.Errorf("addSiafundElements: failed to prepare siafund_elements statement: %w", err)
	}
	defer stmt.Close()

	sfDBIds := make(map[types.SiafundOutputID]int64)
	for _, sfe := range newElements {
		result, err := stmt.Exec(encode(sfe.StateElement.ID), encode(bid), encode(sfe.StateElement.LeafIndex), false, encode(sfe.ClaimStart), encode(sfe.SiafundOutput.Address), encode(sfe.SiafundOutput.Value), false, encode(sfe.StateElement.LeafIndex))
		if err != nil {
			return nil, fmt.Errorf("addSiafundElements: failed to execute siafund_elements statement: %w", err)
		}

		dbID, err := result.LastInsertId()
		if err != nil {
			return nil, fmt.Errorf("addSiafundElements: failed to get last insert ID: %w", err)
		}

		sfDBIds[types.SiafundOutputID(sfe.StateElement.ID)] = dbID
	}
	for _, sfe := range spentElements {
		result, err := stmt.Exec(encode(sfe.StateElement.ID), encode(bid), encode(sfe.StateElement.LeafIndex), true, encode(sfe.ClaimStart), encode(sfe.SiafundOutput.Address), encode(sfe.SiafundOutput.Value), true, encode(sfe.StateElement.LeafIndex))
		if err != nil {
			return nil, fmt.Errorf("addSiafundElements: failed to execute siafund_elements statement: %w", err)
		}

		dbID, err := result.LastInsertId()
		if err != nil {
			return nil, fmt.Errorf("addSiafundElements: failed to get last insert ID: %w", err)
		}

		sfDBIds[types.SiafundOutputID(sfe.StateElement.ID)] = dbID
	}

	return sfDBIds, nil
}

func (ut *updateTx) deleteBlock(bid types.BlockID) error {
	_, err := ut.tx.Exec("DELETE FROM blocks WHERE id = ?", encode(bid))
	return err
}

func (ut *updateTx) addFileContractElements(bid types.BlockID, fces []explorer.FileContractUpdate) (map[explorer.DBFileContract]int64, error) {
	stmt, err := ut.tx.Prepare(`INSERT INTO file_contract_elements(block_id, contract_id, leaf_index, resolved, valid, filesize, file_merkle_root, window_start, window_end, payout, unlock_hash, revision_number)
		VALUES (?, ?, ?, FALSE, TRUE, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (contract_id, revision_number)
		DO UPDATE SET resolved = ?, valid = ?, leaf_index = ?
		RETURNING id;`)
	if err != nil {
		return nil, fmt.Errorf("addFileContractElements: failed to prepare file_contract_elements statement: %w", err)
	}
	defer stmt.Close()

	revisionStmt, err := ut.tx.Prepare(`INSERT INTO last_contract_revision(contract_id, contract_element_id)
	VALUES (?, ?)
	ON CONFLICT (contract_id)
	DO UPDATE SET contract_element_id = ?`)
	if err != nil {
		return nil, fmt.Errorf("addFileContractElements: failed to prepare last_contract_revision statement: %w", err)
	}

	var updateErr error
	fcDBIds := make(map[explorer.DBFileContract]int64)
	for _, update := range fces {
		fce := update.FileContractElement

		fc := &fce.FileContract
		if update.Revision != nil {
			fc = &update.Revision.FileContract
		}

		var dbID int64
		err := stmt.QueryRow(encode(bid), encode(fce.StateElement.ID), encode(fce.StateElement.LeafIndex), fc.Filesize, encode(fc.FileMerkleRoot), fc.WindowStart, fc.WindowEnd, encode(fc.Payout), encode(fc.UnlockHash), fc.RevisionNumber, update.Resolved, update.Valid, encode(fce.StateElement.LeafIndex)).Scan(&dbID)
		if err != nil {
			return nil, fmt.Errorf("addFileContractElements: failed to execute file_contract_elements statement: %w", err)
		}

		if _, err := revisionStmt.Exec(encode(fce.StateElement.ID), dbID, dbID); err != nil {
			return nil, fmt.Errorf("addFileContractElements: failed to update last revision number: %w", err)
		}

		fcDBIds[explorer.DBFileContract{ID: types.FileContractID(fce.StateElement.ID), RevisionNumber: fc.RevisionNumber}] = dbID
	}
	return fcDBIds, updateErr
}

func (ut *updateTx) ApplyIndex(state explorer.UpdateState) error {
	if err := ut.addBlock(state.Block, state.Index.Height); err != nil {
		return fmt.Errorf("ApplyIndex: failed to add block: %w", err)
	} else if err := ut.updateMaturedBalances(false, state.Index.Height); err != nil {
		return fmt.Errorf("ApplyIndex: failed to update matured balances: %w", err)
	}

	scDBIds, err := ut.addSiacoinElements(
		state.Block.ID(),
		append(state.SpentSiacoinElements, state.EphemeralSiacoinElements...),
		state.NewSiacoinElements,
	)
	if err != nil {
		return fmt.Errorf("ApplyIndex: failed to add siacoin outputs: %w", err)
	}
	sfDBIds, err := ut.addSiafundElements(
		state.Block.ID(),
		append(state.SpentSiafundElements, state.EphemeralSiafundElements...),
		state.NewSiafundElements,
	)
	if err != nil {
		return fmt.Errorf("ApplyIndex: failed to add siafund outputs: %w", err)
	}
	if err := ut.updateBalances(state.Index.Height, state.SpentSiacoinElements, state.NewSiacoinElements, state.SpentSiafundElements, state.NewSiafundElements); err != nil {
		return fmt.Errorf("ApplyIndex: failed to update balances: %w", err)
	}

	fcDBIds, err := ut.addFileContractElements(state.Block.ID(), state.FileContractElements)
	if err != nil {
		return fmt.Errorf("v: failed to add file contracts: %w", err)
	}

	if err := ut.addMinerPayouts(state.Block.ID(), state.Index.Height, state.Block.MinerPayouts, scDBIds); err != nil {
		return fmt.Errorf("ApplyIndex: failed to add miner payouts: %w", err)
	} else if err := ut.addTransactions(state.Block.ID(), state.Block.Transactions, scDBIds, sfDBIds, fcDBIds); err != nil {
		return fmt.Errorf("ApplyIndex: failed to add transactions: addTransactions: %w", err)
	} else if err := ut.updateStateTree(state.TreeUpdates); err != nil {
		return fmt.Errorf("ApplyIndex: failed to update state tree: %w", err)
	}

	return nil
}

func (ut *updateTx) RevertIndex(state explorer.UpdateState) error {
	if err := ut.updateMaturedBalances(true, state.Index.Height); err != nil {
		return fmt.Errorf("RevertIndex: failed to update matured balances: %w", err)
	} else if _, err := ut.addSiacoinElements(
		state.Block.ID(),
		state.SpentSiacoinElements,
		append(state.NewSiacoinElements, state.EphemeralSiacoinElements...),
	); err != nil {
		return fmt.Errorf("RevertIndex: failed to update siacoin output state: %w", err)
	} else if _, err := ut.addSiafundElements(
		state.Block.ID(),
		state.SpentSiafundElements,
		append(state.NewSiafundElements, state.EphemeralSiafundElements...),
	); err != nil {
		return fmt.Errorf("RevertIndex: failed to update siafund output state: %w", err)
	} else if err := ut.updateBalances(state.Index.Height, state.SpentSiacoinElements, state.NewSiacoinElements, state.SpentSiafundElements, state.NewSiafundElements); err != nil {
		return fmt.Errorf("RevertIndex: failed to update balances: %w", err)
	} else if _, err := ut.addFileContractElements(state.Block.ID(), state.FileContractElements); err != nil {
		return fmt.Errorf("RevertIndex: failed to update file contract state: %w", err)
	} else if err := ut.deleteBlock(state.Block.ID()); err != nil {
		return fmt.Errorf("RevertIndex: failed to delete block: %w", err)
	} else if err := ut.updateStateTree(state.TreeUpdates); err != nil {
		return fmt.Errorf("RevertIndex: failed to update state tree: %w", err)
	}

	return nil
}

// UpdateChainState implements explorer.Store
func (s *Store) UpdateChainState(reverted []chain.RevertUpdate, applied []chain.ApplyUpdate) error {
	return s.transaction(func(tx *txn) error {
		utx := &updateTx{
			tx:                tx,
			relevantAddresses: make(map[types.Address]bool),
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
