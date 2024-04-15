package sqlite

import (
	"database/sql"
	"errors"
	"fmt"

	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/chain"
	"go.sia.tech/explored/explorer"
)

func (s *Store) addBlock(dbTxn txn, b types.Block, height uint64) error {
	// nonce is encoded because database/sql doesn't support uint64 with high bit set
	_, err := dbTxn.Exec("INSERT INTO blocks(id, height, parent_id, nonce, timestamp) VALUES (?, ?, ?, ?, ?);", dbEncode(b.ID()), height, dbEncode(b.ParentID), dbEncode(b.Nonce), dbEncode(b.Timestamp))
	return err
}

func (s *Store) addMinerPayouts(dbTxn txn, bid types.BlockID, height uint64, scos []types.SiacoinOutput, dbIDs map[types.SiacoinOutputID]int64) error {
	stmt, err := dbTxn.Prepare(`INSERT INTO miner_payouts(block_id, block_order, output_id) VALUES (?, ?, ?);`)
	if err != nil {
		return fmt.Errorf("addMinerPayouts: failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for i := range scos {
		dbID, ok := dbIDs[bid.MinerOutputID(i)]
		if !ok {
			return errors.New("addMinerPayouts: dbID not in map")
		}

		if _, err := stmt.Exec(dbEncode(bid), i, dbID); err != nil {
			return fmt.Errorf("addMinerPayouts: failed to execute statement: %w", err)
		}
	}
	return nil
}

func (s *Store) addArbitraryData(dbTxn txn, id int64, txn types.Transaction) error {
	stmt, err := dbTxn.Prepare(`INSERT INTO transaction_arbitrary_data(transaction_id, transaction_order, data) VALUES (?, ?, ?)`)
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

func (s *Store) addSiacoinInputs(dbTxn txn, id int64, txn types.Transaction) error {
	stmt, err := dbTxn.Prepare(`INSERT INTO transaction_siacoin_inputs(transaction_id, transaction_order, parent_id, unlock_conditions) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addSiacoinInputs: failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for i, sci := range txn.SiacoinInputs {
		if _, err := stmt.Exec(id, i, dbEncode(sci.ParentID), dbEncode(sci.UnlockConditions)); err != nil {
			return fmt.Errorf("addSiacoinInputs: failed to execute statement: %w", err)
		}
	}
	return nil
}

func (s *Store) addSiacoinOutputs(dbTxn txn, id int64, txn types.Transaction, dbIDs map[types.SiacoinOutputID]int64) error {
	stmt, err := dbTxn.Prepare(`INSERT INTO transaction_siacoin_outputs(transaction_id, transaction_order, output_id) VALUES (?, ?, ?)`)
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

func (s *Store) addSiafundInputs(dbTxn txn, id int64, txn types.Transaction) error {
	stmt, err := dbTxn.Prepare(`INSERT INTO transaction_siafund_inputs(transaction_id, transaction_order, parent_id, unlock_conditions, claim_address) VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addSiafundInputs: failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for i, sci := range txn.SiafundInputs {
		if _, err := stmt.Exec(id, i, dbEncode(sci.ParentID), dbEncode(sci.UnlockConditions), dbEncode(sci.ClaimAddress)); err != nil {
			return fmt.Errorf("addSiafundInputs: failed to execute statement: %w", err)
		}
	}
	return nil
}

func (s *Store) addSiafundOutputs(dbTxn txn, id int64, txn types.Transaction, dbIDs map[types.SiafundOutputID]int64) error {
	stmt, err := dbTxn.Prepare(`INSERT INTO transaction_siafund_outputs(transaction_id, transaction_order, output_id) VALUES (?, ?, ?)`)
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

func (s *Store) addFileContracts(dbTxn txn, id int64, txn types.Transaction, fcDBIds map[fileContract]int64) error {
	stmt, err := dbTxn.Prepare(`INSERT INTO transaction_file_contracts(transaction_id, transaction_order, contract_id) VALUES (?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addFileContracts: failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	validOutputsStmt, err := dbTxn.Prepare(`INSERT INTO file_contract_valid_proof_outputs(contract_id, contract_order, address, value) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addFileContracts: failed to prepare valid proof outputs statement: %w", err)
	}
	defer validOutputsStmt.Close()

	missedOutputsStmt, err := dbTxn.Prepare(`INSERT INTO file_contract_missed_proof_outputs(contract_id, contract_order, address, value) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addFileContracts: failed to prepare missed proof outputs statement: %w", err)
	}
	defer missedOutputsStmt.Close()

	for i := range txn.FileContracts {
		dbID, ok := fcDBIds[fileContract{txn.FileContractID(i), 0}]
		if !ok {
			return errors.New("addFileContracts: fcDbID not in map")
		}

		if _, err := stmt.Exec(id, i, dbID); err != nil {
			return fmt.Errorf("addFileContracts: failed to execute transaction_file_contracts statement: %w", err)
		}

		for j, sco := range txn.FileContracts[i].ValidProofOutputs {
			if _, err := validOutputsStmt.Exec(dbID, j, dbEncode(sco.Address), dbEncode(sco.Value)); err != nil {
				return fmt.Errorf("addFileContracts: failed to execute valid proof outputs statement: %w", err)
			}
		}

		for j, sco := range txn.FileContracts[i].MissedProofOutputs {
			if _, err := missedOutputsStmt.Exec(dbID, j, dbEncode(sco.Address), dbEncode(sco.Value)); err != nil {
				return fmt.Errorf("addFileContracts: failed to execute missed proof outputs statement: %w", err)
			}
		}
	}
	return nil
}

func (s *Store) addFileContractRevisions(dbTxn txn, id int64, txn types.Transaction, dbIDs map[fileContract]int64) error {
	stmt, err := dbTxn.Prepare(`INSERT INTO transaction_file_contract_revisions(transaction_id, transaction_order, contract_id, parent_id, unlock_conditions) VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addFileContractRevisions: failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	validOutputsStmt, err := dbTxn.Prepare(`INSERT INTO file_contract_valid_proof_outputs(contract_id, contract_order, address, value) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addFileContracts: failed to prepare valid proof outputs statement: %w", err)
	}
	defer validOutputsStmt.Close()

	missedOutputsStmt, err := dbTxn.Prepare(`INSERT INTO file_contract_missed_proof_outputs(contract_id, contract_order, address, value) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addFileContracts: failed to prepare missed proof outputs statement: %w", err)
	}
	defer missedOutputsStmt.Close()

	for i := range txn.FileContractRevisions {
		fcr := &txn.FileContractRevisions[i]
		dbID, ok := dbIDs[fileContract{fcr.ParentID, fcr.FileContract.RevisionNumber}]
		if !ok {
			return errors.New("addFileContractRevisions: dbID not in map")
		}

		if _, err := stmt.Exec(id, i, dbID, dbEncode(fcr.ParentID), dbEncode(fcr.UnlockConditions)); err != nil {
			return fmt.Errorf("addFileContractRevisions: failed to execute statement: %w", err)
		}

		for j, sco := range txn.FileContractRevisions[i].ValidProofOutputs {
			if _, err := validOutputsStmt.Exec(dbID, j, dbEncode(sco.Address), dbEncode(sco.Value)); err != nil {
				return fmt.Errorf("addFileContractRevisions: failed to execute valid proof outputs statement: %w", err)
			}
		}

		for j, sco := range txn.FileContractRevisions[i].MissedProofOutputs {
			if _, err := missedOutputsStmt.Exec(dbID, j, dbEncode(sco.Address), dbEncode(sco.Value)); err != nil {
				return fmt.Errorf("addFileContractRevisions: failed to execute missed proof outputs statement: %w", err)
			}
		}
	}

	return nil
}

func (s *Store) addTransactions(dbTxn txn, bid types.BlockID, txns []types.Transaction, scDBIds map[types.SiacoinOutputID]int64, sfDBIds map[types.SiafundOutputID]int64, fcDBIds map[fileContract]int64) error {
	insertTransactionStmt, err := dbTxn.Prepare(`INSERT INTO transactions (transaction_id) VALUES (?)
	ON CONFLICT (transaction_id) DO UPDATE SET transaction_id=EXCLUDED.transaction_id -- technically a no-op, but necessary for the RETURNING clause
	RETURNING id;`)
	if err != nil {
		return fmt.Errorf("failed to prepare insert transaction statement: %v", err)
	}
	defer insertTransactionStmt.Close()

	blockTransactionsStmt, err := dbTxn.Prepare(`INSERT INTO block_transactions(block_id, transaction_id, block_order) VALUES (?, ?, ?);`)
	if err != nil {
		return fmt.Errorf("failed to prepare block_transactions statement: %w", err)
	}
	defer blockTransactionsStmt.Close()

	for i, txn := range txns {
		var txnID int64
		err := insertTransactionStmt.QueryRow(dbEncode(txn.ID())).Scan(&txnID)
		if err != nil {
			return fmt.Errorf("failed to insert into transactions: %w", err)
		}

		if _, err := blockTransactionsStmt.Exec(dbEncode(bid), txnID, i); err != nil {
			return fmt.Errorf("failed to insert into block_transactions: %w", err)
		} else if err := s.addArbitraryData(dbTxn, txnID, txn); err != nil {
			return fmt.Errorf("failed to add arbitrary data: %w", err)
		} else if err := s.addSiacoinInputs(dbTxn, txnID, txn); err != nil {
			return fmt.Errorf("failed to add siacoin inputs: %w", err)
		} else if err := s.addSiacoinOutputs(dbTxn, txnID, txn, scDBIds); err != nil {
			return fmt.Errorf("failed to add siacoin outputs: %w", err)
		} else if err := s.addSiafundInputs(dbTxn, txnID, txn); err != nil {
			return fmt.Errorf("failed to add siafund inputs: %w", err)
		} else if err := s.addSiafundOutputs(dbTxn, txnID, txn, sfDBIds); err != nil {
			return fmt.Errorf("failed to add siafund outputs: %w", err)
		} else if err := s.addFileContracts(dbTxn, txnID, txn, fcDBIds); err != nil {
			return fmt.Errorf("failed to add file contract: %w", err)
		} else if err := s.addFileContractRevisions(dbTxn, txnID, txn, fcDBIds); err != nil {
			return fmt.Errorf("failed to add file contract revisions: %w", err)
		}
	}
	return nil
}

type consensusUpdate interface {
	ForEachSiacoinElement(fn func(sce types.SiacoinElement, spent bool))
	ForEachSiafundElement(fn func(sfe types.SiafundElement, spent bool))
	ForEachFileContractElement(fn func(fce types.FileContractElement, rev *types.FileContractElement, resolved, valid bool))
}

type balance struct {
	sc         types.Currency
	immatureSC types.Currency
	sf         uint64
}

func (s *Store) updateBalances(dbTxn txn, height uint64, spentSiacoinElements, newSiacoinElements []types.SiacoinElement, spentSiafundElements, newSiafundElements []types.SiafundElement) error {
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
		addressList = append(addressList, dbEncode(address))
	}

	rows, err := dbTxn.Query(`SELECT address, siacoin_balance, immature_siacoin_balance, siafund_balance
               FROM address_balance
               WHERE address IN (`+queryPlaceHolders(len(addressList))+`)`, addressList...)
	if err != nil {
		return fmt.Errorf("updateBalances: failed to query address_balance: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var bal balance
		var address types.Address
		if err := rows.Scan(dbDecode(&address), dbDecode(&bal.sc), dbDecode(&bal.immatureSC), dbDecode(&bal.sf)); err != nil {
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

	stmt, err := dbTxn.Prepare(`INSERT INTO address_balance(address, siacoin_balance, immature_siacoin_balance, siafund_balance)
       VALUES (?, ?, ?, ?)
       ON CONFLICT(address)
       DO UPDATE set siacoin_balance = ?, immature_siacoin_balance = ?, siafund_balance = ?`)
	if err != nil {
		return fmt.Errorf("updateBalances: failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for addr, bal := range addresses {
		if _, err := stmt.Exec(dbEncode(addr), dbEncode(bal.sc), dbEncode(bal.immatureSC), dbEncode(bal.sf), dbEncode(bal.sc), dbEncode(bal.immatureSC), dbEncode(bal.sf)); err != nil {
			return fmt.Errorf("updateBalances: failed to exec statement: %w", err)
		}
		// log.Println(addr, "=", bal.sc)
	}

	return nil
}

func (s *Store) updateMaturedBalances(dbTxn txn, revert bool, height uint64) error {
	// Prevent double counting - outputs with a maturity height of 0 are
	// handled in updateBalances
	if height == 0 {
		return nil
	}

	rows, err := dbTxn.Query(`SELECT address, value
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
		if err := rows.Scan(dbDecode(&sco.Address), dbDecode(&sco.Value)); err != nil {
			return fmt.Errorf("updateMaturedBalances: failed to scan maturing outputs: %w", err)
		}
		scos = append(scos, sco)
		addressList = append(addressList, dbEncode(sco.Address))
	}

	balanceRows, err := dbTxn.Query(`SELECT address, siacoin_balance, immature_siacoin_balance
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
		if err := balanceRows.Scan(dbDecode(&address), dbDecode(&bal.sc), dbDecode(&bal.immatureSC)); err != nil {
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

	stmt, err := dbTxn.Prepare(`INSERT INTO address_balance(address, siacoin_balance, immature_siacoin_balance, siafund_balance)
	VALUES (?, ?, ?, ?)
	ON CONFLICT(address)
	DO UPDATE set siacoin_balance = ?, immature_siacoin_balance = ?`)
	if err != nil {
		return fmt.Errorf("updateMaturedBalances: failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	initialSF := dbEncode(uint64(0))
	for addr, bal := range addresses {
		if _, err := stmt.Exec(dbEncode(addr), dbEncode(bal.sc), dbEncode(bal.immatureSC), initialSF, dbEncode(bal.sc), dbEncode(bal.immatureSC)); err != nil {
			return fmt.Errorf("updateMaturedBalances: failed to exec statement: %w", err)
		}
	}

	return nil
}

func (s *Store) addSiacoinElements(dbTxn txn, bid types.BlockID, update consensusUpdate, spentElements, newElements []types.SiacoinElement) (map[types.SiacoinOutputID]int64, error) {
	sources := make(map[types.SiacoinOutputID]explorer.Source)
	if applyUpdate, ok := update.(chain.ApplyUpdate); ok {
		block := applyUpdate.Block
		for i := range block.MinerPayouts {
			sources[bid.MinerOutputID(i)] = explorer.SourceMinerPayout
		}

		for _, txn := range block.Transactions {
			for i := range txn.SiacoinOutputs {
				sources[txn.SiacoinOutputID(i)] = explorer.SourceTransaction
			}

			for i := range txn.FileContracts {
				fcid := txn.FileContractID(i)
				for j := range txn.FileContracts[i].ValidProofOutputs {
					sources[fcid.ValidOutputID(j)] = explorer.SourceValidProofOutput
				}
				for j := range txn.FileContracts[i].MissedProofOutputs {
					sources[fcid.MissedOutputID(j)] = explorer.SourceMissedProofOutput
				}
			}
		}
	}

	stmt, err := dbTxn.Prepare(`INSERT INTO siacoin_elements(output_id, block_id, leaf_index, merkle_proof, spent, source, maturity_height, address, value)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (output_id)
			DO UPDATE SET spent = ?`)
	if err != nil {
		return nil, fmt.Errorf("addSiacoinElements: failed to prepare siacoin_elements statement: %w", err)
	}
	defer stmt.Close()

	scDBIds := make(map[types.SiacoinOutputID]int64)
	for _, sce := range newElements {
		result, err := stmt.Exec(dbEncode(sce.StateElement.ID), dbEncode(bid), dbEncode(sce.StateElement.LeafIndex), dbEncode(sce.StateElement.MerkleProof), false, int(sources[types.SiacoinOutputID(sce.StateElement.ID)]), sce.MaturityHeight, dbEncode(sce.SiacoinOutput.Address), dbEncode(sce.SiacoinOutput.Value), false)
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
		result, err := stmt.Exec(dbEncode(sce.StateElement.ID), dbEncode(bid), dbEncode(sce.StateElement.LeafIndex), dbEncode(sce.StateElement.MerkleProof), true, int(sources[types.SiacoinOutputID(sce.StateElement.ID)]), sce.MaturityHeight, dbEncode(sce.SiacoinOutput.Address), dbEncode(sce.SiacoinOutput.Value), true)
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

func (s *Store) addSiafundElements(dbTxn txn, bid types.BlockID, spentElements, newElements []types.SiafundElement) (map[types.SiafundOutputID]int64, error) {
	stmt, err := dbTxn.Prepare(`INSERT INTO siafund_elements(output_id, block_id, leaf_index, merkle_proof, spent, claim_start, address, value)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT
		DO UPDATE SET spent = ?`)
	if err != nil {
		return nil, fmt.Errorf("addSiafundElements: failed to prepare siafund_elements statement: %w", err)
	}
	defer stmt.Close()

	sfDBIds := make(map[types.SiafundOutputID]int64)
	for _, sfe := range newElements {
		result, err := stmt.Exec(dbEncode(sfe.StateElement.ID), dbEncode(bid), dbEncode(sfe.StateElement.LeafIndex), dbEncode(sfe.StateElement.MerkleProof), false, dbEncode(sfe.ClaimStart), dbEncode(sfe.SiafundOutput.Address), dbEncode(sfe.SiafundOutput.Value), false)
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
		result, err := stmt.Exec(dbEncode(sfe.StateElement.ID), dbEncode(bid), dbEncode(sfe.StateElement.LeafIndex), dbEncode(sfe.StateElement.MerkleProof), true, dbEncode(sfe.ClaimStart), dbEncode(sfe.SiafundOutput.Address), dbEncode(sfe.SiafundOutput.Value), true)
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

type fileContract struct {
	id             types.FileContractID
	revisionNumber uint64
}

func (s *Store) addFileContractElements(dbTxn txn, bid types.BlockID, update consensusUpdate) (map[fileContract]int64, error) {
	stmt, err := dbTxn.Prepare(`INSERT INTO file_contract_elements(block_id, contract_id, leaf_index, merkle_proof, resolved, valid, filesize, file_merkle_root, window_start, window_end, payout, unlock_hash, revision_number)
		VALUES (?, ?, ?, ?, FALSE, TRUE, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (contract_id, revision_number)
		DO UPDATE SET resolved = ?, valid = ?
		RETURNING id;`)
	if err != nil {
		return nil, fmt.Errorf("addFileContractElements: failed to prepare file_contract_elements statement: %w", err)
	}
	defer stmt.Close()

	revisionStmt, err := dbTxn.Prepare(`INSERT INTO last_contract_revision(contract_id, contract_element_id)
	VALUES (?, ?)
	ON CONFLICT (contract_id)
	DO UPDATE SET contract_element_id = ?`)
	if err != nil {
		return nil, fmt.Errorf("addFileContractElements: failed to prepare last_contract_revision statement: %w", err)
	}

	var updateErr error
	fcDBIds := make(map[fileContract]int64)
	update.ForEachFileContractElement(func(fce types.FileContractElement, rev *types.FileContractElement, resolved, valid bool) {
		if updateErr != nil {
			return
		}

		fc := &fce.FileContract
		if rev != nil {
			fc = &rev.FileContract
		}

		var dbID int64
		err := stmt.QueryRow(dbEncode(bid), dbEncode(fce.StateElement.ID), dbEncode(fce.StateElement.LeafIndex), dbEncode(fce.StateElement.MerkleProof), fc.Filesize, dbEncode(fc.FileMerkleRoot), fc.WindowStart, fc.WindowEnd, dbEncode(fc.Payout), dbEncode(fc.UnlockHash), fc.RevisionNumber, resolved, valid).Scan(&dbID)
		if err != nil {
			updateErr = fmt.Errorf("addFileContractElements: failed to execute file_contract_elements statement: %w", err)
			return
		}

		if _, err := revisionStmt.Exec(dbEncode(fce.StateElement.ID), dbID, dbID); err != nil {
			updateErr = fmt.Errorf("addFileContractElements: failed to update last revision number: %w", err)
			return
		}

		fcDBIds[fileContract{types.FileContractID(fce.StateElement.ID), fc.RevisionNumber}] = dbID
	})
	return fcDBIds, updateErr
}

func (s *Store) deleteBlock(dbTxn txn, bid types.BlockID) error {
	_, err := dbTxn.Exec("DELETE FROM blocks WHERE id = ?", dbEncode(bid))
	return err
}

// ProcessChainUpdates implements explorer.Store.
func (s *Store) ProcessChainUpdates(crus []chain.RevertUpdate, caus []chain.ApplyUpdate) error {
	return s.transaction(func(dbTxn txn) error {
		for _, cru := range crus {
			if err := s.updateMaturedBalances(dbTxn, true, cru.State.Index.Height+1); err != nil {
				return fmt.Errorf("revertUpdate: failed to update matured balances: %w", err)
			}

			created := make(map[types.Hash256]bool)
			ephemeral := make(map[types.Hash256]bool)
			for _, txn := range cru.Block.Transactions {
				for i := range txn.SiacoinOutputs {
					created[types.Hash256(txn.SiacoinOutputID(i))] = true
				}
				for _, input := range txn.SiacoinInputs {
					ephemeral[types.Hash256(input.ParentID)] = created[types.Hash256(input.ParentID)]
				}
				for i := range txn.SiafundOutputs {
					created[types.Hash256(txn.SiafundOutputID(i))] = true
				}
				for _, input := range txn.SiafundInputs {
					ephemeral[types.Hash256(input.ParentID)] = created[types.Hash256(input.ParentID)]
				}
			}

			// add new siacoin elements to the store
			var newSiacoinElements, spentSiacoinElements []types.SiacoinElement
			var ephemeralSiacoinElements []types.SiacoinElement
			cru.ForEachSiacoinElement(func(se types.SiacoinElement, spent bool) {
				if ephemeral[se.ID] {
					ephemeralSiacoinElements = append(ephemeralSiacoinElements, se)
					return
				}

				if spent {
					newSiacoinElements = append(newSiacoinElements, se)
				} else {
					spentSiacoinElements = append(spentSiacoinElements, se)
				}
			})

			var newSiafundElements, spentSiafundElements []types.SiafundElement
			var ephemeralSiafundElements []types.SiafundElement
			cru.ForEachSiafundElement(func(se types.SiafundElement, spent bool) {
				if ephemeral[se.ID] {
					ephemeralSiafundElements = append(ephemeralSiafundElements, se)
					return
				}

				if spent {
					newSiafundElements = append(newSiafundElements, se)
				} else {
					spentSiafundElements = append(spentSiafundElements, se)
				}
			})

			// log.Println("REVERT!")
			if _, err := s.addSiacoinElements(
				dbTxn,
				cru.Block.ID(),
				cru,
				spentSiacoinElements,
				append(newSiacoinElements, ephemeralSiacoinElements...),
			); err != nil {
				return fmt.Errorf("revertUpdate: failed to update siacoin output state: %w", err)
			} else if _, err := s.addSiafundElements(
				dbTxn,
				cru.Block.ID(),
				spentSiafundElements,
				append(newSiafundElements, ephemeralSiafundElements...),
			); err != nil {
				return fmt.Errorf("revertUpdate: failed to update siafund output state: %w", err)
			} else if err := s.updateBalances(dbTxn, cru.State.Index.Height+1, spentSiacoinElements, newSiacoinElements, spentSiafundElements, newSiafundElements); err != nil {
				return fmt.Errorf("revertUpdate: failed to update balances: %w", err)
			} else if _, err := s.addFileContractElements(dbTxn, cru.Block.ID(), cru); err != nil {
				return fmt.Errorf("revertUpdate: failed to update file contract state: %w", err)
			} else if err := s.updateLeaves(dbTxn, cru); err != nil {
				return fmt.Errorf("revertUpdate: failed to update leaves: %w", err)
			} else if err := s.deleteBlock(dbTxn, cru.Block.ID()); err != nil {
				return fmt.Errorf("revertUpdate: failed to delete block: %w", err)
			}
		}

		for _, cau := range caus {
			if err := s.addBlock(dbTxn, cau.Block, cau.State.Index.Height); err != nil {
				return fmt.Errorf("applyUpdates: failed to add block: %w", err)
			} else if err := s.updateMaturedBalances(dbTxn, false, cau.State.Index.Height); err != nil {
				return fmt.Errorf("applyUpdates: failed to update matured balances: %w", err)
			}

			created := make(map[types.Hash256]bool)
			ephemeral := make(map[types.Hash256]bool)
			for _, txn := range cau.Block.Transactions {
				for i := range txn.SiacoinOutputs {
					created[types.Hash256(txn.SiacoinOutputID(i))] = true
				}
				for _, input := range txn.SiacoinInputs {
					ephemeral[types.Hash256(input.ParentID)] = created[types.Hash256(input.ParentID)]
				}
				for i := range txn.SiafundOutputs {
					created[types.Hash256(txn.SiafundOutputID(i))] = true
				}
				for _, input := range txn.SiafundInputs {
					ephemeral[types.Hash256(input.ParentID)] = created[types.Hash256(input.ParentID)]
				}
			}

			// add new siacoin elements to the store
			var newSiacoinElements, spentSiacoinElements []types.SiacoinElement
			var ephemeralSiacoinElements []types.SiacoinElement
			cau.ForEachSiacoinElement(func(se types.SiacoinElement, spent bool) {
				if ephemeral[se.ID] {
					ephemeralSiacoinElements = append(ephemeralSiacoinElements, se)
					return
				}

				if spent {
					spentSiacoinElements = append(spentSiacoinElements, se)
				} else {
					newSiacoinElements = append(newSiacoinElements, se)
				}
			})

			var newSiafundElements, spentSiafundElements []types.SiafundElement
			var ephemeralSiafundElements []types.SiafundElement
			cau.ForEachSiafundElement(func(se types.SiafundElement, spent bool) {
				if ephemeral[se.ID] {
					ephemeralSiafundElements = append(ephemeralSiafundElements, se)
					return
				}

				if spent {
					spentSiafundElements = append(spentSiafundElements, se)
				} else {
					newSiafundElements = append(newSiafundElements, se)
				}
			})

			scDBIds, err := s.addSiacoinElements(
				dbTxn,
				cau.Block.ID(),
				cau,
				append(spentSiacoinElements, ephemeralSiacoinElements...),
				newSiacoinElements,
			)
			if err != nil {
				return fmt.Errorf("applyUpdates: failed to add siacoin outputs: %w", err)
			}
			sfDBIds, err := s.addSiafundElements(
				dbTxn,
				cau.Block.ID(),
				append(spentSiafundElements, ephemeralSiafundElements...),
				newSiafundElements,
			)
			if err != nil {
				return fmt.Errorf("applyUpdates: failed to add siafund outputs: %w", err)
			}
			if err := s.updateBalances(dbTxn, cau.State.Index.Height, spentSiacoinElements, newSiacoinElements, spentSiafundElements, newSiafundElements); err != nil {
				return fmt.Errorf("applyUpdates: failed to update balances: %w", err)
			}

			fcDBIds, err := s.addFileContractElements(dbTxn, cau.Block.ID(), cau)
			if err != nil {
				return fmt.Errorf("applyUpdates: failed to add file contracts: %w", err)
			}

			if err := s.addMinerPayouts(dbTxn, cau.Block.ID(), cau.State.Index.Height, cau.Block.MinerPayouts, scDBIds); err != nil {
				return fmt.Errorf("applyUpdates: failed to add miner payouts: %w", err)
			} else if err := s.addTransactions(dbTxn, cau.Block.ID(), cau.Block.Transactions, scDBIds, sfDBIds, fcDBIds); err != nil {
				return fmt.Errorf("applyUpdates: failed to add transactions: addTransactions: %w", err)
			}

			if err := s.updateLeaves(dbTxn, cau); err != nil {
				return err
			}
		}
		return nil
	})
}

// Tip implements explorer.Store.
func (s *Store) Tip() (result types.ChainIndex, err error) {
	const query = `SELECT id, height FROM blocks ORDER BY height DESC LIMIT 1`
	err = s.transaction(func(dbTx txn) error {
		return dbTx.QueryRow(query).Scan(dbDecode(&result.ID), &result.Height)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return types.ChainIndex{}, explorer.ErrNoTip
	}
	return
}
