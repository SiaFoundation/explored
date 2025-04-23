package sqlite

import (
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"time"

	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/chain"
	"go.sia.tech/explored/explorer"
)

type updateTx struct {
	tx *txn
}

func addBlock(tx *txn, b types.Block, cie types.ChainIndexElement, height uint64) error {
	// nonce is encoded because database/sql doesn't support uint64 with high bit set
	var v2Height any
	var v2Commitment any
	if b.V2 != nil {
		v2Height = encode(b.V2.Height)
		v2Commitment = encode(b.V2.Commitment)
	}
	_, err := tx.Exec("INSERT INTO blocks(id, height, parent_id, nonce, timestamp, leaf_index, v2_height, v2_commitment) VALUES (?, ?, ?, ?, ?, ?, ?, ?);", encode(b.ID()), height, encode(b.ParentID), encode(b.Nonce), encode(b.Timestamp), encode(cie.StateElement.LeafIndex), v2Height, v2Commitment)
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
		var dbID int64
		txnID := txn.ID()
		if err := checkTransactionStmt.QueryRow(encode(txnID)).Scan(&dbID); err != nil && err != sql.ErrNoRows {
			return nil, fmt.Errorf("failed to check if transaction exists: %w", err)
		} else if err == nil {
			exist = true
		}

		if !exist {
			result, err := insertTransactionStmt.Exec(encode(txnID))
			if err != nil {
				return nil, fmt.Errorf("failed to insert into transactions: %w", err)
			}
			dbID, err = result.LastInsertId()
			if err != nil {
				return nil, fmt.Errorf("failed to get transaction ID: %w", err)
			}
		}

		// If we have the same transaction multiple times in one block, exist
		// will be true after the above query after the first time the
		// transaction is encountered by this loop. So we only set the value in
		// the map for each transaction once.
		if _, ok := txnDBIds[txnID]; !ok {
			txnDBIds[txnID] = txnDBId{id: dbID, exist: exist}
		}

		if _, err := blockTransactionsStmt.Exec(encode(bid), dbID, i); err != nil {
			return nil, fmt.Errorf("failed to insert into block_transactions: %w", err)
		}
	}

	return txnDBIds, nil
}

func addTransactionFields(tx *txn, txns []types.Transaction, scDBIds map[types.SiacoinOutputID]int64, sfDBIds map[types.SiafundOutputID]int64, fcDBIds map[explorer.DBFileContract]int64, txnDBIds map[types.TransactionID]txnDBId) error {
	for _, txn := range txns {
		txnID := txn.ID()
		dbID, ok := txnDBIds[txnID]
		if !ok {
			panic(fmt.Errorf("txn %v should be in txnDBIds", txn.ID()))
		}

		// transaction already exists, don't reinsert its fields
		if dbID.exist {
			continue
		}
		// set exist = true so we don't re-insert fields in case we have
		// multiple of the same transaction in a block
		txnDBIds[txnID] = txnDBId{id: dbID.id, exist: true}

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

func addHostAnnouncements(tx *txn, timestamp time.Time, hostAnnouncements []chain.HostAnnouncement, v2HostAnnouncements []explorer.V2HostAnnouncement) error {
	hosts := make([]explorer.Host, 0, len(hostAnnouncements)+len(v2HostAnnouncements))
	for _, announcement := range hostAnnouncements {
		hosts = append(hosts, explorer.Host{
			PublicKey:  announcement.PublicKey,
			NetAddress: announcement.NetAddress,

			KnownSince:       timestamp,
			LastAnnouncement: timestamp,
		})
	}
	for _, announcement := range v2HostAnnouncements {
		hosts = append(hosts, explorer.Host{
			PublicKey:      announcement.PublicKey,
			V2NetAddresses: []chain.NetAddress(announcement.V2HostAnnouncement),

			KnownSince:       timestamp,
			LastAnnouncement: timestamp,
		})
	}
	return addHosts(tx, hosts)
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
			if err := stmt.QueryRow(encode(sce.ID), encode(index.ID), encode(sce.StateElement.LeafIndex), int(sce.Source), sce.MaturityHeight, encode(sce.SiacoinOutput.Address), encode(sce.SiacoinOutput.Value), encode(sce.StateElement.LeafIndex)).Scan(&dbID); err != nil {
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

func addEvents(tx *txn, bid types.BlockID, scDBIds map[types.SiacoinOutputID]int64, sfDBIds map[types.SiafundOutputID]int64, fcDBIds map[explorer.DBFileContract]int64, v2FcDBIds map[explorer.DBFileContract]int64, txnDBIds map[types.TransactionID]txnDBId, v2TxnDBIds map[types.TransactionID]txnDBId, events []explorer.Event) error {
	if len(events) == 0 {
		return nil
	}

	insertEventStmt, err := tx.Prepare(`INSERT INTO events (event_id, maturity_height, date_created, event_type, block_id) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (event_id) DO NOTHING RETURNING id`)
	if err != nil {
		return fmt.Errorf("failed to prepare event statement: %w", err)
	}
	defer insertEventStmt.Close()

	addrStmt, err := tx.Prepare(`INSERT INTO address_balance (address, siacoin_balance, immature_siacoin_balance, siafund_balance) VALUES ($1, $2, $2, 0) ON CONFLICT (address) DO UPDATE SET address=EXCLUDED.address RETURNING id`)
	if err != nil {
		return fmt.Errorf("failed to prepare address statement: %w", err)
	}
	defer addrStmt.Close()

	relevantAddrStmt, err := tx.Prepare(`INSERT INTO event_addresses (event_id, address_id, event_maturity_height) VALUES ($1, $2, $3) ON CONFLICT (event_id, address_id) DO NOTHING`)
	if err != nil {
		return fmt.Errorf("failed to prepare relevant address statement: %w", err)
	}
	defer relevantAddrStmt.Close()

	v1TransactionEventStmt, err := tx.Prepare(`INSERT INTO v1_transaction_events (event_id, transaction_id) VALUES (?, ?)`)
	if err != nil {
		return fmt.Errorf("failed to prepare v1 transaction event statement: %w", err)
	}
	defer v1TransactionEventStmt.Close()

	v2TransactionEventStmt, err := tx.Prepare(`INSERT INTO v2_transaction_events (event_id, transaction_id) VALUES (?, ?)`)
	if err != nil {
		return fmt.Errorf("failed to prepare v2 transaction event statement: %w", err)
	}
	defer v2TransactionEventStmt.Close()

	payoutEventStmt, err := tx.Prepare(`INSERT INTO payout_events (event_id, output_id) VALUES (?, ?)`)
	if err != nil {
		return fmt.Errorf("failed to prepare minerpayout event statement: %w", err)
	}
	defer payoutEventStmt.Close()

	v1ContractResolutionEventStmt, err := tx.Prepare(`INSERT INTO v1_contract_resolution_events (event_id, output_id, parent_id, missed) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("failed to prepare v1 contract resolution event statement: %w", err)
	}
	defer v1ContractResolutionEventStmt.Close()

	v2ContractResolutionEventStmt, err := tx.Prepare(`INSERT INTO v2_contract_resolution_events (event_id, output_id, parent_id, missed) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("failed to prepare v2 contract resolution event statement: %w", err)
	}
	defer v2ContractResolutionEventStmt.Close()

	for _, event := range events {
		var eventID int64
		err = insertEventStmt.QueryRow(encode(event.ID), event.MaturityHeight, encode(event.Timestamp), event.Type, encode(bid)).Scan(&eventID)
		if errors.Is(err, sql.ErrNoRows) {
			continue // skip if the event already exists
		} else if err != nil {
			return fmt.Errorf("failed to add event: %w", err)
		}

		used := make(map[types.Address]bool)
		for _, addr := range event.Relevant {
			if used[addr] {
				continue
			}

			var addressID int64
			err = addrStmt.QueryRow(encode(addr), encode(types.ZeroCurrency)).Scan(&addressID)
			if err != nil {
				return fmt.Errorf("failed to get address: %w", err)
			}

			_, err = relevantAddrStmt.Exec(eventID, addressID, event.MaturityHeight)
			if err != nil {
				return fmt.Errorf("failed to add relevant address: %w", err)
			}

			used[addr] = true
		}

		switch v := event.Data.(type) {
		case explorer.EventV1Transaction:
			dbID := txnDBIds[types.TransactionID(event.ID)].id
			if _, err = v1TransactionEventStmt.Exec(eventID, dbID); err != nil {
				return fmt.Errorf("failed to insert transaction event: %w", err)
			}
		case explorer.EventV2Transaction:
			dbID := v2TxnDBIds[types.TransactionID(event.ID)].id
			if _, err = v2TransactionEventStmt.Exec(eventID, dbID); err != nil {
				return fmt.Errorf("failed to insert transaction event: %w", err)
			}
		case explorer.EventPayout:
			_, err = payoutEventStmt.Exec(eventID, scDBIds[types.SiacoinOutputID(event.ID)])
		case explorer.EventV1ContractResolution:
			_, err = v1ContractResolutionEventStmt.Exec(eventID, scDBIds[v.SiacoinElement.ID], fcDBIds[explorer.DBFileContract{ID: v.Parent.ID, RevisionNumber: v.Parent.RevisionNumber}], v.Missed)
		case explorer.EventV2ContractResolution:
			_, err = v2ContractResolutionEventStmt.Exec(eventID, scDBIds[v.SiacoinElement.ID], v2FcDBIds[explorer.DBFileContract{ID: v.Resolution.Parent.ID, RevisionNumber: v.Resolution.Parent.V2FileContract.RevisionNumber}], v.Missed)
		default:
			return fmt.Errorf("unknown event type: %T", reflect.TypeOf(event.Data))
		}
		if err != nil {
			return fmt.Errorf("failed to insert %v event: %w", reflect.TypeOf(event.Data), err)
		}
	}
	return nil
}

func deleteBlock(tx *txn, bid types.BlockID) error {
	_, err := tx.Exec("DELETE FROM blocks WHERE id = ?", encode(bid))
	return err
}

func updateFileContractElements(tx *txn, revert bool, index types.ChainIndex, b types.Block, fces []explorer.FileContractUpdate) (map[explorer.DBFileContract]int64, error) {
	stmt, err := tx.Prepare(`INSERT INTO file_contract_elements(contract_id, block_id, transaction_id, leaf_index, resolved, valid, filesize, file_merkle_root, window_start, window_end, payout, unlock_hash, revision_number)
        VALUES (?, ?, ?, ?, FALSE, FALSE, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (contract_id, revision_number)
        DO UPDATE SET resolved = ?, valid = ?, leaf_index = ?
        RETURNING id;`)
	if err != nil {
		return nil, fmt.Errorf("updateFileContractElements: failed to prepare main statement: %w", err)
	}
	defer stmt.Close()

	revisionStmt, err := tx.Prepare(`INSERT INTO last_contract_revision(contract_id, contract_element_id, ed25519_renter_key, ed25519_host_key, confirmation_height, confirmation_block_id, confirmation_transaction_id)
    VALUES (?, ?, ?, ?, COALESCE(?, X''), COALESCE(?, X''), COALESCE(?, X''))
    ON CONFLICT (contract_id)
    DO UPDATE SET contract_element_id = ?, ed25519_renter_key = COALESCE(?, ed25519_renter_key), ed25519_host_key = COALESCE(?, ed25519_host_key), confirmation_height = COALESCE(?, confirmation_height), confirmation_block_id = COALESCE(?, confirmation_block_id), confirmation_transaction_id = COALESCE(?, confirmation_transaction_id)`)
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
	addFC := func(fcID types.FileContractID, leafIndex uint64, fc types.FileContract, confirmationTransactionID *types.TransactionID, resolved, valid, lastRevision bool) error {
		var dbID int64
		dbFC := explorer.DBFileContract{ID: fcID, RevisionNumber: fc.RevisionNumber}
		err := stmt.QueryRow(encode(fcID), encode(index.ID), encode(fcTxns[dbFC]), encode(leafIndex), encode(fc.Filesize), encode(fc.FileMerkleRoot), encode(fc.WindowStart), encode(fc.WindowEnd), encode(fc.Payout), encode(fc.UnlockHash), encode(fc.RevisionNumber), resolved, valid, encode(leafIndex)).Scan(&dbID)
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
			var encodedRenterKey, encodedHostKey []byte
			if keys, ok := fcKeys[dbFC]; ok {
				encodedRenterKey = encode(keys[0]).([]byte)
				encodedHostKey = encode(keys[1]).([]byte)
			}

			var encodedHeight, encodedBlockID, encodedConfirmationTransactionID []byte
			if confirmationTransactionID != nil {
				encodedHeight = encode(index.Height).([]byte)
				encodedBlockID = encode(index.ID).([]byte)
				encodedConfirmationTransactionID = encode(*confirmationTransactionID).([]byte)
			}

			if _, err := revisionStmt.Exec(encode(fcID), dbID, encodedRenterKey, encodedHostKey, encodedHeight, encodedBlockID, encodedConfirmationTransactionID, dbID, encodedRenterKey, encodedHostKey, encodedHeight, encodedBlockID, encodedConfirmationTransactionID); err != nil {
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
			update.ConfirmationTransactionID,
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
		// add in any contracts that are not the latest, i.e. contracts that
		// were created and revised in the same block
		for j, fc := range txn.FileContracts {
			fcID := txn.FileContractID(j)
			dbFC := explorer.DBFileContract{ID: txn.FileContractID(j), RevisionNumber: fc.RevisionNumber}
			if _, exists := fcDBIds[dbFC]; exists {
				continue
			}

			if err := addFC(fcID, 0, fc, nil, false, false, false); err != nil {
				return nil, fmt.Errorf("updateFileContractElements: %w", err)
			}
		}
		// add in any revisions that are not the latest, i.e. contracts that
		// were revised multiple times in one block
		for _, fcr := range txn.FileContractRevisions {
			fc := fcr.FileContract
			dbFC := explorer.DBFileContract{ID: fcr.ParentID, RevisionNumber: fc.RevisionNumber}
			if _, exists := fcDBIds[dbFC]; exists {
				continue
			}

			if err := addFC(fcr.ParentID, 0, fc, nil, false, false, false); err != nil {
				return nil, fmt.Errorf("updateFileContractElements: %w", err)
			}
		}
	}

	return fcDBIds, nil
}

func updateFileContractIndices(tx *txn, revert bool, index types.ChainIndex, fces []explorer.FileContractUpdate) error {
	proofIndexStmt, err := tx.Prepare(`UPDATE last_contract_revision SET proof_height = ?, proof_block_id = ?, proof_transaction_id = ? WHERE contract_id = ?`)
	if err != nil {
		return fmt.Errorf("updateFileContractIndices: failed to prepare proof index statement: %w", err)
	}
	defer proofIndexStmt.Close()

	for _, update := range fces {
		// id stays the same even if revert happens so we don't need to check that here
		fcID := update.FileContractElement.ID

		if revert {
			if update.ProofTransactionID != nil {
				if _, err := proofIndexStmt.Exec(nil, nil, nil, encode(fcID)); err != nil {
					return fmt.Errorf("updateFileContractIndices: failed to update proof index: %w", err)
				}
			}
		} else {
			if update.ProofTransactionID != nil {
				if _, err := proofIndexStmt.Exec(encode(index.Height), encode(index.ID), encode(update.ProofTransactionID), encode(fcID)); err != nil {
					return fmt.Errorf("updateFileContractIndices: failed to update proof index: %w", err)
				}
			}
		}
	}

	return nil
}

func addMetrics(tx *txn, s explorer.UpdateState) error {
	_, err := tx.Exec(`INSERT INTO network_metrics(block_id, height, difficulty, siafund_tax_revenue, num_leaves, total_hosts, active_contracts, failed_contracts, successful_contracts, storage_utilization, circulating_supply, contract_revenue) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		encode(s.Metrics.Index.ID),
		s.Metrics.Index.Height,
		encode(s.Metrics.Difficulty),
		encode(s.Metrics.SiafundTaxRevenue),
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
	err = ut.tx.QueryRow(`SELECT EXISTS(SELECT public_key FROM host_info WHERE public_key = ?)`, encode(pubkey)).Scan(&exists)
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
	if err := addBlock(ut.tx, state.Block, state.ChainIndexElement, state.Metrics.Index.Height); err != nil {
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
	fcDBIds, err := updateFileContractElements(ut.tx, false, state.Metrics.Index, state.Block, state.FileContractElements)
	if err != nil {
		return fmt.Errorf("ApplyIndex: failed to add file contracts: %w", err)
	}

	v2FcDBIds, err := updateV2FileContractElements(ut.tx, false, state.Metrics.Index, state.Block, state.V2FileContractElements)
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
	} else if err := addHostAnnouncements(ut.tx, state.Block.Timestamp, state.HostAnnouncements, state.V2HostAnnouncements); err != nil {
		return fmt.Errorf("ApplyIndex: failed to add host announcements: %w", err)
	} else if err := updateFileContractIndices(ut.tx, false, state.Metrics.Index, state.FileContractElements); err != nil {
		return fmt.Errorf("ApplyIndex: failed to update file contract element indices: %w", err)
	} else if err := updateV2FileContractIndices(ut.tx, false, state.Metrics.Index, state.V2FileContractElements); err != nil {
		return fmt.Errorf("ApplyIndex: failed to update v2 file contract element indices: %w", err)
	} else if err := addEvents(ut.tx, state.Block.ID(), scDBIds, sfDBIds, fcDBIds, v2FcDBIds, txnDBIds, v2TxnDBIds, state.Events); err != nil {
		return fmt.Errorf("ApplyIndex: failed to add events: %w", err)
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
	} else if _, err := updateFileContractElements(ut.tx, true, state.Metrics.Index, state.Block, state.FileContractElements); err != nil {
		return fmt.Errorf("RevertIndex: failed to update file contract state: %w", err)
	} else if _, err := updateV2FileContractElements(ut.tx, true, state.Metrics.Index, state.Block, state.V2FileContractElements); err != nil {
		return fmt.Errorf("ApplyIndex: failed to add v2 file contracts: %w", err)
	} else if err := deleteBlock(ut.tx, state.Block.ID()); err != nil {
		return fmt.Errorf("RevertIndex: failed to delete block: %w", err)
	} else if err := updateStateTree(ut.tx, state.TreeUpdates); err != nil {
		return fmt.Errorf("RevertIndex: failed to update state tree: %w", err)
	} else if err := updateFileContractIndices(ut.tx, true, state.Metrics.Index, state.FileContractElements); err != nil {
		return fmt.Errorf("RevertIndex: failed to update file contract element indices: %w", err)
	} else if err := updateV2FileContractIndices(ut.tx, true, state.Metrics.Index, state.V2FileContractElements); err != nil {
		return fmt.Errorf("ApplyIndex: failed to update v2 file contract element indices: %w", err)
	}

	return nil
}

func addHosts(tx *txn, hosts []explorer.Host) error {
	if len(hosts) == 0 {
		return nil
	}

	stmt, err := tx.Prepare(`INSERT INTO host_info(public_key, v2, net_address, country_code, latitude, longitude, known_since, last_scan, last_scan_successful, last_scan_error, next_scan, failed_interactions_streak, last_announcement, total_scans, successful_interactions, failed_interactions, settings_accepting_contracts, settings_max_download_batch_size, settings_max_duration, settings_max_revise_batch_size, settings_net_address, settings_remaining_storage, settings_sector_size, settings_total_storage, settings_used_storage, settings_address, settings_window_size, settings_collateral, settings_max_collateral, settings_base_rpc_price, settings_contract_price, settings_download_bandwidth_price, settings_sector_access_price, settings_storage_price, settings_upload_bandwidth_price, settings_ephemeral_account_expiry, settings_max_ephemeral_account_balance, settings_revision_number, settings_version, settings_release, settings_sia_mux_port, price_table_uid, price_table_validity, price_table_host_block_height, price_table_update_price_table_cost, price_table_account_balance_cost, price_table_fund_account_cost, price_table_latest_revision_cost, price_table_subscription_memory_cost, price_table_subscription_notification_cost, price_table_init_base_cost, price_table_memory_time_cost, price_table_download_bandwidth_cost, price_table_upload_bandwidth_cost, price_table_drop_sectors_base_cost, price_table_drop_sectors_unit_cost, price_table_has_sector_base_cost, price_table_read_base_cost, price_table_read_length_cost, price_table_renew_contract_cost, price_table_revision_base_cost, price_table_swap_sector_base_cost, price_table_write_base_cost, price_table_write_length_cost, price_table_write_store_cost, price_table_txn_fee_min_recommended, price_table_txn_fee_max_recommended, price_table_contract_price, price_table_collateral_cost, price_table_max_collateral, price_table_max_duration, price_table_window_size, price_table_registry_entries_left, price_table_registry_entries_total, v2_settings_protocol_version, v2_settings_release, v2_settings_wallet_address, v2_settings_accepting_contracts, v2_settings_max_collateral, v2_settings_max_contract_duration, v2_settings_remaining_storage, v2_settings_total_storage, v2_settings_used_storage, v2_prices_contract_price, v2_prices_collateral_price, v2_prices_storage_price, v2_prices_ingress_price, v2_prices_egress_price, v2_prices_free_sector_price, v2_prices_tip_height, v2_prices_valid_until, v2_prices_signature) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35,$36,$37,$38,$39,$40,$41,$42,$43,$44,$45,$46,$47,$48,$49,$50,$51,$52,$53,$54,$55,$56,$57,$58,$59,$60,$61,$62,$63,$64,$65,$66,$67,$68,$69,$70,$71,$72,$73,$74,$75,$76,$77,$78,$79,$80,$81,$82,$83,$84,$85,$86,$87,$88,$89,$90,$91,$92) ON CONFLICT (public_key) DO UPDATE SET v2 = EXCLUDED.v2, net_address = EXCLUDED.net_address, last_announcement = EXCLUDED.last_announcement, next_scan = EXCLUDED.last_announcement`)
	if err != nil {
		return fmt.Errorf("failed to prepare host_info stmt: %w", err)
	}
	defer stmt.Close()

	deleteV2AddrStmt, err := tx.Prepare(`DELETE FROM host_info_v2_netaddresses WHERE public_key = ?`)
	if err != nil {
		return fmt.Errorf("failed to prepare delete v2 net address stmt: %w", err)
	}
	defer deleteV2AddrStmt.Close()

	addV2AddrStmt, err := tx.Prepare(`INSERT INTO host_info_v2_netaddresses(public_key, netaddress_order, protocol, address) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("failed to prepare add v2 net address stmt: %w", err)
	}
	defer addV2AddrStmt.Close()

	for _, host := range hosts {
		s, p := host.Settings, host.PriceTable
		sV2, pV2 := host.V2Settings, host.V2Settings.Prices

		isV2 := len(host.V2NetAddresses) > 0
		if _, err := stmt.Exec(encode(host.PublicKey), isV2, host.NetAddress, host.Location.CountryCode, host.Location.Latitude, host.Location.Longitude, encode(host.KnownSince), encode(host.LastScan), host.LastScanSuccessful, "", encode(host.LastAnnouncement), 0, encode(host.LastAnnouncement), host.TotalScans, host.SuccessfulInteractions, host.FailedInteractions, s.AcceptingContracts, encode(s.MaxDownloadBatchSize), encode(s.MaxDuration), encode(s.MaxReviseBatchSize), s.NetAddress, encode(s.RemainingStorage), encode(s.SectorSize), encode(s.TotalStorage), encode(s.TotalStorage-s.RemainingStorage), encode(s.Address), encode(s.WindowSize), encode(s.Collateral), encode(s.MaxCollateral), encode(s.BaseRPCPrice), encode(s.ContractPrice), encode(s.DownloadBandwidthPrice), encode(s.SectorAccessPrice), encode(s.StoragePrice), encode(s.UploadBandwidthPrice), s.EphemeralAccountExpiry, encode(s.MaxEphemeralAccountBalance), encode(s.RevisionNumber), s.Version, s.Release, s.SiaMuxPort, encode(p.UID), p.Validity, encode(p.HostBlockHeight), encode(p.UpdatePriceTableCost), encode(p.AccountBalanceCost), encode(p.FundAccountCost), encode(p.LatestRevisionCost), encode(p.SubscriptionMemoryCost), encode(p.SubscriptionNotificationCost), encode(p.InitBaseCost), encode(p.MemoryTimeCost), encode(p.DownloadBandwidthCost), encode(p.UploadBandwidthCost), encode(p.DropSectorsBaseCost), encode(p.DropSectorsUnitCost), encode(p.HasSectorBaseCost), encode(p.ReadBaseCost), encode(p.ReadLengthCost), encode(p.RenewContractCost), encode(p.RevisionBaseCost), encode(p.SwapSectorBaseCost), encode(p.WriteBaseCost), encode(p.WriteLengthCost), encode(p.WriteStoreCost), encode(p.TxnFeeMinRecommended), encode(p.TxnFeeMaxRecommended), encode(p.ContractPrice), encode(p.CollateralCost), encode(p.MaxCollateral), encode(p.MaxDuration), encode(p.WindowSize), encode(p.RegistryEntriesLeft), encode(p.RegistryEntriesTotal), sV2.ProtocolVersion[:], sV2.Release, encode(sV2.WalletAddress), sV2.AcceptingContracts, encode(sV2.MaxCollateral), encode(sV2.MaxContractDuration), encode(sV2.RemainingStorage), encode(sV2.TotalStorage), encode(sV2.TotalStorage-sV2.RemainingStorage), encode(pV2.ContractPrice), encode(pV2.Collateral), encode(pV2.StoragePrice), encode(pV2.IngressPrice), encode(pV2.EgressPrice), encode(pV2.FreeSectorPrice), encode(pV2.TipHeight), encode(pV2.ValidUntil), encode(pV2.Signature)); err != nil {
			return fmt.Errorf("failed to execute host_info stmt: %w", err)
		}

		if isV2 {
			if _, err := deleteV2AddrStmt.Exec(encode(host.PublicKey)); err != nil {
				return fmt.Errorf("failed to execute delete v2 net address stmt: %w", err)
			}
			for i, netAddr := range host.V2NetAddresses {
				if _, err := addV2AddrStmt.Exec(encode(host.PublicKey), i, netAddr.Protocol, netAddr.Address); err != nil {
					return fmt.Errorf("failed to execute add v2 net address stmt: %w", err)
				}
			}
		}
	}
	return nil
}

// AddHostScans implements explorer.Store
func (s *Store) AddHostScans(scans ...explorer.HostScan) error {
	return s.transaction(func(tx *txn) error {
		unsuccessfulStmt, err := tx.Prepare(`UPDATE host_info SET last_scan = ?, last_scan_successful = 0, last_scan_error = ?, next_scan = ?, total_scans = total_scans + 1, failed_interactions = failed_interactions + 1, failed_interactions_streak = failed_interactions_streak + 1 WHERE public_key = ?`)
		if err != nil {
			return fmt.Errorf("addHostScans: failed to prepare unsuccessful statement: %w", err)
		}
		defer unsuccessfulStmt.Close()

		successfulStmt, err := tx.Prepare(`UPDATE host_info SET country_code = ?, latitude = ?, longitude = ?, last_scan = ?, last_scan_successful = 1, last_scan_error = "", next_scan = ?, total_scans = total_scans + 1, successful_interactions = successful_interactions + 1, failed_interactions_streak = 0, settings_accepting_contracts = ?, settings_max_download_batch_size = ?, settings_max_duration = ?, settings_max_revise_batch_size = ?, settings_net_address = ?, settings_remaining_storage = ?, settings_sector_size = ?, settings_total_storage = ?, settings_used_storage = ?, settings_address = ?, settings_window_size = ?, settings_collateral = ?, settings_max_collateral = ?, settings_base_rpc_price = ?, settings_contract_price = ?, settings_download_bandwidth_price = ?, settings_sector_access_price = ?, settings_storage_price = ?, settings_upload_bandwidth_price = ?, settings_ephemeral_account_expiry = ?, settings_max_ephemeral_account_balance = ?, settings_revision_number = ?, settings_version = ?, settings_release = ?, settings_sia_mux_port = ?, price_table_uid = ?, price_table_validity = ?, price_table_host_block_height = ?, price_table_update_price_table_cost = ?, price_table_account_balance_cost = ?, price_table_fund_account_cost = ?, price_table_latest_revision_cost = ?, price_table_subscription_memory_cost = ?, price_table_subscription_notification_cost = ?, price_table_init_base_cost = ?, price_table_memory_time_cost = ?, price_table_download_bandwidth_cost = ?, price_table_upload_bandwidth_cost = ?, price_table_drop_sectors_base_cost = ?, price_table_drop_sectors_unit_cost = ?, price_table_has_sector_base_cost = ?, price_table_read_base_cost = ?, price_table_read_length_cost = ?, price_table_renew_contract_cost = ?, price_table_revision_base_cost = ?, price_table_swap_sector_base_cost = ?, price_table_write_base_cost = ?, price_table_write_length_cost = ?, price_table_write_store_cost = ?, price_table_txn_fee_min_recommended = ?, price_table_txn_fee_max_recommended = ?, price_table_contract_price = ?, price_table_collateral_cost = ?, price_table_max_collateral = ?, price_table_max_duration = ?, price_table_window_size = ?, price_table_registry_entries_left = ?, price_table_registry_entries_total = ?, v2_settings_protocol_version = ?, v2_settings_release = ?, v2_settings_wallet_address = ?, v2_settings_accepting_contracts = ?, v2_settings_max_collateral = ?, v2_settings_max_contract_duration = ?, v2_settings_remaining_storage = ?, v2_settings_total_storage = ?, v2_settings_used_storage = ?, v2_prices_contract_price = ?, v2_prices_collateral_price = ?, v2_prices_storage_price = ?, v2_prices_ingress_price = ?, v2_prices_egress_price = ?, v2_prices_free_sector_price = ?, v2_prices_tip_height = ?, v2_prices_valid_until = ?, v2_prices_signature = ? WHERE public_key = ?`)
		if err != nil {
			return fmt.Errorf("addHostScans: failed to prepare successful statement: %w", err)
		}
		defer successfulStmt.Close()

		for _, scan := range scans {
			s, p := scan.Settings, scan.PriceTable
			sV2, pV2 := scan.V2Settings, scan.V2Settings.Prices
			if scan.Success {
				if _, err := successfulStmt.Exec(scan.Location.CountryCode, scan.Location.Latitude, scan.Location.Longitude, encode(scan.Timestamp), encode(scan.NextScan), s.AcceptingContracts, encode(s.MaxDownloadBatchSize), encode(s.MaxDuration), encode(s.MaxReviseBatchSize), s.NetAddress, encode(s.RemainingStorage), encode(s.SectorSize), encode(s.TotalStorage), encode(s.TotalStorage-s.RemainingStorage), encode(s.Address), encode(s.WindowSize), encode(s.Collateral), encode(s.MaxCollateral), encode(s.BaseRPCPrice), encode(s.ContractPrice), encode(s.DownloadBandwidthPrice), encode(s.SectorAccessPrice), encode(s.StoragePrice), encode(s.UploadBandwidthPrice), s.EphemeralAccountExpiry, encode(s.MaxEphemeralAccountBalance), encode(s.RevisionNumber), s.Version, s.Release, s.SiaMuxPort, encode(p.UID), p.Validity, encode(p.HostBlockHeight), encode(p.UpdatePriceTableCost), encode(p.AccountBalanceCost), encode(p.FundAccountCost), encode(p.LatestRevisionCost), encode(p.SubscriptionMemoryCost), encode(p.SubscriptionNotificationCost), encode(p.InitBaseCost), encode(p.MemoryTimeCost), encode(p.DownloadBandwidthCost), encode(p.UploadBandwidthCost), encode(p.DropSectorsBaseCost), encode(p.DropSectorsUnitCost), encode(p.HasSectorBaseCost), encode(p.ReadBaseCost), encode(p.ReadLengthCost), encode(p.RenewContractCost), encode(p.RevisionBaseCost), encode(p.SwapSectorBaseCost), encode(p.WriteBaseCost), encode(p.WriteLengthCost), encode(p.WriteStoreCost), encode(p.TxnFeeMinRecommended), encode(p.TxnFeeMaxRecommended), encode(p.ContractPrice), encode(p.CollateralCost), encode(p.MaxCollateral), encode(p.MaxDuration), encode(p.WindowSize), encode(p.RegistryEntriesLeft), encode(p.RegistryEntriesTotal), sV2.ProtocolVersion[:], sV2.Release, encode(sV2.WalletAddress), sV2.AcceptingContracts, encode(sV2.MaxCollateral), encode(sV2.MaxContractDuration), encode(sV2.RemainingStorage), encode(sV2.TotalStorage), encode(sV2.TotalStorage-sV2.RemainingStorage), encode(pV2.ContractPrice), encode(pV2.Collateral), encode(pV2.StoragePrice), encode(pV2.IngressPrice), encode(pV2.EgressPrice), encode(pV2.FreeSectorPrice), encode(pV2.TipHeight), encode(pV2.ValidUntil), encode(pV2.Signature), encode(scan.PublicKey)); err != nil {
					return fmt.Errorf("addHostScans: failed to execute successful statement: %w", err)
				}
			} else {
				if _, err := unsuccessfulStmt.Exec(encode(scan.Timestamp), *scan.Error, encode(scan.NextScan), encode(scan.PublicKey)); err != nil {
					return fmt.Errorf("addHostScans: failed to execute unsuccessful statement: %w", err)
				}
			}
		}
		return nil
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
