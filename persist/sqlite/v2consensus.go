package sqlite

import (
	"database/sql"
	"errors"
	"fmt"

	"go.sia.tech/core/types"
	"go.sia.tech/explored/explorer"
)

func addV2Transactions(tx *txn, bid types.BlockID, txns []types.V2Transaction) (map[types.TransactionID]txnDBId, error) {
	checkTransactionStmt, err := tx.Prepare(`SELECT id FROM v2_transactions WHERE transaction_id = ?`)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare check v2_transaction statement: %v", err)
	}
	defer checkTransactionStmt.Close()

	insertTransactionStmt, err := tx.Prepare(`INSERT INTO v2_transactions (transaction_id, new_foundation_address, miner_fee, arbitrary_data) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare insert v2_transaction statement: %v", err)
	}
	defer insertTransactionStmt.Close()

	blockTransactionsStmt, err := tx.Prepare(`INSERT INTO v2_block_transactions(block_id, transaction_id, block_order) VALUES (?, ?, ?);`)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare v2_block_transactions statement: %w", err)
	}
	defer blockTransactionsStmt.Close()

	txnDBIds := make(map[types.TransactionID]txnDBId)
	for i, txn := range txns {
		var exist bool
		var txnID int64
		if err := checkTransactionStmt.QueryRow(encode(txn.ID())).Scan(&txnID); err != nil && err != sql.ErrNoRows {
			return nil, fmt.Errorf("failed to insert v2 transaction ID: %w", err)
		} else if err == nil {
			exist = true
		}

		if !exist {
			var newFoundationAddress any
			if txn.NewFoundationAddress != nil {
				newFoundationAddress = encode(txn.NewFoundationAddress)
			}

			result, err := insertTransactionStmt.Exec(encode(txn.ID()), newFoundationAddress, encode(txn.MinerFee), txn.ArbitraryData)
			if err != nil {
				return nil, fmt.Errorf("failed to insert into v2_transactions: %w", err)
			}
			txnID, err = result.LastInsertId()
			if err != nil {
				return nil, fmt.Errorf("failed to get v2 transaction ID: %w", err)
			}
		}
		txnDBIds[txn.ID()] = txnDBId{id: txnID, exist: exist}

		if _, err := blockTransactionsStmt.Exec(encode(bid), txnID, i); err != nil {
			return nil, fmt.Errorf("failed to insert into v2_block_transactions: %w", err)
		}
	}
	return txnDBIds, nil
}

func updateV2FileContractElements(tx *txn, revert bool, index types.ChainIndex, b types.Block, fces []explorer.V2FileContractUpdate) (map[explorer.DBFileContract]int64, error) {
	stmt, err := tx.Prepare(`INSERT INTO v2_file_contract_elements(contract_id, block_id, transaction_id, leaf_index, capacity, filesize, file_merkle_root, proof_height, expiration_height, renter_output_address, renter_output_value, host_output_address, host_output_value, missed_host_value, total_collateral, renter_public_key, host_public_key, revision_number, renter_signature, host_signature)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (contract_id, revision_number)
        DO UPDATE SET leaf_index = ?
        RETURNING id;`)
	if err != nil {
		return nil, fmt.Errorf("updateV2FileContractElements: failed to prepare main statement: %w", err)
	}
	defer stmt.Close()

	revisionStmt, err := tx.Prepare(`INSERT INTO v2_last_contract_revision(contract_id, contract_element_id, confirmation_height, confirmation_block_id, confirmation_transaction_id)
    VALUES (?, ?, COALESCE(?, X''), COALESCE(?, X''), COALESCE(?, X''))
    ON CONFLICT (contract_id)
    DO UPDATE SET contract_element_id = ?, confirmation_height = COALESCE(?, confirmation_height), confirmation_block_id = COALESCE(?, confirmation_block_id), confirmation_transaction_id = COALESCE(?, confirmation_transaction_id)`)
	if err != nil {
		return nil, fmt.Errorf("updateV2FileContractElements: failed to prepare last_contract_revision statement: %w", err)
	}
	defer revisionStmt.Close()

	// so we can get the ids of revision parents to add to the DB
	parentStmt, err := tx.Prepare(`SELECT id FROM v2_file_contract_elements WHERE contract_id = ? AND revision_number = ?`)
	if err != nil {
		return nil, fmt.Errorf("updateV2FileContractElements: failed to prepare parent statement: %w", err)
	}
	defer parentStmt.Close()

	fcTxns := make(map[explorer.DBFileContract]types.TransactionID)
	for _, txn := range b.V2Transactions() {
		id := txn.ID()

		for i, fc := range txn.FileContracts {
			fcTxns[explorer.DBFileContract{
				ID:             txn.V2FileContractID(id, i),
				RevisionNumber: fc.RevisionNumber,
			}] = id
		}
		for _, fcr := range txn.FileContractRevisions {
			fcTxns[explorer.DBFileContract{
				ID:             types.FileContractID(fcr.Parent.ID),
				RevisionNumber: fcr.Revision.RevisionNumber,
			}] = id
		}
		for _, fcr := range txn.FileContractResolutions {
			if v, ok := fcr.Resolution.(*types.V2FileContractRenewal); ok {
				fcTxns[explorer.DBFileContract{
					ID:             types.FileContractID(fcr.Parent.ID).V2RenewalID(),
					RevisionNumber: v.NewContract.RevisionNumber,
				}] = id
			}
		}
	}

	fcDBIds := make(map[explorer.DBFileContract]int64)
	addFC := func(fcID types.FileContractID, leafIndex uint64, fc types.V2FileContract, confirmationTransactionID *types.TransactionID, lastRevision bool) error {
		var dbID int64
		dbFC := explorer.DBFileContract{ID: fcID, RevisionNumber: fc.RevisionNumber}
		err := stmt.QueryRow(encode(fcID), encode(b.ID()), encode(fcTxns[dbFC]), encode(leafIndex), encode(fc.Capacity), encode(fc.Filesize), encode(fc.FileMerkleRoot), encode(fc.ProofHeight), encode(fc.ExpirationHeight), encode(fc.RenterOutput.Address), encode(fc.RenterOutput.Value), encode(fc.HostOutput.Address), encode(fc.HostOutput.Value), encode(fc.MissedHostValue), encode(fc.TotalCollateral), encode(fc.RenterPublicKey), encode(fc.HostPublicKey), encode(fc.RevisionNumber), encode(fc.RenterSignature), encode(fc.HostSignature), encode(leafIndex)).Scan(&dbID)
		if err != nil {
			return fmt.Errorf("failed to execute v2_file_contract_elements statement: %w", err)
		}

		// only update if it's the most recent revision which will come from
		// running ForEachFileContractElement on the update
		if lastRevision {
			var encodedHeight, encodedBlockID, encodedConfirmationTransactionID []byte
			if confirmationTransactionID != nil {
				encodedHeight = encode(index.Height).([]byte)
				encodedBlockID = encode(index.ID).([]byte)
				encodedConfirmationTransactionID = encode(*confirmationTransactionID).([]byte)
			}

			if _, err := revisionStmt.Exec(encode(fcID), dbID, encodedHeight, encodedBlockID, encodedConfirmationTransactionID, dbID, encodedHeight, encodedBlockID, encodedConfirmationTransactionID); err != nil {
				return fmt.Errorf("failed to update last revision number: %w", err)
			}
		}

		fcDBIds[dbFC] = dbID
		return nil
	}

	for _, update := range fces {
		var fce *types.V2FileContractElement

		if revert {
			// Reverting
			if update.Resolution != nil {
				fce = &update.FileContractElement
			} else if update.Revision != nil {
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
			types.FileContractID(fce.ID),
			fce.StateElement.LeafIndex,
			fce.V2FileContract,
			update.ConfirmationTransactionID,
			true,
		); err != nil {
			return nil, fmt.Errorf("updateV2FileContractElements: %w", err)
		}
	}

	if revert {
		return fcDBIds, nil
	}

	for _, txn := range b.V2Transactions() {
		// add in any contracts that are not the latest, i.e. contracts that
		// were created and revised in the same block
		for j, fc := range txn.FileContracts {
			fcID := txn.V2FileContractID(txn.ID(), j)
			dbFC := explorer.DBFileContract{ID: fcID, RevisionNumber: fc.RevisionNumber}
			if _, exists := fcDBIds[dbFC]; exists {
				continue
			}

			if err := addFC(fcID, 0, fc, nil, false); err != nil {
				return nil, fmt.Errorf("updateV2FileContractElements: %w", err)
			}
		}
		// add in any revisions that are not the latest, i.e. contracts that
		// were revised multiple times in one block
		for _, fcr := range txn.FileContractRevisions {
			fc := fcr.Revision
			fcID := types.FileContractID(fcr.Parent.ID)
			dbFC := explorer.DBFileContract{ID: fcID, RevisionNumber: fc.RevisionNumber}
			if _, exists := fcDBIds[dbFC]; exists {
				continue
			}

			if err := addFC(fcID, 0, fc, nil, false); err != nil {
				return nil, fmt.Errorf("updateV2FileContractElements: %w", err)
			}
		}
		// Add the new renewal contracts
		for _, fcr := range txn.FileContractResolutions {
			if v, ok := fcr.Resolution.(*types.V2FileContractRenewal); ok {
				{
					// Add NewContract if we have not seen it already.
					// Only way this could happen is if the renewal is revised
					// in the same block so that the initial renewal is not the
					// "latest" revision of it.
					fc := v.NewContract
					fcID := types.FileContractID(fcr.Parent.ID).V2RenewalID()
					dbFC := explorer.DBFileContract{ID: fcID, RevisionNumber: fc.RevisionNumber}
					if _, exists := fcDBIds[dbFC]; exists {
						continue
					}

					if err := addFC(fcID, 0, fc, nil, false); err != nil {
						return nil, fmt.Errorf("updateV2FileContractElements: failed to add new contract: %w", err)
					}
				}
			}
		}
		// don't add anything, just set parent db IDs in fcDBIds map
		for _, fcr := range txn.FileContractRevisions {
			fcID := types.FileContractID(fcr.Parent.ID)
			parentDBFC := explorer.DBFileContract{ID: fcID, RevisionNumber: fcr.Parent.V2FileContract.RevisionNumber}

			var dbID int64
			if err := parentStmt.QueryRow(encode(fcID), encode(parentDBFC.RevisionNumber)).Scan(&dbID); err != nil {
				return nil, fmt.Errorf("updateV2FileContractElements: failed to get parent contract ID: %w", err)
			}
			fcDBIds[parentDBFC] = dbID
		}
		// don't add anything, just set parent db IDs in fcDBIds map
		for _, fcr := range txn.FileContractResolutions {
			fcID := types.FileContractID(fcr.Parent.ID)
			parentDBFC := explorer.DBFileContract{ID: fcID, RevisionNumber: fcr.Parent.V2FileContract.RevisionNumber}

			var dbID int64
			if err := parentStmt.QueryRow(encode(fcID), encode(parentDBFC.RevisionNumber)).Scan(&dbID); err != nil {
				return nil, fmt.Errorf("updateV2FileContractElements: failed to get parent contract ID: %w", err)
			}
			fcDBIds[parentDBFC] = dbID
		}
	}

	return fcDBIds, nil
}

func updateV2FileContractIndices(tx *txn, revert bool, index types.ChainIndex, fces []explorer.V2FileContractUpdate) error {
	resolutionIndexStmt, err := tx.Prepare(`UPDATE v2_last_contract_revision SET resolution_type = ?, resolution_height = ?, resolution_block_id = ?, resolution_transaction_id = ?, renewed_to_id = ? WHERE contract_id = ?`)
	if err != nil {
		return fmt.Errorf("updateV2FileContractIndices: failed to prepare resolution index statement: %w", err)
	}
	defer resolutionIndexStmt.Close()

	for _, update := range fces {
		// id stays the same even if revert happens so we don't need to check that here
		fcID := update.FileContractElement.ID

		if revert {
			if update.ResolutionTransactionID != nil {
				if _, err := resolutionIndexStmt.Exec(explorer.V2ResolutionInvalid, nil, nil, nil, nil, encode(fcID)); err != nil {
					return fmt.Errorf("updateV2FileContractIndices: failed to update resolution index: %w", err)
				}
			}
		} else {
			if update.ResolutionTransactionID != nil {
				var renewalToID any
				if _, ok := update.Resolution.(*types.V2FileContractExpiration); ok {
					renewalToID = encode(fcID.V2RenewalID())
				}

				resolutionType := explorer.V2ResolutionType(update.Resolution)
				if _, err := resolutionIndexStmt.Exec(resolutionType, encode(index.Height), encode(index.ID), encode(update.ResolutionTransactionID), renewalToID, encode(fcID)); err != nil {
					return fmt.Errorf("updateV2FileContractIndices: failed to update resolution index: %w", err)
				}
			}
		}
	}

	return nil
}

func addV2SiacoinInputs(tx *txn, txnID int64, txn types.V2Transaction, dbIDs map[types.SiacoinOutputID]int64) error {
	stmt, err := tx.Prepare(`INSERT INTO v2_transaction_siacoin_inputs(transaction_id, transaction_order, parent_id, satisfied_policy) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addV2SiacoinInputs: failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for i, sci := range txn.SiacoinInputs {
		dbID, ok := dbIDs[types.SiacoinOutputID(sci.Parent.ID)]
		if !ok {
			return errors.New("addV2SiacoinInputs: dbID not in map")
		}

		if _, err := stmt.Exec(txnID, i, dbID, encode(sci.SatisfiedPolicy)); err != nil {
			return fmt.Errorf("addV2SiacoinInputs: failed to execute statement: %w", err)
		}
	}
	return nil
}

func addV2SiacoinOutputs(tx *txn, txnID int64, txn types.V2Transaction, dbIDs map[types.SiacoinOutputID]int64) error {
	stmt, err := tx.Prepare(`INSERT INTO v2_transaction_siacoin_outputs(transaction_id, transaction_order, output_id) VALUES (?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addV2SiacoinOutputs: failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	id := txn.ID()
	for i := range txn.SiacoinOutputs {
		dbID, ok := dbIDs[txn.SiacoinOutputID(id, i)]
		if !ok {
			return errors.New("addV2SiacoinOutputs: dbID not in map")
		}

		if _, err := stmt.Exec(txnID, i, dbID); err != nil {
			return fmt.Errorf("addV2SiacoinOutputs: failed to execute statement: %w", err)
		}
	}
	return nil
}

func addV2SiafundInputs(tx *txn, txnID int64, txn types.V2Transaction, dbIDs map[types.SiafundOutputID]int64) error {
	stmt, err := tx.Prepare(`INSERT INTO v2_transaction_siafund_inputs(transaction_id, transaction_order, parent_id, claim_address, satisfied_policy) VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addV2SiafundInputs: failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for i, sfi := range txn.SiafundInputs {
		dbID, ok := dbIDs[types.SiafundOutputID(sfi.Parent.ID)]
		if !ok {
			return errors.New("addV2SiafundInputs: dbID not in map")
		}

		if _, err := stmt.Exec(txnID, i, dbID, encode(sfi.ClaimAddress), encode(sfi.SatisfiedPolicy)); err != nil {
			return fmt.Errorf("addV2SiafundInputs: failed to execute statement: %w", err)
		}
	}
	return nil
}

func addV2SiafundOutputs(tx *txn, txnID int64, txn types.V2Transaction, dbIDs map[types.SiafundOutputID]int64) error {
	stmt, err := tx.Prepare(`INSERT INTO v2_transaction_siafund_outputs(transaction_id, transaction_order, output_id) VALUES (?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addV2SiafundOutputs: failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	id := txn.ID()
	for i := range txn.SiafundOutputs {
		dbID, ok := dbIDs[txn.SiafundOutputID(id, i)]
		if !ok {
			return errors.New("addV2SiafundOutputs: dbID not in map")
		}

		if _, err := stmt.Exec(txnID, i, dbID); err != nil {
			return fmt.Errorf("addV2SiafundOutputs: failed to execute statement: %w", err)
		}
	}
	return nil
}

func addV2FileContracts(tx *txn, txnID int64, txn types.V2Transaction, dbIDs map[explorer.DBFileContract]int64) error {
	stmt, err := tx.Prepare(`INSERT INTO v2_transaction_file_contracts(transaction_id, transaction_order, contract_id) VALUES (?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addV2FileContracts: failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for i, fc := range txn.FileContracts {
		dbID, ok := dbIDs[explorer.DBFileContract{
			ID:             txn.V2FileContractID(txn.ID(), i),
			RevisionNumber: fc.RevisionNumber,
		}]
		if !ok {
			return errors.New("addV2FileContracts: dbID not in map")
		}

		if _, err := stmt.Exec(txnID, i, dbID); err != nil {
			return fmt.Errorf("addV2FileContracts: failed to execute statement: %w", err)
		}
	}
	return nil
}

func addV2FileContractRevisions(tx *txn, txnID int64, txn types.V2Transaction, dbIDs map[explorer.DBFileContract]int64) error {
	stmt, err := tx.Prepare(`INSERT INTO v2_transaction_file_contract_revisions(transaction_id, transaction_order, parent_contract_id, revision_contract_id) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addV2FileContractRevisions: failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for i, fcr := range txn.FileContractRevisions {
		parentDBID, ok := dbIDs[explorer.DBFileContract{
			ID:             types.FileContractID(fcr.Parent.ID),
			RevisionNumber: fcr.Parent.V2FileContract.RevisionNumber,
		}]
		if !ok {
			return errors.New("addV2FileContractRevisions: parent dbID not in map")
		}

		dbID, ok := dbIDs[explorer.DBFileContract{
			ID:             types.FileContractID(fcr.Parent.ID),
			RevisionNumber: fcr.Revision.RevisionNumber,
		}]
		if !ok {
			return errors.New("addV2FileContractRevisions: dbID not in map")
		}

		if _, err := stmt.Exec(txnID, i, parentDBID, dbID); err != nil {
			return fmt.Errorf("addV2FileContractRevisions: failed to execute statement: %w", err)
		}
	}
	return nil
}

func addV2FileContractResolutions(tx *txn, txnID int64, txn types.V2Transaction, dbIDs map[explorer.DBFileContract]int64) error {
	renewalStmt, err := tx.Prepare(`INSERT INTO v2_transaction_file_contract_resolutions(transaction_id, transaction_order, parent_contract_id, resolution_type, renewal_new_contract_id, renewal_final_renter_output_address, renewal_final_renter_output_value, renewal_final_host_output_address, renewal_final_host_output_value, renewal_renter_rollover, renewal_host_rollover, renewal_renter_signature, renewal_host_signature) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addV2FileContractResolutions: failed to prepare renewal statement: %w", err)
	}
	defer renewalStmt.Close()

	storageProofStmt, err := tx.Prepare(`INSERT INTO v2_transaction_file_contract_resolutions(transaction_id, transaction_order, parent_contract_id, resolution_type, storage_proof_proof_index, storage_proof_leaf, storage_proof_proof) VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addV2FileContractResolutions: failed to prepare storage proof statement: %w", err)
	}
	defer storageProofStmt.Close()

	expirationStmt, err := tx.Prepare(`INSERT INTO v2_transaction_file_contract_resolutions(transaction_id, transaction_order, parent_contract_id, resolution_type) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addV2FileContractResolutions: failed to prepare expiration statement: %w", err)
	}
	defer expirationStmt.Close()

	for i, fcr := range txn.FileContractResolutions {
		parentDBID, ok := dbIDs[explorer.DBFileContract{
			ID:             types.FileContractID(fcr.Parent.ID),
			RevisionNumber: fcr.Parent.V2FileContract.RevisionNumber,
		}]
		if !ok {
			return errors.New("addV2FileContractResolutions: parent dbID not in map")
		}

		resolutionType := explorer.V2ResolutionType(fcr.Resolution)
		switch v := fcr.Resolution.(type) {
		case *types.V2FileContractRenewal:
			newDBID, ok := dbIDs[explorer.DBFileContract{
				ID:             types.FileContractID(fcr.Parent.ID).V2RenewalID(),
				RevisionNumber: v.NewContract.RevisionNumber,
			}]
			if !ok {
				return errors.New("addV2FileContractResolutions: renewal dbID not in map")
			}

			if _, err := renewalStmt.Exec(txnID, i, parentDBID, resolutionType, newDBID, encode(v.FinalRenterOutput.Address), encode(v.FinalRenterOutput.Value), encode(v.FinalHostOutput.Address), encode(v.FinalHostOutput.Value), encode(v.RenterRollover), encode(v.HostRollover), encode(v.RenterSignature), encode(v.HostSignature)); err != nil {
				return fmt.Errorf("addV2FileContractResolutions: failed to execute renewal statement: %w", err)
			}
		case *types.V2StorageProof:
			if _, err := storageProofStmt.Exec(txnID, i, parentDBID, resolutionType, encode(v.ProofIndex), v.Leaf[:], encode(v.Proof)); err != nil {
				return fmt.Errorf("addV2FileContractResolutions: failed to execute storage proof statement: %w", err)
			}
		case *types.V2FileContractExpiration:
			if _, err := expirationStmt.Exec(txnID, i, parentDBID, resolutionType); err != nil {
				return fmt.Errorf("addV2FileContractResolutions: failed to execute expiration statement: %w", err)
			}
		}
	}
	return nil
}

func addV2Attestations(tx *txn, txnID int64, txn types.V2Transaction) error {
	stmt, err := tx.Prepare(`INSERT INTO v2_transaction_attestations(transaction_id, transaction_order, public_key, key, value, signature) VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addV2Attestations: failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for i, attestation := range txn.Attestations {
		if _, err := stmt.Exec(txnID, i, encode(attestation.PublicKey), attestation.Key, attestation.Value, encode(attestation.Signature)); err != nil {
			return fmt.Errorf("addV2Attestations: failed to execute statement: %w", err)
		}
	}
	return nil
}

func addV2TransactionFields(tx *txn, txns []types.V2Transaction, scDBIds map[types.SiacoinOutputID]int64, sfDBIds map[types.SiafundOutputID]int64, v2FcDBIds map[explorer.DBFileContract]int64, v2TxnDBIds map[types.TransactionID]txnDBId) error {
	for _, txn := range txns {
		dbID, ok := v2TxnDBIds[txn.ID()]
		if !ok {
			panic(fmt.Errorf("txn %v should be in txnDBIds", txn.ID()))
		}

		// transaction already exists, don't reinsert its fields
		if dbID.exist {
			continue
		}

		if err := addV2Attestations(tx, dbID.id, txn); err != nil {
			return fmt.Errorf("addV2TransactionFields: failed to add attestations: %w", err)
		} else if err := addV2SiacoinInputs(tx, dbID.id, txn, scDBIds); err != nil {
			return fmt.Errorf("failed to add siacoin inputs: %w", err)
		} else if err := addV2SiacoinOutputs(tx, dbID.id, txn, scDBIds); err != nil {
			return fmt.Errorf("failed to add siacoin outputs: %w", err)
		} else if err := addV2SiafundInputs(tx, dbID.id, txn, sfDBIds); err != nil {
			return fmt.Errorf("failed to add siafund inputs: %w", err)
		} else if err := addV2SiafundOutputs(tx, dbID.id, txn, sfDBIds); err != nil {
			return fmt.Errorf("failed to add siafund outputs: %w", err)
		} else if err := addV2FileContracts(tx, dbID.id, txn, v2FcDBIds); err != nil {
			return fmt.Errorf("failed to add file contracts: %w", err)
		} else if err := addV2FileContractRevisions(tx, dbID.id, txn, v2FcDBIds); err != nil {
			return fmt.Errorf("failed to add file contract revisions: %w", err)
		} else if err := addV2FileContractResolutions(tx, dbID.id, txn, v2FcDBIds); err != nil {
			return fmt.Errorf("failed to add file contract resolutions: %w", err)
		}
	}

	return nil
}
