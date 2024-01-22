package sqlite

import (
	"database/sql"
	"errors"
	"fmt"

	"go.sia.tech/core/chain"
	"go.sia.tech/core/types"
)

func (s *Store) addBlock(dbTxn txn, b types.Block, height uint64) error {
	// nonce is encoded because database/sql doesn't support uint64 with high bit set
	_, err := dbTxn.Exec("INSERT INTO blocks(id, height, parent_id, nonce, timestamp) VALUES (?, ?, ?, ?, ?);", dbEncode(b.ID()), height, dbEncode(b.ParentID), dbEncode(b.Nonce), dbEncode(b.Timestamp))
	return err
}

func (s *Store) addMinerPayouts(dbTxn txn, bid types.BlockID, height uint64, scos []types.SiacoinOutput, dbIDs map[types.SiacoinOutputID]int64) error {
	stmt, err := dbTxn.Prepare(`INSERT INTO miner_payouts(block_id, block_order, output_id) VALUES (?, ?, ?);`)
	if err != nil {
		return fmt.Errorf("addMinerPayouts: failed to prepare statement: %v", err)
	}
	defer stmt.Close()

	for i := range scos {
		dbID, ok := dbIDs[bid.MinerOutputID(i)]
		if !ok {
			return errors.New("addMinerPayouts: dbID not in map")
		}

		if _, err := stmt.Exec(dbEncode(bid), i, dbID); err != nil {
			return fmt.Errorf("addMinerPayouts: failed to execute statement: %v", err)
		}
	}
	return nil
}

func (s *Store) addArbitraryData(dbTxn txn, id int64, txn types.Transaction) error {
	stmt, err := dbTxn.Prepare(`INSERT INTO transaction_arbitrary_data(transaction_id, transaction_order, data) VALUES (?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addArbitraryData: failed to prepare statement: %v", err)
	}
	defer stmt.Close()

	for i, arbitraryData := range txn.ArbitraryData {
		if _, err := stmt.Exec(id, i, arbitraryData); err != nil {
			return fmt.Errorf("addArbitraryData: failed to execute statement: %v", err)
		}
	}
	return nil
}

func (s *Store) addSiacoinInputs(dbTxn txn, id int64, txn types.Transaction) error {
	stmt, err := dbTxn.Prepare(`INSERT INTO transaction_siacoin_inputs(transaction_id, transaction_order, parent_id, unlock_conditions) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addSiacoinInputs: failed to prepare statement: %v", err)
	}
	defer stmt.Close()

	for i, sci := range txn.SiacoinInputs {
		if _, err := stmt.Exec(id, i, dbEncode(sci.ParentID), dbEncode(sci.UnlockConditions)); err != nil {
			return fmt.Errorf("addSiacoinInputs: failed to execute statement: %v", err)
		}
	}
	return nil
}

func (s *Store) addSiacoinOutputs(dbTxn txn, id int64, txn types.Transaction, dbIDs map[types.SiacoinOutputID]int64) error {
	stmt, err := dbTxn.Prepare(`INSERT INTO transaction_siacoin_outputs(transaction_id, transaction_order, output_id) VALUES (?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addSiacoinOutputs: failed to prepare statement: %v", err)
	}
	defer stmt.Close()

	for i := range txn.SiacoinOutputs {
		dbID, ok := dbIDs[txn.SiacoinOutputID(i)]
		if !ok {
			return errors.New("addSiacoinOutputs: dbID not in map")
		}

		if _, err := stmt.Exec(id, i, dbID); err != nil {
			return fmt.Errorf("addSiacoinOutputs: failed to execute statement: %v", err)
		}
	}
	return nil
}

func (s *Store) addSiafundInputs(dbTxn txn, id int64, txn types.Transaction) error {
	stmt, err := dbTxn.Prepare(`INSERT INTO transaction_siafund_inputs(transaction_id, transaction_order, parent_id, unlock_conditions, claim_address) VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addSiafundInputs: failed to prepare statement: %v", err)
	}
	defer stmt.Close()

	for i, sci := range txn.SiafundInputs {
		if _, err := stmt.Exec(id, i, dbEncode(sci.ParentID), dbEncode(sci.UnlockConditions), dbEncode(sci.ClaimAddress)); err != nil {
			return fmt.Errorf("addSiafundInputs: failed to execute statement: %v", err)
		}
	}
	return nil
}

func (s *Store) addSiafundOutputs(dbTxn txn, id int64, txn types.Transaction, dbIDs map[types.SiafundOutputID]int64) error {
	stmt, err := dbTxn.Prepare(`INSERT INTO transaction_siafund_outputs(transaction_id, transaction_order, output_id) VALUES (?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addSiafundOutputs: failed to prepare statement: %v", err)
	}
	defer stmt.Close()

	for i := range txn.SiafundOutputs {
		dbID, ok := dbIDs[txn.SiafundOutputID(i)]
		if !ok {
			return errors.New("addSiafundOutputs: dbID not in map")
		}

		if _, err := stmt.Exec(id, i, dbID); err != nil {
			return fmt.Errorf("addSiafundOutputs: failed to execute statement: %v", err)
		}
	}
	return nil

}

func (s *Store) addTransactions(dbTxn txn, bid types.BlockID, txns []types.Transaction, scDBIds map[types.SiacoinOutputID]int64, sfDBIds map[types.SiafundOutputID]int64) error {
	transactionsStmt, err := dbTxn.Prepare(`INSERT INTO transactions(transaction_id) VALUES (?);`)
	if err != nil {
		return fmt.Errorf("addTransactions: failed to prepare transactions statement: %v", err)
	}
	defer transactionsStmt.Close()

	blockTransactionsStmt, err := dbTxn.Prepare(`INSERT INTO block_transactions(block_id, transaction_id, block_order) VALUES (?, ?, ?);`)
	if err != nil {
		return fmt.Errorf("addTransactions: failed to prepare block_transactions statement: %v", err)
	}
	defer blockTransactionsStmt.Close()

	for i, txn := range txns {
		result, err := transactionsStmt.Exec(dbEncode(txn.ID()))
		if err != nil {
			return fmt.Errorf("addTransactions: failed to insert into transactions: %v", err)
		}
		txnID, err := result.LastInsertId()
		if err != nil {
			return fmt.Errorf("addTransactions: failed to get insert result ID: %v", err)
		}

		if _, err := blockTransactionsStmt.Exec(dbEncode(bid), txnID, i); err != nil {
			return fmt.Errorf("addTransactions: failed to insert into block_transactions: %v", err)
		} else if err := s.addArbitraryData(dbTxn, txnID, txn); err != nil {
			return fmt.Errorf("addTransactions: failed to add arbitrary data: %v", err)
		} else if err := s.addSiacoinInputs(dbTxn, txnID, txn); err != nil {
			return fmt.Errorf("addSiacoinInputs: failed to add siacoin inputs: %v", err)
		} else if err := s.addSiacoinOutputs(dbTxn, txnID, txn, scDBIds); err != nil {
			return fmt.Errorf("addSiacoinOutputs: failed to add siacoin outputs: %v", err)
		} else if err := s.addSiafundInputs(dbTxn, txnID, txn); err != nil {
			return fmt.Errorf("addSiafundInputs: failed to add siafund inputs: %v", err)
		} else if err := s.addSiafundOutputs(dbTxn, txnID, txn, sfDBIds); err != nil {
			return fmt.Errorf("addSiafundOutputs: failed to add siafund outputs: %v", err)
		}
	}
	return nil
}

func (s *Store) deleteBlock(dbTxn txn, bid types.BlockID) error {
	_, err := dbTxn.Exec("DELETE FROM blocks WHERE id = ?", dbEncode(bid))
	return err
}

func (s *Store) addOutputs(dbTxn txn, update *chain.ApplyUpdate) (map[types.SiacoinOutputID]int64, map[types.SiafundOutputID]int64, error) {
	scDBIds := make(map[types.SiacoinOutputID]int64)
	{
		scOutputsStmt, err := dbTxn.Prepare(`INSERT INTO siacoin_outputs(spent, maturity_height, address, value) VALUES (?, ?, ?, ?)`)
		if err != nil {
			return nil, nil, fmt.Errorf("addOutputs: failed to prepare siacoin_outputs statement: %v", err)
		}
		defer scOutputsStmt.Close()

		var updateErr error
		update.ForEachSiacoinElement(func(sce types.SiacoinElement, spent bool) {
			if updateErr != nil {
				return
			}

			result, err := scOutputsStmt.Exec(false, sce.MaturityHeight, dbEncode(sce.SiacoinOutput.Address), dbEncode(sce.SiacoinOutput.Value))
			if err != nil {
				updateErr = fmt.Errorf("addOutputs: failed to execute siacoin_outputs statement: %v", err)
				return
			}

			dbID, err := result.LastInsertId()
			if err != nil {
				updateErr = fmt.Errorf("addOutputs: failed to get last insert ID: %v", err)
				return
			}

			scDBIds[types.SiacoinOutputID(sce.StateElement.ID)] = dbID
		})
		if updateErr != nil {
			return nil, nil, updateErr
		}
	}

	sfDBIds := make(map[types.SiafundOutputID]int64)
	{
		sfOutputsStmt, err := dbTxn.Prepare(`INSERT INTO siafund_outputs(spent, claim_start, address, value) VALUES (?, ?, ?, ?)`)
		if err != nil {
			return nil, nil, fmt.Errorf("addOutputs: failed to prepare siafund_outputs statement: %v", err)
		}
		defer sfOutputsStmt.Close()

		var updateErr error
		update.ForEachSiafundElement(func(sfe types.SiafundElement, spent bool) {
			if updateErr != nil {
				return
			}

			result, err := sfOutputsStmt.Exec(false, dbEncode(sfe.ClaimStart), dbEncode(sfe.SiafundOutput.Address), dbEncode(sfe.SiafundOutput.Value))
			if err != nil {
				updateErr = fmt.Errorf("addOutputs: failed to execute siafund_outputs statement: %v", err)
				return
			}

			dbID, err := result.LastInsertId()
			if err != nil {
				updateErr = fmt.Errorf("addOutputs: failed to get last insert ID: %v", err)
				return
			}

			sfDBIds[types.SiafundOutputID(sfe.StateElement.ID)] = dbID
		})
		if updateErr != nil {
			return nil, nil, updateErr
		}
	}

	return scDBIds, sfDBIds, nil
}

func (s *Store) applyUpdates() error {
	return s.transaction(func(dbTxn txn) error {
		for _, update := range s.pendingUpdates {
			scDBIds, sfDBIds, err := s.addOutputs(dbTxn, update)
			if err != nil {
				return fmt.Errorf("applyUpdates: failed to add outputs: %v", err)
			}

			if err := s.addBlock(dbTxn, update.Block, update.State.Index.Height); err != nil {
				return fmt.Errorf("applyUpdates: failed to add block: %v", err)
			} else if err := s.addMinerPayouts(dbTxn, update.Block.ID(), update.State.Index.Height, update.Block.MinerPayouts, scDBIds); err != nil {
				return fmt.Errorf("applyUpdates: failed to add miner payouts: %v", err)
			} else if err := s.addTransactions(dbTxn, update.Block.ID(), update.Block.Transactions, scDBIds, sfDBIds); err != nil {
				return fmt.Errorf("applyUpdates: failed to add transactions: %v", err)
			}
		}
		s.pendingUpdates = s.pendingUpdates[:0]
		return nil
	})
}

func (s *Store) revertUpdate(cru *chain.RevertUpdate) error {
	return s.transaction(func(dbTxn txn) error {
		if err := s.deleteBlock(dbTxn, cru.Block.ID()); err != nil {
			return fmt.Errorf("revertUpdate: failed to delete block: %v", err)
		}
		return nil
	})
}

// ProcessChainApplyUpdate implements chain.Subscriber.
func (s *Store) ProcessChainApplyUpdate(cau *chain.ApplyUpdate, mayCommit bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.pendingUpdates = append(s.pendingUpdates, cau)
	if mayCommit {
		return s.applyUpdates()
	}
	return nil
}

// ProcessChainRevertUpdate implements chain.Subscriber.
func (s *Store) ProcessChainRevertUpdate(cru *chain.RevertUpdate) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.pendingUpdates) > 0 && s.pendingUpdates[len(s.pendingUpdates)-1].Block.ID() == cru.Block.ID() {
		s.pendingUpdates = s.pendingUpdates[:len(s.pendingUpdates)-1]
		return nil
	}
	return s.revertUpdate(cru)
}

// Tip implements explorer.Store.
func (s *Store) Tip() (result types.ChainIndex, err error) {
	const query = `SELECT id, height FROM blocks ORDER BY height DESC LIMIT 1`
	err = s.transaction(func(dbTx txn) error {
		return dbTx.QueryRow(query).Scan(dbDecode(&result.ID), &result.Height)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return types.ChainIndex{}, ErrNoTip
	}
	return
}
