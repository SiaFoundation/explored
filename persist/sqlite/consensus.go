package sqlite

import (
	"database/sql"
	"errors"
	"fmt"

	"go.sia.tech/core/chain"
	"go.sia.tech/core/types"
)

const (
	sourceMinerPayout = iota
	sourceTransaction
)

func (s *Store) addBlock(dbTxn txn, b types.Block, height uint64) error {
	// nonce is encoded because database/sql doesn't support uint64 with high bit set
	_, err := dbTxn.Exec("INSERT INTO blocks(id, height, parent_id, nonce, timestamp) VALUES (?, ?, ?, ?, ?);", dbEncode(b.ID()), height, dbEncode(b.ParentID), dbEncode(b.Nonce), dbEncode(b.Timestamp))
	return err
}

func (s *Store) addMinerPayouts(dbTxn txn, bid types.BlockID, height uint64, scos []types.SiacoinOutput) error {
	outputsStmt, err := dbTxn.Prepare(`INSERT INTO siacoin_outputs(spent, source, maturity_height, address, value) VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addSiacoinOutputs: failed to prepare outputs statement: %v", err)
	}
	defer outputsStmt.Close()

	minerPayoutsStmt, err := dbTxn.Prepare(`INSERT INTO miner_payouts(block_id, block_order, output_id) VALUES (?, ?, ?);`)
	if err != nil {
		return fmt.Errorf("addMinerPayouts: failed to prepare statement: %v", err)
	}
	defer minerPayoutsStmt.Close()

	for i, sco := range scos {
		result, err := outputsStmt.Exec(false, sourceMinerPayout, height+144, dbEncode(sco.Address), dbEncode(sco.Value))
		if err != nil {
			return fmt.Errorf("addMinerPayouts: failed to execute outputs statement")
		}

		dbID, err := result.LastInsertId()
		if err != nil {
			return fmt.Errorf("addMinerPayouts: failed to get insert result ID: %v", err)
		}

		if _, err := minerPayoutsStmt.Exec(dbEncode(bid), i, dbID); err != nil {
			return fmt.Errorf("addMinerPayouts: failed to execute miner_payouts statement: %v", err)
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

func (s *Store) addSiacoinOutputs(dbTxn txn, id int64, txn types.Transaction, sces map[types.SiacoinOutputID]types.SiacoinElement) error {
	outputsStmt, err := dbTxn.Prepare(`INSERT INTO siacoin_outputs(spent, source, maturity_height, address, value) VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addSiacoinOutputs: failed to prepare outputs statement: %v", err)
	}
	defer outputsStmt.Close()

	transactionSiacoinOutputsStmt, err := dbTxn.Prepare(`INSERT INTO transaction_siacoin_outputs(transaction_id, transaction_order, output_id) VALUES (?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addSiacoinOutputs: failed to prepare transaction_siacoin_outputs statement: %v", err)
	}
	defer transactionSiacoinOutputsStmt.Close()

	for i, sco := range txn.SiacoinOutputs {
		sce, ok := sces[txn.SiacoinOutputID(i)]
		if !ok {
			return errors.New("addSiacoinOutputs: sce not in map")
		}

		result, err := outputsStmt.Exec(false, sourceTransaction, sce.MaturityHeight, dbEncode(sco.Address), dbEncode(sco.Value))
		if err != nil {
			return fmt.Errorf("addSiacoinOutputs: failed to execute outputs statement: %v", err)
		}

		dbID, err := result.LastInsertId()
		if err != nil {
			return fmt.Errorf("addSiacoinOutputs: failed to get insert result ID: %v", err)
		}

		if _, err := transactionSiacoinOutputsStmt.Exec(id, i, dbID); err != nil {
			return fmt.Errorf("addSiacoinOutputs: failed to execute transaction_siacoin_outputs statement: %v", err)
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

func (s *Store) addSiafundOutputs(dbTxn txn, id int64, txn types.Transaction, sfes map[types.SiafundOutputID]types.SiafundElement) error {
	outputsStmt, err := dbTxn.Prepare(`INSERT INTO siafund_outputs(spent, claim_start, address, value) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addSiafundOutputs: failed to prepare outputs statement: %v", err)
	}
	defer outputsStmt.Close()

	transactionSiafundOutputsStmt, err := dbTxn.Prepare(`INSERT INTO transaction_siafund_outputs(transaction_id, transaction_order, output_id) VALUES (?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addSiafundOutputs: failed to prepare transaction_siafund_outputs statement: %v", err)
	}
	defer transactionSiafundOutputsStmt.Close()

	for i, sfo := range txn.SiafundOutputs {
		sfe, ok := sfes[txn.SiafundOutputID(i)]
		if !ok {
			return errors.New("addSiafundOutputs: sce not in map")
		}

		result, err := outputsStmt.Exec(false, dbEncode(sfe.ClaimStart), dbEncode(sfo.Address), dbEncode(sfo.Value))
		if err != nil {
			return fmt.Errorf("addSiafundOutputs: failed to execute outputs statement: %v", err)
		}

		dbID, err := result.LastInsertId()
		if err != nil {
			return fmt.Errorf("addSiafundOutputs: failed to get insert result ID: %v", err)
		}

		if _, err := transactionSiafundOutputsStmt.Exec(id, i, dbID); err != nil {
			return fmt.Errorf("addSiafundOutputs: failed to execute transaction_siafund statement: %v", err)
		}
	}
	return nil

}

func (s *Store) addTransactions(dbTxn txn, bid types.BlockID, txns []types.Transaction, sces map[types.SiacoinOutputID]types.SiacoinElement, sfes map[types.SiafundOutputID]types.SiafundElement) error {
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
		} else if err := s.addSiacoinOutputs(dbTxn, txnID, txn, sces); err != nil {
			return fmt.Errorf("addSiacoinOutputs: failed to add siacoin outputs: %v", err)
		} else if err := s.addSiafundInputs(dbTxn, txnID, txn); err != nil {
			return fmt.Errorf("addSiafundInputs: failed to add siafund inputs: %v", err)
		} else if err := s.addSiafundOutputs(dbTxn, txnID, txn, sfes); err != nil {
			return fmt.Errorf("addSiafundOutputs: failed to add siafund outputs: %v", err)
		}
	}
	return nil
}

func (s *Store) deleteBlock(dbTxn txn, bid types.BlockID) error {
	_, err := dbTxn.Exec("DELETE FROM blocks WHERE id = ?", dbEncode(bid))
	return err
}

func (s *Store) applyUpdates() error {
	return s.transaction(func(dbTxn txn) error {
		for _, update := range s.pendingUpdates {
			sces := make(map[types.SiacoinOutputID]types.SiacoinElement)
			update.ForEachSiacoinElement(func(sce types.SiacoinElement, spent bool) {
				sces[types.SiacoinOutputID(sce.StateElement.ID)] = sce
			})
			sfes := make(map[types.SiafundOutputID]types.SiafundElement)
			update.ForEachSiafundElement(func(sfe types.SiafundElement, spent bool) {
				sfes[types.SiafundOutputID(sfe.StateElement.ID)] = sfe
			})

			if err := s.addBlock(dbTxn, update.Block, update.State.Index.Height); err != nil {
				return fmt.Errorf("applyUpdates: failed to add block: %v", err)
			} else if err := s.addMinerPayouts(dbTxn, update.Block.ID(), update.State.Index.Height, update.Block.MinerPayouts); err != nil {
				return fmt.Errorf("applyUpdates: failed to add miner payouts: %v", err)
			} else if err := s.addTransactions(dbTxn, update.Block.ID(), update.Block.Transactions, sces, sfes); err != nil {
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
