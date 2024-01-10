package sqlite

import (
	"bytes"
	"fmt"

	"go.sia.tech/core/chain"
	"go.sia.tech/core/types"
)

func encode(obj types.EncoderTo) []byte {
	var buf bytes.Buffer
	e := types.NewEncoder(&buf)
	obj.EncodeTo(e)
	e.Flush()
	return buf.Bytes()
}

func encodeUint64(x uint64) []byte {
	var buf bytes.Buffer
	e := types.NewEncoder(&buf)
	e.WriteUint64(x)
	e.Flush()
	return buf.Bytes()
}

func (s *Store) addBlock(tx txn, b types.Block, height uint64) error {
	// nonce is encoded because database/sql doesn't support uint64 with high bit set
	_, err := tx.Exec("INSERT INTO blocks(id, height, parent_id, nonce, timestamp) VALUES (?, ?, ?, ?, ?);", encode(b.ID()), height, encode(b.ParentID), encodeUint64(b.Nonce), b.Timestamp.Unix())
	return err
}

func (s *Store) addMinerPayouts(tx txn, bid types.BlockID, scos []types.SiacoinOutput) error {
	for i, sco := range scos {
		if _, err := tx.Exec("INSERT INTO miner_payouts(block_id, block_order, address, value) VALUES (?, ?, ?, ?);", encode(bid), i, encode(sco.Address), encode(sco.Value)); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) addArbitraryData(tx txn, id int64, txn types.Transaction) error {
	for i, arbitraryData := range txn.ArbitraryData {
		if _, err := tx.Exec("INSERT INTO arbitrary_data(transaction_id, transaction_order, data) VALUES (?, ?, ?)", id, i, arbitraryData); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) addTransactions(tx txn, bid types.BlockID, txns []types.Transaction) error {
	for i, txn := range txns {
		result, err := tx.Exec("INSERT INTO transactions(transaction_id) VALUES (?);", encode(txn.ID()))
		if err != nil {
			return fmt.Errorf("addTransactions: failed to insert into transactions: %v", err)
		}
		txnID, err := result.LastInsertId()
		if err != nil {
			return fmt.Errorf("addTransactions: failed to get insert result ID: %v", err)
		}

		if _, err := tx.Exec("INSERT INTO block_transactions(block_id, transaction_id, block_order) VALUES (?, ?, ?)", encode(bid), txnID, i); err != nil {
			return fmt.Errorf("addTransactions: failed to insert into block_transactions: %v", err)
		} else if err := s.addArbitraryData(tx, txnID, txn); err != nil {
			return fmt.Errorf("addTransactions: failed to add arbitrary data: %v", err)
		}
	}
	return nil
}

func (s *Store) deleteBlock(tx txn, bid types.BlockID) error {
	_, err := tx.Exec("DELETE FROM blocks WHERE id = ?", encode(bid))
	return err
}

func (s *Store) applyUpdates() error {
	return s.transaction(func(tx txn) error {
		for _, update := range s.pendingUpdates {
			if err := s.addBlock(tx, update.Block, update.State.Index.Height); err != nil {
				return fmt.Errorf("applyUpdates: failed to add block: %v", err)
			} else if err := s.addMinerPayouts(tx, update.Block.ID(), update.Block.MinerPayouts); err != nil {
				return fmt.Errorf("applyUpdates: failed to add miner payouts: %v", err)
			} else if err := s.addTransactions(tx, update.Block.ID(), update.Block.Transactions); err != nil {
				return fmt.Errorf("applyUpdates: failed to add transactions: %v", err)
			}
		}
		s.pendingUpdates = s.pendingUpdates[:0]
		return nil
	})
}

func (s *Store) revertUpdate(cru *chain.RevertUpdate) error {
	return s.transaction(func(tx txn) error {
		if err := s.deleteBlock(tx, cru.Block.ID()); err != nil {
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
