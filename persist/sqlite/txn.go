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

	if err := s.applyUpdates(); err != nil {
		return err
	}
	return s.revertUpdate(cru)
}
