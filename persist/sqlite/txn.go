package sqlite

import (
	"bytes"

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

func (s *Store) addBlock(b types.Block, height uint64) error {
	_, err := s.exec("INSERT INTO Blocks(id, height, parent_id, nonce, timestamp) VALUES (?, ?, ?, ?, ?);", encode(b.ID()), height, encode(b.ParentID), encodeUint64(b.Nonce), b.Timestamp.Unix())
	return err
}

func (s *Store) addMinerPayouts(bid types.BlockID, scos []types.SiacoinOutput) error {
	for i, sco := range scos {
		if _, err := s.exec("INSERT INTO MinerPayouts(block_id, block_order, address, value) VALUES (?, ?, ?, ?);", encode(bid), i, encode(sco.Address), encode(sco.Value)); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) deleteBlock(bid types.BlockID) error {
	_, err := s.exec("DELETE FROM Blocks WHERE id = ?", encode(bid))
	return err
}

func (s *Store) applyUpdates() error {
	for _, update := range s.pendingUpdates {
		if err := s.addBlock(update.Block, update.State.Index.Height); err != nil {
			return err
		} else if err := s.addMinerPayouts(update.Block.ID(), update.Block.MinerPayouts); err != nil {
			return err
		}
	}
	s.pendingUpdates = s.pendingUpdates[:0]
	return nil
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
	if err := s.deleteBlock(cru.Block.ID()); err != nil {
		return err
	}

	return nil
}
