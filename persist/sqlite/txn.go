package sqlite

import (
	"bytes"

	"go.sia.tech/core/types"
	"go.sia.tech/explored/explorer"
)

type explorerTxn struct {
	tx txn
}

// Transaction implements explorer.Store.
func (s *Store) Transaction(fn func(tx explorer.Transaction) error) error {
	return s.transaction(func(tx txn) error {
		return fn(&explorerTxn{tx: tx})
	})
}

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

// AddBlock implements explorer.Transaction.
func (tx *explorerTxn) AddBlock(b types.Block, height uint64) error {
	_, err := tx.tx.Exec("INSERT INTO Blocks(id, height, parent_id, nonce, timestamp) VALUES (?, ?, ?, ?, ?);", encode(b.ID()), height, encode(b.ParentID), encodeUint64(b.Nonce), b.Timestamp.Unix())
	return err
}

// AddMinerPayouts implements explorer.Transaction.
func (tx *explorerTxn) AddMinerPayouts(bid types.BlockID, scos []types.SiacoinOutput) error {
	for i, sco := range scos {
		if _, err := tx.tx.Exec("INSERT INTO MinerPayouts(block_id, block_order, address, value) VALUES (?, ?, ?, ?);", encode(bid), i, encode(sco.Address), encode(sco.Value)); err != nil {
			return err
		}
	}
	return nil
}

// DeleteBlock implements explorer.Transaction.
func (tx *explorerTxn) DeleteBlock(bid types.BlockID) error {
	_, err := tx.tx.Exec("DELETE FROM Blocks WHERE id = ?", encode(bid))
	return err
}
