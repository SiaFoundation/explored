package sqlite

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"go.sia.tech/core/types"
)

var (
	// ErrNoTip is returned when Tip() is unable to find any blocks in the
	// database and thus there is no tip. It does not mean there was an
	// error in the underlying database.
	ErrNoTip = errors.New("no tip found")
)

func decode(obj types.DecoderFrom, data []byte) error {
	d := types.NewBufDecoder(data)
	obj.DecodeFrom(d)
	return d.Err()
}

func decodeUint64(x *uint64, data []byte) error {
	d := types.NewBufDecoder(data)
	if x != nil {
		*x = d.ReadUint64()
	}
	return d.Err()
}

// transactionByID returns the transaction with the given integer ID in the
// database (not its Sia ID).
func (s *Store) transactionByID(txnID int64) (types.Transaction, error) {
	var result types.Transaction

	rows, err := s.query("SELECT data FROM arbitrary_data WHERE transaction_id = ? ORDER BY transaction_order", txnID)
	if err != nil {
		return types.Transaction{}, fmt.Errorf("transactionByID: failed to query arbitrary data: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return types.Transaction{}, fmt.Errorf("transactionByID: failed to scan arbitrary data: %v", err)
		}
		result.ArbitraryData = append(result.ArbitraryData, data)
	}

	return result, nil
}

// Tip implements explorer.Store.
func (s *Store) Tip() (types.ChainIndex, error) {
	var data []byte
	var result types.ChainIndex
	if err := s.queryRow("SELECT id, height FROM blocks WHERE height = (SELECT MAX(height) from blocks)").Scan(&data, &result.Height); errors.Is(err, sql.ErrNoRows) {
		return types.ChainIndex{}, ErrNoTip
	} else if err != nil {
		return types.ChainIndex{}, err
	}
	if err := decode(&result.ID, data); err != nil {
		return types.ChainIndex{}, err
	}
	return result, nil
}

// BlockByID implements explorer.Store.
func (s *Store) BlockByID(id types.BlockID) (types.Block, error) {
	var result types.Block
	{
		var timestamp int64
		var parentID, nonce []byte
		if err := s.queryRow("SELECT parent_id, nonce, timestamp FROM blocks WHERE id = ?", encode(id)).Scan(&parentID, &nonce, &timestamp); err != nil {
			return types.Block{}, err
		}
		result.Timestamp = time.Unix(timestamp, 0).UTC()
		if err := decode(&result.ParentID, parentID); err != nil {
			return types.Block{}, err
		}
		if err := decodeUint64(&result.Nonce, nonce); err != nil {
			return types.Block{}, err
		}
	}

	{
		rows, err := s.query("SELECT address, value FROM miner_payouts WHERE block_id = ? ORDER BY block_order", encode(id))
		if err != nil {
			return types.Block{}, err
		}
		defer rows.Close()

		var address, value []byte
		for rows.Next() {
			if err := rows.Scan(&address, &value); err != nil {
				return types.Block{}, err
			}
			var minerPayout types.SiacoinOutput
			if err := decode(&minerPayout.Address, address); err != nil {
				return types.Block{}, err
			}
			if err := decode(&minerPayout.Value, value); err != nil {
				return types.Block{}, err
			}
			result.MinerPayouts = append(result.MinerPayouts, minerPayout)
		}
	}

	{
		rows, err := s.query("SELECT transaction_id FROM block_transactions WHERE block_id = ? ORDER BY block_order", encode(id))
		if err != nil {
			return types.Block{}, err
		}
		defer rows.Close()

		var txnID int64
		for rows.Next() {
			if err := rows.Scan(&txnID); err != nil {
				return types.Block{}, err
			}
			txn, err := s.transactionByID(txnID)
			if err != nil {
				return types.Block{}, err
			}
			result.Transactions = append(result.Transactions, txn)
		}
	}

	return result, nil
}

// BlockByHeight implements explorer.Store.
func (s *Store) BlockByHeight(height uint64) (types.Block, error) {
	var data []byte
	if err := s.queryRow("SELECT id FROM blocks WHERE height = ?", height).Scan(&data); err != nil {
		return types.Block{}, err
	}

	var bid types.BlockID
	if err := decode(&bid, data); err != nil {
		return types.Block{}, err
	}
	return s.BlockByID(bid)
}

// Transaction implements explorer.Store.
func (s *Store) Transaction(id types.TransactionID) (types.Transaction, error) {
	var txnID int64
	if err := s.queryRow("SELECT id FROM transactions WHERE transaction_id = ?", encode(id)).Scan(&txnID); err != nil {
		return types.Transaction{}, err
	}

	return s.transactionByID(txnID)
}
