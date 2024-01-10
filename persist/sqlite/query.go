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
		if err = rows.Scan(&data); err != nil {
			return types.Transaction{}, fmt.Errorf("transactionByID: failed to scan arbitrary data: %v", err)
		}
		result.ArbitraryData = append(result.ArbitraryData, data)
	}

	return result, nil
}

// Tip implements explorer.Store.
func (s *Store) Tip() (result types.ChainIndex, err error) {
	var data []byte
	err = s.queryRow("SELECT id, height FROM blocks WHERE height = (SELECT MAX(height) from blocks)").Scan(&data, &result.Height)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNoTip
		return
	} else if err != nil {
		return
	}
	if err = decode(&result.ID, data); err != nil {
		return
	}
	return
}

// BlockByID implements explorer.Store.
func (s *Store) BlockByID(id types.BlockID) (result types.Block, err error) {
	{
		var timestamp int64
		var parentID, nonce []byte
		if err = s.queryRow("SELECT parent_id, nonce, timestamp FROM blocks WHERE id = ?", encode(id)).Scan(&parentID, &nonce, &timestamp); err != nil {
			return
		}
		result.Timestamp = time.Unix(timestamp, 0).UTC()
		if err = decode(&result.ParentID, parentID); err != nil {
			return
		}
		if err = decodeUint64(&result.Nonce, nonce); err != nil {
			return
		}
	}

	{
		var rows *loggedRows
		if rows, err = s.query("SELECT address, value FROM miner_payouts WHERE block_id = ? ORDER BY block_order", encode(id)); err != nil {
			return
		}
		defer rows.Close()

		var address, value []byte
		for rows.Next() {
			if err = rows.Scan(&address, &value); err != nil {
				return
			}
			var minerPayout types.SiacoinOutput
			if err = decode(&minerPayout.Address, address); err != nil {
				return
			}
			if err = decode(&minerPayout.Value, value); err != nil {
				return
			}
			result.MinerPayouts = append(result.MinerPayouts, minerPayout)
		}
	}

	{
		var rows *loggedRows
		if rows, err = s.query("SELECT transaction_id FROM block_transactions WHERE block_id = ? ORDER BY block_order", encode(id)); err != nil {
			return
		}
		defer rows.Close()

		var txnID int64
		for rows.Next() {
			if err = rows.Scan(&txnID); err != nil {
				return
			}
			var txn types.Transaction
			if txn, err = s.transactionByID(txnID); err != nil {
				return
			}
			result.Transactions = append(result.Transactions, txn)
		}
	}

	return
}

// BlockByHeight implements explorer.Store.
func (s *Store) BlockByHeight(height uint64) (result types.Block, err error) {
	var data []byte
	if err = s.queryRow("SELECT id FROM blocks WHERE height = ?", height).Scan(&data); err != nil {
		return
	}

	var bid types.BlockID
	if err = decode(&bid, data); err != nil {
		return
	}
	result, err = s.BlockByID(bid)
	return
}

// Transaction implements explorer.Store.
func (s *Store) Transaction(id types.TransactionID) (result types.Transaction, err error) {
	var txnID int64
	if err = s.queryRow("SELECT id FROM transactions WHERE transaction_id = ?", encode(id)).Scan(&txnID); err != nil {
		return
	}

	result, err = s.transactionByID(txnID)
	return
}
