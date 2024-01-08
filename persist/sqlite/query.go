package sqlite

import (
	"database/sql"
	"errors"
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
