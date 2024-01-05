package sqlite

import (
	"time"

	"go.sia.tech/core/types"
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
	if err = s.queryRow("SELECT id, height FROM Blocks WHERE height = (SELECT MAX(height) from Blocks)").Scan(&data, &result.Height); err != nil {
		return
	}
	if err = decode(&result.ID, data); err != nil {
		return
	}
	return
}

// Block implements explorer.Store.
func (s *Store) Block(id types.BlockID) (result types.Block, err error) {
	{
		var timestamp int64
		var parentID, nonce []byte
		if err = s.queryRow("SELECT parent_id, nonce, timestamp FROM Blocks WHERE id = ?", encode(id)).Scan(&parentID, &nonce, &timestamp); err != nil {
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
		if rows, err = s.query("SELECT address, value FROM MinerPayouts WHERE block_id = ? ORDER BY block_order", encode(id)); err != nil {
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

// BlockHeight implements explorer.Store.
func (s *Store) BlockHeight(height uint64) (result types.Block, err error) {
	var data []byte
	if err = s.queryRow("SELECT id FROM Blocks WHERE height = ?", height).Scan(&data); err != nil {
		return
	}

	var bid types.BlockID
	if err = decode(&bid, data); err != nil {
		return
	}
	result, err = s.Block(bid)
	return
}
