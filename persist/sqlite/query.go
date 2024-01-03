package sqlite

import "go.sia.tech/core/types"

func decode(obj types.DecoderFrom, data []byte) error {
	d := types.NewBufDecoder(data)
	obj.DecodeFrom(d)
	return d.Err()
}

func (s *Store) Tip() (result types.ChainIndex, err error) {
	var data []byte
	if err = s.queryRow("SELECT id, height FROM Blocks WHERE height = (SELECT MAX(height) from Blocks)").Scan(&data, &result.Height); err != nil {
		return
	}
	decode(&result.ID, data)
	return
}
