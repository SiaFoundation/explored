package sqlite

import (
	"bytes"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"go.sia.tech/core/types"
)

func dbEncode(obj any) any {
	switch obj := obj.(type) {
	case types.EncoderTo:
		var buf bytes.Buffer
		e := types.NewEncoder(&buf)
		obj.EncodeTo(e)
		e.Flush()
		return buf.Bytes()
	case []types.Hash256:
		var buf bytes.Buffer
		e := types.NewEncoder(&buf)
		e.WritePrefix(len(obj))
		for _, o := range obj {
			o.EncodeTo(e)
		}
		e.Flush()
		return buf.Bytes()
	case types.Currency:
		var buf bytes.Buffer
		e := types.NewEncoder(&buf)
		types.V1Currency(obj).EncodeTo(e)
		e.Flush()
		return buf.Bytes()
	case uint64:
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, obj)
		return b
	case time.Time:
		return obj.Unix()
	default:
		panic(fmt.Sprintf("dbEncode: unsupported type %T", obj))
	}
}

type decodable struct {
	v any
}

// Scan implements the sql.Scanner interface.
func (d *decodable) Scan(src any) error {
	if src == nil {
		return errors.New("cannot scan nil into decodable")
	}

	switch src := src.(type) {
	case []byte:
		switch v := d.v.(type) {
		case types.DecoderFrom:
			dec := types.NewBufDecoder(src)
			v.DecodeFrom(dec)
			return dec.Err()
		case *[]types.Hash256:
			dec := types.NewBufDecoder(src)
			*v = make([]types.Hash256, dec.ReadPrefix())
			for i := range *v {
				(*v)[i].DecodeFrom(dec)
			}
		case *types.Currency:
			dec := types.NewBufDecoder(src)
			(*types.V1Currency)(v).DecodeFrom(dec)
			return dec.Err()
		case *uint64:
			*v = binary.LittleEndian.Uint64(src)
		default:
			return fmt.Errorf("cannot scan %T to %T", src, d.v)
		}
		return nil
	case int64:
		switch v := d.v.(type) {
		case *uint64:
			*v = uint64(src)
		case *time.Time:
			*v = time.Unix(src, 0).UTC()
		default:
			return fmt.Errorf("cannot scan %T to %T", src, d.v)
		}
		return nil
	default:
		return fmt.Errorf("cannot scan %T to %T", src, d.v)
	}
}

func dbDecode(obj any) sql.Scanner {
	return &decodable{obj}
}
