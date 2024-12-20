package sqlite

import (
	"bytes"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"go.sia.tech/core/rhp/v3"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/chain"
)

func encode(obj any) any {
	switch obj := obj.(type) {
	case types.Currency:
		// Currency is encoded as two 64-bit big-endian integers for sorting
		buf := make([]byte, 16)
		binary.BigEndian.PutUint64(buf, obj.Hi)
		binary.BigEndian.PutUint64(buf[8:], obj.Lo)
		return buf
	case types.EncoderTo:
		var buf bytes.Buffer
		e := types.NewEncoder(&buf)
		obj.EncodeTo(e)
		e.Flush()
		return buf.Bytes()
	case rhp.SettingsID:
		return obj[:]
	case []types.Hash256:
		var buf bytes.Buffer
		e := types.NewEncoder(&buf)
		types.EncodeSlice(e, obj)
		e.Flush()
		return buf.Bytes()
	case []chain.NetAddress:
		var buf bytes.Buffer
		e := types.NewEncoder(&buf)
		types.EncodeSlice(e, obj)
		e.Flush()
		return buf.Bytes()
	case uint64:
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, obj)
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
		case *types.Currency:
			if len(src) != 16 {
				return fmt.Errorf("cannot scan %d bytes into Currency", len(src))
			}
			v.Hi = binary.BigEndian.Uint64(src)
			v.Lo = binary.BigEndian.Uint64(src[8:])
		case *rhp.SettingsID:
			*v = rhp.SettingsID(src)
		case types.DecoderFrom:
			dec := types.NewBufDecoder(src)
			v.DecodeFrom(dec)
			return dec.Err()
		case *[]types.Hash256:
			dec := types.NewBufDecoder(src)
			types.DecodeSlice(dec, v)
			return dec.Err()
		case *[]chain.NetAddress:
			dec := types.NewBufDecoder(src)
			types.DecodeSlice(dec, v)
			return dec.Err()
		case *uint64:
			*v = binary.BigEndian.Uint64(src)
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
		case *time.Duration:
			*v = time.Duration(src)
		default:
			return fmt.Errorf("cannot scan %T to %T", src, d.v)
		}
		return nil
	default:
		return fmt.Errorf("cannot scan %T to %T", src, d.v)
	}
}

func decode(obj any) sql.Scanner {
	return &decodable{obj}
}

type nullDecodable struct {
	v any
}

func decodeNull(obj any) sql.Scanner {
	return &nullDecodable{obj}
}

// Scan implements the sql.Scanner interface.
func (d *nullDecodable) Scan(src any) error {
	if src == nil {
		return nil
	}

	dd := decode(d.v)
	return dd.Scan(src)
}
