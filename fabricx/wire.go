// SPDX-License-Identifier: Apache-2.0

package fabricx

import "fmt"

// MarshalExecuteResponse encodes a response so a gateway can compare two
// endorsers byte for byte. Field numbers match the public ExecuteResponse
// shape: 1 read-write set, 3 status, 4 message.
func MarshalExecuteResponse(resp *ExecuteResponse) ([]byte, error) {
	if resp == nil {
		return nil, fmt.Errorf("marshal execute response: nil")
	}
	var b []byte
	if len(resp.ReadWriteSet) > 0 {
		b = appendLengthDelimited(b, 1, resp.ReadWriteSet)
	}
	if resp.Status != 0 {
		b = appendVarintField(b, 3, uint64(resp.Status))
	}
	if resp.Message != "" {
		b = appendLengthDelimited(b, 4, []byte(resp.Message))
	}
	return b, nil
}

// UnmarshalExecuteResponse reverses MarshalExecuteResponse.
func UnmarshalExecuteResponse(b []byte) (*ExecuteResponse, error) {
	out := &ExecuteResponse{}
	for len(b) > 0 {
		key, n := decodeVarint(b)
		if n <= 0 {
			return nil, fmt.Errorf("unmarshal execute response: bad key")
		}
		b = b[n:]
		field, wire := int(key>>3), int(key&7)
		switch wire {
		case 0:
			v, m := decodeVarint(b)
			if m <= 0 {
				return nil, fmt.Errorf("unmarshal execute response: bad varint")
			}
			b = b[m:]
			if field == 3 {
				out.Status = Status(v)
			}
		case 2:
			ln, m := decodeVarint(b)
			if m <= 0 {
				return nil, fmt.Errorf("unmarshal execute response: bad length")
			}
			b = b[m:]
			if uint64(len(b)) < ln {
				return nil, fmt.Errorf("unmarshal execute response: short field %d", field)
			}
			val := append([]byte(nil), b[:ln]...)
			b = b[ln:]
			switch field {
			case 1:
				out.ReadWriteSet = val
			case 4:
				out.Message = string(val)
			}
		default:
			return nil, fmt.Errorf("unmarshal execute response: unsupported wire type %d", wire)
		}
	}
	return out, nil
}

func appendVarintField(b []byte, field int, v uint64) []byte {
	b = appendVarint(b, uint64(field)<<3)
	return appendVarint(b, v)
}

func appendLengthDelimited(b []byte, field int, val []byte) []byte {
	b = appendVarint(b, uint64(field)<<3|2)
	b = appendVarint(b, uint64(len(val)))
	return append(b, val...)
}

func appendVarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

func decodeVarint(b []byte) (uint64, int) {
	var v uint64
	for i := 0; i < len(b) && i < 10; i++ {
		v |= uint64(b[i]&0x7f) << (7 * i)
		if b[i] < 0x80 {
			return v, i + 1
		}
	}
	return 0, -1
}
