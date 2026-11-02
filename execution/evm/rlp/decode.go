// SPDX-License-Identifier: Apache-2.0

package rlp

import (
	"errors"
	"fmt"
)

// Decode parses exactly one canonical RLP item from b. Non-canonical encodings
// (a single byte below 0x80 wrapped as a string, a long form for a short
// payload, or a length with leading zeros) and trailing bytes are errors.
func Decode(b []byte) (Item, error) {
	it, rest, err := decodeOne(b)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("rlp: %d trailing bytes", len(rest))
	}
	return it, nil
}

func decodeOne(b []byte) (Item, []byte, error) {
	if len(b) == 0 {
		return nil, nil, errors.New("rlp: unexpected end of input")
	}
	prefix := b[0]
	switch {
	case prefix < 0x80:
		return []byte{prefix}, b[1:], nil
	case prefix <= 0xb7:
		n := int(prefix - 0x80)
		payload, rest, err := take(b[1:], n)
		if err != nil {
			return nil, nil, err
		}
		if n == 1 && payload[0] < 0x80 {
			return nil, nil, errors.New("rlp: single byte below 0x80 must not be wrapped")
		}
		return payload, rest, nil
	case prefix <= 0xbf:
		payload, rest, err := longPayload(b, prefix-0xb7)
		if err != nil {
			return nil, nil, err
		}
		return payload, rest, nil
	case prefix <= 0xf7:
		payload, rest, err := take(b[1:], int(prefix-0xc0))
		if err != nil {
			return nil, nil, err
		}
		list, err := decodeList(payload)
		return list, rest, err
	default:
		payload, rest, err := longPayload(b, prefix-0xf7)
		if err != nil {
			return nil, nil, err
		}
		list, err := decodeList(payload)
		return list, rest, err
	}
}

// longPayload reads a long-form length of lenOfLen bytes after the prefix.
func longPayload(b []byte, lenOfLen byte) ([]byte, []byte, error) {
	lenBytes, rest, err := take(b[1:], int(lenOfLen))
	if err != nil {
		return nil, nil, err
	}
	if lenBytes[0] == 0 {
		return nil, nil, errors.New("rlp: length has leading zero")
	}
	if len(lenBytes) > 8 {
		return nil, nil, errors.New("rlp: length too large")
	}
	var n uint64
	for _, x := range lenBytes {
		n = n<<8 | uint64(x)
	}
	if n < 56 {
		return nil, nil, errors.New("rlp: long form used for short payload")
	}
	if n > uint64(len(rest)) {
		return nil, nil, errors.New("rlp: unexpected end of input")
	}
	return rest[:n], rest[n:], nil
}

func decodeList(payload []byte) ([]Item, error) {
	list := []Item{}
	for len(payload) > 0 {
		it, rest, err := decodeOne(payload)
		if err != nil {
			return nil, err
		}
		list = append(list, it)
		payload = rest
	}
	return list, nil
}

func take(b []byte, n int) ([]byte, []byte, error) {
	if n > len(b) {
		return nil, nil, errors.New("rlp: unexpected end of input")
	}
	return b[:n], b[n:], nil
}
