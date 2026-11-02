// SPDX-License-Identifier: Apache-2.0

// Package rlp implements the Recursive Length Prefix encoding described in
// appendix B of the Ethereum Yellow Paper. Only encoding is provided; it is
// what the conformance harness needs to compute state roots and logs hashes.
package rlp

import (
	"fmt"
	"math/big"
)

// Item is either a []byte (an RLP string) or a []Item (an RLP list).
type Item interface{}

// Encode returns the RLP encoding of it. It panics if it, or anything nested
// in it, is neither []byte nor []Item.
func Encode(it Item) []byte {
	switch v := it.(type) {
	case []byte:
		if len(v) == 1 && v[0] < 0x80 {
			return []byte{v[0]}
		}
		return append(header(0x80, len(v)), v...)
	case []Item:
		var payload []byte
		for _, child := range v {
			payload = append(payload, Encode(child)...)
		}
		return append(header(0xc0, len(payload)), payload...)
	default:
		panic(fmt.Sprintf("rlp: cannot encode %T", it))
	}
}

// Uint returns the minimal big-endian encoding of n: no leading zeros, and
// zero is the empty string.
func Uint(n *big.Int) []byte {
	return n.Bytes()
}

func header(offset byte, length int) []byte {
	if length < 56 {
		return []byte{offset + byte(length)}
	}
	lenBytes := big.NewInt(int64(length)).Bytes()
	return append([]byte{offset + 55 + byte(len(lenBytes))}, lenBytes...)
}
