// SPDX-License-Identifier: Apache-2.0

// Package trie computes the root hash of a Merkle Patricia trie as defined in
// appendix D of the Ethereum Yellow Paper. It builds the trie once from a full
// key/value set and does not support updates or proofs.
package trie

import (
	"sort"

	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/execution/ethtest/rlp"
)

type entry struct {
	key   []byte // one nibble per byte
	value []byte
}

// Root returns the trie root for kv. Keys are raw byte strings; values are the
// leaf values exactly as they should be stored (callers RLP-encode them).
func Root(kv map[string][]byte) [32]byte {
	entries := make([]entry, 0, len(kv))
	for k, v := range kv {
		entries = append(entries, entry{key: nibbles([]byte(k)), value: v})
	}
	sort.Slice(entries, func(i, j int) bool {
		return string(entries[i].key) < string(entries[j].key)
	})
	var root [32]byte
	copy(root[:], crypto.Keccak256(rlp.Encode(node(entries, 0))))
	return root
}

// node returns the structure of the node holding entries, all of which share
// their first depth nibbles.
func node(entries []entry, depth int) rlp.Item {
	switch len(entries) {
	case 0:
		return []byte{}
	case 1:
		return []rlp.Item{hexPrefix(entries[0].key[depth:], true), entries[0].value}
	}
	if shared := commonPrefix(entries, depth); shared > depth {
		return []rlp.Item{hexPrefix(entries[0].key[depth:shared], false), ref(entries, shared)}
	}
	branch := make([]rlp.Item, 17)
	branch[16] = []byte{}
	rest := entries
	if len(rest[0].key) == depth {
		// Sorted order puts the key that ends here first.
		branch[16] = rest[0].value
		rest = rest[1:]
	}
	for n := byte(0); n < 16; n++ {
		end := 0
		for end < len(rest) && rest[end].key[depth] == n {
			end++
		}
		branch[n] = ref(rest[:end], depth+1)
		rest = rest[end:]
	}
	return branch
}

// ref returns how a parent refers to a child node: inline when its encoding is
// shorter than 32 bytes, otherwise by hash.
func ref(entries []entry, depth int) rlp.Item {
	if len(entries) == 0 {
		return []byte{}
	}
	n := node(entries, depth)
	enc := rlp.Encode(n)
	if len(enc) < 32 {
		return n
	}
	return crypto.Keccak256(enc)
}

func commonPrefix(entries []entry, depth int) int {
	first, last := entries[0].key, entries[len(entries)-1].key
	i := depth
	for i < len(first) && i < len(last) && first[i] == last[i] {
		i++
	}
	return i
}

func nibbles(key []byte) []byte {
	out := make([]byte, 0, 2*len(key))
	for _, b := range key {
		out = append(out, b>>4, b&0x0f)
	}
	return out
}

// hexPrefix is the HP encoding of a nibble path, flagged as leaf or extension.
func hexPrefix(path []byte, leaf bool) []byte {
	var flag byte
	if leaf {
		flag = 2
	}
	var out []byte
	if len(path)%2 == 1 {
		out = append(out, (flag+1)<<4|path[0])
		path = path[1:]
	} else {
		out = append(out, flag<<4)
	}
	for i := 0; i < len(path); i += 2 {
		out = append(out, path[i]<<4|path[i+1])
	}
	return out
}
