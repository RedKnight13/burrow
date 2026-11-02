// SPDX-License-Identifier: Apache-2.0

package trie

import (
	"encoding/hex"
	"testing"

	"github.com/hyperledger/burrow/execution/ethtest/rlp"
)

const emptyRoot = "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"

// rawValues stores each value's bytes as-is, which is how the reference
// vectors were built.
func rawValues(kv map[string]string) map[string][]byte {
	out := make(map[string][]byte, len(kv))
	for k, v := range kv {
		out[k] = []byte(v)
	}
	return out
}

func TestRoot(t *testing.T) {
	tests := []struct {
		name string
		kv   map[string][]byte
		want string
	}{
		{"empty", map[string][]byte{}, emptyRoot},
		{"nil", nil, emptyRoot},
		{
			"doe dog dogglesworth",
			rawValues(map[string]string{"doe": "reindeer", "dog": "puppy", "dogglesworth": "cat"}),
			"8aad789dff2f538bca5d8ea56e8abe10f4c7ba3a5dea95fea4cd6e7c3a1168d3",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Root(tt.kv)
			if hex.EncodeToString(got[:]) != tt.want {
				t.Fatalf("Root() = %x, want %s", got, tt.want)
			}
		})
	}
}

func TestRootSingleKeyDiffersFromEmpty(t *testing.T) {
	got := Root(rawValues(map[string]string{"a": "b"}))
	if hex.EncodeToString(got[:]) == emptyRoot {
		t.Fatal("single-key root equals empty root")
	}
}

func TestRootIndependentOfInsertionOrder(t *testing.T) {
	keys := []string{"horse", "do", "dog", "doge", "d", "dogglesworth", "a"}
	a := map[string][]byte{}
	for _, k := range keys {
		a[k] = rlp.Encode([]byte("v-" + k))
	}
	b := map[string][]byte{}
	for i := len(keys) - 1; i >= 0; i-- {
		b[keys[i]] = rlp.Encode([]byte("v-" + keys[i]))
	}
	if Root(a) != Root(b) {
		t.Fatal("root depends on insertion order")
	}
}
