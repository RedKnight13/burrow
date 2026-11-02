// SPDX-License-Identifier: Apache-2.0

package rlp

import (
	"encoding/hex"
	"math/big"
	"testing"
)

func TestEncode(t *testing.T) {
	lorem := "Lorem ipsum dolor sit amet, consectetur adipisicing elit"
	tests := []struct {
		name string
		item Item
		want string
	}{
		{"string", []byte("dog"), "83646f67"},
		{"list of strings", []Item{[]byte("cat"), []byte("dog")}, "c88363617483646f67"},
		{"empty string", []byte{}, "80"},
		{"empty list", []Item{}, "c0"},
		{"zero", Uint(big.NewInt(0)), "80"},
		{"fifteen", Uint(big.NewInt(15)), "0f"},
		{"1024", Uint(big.NewInt(1024)), "820400"},
		{"zero byte", []byte{0x00}, "00"},
		{"long string", []byte(lorem), "b838" + hex.EncodeToString([]byte(lorem))},
		{"set theory", []Item{[]Item{}, []Item{[]Item{}}, []Item{[]Item{}, []Item{[]Item{}}}}, "c7c0c1c0c3c0c1c0"},
		{"byte 0x80", []byte{0x80}, "8180"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hex.EncodeToString(Encode(tt.item))
			if got != tt.want {
				t.Fatalf("Encode() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestEncodeLongList(t *testing.T) {
	// 60 one-byte items: payload 60 bytes, so the list uses the long form 0xf8 0x3c.
	items := make([]Item, 60)
	for i := range items {
		items[i] = []byte{0x01}
	}
	got := Encode(items)
	if got[0] != 0xf8 || got[1] != 60 || len(got) != 62 {
		t.Fatalf("long list header = %x, len %d", got[:2], len(got))
	}
}
