// SPDX-License-Identifier: Apache-2.0

package rlp

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestDecodeRoundTrip(t *testing.T) {
	items := []Item{
		[]byte("dog"),
		[]byte{},
		[]byte{0x00},
		[]byte{0x7f},
		[]byte{0x80},
		[]byte("Lorem ipsum dolor sit amet, consectetur adipisicing elit"),
		[]Item{},
		[]Item{[]byte("cat"), []byte("dog")},
		[]Item{[]Item{}, []Item{[]Item{}}, []Item{[]Item{}, []Item{[]Item{}}}},
	}
	for _, it := range items {
		enc := Encode(it)
		got, err := Decode(enc)
		if err != nil {
			t.Fatalf("Decode(%x): %v", enc, err)
		}
		if !bytes.Equal(Encode(got), enc) {
			t.Fatalf("round trip %x -> %x", enc, Encode(got))
		}
	}
}

func TestDecodeRejects(t *testing.T) {
	tests := []struct {
		name string
		hex  string
	}{
		{"empty input", ""},
		{"trailing bytes", "8364" + "6f6700"},
		{"truncated string", "83646f"},
		{"truncated list", "c88363617483"},
		{"single byte as short string", "8100"},
		{"short string in long form", "b8020102"},
		{"length with leading zero", "b90002" + "0102"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in, _ := hex.DecodeString(tt.hex)
			if _, err := Decode(in); err == nil {
				t.Fatalf("Decode(%s) succeeded, want error", tt.hex)
			}
		})
	}
}
