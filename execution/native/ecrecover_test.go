// SPDX-License-Identifier: Apache-2.0

package native

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/execution/engine"
)

// ecrecoverInput builds the precompile's Ethereum input: hash | v | r | s,
// 32 bytes each, signed with the well-known key that controls
// 0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b.
func ecrecoverInput(t *testing.T) []byte {
	t.Helper()
	key, _ := hex.DecodeString("45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8")
	priv, _ := btcec.PrivKeyFromBytes(btcec.S256(), key)
	hash := crypto.Keccak256([]byte("burrow"))
	sig, err := btcec.SignCompact(btcec.S256(), priv, hash, false) // [27+recID | r | s]
	if err != nil {
		t.Fatal(err)
	}
	input := make([]byte, 128)
	copy(input, hash)
	input[63] = sig[0]
	copy(input[64:96], sig[1:33])
	copy(input[96:128], sig[33:65])
	return input
}

func callEcrecover(t *testing.T, input []byte) []byte {
	t.Helper()
	out, err := ecrecover(Context{CallParams: engine.CallParams{Input: input, Gas: big.NewInt(1000)}})
	if err != nil {
		t.Fatalf("ecrecover returned error %v, want empty output for invalid input", err)
	}
	return out
}

func TestEcrecoverRecoversSigner(t *testing.T) {
	out := callEcrecover(t, ecrecoverInput(t))
	want, _ := hex.DecodeString("000000000000000000000000a94f5374fce5edbc8e2a8697c15331677e6ebf0b")
	if !bytes.Equal(out, want) {
		t.Fatalf("ecrecover = %x, want %x", out, want)
	}
}

func TestEcrecoverIgnoresBytesPast128(t *testing.T) {
	out := callEcrecover(t, append(ecrecoverInput(t), 0xff, 0xff))
	if len(out) != 32 || out[31] != 0x0b {
		t.Fatalf("ecrecover with trailing bytes = %x", out)
	}
}

func TestEcrecoverInvalidInputReturnsEmpty(t *testing.T) {
	n := btcec.S256().N
	tests := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"empty input", func([]byte) []byte { return nil }},
		{"hash only", func(in []byte) []byte { return in[:32] }},
		{"missing s", func(in []byte) []byte { return in[:96] }},
		{"v is 29", func(in []byte) []byte { in[63] = 29; return in }},
		{"v has high bytes", func(in []byte) []byte { in[62] = 1; return in }},
		{"r is zero", func(in []byte) []byte {
			for i := 64; i < 96; i++ {
				in[i] = 0
			}
			return in
		}},
		{"s is n", func(in []byte) []byte { n.FillBytes(in[96:128]); return in }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if out := callEcrecover(t, tt.mutate(ecrecoverInput(t))); len(out) != 0 {
				t.Fatalf("ecrecover = %x, want empty", out)
			}
		})
	}
}
