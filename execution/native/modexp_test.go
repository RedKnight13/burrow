// SPDX-License-Identifier: Apache-2.0

package native

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/hyperledger/burrow/execution/engine"
)

// modexpInput is EIP-198's input: three 32-byte big-endian lengths followed by
// base, exponent and modulus.
func modexpInput(baseLen, expLen, modLen uint64, rest string) []byte {
	word := func(n uint64) string {
		return strings.Repeat("00", 24) + hex.EncodeToString(big.NewInt(int64(n)).FillBytes(make([]byte, 8)))
	}
	b, _ := hex.DecodeString(word(baseLen) + word(expLen) + word(modLen) + rest)
	return b
}

func callModexp(t *testing.T, input []byte) ([]byte, error) {
	t.Helper()
	return expMod(Context{CallParams: engine.CallParams{Input: input, Gas: big.NewInt(1 << 40)}})
}

func TestModexp(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		// The example from EIP-198: Fermat's little theorem, 3^(p-1) mod p = 1.
		{"eip-198 example", modexpInput(1, 32, 32, "03"+
			"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e"+
			"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"),
			strings.Repeat("00", 31) + "01"},
		{"zero-length base is zero", modexpInput(0, 1, 1, "0205"), "00"},
		{"zero-length exponent is one", modexpInput(1, 0, 1, "0305"), "01"},
		{"zero-length modulus gives empty output", modexpInput(1, 1, 0, "0305"), ""},
		{"operands are unsigned", modexpInput(1, 1, 2, "80"+"01"+"0100"), "0080"},
		{"modulus with top bit set", modexpInput(1, 1, 1, "ff"+"01"+"81"), "7e"},
		{"short input is zero-padded", modexpInput(1, 1, 2, "03"), "0000"},
		{"modulus zero", modexpInput(1, 1, 1, "0302"+"00"), "00"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := callModexp(t, tt.input)
			if err != nil {
				t.Fatalf("expMod error %v", err)
			}
			want, _ := hex.DecodeString(tt.want)
			if !bytes.Equal(got, want) {
				t.Fatalf("expMod = %x, want %x", got, want)
			}
		})
	}
}

func TestModexpRejectsOversizedLengths(t *testing.T) {
	huge := make([]byte, 96)
	huge[0] = 1 // base length 2^248
	for _, input := range [][]byte{
		modexpInput(1025, 1, 1, ""),
		modexpInput(1, 1025, 1, ""),
		modexpInput(1, 1, 1025, ""),
		huge,
	} {
		if _, err := callModexp(t, input); err == nil {
			t.Fatalf("expMod accepted lengths %x", input[:96])
		}
	}
}
