// SPDX-License-Identifier: Apache-2.0

package fixture

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
)

// Quantity is a 0x-prefixed hex number of any size. Leading zeros are allowed
// and "0x" alone means zero.
type Quantity struct {
	*big.Int
}

func (q *Quantity) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("quantity: %w", err)
	}
	digits, err := strip0x(s)
	if err != nil {
		return err
	}
	q.Int = new(big.Int)
	if digits == "" {
		return nil
	}
	if _, ok := q.Int.SetString(digits, 16); !ok {
		return fmt.Errorf("quantity: invalid hex %q", s)
	}
	return nil
}

// Big returns the value, treating an unset Quantity as zero.
func (q Quantity) Big() *big.Int {
	if q.Int == nil {
		return new(big.Int)
	}
	return q.Int
}

// Bytes is 0x-prefixed hex data. "0x" is empty.
type Bytes []byte

func (b *Bytes) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("bytes: %w", err)
	}
	digits, err := strip0x(s)
	if err != nil {
		return err
	}
	if len(digits)%2 == 1 {
		digits = "0" + digits
	}
	out, err := hex.DecodeString(digits)
	if err != nil {
		return fmt.Errorf("bytes: invalid hex %q: %w", s, err)
	}
	*b = out
	return nil
}

// ParseWord parses a hex quantity of at most 32 bytes into a left-padded word.
func ParseWord(s string) ([32]byte, error) {
	var w [32]byte
	digits, err := strip0x(s)
	if err != nil {
		return w, err
	}
	n, ok := new(big.Int).SetString("0"+digits, 16)
	if !ok {
		return w, fmt.Errorf("word: invalid hex %q", s)
	}
	if n.BitLen() > 256 {
		return w, fmt.Errorf("word: %q exceeds 32 bytes", s)
	}
	n.FillBytes(w[:])
	return w, nil
}

func strip0x(s string) (string, error) {
	if !strings.HasPrefix(s, "0x") && !strings.HasPrefix(s, "0X") {
		return "", fmt.Errorf("hex value %q lacks 0x prefix", s)
	}
	return s[2:], nil
}
