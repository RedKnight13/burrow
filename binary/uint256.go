// SPDX-License-Identifier: Apache-2.0

package binary

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
)

// Uint256 is an unsigned integer of up to 256 bits, such as an Ethereum
// balance. It is a value type: copies never share state.
//
// In protobuf it is the minimal big-endian encoding (zero is empty, no leading
// zeros). In JSON and text it is a decimal number; JSON input may also be a
// decimal string or a 0x-prefixed hex string.
type Uint256 [32]byte

var maxUint256 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))

// NewUint256 returns x as a Uint256.
func NewUint256(x uint64) Uint256 {
	var u Uint256
	new(big.Int).SetUint64(x).FillBytes(u[:])
	return u
}

// Uint256FromBig converts x, which must be in [0, 2^256).
func Uint256FromBig(x *big.Int) (Uint256, error) {
	var u Uint256
	if x.Sign() < 0 || x.Cmp(maxUint256) > 0 {
		return u, fmt.Errorf("%v is outside the range of a 256-bit unsigned integer", x)
	}
	x.FillBytes(u[:])
	return u, nil
}

// Big returns the value as a new big.Int.
func (u Uint256) Big() *big.Int {
	return new(big.Int).SetBytes(u[:])
}

// Uint64 returns the value and whether it fits in 64 bits.
func (u Uint256) Uint64() (uint64, bool) {
	b := u.Big()
	return b.Uint64(), b.IsUint64()
}

func (u Uint256) IsZero() bool {
	return u == Uint256{}
}

// Cmp compares u and v, returning -1, 0 or +1.
func (u Uint256) Cmp(v Uint256) int {
	return bytes.Compare(u[:], v[:])
}

// Add returns u + v, or an error on overflow.
func (u Uint256) Add(v Uint256) (Uint256, error) {
	return Uint256FromBig(new(big.Int).Add(u.Big(), v.Big()))
}

// Sub returns u - v, or an error if v > u.
func (u Uint256) Sub(v Uint256) (Uint256, error) {
	if u.Cmp(v) < 0 {
		return Uint256{}, fmt.Errorf("%v - %v is negative", u, v)
	}
	return Uint256FromBig(new(big.Int).Sub(u.Big(), v.Big()))
}

func (u Uint256) String() string {
	return u.Big().String()
}

// Marshal implements the gogoproto customtype interface.
func (u Uint256) Marshal() ([]byte, error) {
	return u.Big().Bytes(), nil
}

// MarshalTo implements the gogoproto customtype interface.
func (u Uint256) MarshalTo(data []byte) (int, error) {
	return copy(data, u.Big().Bytes()), nil
}

// Size implements the gogoproto customtype interface.
func (u Uint256) Size() int {
	return len(u.Big().Bytes())
}

// Unmarshal implements the gogoproto customtype interface. Only the canonical
// minimal encoding is accepted, so every value has one encoding.
func (u *Uint256) Unmarshal(data []byte) error {
	if len(data) > len(u) {
		return fmt.Errorf("uint256: %d bytes is more than 32", len(data))
	}
	if len(data) > 0 && data[0] == 0 {
		return fmt.Errorf("uint256: encoding has a leading zero")
	}
	*u = Uint256{}
	copy(u[len(u)-len(data):], data)
	return nil
}

func (u Uint256) MarshalJSON() ([]byte, error) {
	return []byte(u.String()), nil
}

func (u *Uint256) UnmarshalJSON(data []byte) error {
	s := string(data)
	if strings.HasPrefix(s, `"`) {
		if err := json.Unmarshal(data, &s); err != nil {
			return fmt.Errorf("uint256: %w", err)
		}
	}
	return u.UnmarshalText([]byte(s))
}

func (u Uint256) MarshalText() ([]byte, error) {
	return []byte(u.String()), nil
}

// UnmarshalText parses a decimal number or a 0x-prefixed hex number.
func (u *Uint256) UnmarshalText(text []byte) error {
	s := string(text)
	base := 10
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s, base = s[2:], 16
	}
	if s == "" || strings.ContainsAny(s, "+-") {
		return fmt.Errorf("uint256: invalid number %q", text)
	}
	x, ok := new(big.Int).SetString(s, base)
	if !ok {
		return fmt.Errorf("uint256: invalid number %q", text)
	}
	v, err := Uint256FromBig(x)
	if err != nil {
		return fmt.Errorf("uint256: %w", err)
	}
	*u = v
	return nil
}
