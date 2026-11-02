// SPDX-License-Identifier: Apache-2.0

package binary

import (
	"bytes"
	"encoding/json"
	"math/big"
	"testing"
)

func max256() *big.Int {
	return new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
}

func TestUint256FromBig(t *testing.T) {
	if _, err := Uint256FromBig(big.NewInt(-1)); err == nil {
		t.Fatal("accepted a negative value")
	}
	if _, err := Uint256FromBig(new(big.Int).Lsh(big.NewInt(1), 256)); err == nil {
		t.Fatal("accepted 2^256")
	}
	u, err := Uint256FromBig(max256())
	if err != nil {
		t.Fatal(err)
	}
	if u.Big().Cmp(max256()) != 0 {
		t.Fatalf("round trip = %v", u.Big())
	}
}

func TestUint256Arithmetic(t *testing.T) {
	a, b := NewUint256(5), NewUint256(7)
	sum, err := a.Add(b)
	if err != nil || sum.Big().Int64() != 12 {
		t.Fatalf("5+7 = %v, %v", sum.Big(), err)
	}
	if _, err := a.Sub(b); err == nil {
		t.Fatal("5-7 did not underflow")
	}
	diff, err := b.Sub(a)
	if err != nil || diff.Big().Int64() != 2 {
		t.Fatalf("7-5 = %v, %v", diff.Big(), err)
	}
	top, _ := Uint256FromBig(max256())
	if _, err := top.Add(NewUint256(1)); err == nil {
		t.Fatal("max+1 did not overflow")
	}
	if a.Big().Int64() != 5 {
		t.Fatal("Add mutated its receiver")
	}
	if a.Cmp(b) >= 0 || b.Cmp(a) <= 0 || a.Cmp(NewUint256(5)) != 0 {
		t.Fatal("Cmp is wrong")
	}
	if n, ok := NewUint256(42).Uint64(); !ok || n != 42 {
		t.Fatal("Uint64 of 42")
	}
	if _, ok := top.Uint64(); ok {
		t.Fatal("Uint64 of 2^256-1 reported ok")
	}
}

func TestUint256Protobuf(t *testing.T) {
	tests := []struct {
		value *big.Int
		wire  []byte
	}{
		{big.NewInt(0), []byte{}},
		{big.NewInt(1), []byte{1}},
		{big.NewInt(256), []byte{1, 0}},
		{max256(), bytes.Repeat([]byte{0xff}, 32)},
	}
	for _, tt := range tests {
		u, err := Uint256FromBig(tt.value)
		if err != nil {
			t.Fatal(err)
		}
		got, err := u.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, tt.wire) || u.Size() != len(tt.wire) {
			t.Fatalf("Marshal(%v) = %x (size %d), want %x", tt.value, got, u.Size(), tt.wire)
		}
		buf := make([]byte, u.Size())
		if n, err := u.MarshalTo(buf); err != nil || n != len(tt.wire) || !bytes.Equal(buf, tt.wire) {
			t.Fatalf("MarshalTo(%v) = %x, %d, %v", tt.value, buf, n, err)
		}
		var back Uint256
		if err := back.Unmarshal(tt.wire); err != nil || back.Cmp(u) != 0 {
			t.Fatalf("Unmarshal(%x) = %v, %v", tt.wire, back.Big(), err)
		}
	}
	var u Uint256
	if err := u.Unmarshal(make([]byte, 33)); err == nil {
		t.Fatal("accepted 33 bytes")
	}
	if err := u.Unmarshal([]byte{0, 1}); err == nil {
		t.Fatal("accepted a leading zero")
	}
}

func TestUint256JSON(t *testing.T) {
	big := max256()
	u, _ := Uint256FromBig(big)
	got, err := json.Marshal(u)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != big.String() {
		t.Fatalf("Marshal = %s, want the bare decimal %s", got, big)
	}
	for _, in := range []string{`99999`, `"99999"`, `"0x1869f"`} {
		var v Uint256
		if err := json.Unmarshal([]byte(in), &v); err != nil {
			t.Fatalf("Unmarshal(%s): %v", in, err)
		}
		if n, _ := v.Uint64(); n != 99999 {
			t.Fatalf("Unmarshal(%s) = %v", in, v.Big())
		}
	}
	for _, in := range []string{`-1`, `1.5`, `"abc"`, `"0x"`, `null`} {
		var v Uint256
		if err := json.Unmarshal([]byte(in), &v); err == nil {
			t.Fatalf("Unmarshal(%s) succeeded", in)
		}
	}
}

func TestUint256Text(t *testing.T) {
	var v Uint256
	if err := v.UnmarshalText([]byte("123")); err != nil {
		t.Fatal(err)
	}
	if got, _ := v.MarshalText(); string(got) != "123" {
		t.Fatalf("MarshalText = %s", got)
	}
}
