// SPDX-License-Identifier: Apache-2.0

package evm

import (
	"math/big"
	"testing"

	"github.com/hyperledger/burrow/acm"
	"github.com/hyperledger/burrow/acm/acmstate"
	"github.com/hyperledger/burrow/binary"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/execution/engine"
	"github.com/hyperledger/burrow/permission"
)

// callerOf returns code that CALLs target with 1000 gas, then stores the
// success flag in slot 0, RETURNDATASIZE in slot 2 and 1 in slot 1 (proof the
// caller carried on).
func callerOf(target crypto.Address) []byte {
	code := []byte{0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x73}
	code = append(code, target.Bytes()...)
	return append(code,
		0x61, 0x03, 0xe8, 0xf1, // PUSH2 1000, CALL
		0x60, 0x00, 0x55, // sstore(0, success)
		0x3d, 0x60, 0x02, 0x55, // sstore(2, returndatasize)
		0x60, 0x01, 0x60, 0x01, 0x55, // sstore(1, 1)
		0x00)
}

func slot(t *testing.T, st acmstate.Reader, addr crypto.Address, i int64) int64 {
	t.Helper()
	v, err := st.GetStorage(addr, binary.LeftPadWord256(big.NewInt(i).Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	return new(big.Int).SetBytes(v).Int64()
}

// TestFailedSubCallReturnsZero: on Ethereum an exceptional halt in a callee
// only makes its CALL return 0; the caller continues.
func TestFailedSubCallReturnsZero(t *testing.T) {
	tests := []struct {
		name   string
		callee []byte
	}{
		{"invalid opcode", []byte{0xfe}},
		{"stack underflow", []byte{0x01}},                // ADD on an empty stack
		{"bad jump", []byte{0x60, 0x00, 0x56}},           // JUMP to 0, not a JUMPDEST
		{"out of gas", []byte{0x5b, 0x60, 0x00, 0x56}},   // loop until the 1000 gas runs out
		{"revert", []byte{0x60, 0x00, 0x60, 0x00, 0xfd}}, // REVERT(0, 0)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := acmstate.NewMemoryState()
			origin := newAccount(t, st, "origin")
			callee := makeAccountWithCode(t, st, "callee", tt.callee)
			code := callerOf(callee)
			caller := makeAccountWithCode(t, st, "caller", code)
			if _, err := call(New(engine.Options{}), st, origin, caller, code, nil, big.NewInt(100000)); err != nil {
				t.Fatalf("caller aborted: %v", err)
			}
			if slot(t, st, caller, 1) != 1 || slot(t, st, caller, 0) != 0 || slot(t, st, caller, 2) != 0 {
				t.Fatalf("continued=%d success=%d returndatasize=%d, want 1 0 0",
					slot(t, st, caller, 1), slot(t, st, caller, 0), slot(t, st, caller, 2))
			}
		})
	}
}

// TestPermissionDenialInSubCallAborts: Burrow's permission model stays strict;
// a callee that is denied a permission aborts the whole call.
func TestPermissionDenialInSubCallAborts(t *testing.T) {
	st := acmstate.NewMemoryState()
	origin := newAccount(t, st, "origin")
	other := newAccount(t, st, "other")
	inner := callerOf(other)
	callee := makeAccountWithCode(t, st, "callee", inner)
	err := engine.UpdateAccount(st, callee, func(acc *acm.Account) error {
		return acc.Permissions.Base.Set(permission.Call, false)
	})
	if err != nil {
		t.Fatal(err)
	}
	code := callerOf(callee)
	caller := makeAccountWithCode(t, st, "caller", code)
	if _, err := call(New(engine.Options{}), st, origin, caller, code, nil, big.NewInt(100000)); err == nil {
		t.Fatal("permission denial inside a sub-call did not abort the caller")
	}
}

// TestCreateCollisionReturnsZero: CREATE2 twice with the same salt and code
// targets the same address. As on Ethereum the second returns 0 and the caller
// continues.
func TestCreateCollisionReturnsZero(t *testing.T) {
	create2 := []byte{0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0xf5} // CREATE2(value 0, offset 0, size 0, salt 0)
	code := append(append([]byte{}, create2...), 0x60, 0x00, 0x55)          // sstore(0, first address)
	code = append(code, create2...)
	code = append(code, 0x60, 0x01, 0x55, 0x60, 0x01, 0x60, 0x02, 0x55, 0x00) // sstore(1, second); sstore(2, 1)
	st := acmstate.NewMemoryState()
	origin := newAccount(t, st, "origin")
	self := makeAccountWithCode(t, st, "self", code)
	if _, err := call(New(engine.Options{}), st, origin, self, code, nil, big.NewInt(100000)); err != nil {
		t.Fatalf("caller aborted: %v", err)
	}
	if slot(t, st, self, 0) == 0 || slot(t, st, self, 1) != 0 || slot(t, st, self, 2) != 1 {
		t.Fatalf("first=%d second=%d continued=%d, want non-zero 0 1",
			slot(t, st, self, 0), slot(t, st, self, 1), slot(t, st, self, 2))
	}
}
