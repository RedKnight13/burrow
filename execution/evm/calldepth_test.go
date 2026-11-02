// SPDX-License-Identifier: Apache-2.0

package evm

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/hyperledger/burrow/acm/acmstate"
	"github.com/hyperledger/burrow/binary"
	"github.com/hyperledger/burrow/execution/engine"
)

// TestCallDepthIsLimitedTo1024 uses a contract that increments a counter in
// storage and then calls itself with all its gas. With Ethereum's limit the
// call made at depth 1024 fails, pushes 0 and the caller carries on, so the
// counter ends at 1025 (frames at depths 0..1024) and the outer call succeeds.
func TestCallDepthIsLimitedTo1024(t *testing.T) {
	code := []byte{
		0x60, 0x00, 0x54, 0x60, 0x01, 0x01, 0x60, 0x00, 0x55, // sstore(0, sload(0) + 1)
		0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, // ret, args, value = 0
		0x30, 0x5a, 0xf1, // CALL(gas, address, ...)
		0x50, 0x00, // POP STOP
	}
	st := acmstate.NewMemoryState()
	origin := newAccount(t, st, "origin")
	self := makeAccountWithCode(t, st, "self", code)

	vm := New(engine.Options{})
	if _, err := call(vm, st, origin, self, code, nil, new(big.Int).Lsh(big.NewInt(1), 62)); err != nil {
		t.Fatalf("outer call failed: %v", err)
	}
	got, err := st.GetStorage(self, binary.Word256{})
	if err != nil {
		t.Fatal(err)
	}
	if want := binary.LeftPadBytes(big.NewInt(1025).Bytes(), 32); !bytes.Equal(binary.LeftPadBytes(got, 32), want) {
		t.Fatalf("frames executed = %x, want 1025", got)
	}
}

// TestStackIsLimitedTo1024 pushes 1025 items; Ethereum's stack holds 1024.
func TestStackIsLimitedTo1024(t *testing.T) {
	code := bytes.Repeat([]byte{0x60, 0x00}, 1025) // PUSH1 0, 1025 times
	st := acmstate.NewMemoryState()
	origin := newAccount(t, st, "origin")
	self := makeAccountWithCode(t, st, "self", code)
	if _, err := call(New(engine.Options{}), st, origin, self, code, nil, big.NewInt(1_000_000)); err == nil {
		t.Fatal("1025 stack items accepted")
	}
	ok := bytes.Repeat([]byte{0x60, 0x00}, 1024)
	if _, err := call(New(engine.Options{}), st, origin, self, ok, nil, big.NewInt(1_000_000)); err != nil {
		t.Fatalf("1024 stack items rejected: %v", err)
	}
}

func TestDefaultLimits(t *testing.T) {
	opts := New(engine.Options{}).options
	if opts.CallStackMaxDepth != 1024 || opts.DataStackMaxDepth != 1024 {
		t.Fatalf("defaults: call depth %d, stack %d; want 1024, 1024", opts.CallStackMaxDepth, opts.DataStackMaxDepth)
	}
}

// TestCreateAtDepthLimitPushesZero: a CREATE that would exceed the call depth
// fails only itself, as on Ethereum. With a limit of 1, the outer CREATE runs
// init code at depth 1 whose own CREATE is refused.
func TestCreateAtDepthLimitPushesZero(t *testing.T) {
	inner := []byte{0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0xf0, 0x00} // CREATE(0, 0, 0) STOP
	code := append([]byte{0x67}, inner...)                          // PUSH8 inner
	code = append(code,
		0x60, 0x00, 0x52, // MSTORE at 0: inner occupies bytes 24..31
		0x60, 0x08, 0x60, 0x18, 0x60, 0x00, 0xf0, // CREATE(value 0, offset 24, size 8)
		0x60, 0x00, 0x55, // SSTORE(0, created address)
		0x00)
	st := acmstate.NewMemoryState()
	origin := newAccount(t, st, "origin")
	self := makeAccountWithCode(t, st, "self", code)
	vm := New(engine.Options{CallStackMaxDepth: 1})
	if _, err := call(vm, st, origin, self, code, nil, big.NewInt(1_000_000)); err != nil {
		t.Fatalf("outer call failed: %v", err)
	}
	got, err := st.GetStorage(self, binary.Word256{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 || new(big.Int).SetBytes(got).Sign() == 0 {
		t.Fatal("outer CREATE did not succeed")
	}
}
