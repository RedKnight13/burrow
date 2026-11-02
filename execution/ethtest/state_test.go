// SPDX-License-Identifier: Apache-2.0

package ethtest

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/hyperledger/burrow/execution/ethtest/fixture"
)

func alloc(t *testing.T, js string) fixture.Alloc {
	t.Helper()
	var a fixture.Alloc
	if err := json.Unmarshal([]byte(js), &a); err != nil {
		t.Fatal(err)
	}
	return a
}

func mustAllocRoot(t *testing.T, a fixture.Alloc) string {
	t.Helper()
	r, err := AllocRoot(a)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(r[:])
}

func TestAllocRootEmpty(t *testing.T) {
	got := mustAllocRoot(t, fixture.Alloc{})
	if got != "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421" {
		t.Fatalf("empty alloc root = %s", got)
	}
}

func TestEmptyCodeHash(t *testing.T) {
	got := hex.EncodeToString(codeHash(nil))
	if got != "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470" {
		t.Fatalf("codeHash(empty) = %s", got)
	}
}

func TestZeroStorageOmitted(t *testing.T) {
	with := alloc(t, `{"0x1000000000000000000000000000000000000000":{"nonce":"0x01","balance":"0x02","code":"0x00","storage":{"0x01":"0x05","0x02":"0x00"}}}`)
	without := alloc(t, `{"0x1000000000000000000000000000000000000000":{"nonce":"0x01","balance":"0x02","code":"0x00","storage":{"0x01":"0x05"}}}`)
	if mustAllocRoot(t, with) != mustAllocRoot(t, without) {
		t.Fatal("zero storage value changed the root")
	}
}

func TestStorageAffectsRoot(t *testing.T) {
	a := alloc(t, `{"0x1000000000000000000000000000000000000000":{"nonce":"0x01","balance":"0x02","code":"0x","storage":{"0x01":"0x05"}}}`)
	b := alloc(t, `{"0x1000000000000000000000000000000000000000":{"nonce":"0x01","balance":"0x02","code":"0x","storage":{"0x01":"0x06"}}}`)
	if mustAllocRoot(t, a) == mustAllocRoot(t, b) {
		t.Fatal("different storage gave the same root")
	}
}

func TestLoadAllocBalanceTooBig(t *testing.T) {
	a := alloc(t, `{"0x1000000000000000000000000000000000000000":{"nonce":"0x00","balance":"0x010000000000000000","code":"0x","storage":{}}}`)
	_, err := LoadAlloc(a)
	var unsupported ErrUnsupported
	if !errors.As(err, &unsupported) || unsupported.What != "balance > uint64" {
		t.Fatalf("err = %v, want ErrUnsupported{balance > uint64}", err)
	}
}

func TestStateRootMatchesAllocRoot(t *testing.T) {
	a := alloc(t, `{
		"0x1000000000000000000000000000000000000000":{"nonce":"0x01","balance":"0x0de0b6b3a7640000","code":"0x6001600055","storage":{"0x00":"0x2a","0x0100":"0x0101"}},
		"0xf6c3a9edc1afa0ad5b720e4d42e1437c43d3b3ff":{"nonce":"0x00","balance":"0x0a","code":"0x","storage":{}}
	}`)
	st, err := LoadAlloc(a)
	if err != nil {
		t.Fatal(err)
	}
	got, err := StateRoot(st, false)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got[:]) != mustAllocRoot(t, a) {
		t.Fatalf("StateRoot = %x, AllocRoot = %s", got, mustAllocRoot(t, a))
	}
}

func TestStateRootZeroAddress(t *testing.T) {
	st, err := LoadAlloc(fixture.Alloc{})
	if err != nil {
		t.Fatal(err)
	}
	without, err := StateRoot(st, false)
	if err != nil {
		t.Fatal(err)
	}
	with, err := StateRoot(st, true)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(without[:]) != "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421" {
		t.Fatalf("seeded 0x0 account leaked into root: %x", without)
	}
	if with == without {
		t.Fatal("includeZeroAddr had no effect")
	}
}
