// SPDX-License-Identifier: Apache-2.0

package ethtx

import (
	"bytes"
	"encoding/hex"
	"math"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/hyperledger/burrow/acm"
	"github.com/hyperledger/burrow/acm/acmstate"
	"github.com/hyperledger/burrow/binary"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/execution/evm/rlp"
	"github.com/hyperledger/burrow/permission"
)

// Well-known test key: 0x45a9…f2d8 controls 0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b.
var (
	testKey, _  = hex.DecodeString("45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8")
	testSender  = crypto.MustAddressFromHexString("a94f5374fce5edbc8e2a8697c15331677e6ebf0b")
	contract    = crypto.MustAddressFromHexString("1000000000000000000000000000000000000000")
	coinbase    = crypto.MustAddressFromHexString("2adc25665018aa1fe0e6bc666dac8fc2697ff9ba")
	testChainID = big.NewInt(1)
)

type unsigned struct {
	nonce, gasPrice, gas uint64
	to                   *crypto.Address
	value                uint64
	data                 []byte
}

// sign builds a legacy transaction, EIP-155 when chainID is non-nil.
func sign(t *testing.T, u unsigned, chainID *big.Int) []byte {
	t.Helper()
	to := []byte{}
	if u.to != nil {
		to = u.to.Bytes()
	}
	fields := []rlp.Item{
		rlp.Uint(new(big.Int).SetUint64(u.nonce)), rlp.Uint(new(big.Int).SetUint64(u.gasPrice)),
		rlp.Uint(new(big.Int).SetUint64(u.gas)), to, rlp.Uint(new(big.Int).SetUint64(u.value)), u.data,
	}
	signing := fields
	if chainID != nil {
		signing = append(append([]rlp.Item{}, fields...), rlp.Uint(chainID), []byte{}, []byte{})
	}
	hash := crypto.Keccak256(rlp.Encode(signing))
	priv, _ := btcec.PrivKeyFromBytes(btcec.S256(), testKey)
	compact, err := btcec.SignCompact(btcec.S256(), priv, hash, false)
	if err != nil {
		t.Fatal(err)
	}
	recID := int64(compact[0] - 27)
	v := big.NewInt(27 + recID)
	if chainID != nil {
		v = new(big.Int).Add(new(big.Int).Mul(chainID, big.NewInt(2)), big.NewInt(35+recID))
	}
	r := new(big.Int).SetBytes(compact[1:33])
	s := new(big.Int).SetBytes(compact[33:65])
	return rlp.Encode(append(fields, rlp.Uint(v), rlp.Uint(r), rlp.Uint(s)))
}

func newState(t *testing.T, code []byte, senderPerms permission.AccountPermissions) *acmstate.MemoryState {
	t.Helper()
	st := acmstate.NewMemoryState()
	// Burrow's global permissions account grants nothing, so tests see only
	// the permissions set on each account.
	st.Accounts[acm.GlobalPermissionsAddress].Permissions = permission.ZeroAccountPermissions
	for _, acc := range []*acm.Account{
		{Address: testSender, Balance: 1_000_000_000, Permissions: senderPerms},
		{Address: contract, EVMCode: code, Permissions: permission.AllAccountPermissions},
	} {
		if err := st.UpdateAccount(acc); err != nil {
			t.Fatal(err)
		}
	}
	return st
}

func env() Env {
	return Env{ChainID: testChainID, Coinbase: coinbase, Number: 1, Timestamp: 1000, GasLimit: 10_000_000}
}

func account(t *testing.T, st acmstate.Reader, addr crypto.Address) *acm.Account {
	t.Helper()
	acc, err := st.GetAccount(addr)
	if err != nil {
		t.Fatal(err)
	}
	return acc
}

func TestSenderRecovery(t *testing.T) {
	for _, chainID := range []*big.Int{nil, testChainID} {
		raw := sign(t, unsigned{gasPrice: 1, gas: 21000, to: &contract}, chainID)
		tx, err := Decode(raw)
		if err != nil {
			t.Fatal(err)
		}
		got, err := tx.Sender(testChainID)
		if err != nil {
			t.Fatal(err)
		}
		if got != testSender {
			t.Fatalf("chainID %v: sender %v, want %v", chainID, got, testSender)
		}
	}
}

func TestWrongChainIDIsInvalid(t *testing.T) {
	raw := sign(t, unsigned{gasPrice: 1, gas: 21000, to: &contract}, big.NewInt(5))
	res := Apply(raw, newState(t, []byte{0x00}, permission.AllAccountPermissions), env())
	if res.Status != Invalid || res.Reason != ReasonChainID {
		t.Fatalf("got %v %v", res.Status, res.Reason)
	}
}

func TestApplyCallTransfersValueAndChargesFee(t *testing.T) {
	st := newState(t, []byte{0x00}, permission.AllAccountPermissions) // STOP
	raw := sign(t, unsigned{gasPrice: 2, gas: 50000, to: &contract, value: 5}, testChainID)

	res := Apply(raw, st, env())
	if res.Status != Success {
		t.Fatalf("status %v %v: %v", res.Status, res.Reason, res.Err)
	}
	if res.GasUsed != 21000 {
		t.Fatalf("gas used %d, want 21000 (intrinsic only; STOP costs nothing in Burrow)", res.GasUsed)
	}
	if account(t, st, testSender).Balance != 1_000_000_000 || account(t, st, testSender).Sequence != 0 {
		t.Fatal("Apply mutated the caller's state")
	}

	if err := res.RWSet.ApplyTo(st); err != nil {
		t.Fatal(err)
	}
	sender := account(t, st, testSender)
	if sender.Balance != 1_000_000_000-5-21000*2 || sender.Sequence != 1 {
		t.Fatalf("sender after = balance %d nonce %d", sender.Balance, sender.Sequence)
	}
	if got := account(t, st, contract).Balance; got != 5 {
		t.Fatalf("contract balance %d, want 5", got)
	}
	if got := account(t, st, coinbase); got == nil || got.Balance != 21000*2 {
		t.Fatalf("coinbase = %+v, want balance %d", got, 21000*2)
	}
}

func TestPermissionsAreEnforced(t *testing.T) {
	noCall := permission.NewAccountPermissions(permission.Input)
	st := newState(t, []byte{0x00}, noCall)
	raw := sign(t, unsigned{gasPrice: 1, gas: 50000, to: &contract}, testChainID)
	res := Apply(raw, st, env())
	if res.Status != Invalid || res.Reason != ReasonPermission {
		t.Fatalf("got %v %v, want invalid permission", res.Status, res.Reason)
	}
	if len(res.RWSet.Writes) != 0 {
		t.Fatalf("invalid tx produced writes: %+v", res.RWSet.Writes)
	}

	noInput := permission.NewAccountPermissions(permission.Call)
	res = Apply(raw, newState(t, []byte{0x00}, noInput), env())
	if res.Status != Invalid || res.Reason != ReasonPermission {
		t.Fatalf("without Input: got %v %v, want invalid permission", res.Status, res.Reason)
	}
}

func TestValidation(t *testing.T) {
	tests := []struct {
		name string
		tx   unsigned
		want Reason
	}{
		{"nonce too high", unsigned{nonce: 1, gasPrice: 1, gas: 50000, to: &contract}, ReasonNonceTooHigh},
		{"intrinsic gas too low", unsigned{gasPrice: 1, gas: 20999, to: &contract}, ReasonIntrinsicGas},
		{"insufficient funds", unsigned{gasPrice: 1_000_000, gas: 50000, to: &contract}, ReasonInsufficientFunds},
		{"gas above block limit", unsigned{gasPrice: 1, gas: 10_000_001, to: &contract}, ReasonGasLimit},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := Apply(sign(t, tt.tx, testChainID), newState(t, []byte{0x00}, permission.AllAccountPermissions), env())
			if res.Status != Invalid || res.Reason != tt.want {
				t.Fatalf("got %v %v, want invalid %v", res.Status, res.Reason, tt.want)
			}
		})
	}
}

func TestApplyCreate(t *testing.T) {
	st := newState(t, nil, permission.AllAccountPermissions)
	// Init code returns the one-byte runtime code 0x00:
	// PUSH1 0 PUSH1 0 MSTORE8 PUSH1 1 PUSH1 0 RETURN
	initCode := []byte{0x60, 0x00, 0x60, 0x00, 0x53, 0x60, 0x01, 0x60, 0x00, 0xf3}
	res := Apply(sign(t, unsigned{gasPrice: 1, gas: 100000, data: initCode}, testChainID), st, env())
	if res.Status != Success {
		t.Fatalf("status %v %v: %v", res.Status, res.Reason, res.Err)
	}
	want := crypto.Keccak256(rlp.Encode([]rlp.Item{testSender.Bytes(), []byte{}}))[12:]
	if res.Created == nil || !bytes.Equal(res.Created.Bytes(), want) {
		t.Fatalf("created %v, want %x", res.Created, want)
	}
	if err := res.RWSet.ApplyTo(st); err != nil {
		t.Fatal(err)
	}
	if code := account(t, st, *res.Created).EVMCode; !bytes.Equal(code, []byte{0x00}) {
		t.Fatalf("created code %x", code)
	}
}

func TestFailedCallKeepsNonceAndFeeOnly(t *testing.T) {
	// PUSH1 1 PUSH1 0 SSTORE INVALID
	st := newState(t, []byte{0x60, 0x01, 0x60, 0x00, 0x55, 0xfe}, permission.AllAccountPermissions)
	res := Apply(sign(t, unsigned{gasPrice: 1, gas: 50000, to: &contract, value: 7}, testChainID), st, env())
	if res.Status != Failed {
		t.Fatalf("status %v, want failed", res.Status)
	}
	if len(res.Logs) != 0 {
		t.Fatal("failed tx kept logs")
	}
	if err := res.RWSet.ApplyTo(st); err != nil {
		t.Fatal(err)
	}
	if v, _ := st.GetStorage(contract, binary.Word256{}); len(v) != 0 && new(big.Int).SetBytes(v).Sign() != 0 {
		t.Fatalf("failed call kept storage write %x", v)
	}
	sender := account(t, st, testSender)
	if sender.Sequence != 1 || sender.Balance != 1_000_000_000-res.GasUsed {
		t.Fatalf("sender after failure: nonce %d balance %d (gas used %d)", sender.Sequence, sender.Balance, res.GasUsed)
	}
	if account(t, st, contract).Balance != 0 {
		t.Fatal("value transferred despite failure")
	}
}

func TestLogs(t *testing.T) {
	// PUSH1 0 PUSH1 0 LOG0
	st := newState(t, []byte{0x60, 0x00, 0x60, 0x00, 0xa0}, permission.AllAccountPermissions)
	res := Apply(sign(t, unsigned{gasPrice: 1, gas: 50000, to: &contract}, testChainID), st, env())
	if res.Status != Success || len(res.Logs) != 1 || res.Logs[0].Address != contract {
		t.Fatalf("status %v, logs %+v", res.Status, res.Logs)
	}
}

func TestTypedTransactionUnsupported(t *testing.T) {
	res := Apply([]byte{0x02, 0xc0}, newState(t, nil, permission.AllAccountPermissions), env())
	if res.Status != Unsupported {
		t.Fatalf("status %v, want unsupported", res.Status)
	}
}

func TestRWSetIsDeterministicAndSorted(t *testing.T) {
	// PUSH1 1 PUSH1 2 SSTORE PUSH1 1 PUSH1 1 SSTORE: slots 2 then 1
	code := []byte{0x60, 0x01, 0x60, 0x02, 0x55, 0x60, 0x01, 0x60, 0x01, 0x55}
	raw := sign(t, unsigned{gasPrice: 1, gas: 50000, to: &contract}, testChainID)
	a := Apply(raw, newState(t, code, permission.AllAccountPermissions), env())
	b := Apply(raw, newState(t, code, permission.AllAccountPermissions), env())
	if a.Status != Success {
		t.Fatalf("status %v %v: %v", a.Status, a.Reason, a.Err)
	}
	if !bytes.Equal(a.RWSet.Encode(), b.RWSet.Encode()) {
		t.Fatal("rw-set differs between identical runs")
	}
	for _, list := range [][]Entry{a.RWSet.Reads, a.RWSet.Writes} {
		for i := 1; i < len(list); i++ {
			if !list[i-1].less(list[i]) {
				t.Fatalf("entries not strictly sorted: %v before %v", list[i-1], list[i])
			}
		}
	}
	var slots []string
	for _, w := range a.RWSet.Writes {
		if w.Address == contract && w.Slot != nil {
			slots = append(slots, hex.EncodeToString(w.Slot.Bytes()[31:]))
		}
	}
	if len(slots) != 2 || slots[0] != "01" || slots[1] != "02" {
		t.Fatalf("contract storage writes %v, want [01 02]", slots)
	}
}

func TestFailedCreateLeavesNoAccount(t *testing.T) {
	st := newState(t, nil, permission.AllAccountPermissions)
	res := Apply(sign(t, unsigned{gasPrice: 1, gas: 100000, data: []byte{0xfe}}, testChainID), st, env()) // INVALID
	if res.Status != Failed || res.Created != nil {
		t.Fatalf("status %v created %v, want failed and nil", res.Status, res.Created)
	}
	addr := crypto.Keccak256(rlp.Encode([]rlp.Item{testSender.Bytes(), []byte{}}))[12:]
	for _, w := range res.RWSet.Writes {
		if bytes.Equal(w.Address.Bytes(), addr) {
			t.Fatalf("failed create wrote %v", w)
		}
	}
}

// TestEthereumChecksComeBeforePermissions: Ethereum's validity rules are
// checked first, then Burrow's permissions, which are never skipped.
func TestEthereumChecksComeBeforePermissions(t *testing.T) {
	noPerms := permission.NewAccountPermissions()
	raw := sign(t, unsigned{nonce: 3, gasPrice: 1, gas: 50000, to: &contract}, testChainID)
	res := Apply(raw, newState(t, []byte{0x00}, noPerms), env())
	if res.Status != Invalid || res.Reason != ReasonNonceTooHigh {
		t.Fatalf("got %v %v, want invalid nonce too high", res.Status, res.Reason)
	}
}

// TestMissingSenderIsAnEmptyAccount: as on Ethereum, a sender with no account
// has nonce 0 and balance 0.
func TestMissingSenderIsAnEmptyAccount(t *testing.T) {
	st := newState(t, []byte{0x00}, permission.AllAccountPermissions)
	if err := st.RemoveAccount(testSender); err != nil {
		t.Fatal(err)
	}
	paying := sign(t, unsigned{gasPrice: 1, gas: 50000, to: &contract}, testChainID)
	if res := Apply(paying, st, env()); res.Status != Invalid || res.Reason != ReasonInsufficientFunds {
		t.Fatalf("paying tx: got %v %v, want invalid insufficient funds", res.Status, res.Reason)
	}

	free := sign(t, unsigned{gasPrice: 0, gas: 50000, to: &contract}, testChainID)
	if res := Apply(free, st, env()); res.Status != Invalid || res.Reason != ReasonPermission {
		t.Fatalf("free tx, no global permissions: got %v %v, want invalid permission", res.Status, res.Reason)
	}

	// Creating the sender's account needs CreateAccount, not just Input+Call.
	global := account(t, st, acm.GlobalPermissionsAddress)
	global.Permissions = permission.NewAccountPermissions(permission.Input, permission.Call)
	if err := st.UpdateAccount(global); err != nil {
		t.Fatal(err)
	}
	if res := Apply(free, st, env()); res.Status != Invalid || res.Reason != ReasonPermission {
		t.Fatalf("free tx, global Input+Call: got %v %v, want invalid permission", res.Status, res.Reason)
	}
	global.Permissions = permission.NewAccountPermissions(permission.Input, permission.Call, permission.CreateAccount)
	if err := st.UpdateAccount(global); err != nil {
		t.Fatal(err)
	}
	res := Apply(free, st, env())
	if res.Status != Success {
		t.Fatalf("free tx, global Input+Call+CreateAccount: got %v %v: %v", res.Status, res.Reason, res.Err)
	}
	if err := res.RWSet.ApplyTo(st); err != nil {
		t.Fatal(err)
	}
	if acc := account(t, st, testSender); acc == nil || acc.Sequence != 1 {
		t.Fatalf("sender after = %+v, want nonce 1", acc)
	}
}

func TestCallToNewAccountNeedsCreateAccount(t *testing.T) {
	fresh := crypto.MustAddressFromHexString("3000000000000000000000000000000000000000")
	raw := sign(t, unsigned{gasPrice: 1, gas: 50000, to: &fresh, value: 1}, testChainID)

	callOnly := permission.NewAccountPermissions(permission.Input, permission.Call)
	if res := Apply(raw, newState(t, nil, callOnly), env()); res.Status != Invalid || res.Reason != ReasonPermission {
		t.Fatalf("without CreateAccount: got %v %v, want invalid permission", res.Status, res.Reason)
	}
	withCreate := permission.NewAccountPermissions(permission.Input, permission.Call, permission.CreateAccount)
	st := newState(t, nil, withCreate)
	res := Apply(raw, st, env())
	if res.Status != Success {
		t.Fatalf("with CreateAccount: got %v %v: %v", res.Status, res.Reason, res.Err)
	}
	if err := res.RWSet.ApplyTo(st); err != nil {
		t.Fatal(err)
	}
	if acc := account(t, st, fresh); acc == nil || acc.Balance != 1 {
		t.Fatalf("new account = %+v, want balance 1", acc)
	}
}

// TestCreateCanReadItsOwnStorage: init code that reads an unset slot of the
// contract being created must see zero, not fail.
func TestCreateCanReadItsOwnStorage(t *testing.T) {
	st := newState(t, nil, permission.AllAccountPermissions)
	// PUSH1 0 SLOAD POP, then return the one-byte runtime code 0x00.
	initCode := []byte{0x60, 0x00, 0x54, 0x50, 0x60, 0x00, 0x60, 0x00, 0x53, 0x60, 0x01, 0x60, 0x00, 0xf3}
	res := Apply(sign(t, unsigned{gasPrice: 1, gas: 100000, data: initCode}, testChainID), st, env())
	if res.Status != Success {
		t.Fatalf("status %v %v: %v", res.Status, res.Reason, res.Err)
	}
}

func TestCallToNativeIsUnsupported(t *testing.T) {
	ecrecover := crypto.MustAddressFromHexString("0000000000000000000000000000000000000001")
	res := Apply(sign(t, unsigned{gasPrice: 1, gas: 50000, to: &ecrecover}, testChainID),
		newState(t, nil, permission.AllAccountPermissions), env())
	if res.Status != Unsupported || res.Reason != ReasonNativeCall {
		t.Fatalf("got %v %v, want unsupported %v", res.Status, res.Reason, ReasonNativeCall)
	}
	if len(res.RWSet.Writes) != 0 {
		t.Fatalf("native call wrote %+v", res.RWSet.Writes)
	}
}

// TestFeeOverflowIsNotInsufficientFunds: a coinbase balance that cannot hold
// the fee is a Burrow limit, not a property of the transaction.
func TestFeeOverflowIsNotInsufficientFunds(t *testing.T) {
	st := newState(t, []byte{0x00}, permission.AllAccountPermissions)
	if err := st.UpdateAccount(&acm.Account{Address: coinbase, Balance: math.MaxUint64}); err != nil {
		t.Fatal(err)
	}
	res := Apply(sign(t, unsigned{gasPrice: 1, gas: 50000, to: &contract}, testChainID), st, env())
	if res.Status != Unsupported || res.Reason != ReasonBalanceOverflow {
		t.Fatalf("got %v %v, want unsupported %v", res.Status, res.Reason, ReasonBalanceOverflow)
	}
	if len(res.RWSet.Writes) != 0 {
		t.Fatalf("overflowing tx wrote %+v", res.RWSet.Writes)
	}
}
