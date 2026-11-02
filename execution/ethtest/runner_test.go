// SPDX-License-Identifier: Apache-2.0

package ethtest

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/hyperledger/burrow/acm/acmstate"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/execution/ethtest/fixture"
	"github.com/hyperledger/burrow/execution/evm/ethtx"
	"github.com/hyperledger/burrow/execution/evm/rlp"
)

const (
	contractAddr = "0x1000000000000000000000000000000000000000"
	// senderAddr is controlled by testKey.
	senderAddr = "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b"
	emptyLogs  = "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"
)

var testKey, _ = hex.DecodeString("45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8")

// signLegacy returns an EIP-155 (chain 1) legacy transaction with gas price 0.
func signLegacy(t *testing.T, nonce, gas uint64, to string, data []byte) []byte {
	t.Helper()
	toBytes := []byte{}
	if to != "" {
		toBytes, _ = hex.DecodeString(strings.TrimPrefix(to, "0x"))
	}
	u := func(n uint64) []byte { return rlp.Uint(new(big.Int).SetUint64(n)) }
	fields := []rlp.Item{u(nonce), u(0), u(gas), toBytes, u(0), data}
	hash := crypto.Keccak256(rlp.Encode(append(append([]rlp.Item{}, fields...), u(1), []byte{}, []byte{})))
	priv, _ := btcec.PrivKeyFromBytes(btcec.S256(), testKey)
	sig, err := btcec.SignCompact(btcec.S256(), priv, hash, false)
	if err != nil {
		t.Fatal(err)
	}
	v := u(uint64(37 + sig[0] - 27))
	return rlp.Encode(append(fields, v, rlp.Uint(new(big.Int).SetBytes(sig[1:33])), rlp.Uint(new(big.Int).SetBytes(sig[33:]))))
}

// signedCase is a fixture calling a contract with the given code, at gas price
// 0, with the expected post-state set to the pre-state plus the sender's nonce
// bump. That is what Burrow produces for a contract that changes nothing. It
// checks the harness agrees with itself, not an Ethereum result.
func signedCase(t *testing.T, code string) fixture.StateTest {
	t.Helper()
	var st fixture.StateTest
	js := `{
		"env": {"currentCoinbase": "0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba", "currentGasLimit": "0x07270e00",
			"currentNumber": "0x01", "currentTimestamp": "0x03e8"},
		"pre": {
			"` + contractAddr + `": {"nonce": "0x01", "balance": "0x00", "code": "` + code + `", "storage": {}},
			"` + senderAddr + `": {"nonce": "0x00", "balance": "0x0de0b6b3a7640000", "code": "0x", "storage": {}}
		},
		"transaction": {"sender": "` + senderAddr + `"},
		"post": {"Cancun": [{"hash": "0x00", "logs": "0x` + emptyLogs + `", "indexes": {"data": 0, "gas": 0, "value": 0}}]},
		"config": {"chainid": "0x01"}
	}`
	if err := json.Unmarshal([]byte(js), &st); err != nil {
		t.Fatal(err)
	}
	st.Post["Cancun"][0].TxBytes = signLegacy(t, 0, 100000, contractAddr, nil)
	setExpected(t, &st, func(post fixture.Alloc) {
		sender := post[senderAddr]
		sender.Nonce = fixture.Quantity{Int: big.NewInt(1)}
		post[senderAddr] = sender
	})
	return st
}

// setExpected sets the expected root to pre with edit applied.
func setExpected(t *testing.T, st *fixture.StateTest, edit func(fixture.Alloc)) {
	t.Helper()
	post := fixture.Alloc{}
	for k, v := range st.Pre {
		post[k] = v
	}
	edit(post)
	root, err := AllocRoot(post)
	if err != nil {
		t.Fatal(err)
	}
	st.Post["Cancun"][0].Hash = root[:]
	st.Post["Cancun"][0].State = post
}

func TestRunCasePassOnExpectedPost(t *testing.T) {
	if res := RunCase("stop", signedCase(t, "0x00"), "Cancun", 0); res.Status != Pass {
		t.Fatalf("got %v %q, want pass", res.Status, res.Reason)
	}
}

func TestRunCaseDetectsRootMismatch(t *testing.T) {
	st := signedCase(t, "0x00")
	st.Post["Cancun"][0].Hash[0] ^= 0xff
	if res := RunCase("stop", st, "Cancun", 0); res.Status != Fail || res.Reason != "root" {
		t.Fatalf("got %v %q, want fail root", res.Status, res.Reason)
	}
}

func TestRunCaseDetectsLogsMismatch(t *testing.T) {
	st := signedCase(t, "0x00")
	st.Post["Cancun"][0].Logs[0] ^= 0xff
	if res := RunCase("stop", st, "Cancun", 0); res.Status != Fail || res.Reason != "logs" {
		t.Fatalf("got %v %q, want fail logs", res.Status, res.Reason)
	}
}

// TestRunCaseExecutesBurrow proves the transaction really runs: the contract
// stores 42 in slot 0, and only the root that includes it passes.
func TestRunCaseExecutesBurrow(t *testing.T) {
	st := signedCase(t, "0x602a600055") // PUSH1 42 PUSH1 0 SSTORE
	if res := RunCase("x", st, "Cancun", 0); res.Status != Fail || res.Reason != "root" {
		t.Fatalf("without the store: got %v %q, want fail root", res.Status, res.Reason)
	}
	setExpected(t, &st, func(post fixture.Alloc) {
		sender := post[senderAddr]
		sender.Nonce = fixture.Quantity{Int: big.NewInt(1)}
		post[senderAddr] = sender
		c := post[contractAddr]
		c.Storage = map[string]fixture.Quantity{"0x00": {Int: big.NewInt(42)}}
		post[contractAddr] = c
	})
	if res := RunCase("x", st, "Cancun", 0); res.Status != Pass {
		t.Fatalf("with the store: got %v %q, want pass", res.Status, res.Reason)
	}
}

func TestRunCaseExpectedException(t *testing.T) {
	low := func(t *testing.T) fixture.StateTest {
		st := signedCase(t, "0x00")
		st.Post["Cancun"][0].TxBytes = signLegacy(t, 0, 20000, contractAddr, nil) // below 21000
		setExpected(t, &st, func(fixture.Alloc) {})                               // invalid: no change
		return st
	}
	tests := []struct {
		name   string
		expect string
		status Status
		reason string
	}{
		{"matching reason", "TransactionException.INTRINSIC_GAS_TOO_LOW", Pass, "rejected"},
		{"one of several", "TransactionException.NONCE_IS_MAX|TransactionException.INTRINSIC_GAS_TOO_LOW", Pass, "rejected"},
		{"different reason", "TransactionException.NONCE_MISMATCH_TOO_HIGH", Fail, "exception: got intrinsic gas too low"},
		{"rule Burrow lacks", "TransactionException.SENDER_NOT_EOA", Fail, "unsupported: exception SENDER_NOT_EOA"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := low(t)
			st.Post["Cancun"][0].ExpectException = tt.expect
			res := RunCase("x", st, "Cancun", 0)
			if res.Status != tt.status || res.Reason != tt.reason {
				t.Fatalf("got %v %q, want %v %q", res.Status, res.Reason, tt.status, tt.reason)
			}
		})
	}
}

func TestRunCaseExceptionNotRaised(t *testing.T) {
	st := signedCase(t, "0x00")
	st.Post["Cancun"][0].ExpectException = "TransactionException.INTRINSIC_GAS_TOO_LOW"
	if res := RunCase("x", st, "Cancun", 0); res.Status != Fail || res.Reason != "exception: not raised" {
		t.Fatalf("got %v %q", res.Status, res.Reason)
	}
}

func TestRunCaseUnexpectedException(t *testing.T) {
	st := signedCase(t, "0x00")
	st.Post["Cancun"][0].TxBytes = signLegacy(t, 5, 100000, contractAddr, nil) // nonce too high
	if res := RunCase("x", st, "Cancun", 0); res.Status != Fail || res.Reason != "exception: unexpected nonce too high" {
		t.Fatalf("got %v %q", res.Status, res.Reason)
	}
}

func TestRunCaseUnsupported(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(st *fixture.StateTest)
		reason string
	}{
		{"typed tx", func(st *fixture.StateTest) { st.Post["Cancun"][0].TxBytes = []byte{0x02, 0xc0} },
			"unsupported: typed transaction"},
		{"big balance", func(st *fixture.StateTest) {
			acc := st.Pre[senderAddr]
			acc.Balance = fixture.Quantity{Int: new(big.Int).Lsh(big.NewInt(1), 64)}
			st.Pre[senderAddr] = acc
		}, "unsupported: balance > uint64"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := signedCase(t, "0x00")
			tt.mutate(&st)
			if res := RunCase("x", st, "Cancun", 0); res.Status != Fail || res.Reason != tt.reason {
				t.Fatalf("got %v %q, want fail %q", res.Status, res.Reason, tt.reason)
			}
		})
	}
}

func TestRunCaseSenderMustMatchFixture(t *testing.T) {
	st := signedCase(t, "0x00")
	st.Transaction.Sender = "0xf6c3a9edc1afa0ad5b720e4d42e1437c43d3b3ff"
	if res := RunCase("x", st, "Cancun", 0); res.Status != Fail || res.Reason != "sender" {
		t.Fatalf("got %v %q, want fail sender", res.Status, res.Reason)
	}
}

func TestRunCaseMissingTxBytesIsError(t *testing.T) {
	st := signedCase(t, "0x00")
	st.Post["Cancun"][0].TxBytes = nil
	if res := RunCase("x", st, "Cancun", 0); res.Status != Error {
		t.Fatalf("got %v %q, want error", res.Status, res.Reason)
	}
}

func TestRunCaseBurrowPanicIsCrash(t *testing.T) {
	saved := apply
	defer func() { apply = saved }()
	apply = func([]byte, acmstate.Reader, ethtx.Env) ethtx.Result { panic("boom") }
	if res := RunCase("x", signedCase(t, "0x00"), "Cancun", 0); res.Status != Fail || res.Reason != "crash: panic: boom" {
		t.Fatalf("got %v %q, want fail crash: panic: boom", res.Status, res.Reason)
	}
}

func TestRunWithCallsHookBeforeBurrow(t *testing.T) {
	saved := apply
	defer func() { apply = saved }()
	var order []string
	apply = func(raw []byte, st acmstate.Reader, env ethtx.Env) ethtx.Result {
		order = append(order, "apply")
		return saved(raw, st, env)
	}
	c := Case{ID: "x", Fork: "Cancun", Test: signedCase(t, "0x00")}
	c.RunWith(func() { order = append(order, "hook") }, nil)
	if strings.Join(order, ",") != "hook,apply" {
		t.Fatalf("order = %v", order)
	}
}

func TestLogsHashEmpty(t *testing.T) {
	got := LogsHash(nil)
	if hex.EncodeToString(got[:]) != emptyLogs {
		t.Fatalf("LogsHash(nil) = %x", got)
	}
}

func TestRunFileIDs(t *testing.T) {
	results, err := RunFile("fixture/testdata", "fixture/testdata/state_min.json")
	if err != nil {
		t.Fatal(err)
	}
	want := "state_min.json::tests/minimal.py::test_stop[fork_Cancun-state_test]::Cancun::0"
	if len(results) != 1 || results[0].ID != want || results[0].Fork != "Cancun" {
		t.Fatalf("results = %+v, want one with ID %s", results, want)
	}
}

func TestCasesSortedAndRunnable(t *testing.T) {
	cases, err := Cases("fixture/testdata", "fixture/testdata/state_min.json")
	if err != nil {
		t.Fatal(err)
	}
	want := "state_min.json::tests/minimal.py::test_stop[fork_Cancun-state_test]::Cancun::0"
	if len(cases) != 1 || cases[0].ID != want || cases[0].Fork != "Cancun" || cases[0].Index != 0 {
		t.Fatalf("cases = %+v", cases)
	}
	if res := cases[0].Run(); res.ID != want {
		t.Fatalf("Run().ID = %q", res.ID)
	}
}
