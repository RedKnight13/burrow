// SPDX-License-Identifier: Apache-2.0

package ethtest

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hyperledger/burrow/execution/ethtest/fixture"
)

const (
	contractAddr = "0x1000000000000000000000000000000000000000"
	senderAddr   = "0xf6c3a9edc1afa0ad5b720e4d42e1437c43d3b3ff"
	emptyLogs    = "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"
)

// stopCase calls a contract whose code is STOP with zero value. Burrow changes
// nothing, so the post root equals the pre root. This checks the harness
// agrees with itself; it is not an Ethereum result (Ethereum would charge fees).
func stopCase(t *testing.T) fixture.StateTest {
	t.Helper()
	var st fixture.StateTest
	js := `{
		"env": {"currentCoinbase": "0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba", "currentGasLimit": "0x07270e00",
			"currentNumber": "0x01", "currentTimestamp": "0x03e8"},
		"pre": {
			"` + contractAddr + `": {"nonce": "0x01", "balance": "0x00", "code": "0x00", "storage": {}},
			"` + senderAddr + `": {"nonce": "0x00", "balance": "0x0de0b6b3a7640000", "code": "0x", "storage": {}}
		},
		"transaction": {"nonce": "0x00", "gasPrice": "0x0a", "gasLimit": ["0x0186a0"], "to": "` + contractAddr + `",
			"value": ["0x00"], "data": ["0x"], "sender": "` + senderAddr + `"},
		"post": {"Cancun": [{"hash": "0x00", "logs": "0x` + emptyLogs + `", "indexes": {"data": 0, "gas": 0, "value": 0}}]}
	}`
	if err := json.Unmarshal([]byte(js), &st); err != nil {
		t.Fatal(err)
	}
	root, err := AllocRoot(st.Pre)
	if err != nil {
		t.Fatal(err)
	}
	st.Post["Cancun"][0].Hash = root[:]
	return st
}

func TestRunCasePassWhenNothingChanges(t *testing.T) {
	res := RunCase("stop", stopCase(t), "Cancun", 0)
	if res.Status != Pass {
		t.Fatalf("got %v %q, want pass", res.Status, res.Reason)
	}
}

func TestRunCaseDetectsRootMismatch(t *testing.T) {
	st := stopCase(t)
	st.Post["Cancun"][0].Hash[0] ^= 0xff
	res := RunCase("stop", st, "Cancun", 0)
	if res.Status != Fail || res.Reason != "root" {
		t.Fatalf("got %v %q, want fail root", res.Status, res.Reason)
	}
}

func TestRunCaseDetectsLogsMismatch(t *testing.T) {
	st := stopCase(t)
	st.Post["Cancun"][0].Logs[0] ^= 0xff
	res := RunCase("stop", st, "Cancun", 0)
	if res.Status != Fail || res.Reason != "logs" {
		t.Fatalf("got %v %q, want fail logs", res.Status, res.Reason)
	}
}

func TestRunCaseUnsupported(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(st *fixture.StateTest)
		reason string
	}{
		{"expect exception", func(st *fixture.StateTest) {
			st.Post["Cancun"][0].ExpectException = "TransactionException.INTRINSIC_GAS_TOO_LOW"
		}, "unsupported: tx validation"},
		{"create tx", func(st *fixture.StateTest) { st.Transaction.To = "" }, "unsupported: create tx"},
		{"access list", func(st *fixture.StateTest) {
			st.Transaction.AccessLists = json.RawMessage(`[[]]`)
		}, "unsupported: typed tx"},
		{"big balance", func(st *fixture.StateTest) {
			acc := st.Pre[senderAddr]
			if err := json.Unmarshal([]byte(`"0x010000000000000000"`), &acc.Balance); err != nil {
				t.Fatal(err)
			}
			st.Pre[senderAddr] = acc
		}, "unsupported: balance > uint64"},
		{"call to new account", func(st *fixture.StateTest) {
			st.Transaction.To = "0x2000000000000000000000000000000000000000"
		}, "unsupported: call to new account"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := stopCase(t)
			tt.mutate(&st)
			res := RunCase("x", st, "Cancun", 0)
			if res.Status != Fail || res.Reason != tt.reason {
				t.Fatalf("got %v %q, want fail %q", res.Status, res.Reason, tt.reason)
			}
		})
	}
}

func TestRunCaseEmptyTypedFieldsAreNotTyped(t *testing.T) {
	st := stopCase(t)
	st.Transaction.AccessLists = json.RawMessage(`null`)
	st.Transaction.BlobVersionedHashes = json.RawMessage(`[]`)
	if res := RunCase("x", st, "Cancun", 0); res.Status != Pass {
		t.Fatalf("got %v %q, want pass", res.Status, res.Reason)
	}
}

func TestRunCaseBadIndexIsError(t *testing.T) {
	st := stopCase(t)
	st.Post["Cancun"][0].Indexes.Data = 5
	if res := RunCase("x", st, "Cancun", 0); res.Status != Error {
		t.Fatalf("got %v %q, want error", res.Status, res.Reason)
	}
}

func TestRunCasePanicIsError(t *testing.T) {
	saved := execute
	defer func() { execute = saved }()
	execute = func(c callInput) error { panic("boom") }
	res := RunCase("x", stopCase(t), "Cancun", 0)
	if res.Status != Error || !strings.HasPrefix(res.Reason, "panic:") {
		t.Fatalf("got %v %q, want error panic:", res.Status, res.Reason)
	}
}

func TestLogsHashEmpty(t *testing.T) {
	got := LogsHash(nil)
	if hex.EncodeToString(got[:]) != emptyLogs {
		t.Fatalf("LogsHash(nil) = %x", got)
	}
}

func TestSenderFromSecretKey(t *testing.T) {
	key, _ := hex.DecodeString("45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8")
	addr, err := senderFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(addr.Bytes()) != "a94f5374fce5edbc8e2a8697c15331677e6ebf0b" {
		t.Fatalf("sender = %x", addr.Bytes())
	}
}

func TestRunFileIDs(t *testing.T) {
	results, err := RunFile("fixture/testdata", "fixture/testdata/state_min.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	want := "state_min.json::tests/minimal.py::test_stop[fork_Cancun-state_test]::Cancun::0"
	if results[0].ID != want || results[0].Fork != "Cancun" {
		t.Fatalf("result = %+v, want ID %s", results[0], want)
	}
}

// TestRunCaseExecutesBurrow proves the runner really runs Burrow's EVM: the
// contract stores 42 in slot 0, and only that post-state root passes.
func TestRunCaseExecutesBurrow(t *testing.T) {
	st := stopCase(t)
	acc := st.Pre[contractAddr]
	acc.Code = fixture.Bytes{0x60, 0x2a, 0x60, 0x00, 0x55} // PUSH1 42 PUSH1 0 SSTORE
	st.Pre[contractAddr] = acc

	unchanged, err := AllocRoot(st.Pre)
	if err != nil {
		t.Fatal(err)
	}
	st.Post["Cancun"][0].Hash = unchanged[:]
	if res := RunCase("x", st, "Cancun", 0); res.Status != Fail || res.Reason != "root" {
		t.Fatalf("with pre root: got %v %q, want fail root", res.Status, res.Reason)
	}

	var forty2 fixture.Quantity
	if err := json.Unmarshal([]byte(`"0x2a"`), &forty2); err != nil {
		t.Fatal(err)
	}
	post := fixture.Alloc{}
	for k, v := range st.Pre {
		post[k] = v
	}
	stored := post[contractAddr]
	stored.Storage = map[string]fixture.Quantity{"0x00": forty2}
	post[contractAddr] = stored
	want, err := AllocRoot(post)
	if err != nil {
		t.Fatal(err)
	}
	st.Post["Cancun"][0].Hash = want[:]
	if res := RunCase("x", st, "Cancun", 0); res.Status != Pass {
		t.Fatalf("with stored root: got %v %q, want pass", res.Status, res.Reason)
	}
}
