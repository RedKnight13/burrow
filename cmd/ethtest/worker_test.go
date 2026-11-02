// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/execution/ethtest"
	"github.com/hyperledger/burrow/execution/ethtest/fixture"
	"github.com/hyperledger/burrow/execution/evm/rlp"
)

// TestMain lets the test binary act as the worker child process. With
// fakeWorkerEnv set it instead prints those lines (separated by "|") and exits 2,
// to simulate a worker dying at a chosen point of the protocol.
func TestMain(m *testing.M) {
	if script := os.Getenv(fakeWorkerEnv); script != "" && os.Getenv(workerEnv) == "1" {
		if len(os.Args) > 3 && os.Args[3] != "" {
			os.Exit(0) // resumed after the case: nothing left to run
		}
		for _, line := range strings.Split(script, "|") {
			fmt.Println(line)
		}
		os.Exit(2)
	}
	if os.Getenv(workerEnv) == "1" {
		os.Exit(worker(os.Args[1:], os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}

const fakeWorkerEnv = "ETHTEST_FAKE_WORKER"

const (
	contract = "0x1000000000000000000000000000000000000000"
	// sender is controlled by testKey.
	sender = "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b"
)

var testKey, _ = hex.DecodeString("45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8")

// signedCall is an EIP-155 (chain 1) legacy call to contract with gas price 0.
func signedCall(t *testing.T, gas uint64) string {
	t.Helper()
	to, _ := hex.DecodeString(strings.TrimPrefix(contract, "0x"))
	u := func(n uint64) []byte { return rlp.Uint(new(big.Int).SetUint64(n)) }
	fields := []rlp.Item{u(0), u(0), u(gas), to, u(0), []byte{}}
	hash := crypto.Keccak256(rlp.Encode(append(append([]rlp.Item{}, fields...), u(1), []byte{}, []byte{})))
	priv, _ := btcec.PrivKeyFromBytes(btcec.S256(), testKey)
	sig, err := btcec.SignCompact(btcec.S256(), priv, hash, false)
	if err != nil {
		t.Fatal(err)
	}
	raw := rlp.Encode(append(fields, u(uint64(37+sig[0]-27)),
		rlp.Uint(new(big.Int).SetBytes(sig[1:33])), rlp.Uint(new(big.Int).SetBytes(sig[33:]))))
	return "0x" + hex.EncodeToString(raw)
}

// stateTest builds a fixture calling a contract with the given code. Its
// expected root is the pre-state plus the sender's nonce bump, which is what
// Burrow produces for a contract that changes nothing.
func stateTest(t *testing.T, code string, gas uint64) map[string]interface{} {
	t.Helper()
	account := func(nonce, balance, code string) map[string]interface{} {
		return map[string]interface{}{"nonce": nonce, "balance": balance, "code": code, "storage": map[string]string{}}
	}
	pre := map[string]interface{}{
		contract: account("0x01", "0x00", code),
		sender:   account("0x00", "0x0de0b6b3a7640000", "0x"),
	}
	post := map[string]interface{}{
		contract: account("0x01", "0x00", code),
		sender:   account("0x01", "0x0de0b6b3a7640000", "0x"),
	}
	raw, _ := json.Marshal(post)
	var alloc fixture.Alloc
	if err := json.Unmarshal(raw, &alloc); err != nil {
		t.Fatal(err)
	}
	root, err := ethtest.AllocRoot(alloc)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]interface{}{
		"env": map[string]string{"currentCoinbase": "0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba",
			"currentGasLimit": "0x7fffffffffffffff", "currentNumber": "0x01", "currentTimestamp": "0x03e8"},
		"pre":         pre,
		"transaction": map[string]interface{}{"sender": sender},
		"post": map[string]interface{}{"Cancun": []interface{}{map[string]interface{}{
			"hash":    "0x" + hex.EncodeToString(root[:]),
			"logs":    "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
			"indexes": map[string]int{"data": 0, "gas": 0, "value": 0},
			"txbytes": signedCall(t, gas),
		}}},
		"config": map[string]string{"chainid": "0x01"},
	}
}

// writeGenesis adds one blockchain fixture whose empty pre-state matches its
// genesis root, so the genesis self-check has something to verify.
func writeGenesis(t *testing.T, fixtures string) {
	t.Helper()
	writeJSON(t, filepath.Join(fixtures, "blockchain_tests", "g.json"), map[string]interface{}{
		"t": map[string]interface{}{"network": "Paris", "pre": map[string]interface{}{},
			"genesisBlockHeader": map[string]string{
				"stateRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"}},
	})
}

func writeJSON(t *testing.T, path string, v interface{}) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRunTimesOutLoopAndContinues(t *testing.T) {
	dir := t.TempDir()
	fixtures := filepath.Join(dir, "fixtures")
	// JUMPDEST PUSH1 0 JUMP costs Burrow one gas per iteration, so with old
	// tests' 2^63 gas limit it effectively never ends.
	writeJSON(t, filepath.Join(fixtures, "state_tests", "f.json"), map[string]interface{}{
		"a_loop": stateTest(t, "0x5b600056", 0x7fffffffffffffff),
		"b_stop": stateTest(t, "0x00", 100000),
	})
	writeGenesis(t, fixtures)
	lock := filepath.Join(dir, "fixtures.lock")
	if err := os.WriteFile(lock, []byte("release=test\nsha256=00\nstate_cases=2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	scoreboard, passing := filepath.Join(dir, "scoreboard.md"), filepath.Join(dir, "passing.txt")
	if err := os.WriteFile(passing, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	code := run([]string{"-fixtures", fixtures, "-lock", lock, "-scoreboard", scoreboard, "-passing", passing,
		"-timeout", "1s", "-write"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit %d\nstdout %s\nstderr %s", code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "1/2 pass, 0 errors") {
		t.Fatalf("summary = %q", out.String())
	}
	got, _ := os.ReadFile(passing)
	if string(got) != "f.json::b_stop::Cancun::0\n" {
		t.Fatalf("passing = %q", got)
	}
	board, _ := os.ReadFile(scoreboard)
	// fork | total | pass | fail | unsupported | error | pass %
	if !strings.Contains(string(board), "| Cancun | 2 | 1 | 1 | 0 | 0 | 50.0% |") {
		t.Fatalf("scoreboard:\n%s", board)
	}

	// The committed files now match, so -check passes.
	out.Reset()
	errOut.Reset()
	code = run([]string{"-fixtures", fixtures, "-lock", lock, "-scoreboard", scoreboard, "-passing", passing,
		"-timeout", "1s", "-check"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("-check exit %d, stderr %q", code, errOut.String())
	}
}

func TestRunWritesResultsFile(t *testing.T) {
	dir := t.TempDir()
	fixtures := filepath.Join(dir, "fixtures")
	writeJSON(t, filepath.Join(fixtures, "state_tests", "f.json"), map[string]interface{}{
		"b_stop": stateTest(t, "0x00", 100000),
		"c_new":  stateTest(t, "0x00", 100000),
	})
	lock := filepath.Join(dir, "fixtures.lock")
	if err := os.WriteFile(lock, []byte("release=test\nsha256=00\nstate_cases=2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	results := filepath.Join(dir, "results.txt")
	var out, errOut bytes.Buffer
	if code := run([]string{"-fixtures", fixtures, "-lock", lock, "-run", "b_stop", "-results", results}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut.String())
	}
	got, err := os.ReadFile(results)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "f.json::b_stop::Cancun::0\tpass\t\n" {
		t.Fatalf("results = %q", got)
	}
}

// TestRunFilterSkipsOtherCases checks -run is applied before execution: the
// looping case would time out if it ran.
func TestRunFilterSkipsOtherCases(t *testing.T) {
	dir := t.TempDir()
	fixtures := filepath.Join(dir, "fixtures")
	writeJSON(t, filepath.Join(fixtures, "state_tests", "f.json"), map[string]interface{}{
		"a_loop": stateTest(t, "0x5b600056", 0x7fffffffffffffff),
		"b_stop": stateTest(t, "0x00", 100000),
	})
	lock := filepath.Join(dir, "fixtures.lock")
	if err := os.WriteFile(lock, []byte("release=test\nsha256=00\nstate_cases=2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	start := time.Now()
	code := run([]string{"-fixtures", fixtures, "-lock", lock, "-run", "b_stop", "-timeout", "30s"}, &out, &errOut)
	if code != 0 || !strings.Contains(out.String(), "1/1 pass") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out.String(), errOut.String())
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("filtered run took %v: the excluded looping case was executed", elapsed)
	}
}

// TestRunMemoryCeilingIsCrash uses a contract that fills 16 MiB of memory and
// then calls itself, so each nested frame holds another 16 MiB. The worker
// must stop itself at the ceiling instead of exhausting the machine.
func TestRunMemoryCeilingIsCrash(t *testing.T) {
	dir := t.TempDir()
	fixtures := filepath.Join(dir, "fixtures")
	// PUSH1 0 PUSH3 0xffffe0 MSTORE, then CALL self with all gas.
	hog := "0x600062ffffe05260006000600060006000305af1"
	writeJSON(t, filepath.Join(fixtures, "state_tests", "f.json"), map[string]interface{}{
		"a_hog":  stateTest(t, hog, 0x7fffffffffffffff),
		"b_stop": stateTest(t, "0x00", 100000),
	})
	lock := filepath.Join(dir, "fixtures.lock")
	if err := os.WriteFile(lock, []byte("release=test\nsha256=00\nstate_cases=2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	results := filepath.Join(dir, "results.txt")
	var out, errOut bytes.Buffer
	if code := run([]string{"-fixtures", fixtures, "-lock", lock, "-timeout", "120s", "-worker-mem", "256",
		"-results", results}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut.String())
	}
	got, _ := os.ReadFile(results)
	lines := strings.Split(strings.TrimSuffix(string(got), "\n"), "\n")
	if len(lines) != 2 || lines[0] != "f.json::a_hog::Cancun::0\tfail\tcrash: fatal error: worker memory limit exceeded" ||
		lines[1] != "f.json::b_stop::Cancun::0\tpass\t" {
		t.Fatalf("results:\n%s", got)
	}
}

// writeSetup builds a two-case fixture tree (one passing, one failing on its
// root), a lock, and empty scoreboard and passing files.
func writeSetup(t *testing.T, stateCases int) (fixtures, lock, scoreboard, passing string) {
	t.Helper()
	dir := t.TempDir()
	fixtures = filepath.Join(dir, "fixtures")
	failing := stateTest(t, "0x00", 100000)
	failing["post"].(map[string]interface{})["Cancun"].([]interface{})[0].(map[string]interface{})["hash"] = "0x" + strings.Repeat("00", 32)
	writeJSON(t, filepath.Join(fixtures, "state_tests", "f.json"), map[string]interface{}{
		"b_stop": stateTest(t, "0x00", 100000),
		"c_fail": failing,
	})
	writeGenesis(t, fixtures)
	lock = filepath.Join(dir, "fixtures.lock")
	if err := os.WriteFile(lock, []byte(fmt.Sprintf("release=test\nsha256=00\nstate_cases=%d\n", stateCases)), 0o644); err != nil {
		t.Fatal(err)
	}
	scoreboard, passing = filepath.Join(dir, "scoreboard.md"), filepath.Join(dir, "passing.txt")
	if err := os.WriteFile(scoreboard, []byte("unchanged\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(passing, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	return fixtures, lock, scoreboard, passing
}

// assertUnchanged checks the scoreboard still holds its placeholder and the
// passing list is still empty.
func assertUnchanged(t *testing.T, scoreboard, passing string) {
	t.Helper()
	if got, _ := os.ReadFile(scoreboard); string(got) != "unchanged\n" {
		t.Fatalf("scoreboard was rewritten: %q", got)
	}
	if got, _ := os.ReadFile(passing); len(got) != 0 {
		t.Fatalf("passing list was rewritten: %q", got)
	}
}

func TestWriteRefusesWrongCaseCount(t *testing.T) {
	fixtures, lock, scoreboard, passing := writeSetup(t, 5)
	var out, errOut bytes.Buffer
	code := run([]string{"-fixtures", fixtures, "-lock", lock, "-scoreboard", scoreboard, "-passing", passing, "-write"}, &out, &errOut)
	if code != 1 || !strings.Contains(errOut.String(), "state_cases=5") {
		t.Fatalf("exit %d, stderr %q", code, errOut.String())
	}
	assertUnchanged(t, scoreboard, passing)
}

func TestWriteRefusesToLowerTheRatchet(t *testing.T) {
	fixtures, lock, scoreboard, passing := writeSetup(t, 2)
	if err := os.WriteFile(passing, []byte("f.json::c_fail::Cancun::0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := run([]string{"-fixtures", fixtures, "-lock", lock, "-scoreboard", scoreboard, "-passing", passing, "-write"}, &out, &errOut)
	if code != 1 || !strings.Contains(errOut.String(), "regression: f.json::c_fail::Cancun::0") {
		t.Fatalf("exit %d, stderr %q", code, errOut.String())
	}
	if got, _ := os.ReadFile(passing); string(got) != "f.json::c_fail::Cancun::0\n" {
		t.Fatalf("passing list was lowered: %q", got)
	}
	if got, _ := os.ReadFile(scoreboard); string(got) != "unchanged\n" {
		t.Fatalf("scoreboard was rewritten: %q", got)
	}
}

func TestWriteRefusesWithoutGenesisCheck(t *testing.T) {
	fixtures, lock, scoreboard, passing := writeSetup(t, 2)
	if err := os.RemoveAll(filepath.Join(fixtures, "blockchain_tests")); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := run([]string{"-fixtures", fixtures, "-lock", lock, "-scoreboard", scoreboard, "-passing", passing, "-write"}, &out, &errOut)
	if code != 1 || !strings.Contains(errOut.String(), "genesis root self-check") {
		t.Fatalf("exit %d, stderr %q", code, errOut.String())
	}
	assertUnchanged(t, scoreboard, passing)
}

func TestWriteSucceedsOnACleanRun(t *testing.T) {
	fixtures, lock, scoreboard, passing := writeSetup(t, 2)
	var out, errOut bytes.Buffer
	code := run([]string{"-fixtures", fixtures, "-lock", lock, "-scoreboard", scoreboard, "-passing", passing, "-write"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut.String())
	}
	if got, _ := os.ReadFile(passing); string(got) != "f.json::b_stop::Cancun::0\n" {
		t.Fatalf("passing = %q", got)
	}
}

// TestCrashAfterBurrowReturnsIsHarnessError: a worker that dies after Burrow
// has returned died in harness code, so the case is an error, not a Burrow crash.
func TestCrashAfterBurrowReturnsIsHarnessError(t *testing.T) {
	id := "f.json::x::Cancun::0"
	tests := []struct {
		name, script string
		status       ethtest.Status
	}{
		{"inside Burrow", "start\t" + id + "|exec\t" + id, ethtest.Fail},
		{"after Burrow returned", "start\t" + id + "|exec\t" + id + "|done\t" + id, ethtest.Error},
		{"before Burrow", "start\t" + id, ethtest.Error},
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(fakeWorkerEnv, tt.script)
			results, err := runFileIsolated(self, "root", "f.json", "^"+regexp.QuoteMeta(id)+"$", 10*time.Second, 1<<30)
			if err != nil {
				t.Fatal(err)
			}
			if len(results) == 0 || results[0].ID != id || results[0].Status != tt.status {
				t.Fatalf("results = %+v, want first %s %v", results, id, tt.status)
			}
		})
	}
}
