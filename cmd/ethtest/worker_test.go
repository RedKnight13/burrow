// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hyperledger/burrow/execution/ethtest"
	"github.com/hyperledger/burrow/execution/ethtest/fixture"
)

// TestMain lets the test binary act as the worker child process.
func TestMain(m *testing.M) {
	if os.Getenv(workerEnv) == "1" {
		os.Exit(worker(os.Args[1:], os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}

const (
	contract = "0x1000000000000000000000000000000000000000"
	sender   = "0xf6c3a9edc1afa0ad5b720e4d42e1437c43d3b3ff"
)

// stateTest builds a fixture calling a contract with the given code. Its
// expected root is the pre-state root, which a STOP contract matches.
func stateTest(t *testing.T, code, gas string) map[string]interface{} {
	t.Helper()
	pre := map[string]interface{}{
		contract: map[string]interface{}{"nonce": "0x01", "balance": "0x00", "code": code, "storage": map[string]string{}},
		sender:   map[string]interface{}{"nonce": "0x00", "balance": "0x0de0b6b3a7640000", "code": "0x", "storage": map[string]string{}},
	}
	raw, _ := json.Marshal(pre)
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
			"currentGasLimit": "0x07270e00", "currentNumber": "0x01", "currentTimestamp": "0x03e8"},
		"pre": pre,
		"transaction": map[string]interface{}{"nonce": "0x00", "gasPrice": "0x0a", "gasLimit": []string{gas},
			"to": contract, "value": []string{"0x00"}, "data": []string{"0x"}, "sender": sender},
		"post": map[string]interface{}{"Cancun": []interface{}{map[string]interface{}{
			"hash":    "0x" + hex.EncodeToString(root[:]),
			"logs":    "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
			"indexes": map[string]int{"data": 0, "gas": 0, "value": 0},
		}}},
	}
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
		"a_loop": stateTest(t, "0x5b600056", "0x7fffffffffffffff"),
		"b_stop": stateTest(t, "0x00", "0x0186a0"),
	})
	lock := filepath.Join(dir, "fixtures.lock")
	if err := os.WriteFile(lock, []byte("release=test\nsha256=00\nstate_cases=2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	scoreboard, passing := filepath.Join(dir, "scoreboard.md"), filepath.Join(dir, "passing.txt")

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
	// fork | total | pass | root | logs | timeout | crash | unsupported | error | pass %
	if !strings.Contains(string(board), "| Cancun | 2 | 1 | 0 | 0 | 1 | 0 | 0 | 0 | 50.0% |") {
		t.Fatalf("scoreboard:\n%s", board)
	}

	// The committed files now match, so -check passes apart from the genesis
	// self-check, which needs blockchain fixtures this tree does not have.
	out.Reset()
	errOut.Reset()
	code = run([]string{"-fixtures", fixtures, "-lock", lock, "-scoreboard", scoreboard, "-passing", passing,
		"-timeout", "1s", "-check"}, &out, &errOut)
	if code != 1 || !strings.Contains(errOut.String(), "genesis root self-check") {
		t.Fatalf("-check exit %d, stderr %q", code, errOut.String())
	}
	if strings.Contains(errOut.String(), "regression") || strings.Contains(errOut.String(), "differs") {
		t.Fatalf("unexpected check failure: %q", errOut.String())
	}
}

func TestRunWritesResultsFile(t *testing.T) {
	dir := t.TempDir()
	fixtures := filepath.Join(dir, "fixtures")
	writeJSON(t, filepath.Join(fixtures, "state_tests", "f.json"), map[string]interface{}{
		"b_stop": stateTest(t, "0x00", "0x0186a0"),
		"c_new":  stateTest(t, "0x00", "0x0186a0"),
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

// TestRunFatalBurrowCrashIsFailure uses the contract from the fixture
// stSystemOperationsTest/callRecursiveBomb0_OOG_atMaxCallDepth: it calls itself
// forwarding all but 1024 gas. Burrow has no call-depth limit by default, so the
// worker dies of a Go stack overflow, which cannot be recovered. That is a
// Burrow crash, and the next case in the file still runs.
func TestRunFatalBurrowCrashIsFailure(t *testing.T) {
	dir := t.TempDir()
	fixtures := filepath.Join(dir, "fixtures")
	bombCode := "0x600160005401600055690fffffffffffffffffff610402600054040260025560006000" +
		"690fffffffffffffffffff610402600054040260006000306104005a03f160015500"
	writeJSON(t, filepath.Join(fixtures, "state_tests", "f.json"), map[string]interface{}{
		"a_bomb": stateTest(t, bombCode, "0x174876e800"),
		"b_stop": stateTest(t, "0x00", "0x0186a0"),
	})
	lock := filepath.Join(dir, "fixtures.lock")
	if err := os.WriteFile(lock, []byte("release=test\nsha256=00\nstate_cases=2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	results := filepath.Join(dir, "results.txt")
	var out, errOut bytes.Buffer
	if code := run([]string{"-fixtures", fixtures, "-lock", lock, "-timeout", "60s", "-results", results}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut.String())
	}
	got, _ := os.ReadFile(results)
	lines := strings.Split(strings.TrimSuffix(string(got), "\n"), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "f.json::a_bomb::Cancun::0\tfail\tcrash: ") ||
		lines[1] != "f.json::b_stop::Cancun::0\tpass\t" {
		t.Fatalf("results:\n%s", got)
	}
}
