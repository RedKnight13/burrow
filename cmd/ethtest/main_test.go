// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunRejectsPartialWrite(t *testing.T) {
	for _, flag := range []string{"-write", "-check"} {
		var out, errOut bytes.Buffer
		code := run([]string{"-run", "x", flag}, &out, &errOut)
		if code != 2 || !strings.Contains(errOut.String(), "-run cannot be combined with -write or -check") {
			t.Fatalf("%s: exit %d, stderr %q", flag, code, errOut.String())
		}
	}
}

func TestRunMissingFixturesFails(t *testing.T) {
	var out, errOut bytes.Buffer
	missing := filepath.Join(t.TempDir(), "none")
	if code := run([]string{"-fixtures", missing}, &out, &errOut); code != 1 {
		t.Fatalf("exit %d, want 1; stderr %q", code, errOut.String())
	}
	if code := run([]string{"-fixtures", missing, "-check"}, &out, &errOut); code != 1 {
		t.Fatalf("-check exit %d, want 1; stderr %q", code, errOut.String())
	}
}

func TestSplitID(t *testing.T) {
	path, name, fork, idx, err := splitID("for_cancun/x.json::tests/a.py::test_b[fork_Cancun-state_test]::Cancun::3")
	if err != nil {
		t.Fatal(err)
	}
	if path != "for_cancun/x.json" || name != "tests/a.py::test_b[fork_Cancun-state_test]" || fork != "Cancun" || idx != 3 {
		t.Fatalf("got %q %q %q %d", path, name, fork, idx)
	}
	if _, _, _, _, err := splitID("nonsense"); err == nil {
		t.Fatal("expected error for malformed ID")
	}
}
