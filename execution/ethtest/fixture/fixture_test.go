// SPDX-License-Identifier: Apache-2.0

package fixture

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestQuantity(t *testing.T) {
	max256, _ := new(big.Int).SetString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
	tests := []struct {
		in      string
		want    *big.Int
		wantErr bool
	}{
		{`"0x"`, big.NewInt(0), false},
		{`"0x00"`, big.NewInt(0), false},
		{`"0x0100"`, big.NewInt(256), false},
		{`"0xf"`, big.NewInt(15), false},
		{`"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"`, max256, false},
		{`"12"`, nil, true},
		{`"0xzz"`, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			var q Quantity
			err := json.Unmarshal([]byte(tt.in), &q)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %v", q.Int)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if q.Cmp(tt.want) != 0 {
				t.Fatalf("got %v, want %v", q.Int, tt.want)
			}
		})
	}
}

func TestParseWord(t *testing.T) {
	w, err := ParseWord("0x01")
	if err != nil {
		t.Fatal(err)
	}
	if w[31] != 1 || w[30] != 0 {
		t.Fatalf("ParseWord left-pad wrong: %x", w)
	}
	if _, err := ParseWord("0x01" + hex.EncodeToString(make([]byte, 32))); err == nil {
		t.Fatal("expected error for 33-byte word")
	}
}

func TestLoadStateTests(t *testing.T) {
	tests, err := LoadStateTests("testdata/state_min.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(tests) != 1 {
		t.Fatalf("got %d tests, want 1", len(tests))
	}
	st := tests["tests/minimal.py::test_stop[fork_Cancun-state_test]"]
	post := st.Post["Cancun"]
	if len(post) != 1 {
		t.Fatalf("got %d Cancun post entries, want 1", len(post))
	}
	if post[0].Indexes.Data != 1 || post[0].Indexes.Value != 1 || post[0].Indexes.Gas != 0 {
		t.Fatalf("indexes = %+v", post[0].Indexes)
	}
	if hex.EncodeToString(post[0].Hash) != "94f17be47be2e27f90e110c9c2d405b7c70a9910f766f0af7c8c2ffc521c4667" {
		t.Fatalf("hash = %x", post[0].Hash)
	}
	acc := st.Pre["0x1000000000000000000000000000000000000000"]
	if acc.Balance.String() != "1000000000000000000" || acc.Nonce.Int64() != 1 {
		t.Fatalf("pre account = balance %v nonce %v", acc.Balance.Int, acc.Nonce.Int)
	}
	if acc.Storage["0x00"].Int64() != 42 {
		t.Fatalf("storage[0] = %v", acc.Storage["0x00"].Int)
	}
	if hex.EncodeToString(st.Transaction.Data[1]) != "deadbeef" || len(st.Transaction.Data[0]) != 0 {
		t.Fatalf("data = %x", st.Transaction.Data)
	}
	if st.Transaction.Sender != "0xf6c3a9edc1afa0ad5b720e4d42e1437c43d3b3ff" {
		t.Fatalf("sender = %q", st.Transaction.Sender)
	}
	if st.Env.Coinbase != "0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba" || st.Env.Timestamp.Int64() != 1000 {
		t.Fatalf("env = %+v", st.Env)
	}
}

func TestLoadBlockchainTests(t *testing.T) {
	tests, err := LoadBlockchainTests("testdata/blockchain_min.json")
	if err != nil {
		t.Fatal(err)
	}
	bt := tests["tests/minimal.py::test_empty[fork_Paris-blockchain_test]"]
	if bt.Network != "Paris" {
		t.Fatalf("network = %q", bt.Network)
	}
	if hex.EncodeToString(bt.Genesis.StateRoot) != "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421" {
		t.Fatalf("stateRoot = %x", bt.Genesis.StateRoot)
	}
}

func TestLoadStateTestsBadPath(t *testing.T) {
	if _, err := LoadStateTests("testdata/missing.json"); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestWalkOrder(t *testing.T) {
	root := t.TempDir()
	for _, p := range []string{"state_tests/b/z.json", "state_tests/a/y.json", "state_tests/a/x.json", "state_tests/a/skip.txt"} {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var got []string
	err := Walk(root, "state_tests", func(path string) error {
		rel, _ := filepath.Rel(root, path)
		got = append(got, rel)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"state_tests/a/x.json", "state_tests/a/y.json", "state_tests/b/z.json"}
	if len(got) != len(want) || !sort.StringsAreSorted(got) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestWalkMissingRoot(t *testing.T) {
	err := Walk(filepath.Join(t.TempDir(), "nope"), "state_tests", func(string) error { return nil })
	if err == nil {
		t.Fatal("expected error for missing fixture directory")
	}
}
