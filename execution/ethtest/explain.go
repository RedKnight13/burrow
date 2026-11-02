// SPDX-License-Identifier: Apache-2.0

package ethtest

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"sort"
	"strings"

	"github.com/hyperledger/burrow/acm"
	"github.com/hyperledger/burrow/acm/acmstate"
	"github.com/hyperledger/burrow/binary"
	"github.com/hyperledger/burrow/execution/ethtest/fixture"
)

type flatAccount struct {
	nonce, balance *big.Int
	codeHash       string
	storage        map[string]*big.Int // slot hex -> non-zero value
}

// Explain runs one case and describes how Burrow's post-state differs from the
// fixture's expected post-state, account by account.
func Explain(id string, t fixture.StateTest, fork string, i int) string {
	res, st := runCase(id, t, fork, i, nil, nil)
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s %s\n", id, res.Status, res.Reason)
	if st == nil {
		b.WriteString("Burrow was not run for this case; no state to compare.\n")
		return b.String()
	}
	expected := t.Post[fork][i].State
	if expected == nil {
		b.WriteString("Fixture has no expected post-state to compare.\n")
		return b.String()
	}
	want, err := flattenAlloc(expected)
	if err != nil {
		fmt.Fprintf(&b, "reading expected state: %v\n", err)
		return b.String()
	}
	got, err := flattenState(st, hasZeroAddress(t.Pre))
	if err != nil {
		fmt.Fprintf(&b, "reading Burrow state: %v\n", err)
		return b.String()
	}
	addrs := make(map[string]bool)
	for a := range want {
		addrs[a] = true
	}
	for a := range got {
		addrs[a] = true
	}
	sorted := make([]string, 0, len(addrs))
	for a := range addrs {
		sorted = append(sorted, a)
	}
	sort.Strings(sorted)
	for _, a := range sorted {
		w, okW := want[a]
		g, okG := got[a]
		switch {
		case !okG:
			fmt.Fprintf(&b, "%s: missing in Burrow state\n", a)
		case !okW:
			fmt.Fprintf(&b, "%s: not in expected state\n", a)
		default:
			for _, line := range diffAccount(w, g) {
				fmt.Fprintf(&b, "%s: %s\n", a, line)
			}
		}
	}
	return b.String()
}

func diffAccount(w, g flatAccount) []string {
	var out []string
	if w.nonce.Cmp(g.nonce) != 0 {
		out = append(out, fmt.Sprintf("nonce: want %v, got %v", w.nonce, g.nonce))
	}
	if w.balance.Cmp(g.balance) != 0 {
		out = append(out, fmt.Sprintf("balance: want %v, got %v", w.balance, g.balance))
	}
	if w.codeHash != g.codeHash {
		out = append(out, fmt.Sprintf("code hash: want %s, got %s", w.codeHash, g.codeHash))
	}
	slots := make(map[string]bool)
	for s := range w.storage {
		slots[s] = true
	}
	for s := range g.storage {
		slots[s] = true
	}
	sorted := make([]string, 0, len(slots))
	for s := range slots {
		sorted = append(sorted, s)
	}
	sort.Strings(sorted)
	zero := new(big.Int)
	for _, s := range sorted {
		wv, gv := w.storage[s], g.storage[s]
		if wv == nil {
			wv = zero
		}
		if gv == nil {
			gv = zero
		}
		if wv.Cmp(gv) != 0 {
			out = append(out, fmt.Sprintf("storage[%s]: want %#x, got %#x", s, wv, gv))
		}
	}
	return out
}

func flattenAlloc(a fixture.Alloc) (map[string]flatAccount, error) {
	out := make(map[string]flatAccount, len(a))
	for hexAddr, acc := range a {
		addr, err := parseAddress(hexAddr)
		if err != nil {
			return nil, err
		}
		fa := flatAccount{
			nonce:    acc.Nonce.Big(),
			balance:  acc.Balance.Big(),
			codeHash: hex.EncodeToString(codeHash(acc.Code)),
			storage:  make(map[string]*big.Int),
		}
		for k, v := range acc.Storage {
			slot, err := fixture.ParseWord(k)
			if err != nil {
				return nil, err
			}
			if v.Big().Sign() != 0 {
				fa.storage[hex.EncodeToString(slot[:])] = v.Big()
			}
		}
		out[hex.EncodeToString(addr.Bytes())] = fa
	}
	return out, nil
}

func flattenState(st *acmstate.MemoryState, includeZeroAddr bool) (map[string]flatAccount, error) {
	out := make(map[string]flatAccount)
	err := st.IterateAccounts(func(acc *acm.Account) error {
		if acc.Address == acm.GlobalPermissionsAddress && !includeZeroAddr {
			return nil
		}
		fa := flatAccount{
			nonce:    new(big.Int).SetUint64(acc.Sequence),
			balance:  new(big.Int).SetUint64(acc.Balance),
			codeHash: hex.EncodeToString(codeHash(acc.EVMCode)),
			storage:  make(map[string]*big.Int),
		}
		err := st.IterateStorage(acc.Address, func(key binary.Word256, value []byte) error {
			if v := new(big.Int).SetBytes(value); v.Sign() != 0 {
				fa.storage[hex.EncodeToString(key.Bytes())] = v
			}
			return nil
		})
		if err != nil {
			return err
		}
		out[hex.EncodeToString(acc.Address.Bytes())] = fa
		return nil
	})
	return out, err
}
