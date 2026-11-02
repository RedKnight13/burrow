// SPDX-License-Identifier: Apache-2.0

package ethtest

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hyperledger/burrow/acm/acmstate"
	"github.com/hyperledger/burrow/execution/ethtest/fixture"
	"github.com/hyperledger/burrow/execution/evm/ethtx"
)

type Status int

const (
	Pass Status = iota
	Fail
	Error
)

func (s Status) String() string {
	switch s {
	case Pass:
		return "pass"
	case Fail:
		return "fail"
	default:
		return "error"
	}
}

// Result is the outcome of one case: one entry of a fixture's post[fork].
type Result struct {
	ID     string
	Fork   string
	Status Status
	Reason string
}

// apply is the transaction processor under test. Tests may replace it.
var apply = ethtx.Apply

// RunCase runs post[fork][i] of t.
func RunCase(id string, t fixture.StateTest, fork string, i int) Result {
	res, _ := runCase(id, t, fork, i, nil, nil)
	return res
}

// runCase feeds the case's signed transaction (txbytes) through Burrow's
// transaction processor and compares the resulting state root and logs hash
// with the fixture. It also returns the post-state (nil when Burrow was not
// run), for diffing. onEnter and onLeave, if set, are called just before Burrow
// starts and just after it returns. A
// panic inside Burrow is a Burrow defect ("crash"); any other panic is a
// harness bug (Error).
func runCase(id string, t fixture.StateTest, fork string, i int, onEnter, onLeave func()) (res Result, st *acmstate.MemoryState) {
	res = Result{ID: id, Fork: fork}
	defer func() {
		if r := recover(); r != nil {
			res.Status, res.Reason, st = Error, fmt.Sprintf("panic: %v", r), nil
		}
	}()
	fail := func(reason string) (Result, *acmstate.MemoryState) {
		res.Status, res.Reason = Fail, reason
		return res, st
	}
	harnessError := func(err error) (Result, *acmstate.MemoryState) {
		res.Status, res.Reason = Error, err.Error()
		return res, nil
	}

	posts := t.Post[fork]
	if i < 0 || i >= len(posts) {
		return harnessError(fmt.Errorf("no post entry %s[%d]", fork, i))
	}
	post := posts[i]
	if len(post.TxBytes) == 0 {
		return harnessError(fmt.Errorf("post entry %s[%d] has no txbytes", fork, i))
	}
	env, err := blockEnv(t)
	if err != nil {
		return harnessError(err)
	}
	loaded, err := LoadAlloc(t.Pre)
	var unsupported ErrUnsupported
	if errors.As(err, &unsupported) {
		return fail(unsupported.Error())
	}
	if err != nil {
		return harnessError(err)
	}

	st = loaded
	if onEnter != nil {
		onEnter()
	}
	out, crash := guardedApply(post.TxBytes, st, env)
	if onLeave != nil {
		onLeave()
	}
	if crash != "" {
		return fail(crash)
	}
	if out.Status == ethtx.Unsupported {
		return fail("unsupported: " + string(out.Reason))
	}

	if post.ExpectException != "" {
		want, unknown := expectedReasons(post.ExpectException)
		switch {
		case len(want) == 0:
			return fail("unsupported: exception " + strings.Join(unknown, "|"))
		case out.Status != ethtx.Invalid:
			return fail("exception: not raised")
		case !containsReason(want, out.Reason):
			return fail("exception: got " + string(out.Reason))
		}
	} else if out.Status == ethtx.Invalid {
		return fail("exception: unexpected " + string(out.Reason))
	}

	if out.Status != ethtx.Invalid {
		if t.Transaction.Sender != "" {
			want, err := parseAddress(t.Transaction.Sender)
			if err != nil {
				return harnessError(err)
			}
			if out.Sender != want {
				return fail("sender")
			}
		}
		if err := out.RWSet.ApplyTo(st); err != nil {
			return harnessError(err)
		}
	}

	root, err := StateRoot(st, hasZeroAddress(t.Pre))
	if err != nil {
		return harnessError(err)
	}
	if !bytes.Equal(root[:], post.Hash) {
		return fail("root")
	}
	logs := LogsHash(out.Logs)
	if !bytes.Equal(logs[:], post.Logs) {
		return fail("logs")
	}
	res.Status = Pass
	return res, st
}

// guardedApply runs Burrow's transaction processor and turns a panic inside
// it into a crash reason.
func guardedApply(raw []byte, st acmstate.Reader, env ethtx.Env) (out ethtx.Result, crash string) {
	defer func() {
		if r := recover(); r != nil {
			crash = fmt.Sprintf("crash: panic: %v", r)
		}
	}()
	return apply(raw, st, env), ""
}

// blockEnv builds the processor's block environment from the fixture.
func blockEnv(t fixture.StateTest) (ethtx.Env, error) {
	coinbase, err := parseAddress(t.Env.Coinbase)
	if err != nil {
		return ethtx.Env{}, fmt.Errorf("env coinbase: %w", err)
	}
	chainID := big.NewInt(1)
	if t.Config.ChainID.Int != nil {
		chainID = t.Config.ChainID.Int
	}
	for _, q := range []fixture.Quantity{t.Env.Number, t.Env.Timestamp, t.Env.GasLimit} {
		if !q.Big().IsUint64() {
			return ethtx.Env{}, fmt.Errorf("env value %v exceeds 64 bits", q.Big())
		}
	}
	return ethtx.Env{
		ChainID:   chainID,
		Coinbase:  coinbase,
		Number:    t.Env.Number.Big().Uint64(),
		Timestamp: t.Env.Timestamp.Big().Uint64(),
		GasLimit:  t.Env.GasLimit.Big().Uint64(),
	}, nil
}

// exceptionReasons maps execution-specs exception names to the processor's
// reasons. Names not listed are rules Burrow does not implement yet.
var exceptionReasons = map[string]ethtx.Reason{
	"TransactionException.INTRINSIC_GAS_TOO_LOW":      ethtx.ReasonIntrinsicGas,
	"TransactionException.INSUFFICIENT_ACCOUNT_FUNDS": ethtx.ReasonInsufficientFunds,
	"TransactionException.INVALID_SIGNATURE_VRS":      ethtx.ReasonSignature,
	"TransactionException.INVALID_CHAINID":            ethtx.ReasonChainID,
	"TransactionException.NONCE_IS_MAX":               ethtx.ReasonNonceMax,
	"TransactionException.NONCE_MISMATCH_TOO_LOW":     ethtx.ReasonNonceTooLow,
	"TransactionException.NONCE_MISMATCH_TOO_HIGH":    ethtx.ReasonNonceTooHigh,
	"TransactionException.GAS_ALLOWANCE_EXCEEDED":     ethtx.ReasonGasLimit,
}

// expectedReasons splits an expectException value ("A|B") into the reasons
// Burrow knows and the short names of those it does not.
func expectedReasons(expect string) (known []ethtx.Reason, unknown []string) {
	for _, name := range strings.Split(expect, "|") {
		if r, ok := exceptionReasons[name]; ok {
			known = append(known, r)
		} else {
			unknown = append(unknown, strings.TrimPrefix(name, "TransactionException."))
		}
	}
	return known, unknown
}

func containsReason(list []ethtx.Reason, r ethtx.Reason) bool {
	for _, x := range list {
		if x == r {
			return true
		}
	}
	return false
}

// Case is one entry of a fixture's post[fork] array.
type Case struct {
	ID    string
	Fork  string
	Index int
	Test  fixture.StateTest
}

func (c Case) Run() Result {
	return c.RunWith(nil, nil)
}

// RunWith runs the case, calling onEnter just before Burrow's EVM starts and
// onLeave just after it returns. Either may be nil.
func (c Case) RunWith(onEnter, onLeave func()) Result {
	res, _ := runCase(c.ID, c.Test, c.Fork, c.Index, onEnter, onLeave)
	return res
}

// Cases lists every case in one state-test file, sorted by ID. IDs are
// <path relative to stateRoot>::<test name>::<fork>::<index>.
func Cases(stateRoot, path string) ([]Case, error) {
	tests, err := fixture.LoadStateTests(path)
	if err != nil {
		return nil, err
	}
	rel, err := filepath.Rel(stateRoot, path)
	if err != nil {
		return nil, fmt.Errorf("relative path of %s: %w", path, err)
	}
	rel = filepath.ToSlash(rel)
	var cases []Case
	for name, t := range tests {
		for fork, posts := range t.Post {
			for i := range posts {
				cases = append(cases, Case{
					ID:    fmt.Sprintf("%s::%s::%s::%d", rel, name, fork, i),
					Fork:  fork,
					Index: i,
					Test:  t,
				})
			}
		}
	}
	sort.Slice(cases, func(a, b int) bool { return cases[a].ID < cases[b].ID })
	return cases, nil
}

// RunFile runs every case in one state-test file, in ID order.
func RunFile(stateRoot, path string) ([]Result, error) {
	cases, err := Cases(stateRoot, path)
	if err != nil {
		return nil, err
	}
	results := make([]Result, len(cases))
	for i, c := range cases {
		results[i] = c.Run()
	}
	return results, nil
}
