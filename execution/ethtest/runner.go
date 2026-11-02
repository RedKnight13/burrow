// SPDX-License-Identifier: Apache-2.0

package ethtest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"path/filepath"
	"sort"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/hyperledger/burrow/acm/acmstate"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/execution/engine"
	"github.com/hyperledger/burrow/execution/ethtest/fixture"
	"github.com/hyperledger/burrow/execution/evm"
	"github.com/hyperledger/burrow/execution/exec"
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

// callInput is everything handed to Burrow's EVM for one case.
type callInput struct {
	state      *acmstate.MemoryState
	blockchain engine.Blockchain
	sink       exec.EventSink
	params     engine.CallParams
	code       []byte
}

// execute runs one call through Burrow's EVM. A fresh EVM with a fixed nonce is
// used per case so CREATE addresses do not depend on run order. Its error is
// not inspected: the post-state comparison decides the result.
var execute = func(c callInput) error {
	vm := evm.New(engine.Options{Nonce: []byte("ethtest")})
	_, err := vm.Execute(c.state, c.blockchain, c.sink, c.params, c.code)
	return err
}

// RunCase runs post[fork][i] of t.
func RunCase(id string, t fixture.StateTest, fork string, i int) Result {
	res, _ := runCase(id, t, fork, i)
	return res
}

// runCase also returns the post-execution state (nil when Burrow was not run),
// for diffing.
func runCase(id string, t fixture.StateTest, fork string, i int) (res Result, st *acmstate.MemoryState) {
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
	tx := t.Transaction

	switch {
	case post.ExpectException != "":
		return fail("unsupported: tx validation")
	case tx.To == "":
		return fail("unsupported: create tx")
	case present(tx.AccessLists) || present(tx.BlobVersionedHashes) || present(tx.AuthorizationList):
		return fail("unsupported: typed tx")
	}

	if err := checkIndex(post.Indexes.Data, len(tx.Data), "data"); err != nil {
		return harnessError(err)
	}
	if err := checkIndex(post.Indexes.Gas, len(tx.GasLimit), "gasLimit"); err != nil {
		return harnessError(err)
	}
	if err := checkIndex(post.Indexes.Value, len(tx.Value), "value"); err != nil {
		return harnessError(err)
	}
	data := tx.Data[post.Indexes.Data]
	gas := tx.GasLimit[post.Indexes.Gas]
	value := tx.Value[post.Indexes.Value]

	loaded, err := LoadAlloc(t.Pre)
	var unsupported ErrUnsupported
	if errors.As(err, &unsupported) {
		return fail(unsupported.Error())
	}
	if err != nil {
		return harnessError(err)
	}
	to, err := parseAddress(tx.To)
	if err != nil {
		return harnessError(err)
	}
	if _, ok := t.Pre[tx.To]; !ok {
		return fail("unsupported: call to new account")
	}
	sender, err := txSender(tx)
	if err != nil {
		return harnessError(err)
	}
	callee, err := loaded.GetAccount(to)
	if err != nil {
		return harnessError(err)
	}

	sink := &logSink{}
	st = loaded
	_ = execute(callInput{
		state: st,
		blockchain: &engine.TestBlockchain{
			BlockHeight: t.Env.Number.Big().Uint64(),
			BlockTime:   time.Unix(t.Env.Timestamp.Big().Int64(), 0),
		},
		sink: sink,
		params: engine.CallParams{
			Origin: sender,
			Caller: sender,
			Callee: to,
			Input:  data,
			Value:  *new(big.Int).Set(value.Big()),
			Gas:    new(big.Int).Set(gas.Big()),
		},
		code: callee.EVMCode,
	})

	root, err := StateRoot(st, hasZeroAddress(t.Pre))
	if err != nil {
		return harnessError(err)
	}
	if !bytes.Equal(root[:], post.Hash) {
		return fail("root")
	}
	logs := LogsHash(sink.logs)
	if !bytes.Equal(logs[:], post.Logs) {
		return fail("logs")
	}
	res.Status = Pass
	return res, st
}

// present reports whether an optional transaction field carries anything.
func present(raw json.RawMessage) bool {
	s := string(bytes.TrimSpace(raw))
	return s != "" && s != "null" && s != "[]"
}

func checkIndex(i, n int, field string) error {
	if i < 0 || i >= n {
		return fmt.Errorf("index %d out of range for transaction %s (len %d)", i, field, n)
	}
	return nil
}

func txSender(tx fixture.Transaction) (crypto.Address, error) {
	if tx.Sender != "" {
		return parseAddress(tx.Sender)
	}
	if len(tx.SecretKey) == 0 {
		return crypto.ZeroAddress, fmt.Errorf("transaction has neither sender nor secretKey")
	}
	return senderFromKey(tx.SecretKey)
}

// senderFromKey derives an Ethereum address: the last 20 bytes of the
// keccak256 of the uncompressed public key without its 0x04 prefix.
func senderFromKey(key []byte) (crypto.Address, error) {
	_, pub := btcec.PrivKeyFromBytes(btcec.S256(), key)
	hash := crypto.Keccak256(pub.SerializeUncompressed()[1:])
	addr, err := crypto.AddressFromBytes(hash[12:])
	if err != nil {
		return crypto.ZeroAddress, fmt.Errorf("sender from secret key: %w", err)
	}
	return addr, nil
}

// RunFile runs every case in one state-test file. IDs are
// <path relative to stateRoot>::<test name>::<fork>::<index>, and results are
// sorted by ID.
func RunFile(stateRoot, path string) ([]Result, error) {
	tests, err := fixture.LoadStateTests(path)
	if err != nil {
		return nil, err
	}
	rel, err := filepath.Rel(stateRoot, path)
	if err != nil {
		return nil, fmt.Errorf("relative path of %s: %w", path, err)
	}
	rel = filepath.ToSlash(rel)
	var results []Result
	for name, t := range tests {
		for fork, posts := range t.Post {
			for i := range posts {
				id := fmt.Sprintf("%s::%s::%s::%d", rel, name, fork, i)
				results = append(results, RunCase(id, t, fork, i))
			}
		}
	}
	sort.Slice(results, func(a, b int) bool { return results[a].ID < results[b].ID })
	return results, nil
}
