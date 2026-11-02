// SPDX-License-Identifier: Apache-2.0

package ethtx

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"time"

	"github.com/hyperledger/burrow/acm"
	"github.com/hyperledger/burrow/acm/acmstate"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/execution/engine"
	berrors "github.com/hyperledger/burrow/execution/errors"
	"github.com/hyperledger/burrow/execution/evm"
	"github.com/hyperledger/burrow/execution/evm/rlp"
	"github.com/hyperledger/burrow/execution/exec"
	"github.com/hyperledger/burrow/permission"
)

// Status is the outcome class of a transaction.
type Status int

const (
	// Success: executed and its effects stand.
	Success Status = iota
	// Failed: executed but reverted. The nonce bump and the fee still stand.
	Failed
	// Invalid: rejected before execution. It has no effects and uses no gas.
	Invalid
	// Unsupported: Burrow cannot process this kind of transaction yet.
	Unsupported
)

func (s Status) String() string {
	switch s {
	case Success:
		return "success"
	case Failed:
		return "failed"
	case Invalid:
		return "invalid"
	default:
		return "unsupported"
	}
}

// Reason says why a transaction was invalid or unsupported.
type Reason string

const (
	ReasonNone              Reason = ""
	ReasonDecode            Reason = "decode"
	ReasonTypedTx           Reason = "typed transaction"
	ReasonSignature         Reason = "signature"
	ReasonChainID           Reason = "chain id"
	ReasonUnknownSender     Reason = "unknown sender"
	ReasonPermission        Reason = "permission"
	ReasonNonceTooLow       Reason = "nonce too low"
	ReasonNonceTooHigh      Reason = "nonce too high"
	ReasonNonceMax          Reason = "nonce is max"
	ReasonGasLimit          Reason = "gas limit exceeds block"
	ReasonIntrinsicGas      Reason = "intrinsic gas too low"
	ReasonInsufficientFunds Reason = "insufficient funds"
	ReasonValueTooLarge     Reason = "value exceeds int64"
)

// Env is the block a transaction executes in.
type Env struct {
	ChainID   *big.Int
	Coinbase  crypto.Address
	Number    uint64
	Timestamp uint64
	GasLimit  uint64
}

// Result is the deterministic outcome of a transaction.
type Result struct {
	Status  Status
	Reason  Reason
	Err     error // detail for Invalid, Unsupported and Failed
	Sender  crypto.Address
	GasUsed uint64
	Return  []byte
	Created *crypto.Address // address of a created contract
	Logs    []*exec.LogEvent
	RWSet   RWSet
}

// Intrinsic gas: one schedule (Istanbul calldata pricing) until Burrow has
// per-fork configuration.
const (
	gasTx             = 21000
	gasTxCreate       = 32000
	gasTxDataZero     = 4
	gasTxDataNonZero  = 16
	evmNonceForEthTxs = "ethtx"
)

// Apply processes one raw signed transaction against st without modifying it.
// Burrow permissions are always checked: the sender needs Input, and Call or
// CreateContract. The caller applies Result.RWSet to commit the effects.
func Apply(raw []byte, st acmstate.Reader, env Env) Result {
	tx, err := Decode(raw)
	if errors.Is(err, errTyped) {
		return Result{Status: Unsupported, Reason: ReasonTypedTx, Err: err}
	}
	if err != nil {
		return invalid(ReasonDecode, err)
	}
	sender, err := tx.Sender(env.ChainID)
	if errors.Is(err, errChainID) {
		return invalid(ReasonChainID, err)
	}
	if err != nil {
		return invalid(ReasonSignature, err)
	}

	rec := newRecorder(st)
	res, ok := validate(rec, tx, sender, env)
	if !ok {
		return res
	}

	// Charge the full gas allowance up front and bump the nonce. These stand
	// even if execution fails.
	acc, err := senderAccount(rec, sender)
	if err != nil {
		return invalid(ReasonUnknownSender, err)
	}
	upfront := new(big.Int).Mul(new(big.Int).SetUint64(tx.Gas), tx.GasPrice)
	acc.Balance -= upfront.Uint64()
	acc.Sequence++
	if err := rec.UpdateAccount(acc); err != nil {
		return invalid(ReasonUnknownSender, err)
	}

	gas := new(big.Int).SetUint64(tx.Gas - intrinsicGas(tx))
	frame := rec.child()
	ret, created, logs, execErr := execute(frame, tx, sender, gas, env)

	res = Result{Status: Success, Sender: sender, Return: ret, Created: created, Logs: logs}
	if execErr != nil {
		res.Status, res.Err, res.Logs, res.Created = Failed, execErr, nil, nil
	} else {
		frame.commit()
	}

	res.GasUsed = tx.Gas - gas.Uint64()
	if err := settleFees(rec, sender, env.Coinbase, tx.GasPrice, gas.Uint64(), res.GasUsed); err != nil {
		return invalid(ReasonInsufficientFunds, err)
	}
	res.RWSet = rec.rwset()
	return res
}

func invalid(reason Reason, err error) Result {
	return Result{Status: Invalid, Reason: reason, Err: err}
}

// validate checks everything that makes a transaction unincludable. Reads it
// performs are recorded but no writes happen.
func validate(rec *overlay, tx *Transaction, sender crypto.Address, env Env) (Result, bool) {
	fail := func(r Reason, format string, args ...interface{}) (Result, bool) {
		res := invalid(r, fmt.Errorf(format, args...))
		res.Sender = sender
		return res, false
	}
	acc, err := senderAccount(rec, sender)
	if err != nil {
		return fail(ReasonUnknownSender, "reading sender: %v", err)
	}
	// Ethereum's validity rules first, then Burrow's permissions.
	switch {
	case acc.Sequence == math.MaxUint64:
		return fail(ReasonNonceMax, "sender nonce is at its maximum")
	case tx.Nonce < acc.Sequence:
		return fail(ReasonNonceTooLow, "nonce %d, account nonce %d", tx.Nonce, acc.Sequence)
	case tx.Nonce > acc.Sequence:
		return fail(ReasonNonceTooHigh, "nonce %d, account nonce %d", tx.Nonce, acc.Sequence)
	case tx.Gas > env.GasLimit:
		return fail(ReasonGasLimit, "gas %d exceeds block gas limit %d", tx.Gas, env.GasLimit)
	case tx.Gas < intrinsicGas(tx):
		return fail(ReasonIntrinsicGas, "gas %d below intrinsic %d", tx.Gas, intrinsicGas(tx))
	}
	cost := new(big.Int).Mul(new(big.Int).SetUint64(tx.Gas), tx.GasPrice)
	cost.Add(cost, tx.Value)
	if cost.Cmp(new(big.Int).SetUint64(acc.Balance)) > 0 {
		return fail(ReasonInsufficientFunds, "cost %v exceeds balance %d", cost, acc.Balance)
	}
	needed := []permission.PermFlag{permission.Input, permission.Call}
	if tx.To == nil {
		needed[1] = permission.CreateContract
	}
	for _, perm := range needed {
		if !hasPermission(rec, acc, perm) {
			return fail(ReasonPermission, "sender %v lacks %v permission", sender, perm)
		}
	}
	if !tx.Value.IsInt64() {
		res := Result{Status: Unsupported, Reason: ReasonValueTooLarge, Sender: sender,
			Err: fmt.Errorf("value %v exceeds Burrow's int64 transfer limit", tx.Value)}
		return res, false
	}
	return Result{}, true
}

// senderAccount returns the sender's account, or, as on Ethereum, an empty one
// (nonce 0, balance 0) when it does not exist.
func senderAccount(rec *overlay, sender crypto.Address) (*acm.Account, error) {
	acc, err := rec.GetAccount(sender)
	if err != nil {
		return nil, err
	}
	if acc == nil {
		acc = &acm.Account{Address: sender}
	}
	return acc, nil
}

// hasPermission composes the account's own permissions with the chain's global
// permissions. A permission set in neither is denied.
func hasPermission(st acmstate.Reader, acc *acm.Account, perm permission.PermFlag) bool {
	global, err := acmstate.GlobalAccountPermissions(st)
	if err != nil {
		return false
	}
	ok, err := acc.Permissions.Base.Compose(global.Base).Get(perm)
	return err == nil && ok
}

func intrinsicGas(tx *Transaction) uint64 {
	gas := uint64(gasTx)
	if tx.To == nil {
		gas += gasTxCreate
	}
	for _, b := range tx.Data {
		if b == 0 {
			gas += gasTxDataZero
		} else {
			gas += gasTxDataNonZero
		}
	}
	return gas
}

// execute runs the call or creation in frame, which the caller commits only on
// success. gas is decremented by Burrow's EVM as it runs.
func execute(frame *overlay, tx *Transaction, sender crypto.Address, gas *big.Int, env Env) (
	ret []byte, created *crypto.Address, logs []*exec.LogEvent, err error) {

	sink := &logSink{}
	blockchain := &engine.TestBlockchain{
		BlockHeight: env.Number,
		BlockTime:   time.Unix(int64(env.Timestamp), 0),
	}
	vm := evm.New(engine.Options{Nonce: []byte(evmNonceForEthTxs)})
	params := engine.CallParams{
		CallType: exec.CallTypeCall,
		Origin:   sender,
		Caller:   sender,
		Input:    tx.Data,
		Value:    *new(big.Int).Set(tx.Value),
		Gas:      gas,
	}

	if tx.To == nil {
		addr := contractAddress(sender, tx.Nonce)
		if err := engine.CreateAccount(frame, addr); err != nil {
			return nil, nil, nil, fmt.Errorf("creating contract account: %w", err)
		}
		params.Callee, params.Input = addr, nil
		ret, err = vm.Execute(frame, blockchain, sink, params, tx.Data)
		if err != nil {
			return nil, nil, nil, err
		}
		if err := engine.InitEVMCode(frame, addr, ret); err != nil {
			return nil, nil, nil, fmt.Errorf("storing contract code: %w", err)
		}
		return ret, &addr, sink.logs, nil
	}

	callee, err := frame.GetAccount(*tx.To)
	if err != nil {
		return nil, nil, nil, err
	}
	if callee == nil {
		if err := engine.CreateAccount(frame, *tx.To); err != nil {
			return nil, nil, nil, fmt.Errorf("creating callee account: %w", err)
		}
		callee = &acm.Account{Address: *tx.To}
	}
	params.Callee = *tx.To
	ret, err = vm.Execute(frame, blockchain, sink, params, callee.EVMCode)
	if err != nil {
		return nil, nil, nil, err
	}
	return ret, nil, sink.logs, nil
}

// contractAddress is keccak256(rlp([sender, nonce]))[12:].
func contractAddress(sender crypto.Address, nonce uint64) crypto.Address {
	enc := rlp.Encode([]rlp.Item{sender.Bytes(), rlp.Uint(new(big.Int).SetUint64(nonce))})
	addr, _ := crypto.AddressFromBytes(crypto.Keccak256(enc)[12:])
	return addr
}

// settleFees refunds unused gas to the sender and pays the used gas to the
// coinbase. A zero fee leaves the coinbase untouched.
func settleFees(rec *overlay, sender, coinbase crypto.Address, price *big.Int, gasLeft, gasUsed uint64) error {
	refund := new(big.Int).Mul(new(big.Int).SetUint64(gasLeft), price)
	acc, err := rec.GetAccount(sender)
	if err != nil {
		return err
	}
	if err := acc.AddToBalance(refund.Uint64()); err != nil {
		return err
	}
	if err := rec.UpdateAccount(acc); err != nil {
		return err
	}
	fee := new(big.Int).Mul(new(big.Int).SetUint64(gasUsed), price)
	if fee.Sign() == 0 {
		return nil
	}
	cb, err := rec.GetAccount(coinbase)
	if err != nil {
		return err
	}
	if cb == nil {
		cb = &acm.Account{Address: coinbase}
	}
	if err := cb.AddToBalance(fee.Uint64()); err != nil {
		return err
	}
	return rec.UpdateAccount(cb)
}

// logSink keeps the logs Burrow's EVM emits.
type logSink struct {
	logs []*exec.LogEvent
}

var _ exec.EventSink = (*logSink)(nil)

func (s *logSink) Call(*exec.CallEvent, *berrors.Exception) error { return nil }
func (s *logSink) Print(*exec.PrintEvent) error                   { return nil }
func (s *logSink) Log(l *exec.LogEvent) error {
	s.logs = append(s.logs, l)
	return nil
}
