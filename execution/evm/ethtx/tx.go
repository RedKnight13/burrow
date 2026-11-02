// SPDX-License-Identifier: Apache-2.0

// Package ethtx processes signed Ethereum transactions against Burrow state.
// Apply decodes and validates a transaction, enforces Burrow permissions, runs
// it through Burrow's EVM over a recording overlay, and returns the outcome
// with a deterministic read-write set. It never mutates the caller's state.
package ethtx

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/execution/evm/rlp"
)

var (
	errTyped = errors.New("typed (EIP-2718) transactions are not supported yet")
	// errChainID is for typed transactions, which carry a chain ID field.
	errChainID   = errors.New("transaction is for a different chain ID")
	secp256k1N   = btcec.S256().N
	secp256k1Mid = new(big.Int).Rsh(secp256k1N, 1)
)

// Transaction is a decoded legacy (pre-EIP-2718) transaction.
type Transaction struct {
	Nonce    uint64
	GasPrice *big.Int
	Gas      uint64
	To       *crypto.Address // nil for contract creation
	Value    *big.Int
	Data     []byte
	V, R, S  *big.Int
}

// Decode parses a raw signed transaction. Typed transactions return errTyped.
func Decode(raw []byte) (*Transaction, error) {
	if len(raw) > 0 && raw[0] < 0xc0 {
		return nil, errTyped
	}
	it, err := rlp.Decode(raw)
	if err != nil {
		return nil, fmt.Errorf("decoding transaction: %w", err)
	}
	fields, ok := it.([]rlp.Item)
	if !ok || len(fields) != 9 {
		return nil, errors.New("transaction is not a list of 9 fields")
	}
	b := make([][]byte, 9)
	for i, f := range fields {
		if b[i], ok = f.([]byte); !ok {
			return nil, fmt.Errorf("transaction field %d is a list", i)
		}
	}
	tx := &Transaction{Data: b[5]}
	if tx.Nonce, err = uint64Field(b[0], "nonce"); err != nil {
		return nil, err
	}
	if tx.GasPrice, err = bigField(b[1], "gasPrice"); err != nil {
		return nil, err
	}
	if tx.Gas, err = uint64Field(b[2], "gas"); err != nil {
		return nil, err
	}
	switch len(b[3]) {
	case 0:
	case crypto.AddressLength:
		to, err := crypto.AddressFromBytes(b[3])
		if err != nil {
			return nil, fmt.Errorf("transaction to: %w", err)
		}
		tx.To = &to
	default:
		return nil, fmt.Errorf("transaction to has %d bytes", len(b[3]))
	}
	if tx.Value, err = bigField(b[4], "value"); err != nil {
		return nil, err
	}
	if tx.V, err = bigField(b[6], "v"); err != nil {
		return nil, err
	}
	if tx.R, err = bigField(b[7], "r"); err != nil {
		return nil, err
	}
	if tx.S, err = bigField(b[8], "s"); err != nil {
		return nil, err
	}
	return tx, nil
}

// Sender recovers the signing address. chainID is the chain the transaction
// must be bound to when it uses EIP-155 replay protection.
func (tx *Transaction) Sender(chainID *big.Int) (crypto.Address, error) {
	var recID int64
	var hash []byte
	switch v := tx.V; {
	case v.Cmp(big.NewInt(27)) == 0 || v.Cmp(big.NewInt(28)) == 0:
		recID = v.Int64() - 27
		hash = tx.signingHash(nil)
	case v.Cmp(big.NewInt(35)) >= 0:
		txChain := new(big.Int).Rsh(new(big.Int).Sub(v, big.NewInt(35)), 1)
		if txChain.Cmp(chainID) != 0 {
			// For a legacy transaction a v that does not encode this chain is an
			// invalid signature, as in Ethereum's execution specs.
			return crypto.ZeroAddress, fmt.Errorf("signature v %v does not encode chain %v", v, chainID)
		}
		recID = int64(new(big.Int).Sub(v, big.NewInt(35)).Bit(0))
		hash = tx.signingHash(chainID)
	default:
		return crypto.ZeroAddress, fmt.Errorf("invalid signature v %v", v)
	}
	if tx.R.Sign() <= 0 || tx.R.Cmp(secp256k1N) >= 0 || tx.S.Sign() <= 0 || tx.S.Cmp(secp256k1Mid) > 0 {
		return crypto.ZeroAddress, errors.New("signature r or s out of range")
	}
	compact := make([]byte, 65)
	compact[0] = byte(27 + recID)
	tx.R.FillBytes(compact[1:33])
	tx.S.FillBytes(compact[33:65])
	pub, _, err := btcec.RecoverCompact(btcec.S256(), compact, hash)
	if err != nil {
		return crypto.ZeroAddress, fmt.Errorf("recovering sender: %w", err)
	}
	addr, err := crypto.AddressFromBytes(crypto.Keccak256(pub.SerializeUncompressed()[1:])[12:])
	if err != nil {
		return crypto.ZeroAddress, fmt.Errorf("recovering sender: %w", err)
	}
	return addr, nil
}

// signingHash is keccak256 of the unsigned fields, with [chainID, 0, 0]
// appended under EIP-155.
func (tx *Transaction) signingHash(chainID *big.Int) []byte {
	to := []byte{}
	if tx.To != nil {
		to = tx.To.Bytes()
	}
	fields := []rlp.Item{
		rlp.Uint(new(big.Int).SetUint64(tx.Nonce)), rlp.Uint(tx.GasPrice),
		rlp.Uint(new(big.Int).SetUint64(tx.Gas)), to, rlp.Uint(tx.Value), tx.Data,
	}
	if chainID != nil {
		fields = append(fields, rlp.Uint(chainID), []byte{}, []byte{})
	}
	return crypto.Keccak256(rlp.Encode(fields))
}

func bigField(b []byte, name string) (*big.Int, error) {
	if len(b) > 0 && b[0] == 0 {
		return nil, fmt.Errorf("transaction %s has a leading zero", name)
	}
	if len(b) > 32 {
		return nil, fmt.Errorf("transaction %s exceeds 256 bits", name)
	}
	return new(big.Int).SetBytes(b), nil
}

func uint64Field(b []byte, name string) (uint64, error) {
	n, err := bigField(b, name)
	if err != nil {
		return 0, err
	}
	if !n.IsUint64() {
		return 0, fmt.Errorf("transaction %s exceeds 64 bits", name)
	}
	return n.Uint64(), nil
}
