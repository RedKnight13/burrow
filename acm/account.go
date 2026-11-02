// Copyright Monax Industries Limited
// SPDX-License-Identifier: Apache-2.0

package acm

import (
	"bytes"
	"fmt"
	"reflect"

	"github.com/gogo/protobuf/proto"
	"github.com/hyperledger/burrow/binary"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/event/query"
	"github.com/hyperledger/burrow/execution/errors"
	"github.com/hyperledger/burrow/permission"
)

var GlobalPermissionsAddress = crypto.Address(binary.Zero160)

func NewAccount(pubKey *crypto.PublicKey) *Account {
	return &Account{
		Address:   pubKey.GetAddress(),
		PublicKey: pubKey,
	}
}

func NewAccountFromSecret(secret string) *Account {
	return NewAccount(crypto.PrivateKeyFromSecret(secret, crypto.CurveTypeEd25519).GetPublicKey())
}

func (acc *Account) GetAddress() crypto.Address {
	return acc.Address
}

// AddToBalance credits amount to the account.
func (acc *Account) AddToBalance(amount uint64) error {
	return acc.Credit(binary.NewUint256(amount))
}

// SubtractFromBalance debits amount from the account.
func (acc *Account) SubtractFromBalance(amount uint64) error {
	return acc.Debit(binary.NewUint256(amount))
}

// Credit adds amount to the balance, failing if it would exceed 2^256 - 1.
func (acc *Account) Credit(amount binary.Uint256) error {
	sum, err := acc.Balance.Add(amount)
	if err != nil {
		return errors.Errorf(errors.Codes.IntegerOverflow,
			"uint256 overflow: attempt to add %v to the balance of %s", amount, acc.Address)
	}
	acc.Balance = sum
	return nil
}

// Debit subtracts amount from the balance, failing if the balance is smaller.
func (acc *Account) Debit(amount binary.Uint256) error {
	diff, err := acc.Balance.Sub(amount)
	if err != nil {
		return errors.Errorf(errors.Codes.InsufficientBalance,
			"insufficient funds: attempt to subtract %v from the balance of %s", amount, acc.Address)
	}
	acc.Balance = diff
	return nil
}

// Return bytes of any code-type value that is set. EVM, WASM, or native name
func (acc *Account) Code() []byte {
	switch {
	case len(acc.EVMCode) > 0:
		return acc.EVMCode
	case len(acc.WASMCode) > 0:
		return acc.WASMCode
	case acc.NativeName != "":
		return []byte(acc.NativeName)
	}
	return nil
}

// Conversions
//
// Using the naming convention is this package of 'As<Type>' being
// a conversion from Account to <Type> and 'From<Type>' being conversion
// from <Type> to Account. Conversions are done by copying

// Creates an otherwise zeroed Account from an Addressable and returns it as MutableAccount
func FromAddressable(addressable crypto.Addressable) *Account {
	return &Account{
		Address:   addressable.GetAddress(),
		PublicKey: addressable.GetPublicKey(),
		// Since nil slices and maps compare differently to empty ones
		EVMCode: Bytecode{},
		Permissions: permission.AccountPermissions{
			Roles: []string{},
		},
	}
}

// Copies all mutable parts of account
func (acc *Account) Copy() *Account {
	if acc == nil {
		return nil
	}
	accCopy := *acc
	accCopy.Permissions.Roles = make([]string, len(acc.Permissions.Roles))
	copy(accCopy.Permissions.Roles, acc.Permissions.Roles)
	return &accCopy
}

func (acc *Account) Equal(accOther *Account) bool {
	buf := proto.NewBuffer(nil)
	err := buf.Marshal(acc)
	if err != nil {
		return false
	}
	accEnc := buf.Bytes()
	buf.Reset()
	err = buf.Marshal(accOther)
	if err != nil {
		return false
	}
	accOtherEnc := buf.Bytes()
	return bytes.Equal(accEnc, accOtherEnc)
}

func (acc Account) String() string {
	return fmt.Sprintf("Account{Address: %s; Sequence: %v; PublicKey: %v Balance: %v; CodeLength: %v; Permissions: %v}",
		acc.Address, acc.Sequence, acc.PublicKey, acc.Balance, len(acc.EVMCode), acc.Permissions)
}

func (acc *Account) Get(key string) (interface{}, bool) {
	switch key {
	case "Permissions":
		return acc.Permissions.Base.ResultantPerms(), true
	case "Roles":
		return acc.Permissions.Roles, true
	default:
		return query.GetReflect(reflect.ValueOf(acc), key)
	}
}
