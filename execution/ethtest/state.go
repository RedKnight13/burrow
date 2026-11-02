// SPDX-License-Identifier: Apache-2.0

// Package ethtest runs Ethereum state-test fixtures against Burrow's EVM and
// computes the Ethereum state root and logs hash of the result.
package ethtest

import (
	"bytes"
	"fmt"
	"math/big"
	"path/filepath"
	"strings"

	"github.com/hyperledger/burrow/acm"
	"github.com/hyperledger/burrow/acm/acmstate"
	"github.com/hyperledger/burrow/binary"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/execution/ethtest/fixture"
	"github.com/hyperledger/burrow/execution/ethtest/trie"
	"github.com/hyperledger/burrow/execution/evm/rlp"
	"github.com/hyperledger/burrow/permission"
)

// ErrUnsupported reports a case Burrow cannot represent or run.
type ErrUnsupported struct {
	What string
}

func (e ErrUnsupported) Error() string {
	return "unsupported: " + e.What
}

func codeHash(code []byte) []byte {
	return crypto.Keccak256(code)
}

func parseAddress(s string) (crypto.Address, error) {
	addr, err := crypto.AddressFromHexString(strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X"))
	if err != nil {
		return crypto.ZeroAddress, fmt.Errorf("address %q: %w", s, err)
	}
	return addr, nil
}

// accountLeaf is the RLP of an account as stored in the state trie.
func accountLeaf(nonce, balance *big.Int, storageRoot [32]byte, code []byte) []byte {
	return rlp.Encode([]rlp.Item{rlp.Uint(nonce), rlp.Uint(balance), storageRoot[:], codeHash(code)})
}

// storageRoot hashes slot keys and RLP-encodes values; zero values are absent.
func storageRoot(slots map[[32]byte]*big.Int) [32]byte {
	kv := make(map[string][]byte, len(slots))
	for slot, v := range slots {
		if v.Sign() == 0 {
			continue
		}
		kv[string(crypto.Keccak256(slot[:]))] = rlp.Encode(rlp.Uint(v))
	}
	return trie.Root(kv)
}

// AllocRoot computes the state root straight from a fixture alloc.
func AllocRoot(a fixture.Alloc) ([32]byte, error) {
	kv := make(map[string][]byte, len(a))
	for hexAddr, acc := range a {
		addr, err := parseAddress(hexAddr)
		if err != nil {
			return [32]byte{}, err
		}
		slots := make(map[[32]byte]*big.Int, len(acc.Storage))
		for k, v := range acc.Storage {
			slot, err := fixture.ParseWord(k)
			if err != nil {
				return [32]byte{}, fmt.Errorf("account %s: %w", hexAddr, err)
			}
			slots[slot] = v.Big()
		}
		kv[string(crypto.Keccak256(addr.Bytes()))] = accountLeaf(acc.Nonce.Big(), acc.Balance.Big(), storageRoot(slots), acc.Code)
	}
	return trie.Root(kv), nil
}

// LoadAlloc builds a Burrow in-memory state from a fixture alloc. Every account,
// including Burrow's global permissions account at 0x0, gets all permissions
// so Burrow's permission layer does not affect results.
func LoadAlloc(a fixture.Alloc) (*acmstate.MemoryState, error) {
	st := acmstate.NewMemoryState()
	st.Accounts[acm.GlobalPermissionsAddress].Permissions = permission.AllAccountPermissions
	for hexAddr, acc := range a {
		addr, err := parseAddress(hexAddr)
		if err != nil {
			return nil, err
		}
		if !acc.Nonce.Big().IsUint64() {
			return nil, ErrUnsupported{What: "nonce > uint64"}
		}
		balance, err := binary.Uint256FromBig(acc.Balance.Big())
		if err != nil {
			return nil, fmt.Errorf("account %s balance: %w", hexAddr, err)
		}
		err = st.UpdateAccount(&acm.Account{
			Address:     addr,
			Sequence:    acc.Nonce.Big().Uint64(),
			Balance:     balance,
			EVMCode:     acm.Bytecode(acc.Code),
			Permissions: permission.AllAccountPermissions,
		})
		if err != nil {
			return nil, fmt.Errorf("loading account %s: %w", hexAddr, err)
		}
		for k, v := range acc.Storage {
			if v.Big().Sign() == 0 {
				continue
			}
			slot, err := fixture.ParseWord(k)
			if err != nil {
				return nil, fmt.Errorf("account %s: %w", hexAddr, err)
			}
			var value [32]byte
			v.Big().FillBytes(value[:])
			if err := st.SetStorage(addr, binary.Word256(slot), value[:]); err != nil {
				return nil, fmt.Errorf("account %s storage: %w", hexAddr, err)
			}
		}
	}
	return st, nil
}

// StateRoot computes the Ethereum state root of a Burrow state. The global
// permissions account at 0x0 is left out unless includeZeroAddr is set.
func StateRoot(st *acmstate.MemoryState, includeZeroAddr bool) ([32]byte, error) {
	kv := make(map[string][]byte)
	err := st.IterateAccounts(func(acc *acm.Account) error {
		if acc.Address == acm.GlobalPermissionsAddress && !includeZeroAddr {
			return nil
		}
		slots := make(map[[32]byte]*big.Int)
		err := st.IterateStorage(acc.Address, func(key binary.Word256, value []byte) error {
			slots[key] = new(big.Int).SetBytes(value)
			return nil
		})
		if err != nil {
			return fmt.Errorf("storage of %v: %w", acc.Address, err)
		}
		nonce := new(big.Int).SetUint64(acc.Sequence)
		balance := acc.Balance.Big()
		kv[string(crypto.Keccak256(acc.Address.Bytes()))] = accountLeaf(nonce, balance, storageRoot(slots), acc.EVMCode)
		return nil
	})
	if err != nil {
		return [32]byte{}, err
	}
	return trie.Root(kv), nil
}

// GenesisCheck is the result of CheckGenesisRoots.
type GenesisCheck struct {
	Checked           int      // blockchain tests examined
	Matched           int      // AllocRoot(pre) == genesis stateRoot
	BurrowMatched     int      // the same via LoadAlloc and StateRoot
	BurrowUnsupported int      // pre could not be loaded into Burrow state
	Mismatched        int      // roots that differed, on either path
	Mismatches        []string // the first maxMismatches of them
}

const maxMismatches = 20

// CheckGenesisRoots compares, for every blockchain fixture under root, the
// state root of pre with genesisBlockHeader.stateRoot, both directly and via
// Burrow's state. It proves the hashing code without involving the EVM.
func CheckGenesisRoots(root string) (GenesisCheck, error) {
	var res GenesisCheck
	mismatch := func(format string, args ...interface{}) {
		res.Mismatched++
		if len(res.Mismatches) < maxMismatches {
			res.Mismatches = append(res.Mismatches, fmt.Sprintf(format, args...))
		}
	}
	err := fixture.Walk(root, "blockchain_tests", func(path string) error {
		tests, err := fixture.LoadBlockchainTests(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		for name, bt := range tests {
			res.Checked++
			want := bt.Genesis.StateRoot
			got, err := AllocRoot(bt.Pre)
			if err != nil {
				return fmt.Errorf("%s::%s: %w", rel, name, err)
			}
			if !bytes.Equal(got[:], want) {
				mismatch("%s::%s: alloc root %x, want %x", rel, name, got, want)
				continue
			}
			res.Matched++
			st, err := LoadAlloc(bt.Pre)
			if _, ok := err.(ErrUnsupported); ok {
				res.BurrowUnsupported++
				continue
			}
			if err != nil {
				return fmt.Errorf("%s::%s: %w", rel, name, err)
			}
			got, err = StateRoot(st, hasZeroAddress(bt.Pre))
			if err != nil {
				return fmt.Errorf("%s::%s: %w", rel, name, err)
			}
			if !bytes.Equal(got[:], want) {
				mismatch("%s::%s: burrow state root %x, want %x", rel, name, got, want)
				continue
			}
			res.BurrowMatched++
		}
		return nil
	})
	return res, err
}

// OK reports whether at least one root was checked and none differed.
func (g GenesisCheck) OK() bool {
	return g.Checked > 0 && g.Mismatched == 0 && g.Matched == g.Checked &&
		g.BurrowMatched+g.BurrowUnsupported == g.Checked
}

func hasZeroAddress(a fixture.Alloc) bool {
	for hexAddr := range a {
		if addr, err := parseAddress(hexAddr); err == nil && addr == acm.GlobalPermissionsAddress {
			return true
		}
	}
	return false
}
