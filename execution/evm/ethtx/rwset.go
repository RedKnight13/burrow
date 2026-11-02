// SPDX-License-Identifier: Apache-2.0

package ethtx

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/hyperledger/burrow/acm"
	"github.com/hyperledger/burrow/acm/acmstate"
	"github.com/hyperledger/burrow/binary"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/execution/evm/rlp"
)

// Entry is one key of a read-write set: an account (Slot nil) or one storage
// slot of an account.
type Entry struct {
	Address crypto.Address
	Slot    *binary.Word256
	// Value is the protobuf encoding of the account, or the 32-byte storage
	// value. Nil means absent: not found on read, removed on write.
	Value []byte
	// Account is the decoded account for account entries with a value.
	Account *acm.Account
}

func (e Entry) less(o Entry) bool {
	if c := bytes.Compare(e.Address.Bytes(), o.Address.Bytes()); c != 0 {
		return c < 0
	}
	switch {
	case e.Slot == nil:
		return o.Slot != nil
	case o.Slot == nil:
		return false
	}
	return bytes.Compare(e.Slot.Bytes(), o.Slot.Bytes()) < 0
}

func (e Entry) String() string {
	if e.Slot == nil {
		return fmt.Sprintf("account %v", e.Address)
	}
	return fmt.Sprintf("storage %v[%x]", e.Address, e.Slot.Bytes())
}

// RWSet lists what a transaction read from the base state, with the values it
// saw, and what it wrote. Both lists are sorted by address, then slot, with the
// account entry first.
type RWSet struct {
	Reads  []Entry
	Writes []Entry
}

// Encode is a deterministic byte encoding of the set:
// rlp([[address, slot, value]...] reads, [...] writes), slot empty for accounts.
func (s RWSet) Encode() []byte {
	enc := func(list []Entry) []rlp.Item {
		out := make([]rlp.Item, 0, len(list))
		for _, e := range list {
			slot := []byte{}
			if e.Slot != nil {
				slot = e.Slot.Bytes()
			}
			value := e.Value
			if value == nil {
				value = []byte{}
			}
			out = append(out, []rlp.Item{e.Address.Bytes(), slot, value})
		}
		return out
	}
	return rlp.Encode([]rlp.Item{enc(s.Reads), enc(s.Writes)})
}

// ApplyTo writes the set's writes into st.
func (s RWSet) ApplyTo(st acmstate.Writer) error {
	for _, w := range s.Writes {
		var err error
		switch {
		case w.Slot != nil:
			value := w.Value
			if value == nil {
				value = binary.Zero256.Bytes()
			}
			err = st.SetStorage(w.Address, *w.Slot, value)
		case w.Account == nil:
			err = st.RemoveAccount(w.Address)
		default:
			err = st.UpdateAccount(w.Account.Copy())
		}
		if err != nil {
			return fmt.Errorf("applying write to %v: %w", w, err)
		}
	}
	return nil
}

// overlay is a copy-on-write layer over a reader. The bottom layer records the
// first read of each key from the base state; child layers buffer the writes of
// a frame that may be discarded.
type overlay struct {
	parent   acmstate.Reader
	reads    map[string]Entry // nil except on the bottom layer
	accounts map[crypto.Address]*acm.Account
	storage  map[crypto.Address]map[binary.Word256][]byte
}

var _ acmstate.ReaderWriter = (*overlay)(nil)

func newRecorder(base acmstate.Reader) *overlay {
	o := newOverlay(base)
	o.reads = make(map[string]Entry)
	return o
}

func newOverlay(parent acmstate.Reader) *overlay {
	return &overlay{
		parent:   parent,
		accounts: make(map[crypto.Address]*acm.Account),
		storage:  make(map[crypto.Address]map[binary.Word256][]byte),
	}
}

func (o *overlay) child() *overlay {
	return newOverlay(o)
}

func (o *overlay) GetAccount(address crypto.Address) (*acm.Account, error) {
	if acc, ok := o.accounts[address]; ok {
		return acc.Copy(), nil
	}
	acc, err := o.parent.GetAccount(address)
	if err != nil {
		return nil, err
	}
	if o.reads != nil {
		key := address.String()
		if _, seen := o.reads[key]; !seen {
			o.reads[key] = accountEntry(address, acc)
		}
	}
	return acc.Copy(), nil
}

func (o *overlay) GetStorage(address crypto.Address, key binary.Word256) ([]byte, error) {
	if slots, ok := o.storage[address]; ok {
		if v, ok := slots[key]; ok {
			return copyBytes(v), nil
		}
	}
	if acc, written := o.accounts[address]; written && acc == nil {
		return nil, nil // removed in this layer
	}
	v, err := o.parent.GetStorage(address, key)
	if err != nil {
		// Burrow's state errors on storage of an account it does not have;
		// an account that exists only in this overlay has empty storage.
		if acc, aerr := o.parent.GetAccount(address); aerr == nil && acc == nil {
			v, err = nil, nil
		}
	}
	if err != nil {
		return nil, err
	}
	if o.reads != nil {
		k := address.String() + "/" + key.String()
		if _, seen := o.reads[k]; !seen {
			slot := key
			o.reads[k] = Entry{Address: address, Slot: &slot, Value: storageValue(v)}
		}
	}
	return copyBytes(v), nil
}

func (o *overlay) UpdateAccount(acc *acm.Account) error {
	if acc == nil {
		return fmt.Errorf("UpdateAccount with nil account")
	}
	o.accounts[acc.Address] = acc.Copy()
	return nil
}

func (o *overlay) RemoveAccount(address crypto.Address) error {
	o.accounts[address] = nil
	return nil
}

func (o *overlay) SetStorage(address crypto.Address, key binary.Word256, value []byte) error {
	slots, ok := o.storage[address]
	if !ok {
		slots = make(map[binary.Word256][]byte)
		o.storage[address] = slots
	}
	slots[key] = copyBytes(value)
	return nil
}

// commit merges this layer's writes into its parent overlay.
func (o *overlay) commit() {
	parent := o.parent.(*overlay)
	for addr, acc := range o.accounts {
		parent.accounts[addr] = acc
	}
	for addr, slots := range o.storage {
		for k, v := range slots {
			_ = parent.SetStorage(addr, k, v)
		}
	}
}

func (o *overlay) rwset() RWSet {
	var s RWSet
	for _, e := range o.reads {
		s.Reads = append(s.Reads, e)
	}
	for addr, acc := range o.accounts {
		s.Writes = append(s.Writes, accountEntry(addr, acc))
	}
	for addr, slots := range o.storage {
		for k, v := range slots {
			slot := k
			s.Writes = append(s.Writes, Entry{Address: addr, Slot: &slot, Value: storageValue(v)})
		}
	}
	sort.Slice(s.Reads, func(i, j int) bool { return s.Reads[i].less(s.Reads[j]) })
	sort.Slice(s.Writes, func(i, j int) bool { return s.Writes[i].less(s.Writes[j]) })
	return s
}

func accountEntry(address crypto.Address, acc *acm.Account) Entry {
	if acc == nil {
		return Entry{Address: address}
	}
	enc, err := acc.Marshal()
	if err != nil {
		// Marshal of a well-formed in-memory account cannot fail.
		panic(fmt.Sprintf("encoding account %v: %v", address, err))
	}
	return Entry{Address: address, Value: enc, Account: acc.Copy()}
}

// storageValue normalises a storage value: zero or empty means absent.
func storageValue(v []byte) []byte {
	for _, b := range v {
		if b != 0 {
			return binary.LeftPadBytes(v, binary.Word256Bytes)
		}
	}
	return nil
}

func copyBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	return append([]byte{}, b...)
}
