// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"math"
	"math/big"
	"testing"

	"github.com/hyperledger/burrow/execution/errors"
)

func newMemory() (*dynamicMemory, *errors.Maybe) {
	maybe := new(errors.Maybe)
	return NewDynamicMemory(defaultInitialMemoryCapacity, defaultMaximumMemoryCapacity, maybe).(*dynamicMemory), maybe
}

// TestMemoryOffsetOverflowIsAnError: offset + length past 2^64 must be an
// error, not a slice panic.
func TestMemoryOffsetOverflowIsAnError(t *testing.T) {
	maxOffset := new(big.Int).SetUint64(math.MaxUint64)
	t.Run("read", func(t *testing.T) {
		mem, maybe := newMemory()
		if out := mem.Read(maxOffset, big.NewInt(4)); out != nil {
			t.Fatalf("Read = %x, want nil", out)
		}
		if maybe.Error() == nil {
			t.Fatal("no error for overflowing read")
		}
	})
	t.Run("write", func(t *testing.T) {
		mem, maybe := newMemory()
		mem.Write(maxOffset, []byte{1, 2})
		if maybe.Error() == nil {
			t.Fatal("no error for overflowing write")
		}
	})
}

// TestMemoryZeroLengthAccessDoesNotExpand: as on Ethereum, touching zero bytes
// at any offset is valid and leaves memory size unchanged.
func TestMemoryZeroLengthAccessDoesNotExpand(t *testing.T) {
	mem, maybe := newMemory()
	huge := new(big.Int).Lsh(big.NewInt(1), 62)
	if out := mem.Read(huge, big.NewInt(0)); len(out) != 0 {
		t.Fatalf("Read = %x, want empty", out)
	}
	mem.Write(huge, nil)
	if err := maybe.Error(); err != nil {
		t.Fatalf("zero-length access errored: %v", err)
	}
	if got := mem.Capacity().Int64(); got != 0 {
		t.Fatalf("Capacity = %d, want 0", got)
	}
}

// TestMemorySizeIsInWords: memory starts empty and grows in 32-byte words, so
// MSIZE is always a multiple of 32.
func TestMemorySizeIsInWords(t *testing.T) {
	mem, maybe := newMemory()
	if got := mem.Capacity().Int64(); got != 0 {
		t.Fatalf("initial Capacity = %d, want 0", got)
	}
	mem.Write(big.NewInt(0), []byte{1})
	if got := mem.Capacity().Int64(); got != 32 {
		t.Fatalf("after one byte at 0: Capacity = %d, want 32", got)
	}
	mem.Read(big.NewInt(33), big.NewInt(1))
	if got := mem.Capacity().Int64(); got != 64 {
		t.Fatalf("after reading byte 33: Capacity = %d, want 64", got)
	}
	if err := maybe.Error(); err != nil {
		t.Fatal(err)
	}
}
