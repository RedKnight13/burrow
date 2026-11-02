// SPDX-License-Identifier: Apache-2.0

package fabricx

import (
	"bytes"
	"context"
	"testing"
)

func TestExecuteRejectsEmptyTransaction(t *testing.T) {
	e := NewEndorser(nil)
	resp, err := e.Execute(context.Background(), &ExecuteRequest{})
	if err != nil {
		t.Fatalf("empty transaction must be an application rejection, not a transport error: %v", err)
	}
	if resp.Status != StatusRejected {
		t.Fatalf("status = %d, want %d", resp.Status, StatusRejected)
	}
	if resp.Message == "" {
		t.Fatal("rejection message is empty")
	}
}

type fixedExecutor struct {
	set []byte
}

func (f fixedExecutor) Execute(context.Context, []byte, int64) ([]byte, error) {
	return f.set, nil
}

func TestExecuteRequiresExecutor(t *testing.T) {
	e := NewEndorser(nil)
	_, err := e.Execute(context.Background(), &ExecuteRequest{EthereumTx: []byte{1}})
	if err == nil {
		t.Fatal("missing executor returned no error")
	}
}

func TestExecuteRepeatsReadWriteSet(t *testing.T) {
	want := []byte{1, 2, 3}
	e := NewEndorser(fixedExecutor{set: want})
	req := &ExecuteRequest{EthereumTx: []byte{9}, Timestamp: 11}

	first, err := e.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	second, err := e.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("Execute again: %v", err)
	}
	if first.Status != StatusSuccess || second.Status != StatusSuccess {
		t.Fatalf("status = %d and %d, want %d", first.Status, second.Status, StatusSuccess)
	}
	if !bytes.Equal(first.ReadWriteSet, want) || !bytes.Equal(second.ReadWriteSet, want) {
		t.Fatalf("read-write sets = %x and %x, want %x", first.ReadWriteSet, second.ReadWriteSet, want)
	}
}
