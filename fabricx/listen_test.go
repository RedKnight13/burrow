// SPDX-License-Identifier: Apache-2.0

package fabricx

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestListenerRejectsEmptyTransaction(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, ln, NewEndorser(nil))
	}()

	callCtx, callCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer callCancel()
	resp, err := Call(callCtx, ln.Addr().String(), &ExecuteRequest{})
	cancel()
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if resp.Status != StatusRejected {
		t.Fatalf("status = %d, want %d", resp.Status, StatusRejected)
	}
	if resp.Message == "" {
		t.Fatal("rejection message is empty")
	}
	select {
	case err := <-done:
		if err != nil && ctx.Err() == nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after cancel")
	}
}
