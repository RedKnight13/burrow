// SPDX-License-Identifier: Apache-2.0

package fabricx

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc"
)

func TestListenGRPCRejectsEmptyTransaction(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr, err := ListenGRPC(ctx, "127.0.0.1:0", NewEndorser(nil))
	if err != nil {
		t.Fatalf("ListenGRPC: %v", err)
	}

	callCtx, callCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer callCancel()
	conn, err := grpc.DialContext(callCtx, addr,
		grpc.WithInsecure(),
		grpc.WithBlock(),
		grpc.WithDefaultCallOptions(grpc.CallCustomCodec(wireCodec{})),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	resp, err := InvokeExecute(callCtx, conn, &ExecuteRequest{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if resp.Status != StatusRejected {
		t.Fatalf("status = %d, want %d", resp.Status, StatusRejected)
	}
}
