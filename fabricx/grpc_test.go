// SPDX-License-Identifier: Apache-2.0

package fabricx

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
)

func TestGRPCExecuteRejectsEmptyTransaction(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer(grpc.CustomCodec(wireCodec{}))
	RegisterEndorsement(srv, NewEndorser(nil))
	go func() {
		_ = srv.Serve(lis)
	}()
	defer srv.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, lis.Addr().String(),
		grpc.WithInsecure(),
		grpc.WithBlock(),
		grpc.WithDefaultCallOptions(grpc.CallCustomCodec(wireCodec{})),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	resp, err := InvokeExecute(ctx, conn, &ExecuteRequest{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if resp.Status != StatusRejected {
		t.Fatalf("status = %d, want %d", resp.Status, StatusRejected)
	}
	if resp.Message == "" {
		t.Fatal("rejection message is empty")
	}
}
