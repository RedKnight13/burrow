// SPDX-License-Identifier: Apache-2.0

package fabricx

import (
	"context"
	"fmt"
	"net"

	"google.golang.org/grpc"
)

// ExecuteMethod is the gRPC method a Fabric-X gateway calls.
const ExecuteMethod = "/endorsementpb.EvmEndorsement/Execute"

// ListenGRPC serves Execute until ctx is cancelled. The returned address is
// the bound host:port, which may differ from addr when addr uses port 0.
func ListenGRPC(ctx context.Context, addr string, e *Endorser) (string, error) {
	if e == nil {
		return "", fmt.Errorf("listen grpc: nil endorser")
	}
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return "", fmt.Errorf("listen grpc: %w", err)
	}
	srv := grpc.NewServer(grpc.CustomCodec(wireCodec{}))
	RegisterEndorsement(srv, e)
	go func() {
		<-ctx.Done()
		srv.Stop()
		_ = lis.Close()
	}()
	go func() {
		_ = srv.Serve(lis)
	}()
	return lis.Addr().String(), nil
}

type wireCodec struct{}

func (wireCodec) Marshal(v interface{}) ([]byte, error) {
	switch m := v.(type) {
	case *ExecuteRequest:
		return marshalExecuteRequest(m)
	case *ExecuteResponse:
		return MarshalExecuteResponse(m)
	default:
		return nil, fmt.Errorf("wire codec: unsupported %T", v)
	}
}

func (wireCodec) Unmarshal(data []byte, v interface{}) error {
	switch m := v.(type) {
	case *ExecuteRequest:
		got, err := unmarshalExecuteRequest(data)
		if err != nil {
			return err
		}
		*m = *got
		return nil
	case *ExecuteResponse:
		got, err := UnmarshalExecuteResponse(data)
		if err != nil {
			return err
		}
		*m = *got
		return nil
	default:
		return fmt.Errorf("wire codec: unsupported %T", v)
	}
}

func (wireCodec) String() string { return "proto" }

// RegisterEndorsement exposes Execute on srv. The bytes are protobuf field
// numbers a Fabric-X gateway already sends. geth is not linked.
type endorsementService interface {
	Execute(ctx context.Context, req *ExecuteRequest) (*ExecuteResponse, error)
}

func RegisterEndorsement(srv *grpc.Server, e *Endorser) {
	srv.RegisterService(&grpc.ServiceDesc{
		ServiceName: "endorsementpb.EvmEndorsement",
		HandlerType: (*endorsementService)(nil),
		Methods: []grpc.MethodDesc{{
			MethodName: "Execute",
			Handler:    executeHandler,
		}},
		Metadata: "fabricx/endorsement.proto",
	}, e)
}

func executeHandler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := &ExecuteRequest{}
	if err := dec(in); err != nil {
		return nil, err
	}
	e, ok := srv.(*Endorser)
	if !ok || e == nil {
		return nil, fmt.Errorf("execute: endorser is not registered")
	}
	if interceptor == nil {
		return e.Execute(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ExecuteMethod,
	}
	return interceptor(ctx, in, info, func(ctx context.Context, req interface{}) (interface{}, error) {
		return e.Execute(ctx, req.(*ExecuteRequest))
	})
}

// InvokeExecute calls Execute on a connection that uses wireCodec.
func InvokeExecute(ctx context.Context, conn *grpc.ClientConn, req *ExecuteRequest) (*ExecuteResponse, error) {
	out := &ExecuteResponse{}
	if err := conn.Invoke(ctx, ExecuteMethod, req, out); err != nil {
		return nil, fmt.Errorf("invoke execute: %w", err)
	}
	return out, nil
}
