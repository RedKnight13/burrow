// SPDX-License-Identifier: Apache-2.0

package fabricx

import (
	"context"
	"fmt"
)

// Status is the application outcome of an endorsement. It is not a transport error.
type Status int32

const (
	StatusUnspecified Status = 0
	StatusSuccess     Status = 1
	StatusReverted    Status = 2
	StatusExecFailed  Status = 3
	StatusRejected    Status = 4
)

// ExecuteRequest is what a Fabric-X gateway sends to an external endorser.
// EthereumTx is the marshaled Ethereum transaction. Empty is invalid.
type ExecuteRequest struct {
	EthereumTx []byte
	Timestamp  int64
}

// ExecuteResponse carries the application outcome. A rejected transaction is
// reported here so the gateway can keep geth as the default and treat this
// process as optional.
type ExecuteResponse struct {
	ReadWriteSet []byte
	Status       Status
	Message      string
}

// Executor runs a transaction and returns a deterministic read-write set.
// The EVM implementation is not this package.
type Executor interface {
	Execute(ctx context.Context, ethereumTx []byte, timestamp int64) (readWriteSet []byte, err error)
}

// Endorser is the Apache-2.0 process a Fabric-X gateway can select.
type Endorser struct {
	exec Executor
}

// NewEndorser returns an endorser. exec may be nil until a transaction needs it.
func NewEndorser(exec Executor) *Endorser {
	return &Endorser{exec: exec}
}

// Execute endorses one transaction. An empty transaction is rejected here.
func (e *Endorser) Execute(ctx context.Context, req *ExecuteRequest) (*ExecuteResponse, error) {
	if req == nil || len(req.EthereumTx) == 0 {
		return &ExecuteResponse{
			Status:  StatusRejected,
			Message: "ethereum transaction is empty",
		}, nil
	}
	if e.exec == nil {
		return nil, fmt.Errorf("execute ethereum transaction: no executor")
	}
	set, err := e.exec.Execute(ctx, req.EthereumTx, req.Timestamp)
	if err != nil {
		return nil, fmt.Errorf("execute ethereum transaction: %w", err)
	}
	return &ExecuteResponse{
		ReadWriteSet: set,
		Status:       StatusSuccess,
	}, nil
}
