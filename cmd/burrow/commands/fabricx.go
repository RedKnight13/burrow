// SPDX-License-Identifier: Apache-2.0

package commands

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/hyperledger/burrow/fabricx"
	cli "github.com/jawher/mow.cli"
)

// Fabricx serves the external endorser. It does not start Tendermint and it
// does not execute contracts until an executor is configured.
func Fabricx(output Output) func(cmd *cli.Cmd) {
	return func(cmd *cli.Cmd) {
		listenOpt := cmd.StringOpt("l listen", "127.0.0.1:50051", "Address for the Fabric-X endorsement RPC")
		cmd.Spec = "[--listen=<address>]"
		cmd.Action = func() {
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			addr, err := fabricx.ListenGRPC(ctx, *listenOpt, fabricx.NewEndorser(nil))
			if err != nil {
				output.Fatalf("Could not start fabricx endorser: %v", err)
			}
			output.Logf("fabricx endorser listening on %s", addr)
			<-ctx.Done()
		}
	}
}
