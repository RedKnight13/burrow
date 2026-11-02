package defaults

import (
	"github.com/hyperledger/burrow/execution/engine"
	"github.com/hyperledger/burrow/execution/native"
	"github.com/hyperledger/burrow/logging"
)

const (
	// MaxCallDepth is Ethereum's message-call depth limit.
	MaxCallDepth = 1024
	// MaxStackItems is the size of Ethereum's EVM stack.
	MaxStackItems = 1024
)

func CompleteOptions(options engine.Options) engine.Options {
	// Set defaults
	if options.MemoryProvider == nil {
		options.MemoryProvider = engine.DefaultDynamicMemoryProvider
	}
	if options.Logger == nil {
		options.Logger = logging.NewNoopLogger()
	}
	if options.Natives == nil {
		options.Natives = native.MustDefaultNatives()
	}
	// Ethereum's limits. Zero used to mean unlimited, which let one transaction
	// recurse until the Go runtime overflowed its stack and killed the node.
	if options.CallStackMaxDepth == 0 {
		options.CallStackMaxDepth = MaxCallDepth
	}
	if options.DataStackMaxDepth == 0 {
		options.DataStackMaxDepth = MaxStackItems
	}
	return options
}
