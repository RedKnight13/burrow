// SPDX-License-Identifier: Apache-2.0

package ethtest

import (
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/execution/evm/rlp"
	"github.com/hyperledger/burrow/execution/exec"
)

// LogsHash is keccak256(rlp(logs)), each log encoded as [address, topics, data].
func LogsHash(logs []*exec.LogEvent) [32]byte {
	items := make([]rlp.Item, 0, len(logs))
	for _, l := range logs {
		topics := make([]rlp.Item, 0, len(l.Topics))
		for _, topic := range l.Topics {
			topics = append(topics, topic.Bytes())
		}
		items = append(items, []rlp.Item{l.Address.Bytes(), topics, []byte(l.Data)})
	}
	var h [32]byte
	copy(h[:], crypto.Keccak256(rlp.Encode(items)))
	return h
}
