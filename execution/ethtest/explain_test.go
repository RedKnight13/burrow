// SPDX-License-Identifier: Apache-2.0

package ethtest

import (
	"math/big"
	"strings"
	"testing"

	"github.com/hyperledger/burrow/execution/ethtest/fixture"
)

func TestExplainShowsDifferingField(t *testing.T) {
	st := signedCase(t, "0x00")
	setExpected(t, &st, func(post fixture.Alloc) {
		sender := post[senderAddr]
		sender.Nonce = fixture.Quantity{Int: big.NewInt(2)} // Burrow will produce 1
		post[senderAddr] = sender
	})

	out := Explain("x", st, "Cancun", 0)
	if !strings.Contains(out, "fail root") {
		t.Fatalf("result line missing:\n%s", out)
	}
	if !strings.Contains(out, strings.TrimPrefix(senderAddr, "0x")) || !strings.Contains(out, "nonce: want 2, got 1") {
		t.Fatalf("nonce diff missing:\n%s", out)
	}
	if strings.Contains(out, strings.TrimPrefix(contractAddr, "0x")) {
		t.Fatalf("unchanged account reported:\n%s", out)
	}
}
