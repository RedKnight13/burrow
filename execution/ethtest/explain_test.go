// SPDX-License-Identifier: Apache-2.0

package ethtest

import (
	"math/big"
	"strings"
	"testing"

	"github.com/hyperledger/burrow/execution/ethtest/fixture"
)

func TestExplainShowsDifferingField(t *testing.T) {
	st := stopCase(t)
	post := fixture.Alloc{}
	for k, v := range st.Pre {
		post[k] = v
	}
	sender := post[senderAddr]
	sender.Nonce = fixture.Quantity{Int: big.NewInt(1)} // Ethereum bumps the nonce; the harness does not
	post[senderAddr] = sender
	st.Post["Cancun"][0].State = post
	st.Post["Cancun"][0].Hash[0] ^= 0xff

	out := Explain("x", st, "Cancun", 0)
	if !strings.Contains(out, "fail root") {
		t.Fatalf("result line missing:\n%s", out)
	}
	if !strings.Contains(out, strings.TrimPrefix(senderAddr, "0x")) || !strings.Contains(out, "nonce: want 1, got 0") {
		t.Fatalf("nonce diff missing:\n%s", out)
	}
	if strings.Contains(out, strings.TrimPrefix(contractAddr, "0x")) {
		t.Fatalf("unchanged account reported:\n%s", out)
	}
}
