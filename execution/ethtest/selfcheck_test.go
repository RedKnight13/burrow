// SPDX-License-Identifier: Apache-2.0

package ethtest

import (
	"os"
	"testing"
)

// fixturesDir is where tests/scripts/fetch_eth_fixtures.sh unpacks the
// release, unless ETHTEST_FIXTURES says otherwise.
func fixturesDir() string {
	if dir := os.Getenv("ETHTEST_FIXTURES"); dir != "" {
		return dir
	}
	return "../../tests/ethereum/fixtures"
}

// TestBlockchainGenesisRoots proves the trie, RLP and Burrow state read-back
// against every blockchain fixture's genesis state root. cmd/ethtest -check
// runs the same check and fails instead of skipping when fixtures are absent.
func TestBlockchainGenesisRoots(t *testing.T) {
	dir := fixturesDir()
	if _, err := os.Stat(dir); err != nil {
		t.Skip("FIXTURES NOT DOWNLOADED: run tests/scripts/fetch_eth_fixtures.sh")
	}
	res, err := CheckGenesisRoots(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("genesis roots: checked %d, matched %d, burrow path matched %d, burrow path unsupported %d, mismatched %d",
		res.Checked, res.Matched, res.BurrowMatched, res.BurrowUnsupported, res.Mismatched)
	for _, m := range res.Mismatches {
		t.Error(m)
	}
	if !res.OK() {
		t.Fatal("genesis root self-check failed")
	}
}
