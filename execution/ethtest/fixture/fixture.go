// SPDX-License-Identifier: Apache-2.0

// Package fixture reads the state_test and blockchain_test JSON formats
// published by ethereum/execution-specs.
package fixture

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Account is a pre- or post-state account. Storage keys are hex strings;
// use ParseWord to turn them into slots.
type Account struct {
	Nonce   Quantity            `json:"nonce"`
	Balance Quantity            `json:"balance"`
	Code    Bytes               `json:"code"`
	Storage map[string]Quantity `json:"storage"`
}

// Alloc maps a hex address to its account.
type Alloc map[string]Account

type Env struct {
	Coinbase   string   `json:"currentCoinbase"`
	GasLimit   Quantity `json:"currentGasLimit"`
	Number     Quantity `json:"currentNumber"`
	Timestamp  Quantity `json:"currentTimestamp"`
	Difficulty Quantity `json:"currentDifficulty"`
	Random     Bytes    `json:"currentRandom"`
	BaseFee    Quantity `json:"currentBaseFee"`
}

type Transaction struct {
	Data                []Bytes         `json:"data"`
	GasLimit            []Quantity      `json:"gasLimit"`
	Value               []Quantity      `json:"value"`
	To                  string          `json:"to"`
	Sender              string          `json:"sender"`
	SecretKey           Bytes           `json:"secretKey"`
	Nonce               Quantity        `json:"nonce"`
	GasPrice            Quantity        `json:"gasPrice"`
	AccessLists         json.RawMessage `json:"accessLists"`
	BlobVersionedHashes json.RawMessage `json:"blobVersionedHashes"`
	AuthorizationList   json.RawMessage `json:"authorizationList"`
}

type Indexes struct {
	Data  int `json:"data"`
	Gas   int `json:"gas"`
	Value int `json:"value"`
}

type PostEntry struct {
	Hash            Bytes   `json:"hash"`
	Logs            Bytes   `json:"logs"`
	Indexes         Indexes `json:"indexes"`
	TxBytes         Bytes   `json:"txbytes"`
	ExpectException string  `json:"expectException"`
	State           Alloc   `json:"state"`
}

// Config carries chain parameters; only the chain ID is used.
type Config struct {
	ChainID Quantity `json:"chainid"`
}

type StateTest struct {
	Env         Env                    `json:"env"`
	Pre         Alloc                  `json:"pre"`
	Transaction Transaction            `json:"transaction"`
	Post        map[string][]PostEntry `json:"post"`
	Config      Config                 `json:"config"`
}

type GenesisHeader struct {
	StateRoot Bytes `json:"stateRoot"`
}

type BlockchainTest struct {
	Network string        `json:"network"`
	Pre     Alloc         `json:"pre"`
	Genesis GenesisHeader `json:"genesisBlockHeader"`
}

func LoadStateTests(path string) (map[string]StateTest, error) {
	tests := make(map[string]StateTest)
	if err := load(path, &tests); err != nil {
		return nil, err
	}
	return tests, nil
}

func LoadBlockchainTests(path string) (map[string]BlockchainTest, error) {
	tests := make(map[string]BlockchainTest)
	if err := load(path, &tests); err != nil {
		return nil, err
	}
	return tests, nil
}

func load(path string, v interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading fixture: %w", err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("parsing fixture %s: %w", path, err)
	}
	return nil
}

// Walk calls fn for every .json file under root/kind, in sorted path order.
// kind is "state_tests" or "blockchain_tests".
func Walk(root, kind string, fn func(path string) error) error {
	dir := filepath.Join(root, kind)
	var paths []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".json") {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("walking %s: %w", dir, err)
	}
	sort.Strings(paths)
	for _, p := range paths {
		if err := fn(p); err != nil {
			return err
		}
	}
	return nil
}
