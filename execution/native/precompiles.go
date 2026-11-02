package native

import (
	cryptoSha256 "crypto/sha256"
	"fmt"
	"math/big"

	"github.com/hyperledger/burrow/execution/engine"

	"github.com/btcsuite/btcd/btcec"

	"github.com/hyperledger/burrow/binary"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/permission"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"
)

var Precompiles = New().
	MustFunction(`Recover public key/address of account that signed the data`,
		leftPadAddress(1),
		permission.None,
		ecrecover).
	MustFunction(`Compute the sha256 hash of input`,
		leftPadAddress(2),
		permission.None,
		sha256).
	MustFunction(`Compute the ripemd160 hash of input`,
		leftPadAddress(3),
		permission.None,
		ripemd160Func).
	MustFunction(`Return an output identical to the input`,
		leftPadAddress(4),
		permission.None,
		identity).
	MustFunction(`Compute the operation base**exp % mod where the values are big ints`,
		leftPadAddress(5),
		permission.None,
		expMod).
	MustFunction(`Compute the keccak256 hash of input`,
		leftPadAddress(20),
		permission.None,
		keccak256Func)

func leftPadAddress(bs ...byte) crypto.Address {
	return crypto.AddressFromWord256(binary.LeftPadWord256(bs))
}

// SECP256K1 Recovery, as specified in appendix E of the Ethereum Yellow Paper.
// The input is hash | v | r | s, 32 bytes each, right-padded with zeros when
// shorter; anything past 128 bytes is ignored. Invalid input (v not 27 or 28,
// r or s outside [1, n-1]) or a failed recovery returns empty output, not an
// error, so the calling contract can check the result.
func ecrecover(ctx Context) ([]byte, error) {
	// Deduct gas
	gasRequired := engine.GasEcRecover
	var err error = engine.UseGasNegative(ctx.Gas, gasRequired)
	if err != nil {
		return nil, err
	}

	input := make([]byte, 4*binary.Word256Bytes)
	copy(input, ctx.Input)
	hash := input[:32]
	v := new(big.Int).SetBytes(input[32:64])
	r := new(big.Int).SetBytes(input[64:96])
	s := new(big.Int).SetBytes(input[96:128])

	n := btcec.S256().N
	if !v.IsUint64() || (v.Uint64() != 27 && v.Uint64() != 28) ||
		r.Sign() == 0 || r.Cmp(n) >= 0 || s.Sign() == 0 || s.Cmp(n) >= 0 {
		return []byte{}, nil
	}

	// btcec's compact signature is [27 + recovery id | r | s].
	sig := make([]byte, 1+2*binary.Word256Bytes)
	sig[0] = byte(v.Uint64())
	copy(sig[1:], input[64:128])
	publicKey, _, err := btcec.RecoverCompact(btcec.S256(), sig, hash)
	if err != nil {
		return []byte{}, nil
	}

	// The address is the last 20 bytes of keccak256 of the uncompressed public
	// key without its 0x04 prefix.
	hashed := crypto.Keccak256(publicKey.SerializeUncompressed()[1:])
	hashed = hashed[len(hashed)-crypto.AddressLength:]
	return binary.LeftPadBytes(hashed, binary.Word256Bytes), nil
}

func sha256(ctx Context) (output []byte, err error) {
	// Deduct gas
	gasRequired := wordsIn(uint64(len(ctx.Input)))*engine.GasSha256Word + engine.GasSha256Base
	err = engine.UseGasNegative(ctx.Gas, gasRequired)
	if err != nil {
		return nil, err
	}
	// Hash
	hasher := cryptoSha256.New()
	// CONTRACT: this does not err
	hasher.Write(ctx.Input)
	return hasher.Sum(nil), nil
}

func ripemd160Func(ctx Context) (output []byte, err error) {
	// Deduct gas
	gasRequired := wordsIn(uint64(len(ctx.Input)))*engine.GasRipemd160Word + engine.GasRipemd160Base
	err = engine.UseGasNegative(ctx.Gas, gasRequired)
	if err != nil {
		return nil, err
	}
	// Hash
	hasher := ripemd160.New()
	// CONTRACT: this does not err
	hasher.Write(ctx.Input)
	return binary.LeftPadBytes(hasher.Sum(nil), 32), nil
}

func keccak256Func(ctx Context) (output []byte, err error) {
	// Deduct gas
	gasRequired := wordsIn(uint64(len(ctx.Input)))*engine.GasRipemd160Word + engine.GasRipemd160Base
	err = engine.UseGasNegative(ctx.Gas, gasRequired)
	if err != nil {
		return nil, err
	}
	// Hash
	hasher := sha3.NewLegacyKeccak256()
	// CONTRACT: this does not err
	hasher.Write(ctx.Input)
	return binary.LeftPadBytes(hasher.Sum(nil), 32), nil
}

func identity(ctx Context) (output []byte, err error) {
	// Deduct gas
	gasRequired := wordsIn(uint64(len(ctx.Input)))*engine.GasIdentityWord + engine.GasIdentityBase
	err = engine.UseGasNegative(ctx.Gas, gasRequired)
	if err != nil {
		return nil, err
	}
	// Return identity
	return ctx.Input, nil
}

// expMod: function that implements the EIP 198 (https://github.com/ethereum/EIPs/blob/master/EIPS/eip-198.md with
// a fixed gas requirement)
func expMod(ctx Context) (output []byte, err error) {
	const errHeader = "expMod"

	input, segments, err := cut(ctx.Input, binary.Word256Bytes, binary.Word256Bytes, binary.Word256Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", errHeader, err)
	}

	// get the lengths of base, exp and mod
	baseLength := getUint64(segments[0])
	expLength := getUint64(segments[1])
	modLength := getUint64(segments[2])

	// TODO: implement non-trivial gas schedule for this operation. Probably a parameterised version of the one
	// described in EIP though that one seems like a bit of a complicated fudge
	gasRequired := engine.GasExpModBase + engine.GasExpModWord*(wordsIn(baseLength)*wordsIn(expLength)*wordsIn(modLength))

	err = engine.UseGasNegative(ctx.Gas, gasRequired)
	if err != nil {
		return nil, err
	}

	input, segments, err = cut(input, baseLength, expLength, modLength)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", errHeader, err)
	}

	// get the values of base, exp and mod
	base := getBigInt(segments[0], baseLength)
	exp := getBigInt(segments[1], expLength)
	mod := getBigInt(segments[2], modLength)

	// handle mod 0
	if mod.Sign() == 0 {
		return binary.LeftPadBytes([]byte{}, int(modLength)), nil
	}

	// return base**exp % mod left padded
	return binary.LeftPadBytes(new(big.Int).Exp(base, exp, mod).Bytes(), int(modLength)), nil
}

// Partition the head of input into segments for each length in lengths. The first return value is the unconsumed tail
// of input and the seconds is the segments. Returns an error if input is of insufficient length to establish each segment.
func cut(input []byte, lengths ...uint64) ([]byte, [][]byte, error) {
	segments := make([][]byte, len(lengths))
	for i, length := range lengths {
		if uint64(len(input)) < length {
			return nil, nil, fmt.Errorf("input is not long enough")
		}
		segments[i] = input[:length]
		input = input[length:]
	}
	return input, segments, nil
}

func getBigInt(bs []byte, numBytes uint64) *big.Int {
	bits := uint(numBytes) * 8
	// Push bytes into big.Int and interpret as twos complement encoding with of bits width
	return binary.FromTwosComplement(new(big.Int).SetBytes(bs), bits)
}

func getUint64(bs []byte) uint64 {
	return binary.Uint64FromWord256(binary.LeftPadWord256(bs))
}

func wordsIn(numBytes uint64) uint64 {
	return numBytes + binary.Word256Bytes - 1/binary.Word256Bytes
}
