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

// SECP256K1 Recovery
func ecrecover(ctx Context) ([]byte, error) {
	// Deduct gas
	gasRequired := engine.GasEcRecover
	var err error = engine.UseGasNegative(ctx.Gas, gasRequired)
	if err != nil {
		return nil, err
	}

	// layout is:
	// input:  [ hash |  v   |  r   |  s   ]
	// bytes:  [ 32   |  32  |  32  |  32  ]
	// Where:
	//   hash = message digest
	//   v = 27 + recovery id (which of 4 possible x coords do we take as public key) (single byte but padded)
	//   r = encrypted random point
	//   s = signature proof

	// Signature layout required by ethereum:
	// sig:    [  r   |  s   |  v  ]
	// bytes:  [  32  |  32  |  1  ]
	hash := ctx.Input[:32]

	const compactSigLength = 2*binary.Word256Bytes + 1
	sig := make([]byte, compactSigLength)
	// Copy in r, s
	copy(sig, ctx.Input[2*binary.Word256Bytes:4*binary.Word256Bytes])
	// Check v is single byte
	v := ctx.Input[binary.Word256Bytes : 2*binary.Word256Bytes]
	if !binary.IsZeros(v[:len(v)-1]) {
		return nil, fmt.Errorf("ecrecover: recovery ID is larger than one byte")
	}
	// Copy in v to last element of sig
	sig[2*binary.Word256Bytes] = v[len(v)-1]

	publicKey, isCompressed, err := btcec.RecoverCompact(btcec.S256(), sig, hash)
	if err != nil {
		return nil, err
	}

	var serializedPublicKey []byte
	if isCompressed {
		serializedPublicKey = publicKey.SerializeCompressed()
	} else {
		serializedPublicKey = publicKey.SerializeUncompressed()
	}
	// First byte is a length-prefix
	hashed := crypto.Keccak256(serializedPublicKey[1:])
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
// maxModexpLength bounds each of the base, exponent and modulus lengths, as
// EIP-7823 does on Ethereum. Burrow's flat gas cost cannot bound the work or
// memory of larger operands.
const maxModexpLength = 1024

// expMod computes base**exp % mod as specified by EIP-198. The input is three
// 32-byte big-endian lengths followed by base, exponent and modulus, all
// unsigned big-endian and right-padded with zeros when the input is short. The
// output is the result left-padded to the modulus length; a zero modulus gives
// zero.
func expMod(ctx Context) (output []byte, err error) {
	const errHeader = "expMod"

	lengths := padRight(ctx.Input, 3*binary.Word256Bytes)
	var lens [3]uint64
	for i := range lens {
		n := new(big.Int).SetBytes(lengths[i*binary.Word256Bytes : (i+1)*binary.Word256Bytes])
		if !n.IsUint64() || n.Uint64() > maxModexpLength {
			return nil, fmt.Errorf("%s: operand length %v exceeds %d bytes", errHeader, n, maxModexpLength)
		}
		lens[i] = n.Uint64()
	}
	baseLength, expLength, modLength := lens[0], lens[1], lens[2]

	// TODO: implement non-trivial gas schedule for this operation. Probably a parameterised version of the one
	// described in EIP though that one seems like a bit of a complicated fudge
	gasRequired := engine.GasExpModBase + engine.GasExpModWord*(wordsIn(baseLength)*wordsIn(expLength)*wordsIn(modLength))

	err = engine.UseGasNegative(ctx.Gas, gasRequired)
	if err != nil {
		return nil, err
	}

	var operands []byte
	if len(ctx.Input) > 3*binary.Word256Bytes {
		operands = ctx.Input[3*binary.Word256Bytes:]
	}
	operands = padRight(operands, int(baseLength+expLength+modLength))
	base := new(big.Int).SetBytes(operands[:baseLength])
	exp := new(big.Int).SetBytes(operands[baseLength : baseLength+expLength])
	mod := new(big.Int).SetBytes(operands[baseLength+expLength : baseLength+expLength+modLength])

	if mod.Sign() == 0 {
		return make([]byte, modLength), nil
	}
	return binary.LeftPadBytes(new(big.Int).Exp(base, exp, mod).Bytes(), int(modLength)), nil
}

// padRight returns b extended with zeros to at least n bytes, without
// modifying b.
func padRight(b []byte, n int) []byte {
	if len(b) >= n {
		return b
	}
	out := make([]byte, n)
	copy(out, b)
	return out
}

func wordsIn(numBytes uint64) uint64 {
	return numBytes + binary.Word256Bytes - 1/binary.Word256Bytes
}
