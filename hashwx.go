package gocap

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"strconv"

	"github.com/gomodb/gocap/internal/hashwx"
)

// HashWX constants mirror capjs-core's hashwx.js.
const (
	// HashwxSeedSize is the size of the seed passed to hashwx_make.
	HashwxSeedSize = 32
	// HashwxChallengeSize is the size of the random challenge value.
	HashwxChallengeSize = 32
	// DefaultHashwxNoncesPerHash is the default number of nonces covered by
	// each generated HashWX hash function.
	DefaultHashwxNoncesPerHash = defaultHashwxNoncesPerHash
	// DefaultHashwxDifficulty is the default expected number of hashes per
	// solve, across all sub-challenges.
	DefaultHashwxDifficulty = defaultHashwxDifficulty
	// DefaultHashwxChallengeCount is the default number of independent
	// HashWX sub-challenges.
	DefaultHashwxChallengeCount = defaultHashwxChallengeCount
	// MaxHashwxDifficulty is the largest accepted HashWX difficulty.
	MaxHashwxDifficulty = maxHashwxDifficulty
	// MaxHashwxNoncesPerHash is the largest accepted nonces-per-hash value.
	MaxHashwxNoncesPerHash = maxHashwxNoncesPerHash
	// MaxHashwxChallengeCount is the largest accepted sub-challenge count.
	MaxHashwxChallengeCount = maxHashwxChallengeCount
)

// HashwxTarget returns the largest 64-bit hash accepted at the given
// difficulty: floor((2^64 - 1) / difficulty).
func HashwxTarget(difficulty int64) (uint64, error) {
	if difficulty <= 0 {
		return 0, errors.New("hashwx difficulty must be positive")
	}

	return ^uint64(0) / uint64(difficulty), nil
}

// HashwxSeed derives the seed for one generated HashWX function:
// sha256(challenge || u64le(block)). Each block covers HashwxNoncesPerHash
// consecutive nonces.
func HashwxSeed(challenge []byte, block uint64) [32]byte {
	var buf [HashwxChallengeSize + 8]byte

	copy(buf[:HashwxChallengeSize], challenge)
	binary.LittleEndian.PutUint64(buf[HashwxChallengeSize:], block)

	return sha256.Sum256(buf[:])
}

// HashwxHash runs the HashWX function generated from seed over nonce.
func HashwxHash(seed [32]byte, nonce uint64) (uint64, error) {
	return hashwx.Hash(seed, nonce)
}

// HashwxReady compiles and initializes the embedded HashWX module. Call it at
// boot to move the initialization cost off the first verification request.
func HashwxReady() error {
	return hashwx.Ready()
}

// parseHashwxNonce mirrors parseNonce in capjs-core's hashwx.js. Only
// non-negative safe numbers and decimal strings are accepted.
func parseHashwxNonce(v any) (uint64, bool) {
	if f, ok := v.(float64); ok {
		if math.IsNaN(f) || math.IsInf(f, 0) || f < 0 ||
			f > 9007199254740991 || math.Trunc(f) != f {
			return 0, false
		}

		return uint64(f), true
	}

	if f, ok := v.(float32); ok {
		return parseHashwxNonce(float64(f))
	}

	s, ok := jsValueString(v)
	if !ok || len(s) == 0 || len(s) > 20 {
		return 0, false
	}

	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
	}

	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, false
	}

	return n, true
}

// validateV2Hashwx verifies one HashWX sub-challenge solution.
func validateV2Hashwx(e v2ExpectedEntry, s V2Solution) ValidateResult {
	challenge, err := hex.DecodeString(e.C)
	if err != nil || len(challenge) != HashwxChallengeSize {
		return res(ErrInvalidSolution)
	}

	if e.D < 1 || e.D > maxHashwxDifficulty {
		return res(ErrInvalidSolution)
	}

	if e.N < 1 || e.N > maxHashwxNoncesPerHash {
		return res(ErrInvalidSolution)
	}

	nonce, ok := parseHashwxNonce(s.Nonce)
	if !ok {
		return res(ErrInvalidSolution)
	}

	target, err := HashwxTarget(int64(e.D))
	if err != nil {
		return res(ErrInvalidSolution)
	}

	seed := HashwxSeed(challenge, nonce/uint64(e.N))

	hash, err := HashwxHash(seed, nonce)
	if err != nil {
		return ValidateResult{
			Success:  false,
			Reason:   ErrHashwxUnavailable.Error(),
			ErrorStr: err.Error(),
			err:      ErrHashwxUnavailable,
		}
	}

	if hash > target {
		return res(ErrInvalidSolution)
	}

	return ValidateResult{Success: true}
}
