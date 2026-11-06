package gocap

import (
	"context"
	"fmt"
	"math"
	"math/big"
	"strings"
	"time"
)

// generateChallengeWithContext creates a format-1 challenge.
func generateChallengeWithContext(
	ctx context.Context,
	secret []byte,
	opts GenerateOptions,
) (ChallengeResult, error) {
	if len(secret) < 16 {
		return ChallengeResult{}, ErrShortSecret
	}

	c, s, d, ttl, err := clampChallengeOptions(opts)
	if err != nil {
		return ChallengeResult{}, err
	}

	now := time.Now().UnixMilli()
	expires := now + ttl.Milliseconds()

	nonce, err := randomHex(25)
	if err != nil {
		return ChallengeResult{}, err
	}

	payload := map[string]any{
		"n":   nonce,
		"c":   c,
		"s":   s,
		"d":   d,
		"exp": expires,
		"iat": now,
	}
	if opts.Scope != "" {
		payload["sk"] = opts.Scope
	}

	if len(opts.Extra) > 0 {
		payload["x"] = opts.Extra
	}

	var instrBlob string

	if opts.Instrumentation {
		ei, blob, err := buildInstrumentation(opts, int64(ttl.Milliseconds()), expires, secret)
		if err != nil {
			return ChallengeResult{}, err
		}

		payload["ei"] = ei
		instrBlob = blob
	}

	token := jwtSign(payload, secret)

	if opts.Storage != nil {
		if err := opts.Storage.CleanupExpired(ctx); err != nil {
			return ChallengeResult{}, err
		}

		if err := opts.Storage.SetChallengeToken(ctx, token, time.UnixMilli(expires)); err != nil {
			return ChallengeResult{}, err
		}
	}

	return ChallengeResult{
		Challenge:       ChallengeSpec{C: c, S: s, D: d},
		Token:           token,
		Expires:         expires,
		Instrumentation: instrBlob,
	}, nil
}

// buildInstrumentation generates instrumentation params and encrypts the metadata.
func buildInstrumentation(
	opts GenerateOptions,
	ttlMs int64,
	expires int64,
	secret []byte,
) (string, string, error) {
	instrOpts := InstrumentationOptions{
		BlockAutomatedBrowsers: false,
		ObfuscationLevel:       3,
		TTLMs:                  ttlMs,
	}
	if opts.InstrumentationOpts != nil {
		instrOpts = *opts.InstrumentationOpts
	}

	// capjs-core always overrides ttlMs with the challenge lifetime.
	instrOpts.TTLMs = ttlMs

	generator := opts.InstrumentationGenerator
	if generator == nil {
		generator = GenerateInstrumentation
	}

	meta, blob, err := generator(instrOpts)
	if err != nil {
		return "", "", err
	}

	meta.Expires = expires

	ei, err := encodeInstrumentationMeta(meta, secret)
	if err != nil {
		return "", "", err
	}

	return ei, blob, nil
}

// generateChallengeV2 creates a format-2 multi-protocol challenge.
func generateChallengeV2(
	ctx context.Context,
	secret []byte,
	opts GenerateOptions,
) (ChallengeResult, error) {
	if len(secret) < 16 {
		return ChallengeResult{}, ErrShortSecret
	}

	protocols := opts.Protocols
	if len(protocols) == 0 {
		protocols = []string{"rsw"}
	}

	ttl := opts.Expires
	if ttl <= 0 {
		ttl = defaultChallengeTTL
	}

	now := time.Now().UnixMilli()
	exp := now + ttl.Milliseconds()

	challenges := make([]V2Challenge, 0, len(protocols))
	expected := make([]v2ExpectedEntry, 0, len(protocols))

	for _, proto := range protocols {
		var (
			chs        []V2Challenge
			expEntries []v2ExpectedEntry
			err        error
		)

		switch proto {
		case "sha256-pow":
			chs, expEntries, err = generateV2Sha256Pow(opts)
		case "rsw":
			chs, expEntries, err = generateV2Rsw(opts)
		case "hashwx":
			chs, expEntries, err = generateV2Hashwx(opts)
		case "instrumentation":
			chs, expEntries, err = generateV2Instrumentation(opts, int64(ttl.Milliseconds()), exp)
		default:
			return ChallengeResult{}, fmt.Errorf("unknown protocol %q", proto)
		}

		if err != nil {
			return ChallengeResult{}, err
		}

		challenges = append(challenges, chs...)
		expected = append(expected, expEntries...)
	}

	ev, err := encryptGcm(map[string]any{"expected": expected}, secret, "cap:fmt2-v1")
	if err != nil {
		return ChallengeResult{}, err
	}

	nonce, err := randomHex(16)
	if err != nil {
		return ChallengeResult{}, err
	}

	tokenPayload := map[string]any{
		"f":   2,
		"n":   nonce,
		"exp": exp,
		"iat": now,
		"ev":  ev,
	}
	if opts.Scope != "" {
		tokenPayload["sk"] = opts.Scope
	}

	if len(opts.Extra) > 0 {
		tokenPayload["x"] = opts.Extra
	}

	token := jwtSign(tokenPayload, secret)

	if opts.Storage != nil {
		if err := opts.Storage.CleanupExpired(ctx); err != nil {
			return ChallengeResult{}, err
		}

		if err := opts.Storage.SetChallengeToken(ctx, token, time.UnixMilli(exp)); err != nil {
			return ChallengeResult{}, err
		}
	}

	return ChallengeResult{
		Token:      token,
		Expires:    exp,
		Format:     2,
		Challenges: challenges,
	}, nil
}

func generateV2Sha256Pow(opts GenerateOptions) ([]V2Challenge, []v2ExpectedEntry, error) {
	c := opts.ChallengeCount
	if c == 0 {
		c = defaultChallengeCount
	}

	s := opts.ChallengeSize
	if s == 0 {
		s = defaultChallengeSize
	}

	d := opts.ChallengeDifficulty
	if d == 0 {
		d = defaultChallengeDifficulty
	}

	if c < 1 || c > maxChallengeCount || s < 1 || s > maxChallengeSize || d < 1 ||
		d > maxChallengeDifficulty {
		return nil, nil, fmt.Errorf("invalid sha256-pow params")
	}

	target := strings.Repeat("0", d)
	challenges := make([]V2Challenge, 0, c)

	expected := make([]v2ExpectedEntry, 0, c)
	for i := 0; i < c; i++ {
		salt, err := randomHex(s)
		if err != nil {
			return nil, nil, err
		}

		challenges = append(challenges, V2Challenge{
			Protocol: "sha256-pow",
			Payload:  map[string]any{"salt": salt, "target": target},
		})
		expected = append(expected, v2ExpectedEntry{
			Protocol: "sha256-pow",
			Salt:     salt,
			Target:   target,
		})
	}

	return challenges, expected, nil
}

func generateV2Hashwx(opts GenerateOptions) ([]V2Challenge, []v2ExpectedEntry, error) {
	difficulty := opts.HashwxDifficulty
	if difficulty == 0 {
		difficulty = defaultHashwxDifficulty
	}

	noncesPerHash := opts.HashwxNoncesPerHash
	if noncesPerHash == 0 {
		noncesPerHash = defaultHashwxNoncesPerHash
	}

	count := opts.HashwxChallengeCount
	if count == 0 {
		count = defaultHashwxChallengeCount
	}

	if difficulty < 1 || difficulty > maxHashwxDifficulty {
		return nil, nil, fmt.Errorf(
			"hashwxDifficulty must be an integer in [1, %d]",
			maxHashwxDifficulty,
		)
	}

	if noncesPerHash < 1 || noncesPerHash > maxHashwxNoncesPerHash {
		return nil, nil, fmt.Errorf(
			"hashwxNoncesPerHash must be an integer in [1, %d]",
			maxHashwxNoncesPerHash,
		)
	}

	if count < 1 || count > maxHashwxChallengeCount {
		return nil, nil, fmt.Errorf(
			"hashwxChallengeCount must be an integer in [1, %d]",
			maxHashwxChallengeCount,
		)
	}

	each := max(int(math.Round(float64(difficulty)/float64(count))), 1)

	challenges := make([]V2Challenge, 0, count)
	expected := make([]v2ExpectedEntry, 0, count)

	for range count {
		c, err := randomHex(32)
		if err != nil {
			return nil, nil, err
		}

		challenges = append(challenges, V2Challenge{
			Protocol: "hashwx",
			Payload:  map[string]any{"c": c, "d": each, "n": noncesPerHash},
		})
		expected = append(expected, v2ExpectedEntry{
			Protocol: "hashwx",
			C:        c,
			D:        each,
			N:        noncesPerHash,
		})
	}

	return challenges, expected, nil
}

func generateV2Rsw(opts GenerateOptions) ([]V2Challenge, []v2ExpectedEntry, error) {
	minter := opts.Rsw

	if minter == nil {
		if opts.Keypair == nil {
			return nil, nil, ErrRSWKeypairRequired
		}

		rswT := opts.RSWT
		if rswT <= 0 {
			rswT = defaultRSWT
		}

		built, err := BuildRswMinter(struct {
			N *big.Int
			P *big.Int
			Q *big.Int
			T int
			G *big.Int
		}{
			N: opts.Keypair.N,
			P: opts.Keypair.P,
			Q: opts.Keypair.Q,
			T: rswT,
		})
		if err != nil {
			return nil, nil, err
		}

		minter = built
	}

	mintResult, err := minter.Mint()
	if err != nil {
		return nil, nil, err
	}

	challenges := []V2Challenge{{
		Protocol: "rsw",
		Payload:  map[string]any{"N": minter.N_hex, "x": mintResult.X_hex, "t": minter.T},
	}}
	expected := []v2ExpectedEntry{{
		Protocol: "rsw",
		Y:        mintResult.Y_hex,
	}}

	return challenges, expected, nil
}

func generateV2Instrumentation(
	opts GenerateOptions,
	ttlMs int64,
	challengeExpires int64,
) ([]V2Challenge, []v2ExpectedEntry, error) {
	instrOpts := InstrumentationOptions{
		BlockAutomatedBrowsers: false,
		ObfuscationLevel:       3,
		TTLMs:                  ttlMs,
	}
	if opts.InstrumentationOpts != nil {
		instrOpts = *opts.InstrumentationOpts
	}

	// capjs-core always overrides ttlMs with the challenge lifetime and
	// stores the challenge expiry in the encrypted metadata.
	instrOpts.TTLMs = ttlMs

	generator := opts.InstrumentationGenerator
	if generator == nil {
		generator = GenerateInstrumentation
	}

	meta, blob, err := generator(instrOpts)
	if err != nil {
		return nil, nil, err
	}

	meta.Expires = challengeExpires

	challenges := []V2Challenge{{
		Protocol: "instrumentation",
		Payload:  map[string]any{"blob": blob},
	}}
	expected := []v2ExpectedEntry{{
		Protocol:        "instrumentation",
		Instrumentation: meta,
	}}

	return challenges, expected, nil
}
