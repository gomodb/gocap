package gocap

import (
	"context"
	"fmt"
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
		ei, blob, err := buildInstrumentation(opts, int64(ttl.Milliseconds()), secret)
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
	secret []byte,
) (string, string, error) {
	instrOpts := InstrumentationOptions{
		BlockAutomatedBrowsers: false,
		ObfuscationLevel:       3,
		TTLMs:                  ttlMs,
	}
	if opts.InstrumentationOpts != nil {
		instrOpts = *opts.InstrumentationOpts
		if instrOpts.TTLMs <= 0 {
			instrOpts.TTLMs = ttlMs
		}
	}

	meta, blob, err := GenerateInstrumentation(instrOpts)
	if err != nil {
		return "", "", err
	}

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
			chs []V2Challenge
			exp []v2ExpectedEntry
			err error
		)

		switch proto {
		case "sha256-pow":
			chs, exp, err = generateV2Sha256Pow(opts)
		case "rsw":
			chs, exp, err = generateV2Rsw(opts)
		case "instrumentation":
			chs, exp, err = generateV2Instrumentation(opts, int64(ttl.Milliseconds()))
		default:
			return ChallengeResult{}, fmt.Errorf("unknown protocol %q", proto)
		}

		if err != nil {
			return ChallengeResult{}, err
		}

		challenges = append(challenges, chs...)
		expected = append(expected, exp...)
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

func generateV2Rsw(opts GenerateOptions) ([]V2Challenge, []v2ExpectedEntry, error) {
	if opts.Keypair == nil {
		return nil, nil, ErrRSWKeypairRequired
	}

	rswT := opts.RSWT
	if rswT <= 0 {
		rswT = defaultRSWT
	}

	minter, err := BuildRswMinter(struct {
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

	mintResult, err := minter.Mint()
	if err != nil {
		return nil, nil, err
	}

	challenges := []V2Challenge{{
		Protocol: "rsw",
		Payload:  map[string]any{"N": minter.N_hex, "x": mintResult.X_hex, "t": rswT},
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
) ([]V2Challenge, []v2ExpectedEntry, error) {
	instrOpts := InstrumentationOptions{
		BlockAutomatedBrowsers: false,
		ObfuscationLevel:       3,
		TTLMs:                  ttlMs,
	}
	if opts.InstrumentationOpts != nil {
		instrOpts = *opts.InstrumentationOpts
	}

	meta, blob, err := GenerateInstrumentation(instrOpts)
	if err != nil {
		return nil, nil, err
	}

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
