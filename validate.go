package gocap

import (
	"context"
	"encoding/json/v2"
	"strconv"
	"strings"
	"time"
)

// validateChallengeWithContext validates a format-1 PoW challenge.
func validateChallengeWithContext(
	ctx context.Context,
	secret []byte,
	body ValidateBody,
	opts ValidateOptions,
) (ValidateResult, error) {
	if len(secret) < 16 {
		return ValidateResult{}, ErrShortSecret
	}

	if body.Token == "" {
		return res(ErrMissingToken), nil
	}

	if body.Solutions.IsZero() {
		return res(ErrMissingSolutions), nil
	}

	if body.Solutions.Objects != nil {
		return res(ErrInvalidSolutions), nil
	}

	solutions := body.Solutions.Numbers

	payload := jwtVerify(body.Token, secret)
	if payload == nil {
		return res(ErrInvalidToken), nil
	}

	if r := checkScope(payload, opts.Scope); !r.Success {
		return r, nil
	}

	exp, ok := asInt64(payload["exp"])
	if !ok || exp < currentUnixMilli() {
		return res(ErrExpired), nil
	}

	c, s, d, r := parseFormat1Payload(payload)
	if !r.Success {
		return r, nil
	}

	if int64(len(solutions)) != c {
		return res(ErrInvalidSolutions), nil
	}

	// Verify PoW solutions
	if r := verifyPoW1(body.Token, solutions, int(c), int(s), int(d)); !r.Success {
		return r, nil
	}

	// Validate instrumentation if present
	instrRes := validateFormat1Instr(payload, body, secret)
	if !instrRes.Success {
		return instrRes, nil
	}

	// Consume nonce (replay protection)
	if r := consumeNonce(ctx, opts.ConsumeNonce, body.Token, exp); !r.Success {
		return r, nil
	}

	result, err := issueValidationToken(payload, opts)
	if err != nil {
		return ValidateResult{}, err
	}

	result.RiskFlags = instrRes.RiskFlags
	if result.RiskFlags == nil {
		result.RiskFlags = []string{}
	}

	return result, nil
}

// validateChallengeV2 validates a format-2 multi-protocol challenge.
func validateChallengeV2(
	ctx context.Context,
	secret []byte,
	body ValidateBody,
	payload map[string]any,
	opts ValidateOptions,
) (ValidateResult, error) {
	if r := checkScope(payload, opts.Scope); !r.Success {
		return r, nil
	}

	exp, ok := asInt64(payload["exp"])
	if !ok || exp < currentUnixMilli() {
		return res(ErrExpired), nil
	}

	ev, ok := payload["ev"].(string)
	if !ok {
		return res(ErrInvalidToken), nil
	}

	decrypted, ok := decryptGcmRaw(ev, secret, "cap:fmt2-v1")
	if !ok {
		return res(ErrInvalidToken), nil
	}

	var expectedWrapper struct {
		Expected []v2ExpectedEntry `json:"expected"`
	}
	if err := json.Unmarshal(decrypted, &expectedWrapper); err != nil {
		return res(ErrInvalidToken), nil
	}

	expected := expectedWrapper.Expected

	if body.Solutions.IsZero() {
		return res(ErrMissingSolutions), nil
	}

	solutions := body.Solutions.Objects
	if solutions == nil {
		// A number array is a valid shape for format-1, but not for a
		// format-2 token. capjs-core reports invalid_solutions on a length
		// mismatch and invalid_solution otherwise.
		if len(body.Solutions.Numbers) != len(expected) {
			return res(ErrInvalidSolutions), nil
		}

		return res(ErrInvalidSolution), nil
	}

	if len(solutions) != len(expected) {
		return res(ErrInvalidSolutions), nil
	}

	riskFlags := make([]string, 0, len(expected))

	for i, e := range expected {
		r := validateV2ProtocolSolution(e, solutions[i])
		if !r.Success {
			return r, nil
		}

		riskFlags = append(riskFlags, r.RiskFlags...)
	}

	if r := consumeNonce(ctx, opts.ConsumeNonce, body.Token, exp); !r.Success {
		return r, nil
	}

	result, err := issueValidationToken(payload, opts)
	if err != nil {
		return ValidateResult{}, err
	}

	result.RiskFlags = riskFlags
	if result.RiskFlags == nil {
		result.RiskFlags = []string{}
	}

	return result, nil
}

// ─── Sub-validators ─────────────────────────────────────────────────────────

func checkScope(payload map[string]any, scope string) ValidateResult {
	if scope == "" {
		return ValidateResult{Success: true}
	}

	psk, _ := payload["sk"].(string)
	if psk != scope {
		return res(ErrScopeMismatch)
	}

	return ValidateResult{Success: true}
}

func parseFormat1Payload(payload map[string]any) (int64, int64, int64, ValidateResult) {
	c, okC := asInt64(payload["c"])
	s, okS := asInt64(payload["s"])

	d, okD := asInt64(payload["d"])
	if !okC || !okS || !okD ||
		c < 1 || c > maxChallengeCount ||
		s < 1 || s > maxChallengeSize ||
		d < 1 || d > maxChallengeDifficulty {
		return 0, 0, 0, res(ErrInvalidToken)
	}

	return c, s, d, ValidateResult{Success: true}
}

func verifyPoW1(token string, solutions []int64, c, s, d int) ValidateResult {
	tokenFnv := fnv1a(token)

	for i := range c {
		idxStr := strconv.Itoa(i + 1)
		saltSeed := fnv1aResume(tokenFnv, idxStr)
		targetSeed := fnv1aResume(saltSeed, "d")
		salt := prngFromHash(saltSeed, s)
		target := prngFromHash(targetSeed, d)

		hash := sha256Hex(salt + strconv.FormatInt(solutions[i], 10))
		if !strings.HasPrefix(hash, target) {
			return res(ErrInvalidSolution)
		}
	}

	return ValidateResult{Success: true}
}

func validateFormat1Instr(payload map[string]any, body ValidateBody, secret []byte) ValidateResult {
	ei, hasEI := payload["ei"]
	if !hasEI {
		return ValidateResult{Success: true}
	}

	eiStr, ok := ei.(string)
	if !ok {
		return failInstrErr(ErrInstrCorrupted)
	}

	instrMeta := instrumentationMetaFromEncrypted(eiStr, secret)
	if instrMeta == nil {
		return failInstrErr(ErrInstrCorrupted)
	}

	if instrMeta.Expires > 0 && currentUnixMilli() > instrMeta.Expires {
		return failInstrErr(ErrInstrExpired)
	}

	return validateInstrumentationBody(instrMeta, body)
}

func consumeNonce(
	ctx context.Context,
	fn func(context.Context, string, time.Duration) (bool, error),
	token string,
	exp int64,
) ValidateResult {
	if fn == nil {
		return ValidateResult{Success: true}
	}

	sig := jwtSigHexFn(token)
	if sig == "" {
		return res(ErrInvalidToken)
	}

	ttl := max(exp-currentUnixMilli(), 1)

	claimed, err := fn(ctx, sig, time.Duration(ttl)*time.Millisecond)
	if err != nil {
		return ValidateResult{
			Success:  false,
			Reason:   ErrNonceStoreError.Error(),
			ErrorStr: err.Error(),
			err:      ErrNonceStoreError,
		}
	}

	if !claimed {
		return res(ErrAlreadyRedeemed)
	}

	return ValidateResult{Success: true}
}

func validateV2ProtocolSolution(e v2ExpectedEntry, s V2Solution) ValidateResult {
	switch e.Protocol {
	case "sha256-pow":
		return validateV2Sha256Pow(e, s)
	case "rsw":
		return validateV2Rsw(e, s)
	case "hashwx":
		return validateV2Hashwx(e, s)
	case "instrumentation":
		return validateV2Instrumentation(e, s)
	default:
		return res(ErrInvalidSolution)
	}
}

func validateV2Sha256Pow(e v2ExpectedEntry, s V2Solution) ValidateResult {
	nonce, ok := jsValueString(s.Nonce)
	if !ok {
		return res(ErrInvalidSolution)
	}

	h := sha256Hex(e.Salt + nonce)
	if !strings.HasPrefix(h, e.Target) {
		return res(ErrInvalidSolution)
	}

	return ValidateResult{Success: true}
}

func validateV2Rsw(e v2ExpectedEntry, s V2Solution) ValidateResult {
	if !VerifyRswSolution(e.Y, s.Y) {
		return res(ErrInvalidSolution)
	}

	return ValidateResult{Success: true}
}

func validateV2Instrumentation(e v2ExpectedEntry, s V2Solution) ValidateResult {
	if e.Instrumentation == nil {
		return failInstrErr(ErrInstrCorrupted)
	}

	if e.Instrumentation.Expires > 0 && currentUnixMilli() > e.Instrumentation.Expires {
		return failInstrErr(ErrInstrExpired)
	}

	if s.Blocked != nil && *s.Blocked {
		if e.Instrumentation.BlockAutomatedBrowsers {
			return failInstrErr(ErrInstrAutomatedBrowser)
		}

		return failInstrErr(ErrInstrFailed)
	}

	if s.Timeout != nil && *s.Timeout {
		return failInstrErr(ErrInstrTimeout)
	}

	if s.Instr != nil {
		vr := verifyInstrumentationResult(
			e.Instrumentation,
			&InstrumentationResult{
				I:     s.Instr.I,
				State: s.Instr.State,
				P:     s.Instr.P,
				VP:    s.Instr.VP,
				Ts:    s.Instr.Ts,
			},
		)
		if !vr.Valid {
			r := ValidateResult{
				Success:   false,
				Reason:    vr.Reason,
				InstrErr:  true,
				BlockedBy: vr.BlockedBy,
			}
			r.err = instrSentinel(vr.Reason)

			return r
		}

		return ValidateResult{Success: true, RiskFlags: vr.RiskFlags}
	}

	return failInstrErr(ErrInstrMissing)
}

// validateInstrumentationBody checks instrumentation results for format-1 challenges.
func validateInstrumentationBody(meta *InstrumentationMeta, body ValidateBody) ValidateResult {
	if body.Blocked {
		if meta.BlockAutomatedBrowsers {
			return failInstrErr(ErrInstrAutomatedBrowser)
		}

		return failInstrErr(ErrInstrFailed)
	}

	if body.Timeout {
		return failInstrErr(ErrInstrTimeout)
	}

	if body.Instr != nil {
		vr := verifyInstrumentationResult(
			meta,
			&InstrumentationResult{
				I:     body.Instr.I,
				State: body.Instr.State,
				P:     body.Instr.P,
				VP:    body.Instr.VP,
				Ts:    body.Instr.Ts,
			},
		)
		if !vr.Valid {
			r := ValidateResult{
				Success:   false,
				Reason:    vr.Reason,
				InstrErr:  true,
				BlockedBy: vr.BlockedBy,
			}
			r.err = instrSentinel(vr.Reason)

			return r
		}

		return ValidateResult{Success: true, RiskFlags: vr.RiskFlags}
	}

	return failInstrErr(ErrInstrMissing)
}

// issueValidationToken creates a validation (redeem) token after successful challenge verification.
func issueValidationToken(payload map[string]any, opts ValidateOptions) (ValidateResult, error) {
	tokenTTL := defaultTokenTTL
	if opts.TokenTTL > 0 {
		tokenTTL = opts.TokenTTL
	}

	tokenExpires := time.Now().Add(tokenTTL).UnixMilli()

	var scopePtr *string

	if scope, ok := payload["sk"].(string); ok && scope != "" {
		scopePtr = new(scope)
	}

	iat, iatOK := asInt64(payload["iat"])

	var iatPtr *int64
	if iatOK {
		iatPtr = new(iat)
	}

	if opts.SignToken != nil {
		signed, err := opts.SignToken(
			RedeemTokenData{Scope: scopePtr, Expires: tokenExpires, Iat: iat},
		)
		if err != nil {
			return ValidateResult{}, err
		}

		if opts.Storage != nil {
			ctx := context.Background()
			if err := opts.Storage.CleanupExpired(ctx); err != nil {
				return ValidateResult{}, err
			}

			if err := opts.Storage.SetValidationToken(
				ctx,
				signed,
				time.UnixMilli(tokenExpires),
			); err != nil {
				return ValidateResult{}, err
			}
		}

		return ValidateResult{
			Success: true,
			Token:   signed,
			Expires: tokenExpires,
			Scope:   scopePtr,
			Iat:     iatPtr,
		}, nil
	}

	id, err := randomHex(8)
	if err != nil {
		return ValidateResult{}, err
	}

	verToken, err := randomHex(15)
	if err != nil {
		return ValidateResult{}, err
	}

	tokenHash := sha256Hex(verToken)
	token := id + ":" + verToken
	tokenKey := id + ":" + tokenHash

	if opts.Storage != nil {
		ctx := context.Background()
		if err := opts.Storage.CleanupExpired(ctx); err != nil {
			return ValidateResult{}, err
		}

		if err := opts.Storage.SetValidationToken(
			ctx,
			token,
			time.UnixMilli(tokenExpires),
		); err != nil {
			return ValidateResult{}, err
		}

		// Also index the hashed lookup key so callers can follow the
		// upstream tokenKey privacy pattern and validate with either form.
		if err := opts.Storage.SetValidationToken(
			ctx,
			tokenKey,
			time.UnixMilli(tokenExpires),
		); err != nil {
			return ValidateResult{}, err
		}
	}

	return ValidateResult{
		Success:  true,
		Token:    token,
		TokenKey: new(tokenKey),
		Expires:  tokenExpires,
		Scope:    scopePtr,
		Iat:      iatPtr,
	}, nil
}
