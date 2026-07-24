package gocap

import (
	"context"
	"time"
)

const (
	defaultChallengeCount      = 50
	defaultChallengeSize       = 32
	defaultChallengeDifficulty = 4
	defaultChallengeTTL        = 10 * time.Minute
	defaultTokenTTL            = 20 * time.Minute
	maxChallengeCount          = 1000
	maxChallengeSize           = 256
	maxChallengeDifficulty     = 16
	defaultRSWT                = 75000
)

var (
	currentUnixMilli = func() int64 { return time.Now().UnixMilli() }
	jwtSigHexFn      = jwtSigHex
)

// ChallengeSpec describes the format-1 PoW parameters sent to the client.
type ChallengeSpec struct {
	// C is the number of PoW items the client must solve.
	C int `json:"c"`
	// S is the salt length in hex characters.
	S int `json:"s"`
	// D is the target prefix difficulty in hex characters.
	D int `json:"d"`
}

// ChallengeResult is the challenge payload returned by CreateChallenge.
type ChallengeResult struct {
	// Challenge contains the format-1 PoW parameters (omitted for format-2).
	Challenge ChallengeSpec `json:"challenge"`
	// Token is the signed JWT carrying the challenge parameters.
	Token string `json:"token"`
	// Expires is the challenge expiration time in Unix milliseconds.
	Expires int64 `json:"expires"`
	// Instrumentation is an opaque blob for client-side browser checks
	// (format-1 only, base64-encoded deflated JS in the JS reference impl).
	Instrumentation string `json:"instrumentation,omitzero"`
	// Format is 2 when the result uses the multi-protocol format, 0 or
	// omitted for format-1.
	Format int `json:"format,omitzero"`
	// Challenges is the protocol-specific challenge list (format-2 only).
	Challenges []V2Challenge `json:"challenges,omitzero"`
}

// V2Challenge represents a single protocol-specific challenge in format-2.
type V2Challenge struct {
	// Protocol identifies the challenge type: "sha256-pow", "rsw", or
	// "instrumentation".
	Protocol string `json:"protocol"`
	// Payload carries protocol-specific parameters (salt/target for PoW,
	// N/x/t for RSW, blob for instrumentation).
	Payload map[string]any `json:"payload"`
}

// GenerateOptions configures challenge generation.
// Most fields map directly to CapOptions fields. Zero values use defaults.
type GenerateOptions struct {
	// ChallengeCount sets the number of PoW items (default 50).
	ChallengeCount int
	// ChallengeSize sets the salt length in hex characters (default 32).
	ChallengeSize int
	// ChallengeDifficulty sets the target prefix length in hex characters
	// (default 4).
	ChallengeDifficulty int
	// Expires sets the challenge lifetime (default 10 minutes).
	Expires time.Duration
	// Scope binds the challenge to a logical site or action.
	Scope string
	// Extra is embedded in the challenge token payload under key "x".
	Extra map[string]any
	// Storage persists challenge and validation tokens.
	Storage Storage
	// Instrumentation enables format-1 client-side browser checks when true.
	Instrumentation bool
	// InstrumentationOpts fine-tunes instrumentation behaviour.
	InstrumentationOpts *InstrumentationOptions
	// Format selects the challenge format. 0 or 1 for format-1 (default),
	// 2 for the multi-protocol format-2.
	Format int
	// Protocols lists the protocols to include in a format-2 challenge.
	// Valid values: "sha256-pow", "rsw", "instrumentation".
	Protocols []string
	// Keypair is the RSA-style keypair needed for the "rsw" protocol.
	Keypair *RswKeypair
	// RSWT is the number of sequential squarings for RSW puzzles
	// (default 75000).
	RSWT int
}

// RedeemTokenData contains the data passed to the SignToken callback.
type RedeemTokenData struct {
	// Scope is the original challenge scope, or nil if unset.
	Scope *string `json:"scope"`
	// Expires is the redeem token expiration time in Unix milliseconds.
	Expires int64 `json:"expires"`
	// Iat is the original challenge issue-at time in Unix milliseconds.
	Iat int64 `json:"iat,omitzero"`
}

// ValidateBody is the request body for RedeemChallenge.
type ValidateBody struct {
	// Token is the challenge token issued by CreateChallenge.
	Token string `json:"token"`
	// Solutions contains the PoW nonces for format-1 challenges.
	Solutions []int64 `json:"solutions"`
	// V2Sol contains protocol-specific solutions for format-2 challenges.
	V2Sol []V2Solution `json:"v2Sol,omitzero"`
	// Instr carries the instrumentation result payload (format-1).
	Instr *InstrPayload `json:"instr,omitzero"`
	// Blocked reports that instrumentation determined the page was blocked.
	Blocked bool `json:"instr_blocked,omitzero"`
	// Timeout reports that instrumentation timed out.
	Timeout bool `json:"instr_timeout,omitzero"`
}

// V2Solution is a protocol-specific solution for format-2.
// Only the fields relevant to the protocol need to be set.
type V2Solution struct {
	// Protocol identifies the challenge type this solution is for: must
	// match the corresponding V2Challenge.Protocol.
	Protocol string `json:"protocol"`
	// Nonce is the PoW solution nonce for "sha256-pow" protocol.
	Nonce any `json:"nonce,omitzero"`
	// Y is the RSW solution for the "rsw" protocol.
	Y string `json:"y,omitzero"`
	// Blocked indicates the instrumentation was blocked. Set for
	// "instrumentation" protocol as an alternative to Instr/Timeout.
	Blocked *bool `json:"blocked,omitzero"`
	// Timeout indicates the instrumentation timed out. Set for
	// "instrumentation" protocol as an alternative to Instr/Blocked.
	Timeout *bool `json:"timeout,omitzero"`
	// Instr carries the full instrumentation result for "instrumentation"
	// protocol instead of using Blocked/Timeout shortcuts.
	Instr any `json:"instr,omitzero"`
}

// InstrPayload is the client-side instrumentation result payload.
type InstrPayload struct {
	// I is the instrumentation challenge ID.
	I string `json:"i"`
	// State maps variable names to their computed values.
	State map[string]int `json:"state"`
	// Ts is the client timestamp in Unix milliseconds.
	Ts int64 `json:"ts,omitzero"`
}

// ValidateOptions configures challenge validation behaviour.
type ValidateOptions struct {
	// Scope must match the original challenge scope when set.
	Scope string
	// TokenTTL controls the lifetime of the issued validation token
	// (default 20 minutes).
	TokenTTL time.Duration
	// Storage persists the issued validation token for later verification.
	Storage Storage
	// ConsumeNonce provides replay protection. The callback receives the
	// hex-encoded HMAC signature of the challenge token and its remaining
	// TTL. Return true to claim the nonce (first use), false for replay.
	ConsumeNonce func(ctx context.Context, signatureHex string, ttl time.Duration) (bool, error)
	// SignToken overrides the default validation token format. If nil, a
	// random id:verToken format is used. The callback receives the scope,
	// expiration, and original issue time.
	SignToken func(data RedeemTokenData) (string, error)
}

// ValidateResult is the outcome of RedeemChallenge or ValidateToken.
//
// It implements the error interface, so callers can use errors.Is/As:
//
//	if errors.Is(result, ErrExpired) { ... }
//
// When Success is false, Error() returns the Reason string and Unwrap()
// returns the corresponding sentinel error.
type ValidateResult struct {
	// Success reports whether validation passed.
	Success bool `json:"success"`
	// Reason describes the failure reason when Success is false. It matches
	// one of the ErrXXX sentinel error strings.
	Reason string `json:"reason,omitzero"`
	// ErrorStr carries a lower-level error message (e.g. a storage error).
	ErrorStr string `json:"error,omitzero"`
	// InstrErr is true when the failure is instrumentation-related.
	InstrErr bool `json:"instr_error,omitzero"`
	// Token is the issued validation token on success.
	Token string `json:"token,omitzero"`
	// TokenKey is an alternative lookup key for the default token format.
	// Clients may store this instead of the full token for privacy.
	TokenKey *string `json:"tokenKey,omitzero"`
	// Expires is the validation token expiration in Unix milliseconds.
	Expires int64 `json:"expires,omitzero"`
	// Scope is the validated scope, if any.
	Scope *string `json:"scope"`
	// Iat is the original challenge issue-at time in Unix milliseconds.
	Iat *int64 `json:"iat,omitzero"`
	// err is the sentinel error for errors.Is/As, not serialized to JSON.
	err error `json:"-"`
}

// Error implements the error interface. It returns the Reason string, or
// "success" when the validation passed.
func (r ValidateResult) Error() string {
	if r.Reason != "" {
		return r.Reason
	}

	return "success"
}

// Unwrap returns the sentinel error, enabling errors.Is(r, ErrExpired) etc.
func (r ValidateResult) Unwrap() error {
	return r.err
}

// CapOptions configures a Cap instance. All fields are optional except
// Secret, which must be at least 16 bytes.
type CapOptions struct {
	// Secret is used to sign and verify challenge tokens via HMAC-SHA256.
	// Must be at least 16 bytes; 32+ recommended.
	Secret []byte
	// Storage persists challenge and validation tokens. If nil, token
	// verification via ValidateToken will fail with storage_not_configured.
	Storage Storage
	// ChallengeCount sets the number of PoW items (format-1, default 50).
	ChallengeCount int
	// ChallengeSize sets the salt length in hex characters (format-1,
	// default 32).
	ChallengeSize int
	// ChallengeDifficulty sets the target prefix hex length (format-1,
	// default 4).
	ChallengeDifficulty int
	// ChallengeTTL controls challenge token lifetime (default 10 minutes).
	ChallengeTTL time.Duration
	// Scope binds the challenge to a logical site or action.
	Scope string
	// Extra is embedded in the challenge token payload as the "x" field.
	Extra map[string]any
	// TokenTTL controls validation token lifetime (default 20 minutes).
	TokenTTL time.Duration
	// ConsumeNonce provides replay protection. See ValidateOptions.
	ConsumeNonce func(ctx context.Context, signatureHex string, ttl time.Duration) (bool, error)
	// SignToken overrides the default validation token format. See
	// ValidateOptions.
	SignToken func(data RedeemTokenData) (string, error)
	// Format selects the challenge format. 0 or 1 for format-1 (default),
	// 2 for the multi-protocol format-2.
	Format int
	// Protocols lists the protocols for format-2 challenges. Required when
	// Format is 2.
	Protocols []string
	// Keypair is the RSA-style keypair required for the "rsw" protocol.
	Keypair *RswKeypair
	// RSWT is the sequential squaring count for RSW puzzles (default 75000).
	RSWT int
	// Instrumentation enables format-1 client-side browser checks.
	Instrumentation bool
	// InstrumentationOpts fine-tunes instrumentation behaviour.
	InstrumentationOpts *InstrumentationOptions
}

// Cap is an instance-based API for creating and redeeming challenges.
// Create one via NewCap and reuse it across requests.
type Cap struct {
	secret       []byte
	storage      Storage
	generateOpts GenerateOptions
	validateOpts ValidateOptions
}

// NewCap creates a Cap instance with the given options.
// Secret must be at least 16 bytes. When Format is 2, at least one protocol
// must be specified in Protocols.
func NewCap(opts CapOptions) (*Cap, error) {
	if len(opts.Secret) < 16 {
		return nil, ErrShortSecret
	}

	if opts.Format == 2 && len(opts.Protocols) == 0 {
		return nil, ErrFormat2NoProtocols
	}

	secretCopy := make([]byte, len(opts.Secret))
	copy(secretCopy, opts.Secret)

	return &Cap{
		secret:  secretCopy,
		storage: opts.Storage,
		generateOpts: GenerateOptions{
			ChallengeCount:      opts.ChallengeCount,
			ChallengeSize:       opts.ChallengeSize,
			ChallengeDifficulty: opts.ChallengeDifficulty,
			Expires:             opts.ChallengeTTL,
			Scope:               opts.Scope,
			Extra:               cloneMap(opts.Extra),
			Storage:             opts.Storage,
			Instrumentation:     opts.Instrumentation,
			InstrumentationOpts: opts.InstrumentationOpts,
			Format:              opts.Format,
			Protocols:           opts.Protocols,
			Keypair:             opts.Keypair,
			RSWT:                opts.RSWT,
		},
		validateOpts: ValidateOptions{
			Scope:        opts.Scope,
			TokenTTL:     opts.TokenTTL,
			Storage:      opts.Storage,
			ConsumeNonce: opts.ConsumeNonce,
			SignToken:    opts.SignToken,
		},
	}, nil
}

// CreateChallenge creates challenge parameters and a signed challenge token.
// When Format is 2, it returns a multi-protocol challenge; otherwise a
// format-1 PoW challenge.
func (c *Cap) CreateChallenge(ctx context.Context) (ChallengeResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if c.generateOpts.Format == 2 {
		return generateChallengeV2(ctx, c.secret, c.generateOpts)
	}

	return generateChallengeWithContext(ctx, c.secret, c.generateOpts)
}

// RedeemChallenge verifies PoW solutions and returns a validation result.
//
// On success (result.Success == true), result.Token and result.Expires are
// set. The token can later be verified with ValidateToken.
//
// On validation failure (result.Success == false), result.Reason describes
// the error and errors.Is can identify the specific reason.
//
// Internal errors (storage, config) are returned as the error value.
func (c *Cap) RedeemChallenge(ctx context.Context, proof ValidateBody) (ValidateResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	// Auto-detect format from the token's "f" field.
	if proof.Token != "" {
		payload := jwtVerify(proof.Token, c.secret)
		if payload != nil {
			if f, _ := asInt64(payload["f"]); f == 2 {
				return validateChallengeV2(ctx, c.secret, proof, payload, c.validateOpts)
			}
		}
	}

	r, err := validateChallengeWithContext(ctx, c.secret, proof, c.validateOpts)
	if err != nil {
		return ValidateResult{}, err
	}

	return r, nil
}

// ValidateToken reports whether a validation token exists and is not expired.
// Returns a ValidateResult that can be checked with errors.Is:
//
//	vr := cap.ValidateToken(ctx, token)
//	if errors.Is(vr, ErrTokenNotFound) { ... }
func (c *Cap) ValidateToken(ctx context.Context, token string) ValidateResult {
	if ctx == nil {
		ctx = context.Background()
	}

	if c.storage == nil {
		return res(ErrStorageNotConfigured)
	}

	if token == "" {
		return res(ErrMissingToken)
	}

	if err := c.storage.CleanupExpired(ctx); err != nil {
		return ValidateResult{
			Reason:   ErrCleanupError.Error(),
			ErrorStr: err.Error(),
			err:      ErrCleanupError,
		}
	}

	expiresAt, ok, err := c.storage.GetValidationTokenExpiry(ctx, token)
	if err != nil {
		return ValidateResult{
			Reason:   ErrStorageError.Error(),
			ErrorStr: err.Error(),
			err:      ErrStorageError,
		}
	}

	if !ok {
		return res(ErrTokenNotFound)
	}

	if !expiresAt.After(time.Now()) {
		return res(ErrTokenExpired)
	}

	return ValidateResult{Success: true}
}
