package gocap

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"math/big"
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

	// HashWX defaults mirror capjs-core.
	defaultHashwxDifficulty     = 1_000_000
	defaultHashwxNoncesPerHash  = 65536
	defaultHashwxChallengeCount = 4
	maxHashwxDifficulty         = 1_000_000_000
	maxHashwxNoncesPerHash      = 1_048_576
	maxHashwxChallengeCount     = 64
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
	// Token is the signed JWT carrying the challenge parameters.
	Token string `json:"token"`
	// Instrumentation is an opaque blob for client-side browser checks
	// (format-1 only, base64-encoded deflated JS in the JS reference impl).
	Instrumentation string `json:"instrumentation,omitzero"`
	// Challenges is the protocol-specific challenge list (format-2 only).
	Challenges []V2Challenge `json:"challenges,omitzero"`
	// Challenge contains the format-1 PoW parameters (omitted for format-2).
	Challenge ChallengeSpec `json:"challenge"`
	// Expires is the challenge expiration time in Unix milliseconds.
	Expires int64 `json:"expires"`
	// Format is 2 when the result uses the multi-protocol format, 0 or
	// omitted for format-1.
	Format int `json:"format,omitzero"`
}

// MarshalJSON omits the format-1 `challenge` object for format-2 results,
// matching capjs-core's wire shape.
func (r ChallengeResult) MarshalJSON() ([]byte, error) {
	if r.Format == 2 {
		type format2 struct {
			Token      string        `json:"token"`
			Challenges []V2Challenge `json:"challenges"`
			Expires    int64         `json:"expires"`
			Format     int           `json:"format"`
		}

		return json.Marshal(format2{
			Token:      r.Token,
			Expires:    r.Expires,
			Format:     r.Format,
			Challenges: r.Challenges,
		})
	}

	type format1 ChallengeResult

	return json.Marshal(format1(r))
}

// V2Challenge represents a single protocol-specific challenge in format-2.
type V2Challenge struct {
	// Payload carries protocol-specific parameters (salt/target for PoW,
	// N/x/t for RSW, blob for instrumentation).
	Payload map[string]any `json:"payload"`
	// Protocol identifies the challenge type: "sha256-pow", "rsw",
	// "hashwx", or "instrumentation".
	Protocol string `json:"protocol"`
}

// InstrumentationGenerator produces instrumentation metadata together with a
// base64-encoded, deflate-raw JavaScript bundle. It mirrors the
// instrumentationGenerator escape hatch in capjs-core.
type InstrumentationGenerator func(
	opts InstrumentationOptions,
) (*InstrumentationMeta, string, error)

// GenerateOptions configures challenge generation.
// Most fields map directly to CapOptions fields. Zero values use defaults.
type GenerateOptions struct {
	// Storage persists challenge and validation tokens.
	Storage Storage
	// Extra is embedded in the challenge token payload under key "x".
	Extra map[string]any
	// InstrumentationOpts fine-tunes instrumentation behaviour.
	InstrumentationOpts *InstrumentationOptions
	// InstrumentationGenerator overrides the built-in instrumentation
	// generator. The returned blob must be a base64-encoded, deflate-raw
	// JavaScript bundle understood by the Cap widget.
	InstrumentationGenerator InstrumentationGenerator
	// Keypair is the RSA-style keypair needed for the "rsw" protocol.
	Keypair *RswKeypair
	// Rsw is an optional prebuilt RSW minter. When set it is used instead of
	// building a minter from Keypair, matching capjs-core's opts.rsw.
	Rsw *RswMinter
	// Scope binds the challenge to a logical site or action.
	Scope string
	// Protocols lists the protocols to include in a format-2 challenge.
	// Valid values: "sha256-pow", "rsw", "hashwx", "instrumentation".
	Protocols []string
	// ChallengeCount sets the number of PoW items (default 50).
	ChallengeCount int
	// ChallengeSize sets the salt length in hex characters (default 32).
	ChallengeSize int
	// ChallengeDifficulty sets the target prefix length in hex characters
	// (default 4).
	ChallengeDifficulty int
	// Expires sets the challenge lifetime (default 10 minutes).
	Expires time.Duration
	// Format selects the challenge format. 0 or 1 for format-1 (default),
	// 2 for the multi-protocol format-2.
	Format int
	// RSWT is the number of sequential squarings for RSW puzzles
	// (default 75000).
	RSWT int
	// HashwxDifficulty is the expected number of HashWX hashes per solve,
	// across all sub-challenges (default 1,000,000).
	HashwxDifficulty int
	// HashwxNoncesPerHash is the number of nonces covered by each generated
	// HashWX hash function (default 65,536).
	HashwxNoncesPerHash int
	// HashwxChallengeCount is the number of independent HashWX sub-challenges
	// (default 4).
	HashwxChallengeCount int
	// Instrumentation enables format-1 client-side browser checks when true.
	Instrumentation bool
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

// ValidateBody is the request body for RedeemChallenge. It mirrors
// capjs-core's ValidateChallengeBody: solutions travel in a single `solutions`
// field, as an array of numbers (format-1) or protocol-specific objects
// (format-2).
type ValidateBody struct {
	// Instr carries the instrumentation result payload (format-1).
	Instr *InstrPayload `json:"instr,omitzero"`
	// Token is the challenge token issued by CreateChallenge.
	Token string `json:"token"`
	// Solutions is the unified solutions array. Use NumberSolutions for
	// format-1 and ObjectSolutions for format-2.
	Solutions Solutions `json:"solutions,omitzero"`
	// Blocked reports that instrumentation determined the page was blocked.
	Blocked bool `json:"instr_blocked,omitzero"`
	// Timeout reports that instrumentation timed out.
	Timeout bool `json:"instr_timeout,omitzero"`
}

// Solutions is the Go representation of capjs-core's
// `solutions: number[] | Format2Solution[]` union. Exactly one of Numbers or
// Objects is used for a given challenge format.
type Solutions struct {
	// Numbers holds format-1 nonce solutions.
	Numbers []int64
	// Objects holds format-2 protocol-specific solutions.
	Objects []V2Solution
}

// NumberSolutions builds a format-1 solutions value.
func NumberSolutions(nums ...int64) Solutions {
	return Solutions{Numbers: nums}
}

// ObjectSolutions builds a format-2 solutions value.
func ObjectSolutions(sols ...V2Solution) Solutions {
	return Solutions{Objects: sols}
}

// SolutionsFromNumbers builds a format-1 solutions value from a slice.
func SolutionsFromNumbers(nums []int64) Solutions {
	return Solutions{Numbers: nums}
}

// SolutionsFromObjects builds a format-2 solutions value from a slice.
func SolutionsFromObjects(sols []V2Solution) Solutions {
	return Solutions{Objects: sols}
}

// IsZero reports whether no solutions were provided.
func (s Solutions) IsZero() bool {
	return s.Numbers == nil && s.Objects == nil
}

// MarshalJSON emits a JSON array of numbers or objects, matching the official
// wire format.
func (s Solutions) MarshalJSON() ([]byte, error) {
	if s.Objects != nil {
		return json.Marshal(s.Objects)
	}

	if s.Numbers != nil {
		return json.Marshal(s.Numbers)
	}

	return []byte("[]"), nil
}

// UnmarshalJSON accepts either a number array or an object array.
func (s *Solutions) UnmarshalJSON(data []byte) error {
	var numbers []int64
	if err := json.Unmarshal(data, &numbers); err == nil {
		s.Numbers = numbers
		s.Objects = nil

		return nil
	}

	var objects []V2Solution
	if err := json.Unmarshal(data, &objects); err != nil {
		return fmt.Errorf("invalid solutions: %w", err)
	}

	s.Objects = objects
	s.Numbers = nil

	return nil
}

// V2Solution is a protocol-specific solution for format-2. Only the fields
// relevant to the challenge protocol are set, exactly like capjs-core's
// Format2Solution union. Solutions are matched to challenges by position; the
// wire format has no protocol field.
type V2Solution struct {
	// Nonce is the PoW solution nonce for "sha256-pow" and "hashwx".
	Nonce any `json:"nonce,omitzero"`
	// Blocked indicates that instrumentation was blocked.
	Blocked *bool `json:"blocked,omitzero"`
	// Timeout indicates that instrumentation timed out.
	Timeout *bool `json:"timeout,omitzero"`
	// Instr carries the full instrumentation result.
	Instr *InstrPayload `json:"instr,omitzero"`
	// Y is the RSW solution for the "rsw" protocol.
	Y string `json:"y,omitzero"`
}

// InstrPayload is the client-side instrumentation result payload.
type InstrPayload struct {
	// I is the instrumentation challenge ID.
	I string `json:"i"`
	// State maps variable names to their computed values.
	State map[string]int `json:"state"`
	// P is the browser probe vector collected by the instrumentation script.
	P ProbeVector `json:"p,omitempty"`
	// VP is the parent window viewport size ([width, height]), added by the
	// widget after the iframe reports back.
	VP []float64 `json:"vp,omitempty"`
	// Ts is the client timestamp in Unix milliseconds.
	Ts int64 `json:"ts,omitzero"`
}

// ValidateOptions configures challenge validation behaviour.
type ValidateOptions struct {
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
	// Scope must match the original challenge scope when set.
	Scope string
	// TokenTTL controls the lifetime of the issued validation token
	// (default 20 minutes).
	TokenTTL time.Duration
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
	// err is the sentinel error for errors.Is/As, not serialized to JSON.
	err error `json:"-"`
	// TokenKey is an alternative lookup key for the default token format.
	// Clients may store this instead of the full token for privacy.
	TokenKey *string `json:"tokenKey,omitzero"`
	// Scope is the validated scope, if any.
	Scope *string `json:"scope"`
	// Iat is the original challenge issue-at time in Unix milliseconds.
	Iat *int64 `json:"iat,omitzero"`
	// Reason describes the failure reason when Success is false. It matches
	// one of the ErrXXX sentinel error strings.
	Reason string `json:"reason,omitzero"`
	// ErrorStr carries a lower-level error message (e.g. a storage error).
	ErrorStr string `json:"error,omitzero"`
	// Token is the issued validation token on success.
	Token string `json:"token,omitzero"`
	// RiskFlags contains non-gating automation signals (for example
	// "native_tamper"). They should raise difficulty, not block.
	RiskFlags []string `json:"riskFlags"`
	// BlockedBy lists the gating detection checks that failed when Reason is
	// "instr_automated_browser".
	BlockedBy []string `json:"blockedBy,omitzero"`
	// Expires is the validation token expiration in Unix milliseconds.
	Expires int64 `json:"expires,omitzero"`
	// Success reports whether validation passed.
	Success bool `json:"success"`
	// InstrErr is true when the failure is instrumentation-related.
	InstrErr bool `json:"instr_error,omitzero"`
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
	// Storage persists challenge and validation tokens. If nil, token
	// verification via ValidateToken will fail with storage_not_configured.
	Storage Storage
	// Extra is embedded in the challenge token payload as the "x" field.
	Extra map[string]any
	// ConsumeNonce provides replay protection. See ValidateOptions.
	ConsumeNonce func(ctx context.Context, signatureHex string, ttl time.Duration) (bool, error)
	// SignToken overrides the default validation token format. See
	// ValidateOptions.
	SignToken func(data RedeemTokenData) (string, error)
	// Keypair is the RSA-style keypair required for the "rsw" protocol.
	Keypair *RswKeypair
	// Rsw is an optional prebuilt RSW minter. When set it is used instead of
	// building a minter from Keypair, matching capjs-core's opts.rsw.
	Rsw *RswMinter
	// InstrumentationOpts fine-tunes instrumentation behaviour.
	InstrumentationOpts *InstrumentationOptions
	// InstrumentationGenerator overrides the built-in instrumentation
	// generator. See GenerateOptions.
	InstrumentationGenerator InstrumentationGenerator
	// Scope binds the challenge to a logical site or action.
	Scope string
	// Secret is used to sign and verify challenge tokens via HMAC-SHA256.
	// Must be at least 16 bytes; 32+ recommended.
	Secret []byte
	// Protocols lists the protocols for format-2 challenges. When empty,
	// format-2 defaults to ["rsw"] exactly like capjs-core.
	Protocols []string
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
	// TokenTTL controls validation token lifetime (default 20 minutes).
	TokenTTL time.Duration
	// Format selects the challenge format. 0 or 1 for format-1 (default),
	// 2 for the multi-protocol format-2.
	Format int
	// RSWT is the sequential squaring count for RSW puzzles (default 75000).
	RSWT int
	// HashwxDifficulty is the expected number of HashWX hashes per solve
	// (default 1,000,000). Only used when Format is 2.
	HashwxDifficulty int
	// HashwxNoncesPerHash is the number of nonces covered by each generated
	// HashWX hash function (default 65,536).
	HashwxNoncesPerHash int
	// HashwxChallengeCount is the number of independent HashWX
	// sub-challenges (default 4).
	HashwxChallengeCount int
	// Instrumentation enables format-1 client-side browser checks.
	Instrumentation bool
}

// Cap is an instance-based API for creating and redeeming challenges.
// Create one via NewCap and reuse it across requests.
type Cap struct {
	validateOpts ValidateOptions
	storage      Storage
	secret       []byte
	generateOpts GenerateOptions
}

// NewCap creates a Cap instance with the given options.
// Secret must be at least 16 bytes. When Format is 2 and Protocols is empty,
// the instance defaults to the "rsw" protocol, matching capjs-core.
func NewCap(opts CapOptions) (*Cap, error) {
	if len(opts.Secret) < 16 {
		return nil, ErrShortSecret
	}

	protocols := opts.Protocols
	if opts.Format == 2 && len(protocols) == 0 {
		protocols = []string{"rsw"}
	}

	rswMinter := opts.Rsw
	if rswMinter == nil && opts.Format == 2 && opts.Keypair != nil &&
		hasProtocol(protocols, "rsw") {
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
			return nil, err
		}

		rswMinter = minter
	}

	secretCopy := make([]byte, len(opts.Secret))
	copy(secretCopy, opts.Secret)

	return &Cap{
		secret:  secretCopy,
		storage: opts.Storage,
		generateOpts: GenerateOptions{
			ChallengeCount:           opts.ChallengeCount,
			ChallengeSize:            opts.ChallengeSize,
			ChallengeDifficulty:      opts.ChallengeDifficulty,
			Expires:                  opts.ChallengeTTL,
			Scope:                    opts.Scope,
			Extra:                    cloneMap(opts.Extra),
			Storage:                  opts.Storage,
			Instrumentation:          opts.Instrumentation,
			InstrumentationOpts:      opts.InstrumentationOpts,
			InstrumentationGenerator: opts.InstrumentationGenerator,
			Format:                   opts.Format,
			Protocols:                protocols,
			Keypair:                  opts.Keypair,
			Rsw:                      rswMinter,
			RSWT:                     opts.RSWT,
			HashwxDifficulty:         opts.HashwxDifficulty,
			HashwxNoncesPerHash:      opts.HashwxNoncesPerHash,
			HashwxChallengeCount:     opts.HashwxChallengeCount,
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
