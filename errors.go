package gocap

import "errors"

// Sentinel errors for challenge validation and token verification.
// Use errors.Is(result, ErrXXX) to check the failure reason.
var (
	// ErrMissingToken is returned when the challenge token is empty.
	ErrMissingToken = errors.New("missing_token")
	// ErrMissingSolutions is returned when the solutions array is nil.
	ErrMissingSolutions = errors.New("missing_solutions")
	// ErrInvalidToken is returned when the JWT is malformed, tampered, or
	// has an invalid signature.
	ErrInvalidToken = errors.New("invalid_token")
	// ErrScopeMismatch is returned when the requested scope doesn't match
	// the scope embedded in the challenge token.
	ErrScopeMismatch = errors.New("scope_mismatch")
	// ErrExpired is returned when the challenge or validation token has
	// exceeded its time-to-live.
	ErrExpired = errors.New("expired")
	// ErrInvalidSolutions is returned when the number of solutions doesn't
	// match the challenge count or a solution is negative.
	ErrInvalidSolutions = errors.New("invalid_solutions")
	// ErrInvalidSolution is returned when a PoW solution doesn't produce
	// a hash with the required target prefix.
	ErrInvalidSolution = errors.New("invalid_solution")
	// ErrAlreadyRedeemed is returned by the ConsumeNonce callback when the
	// challenge token signature has already been used.
	ErrAlreadyRedeemed = errors.New("already_redeemed")
	// ErrNonceStoreError is returned when the ConsumeNonce callback itself
	// fails (e.g. a storage backend error).
	ErrNonceStoreError = errors.New("nonce_store_error")
	// ErrStorageNotConfigured is returned by ValidateToken when no Storage
	// was provided to the Cap instance.
	ErrStorageNotConfigured = errors.New("storage_not_configured")
	// ErrCleanupError is returned when the storage's CleanupExpired call fails.
	ErrCleanupError = errors.New("cleanup_error")
	// ErrStorageError is returned when a storage Get/Set operation fails.
	ErrStorageError = errors.New("storage_error")
	// ErrTokenNotFound is returned when the validation token is not found
	// in storage.
	ErrTokenNotFound = errors.New("token_not_found")
	// ErrTokenExpired is returned when the validation token exists but has
	// passed its expiration time.
	ErrTokenExpired = errors.New("token_expired")
	// ErrInstrCorrupted is returned when the instrumentation metadata
	// cannot be decrypted or parsed.
	ErrInstrCorrupted = errors.New("instr_corrupted")
	// ErrInstrExpired is returned when the instrumentation metadata has
	// exceeded its expiration time.
	ErrInstrExpired = errors.New("instr_expired")
	// ErrInstrAutomatedBrowser is returned when the instrumentation
	// detected an automated browser and BlockAutomatedBrowsers is enabled.
	ErrInstrAutomatedBrowser = errors.New("instr_automated_browser")
	// ErrInstrTimeout is returned when the instrumentation timed out.
	ErrInstrTimeout = errors.New("instr_timeout")
	// ErrInstrFailed is returned when the instrumentation result
	// verification fails unexpectedly.
	ErrInstrFailed = errors.New("instr_failed")
	// ErrInstrMissing is returned when instrumentation is required but
	// no instrumentation result was provided.
	ErrInstrMissing = errors.New("instr_missing")
	// ErrShortSecret is returned by NewCap when Secret is shorter than 16 bytes.
	ErrShortSecret = errors.New("secret must be at least 16 bytes")
	// ErrFormat2NoProtocols is returned by NewCap when Format is 2 but no
	// protocols are specified.
	ErrFormat2NoProtocols = errors.New("format-2 requires at least one protocol")
	// ErrRSWBitsMustBeEven is returned by GenerateRswKeypair when bits is odd.
	ErrRSWBitsMustBeEven = errors.New("rsw bits must be even")
	// ErrRSWKeypairRequired is returned when format-2 rsw protocol is used
	// without providing a keypair.
	ErrRSWKeypairRequired = errors.New("format-2 rsw requires opts.Keypair")
)
