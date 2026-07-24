// Package gocap provides a server-side implementation of Cap, a proof-of-work
// based CAPTCHA alternative. It generates cryptographic challenges that clients
// must solve, then verifies the solutions and issues validation tokens.
//
// # Quick Start
//
//	secret := []byte("32-byte-high-entropy-secret-for-signing")
//	store := gocap.NewMemoryStorage()
//
//	cap, err := gocap.NewCap(gocap.CapOptions{
//	    Secret:  secret,
//	    Storage: store,
//	})
//
//	// Generate a challenge
//	challenge, err := cap.CreateChallenge(ctx)
//	// Send challenge.Token, challenge.Challenge (c, s, d) to the client
//
//	// Verify the client's PoW solutions
//	result, err := cap.RedeemChallenge(ctx, gocap.ValidateBody{
//	    Token:     challenge.Token,
//	    Solutions: clientSolutions, // []int64 from the client
//	})
//	if errors.Is(result, gocap.ErrInvalidSolution) {
//	    // PoW verification failed
//	}
//
//	// Validate the issued token
//	vr := cap.ValidateToken(ctx, result.Token)
//	if errors.Is(vr, gocap.ErrTokenNotFound) {
//	    // Token not found or expired
//	}
//
// # Challenge Formats
//
// Format-1 (default): A stateless SHA-256 proof-of-work challenge. The server
// derives salt and target values from the token itself using FNV-1a and xorshift
// PRNG, so no server-side storage is required for challenge verification.
//
// Format-2 (opt-in): A multi-protocol challenge framework supporting:
//   - sha256-pow: Standard PoW with random salt per item
//   - rsw: Time-lock puzzles based on repeated squaring (quantum-resistant)
//   - instrumentation: Client-side browser integrity checks
//
// # Sentinel Errors
//
// All validation failures are returned as ValidateResult values that implement
// the error interface. Use errors.Is() to check specific failure reasons:
//
//	if errors.Is(result, gocap.ErrExpired) { /* challenge expired */ }
//	if errors.Is(result, gocap.ErrInvalidSolution) { /* PoW wrong */ }
//
// # Storage
//
// The Storage interface allows plugging in custom backends for challenge and
// validation token persistence. A built-in MemoryStorage is provided for
// development and testing. For production, implement the Storage interface
// with Redis, PostgreSQL, or any other backend.
package gocap
