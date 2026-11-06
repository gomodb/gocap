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
//	    Solutions: gocap.SolutionsFromNumbers(clientSolutions), // []int64 from the client
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
//   - rsw: Time-lock puzzles based on repeated squaring
//   - hashwx: GPU-resistant PoW with a freshly generated hash function per
//     block (the current capjs-core default for new standalone keys)
//   - instrumentation: Client-side browser integrity checks, including the
//     probe vector and server-side automation detection
//
// Format-2 request bodies accept the official widget shape: solutions are
// sent in the "solutions" array as protocol-specific objects.
//
// # Recommended Configuration
//
// For new deployments, prefer format-2 with the "hashwx" and "instrumentation"
// protocols. HashWX is the most GPU-resistant PoW in Cap, and instrumentation
// adds browser-environment checks. The library defaults are intentionally
// unchanged: format-1 uses sha256-pow, and format-2 defaults to ["rsw"] when
// Protocols is empty.
//
//	cap, err := gocap.NewCap(gocap.CapOptions{
//	    Secret:             secret,
//	    Format:             2,
//	    Protocols:          []string{"hashwx", "instrumentation"},
//	    HashwxDifficulty:   1_000_000,
//	    InstrumentationOpts: &gocap.InstrumentationOptions{
//	        BlockAutomatedBrowsers: true,
//	    },
//	})
//
// Call HashwxReady at startup to compile the embedded HashWX wasm before the
// first request. Use ConsumeNonce (for example a Redis SET NX EX) for replay
// protection. RSW is deprecated upstream; SHA-256 remains available for
// clients without WebAssembly.
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
