# gocap

[![Go Reference](https://pkg.go.dev/badge/github.com/gomodb/gocap)](https://pkg.go.dev/github.com/gomodb/gocap)
English | [中文](README.md)

A Go server-side implementation of [CAP](https://github.com/tiagozip/cap), a proof-of-work based CAPTCHA alternative. Supports pluggable storage, multi-protocol challenges (including RSW time-lock puzzles), and client-side instrumentation.

## Features

- **PoW challenges** — Stateless FNV-1a + xorshift salt/target derivation
- **Format-2 multi-protocol** — Combine `sha256-pow` / `rsw` / `instrumentation` protocols
- **RSW time-lock puzzles** — Quantum-resistant repeated-squaring challenges
- **Instrumentation** — Browser behavior analysis with AES-256-GCM encrypted metadata
- **JWT HS256** — Built-in signing and verification, with optional custom token issuers
- **Replay protection** — One-time use via `ConsumeNonce` callback
- **Pluggable storage** — Unified `Storage` interface with in-memory implementation
- **Sentinel errors** — All failure reasons accessible via `errors.Is`

## Installation

```bash
go get github.com/gomodb/gocap
```

Minimum Go version: 1.25

## Quick Start

### Format-1: Basic PoW Challenge

```go
package main

import (
 "context"
 "errors"
 "log"

 "github.com/gomodb/gocap"
)

func main() {
 secret := []byte("32-byte-high-entropy-secret-for-signing!")
 ctx := context.Background()

 cap, err := gocap.NewCap(gocap.CapOptions{
  Secret:              secret,
  Storage:             gocap.NewMemoryStorage(),
  ChallengeCount:      1,
  ChallengeSize:       8,
  ChallengeDifficulty: 1,
 })
 if err != nil {
  log.Fatal(err)
 }

 // Server generates a challenge
 challenge, err := cap.CreateChallenge(ctx)
 if err != nil {
  log.Fatal(err)
 }
 log.Printf("Challenge: c=%d, s=%d, d=%d",
  challenge.Challenge.C,
  challenge.Challenge.S,
  challenge.Challenge.D,
 )

 // ── Client-side: solve the PoW ──
 // The client brute-forces nonces until sha256(salt || nonce) starts
 // with the required target prefix. See the CAP widget SDK for a
 // production-ready solver.

 // Server verifies the solutions
 result, err := cap.RedeemChallenge(ctx, gocap.ValidateBody{
  Token:     challenge.Token,
  Solutions: clientSolutions, // []int64 from the client
 })
 if err != nil {
  log.Fatal(err)
 }
 if !result.Success {
  log.Fatalf("validation failed: %s", result.Reason)
 }
 log.Printf("validation token: %s", result.Token)

 // Verify the issued token
 vr := cap.ValidateToken(ctx, result.Token)
 if errors.Is(vr, gocap.ErrTokenNotFound) {
  log.Fatal("token not found or expired")
 }
}
```

### Error Handling

```go
result, err := cap.RedeemChallenge(ctx, proof)
if err != nil {
 // System-level error (config, storage, etc.)
}
if !result.Success {
 switch {
 case errors.Is(result, gocap.ErrExpired):
  // Challenge expired
 case errors.Is(result, gocap.ErrInvalidSolution):
  // Wrong PoW solution
 case errors.Is(result, gocap.ErrInstrMissing):
  // Instrumentation data missing
 case errors.Is(result, gocap.ErrAlreadyRedeemed):
  // Replay attack detected
 }
}
```

### Format-2: Multi-Protocol Challenge

```go
package main

import (
 "context"
 "log"

 "github.com/gomodb/gocap"
)

func main() {
 secret := []byte("32-byte-high-entropy-secret-for-signing!")
 ctx := context.Background()

 // Generate an RSW keypair (do once at startup, persist for reuse)
 kp, err := gocap.GenerateRswKeypair(2048)
 if err != nil {
  log.Fatal(err)
 }

 cap, err := gocap.NewCap(gocap.CapOptions{
  Secret:    secret,
  Storage:   gocap.NewMemoryStorage(),
  Format:    2,
  Protocols: []string{"sha256-pow", "rsw"},
  Keypair:   kp,
 })
 if err != nil {
  log.Fatal(err)
 }

 challenge, err := cap.CreateChallenge(ctx)
 if err != nil {
  log.Fatal(err)
 }
 _ = challenge
}
```

## API Reference

### Cap Methods

| Method | Description |
| -------- | ------------- |
| `NewCap(opts)` | Create a Cap instance (secret must be >= 16 bytes) |
| `CreateChallenge(ctx)` | Generate a challenge, returns token + parameters |
| `RedeemChallenge(ctx, body)` | Verify PoW solutions, issue a validation token |
| `ValidateToken(ctx, token)` | Check a validation token exists and is not expired |

### Sentinel Errors (use with `errors.Is`)

| Error | Condition |
| ------- | ----------- |
| `ErrMissingToken` | Challenge token is empty |
| `ErrMissingSolutions` | Solutions array is nil |
| `ErrInvalidToken` | JWT signature invalid or payload corrupted |
| `ErrScopeMismatch` | Scope does not match |
| `ErrExpired` | Challenge or validation token expired |
| `ErrInvalidSolutions` | Solution count mismatch or negative nonce |
| `ErrInvalidSolution` | PoW solution is incorrect |
| `ErrAlreadyRedeemed` | Token already consumed (replay) |
| `ErrNonceStoreError` | ConsumeNonce callback failed |
| `ErrStorageNotConfigured` | No Storage configured |
| `ErrCleanupError` | Storage cleanup failed |
| `ErrStorageError` | Storage read/write failed |
| `ErrTokenNotFound` | Validation token not found |
| `ErrTokenExpired` | Validation token expired |
| `ErrInstrCorrupted` | Instrumentation metadata corrupted |
| `ErrInstrExpired` | Instrumentation metadata expired |
| `ErrInstrAutomatedBrowser` | Automated browser detected |
| `ErrInstrTimeout` | Instrumentation timed out |
| `ErrInstrFailed` | Instrumentation verification failed |
| `ErrInstrMissing` | Instrumentation result missing |

### Storage Interface

```go
type Storage interface {
 SetChallengeToken(ctx, token, expiresAt) error
 GetChallengeTokenExpiry(ctx, token) (time.Time, bool, error)
 SetValidationToken(ctx, token, expiresAt) error
 GetValidationTokenExpiry(ctx, token) (time.Time, bool, error)
 CleanupExpired(ctx) error
}
```

A built-in `MemoryStorage` is provided for development. For production, implement the interface with Redis, PostgreSQL, etc. See `examples/storage/`.

## Format-2 Protocol Reference

| Protocol | Description | Solving |
| -------- | ----------- | ------- |
| `sha256-pow` | Standard SHA-256 prefix PoW | Brute-force nonce search |
| `rsw` | Repeated-squaring time-lock puzzle | Client performs t sequential squarings |
| `instrumentation` | Browser behavior analysis | Client executes probing script |

## Other Go Implementations

- [ackcoder/go-cap](https://github.com/ackcoder/go-cap) — Another CAP server-side Go implementation
- [samwafgo/cap_go_server](https://github.com/samwafgo/cap_go_server) — CAP verification server Go implementation

## Running Tests

```bash
go test ./... -v
# Skip slow tests (e.g. 2048-bit RSA key generation)
go test ./... -short
```

## Security Considerations

- **Secret**: Minimum 16 bytes, 32+ recommended. Generate with `openssl rand -hex 32`.
- **Replay protection**: Use the `ConsumeNonce` callback (e.g. Redis SETNX).
- **RSW keys**: `GenerateRswKeypair(2048)` takes a few hundred milliseconds. Generate once at startup and persist.
- **Storage**: `MemoryStorage` loses data on restart. Use a persistent backend in production.
