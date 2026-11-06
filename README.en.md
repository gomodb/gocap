# gocap

[![Go Reference](https://pkg.go.dev/badge/github.com/gomodb/gocap)](https://pkg.go.dev/github.com/gomodb/gocap)
English | [中文](README.md)

A Go server-side implementation of [CAP](https://github.com/tiagozip/cap), a proof-of-work based CAPTCHA alternative. Supports HashWX / RSW / SHA-256 multi-protocol challenges, browser automation detection, and pluggable storage.

## Features

- **PoW challenges** — Stateless FNV-1a + xorshift salt/target derivation
- **Format-2 multi-protocol** — Combine `sha256-pow` / `rsw` / `hashwx` / `instrumentation` protocols
- **HashWX** — GPU-resistant PoW with a freshly generated hash function per block (the current capjs-core/standalone default)
- **RSW time-lock puzzles** — Repeated-squaring time-lock challenges (deprecated upstream)
- **Instrumentation** — Executable JS probe bundle plus server-side automation detection (`riskFlags` / `blockedBy`, AES-256-GCM encrypted metadata)
- **JWT HS256** — Built-in signing and verification, with optional custom token issuers
- **Replay protection** — One-time use via `ConsumeNonce` callback
- **Pluggable storage** — Unified `Storage` interface with in-memory implementation
- **Sentinel errors** — All failure reasons accessible via `errors.Is`

## Installation

```bash
go get github.com/gomodb/gocap
```

Minimum Go version: 1.27

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
  Solutions: gocap.SolutionsFromNumbers(clientSolutions), // []int64 from the client
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

 cap, err := gocap.NewCap(gocap.CapOptions{
  Secret:    secret,
  Format:    2,
  Protocols: []string{"hashwx", "instrumentation"},
  InstrumentationOpts: &gocap.InstrumentationOptions{
   BlockAutomatedBrowsers: true,
   ObfuscationLevel:       3,
  },
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

> This is the security-first protocol combination. See "Recommended Configuration (Security First)" below for the full production setup (replay protection, TTLs, tuning).

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
| `rsw` | Repeated-squaring time-lock puzzle (deprecated upstream) | Client performs t sequential squarings |
| `hashwx` | GPU-resistant PoW with a per-block hash function | Client searches nonces in WebAssembly |
| `instrumentation` | Browser behavior analysis | Client executes JS and returns state + probe |

## Recommended Configuration (Security First)

As of capjs-core 0.1.6 / standalone 3.1.17, new deployments should prefer **HashWX + instrumentation**:

- **HashWX** is the most GPU-resistant PoW in Cap: a GPU is only about 2x faster than a CPU, versus roughly 150–170x for SHA-256 / RSW.
- **Instrumentation** is a browser-environment layer that complements PoW. It is not a replacement for PoW and is not a cryptographic guarantee on its own.
- **RSW is deprecated upstream** and should not be used for new deployments; keep it only for legacy keys.
- **SHA-256** is for clients without WebAssembly or for a pure-JS fallback.

> gocap's defaults are unchanged: format-1 uses `sha256-pow`, and format-2 defaults to `["rsw"]` when `Protocols` is omitted. Security-first requires explicit configuration.

```go
package main

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/gomodb/gocap"
)

func main() {
	secret := []byte("replace-with-a-32-byte-high-entropy-secret")

	// Optional: warm up HashWX to avoid compiling the embedded wasm on first verify.
	if err := gocap.HashwxReady(); err != nil {
		log.Fatal(err)
	}

	cap, err := gocap.NewCap(gocap.CapOptions{
		Secret:  secret,
		Storage: gocap.NewMemoryStorage(), // replace with Redis/PostgreSQL in production

		Format:    2,
		Protocols: []string{"hashwx", "instrumentation"},

		HashwxDifficulty:     1_000_000, // ~0.5s desktop / 1-6s phone
		HashwxChallengeCount: 4,
		HashwxNoncesPerHash:  65_536,

		InstrumentationOpts: &gocap.InstrumentationOptions{
			BlockAutomatedBrowsers: true, // roll out with riskFlags first
			ObfuscationLevel:       3,
		},

		ChallengeTTL: 10 * time.Minute,
		TokenTTL:     20 * time.Minute,

		ConsumeNonce: func(context.Context, string, time.Duration) (bool, error) {
			// Production: implement one-time consumption, e.g. Redis:
			//   SET cap:nonce:<sig> 1 NX EX <ttl>
			// true = first use, false = replay.
			return false, errors.New("implement ConsumeNonce with Redis SET NX EX")
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()

	// POST /api/cap/challenge
	challenge, err := cap.CreateChallenge(ctx)
	if err != nil {
		log.Fatal(err)
	}
	_ = challenge // returns token / challenges / expires

	// POST /api/cap/redeem
	var body gocap.ValidateBody
	// In a real handler: json.NewDecoder(r.Body).Decode(&body)
	result, err := cap.RedeemChallenge(ctx, body)
	if err != nil {
		log.Fatal(err)
	}
	if !result.Success {
		log.Printf("blocked: %s (blockedBy=%v)", result.Reason, result.BlockedBy)
	}
}
```

### Client Integration

HashWX requires WebAssembly and a widget version that supports it (0.1.58+):

```html
<script type="module" src="https://cdn.jsdelivr.net/npm/cap-widget"></script>
<cap-widget data-cap-api-endpoint="/api/cap/"></cap-widget>
```

The backend only needs `POST /api/cap/challenge` and `POST /api/cap/redeem`, calling `CreateChallenge` and `RedeemChallenge`. Instrumentation probe data is collected by the widget executing the JS bundle that gocap returns inside a browser iframe.

### Protocol Selection

| Scenario | Recommendation | Notes |
|---|---|---|
| New deployment, security first | `hashwx` + `instrumentation` | Best GPU-farm resistance; requires WASM + JS |
| No WebAssembly support | `sha256-pow` (format-1 or format-2) | Raise `ChallengeDifficulty` / `ChallengeCount` to offset GPU advantage |
| Legacy keys / compatibility | `rsw` | Deprecated upstream; do not use for new deployments |
| API-only / no browser | PoW only (`hashwx` or `sha256-pow`) | Do not enable `BlockAutomatedBrowsers` without a probe |
| High-risk workloads | HashWX + instrumentation + edge rate limiting/WAF | PoW raises per-request cost; it is not a rate limiter |

### Tuning and Operations

- `HashwxDifficulty` defaults to `1_000_000`: tune against p90, lower for mobile-heavy traffic, raise for desktop. Work scales roughly linearly.
- `HashwxChallengeCount: 4` splits the total difficulty into four sub-challenges and smooths the tail. Leave `HashwxNoncesPerHash` at its default unless benchmarking.
- `BlockAutomatedBrowsers`: start with `false`, watch `riskFlags` / `blockedBy` for false positives, then enable. Without a probe it returns `instr_probe_missing`.
- `ConsumeNonce`: use Redis `SET NX EX` in production; otherwise the same challenge token can be redeemed repeatedly.
- `Scope`: bind the challenge to a site/action and pass the same scope during validation; use `Extra` for non-sensitive context.
- Rate limiting: gocap is a library and has no built-in limiter; rate-limit challenge/redeem at your gateway or edge.
- Secret: use at least 32 high-entropy bytes and rotate them; never reuse the example string.
- Instrumentation requires a browser to execute the JS bundle; server-side/script clients cannot produce the probe.
- When self-hosting the widget, serve both the widget JS and the HashWX wasm files (see the upstream widget docs).
- HashWX relies on wazero to execute the vendored wasm. If that dependency is unacceptable, use `sha256-pow` / `rsw`, or replace the HashWX engine (see the compatibility notes).

A complete runnable example is available at [`examples/recommended/main.go`](examples/recommended/main.go).

## Compatibility with capjs-core

gocap is aligned with capjs-core 0.1.6:

- Format-2 bodies match the official widget exactly: `solutions` is an array of objects containing only `nonce` / `y` / `instr` / `blocked` / `timeout`, matched to challenges by position. The legacy `v2Sol` field and the per-solution `protocol` field are no longer supported.
- Go API: build `ValidateBody.Solutions` with `gocap.NumberSolutions(...)` (Format-1) or `gocap.ObjectSolutions(...)` (Format-2); it still serializes to the official `solutions` array.
- JSON encoding/decoding uses Go 1.27's `encoding/json/v2`; v1 `encoding/json` is no longer used.
- Supports `hashwx` / `sha256-pow` / `rsw` / `instrumentation`; format-2 defaults to `["rsw"]` when `Protocols` is empty.
- Instrumentation ships a complete `base64(deflate-raw)` JavaScript bundle with probe collection; the server runs `DetectAutomation` and returns the same `riskFlags`, `blockedBy` and `instr_probe_missing` semantics as upstream.
- The 0.1.5 forged-blocked-marker hardening and the 0.1.3 detection layer are included.
- `ObfuscationLevel` 1–3 keeps line breaks, 4–10 compacts; the javascript-obfuscator transformations are not replicated (script semantics and wire format are identical).
- `Storage` / `ValidateToken` are gocap extensions. Default validation tokens are indexed under both the raw `token` and the hashed `tokenKey`; `ValidateToken` accepts either and is not single-use (upstream standalone's `siteverify` uses Redis `GETDEL`).

HashWX runs the upstream vendored `hashwx.wasm` through `wazero` (LGPL-3.0, see `internal/hashwx/LICENSE`), which adds a `github.com/tetratelabs/wazero` dependency.

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

- **Protocol choice**: New deployments should prefer `hashwx` + `instrumentation`; RSW is deprecated. See "Recommended Configuration (Security First)".
- **Secret**: Minimum 16 bytes, 32+ recommended. Generate with `openssl rand -hex 32`.
- **Replay protection**: Use the `ConsumeNonce` callback (e.g. Redis SETNX); without it, a challenge token can be redeemed repeatedly.
- **Instrumentation**: Requires a browser to execute the JS bundle; roll out `BlockAutomatedBrowsers` after watching `riskFlags` / `blockedBy`.
- **Rate limiting**: gocap is a library with no built-in limiter; rate-limit challenge/redeem at your gateway or edge.
- **RSW keys**: `GenerateRswKeypair(2048)` takes a few hundred milliseconds. Generate once at startup and persist.
- **HashWX**: The embedded wasm is compiled on first verification; call `HashwxReady()` at startup to warm it up.
- **Storage**: `MemoryStorage` loses data on restart. Use a persistent backend in production.
