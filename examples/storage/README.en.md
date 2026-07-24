# Storage Examples

中文版: [README.md](README.md)

This directory contains example implementation documents for `gocap.Storage` backends.

Currently included:

- `rueidis.en.md`: a Redis storage example based on `github.com/redis/rueidis`
- `go-redis-v9.en.md`: a Redis storage example based on `github.com/redis/go-redis/v9`, suitable when your project already uses go-redis

All examples are built around the same `Storage` interface:

```go
type Storage interface {
    SetChallengeToken(ctx context.Context, token string, expiresAt time.Time) error
    GetChallengeTokenExpiry(ctx context.Context, token string) (time.Time, bool, error)
    SetValidationToken(ctx context.Context, token string, expiresAt time.Time) error
    GetValidationTokenExpiry(ctx context.Context, token string) (time.Time, bool, error)
    CleanupExpired(ctx context.Context) error
}
```

Notes:

- Redis-backed versions usually rely on TTL for expiration, so `CleanupExpired` can be a no-op.
- The sample code prioritizes readability and keeps names aligned with the current public API in this repository.
- If you want to use these examples directly in production, add connection pooling, timeouts, observability, and error wrapping.
