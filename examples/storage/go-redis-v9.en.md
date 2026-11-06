# go-redis v9 Storage Example

中文版: [go-redis-v9.md](go-redis-v9.md)

This example shows how to implement `gocap.Storage` with `github.com/redis/go-redis/v9`.

If your project already uses go-redis broadly, this version is usually easier to integrate into existing infrastructure.

## Dependency

```bash
go get github.com/redis/go-redis/v9
```

## Example Code

```go
package storage

import (
    "context"
    "errors"
    "strconv"
    "time"

    "github.com/redis/go-redis/v9"
)

const (
    defaultRedisAddress          = "127.0.0.1:6379"
    defaultChallengeTokenPrefix  = "gocap:challenge:"
    defaultValidationTokenPrefix = "gocap:validation:"
)

type RedisStorageOptions struct {
    Address               string
    Password              string
    DB                    int
    ChallengeTokenPrefix  string
    ValidationTokenPrefix string
}

type RedisStorage struct {
    client                redis.UniversalClient
    challengeTokenPrefix  string
    validationTokenPrefix string
}

func NewRedisStorageWithClient(client redis.UniversalClient, opts RedisStorageOptions) *RedisStorage {
    challengePrefix, validationPrefix := normalizeRedisPrefixes(opts)
    return &RedisStorage{
        client:                client,
        challengeTokenPrefix:  challengePrefix,
        validationTokenPrefix: validationPrefix,
    }
}

func NewRedisStorage(opts RedisStorageOptions) *RedisStorage {
    address := opts.Address
    if address == "" {
        address = defaultRedisAddress
    }

    client := redis.NewClient(&redis.Options{
        Addr:     address,
        Password: opts.Password,
        DB:       opts.DB,
    })

    return NewRedisStorageWithClient(client, opts)
}

func (s *RedisStorage) Close() error {
    if s.client == nil {
        return nil
    }
    return s.client.Close()
}

func (s *RedisStorage) SetChallengeToken(ctx context.Context, token string, expiresAt time.Time) error {
    return s.setToken(ctx, s.challengeTokenPrefix, token, expiresAt)
}

func (s *RedisStorage) GetChallengeTokenExpiry(ctx context.Context, token string) (time.Time, bool, error) {
    return s.getTokenExpiry(ctx, s.challengeTokenPrefix, token)
}

func (s *RedisStorage) SetValidationToken(ctx context.Context, token string, expiresAt time.Time) error {
    return s.setToken(ctx, s.validationTokenPrefix, token, expiresAt)
}

func (s *RedisStorage) GetValidationTokenExpiry(ctx context.Context, token string) (time.Time, bool, error) {
    return s.getTokenExpiry(ctx, s.validationTokenPrefix, token)
}

func (s *RedisStorage) CleanupExpired(context.Context) error {
    return nil
}

func (s *RedisStorage) setToken(ctx context.Context, prefix, token string, expiresAt time.Time) error {
    key := prefix + token
    ttl := expiresAt.Sub(time.Now())
    if ttl < time.Second {
        ttl = time.Second
    }

    value := strconv.FormatInt(expiresAt.UnixMilli(), 10)
    return s.client.Set(ctx, key, value, ttl).Err()
}

func (s *RedisStorage) getTokenExpiry(ctx context.Context, prefix, token string) (time.Time, bool, error) {
    key := prefix + token
    value, err := s.client.Get(ctx, key).Result()
    if err != nil {
        if errors.Is(err, redis.Nil) {
            return time.Time{}, false, nil
        }
        return time.Time{}, false, err
    }

    ms, err := strconv.ParseInt(value, 10, 64)
    if err != nil {
        return time.Time{}, false, err
    }

    return time.UnixMilli(ms), true, nil
}

func normalizeRedisPrefixes(opts RedisStorageOptions) (string, string) {
    challengePrefix := opts.ChallengeTokenPrefix
    if challengePrefix == "" {
        challengePrefix = defaultChallengeTokenPrefix
    }

    validationPrefix := opts.ValidationTokenPrefix
    if validationPrefix == "" {
        validationPrefix = defaultValidationTokenPrefix
    }

    return challengePrefix, validationPrefix
}
```

## Notes

- This version uses `redis.UniversalClient`, which makes it easier to grow into Sentinel or Cluster later.
- `NewRedisStorage` returns a usable instance directly. If you want connectivity checks during startup, call `client.Ping(ctx)` separately.
- Like the rueidis version, a missing key returns `(time.Time{}, false, nil)` so the behavior matches the `Storage` contract.

## Usage with Cap Instance

```go
package main

import (
 "context"
 "fmt"
 "log"

 "github.com/gomodb/gocap"
)

func main() {
 ctx := context.Background()
 secret := []byte("meow-meow-meow-meow-dont-use-in-prod-meow-meow-meow-meow")

 store := NewRedisStorage(RedisStorageOptions{
  Address: "127.0.0.1:6379",
 })

 cap, err := gocap.NewCap(gocap.CapOptions{
  Secret:              secret,
  Storage:             store,
  ChallengeCount:      50,
  ChallengeSize:       32,
  ChallengeDifficulty: 4,
 })
 if err != nil {
  log.Fatal(err)
 }

 challenge, err := cap.CreateChallenge(ctx)
 if err != nil {
  log.Fatal(err)
 }
 fmt.Println("challenge token:", challenge.Token)

 // solutions are submitted by the client after solving the PoW
 result, err := cap.RedeemChallenge(ctx, gocap.ValidateBody{
  Token:     challenge.Token,
  Solutions: gocap.SolutionsFromNumbers([]int64{1, 2, 3}), // actual values come from the client
 })
 if err != nil {
  log.Fatal(err)
 }
 if !result.Success {
  log.Fatalf("validation failed: %s", result.Reason)
 }
 fmt.Println("validation token:", result.Token)

 if vr := cap.ValidateToken(ctx, result.Token); vr.Success {
  fmt.Println("token is valid")
 }
}
```

## Good Fit When

- Your project already uses `github.com/redis/go-redis/v9`.
- You want to reuse existing Redis middleware, hooks, tracing, or observability infrastructure.
- You prefer the higher-level API style of go-redis.
