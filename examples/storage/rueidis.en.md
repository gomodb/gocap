# Rueidis Storage Example

中文版: [rueidis.md](rueidis.md)

This example shows how to implement `gocap.Storage` with `github.com/redis/rueidis`.

Core ideas:

- Use the token as part of the Redis key.
- Store the expiry as a Unix millisecond timestamp in the value.
- Keep the Redis key TTL aligned with `expiresAt`.
- Read the stored value back and convert it to `time.Time`.

## Dependency

```bash
go get github.com/redis/rueidis
```

## Example Code

```go
package storage

import (
    "context"
    "strconv"
    "time"

    "github.com/redis/rueidis"
)

const (
    defaultRedisAddress          = "127.0.0.1:6379"
    defaultChallengeTokenPrefix  = "gocap:challenge:"
    defaultValidationTokenPrefix = "gocap:validation:"
)

type RedisStorageOptions struct {
    Address               string
    ChallengeTokenPrefix  string
    ValidationTokenPrefix string
}

type RedisStorage struct {
    client                rueidis.Client
    challengeTokenPrefix  string
    validationTokenPrefix string
}

func NewRedisStorageWithClient(client rueidis.Client, opts RedisStorageOptions) *RedisStorage {
    challengePrefix, validationPrefix := normalizeRedisPrefixes(opts)
    return &RedisStorage{
        client:                client,
        challengeTokenPrefix:  challengePrefix,
        validationTokenPrefix: validationPrefix,
    }
}

func NewRedisStorage(opts RedisStorageOptions) (*RedisStorage, error) {
    address := opts.Address
    if address == "" {
        address = defaultRedisAddress
    }

    challengePrefix, validationPrefix := normalizeRedisPrefixes(opts)
    client, err := rueidis.NewClient(rueidis.ClientOption{InitAddress: []string{address}})
    if err != nil {
        return nil, err
    }

    return &RedisStorage{
        client:                client,
        challengeTokenPrefix:  challengePrefix,
        validationTokenPrefix: validationPrefix,
    }, nil
}

func (s *RedisStorage) Close() {
    if s.client != nil {
        s.client.Close()
    }
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
    cmd := s.client.B().Set().Key(key).Value(value).PxMilliseconds(ttl.Milliseconds()).Build()
    return s.client.Do(ctx, cmd).Error()
}

func (s *RedisStorage) getTokenExpiry(ctx context.Context, prefix, token string) (time.Time, bool, error) {
    key := prefix + token
    cmd := s.client.B().Get().Key(key).Build()
    resp := s.client.Do(ctx, cmd)

    value, err := resp.ToString()
    if err != nil {
        if rueidis.IsRedisNil(err) {
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

- If your project already manages a shared `rueidis.Client`, prefer `NewRedisStorageWithClient` to avoid duplicate connections.
- The TTL is clamped to at least `1s` to avoid immediate expiration when the remaining lifetime is extremely short.
- Use `rueidis.IsRedisNil(err)` to distinguish a missing key from a real Redis error.

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
  Solutions: []int64{1, 2, 3}, // actual values come from the client
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

- Your project already uses `rueidis`.
- You care more about Redis protocol-level performance and lower allocation overhead.
- You want to build a Redis backend on top of `gocap.Storage`.
