# go-redis v9 存储示例

这个示例展示如何使用 `github.com/redis/go-redis/v9` 实现 `gocap.Storage`。

如果你的项目已经广泛使用 go-redis，这个版本通常更容易直接接入现有基础设施。

## 依赖

```bash
go get github.com/redis/go-redis/v9
```

## 示例代码

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

## 说明

- 这里使用 `redis.UniversalClient`，这样后续切换到 Sentinel 或 Cluster 时更容易平滑扩展。
- `NewRedisStorage` 返回可直接使用的实例；如果你希望在初始化阶段先做连通性检查，可以额外调用 `client.Ping(ctx)`。
- 与 rueidis 版本一样，键不存在时返回 `(time.Time{}, false, nil)`，与 `Storage` 语义保持一致。

## 接入 Cap 实例

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

 // solutions 由客户端 PoW 计算后提交
 result, err := cap.RedeemChallenge(ctx, gocap.ValidateBody{
  Token:     challenge.Token,
  Solutions: []int64{1, 2, 3}, // 实际值来自客户端解答
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

## 适用场景

- 你的项目已经使用 `github.com/redis/go-redis/v9`。
- 你希望复用现有的 Redis 中间件、Hook、Tracing 或监控设施。
- 你更偏好 go-redis 的高层 API 风格。
