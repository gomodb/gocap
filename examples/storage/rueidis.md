# Rueidis 存储示例

这个示例展示如何使用 `github.com/redis/rueidis` 实现 `gocap.Storage`。

核心思路是：

- 令牌作为 Redis key 的一部分。
- 过期时间以 Unix 毫秒时间戳形式写入 value。
- Redis key 的 TTL 与 `expiresAt` 保持一致。
- 读取时先取 value，再反解为 `time.Time`。

## 依赖

```bash
go get github.com/redis/rueidis
```

## 示例代码

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

## 说明

- 如果项目已经统一维护了 `rueidis.Client`，优先使用 `NewRedisStorageWithClient`，避免重复创建连接。
- TTL 最短被钳制为 `1s`，用于规避极短剩余生命周期导致的立即过期问题。
- 使用 `rueidis.IsRedisNil(err)` 区分键不存在和真实 Redis 错误。

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

- 你已经在项目中使用 `rueidis`。
- 更关注 Redis 协议层性能与较低分配开销。
- 想基于 `gocap.Storage` 自行落地一个 Redis 后端。
