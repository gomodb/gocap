# gocap

[English](README.en.md) | 中文

Go 语言实现的 [CAP](https://github.com/tiagozip/cap) 服务端，一个基于工作量证明（PoW）的验证码替代方案。支持可插拔存储、多协议挑战格式（含 RSW 时间锁谜题）和客户端浏览器检测。

## 特性

- **PoW 挑战** — FNV-1a + xorshift 派生盐值与目标前缀，无状态验证
- **多协议格式 (Format-2)** — 支持 `sha256-pow` / `rsw` / `instrumentation` 协议组合
- **RSW 时间锁谜题** — 基于重复平方运算的量子抵抗型挑战
- **客户端检测** — 浏览器行为分析参数生成与结果验证（AES-256-GCM 加密）
- **JWT HS256** — 内置签名与验证，可选自定义签发
- **重放保护** — 通过 `ConsumeNonce` 回调支持一次性令牌
- **可插拔存储** — 统一的 `Storage` 接口，内置内存实现，可接入 Redis/PostgreSQL 等
- **哨兵错误** — 所有失败原因均可通过 `errors.Is` 判断

## 安装

```bash
go get github.com/gomodb/gocap
```

最低 Go 版本：1.25

## 快速开始

### Format-1：基本 PoW 挑战

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

 // 服务端生成挑战
 challenge, err := cap.CreateChallenge(ctx)
 if err != nil {
  log.Fatal(err)
 }
 fmt.Printf("Challenge: c=%d, s=%d, d=%d\n",
  challenge.Challenge.C,
  challenge.Challenge.S,
  challenge.Challenge.D,
 )
 fmt.Printf("Token: %s\n", challenge.Token)

 // ── 客户端侧：求解 PoW ──
 // 客户端根据 challenge.Challenge 中的 c、s、d 参数暴力搜索 nonce，
 // 使 sha256(salt || nonce) 的前 d 个 hex 字符等于 target。
 // 参考实现见 https://github.com/tiagozip/cap 的前端 widget。

 // 服务端验证
 result, err := cap.RedeemChallenge(ctx, gocap.ValidateBody{
  Token:     challenge.Token,
  Solutions: solutions,
 })
 if err != nil {
  log.Fatal(err)
 }
 if !result.Success {
  log.Fatalf("验证失败: %s", result.Reason)
 }
 fmt.Printf("验证令牌: %s\n", result.Token)

 // 验证令牌有效性
 vr := cap.ValidateToken(ctx, result.Token)
 if errors.Is(vr, gocap.ErrTokenNotFound) {
  log.Fatal("令牌不存在或已过期")
 }
}
```

### Format-2：多协议挑战

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

 // 生成 RSW 密钥对（生产环境应在启动时生成一次并持久化）
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

 // 生成多协议挑战
 challenge, err := cap.CreateChallenge(ctx)
 if err != nil {
  log.Fatal(err)
 }
 _ = challenge
}
```

### 错误判断

```go
result, err := cap.RedeemChallenge(ctx, proof)
if err != nil {
 // 系统级错误（配置、存储等）
}
if !result.Success {
 switch {
 case errors.Is(result, gocap.ErrExpired):
  // 挑战已过期
 case errors.Is(result, gocap.ErrInvalidSolution):
  // PoW 解答错误
 case errors.Is(result, gocap.ErrInstrMissing):
  // 缺少客户端检测数据
 case errors.Is(result, gocap.ErrAlreadyRedeemed):
  // 令牌已被消费（重放攻击）
 }
}
```

## API 总览

### Cap 实例

| 方法 | 说明 |
| ------ | ------ |
| `NewCap(opts)` | 创建实例，secret 至少 16 字节 |
| `CreateChallenge(ctx)` | 生成挑战，返回 token + 参数 |
| `RedeemChallenge(ctx, body)` | 验证 PoW 解，签发验证令牌 |
| `ValidateToken(ctx, token)` | 检查验证令牌是否存在且未过期 |

### 哨兵错误（可通过 `errors.Is` 判断）

| 错误 | 触发条件 |
| ------ | --------- |
| `ErrMissingToken` | 挑战令牌为空 |
| `ErrMissingSolutions` | Solutions 数组为 nil |
| `ErrInvalidToken` | JWT 签名无效或载荷损坏 |
| `ErrScopeMismatch` | scope 不匹配 |
| `ErrExpired` | 挑战或验证令牌过期 |
| `ErrInvalidSolutions` | 解的数量不匹配或包含负数 |
| `ErrInvalidSolution` | PoW 解不正确 |
| `ErrAlreadyRedeemed` | 令牌已被消费 |
| `ErrNonceStoreError` | ConsumeNonce 回调失败 |
| `ErrStorageNotConfigured` | 未配置 Storage |
| `ErrCleanupError` | 存储清理失败 |
| `ErrStorageError` | 存储读写失败 |
| `ErrTokenNotFound` | 验证令牌不存在 |
| `ErrTokenExpired` | 验证令牌已过期 |
| `ErrInstrCorrupted` | 检测元数据损坏 |
| `ErrInstrExpired` | 检测元数据过期 |
| `ErrInstrAutomatedBrowser` | 检测到自动化浏览器 |
| `ErrInstrTimeout` | 检测超时 |
| `ErrInstrFailed` | 检测验证失败 |
| `ErrInstrMissing` | 缺少检测结果 |

### 存储接口

```go
type Storage interface {
 SetChallengeToken(ctx, token, expiresAt) error
 GetChallengeTokenExpiry(ctx, token) (time.Time, bool, error)
 SetValidationToken(ctx, token, expiresAt) error
 GetValidationTokenExpiry(ctx, token) (time.Time, bool, error)
 CleanupExpired(ctx) error
}
```

内置 `MemoryStorage` 适用于开发测试。生产环境请实现 `Storage` 接口接入 Redis、PostgreSQL 等后端，参见 `examples/storage/`。

## Format-2 协议参考

| 协议 | 说明 | 求解方式 |
| ------ | ------ | --------- |
| `sha256-pow` | 标准 SHA-256 前缀匹配 PoW | 客户端暴力搜索 nonce |
| `rsw` | 基于重复平方的时间锁谜题 | 客户端执行 t 次连续平方运算 |
| `instrumentation` | 浏览器行为分析 | 客户端执行检测脚本并返回结果 |

## 其他 Go 实现

- [ackcoder/go-cap](https://github.com/ackcoder/go-cap) — 另一 CAP 服务端 Go 实现
- [samwafgo/cap_go_server](https://github.com/samwafgo/cap_go_server) — CAP 验证服务器 Go 实现

## 运行测试

```bash
go test ./... -v
# 跳过耗时测试（如 2048 位 RSA 密钥生成）
go test ./... -short
```

## 安全注意事项

- **Secret**：至少 16 字节，建议 32+ 字节高强度随机值。生成：`openssl rand -hex 32`
- **重放保护**：通过 `ConsumeNonce` 回调实现（如 Redis SETNX）
- **RSW 密钥**：`GenerateRswKeypair(2048)` 约耗时数百毫秒，启动时生成一次并持久化
- **存储**：`MemoryStorage` 重启后数据丢失，生产环境请使用持久化后端
