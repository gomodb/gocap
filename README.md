# gocap

[![Go Reference](https://pkg.go.dev/badge/github.com/gomodb/gocap)](https://pkg.go.dev/github.com/gomodb/gocap)
[English](README.en.md) | 中文

Go 语言实现的 [CAP](https://github.com/tiagozip/cap) 服务端，一个基于工作量证明（PoW）的验证码替代方案。支持 HashWX / RSW / SHA-256 多协议挑战、浏览器自动化检测、可插拔存储。

## 特性

- **PoW 挑战** — FNV-1a + xorshift 派生盐值与目标前缀，无状态验证
- **多协议格式 (Format-2)** — 支持 `sha256-pow` / `rsw` / `hashwx` / `instrumentation` 协议组合
- **HashWX** — 每个 block 生成独立哈希函数的 GPU 抗性 PoW（当前 capjs-core/standalone 默认）
- **RSW 时间锁谜题** — 基于重复平方运算的时序挑战（上游已标记 deprecated）
- **客户端检测** — 生成可执行的 JS 检测脚本、probe 向量，并在服务端执行自动化检测（`riskFlags` / `blockedBy`，AES-256-GCM 加密元数据）
- **JWT HS256** — 内置签名与验证，可选自定义签发
- **重放保护** — 通过 `ConsumeNonce` 回调支持一次性令牌
- **可插拔存储** — 统一的 `Storage` 接口，内置内存实现，可接入 Redis/PostgreSQL 等
- **哨兵错误** — 所有失败原因均可通过 `errors.Is` 判断

## 安装

```bash
go get github.com/gomodb/gocap
```

最低 Go 版本：1.27

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
  Solutions: gocap.SolutionsFromNumbers(solutions),
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

> 这是安全优先的推荐协议组合。完整生产配置（重放保护、TTL、调优）见下文“推荐配置（安全优先）”。

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
| `rsw` | 基于重复平方的时间锁谜题（上游已 deprecated） | 客户端执行 t 次连续平方运算 |
| `hashwx` | GPU 抗性 PoW，每个 block 使用独立哈希函数 | 客户端用 WebAssembly 搜索 nonce |
| `instrumentation` | 浏览器行为分析 | 客户端执行 JS 脚本并返回 state + probe |

## 推荐配置（安全优先）

截至 capjs-core 0.1.6 / standalone 3.1.17，新部署推荐 **HashWX + instrumentation**：

- **HashWX** 是当前抗 GPU 批量求解能力最好的 PoW：GPU 相对 CPU 仅约 2x，而 SHA-256 / RSW 约 150–170x。
- **instrumentation** 是浏览器环境检测层，与 PoW 叠加使用；它不是 PoW 的替代品，也不能单独作为密码学保证。
- **RSW 已被上游标记 deprecated**，不建议用于新部署；仅保留给旧 key / 兼容场景。
- **SHA-256** 仅用于不支持 WebAssembly 的旧客户端，或需要纯 JS 回退的场景。

> gocap 的默认值保持不变：Format-1 默认 `sha256-pow`；Format-2 省略 `Protocols` 时默认 `["rsw"]`。安全优先需要显式配置。

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

	// 可选：预热 HashWX，避免第一次校验时编译内嵌 wasm
	if err := gocap.HashwxReady(); err != nil {
		log.Fatal(err)
	}

	cap, err := gocap.NewCap(gocap.CapOptions{
		Secret:  secret,
		Storage: gocap.NewMemoryStorage(), // 生产环境替换为 Redis/PostgreSQL 实现

		Format:    2,
		Protocols: []string{"hashwx", "instrumentation"},

		HashwxDifficulty:     1_000_000, // 约 0.5s 桌面 / 1–6s 手机
		HashwxChallengeCount: 4,
		HashwxNoncesPerHash:  65_536,

		InstrumentationOpts: &gocap.InstrumentationOptions{
			BlockAutomatedBrowsers: true, // 建议先观察 riskFlags 再开启
			ObfuscationLevel:       3,
		},

		ChallengeTTL: 10 * time.Minute,
		TokenTTL:     20 * time.Minute,

		ConsumeNonce: func(context.Context, string, time.Duration) (bool, error) {
			// 生产环境必须实现一次性消费，例如 Redis:
			//   SET cap:nonce:<sig> 1 NX EX <ttl>
			// 返回 true = 首次使用，false = 重放。
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
	_ = challenge // 返回 token / challenges / expires

	// POST /api/cap/redeem
	var body gocap.ValidateBody
	// 实际 handler: json.NewDecoder(r.Body).Decode(&body)
	result, err := cap.RedeemChallenge(ctx, body)
	if err != nil {
		log.Fatal(err)
	}
	if !result.Success {
		log.Printf("blocked: %s (blockedBy=%v)", result.Reason, result.BlockedBy)
	}
}
```

### 客户端集成

HashWX 需要 WebAssembly，以及支持 HashWX 的官方 widget（0.1.58+）：

```html
<script type="module" src="https://cdn.jsdelivr.net/npm/cap-widget"></script>
<cap-widget data-cap-api-endpoint="/api/cap/"></cap-widget>
```

后端只需提供 `POST /api/cap/challenge` 和 `POST /api/cap/redeem`，分别调用 `CreateChallenge` 和 `RedeemChallenge`。instrumentation 的 probe 由 widget 在浏览器 iframe 中执行 gocap 下发的 JS 得到。

### 协议选择

| 场景 | 推荐 | 说明 |
|---|---|---|
| 新部署、安全优先 | `hashwx` + `instrumentation` | 抗 GPU 农场最好；需要 WASM + JS |
| 客户端不支持 WASM | `sha256-pow`（Format-1 或 Format-2） | 提高 `ChallengeDifficulty` / `ChallengeCount` 弥补 GPU 优势 |
| 旧 key / 兼容 | `rsw` | 上游已 deprecated，不要用于新部署 |
| 纯 API / 无浏览器 | 仅 PoW（`hashwx` 或 `sha256-pow`） | 没有 probe 时不要开 `BlockAutomatedBrowsers` |
| 高风险业务 | HashWX + instrumentation + 网关限流/WAF | PoW 只提高单次成本，不替代限流 |

### 调优与部署要点

- `HashwxDifficulty` 默认 `1_000_000`：按 p90 调整；移动端多则降低，桌面为主可提高。工作量与 difficulty 近似线性。
- `HashwxChallengeCount: 4`：把总难度拆成 4 个子挑战，平滑尾延迟；不要随意改 `HashwxNoncesPerHash`。
- `BlockAutomatedBrowsers`：先设为 `false`，观察 `riskFlags` / `blockedBy` 的误杀，再开启；开启后无 probe 会返回 `instr_probe_missing`。
- `ConsumeNonce`：生产环境必须接 Redis `SET NX EX`，否则同一个 challenge token 可重复兑换。
- `Scope`：绑定站点/业务动作，验证时传相同的 scope；`Extra` 可携带业务上下文（不要放敏感信息）。
- 限流：gocap 是库，不内置限流/封禁；请在网关/边缘层限制 challenge/redeem 频率。
- Secret：≥32 字节高熵值，定期轮换；不要复用示例字符串。
- instrumentation 依赖浏览器执行 gocap 下发的 JS；纯服务端/脚本客户端无法完成 probe。
- self-host widget 时需同时托管 widget JS 和 HashWX 的 wasm 文件（见上游 widget 文档）。
- HashWX 依赖 wazero 执行 vendored wasm；如果无法接受该依赖，只能选择 `sha256-pow` / `rsw`，或自行替换 HashWX 引擎（见兼容性说明）。

完整可运行示例见 [`examples/recommended/main.go`](examples/recommended/main.go)。

## 与 capjs-core 的兼容性

gocap 已对齐上游 capjs-core 0.1.6 的协议与行为：

- Format-2 请求体与官方 widget 完全一致：`solutions` 为对象数组，元素只含 `nonce` / `y` / `instr` / `blocked` / `timeout`，按挑战顺序匹配；不再支持旧的 `v2Sol` 字段或 solution 内的 `protocol` 字段。
- Go API：`ValidateBody.Solutions` 可用 `gocap.NumberSolutions(...)`（Format-1）或 `gocap.ObjectSolutions(...)`（Format-2）构造；序列化后仍是官方的 `solutions` 数组。
- JSON 编解码统一使用 Go 1.27 的 `encoding/json/v2`，不再依赖 v1 `encoding/json`。
- 支持 `hashwx` / `sha256-pow` / `rsw` / `instrumentation`；format-2 省略 `Protocols` 时默认 `["rsw"]`。
- instrumentation 下发 `base64(deflate-raw)` 的完整 JS 脚本，包含探测代码与 probe；服务端执行 `DetectAutomation`，返回与上游一致的 `riskFlags`、`blockedBy` 和 `instr_probe_missing`。
- 已应用上游 0.1.5 的“拒绝伪造 blocked 标记”修复，以及 0.1.3 的检测层加固。
- `ObfuscationLevel` 1–3 保留换行、4–10 压缩；未复刻 javascript-obfuscator 的混淆强度（脚本语义与线格式一致）。
- `Storage` / `ValidateToken` 是 gocap 扩展。默认验证令牌会同时索引原始 `token` 与 `tokenKey`，`ValidateToken` 支持两者，且不是一次性消费（上游 standalone 的 `siteverify` 使用 Redis `GETDEL`）。

HashWX 通过 `wazero` 执行上游 vendored 的 `hashwx.wasm`（LGPL-3.0，见 `internal/hashwx/LICENSE`），因此模块新增 `github.com/tetratelabs/wazero` 依赖。

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

- **协议选择**：新部署推荐 `hashwx` + `instrumentation`；RSW 已 deprecated，不建议用于新部署。完整配置见“推荐配置（安全优先）”。
- **Secret**：至少 16 字节，建议 32+ 字节高强度随机值。生成：`openssl rand -hex 32`
- **重放保护**：通过 `ConsumeNonce` 回调实现（如 Redis SETNX）；生产环境必须实现，否则同一挑战可重复兑换
- **instrumentation**：需要浏览器执行 gocap 下发的 JS；`BlockAutomatedBrowsers` 建议先观察 `riskFlags` / `blockedBy` 再开启
- **限流**：gocap 是库，不内置限流/封禁；请在网关/边缘层限制 challenge/redeem 频率
- **RSW 密钥**：`GenerateRswKeypair(2048)` 约耗时数百毫秒，启动时生成一次并持久化
- **HashWX**：首次校验会编译内嵌 wasm；可在启动时调用 `HashwxReady()` 预热
- **存储**：`MemoryStorage` 重启后数据丢失，生产环境请使用持久化后端
