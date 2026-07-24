# 存储示例

这个目录用于存放 `gocap.Storage` 的示例实现文档。

当前包含以下示例：

- `rueidis.md`：基于 `github.com/redis/rueidis` 的 Redis 存储实现示例。
- `go-redis-v9.md`：基于 `github.com/redis/go-redis/v9` 的 Redis 存储实现示例，适合已经在项目中使用 go-redis 的场景。

所有示例都围绕同一个 `Storage` 接口展开：

```go
type Storage interface {
    SetChallengeToken(ctx context.Context, token string, expiresAt time.Time) error
    GetChallengeTokenExpiry(ctx context.Context, token string) (time.Time, bool, error)
    SetValidationToken(ctx context.Context, token string, expiresAt time.Time) error
    GetValidationTokenExpiry(ctx context.Context, token string) (time.Time, bool, error)
    CleanupExpired(ctx context.Context) error
}
```

说明：

- Redis 版本通常依赖 TTL 自动清理过期键，因此 `CleanupExpired` 可以实现为 no-op。
- 示例代码以可读性为主，字段和方法命名保持与当前仓库公开接口一致。
- 如果你想把示例直接接入业务项目，建议补充连接池、超时、监控和错误包装等生产环境配置。
