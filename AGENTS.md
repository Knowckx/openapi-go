# 项目维护说明

本项目是 Longbridge Go SDK 的长期维护 fork，用于修复官方 SDK 尚未解决的问题并叠加自定义特性。

- Fork：`https://github.com/Knowckx/openapi-go`（`origin`）
- 官方：`https://github.com/longbridge/openapi-go`（`upstream`）
- 保留官方 module path：`github.com/longbridge/openapi-go`

## 分支与发布

- `main` 仅镜像 `upstream/main`，不承载自定义修改。
- `custom` 是长期维护分支，自定义功能按独立 commit 累积。
- 官方更新先以 fast-forward 同步到 `main`，再 merge 到 `custom`；不要改写已发布的 `custom` 历史。
- 稳定版本使用 `v<官方版本>-knowckx.<序号>` tag，业务项目通过 `replace` 固定依赖该 tag。

```go
require github.com/longbridge/openapi-go v0.25.2

replace github.com/longbridge/openapi-go => github.com/Knowckx/openapi-go v0.25.2-knowckx.1
```

## 当前自定义逻辑

OAuth 除保留按本地过期时间自动刷新外，还在统一 HTTP 层识别结构化错误码 `401102`：使用现有 refresh token 串行强制刷新、更新内存并持久化 token，然后仅重试原请求一次。并发失败请求复用首次刷新结果；refresh token 缺失或被拒绝时返回 `oauth.ErrReauthorizationRequired`。调用方无需实现刷新、修改 token 文件或重建 Context。
