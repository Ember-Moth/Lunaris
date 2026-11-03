# JSON 管理 API 请求示例

本目录的 `.json` 文件是 `PUT /api/v1/config/draft` 的请求体示例，不是程序启动文件，也不会自动同步到数据库。节点配置唯一持久化来源是 SQLite；启动设置仍使用根目录的 `config.example.yaml`。

## 使用流程

1. 运行 `lunaris-web serve --config config.example.yaml`，按[管理说明](../docs/management-implementation.md)完成初始化和登录。
2. 通过 `POST /api/v1/credentials` 创建或生成代理凭据；需要 TLS 时，通过 `POST /api/v1/certificates` 上传证书链和私钥。
3. 将示例中 `credential_assets` / `certificate_assets` 的 `cred_...` / `cert_...` 示例值替换成接口实际返回的 ID。它们不是密码、公钥或文件路径。
4. 按需调整监听地址、端口和协议参数；`config.listeners[].enabled` 必须明确为 true 才启用，`options` 无额外选项时明确填写 `{}`。
5. 可先向 `POST /api/v1/config/validate` 提交请求体校验，再使用当前草稿的 ETag 作为 `If-Match` 保存。
6. 创建应用计划，核对受影响监听器和断连影响，带幂等键提交应用并查询操作结果。

所有写请求需要正确的 Origin；登录后的写请求还需要会话 Cookie 和 `X-CSRF-Token`。相同 JSON 既可校验也可保存，但保存不自动应用。

## 凭据和证书

| 逻辑用途 | 凭据内容 / 创建方式 |
| --- | --- |
| Shadowsocks classic、Trojan、AnyTLS、Hysteria2、Snell、Mieru、SSR | 按协议约束创建 password/generic 资产 |
| VLESS、VMess | 创建或生成 uuid 资产 |
| Shadowsocks 2022 | 按方法创建或生成 ss2022-128 / ss2022-256 资产 |
| REALITY | 创建或生成 x25519 私钥资产；客户端使用对应公钥 |
| VLESS Encryption | 创建或生成 vless-encryption 资产 |
| TLS | 上传匹配的 PEM 证书链和私钥，再引用证书资产 ID |

逻辑名称由 `credential_refs`、`certificate_ref` 和协议中的 `*_ref` 引用；映射表把这些名称绑定到不可变资产。轮换时创建新资产并更新映射，经过正常计划和应用流程。

`limits` 中时间限制的 JSON 单位为纳秒；例如 `10000000000` 表示 10 秒，省略 limits 使用服务端默认值。REALITY 的 `max_time_difference` 同样使用纳秒。示例保留原先协议组合，未提供有效的真实资产 ID，必须先完成绑定才能通过验证。

API 不接受 `secret_env`、`secret_file` 或证书本机路径。凭据创建请求直接传值，证书上传请求直接传 PEM；原始秘密不写入本目录。完整安装备份使用离线 `backup`/`restore`，不能用脱敏配置查询结果替代。
