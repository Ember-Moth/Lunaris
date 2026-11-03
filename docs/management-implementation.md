# P5 管理 API 使用与验证

状态：2026-11-02，P5 已接入实际配置服务和代理运行时。Web 页面仍是骨架；本阶段可通过 HTTP 客户端管理节点。节点 YAML 已退役，仅启动设置保留 YAML。接口和数据类型以 [OpenAPI](../api/openapi.yaml) 为准，前端类型由它生成。

## 启动与初始化

```sh
make build-web
bin/lunaris-web serve --config config.example.yaml
```

默认监听 `127.0.0.1:9080`。`serve` 复用 SQLite 中的 committed 配置，不自动应用 draft。管理端口先绑定并作为代理配置的保留端点；代理恢复失败时保留管理 API，`/status` 返回 `restore_error` 和 provisional 状态，供保存新草稿或 recover 计划修复。数据库损坏或 schema 不兼容仍会拒绝启动。

首次启动在数据目录创建权限为 `0600` 的 `setup-token` 文件，有效期 30 分钟。原文不写服务日志，也不由 HTTP 返回。默认数据目录由程序以 `0700` 创建，建议已有目录也保持 `0700`；已有目录禁止组/其他用户写入，数据库和秘密文件必须为私有文件。

读取该本机文件，把 token、用户名和密码提交到 `POST /api/v1/setup`，成功后正常登录。单管理员建立与 token 消费属于同一事务，成功后删除 token 文件。初始化完成后不能通过 `/setup` 再创建账户。

所有写请求都必须提供与管理地址一致的 `Origin`，例如：

```http
Origin: http://127.0.0.1:9080
Content-Type: application/json
```

登录后的写操作还需 cookie 和 `X-CSRF-Token`。登录响应 data 提供 CSRF token，cookie 为 HttpOnly、SameSite=Strict、Path=/。HTTPS 使用 Secure 的 `__Host-lunaris_session`，回环 HTTP 使用 `lunaris_session`。会话绝对有效期 12 小时，普通 GET 不刷新有效期。

管理员名称为 1–64 位 ASCII 字母、数字、点、下划线或连字符；密码为 12–1024 字节的有效 UTF-8，不截断。密码使用 Argon2id，参数为 64 MiB、3 次迭代、并行度 1、随机 16 字节盐和 32 字节输出；参数保存在哈希中，校验时约束上限。该配置高于 [OWASP Argon2id 最低建议](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)。

## 管理 HTTPS 与反代

原生 HTTPS 启动配置：

```yaml
data_dir: ./data
admin:
  listen: 0.0.0.0:9080
  public_url: https://node.example.com:9080
  tls:
    certificate_file: fullchain.pem
    private_key_file: privkey.pem
```

TLS 最低版本为 1.2，管理协议使用 HTTP/1.1。公开地址和管理证书是启动设置，改变它们需要重启；不属于代理 NodeConfig 的应用操作。

可信 HTTPS 反代配置：

```yaml
data_dir: ./data
admin:
  listen: 127.0.0.1:9080
  public_url: https://node.example.com
  trusted_proxies: [127.0.0.1/32]
```

仅来自已配置反代地址的请求才使用转发头。反代必须提供 `X-Forwarded-Proto: https`，并保留公共 Host 或提供匹配的 `X-Forwarded-Host`。`X-Forwarded-For` 从右向左剥离可信代理，遇到首个非可信地址即停止；不要把任意客户端声明当作可信来源。原生 TLS 与反代模式不能同时启用，`/0` 信任范围被拒绝。

没有原生 TLS 或可信反代时，仅允许回环 HTTP 和回环 public_url。Host/Origin 以完整规范化 origin 比较，不做域名后缀匹配；不启用跨域访问。来源检查与会话 CSRF token 共同防护，设计依据见 [OWASP CSRF 指南](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)。

## 资产、草稿与应用

代理凭据和证书均为不可变资产。创建凭据示例：

```json
{"kind":"uuid","label":"phone","generate":true}
```

`kind` 支持 `generic`、`password`、`uuid`、`ss2022-128`、`ss2022-256`、`x25519`、`vless-encryption`。`secret` 与 `generate: true` 二选一。普通创建/列表响应仅返回资产 ID、类型、标签和引用元数据，不回显秘密。

草稿使用稳定逻辑名称绑定不透明资产 ID：

```json
{
  "config": {
    "schema_version": 1,
    "listeners": [
      {
        "id": "vless-main",
        "enabled": true,
        "protocol": "vless",
        "address": "127.0.0.1",
        "port": 8443,
        "credential_refs": ["phone"],
        "options": {}
      }
    ]
  },
  "credential_assets": {"phone": "cred_example"},
  "certificate_assets": {}
}
```

示例只说明结构，`cred_example` 应替换为实际创建的 ID。逻辑引用映射沿用 P3 存储模型；保存草稿不会复制一个新的秘密资产。时间限制在 JSON 中以纳秒表示，省略 limits 时使用节点默认值。

流程：

1. `GET /config/draft` 获取 revision、配置、资产绑定及 ETag。
2. `PUT /config/draft` 带一个强 `If-Match` 保存完整候选；缺少前置条件返回 428，旧版本返回 412。
3. `POST /config/plans` 指定 draft_revision 和 base_revision；计划包含 boot_id、runtime_epoch、有效期和影响列表。缓存最多 128 个计划，每个有效 2 分钟。
4. `POST /config/apply` 带 Idempotency-Key。涉及断开现有连接时，必须发送 `acknowledge_disconnects: true`。
5. 服务端持久化受理记录后返回 202、operation_id 和 Location，后续查询 `/operations/{id}`。受理后的任务由服务生命周期拥有，不因 HTTP 断开、超时或退出登录取消。

幂等作用域为管理员与应用端点。查重先于计划有效期检查，支持进程重启后重试；已受理的同键不同请求返回 40903。数据库提交结果无法确认时冻结写入，操作查询继续显式呈现 `uncertain`，不猜测回退。

当前持久化操作沿用 P3 的状态：running / succeeded / failed / failed_rolled_back / degraded / interrupted；phase 为 accepted / applying / committing / finished。`applying` 包含准备和运行时替换，尚不把无法独立确认的子步骤伪装成额外阶段。进程内无法确认的结果通过 uncertain 视图表达，重启后由 committed 和操作记录恢复。

应用期间草稿和资产变更返回 40901，并给出当前操作 ID；读取和认证仍可用。运行时在转换入口检查计划代次，避免过期计划开始替换。计划不能预留端口，最终仍以真实绑定结果为准。

历史配置和执行中操作引用的资产不可删除。引用列表最多返回 100 条，`reference_count` 与 `references_truncated` 标明完整数量和截断。资源/历史列表分页最多 100 项；本阶段不自动删除保留历史版本。

## 敏感导出、配置查询与日志

`POST /auth/reauth` 校验当前密码，授予当前会话 5 分钟的敏感访问资格。`POST /listeners/{id}/connection-info` 还需预期 committed_revision、明确的客户端 host，以及多用户监听器上的 credential_ref。

导出格式为 `parameters-v1`，提供客户端无关的端点、协议、所选用户认证、传输和扩展参数，**不是可直接导入任意客户端的订阅链接**。仅导出所选用户及该监听器必需的共享插件密码；证书私钥不导出，REALITY/VLESS Encryption 的服务器私钥转换成客户端公钥。通配 bind 地址不会被自动写成客户端地址。响应前重新核对会话、重新认证有效期、committed 和运行摘要。

普通配置查询使用 `GET /config/draft` 与 `/config/committed`，只返回 JSON 配置和资产 ID 映射；保存使用 `PUT /config/draft`。YAML 模板与导入端点已移除，返回 404。代理配置不接受本机文件路径或环境变量引用，脱敏 JSON 查询也不能替代含秘密材料的完整备份。

`GET /logs` 返回管理动作、应用完成与监听失败等服务端控制的消息；不转发原始请求、Cookie、密码或底层任意错误文本。内存环保留 512 条，游标带 boot_id；过旧或跨重启的游标显式标记 truncated / restarted。默认响应均为 no-store。

## 离线恢复与资源边界

停止正在使用同一数据目录的节点后，可执行：

```sh
# 仅未初始化节点：重新生成一次性 token 文件
bin/lunaris admin setup-token --data-dir ./data

# 已有管理员：从权限为 0600 的文件设置新密码
bin/lunaris admin reset-password --data-dir ./data --password-file new-password.txt
```

改密和离线重置在同一事务中更新密码版本并撤销全部会话。正常进程重启保留尚未过期的会话；备份还原保留账户和配置，但在发布还原副本之前撤销其中的会话及旧 setup token。原备份和原安装不受修改。

- 管理连接最多 128 个，同时处理的 API 请求最多 32 个。
- Argon2 操作最多同时 2 个。认证尝试按来源/操作限制每分钟 5 次，另外共享每分钟 30 次总预算；最多保留 32 个会话。
- HTTP 头最多 16 KiB；请求体采用有界流式读取。认证通常限 4 KiB，改密 8 KiB，凭据 16 KiB，配置 1 MiB，证书封套 3 MiB；每份证书/私钥不超过 1 MiB。
- 超限业务请求返回 JSON 信封；TLS/HTTP 头本身无法解析时可能在 Hertz 传输边界拒绝，不保证业务信封。
- 过期会话每分钟清理，GET 不修改会话有效期。完整数据库备份还原仍走离线 CLI，Web 不提供任意命令或文件读取接口。

## 验证

```sh
make check
make check-web
make build-web
python3 scripts/test-management.py
```

回归覆盖初始化竞争、密码版本与延迟登录竞争、提交响应失败后的撤销、会话过期、Host/Origin/CSRF、可信反代、重复 Cookie、登录限流、请求体限制、资产脱敏与历史引用保护、ETag、计划过期与运行代次、幂等冲突/重启重放、断开 HTTP/退出登录后的独立执行、断连确认、真实 Shadowsocks 转发及密钥轮换、管理端口冲突、代理恢复失败后的修复入口、uncertain 状态，以及备份还原和离线管理员恢复。

独立二进制流程由 `scripts/test-management.py` 复现。P6 的浏览器表单与交互验收、真实 Linux/公网部署、生产反代与证书运维仍需后续完成。

全量回归额外复现并修复了既有 VLESS 原生 mux 的并发刷新问题：写入到达顺序不等于互斥锁获取顺序，基于到达计数的条件 flush 可能留下最后一批缓冲数据。现在每个持锁写入批次都完成 flush；并发 TCP/UDP 帧回归单独重复验证。

2026-11-02 验证记录：`make check`、`make check-web`、独立管理二进制流程、Linux amd64/arm64 的核心/管理版 CGO=0 交叉编译和 Xray 的 96 个 VLESS 回环组合通过。全量检查曾出现一次既有 h2mux/WebSocket 组合超时，随后该组合单独重复 30 次及完整管理检查均通过；本阶段不将该偶发问题标为已修复。预览后监听失败、候选清理失败及资源所有权保留的回归另重复 30 次通过。

路由、DNS 及 GeoData 已接入同一 API/SQLite 配置生命周期；GeoData 二进制上传上限 128 MiB，单次上传受独立并发限制，历史引用受删除保护。使用与验证见[路由和 DNS](routing-dns.md)。
