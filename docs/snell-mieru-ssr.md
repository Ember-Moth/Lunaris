# Snell、Mieru 与 ShadowsocksR

三个协议共用 Lunaris 的凭据资产、协议工厂、传输工厂、relay 和重载机制。配置示例见 [snell-mieru-ssr.yaml](../examples/snell-mieru-ssr.yaml)。

## Snell

直接依赖 [SagerNet/sing-snell](https://github.com/SagerNet/sing-snell)，锁定 `bc5a12ac736f`，不复制 Polaris 修改过的 sing-snell。

| 服务端版本 | 客户端 | 选项 | 凭据 |
| --- | --- | --- | --- |
| `5`，默认 | v4 兼容客户端 | `obfs: none/http/tls` | 一份 PSK，1–255 字节 |
| `6` | v6 客户端 | `mode: default/unshaped/unsafe-raw` | 一份 PSK，12–255 字节 |

```yaml
protocol: snell
credential_refs: [snell-psk]
options:
  version: 6
  mode: default
```

Snell 监听 TCP，承载 TCP 和协议原生 UDP，包含上游的 TCP 连接复用。v5 的 HTTP/TLS obfs 是协议混淆，不使用 `certificate_ref`；v6 不接受 v5 obfs。`unsafe-raw` 是上游明文记录模式，不提供常规 PSK 加密握手保护，必须显式选择，默认不会启用。

保留公共 UoT/mux 扩展入口，默认关闭，已用 SDK 客户端覆盖。Snell 的已认证 TCP 流通过标准 net.Conn 接口进入共享处理链，避免上游 vector writer 对控制头部空间的假设，同时保留半关闭和 MTU。UDP 遵循 sing-snell 的帧长约束，本轮独立互通使用小于 1 KiB 的数据报；不将大数据报或 v5 专用 QUIC proxy 模式列为已验证能力。

本轮按上游单 PSK 服务端语义接入，没有导入 Polaris 定制的多 PSK 探测、用户热更新或 Argon2 副本。

## Mieru

移植 [Polaris 的原生 Mieru v3 实现](https://github.com/HyperPteLtd/Polaris/tree/56d52fb44958ef3cc2a7fb841cd240f8206234b2/pkg/sagernet/sing-mieru/native)，服务端运行时不依赖 enfein/mieru 应用或 Polaris 控制面。

支持 TCP underlay、可靠 UDP、多个逻辑会话、TCP CONNECT、UDP ASSOCIATE、用户名/密码、user hint，以及源版本的 traffic-pattern protobuf 参数。

```yaml
protocol: mieru
network: [tcp, udp]
credential_refs: [alice, bob]
options:
  users:
    - username: alice
      credential_ref: alice
    - username: bob
      credential_ref: bob
  user_hint_is_mandatory: true
  mtu: 1400
```

`network` 可以是 `[tcp]`、`[udp]` 或两者，省略时同时监听 TCP/UDP；两种 underlay 均可代理 TCP 和 UDP。传输为 `native`，不叠加 TLS、UoT 或 sing-mux。`mtu` 允许 576–9000，零或省略沿用原实现默认值。

`traffic_pattern` 可选，填写源版本支持的 Base64 protobuf 配置；不存在的顶层选项会被拒绝。用户映射必须完整、用户名与引用不得重复。

移植适配增加了宿主拥有的 socket 接入、单会话取消、握手名额、逻辑会话总量限制，以及 64 MiB 的排队/重排/重传 payload 总预算。TCP 通过背压等待预算；UDP 对未获预算的数据不推进累计确认，允许客户端重传。消费、ACK、关闭和取消会释放对应预算。该预算不包含所有协议元数据、socket 内核缓冲和正在消费的单个数据块，不是进程总 RSS 上限。

可靠 UDP 保留分片、累计 ACK、乱序重排、接收窗口、拥塞窗口、重传和心跳。动态读取期限可以影响已经阻塞的 Read；停止后不会关闭或遗留不属于协议层的监听 socket。

## ShadowsocksR

移植 [Polaris 的 SSR 编解码实现](https://github.com/HyperPteLtd/Polaris/tree/56d52fb44958ef3cc2a7fb841cd240f8206234b2/pkg/sagernet/sing-shadowsocksr)，在 `internal/protocol/shadowsocksr/wire` 保留源许可和测试。

加密方法：

- classic：`none`、AES-128/192/256-CTR、AES-128/192/256-CFB、`rc4-md5`、`chacha20`、`chacha20-ietf`。
- SIP004：AES-128/192/256-GCM、`chacha20-ietf-poly1305`、`xchacha20-ietf-poly1305`；`chacha20-poly1305` 为别名。
- SS2022 方法仍使用 `protocol: shadowsocks`，SSR 配置会拒绝它们。

协议与用户形式：

| SSR 协议 | 用户配置 |
| --- | --- |
| `origin`、`verify_simple`、`verify_sha1`、`auth_simple`、`auth_sha1`、`auth_sha1_v2`、`auth_sha1_v4` | 一份凭据，不填写 `users` |
| `auth_aes128_md5`、`auth_aes128_sha1`、`auth_chain_a` 至 `auth_chain_f` | `users` 显式映射非零 uint32 ID 与凭据引用；支持同端口多用户 |

混淆支持 `plain`、`http_simple`、`http_post`、`tls1.0_session_auth`、`tls1.2_ticket_auth`、`tls1.2_ticket_fastauth`。混淆只应用于 TCP，UDP-only 配置必须使用 `plain`。

```yaml
protocol: shadowsocksr
network: [tcp, udp]
credential_refs: [alice, bob]
options:
  method: aes-128-cfb
  protocol: auth_aes128_sha1
  obfs: plain
  server_key_ref: ssr-server
  users:
    - {id: 1, credential_ref: alice}
    - {id: 2, credential_ref: bob}
```

`server_key_ref` 指向共享 cipher 密码，和用户凭据分开；多用户模式必须配置。单用户省略时使用该用户凭据作为 cipher 密码。客户端 password 填写共享密码，`protocol-param` 填写 `用户ID:用户密码`。服务端 `protocol_param` 和 `obfs_param` 保留源实现含义，不用来保存用户密码。

`none` 不加密，`origin` 仅提供原始封装；保留这些名称用于协议兼容，不把它们描述为具有 AEAD 认证的模式。

SSR 原生 UDP 先完成解码与用户识别，再按用户和源地址建立有界队列，使用共享 UDP relay。实例内总排队 payload 限制为 16 MiB。TCP 的 SIP004 盐重放历史复用移植包的有界精确缓存，不依赖 Polaris 对 sing 的私有改动。

移植时修正了返回已归还接收缓冲区的切片、共享 MAC/混淆状态并发访问，以及 TLS ticket 初始大记录的长度边界。网络读写不会持有编解码状态锁。

## 凭据与生命周期

PSK、用户密码和 SSR 共享密码均使用已有凭据资产。共享密码引用参与配置校验、持久化快照与运行时指纹。修改凭据或协议选项会重建受影响的监听器并关闭旧会话，非法配置在停止现有监听器之前拒绝。

移植过程还修正了共享 UDP relay 的前后头部空间计算：沿 sing 的包装链查询 headroom，确保缓存首包包装不会隐藏 Snell UDP writer 所需空间。

## 验证

```sh
make check
make build
go build -C test/clients/mieru -o /tmp/lunaris-mieru-client .
go build -C test/clients/shadowsocksr -o /tmp/lunaris-ssr-client .
python3 scripts/test-snell-mieru-ssr.py \
  --sing-box /path/to/sing-box \
  --mihomo /path/to/mihomo \
  --mieru-client /tmp/lunaris-mieru-client \
  --ssr-client /tmp/lunaris-ssr-client
```

两个 `test/clients` 子模块只构建独立测试客户端，不被节点主模块导入，也不使用本地 replace。脚本绑定回环地址，使用临时凭据和配置，不改系统路由。

本机验证记录，2026-11-01：

- sing-box 1.14.4 发行程序：6 个 Snell 版本/模式组合的 TCP/UDP。
- Mihomo v1.19.33 原始编解码库：51 个 SSR cipher/protocol/obfs/用户组合的 TCP/UDP；包含大首包。
- Mihomo v1.19.33 发行程序：Mieru TCP/UDP underlay 的 TCP/UDP 代理。
- enfein/mieru v3.34.0 官方 API：两名用户分别通过两种 underlay，每次 4 条并发 TCP 流及 UDP；额外覆盖每七个数据报丢弃一个的双向丢包恢复。
- Go 回归：原编解码向量、分片/篡改、Snell 复用、配置拒绝、凭据轮换、关闭/预算回收、动态读取期限及 race。

Mihomo v1.19.33 的 TLS ticket 客户端在初始读写并发时存在 `sendBuf`/握手状态数据竞争，已用未修改客户端代码和 race 检测复现。SSR 测试客户端默认顺序发起初始写入和读取，验证合法 wire 数据；`ConcurrentStartup: true` 可复现该客户端问题。未修改第三方客户端，也不宣称该发行程序的大首包并发路径已通过。

SSR 的其他 legacy 模式和 SIP004 组合由源包向量与 Go 测试覆盖，没有等价的全矩阵第三方发行客户端证明。本机回环、受控丢包和交叉编译不能代替真实 Linux、公网 MTU/丢包或长期负载验证。
