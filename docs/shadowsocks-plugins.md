# Shadowsocks 插件

Lunaris 支持六类内置 Shadowsocks 插件，适用于现有 classic AEAD 和 SS2022 方法。它们是独立的传输工厂，不增加代理协议种类，不启动外部插件进程。

| `transport.type` | 支持范围 | 监听套接字 |
|---|---|---|
| `obfs` | simple-obfs HTTP / TLS 混淆 | TCP |
| `v2ray-plugin` | WebSocket，可选 TLS、v2ray mux、early data；HTTPUpgrade | TCP |
| `gost-plugin` | WebSocket，可选 TLS、smux | TCP |
| `shadow-tls` | ShadowTLS v1 / v2 / v3 | TCP |
| `restls` | Restls TLS 1.2 / 1.3 | TCP |
| `kcptun` | KCP + smux v1/v2，可选压缩与 FEC | UDP |

插件参数放在 `transport.plugin`。WebSocket 的 `path`、`host` 与 TLS 的 `certificate_ref` 仍使用现有公共字段。插件密码/密钥通过 `password_ref` 或 `key_ref` 引用凭据，不允许明文放进可回显的插件选项。

完整示例见 [shadowsocks-plugins.yaml](../examples/shadowsocks-plugins.yaml)。现有 Shadowsocks 凭据、SS2022 `server_key_ref` 和多用户配置继续适用。

## 基本配置

```yaml
credentials:
  - id: ss-user
    secret_env: LUNARIS_SS_PASSWORD
  - id: plugin-password
    secret_env: LUNARIS_PLUGIN_PASSWORD
listeners:
  - id: ss-shadowtls
    protocol: shadowsocks
    address: 127.0.0.1
    port: 8443
    credential_refs: [ss-user]
    options:
      method: aes-128-gcm
    udp_over_tcp: true
    transport:
      type: shadow-tls
      plugin:
        version: 3
        password_ref: plugin-password
        handshake: www.example.com:443
        strict-mode: true
```

客户端的 Shadowsocks 密码对应 `ss-user`；插件密码对应 `plugin-password`。伪装目标应与客户端的 `host`、SNI 和证书校验设置匹配。示例域名需要换成实际目标。

`network` 描述监听套接字，通常省略即可：kcptun 自动选择 UDP，其余插件自动选择 TCP。**原生 Shadowsocks UDP 不通过这些插件**；需要 UDP 转发时，双方启用 UoT，Lunaris 设置 `udp_over_tcp: true`。如需同时提供原生 UDP，单独配置一个 `native` UDP 监听器，显式决定其暴露端口。

## 插件参数

### simple-obfs

```yaml
transport:
  type: obfs
  plugin:
    mode: tls   # 或 http
```

这是混淆层，不使用 `certificate_ref`。HTTP 首包、TLS 分片和并发写入由适配器处理；内层仍须完成 Shadowsocks 认证。

### v2ray-plugin / gost-plugin

```yaml
certificate_ref: edge
transport:
  type: v2ray-plugin
  path: /proxy
  host: proxy.example.com
  plugin:
    mode: websocket
    mux: true
```

- `mode` 默认为 `websocket`；v2ray-plugin 的 QUIC 模式未接入。
- `mux` 默认为 `true`。v2ray-plugin 使用自己的 mux 协议，gost-plugin 使用 smux；它们和监听器顶层的 `multiplex`（sing-mux）是不同层。
- 删除 `certificate_ref` 即使用无 TLS 的 WebSocket 载体。
- v2ray-plugin 可用 `v2ray-http-upgrade: true` 切换为 HTTPUpgrade。
- WebSocket early data 使用 `path: /proxy?ed=2048`，最多 65535 字节，通过 `Sec-WebSocket-Protocol` 传递；HTTPUpgrade 不接受该选项。
- `headers` 是服务端要求客户端携带的额外 HTTP 请求头。未知、冲突或非法字段会在检查配置时拒绝。
- v2ray-plugin 支持 `max-sessions`、`max-session-queued-bytes`、`max-queued-bytes`、`max-active-streams`；gost-plugin 支持 `max-streams`、`max-active-streams`。流数量进一步受节点的 `max_connections`、`max_udp_sessions` 限制；实际认证超时统一使用节点 `handshake_timeout`。

未认证物理连接仍受握手预算约束。首条 Shadowsocks 流认证后共享连接可长期保持；后续每条逻辑流分别受认证超时限制，超时不会关闭已经认证的其他流。

### ShadowTLS

`version` 支持 1–3，兼容默认值为 2；建议明确指定所需版本。`handshake` 为必填目标 `host:port`；v2/v3 必须设置 `password_ref`，v3 可设置 `strict-mode`。

本次独立互通使用 v1/v2 + TLS 1.2 目标、v3 + TLS 1.3 目标。v2 与本机 OpenSSL TLS 1.3 目标的会话 ticket 存在兼容差异，会出现流内认证失败；该组合不在本次通过范围内。v2 应使用已确认兼容的 TLS 1.2 目标。

上游 `sing-shadowtls` v0.2.1 的部分 v3 向量写入路径不适用本节点；适配层使用序列化的、最大 16 KiB 的普通写入，保持 HMAC 与 TLS 记录顺序。

### Restls

```yaml
transport:
  type: restls
  plugin:
    password_ref: plugin-password
    dest: www.example.com:443
    # restls-script: "250?100<1,350~100<1,600~100,300~200,300~100"
    # min-record-len: 15
```

`dest` 与 `password_ref` 必填。脚本使用上游 Restls 语法，配置检查会解析它；脚本最多 4096 字节，`min-record-len` 为 0–16384（0 采用上游默认值）。目标连接在认证后继续承担伪装流量，直到实际流关闭或节点停止；握手超时不会误杀已认证的长连接。

### kcptun

```yaml
transport:
  type: kcptun
  plugin:
    key_ref: plugin-password
    crypt: aes
    mode: fast
    nocomp: false
    smuxver: 1
    datashard: 10
    parityshard: 3
```

常用参数：`mtu`、`sndwnd`、`rcvwnd`、`datashard`、`parityshard`、`sockbuf`、`dscp`、`ratelimit`、`smuxver`、`smuxbuf`、`framesize`、`streambuf`、`keepalive`、`nocomp`、`acknodelay`。`mode` 支持 `normal`、`fast`、`fast2`、`fast3`、`manual`；只有 `manual` 使用自行设置的 `nodelay`、`interval`、`resend` 和 `nc`。

保留上游密码算法选择，包含 `aes`、AES-128/192、AES-GCM、Blowfish、Twofish、CAST5、XTEA、Salsa20。`none`、`null`、`xor`、`tea`、`3des` 需要显式 `allow-insecure: true`。本次独立验证了 `aes` 与 MetaCubeX 的 `aes-128-gcm` 扩展，以及压缩开关、smux v1/v2。

`max-sessions`、`max-streams`、`max-active-streams` 会再按节点资源上限收紧。未认证会话使用 `max_pending_handshakes` 与 `handshake_timeout`，只发 keep-alive 不会释放认证预算。`conn`、`autoexpire`、`scavengettl` 是客户端连接池设置，服务端拒绝这些字段。

## 验证与边界

独立客户端采用原始 Mihomo v1.19.33，位于单独 Go module，不进入生产依赖：

```sh
go build -C test/clients/ssplugins -o ../../../bin/test-ssplugins-client .
make build
python3 scripts/test-ssplugins.py
```

2026-11-01：**162 个插件/方法组合**通过，另通过 4 个错误插件凭据拒绝测试，并在每次拒绝后验证正常连接恢复，覆盖三种 classic AEAD 与三种 SS2022、并发 TCP、128 KiB TCP 数据、UoT 数据报（至 8 KiB）、WebSocket TLS/mux/early data、HTTPUpgrade、ShadowTLS 三版本、Restls 两个 TLS 版本、KCP 压缩与 smux 版本组合。macOS 本机大于默认 UDP 数据报上限的发送会返回 `message too long`，不将该失败算作协议错误或通过结果。

完整 `make check`、管理构建 vet/race、Linux amd64/arm64 的 CGO=0 交叉编译及六监听器示例的 `check` 均通过。

一次并行构建期间的 WebSocket early-data 客户端复跑超过 40 秒。随后该组合的定向测试与完整矩阵复跑通过，未复现该超时；原因尚未定位。独立客户端测试工具已增加连接上下文取消和总超时堆栈记录。

本地回归另覆盖错误配置、秘密字段引用、真实流存活超过握手预算、逻辑流超时隔离、未认证 KCP 会话回收、伪装目标关闭、密码轮换撤销旧连接、无效配置保持旧监听器和停止清理。来源与许可见[第三方声明](../THIRD_PARTY_NOTICES.md)。

证据限于本机回环；公网伪装目标、CDN、丢包/拥塞和长期压力尚未验证。未接入任意外部 SIP003 程序、v2ray-plugin QUIC、Cloak、GoQuiet 或 JLS。
