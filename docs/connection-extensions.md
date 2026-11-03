# UoT、sing-mux 与 REALITY

配置通过 JSON API 保存为 SQLite 草稿；完整请求结构与资产 ID 替换方法见[示例说明](../examples/README.md)。下方局部片段按字段合入对应监听器。

这些功能通过现有协议工厂、传输工厂和 `internal/inbound` 组装，不引入 sing-box 产品依赖，也不维护本地 vendor 或 replace。构建要求 Go 1.27；CI 使用 Go 1.27.3。

## 支持范围

| 协议 | UoT | smux / yamux / h2mux | REALITY |
| --- | --- | --- | --- |
| Shadowsocks classic AEAD / 2022 | 支持，须启用 TCP 监听 | 支持 | 不支持 |
| VLESS | 支持 | 支持 | 支持，可选 Vision |
| VMess AEAD | 支持 | 支持 | 支持 |
| Trojan | 支持 | 支持 | 支持 |
| AnyTLS | 固定 v2，自动启用；拒绝 v1 | 使用协议自身的多流，不叠加 sing-mux | 支持 |
| Naive | 自动启用 v1/v2 | 使用 HTTP 自身多流，不叠加 sing-mux | 不支持 |
| Hysteria2 / TUIC | 使用原生 UDP | 使用原生 QUIC 多流 | 不支持 |

UoT 和 sing-mux 位于协议认证后的处理链，所以可以与该协议已支持的 TCP/TLS、WebSocket、HTTPUpgrade、REALITY 配合。服务端接收能力与客户端选择的封装方式分别处理；不会递归接受 sing-mux 会话。

## UoT

对于可选 UoT 的协议，监听器设置：

```json
{
  "udp_over_tcp": true
}
```

使用 `sing/common/uot` 的地址和帧编解码，识别对应版本的保留目标地址；v2 同时支持固定目标和每包目标地址。AnyTLS 固定使用 v2，服务端自动启用并拒绝 v1。其他协议未开启可选 UoT 时会明确拒绝这些保留地址，不交给 DNS 或直接出口。

UoT 请求头与首包受握手超时限制，收到实际目标地址后才进入共享 UDP relay。包边界、空数据报、每包目的地址和响应地址保持不变。UDP 空闲超时会关闭关联的逻辑流。

AnyTLS 的 UDP 是协议自带的 UoT v2，不需要单独开启：

```json
{
  "certificate_ref": "server",
  "credential_refs": [
    "password"
  ],
  "protocol": "anytls",
  "transport": {
    "type": "tcp"
  }
}
```

## Shadowsocks 的 UDP 模式与 mux 关系

`network` 控制监听套接字，`udp_over_tcp` 控制是否接收 TCP 上的 UoT；开启 UoT 不会关闭原生 UDP：

| UDP 接收方式 | `network` | `udp_over_tcp` |
| --- | --- | --- |
| 原生 UDP | `[tcp, udp]` | 省略或 false |
| UoT | `[tcp]` | true |
| 原生 UDP 与 UoT 并存 | `[tcp, udp]` | true |

这三种配置都保留普通 TCP 代理。Shadowsocks 还可以同时开启 `multiplex.enabled`，由不同客户端选择普通连接、UoT 或 mux。mux 自身也能承载 UDP 子流。

sing-box 1.14.4 的限制属于 **Shadowsocks 出站客户端**：当 `udp_over_tcp.enabled` 为 true 时，它创建 UoT client 并跳过 mux client，`multiplex` 配置不生效，而非叠加两种封装。[出站源码](https://github.com/SagerNet/sing-box/blob/v1.14.4/protocol/shadowsocks/outbound.go)

其 **Shadowsocks 入站服务端**同时接入 UoT router 和可选的 mux router，因此不存在服务端全局互斥。Lunaris 保持这个接收语义，不因启用 mux 就拒绝其他客户端的 UoT。[入站源码](https://github.com/SagerNet/sing-box/blob/v1.14.4/protocol/shadowsocks/inbound.go)

服务端同端口并存示例：

```json
{
  "credential_refs": [
    "password"
  ],
  "multiplex": {
    "enabled": true
  },
  "network": [
    "tcp",
    "udp"
  ],
  "options": {
    "method": "aes-128-gcm"
  },
  "protocol": "shadowsocks",
  "udp_over_tcp": true
}
```

SDK 可以手动在 mux 子流中承载 UoT，服务端处理链也能接收，但这不代表 sing-box Shadowsocks 出站会使用该组合。客户端配置应遵循它的 UoT 优先规则。AnyTLS 客户端则固定使用 UoT v2，与可选 Shadowsocks UoT 配置不同。[AnyTLS 出站源码](https://github.com/SagerNet/sing-box/blob/v1.14.4/protocol/anytls/outbound.go)

## sing-mux

```json
{
  "multiplex": {
    "enabled": true,
    "padding": true
  }
}
```

直接使用 `github.com/sagernet/sing-mux`，由客户端协商 smux、yamux 或 h2mux，服务端无需指定某一种。`padding: true` 要求客户端开启 padding；省略或设为 false 时接受带 padding 和不带 padding 的连接。

当前锁定 `v0.3.10-0.20260929204512-caf09fe32475`，其中包含上游 h2mux 的并发关闭与待接收流退出修复。TCP/UDP 子流使用相同的 relay 限额。额外跟踪未完成请求头的子流，防止只打开流、不发送目标地址的连接永久占位。

HTTP/2 逻辑流不实现普通 socket deadline，适配层用受跟踪的关闭计时器实现 UDP 空闲超时。停止监听器会关闭主连接和子流，凭据重载也会撤销旧 mux 会话。

## REALITY 与旧客户端兼容

新握手始终使用 `github.com/xtls/reality`，锁定上游 `83f621788ca8`，没有降级该依赖或修改它的源码。最新上游要求 ClientHello 包含 X25519MLKEM768 key share。

sing-box 1.14.4 的 REALITY 客户端会移除这个 key share；它直接连接严格的新握手实现时会进入回落路径。[该版本客户端实现](https://github.com/SagerNet/sing-box/blob/v1.14.4/common/tls/reality_client.go)

配置 `allow_legacy_clients: true` 可在同一端口同时支持新旧客户端：

- 含现代 key share 的握手交给最新版 `xtls/reality`。
- 旧 X25519 握手交给直接依赖 `github.com/metacubex/utls` 提供的兼容 REALITY 服务端；这也是 sing-box 使用的库接口。[服务端接入](https://github.com/SagerNet/sing-box/blob/v1.14.4/common/tls/reality_server.go)
- 分流只读取有界 ClientHello，并逐字节重放原报文，不修改 TLS transcript。
- 不在新路径认证失败后重试兼容路径。两条路径共享相同的私钥、server name、short ID 和时间差校验。

`allow_legacy_clients` 默认 false。开启时会保留旧握手语义，并额外维护兼容后端；不能将旧客户端描述成使用了新的 key share。

先生成密钥：

```sh
./bin/lunaris keygen reality
```

输出 JSON 中 `private_key` 供服务端保存，`public_key` 配置到客户端。私钥使用现有凭据资产，不写入协议 options：

```json
{
  "config": {
    "listeners": [
      {
        "address": "127.0.0.1",
        "credential_refs": [
          "user"
        ],
        "id": "vless-reality",
        "multiplex": {
          "enabled": true
        },
        "port": 8443,
        "protocol": "vless",
        "transport": {
          "reality": {
            "allow_legacy_clients": true,
            "max_time_difference": 60000000000,
            "private_key_ref": "reality-key",
            "server_names": [
              "target.example.net"
            ],
            "short_ids": [
              "0102030405060708"
            ],
            "target": "target.example.net:443"
          },
          "type": "reality"
        },
        "enabled": true
      }
    ],
    "schema_version": 1
  },
  "credential_assets": {
    "user": "cred_user",
    "reality-key": "cred_reality-key"
  },
  "certificate_assets": {}
}
```

将 target 和 server_names 替换为实际 TLS 1.3 目标站点。`short_ids` 是最多 16 个十六进制字符、长度为偶数的字符串，空字符串表示允许空 short ID。时间差未设置时按 1 分钟处理；最大可设为 24 小时。`certificate_ref` 与 REALITY 配置互斥。

已移植的 XHTTP 见[独立说明](xhttp.md)。VLESS 已支持 [Encryption 与 Vision](vless-encryption-vision.md)。本页原有示例仍使用空 flow 和 `encryption: none`；ML-DSA 和 gRPC 尚未接入。

## 生命周期与持久化

REALITY 私钥引用属于传输资产，不加入 `credential_refs` 中的协议用户列表。规范化校验会验证它是 base64url 编码的 32 字节 X25519 私钥；运行时指纹包含实际私钥内容，轮换会重建引用它的监听器并关闭旧连接。SQLite 的不可变凭据版本、重启恢复、备份和还原会一起保存它，无需新数据库迁移。

`POST /api/v1/config/validate` 只做配置和资产校验，不访问伪装目标。启动时按当前 xtls/reality 的要求探测目标 TLS record 特征；使用上游导出的探测连接实现，同时给 socket 加入取消和超时。共享探测结果使用引用计数，最后一个监听器停止后释放。未成功完成探测的实例不会报告启动成功。

认证前的回落连接也受握手期限限制，取消、重载和退出会关闭客户端及目标站 socket。协议认证后的流交给原有 relay 管理；兼容模式不会放宽用户协议的凭据校验。

## 验证

Go 回归包含可选 UoT v1/v2、AnyTLS 默认 v2 与拒绝 v1、固定/每包目标、空数据报，以及 Shadowsocks 原生 UDP/UoT/mux 同端口共存；三种 mux 的 TCP/UDP、多子流、padding、mux 子流中的 UoT、超时与停止；REALITY 新旧握手共存、严格模式拒绝旧握手、错误 short ID、普通 TLS 回落、私钥轮换、ClientHello 分片和原始字节保留，以及目标探测取消和共享引用回收。

发行客户端验证：

```sh
make build-web
python3 scripts/test-interop.py --client /path/to/sing-box
python3 scripts/test-extensions.py --client /path/to/sing-box --xray-client /path/to/xray
```

脚本只使用回环地址与临时目标服务。独立客户端结果、真实 Linux 运行和公网网络行为分别记录，不把本机回环或交叉编译当作生产验证。

本轮验证记录（2026-11-01）：sing-box 1.14.4 发行程序通过原有 19 个组合、新增 20 个扩展组合及 7 种 Shadowsocks 同端口客户端配置；Xray 26.10.31（官方标签 `a4a3dff5b20c` 源码构建）通过 VLESS/VMess/Trojan + REALITY 的 TCP/UDP。新旧 REALITY 客户端使用同一组已开启兼容的监听端口。Xray 验证设置 `XRAY_CONE_DISABLED=true` 使用原生 UDP，未启用 XUDP 或 Vision。核心/管理构建的 vet、race 和 Linux amd64/arm64 的 CGO=0 交叉编译通过。

追加稳定性检查：UDP/UoT/mux 相关 Go 矩阵在 race 模式下连续 100 轮通过，独立 sing-box 的 19 个 TCP/UDP 组合连续 20 轮通过。回归期间曾出现偶发 UDP 超时或报文异常，补充诊断后未再复现，根因尚未定位；上述重复通过不作为该异常已修复的证据。
