# XHTTP 传输

从 [Polaris 的 XHTTP 实现](https://github.com/HyperPteLtd/Polaris/tree/56d52fb44958ef3cc2a7fb841cd240f8206234b2/internal/transport/xhttp) 移植，来源提交为 `56d52fb44958ef3cc2a7fb841cd240f8206234b2`。保留三种上传模式、padding 与字段放置、乱序上传队列、会话/请求/字节限额、缓冲池和 HTTP/3 连接回收测试。没有引入 Polaris 产品模块、Xray-core 模块、本地 SagerNet 副本或 replace。

## 支持范围

| 协议 | HTTP/1.1 | HTTP/2 | HTTP/3 | 代理流量 |
| --- | --- | --- | --- | --- |
| VLESS | 明文或 TLS | h2c 或 TLS | 必须 TLS | TCP、原生 UDP 帧、可选 UoT / sing-mux |
| VMess AEAD | 明文或 TLS | h2c 或 TLS | 必须 TLS | TCP、原生 UDP 帧、可选 UoT / sing-mux |
| Trojan | 必须 TLS | 必须 TLS | 必须 TLS | TCP、UDP associate、可选 UoT / sing-mux |

`mode` 支持 `packet-up`、`stream-up`、`stream-one` 和 `auto`。`auto` 是服务端接受模式，不指定客户端最终选择哪种上传方式。

`http_version` 支持：

| 值 | 实际监听套接字 | 行为 |
| --- | --- | --- |
| 省略或 `auto` | TCP | 接收 HTTP/1.1 与 HTTP/2；TLS 通过 ALPN 协商，明文支持 h2c |
| `h1` | TCP | HTTP/1.1 |
| `h2` | TCP | HTTP/2，包含 h2c |
| `h3` | UDP | HTTP/3，要求 `certificate_ref` |

`network` 省略时从所选 HTTP 版本推导。显式指定不匹配的套接字网络会被拒绝。协议提供的是逻辑字节流，HTTP/3 的 UDP 套接字由传输工厂持有，因此 VLESS/VMess/Trojan 无须自行实现 QUIC。

本轮不增加 XHTTP 与 REALITY 的组合、Vision、VLESS 新加密或 XUDP；错误组合会在配置阶段被拒绝。

## 配置

完整示例见 [xhttp.yaml](../examples/xhttp.yaml)。

```yaml
protocol: vless
credential_refs: [device]
certificate_ref: server
transport:
  type: xhttp
  path: /proxy
  host: node.example.com
  xhttp:
    mode: auto
    http_version: h2
    extra:
      xPaddingBytes: "100-1000"
      scMaxEachPostBytes: 1000000
      scMaxBufferedPosts: 30
      scMaxBufferedBytes: 4194304
      scMaxTotalBufferedBytes: 67108864
```

`path` 默认为 `/`，是未转义的绝对路径，可附带查询参数。Path 前缀规范化和字段提取沿用 Polaris。`host` 可省略；配置时忽略请求 Host 的大小写和端口，不将 `X-Forwarded-For` 当作可信客户端地址。

`extra` 是 YAML 映射或 API JSON 对象，保留上游字段拼写。范围值支持整数、`"from-to"` 字符串及 `{from, to}` 对象。

支持的服务端字段：

- Padding：`xPaddingBytes`、`xPaddingObfsMode`、`xPaddingKey`、`xPaddingHeader`、`xPaddingPlacement`、`xPaddingMethod`。
- 会话与序号：`sessionIDPlacement`、`sessionIDKey`、`seqPlacement`、`seqKey`。
- 上传与响应：`uplinkDataPlacement`、`uplinkDataKey`、`noSSEHeader`、`scStreamUpServerSecs`。
- 资源边界：`scMaxEachPostBytes`、`scMaxBufferedPosts`、`scMaxBufferedBytes`、`scMaxTotalBufferedBytes`、`scMaxActiveSessions`、`scMaxConcurrentRequests`、`serverMaxHeaderBytes`。
- HTTP/3 窗口：`h3InitialStreamReceiveWindow`、`h3MaxStreamReceiveWindow`、`h3InitialConnectionReceiveWindow`、`h3MaxConnectionReceiveWindow`。

未知字段和客户端专用字段（例如 `xmux`、`downloadSettings`、`headers`、`scMinPostsIntervalMs`、`uplinkChunkSize`）在监听器配置中明确拒绝。移植包保留客户端辅助代码与测试用于互通回归，Lunaris 没有新增 XHTTP 出站产品接口。客户端自行设置 XMUX，与协议内可选的 `multiplex` / sing-mux 是两种不同层次的复用。

## 生命周期与资源

XHTTP 会话、HTTP 请求、物理连接和协议转发流分别计数。`packet-up` 的上下行会使用不同 HTTP 连接，不能把单个物理 HTTP 连接等同于一个协议用户流。重建后的流受节点的握手超时、待握手名额和连接限额约束，协议认证后进入原有 relay。

默认单 POST 上限 1,000,000 字节、单会话上传缓冲 4 MiB、全监听器上传缓冲 256 MiB，可通过 `extra` 调整。接入层拒绝超过 16 MiB 的单 POST、64 KiB 的 padding、64 MiB 的单会话缓冲或 HTTP/3 流窗口，以及 1 GiB 的总上传缓冲或 HTTP/3 连接窗口。

活动 XHTTP 会话上限取配置值与 `max_connections + max_udp_sessions` 的较小值。并发请求上限进一步受 `2 × (max_connections + max_udp_sessions) + max_pending_handshakes` 限制。物理 HTTP 连接上限为 `min(65536, max(2, 2 × (max_connections + max_udp_sessions)))`；实际 TCP/UDP 转发仍分别受 relay 原有限额约束。这些是节点所拥有资源的边界，不是进程总 RSS 上限。

未配对的上传会话和未完成的协议握手受握手期限约束。完整包上传读取正文前先预留字节预算，取消后释放；乱序包只有在序号连续时才交给协议。

停止或重载会关闭全部重建流、HTTP/QUIC 连接、请求体和队列，并等待 handler 与协议清理。`Stop(ctx)` 超时后仍保留清理所有权，后续调用可以确认释放。HTTP/1.1 的单流请求使用有界预读识别截断正文，及时取消待处理的协议/出口操作；正常 EOF 仍作为读取结果保留。

相较源实现，移植还增加了响应写入中断与退出等待、请求体取消、即时停止 keepalive 定时器，以及配置范围溢出校验；修正了幂为 2 的字符表导致随机字符串生成停滞的问题。

## 验证

```sh
make check
make build
python3 scripts/test-xhttp.py --client /path/to/xray
```

Go 测试包含原移植包测试，以及实际 VLESS/VMess/Trojan TCP/UDP 转发、三种上传模式与 auto、HTTP/1.1–3、h2c、UoT/mux、配置快照隔离、握手超时、客户端取消、停止截止后继续清理和重载撤销。

2026-11-01，本机独立 Xray 26.10.31（源码提交 `a4a3dff5b20c` 构建）通过 47 个 TCP/UDP 组合：44 个协议/模式/HTTP 组合及 3 个 header/cookie/query、自定义 padding 组合。TLS 客户端固定临时测试证书的 SHA-256；未改系统信任。UDP 设置 `XRAY_CONE_DISABLED=true` 使用原生协议帧。

执行期间曾出现一次 UDP 回包超时，后续完整矩阵通过；既有偶发 UDP 异常仍不能据此认定已修复。本机回环不代表真实 CDN、反向代理、公网丢包/MTU、Linux 运行或长期负载验证。

源文件的 MPL-2.0 与 GPL-3.0-or-later 声明保留，来源和改动见 [第三方声明](../THIRD_PARTY_NOTICES.md)。
