# Naive 与 Shadowsocks 2022

两者通过现有协议注册表组装，沿用凭据资产、限额、重载和共享 relay。Shadowsocks 2022 仍使用 `protocol: shadowsocks`，由 `options.method` 选择。

## Naive

支持带 TLS 的 HTTP/1.1 CONNECT、HTTP/2 和 HTTP/3，包含 Naive variant-1 padding、多用户认证及 UoT v1/v2。默认传输是 `http`，监听 TCP 并通过 ALPN 协商 HTTP/2 或 HTTP/1.1；`quic` 监听 UDP，承载 HTTP/3。两种传输均要求 `certificate_ref`，不接受 WebSocket、HTTPUpgrade、REALITY 或额外 sing-mux。

```yaml
protocol: naive
credential_refs: [phone, laptop]
certificate_ref: server
transport: {type: http} # HTTP/3 使用 quic
options:
  users:
    - username: alice
      credential_ref: phone
    - username: bob
      credential_ref: laptop
```

用户名与凭据引用一一对应，密码仅存于凭据资产。服务端自动识别 UoT；sing-box 客户端转发 UDP 时须设置 `udp_over_tcp.enabled: true`，通常选择 version 2。HTTP/3 使用 QUIC 流承载 UoT，并不是原生 UDP 数据报代理或 MASQUE。

要同时提供 HTTP/2 与 HTTP/3，配置两个监听器，分别使用 `http` 和 `quic`；可以共用同一数字端口，因为 TCP 与 UDP 套接字独立。完整示例见 [naive-ss2022.yaml](../examples/naive-ss2022.yaml)。

HTTP、HTTP/2 和 HTTP/3 的监听、TLS、连接限制归传输层所有；Naive 工厂只接收 HTTP 请求并进行认证、padding 和目标地址处理。HTTP/2/3 流关闭会先中断并等待读写结束，再结束 HTTP handler。QUIC 0-RTT 关闭。未实现伪装网站、自动证书签发或流量不可识别性保证。

协议格式参考 [NaiveProxy padding](https://github.com/klzgrad/naiveproxy/blob/master/src/net/tools/naive/naive_padding_socket.cc) 和 [sing-box Naive 入站](https://github.com/SagerNet/sing-box/blob/v1.14.4/protocol/naive/inbound.go)。HTTP/2 使用 `golang.org/x/net/http2`，HTTP/3 使用已有 `sagernet/quic-go/http3`，认证和 UoT 复用 sing；没有引入 sing-box 模块或复制其协议包。

## Shadowsocks 2022

| method | 解码后的密钥长度 | 单用户 | 同端口多用户 |
| --- | --- | --- | --- |
| `2022-blake3-aes-128-gcm` | 16 字节 | 支持 | 支持 |
| `2022-blake3-aes-256-gcm` | 32 字节 | 支持 | 支持 |
| `2022-blake3-chacha20-poly1305` | 32 字节 | 支持 | 不支持，配置阶段拒绝 |

密钥必须是对应长度的标准 Base64 编码，不接受普通口令、超长密钥自动派生、重复密钥或服务端凭据中的冒号密钥链。可用 `openssl rand -base64 16` 或 `openssl rand -base64 32` 生成。

单用户模式只引用一个密钥：

```yaml
protocol: shadowsocks
credential_refs: [ss-user]
options:
  method: 2022-blake3-aes-128-gcm
```

多用户模式将服务端身份密钥与用户密钥分开：

```yaml
protocol: shadowsocks
credential_refs: [ss-alice, ss-bob]
options:
  method: 2022-blake3-aes-128-gcm
  server_key_ref: ss-server
```

`server_key_ref` 指向独立凭据资产，不加入用户 `credential_refs`。客户端 password 使用 `服务端密钥:该用户密钥`。所有密钥均需满足该方法的长度约束。服务端密钥、用户密钥或用户列表变化会重建监听器并撤销旧会话；非法密钥在停止现有监听器之前被拒绝。服务端密钥引用参与运行时指纹与持久化版本，沿用既有凭据存储，不增加数据库迁移。

三种方法都支持原生 TCP/UDP、可选 UoT v1/v2 以及 smux/yamux/h2mux；与 classic AEAD 一样，可以同时开放原生 UDP、UoT 和 mux：

```yaml
network: [tcp, udp]
udp_over_tcp: true
multiplex: {enabled: true, padding: true}
```

密码学、时间戳验证、协议帧和响应编码使用 `sing-shadowsocks/shadowaead_2022`。锁定上游 `65740e0f0e3e`，包含首个大响应分段及输入长度校验修复；使用远程 Go module，无本地 vendor/replace。[上游源码](https://github.com/SagerNet/sing-shadowsocks/tree/65740e0f0e3ea0d78beb9f3972ba42a75a6cd160/shadowaead_2022)

适配层只读取 UDP 会话路由标识，为每个已认证的用户/会话创建独立上游状态，避免旧 NAT 结束回调删除后继会话。认证失败不保留会话，活动会话受 `max_udp_sessions` 限制；转发空闲时释放活动名额，同时保留加密会话至少一分钟，避免短超时下服务端会话 ID 反复变化；复用时仍检查重放窗口。会话状态数量上限为 `min(65536, max(1024, 4 × max_udp_sessions))`，认证失败不占用该缓存。接收队列和总排队字节数沿用现有边界。TCP 关闭先撤销底层连接，再等待协议读写退出，避免与上游懒初始化响应 writer 并发。

## 验证

```sh
make check
make build
python3 scripts/test-naive-ss2022.py --client /path/to/sing-box
```

Go 回归覆盖 Naive 三种 HTTP 版本的 TCP/UDP、padding 分片和第八帧边界、错误认证与停止；SS2022 三种方法、AES 多用户、UoT/mux、非法密钥、UDP 重放、会话超限及服务端密钥轮换。

2026-11-01，本机 sing-box 1.14.4 发行客户端通过 Naive HTTP/2 和 42 个 SS2022 单/多用户与传输组合的 TCP/UDP。该客户端的 Naive HTTP/3 在本机报 `quic protocol error`，对照连接原版 sing-box 服务端也失败，尚未完成独立客户端 HTTP/3 验收。可显式添加 `--skip-naive-quic` 复跑其余 43 个组合；脚本会打印跳过项，不会将跳过计为通过。Go HTTP/3 回环通过与发行客户端验证分开记录。

本机回环和交叉编译不代表真实 Linux、公网 MTU/丢包、长期运行或生产验证。
