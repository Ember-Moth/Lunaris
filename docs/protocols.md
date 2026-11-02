# 协议、传输与证书

状态：2026-11-01，已接入十一类节点协议，Shadowsocks 同时支持 classic AEAD 与 2022。所有协议共用 sing 转发与运行管理；直接依赖上游 Go modules，不使用 sing-box 模块、本地 vendor 或本地 replace。P5 HTTP 管理 API 已接入，Web 表单留待 P6。

## 支持矩阵

`network` 指节点实际监听的套接字，不是客户端请求转发的流量类型。例如 VLESS 用 TCP 套接字承载 TCP 和 UDP；Hysteria2/TUIC 用 UDP 套接字上的 QUIC 承载两者。

| 协议 | `network` | `transport.type` | TLS | 转发 | 凭据 |
| --- | --- | --- | --- | --- | --- |
| Shadowsocks classic AEAD | 原生 TCP/UDP；插件按载体 | `native` 或[插件](shadowsocks-plugins.md) | 按插件 | TCP、原生 UDP / UoT | 每监听器一个密码 |
| Shadowsocks 2022 | 原生 TCP/UDP；插件按载体 | `native` 或[插件](shadowsocks-plugins.md) | 按插件 | TCP、原生 UDP / UoT | 单用户密钥；AES 支持多用户 |
| Snell v5/v6 | TCP | `tcp` | 使用协议自身格式 | TCP、UDP | 每监听器一个 PSK |
| Mieru v3 | TCP / UDP | `native` | 使用协议自身加密 | TCP、UDP | 用户名与密码映射 |
| ShadowsocksR | TCP / UDP | `native` | 使用选定 cipher/obfs | TCP、UDP | 单用户或 UID/密码映射 |
| Naive | TCP 或 UDP | `http` 或 `quic` | 必须 | TCP、UDP（UoT） | 用户名与密码映射 |
| VLESS | TCP；XHTTP h3 用 UDP | `tcp`、`ws`、`httpupgrade`、`reality`、`xhttp` | 可选 | TCP、原生 UDP / XUDP（Vision） | 一个或多个非零 UUID |
| VMess AEAD | TCP；XHTTP h3 用 UDP | `tcp`、`ws`、`httpupgrade`、`reality`、`xhttp` | 可选 | TCP、原生 UDP 帧 | 一个或多个非零 UUID；客户端 `alter_id: 0` |
| Trojan | TCP；XHTTP h3 用 UDP | `tcp`、`ws`、`httpupgrade`、`reality`、`xhttp` | 必须 | TCP、UDP associate | 一个或多个密码 |
| AnyTLS | TCP | `tcp`、`reality` | 必须 | TCP、UDP（内建 UoT v2） | 一个或多个密码 |
| Hysteria2 | UDP | `quic` | 必须，TLS 1.3 | TCP、UDP datagram | 一个或多个密码 |
| TUIC v5 | UDP | `quic` | 必须，TLS 1.3 | TCP、UDP datagram / UDP stream | UUID 与密码映射 |

省略 `network` 时按协议选择监听套接字。VLESS/VMess/Trojan/AnyTLS 省略传输时默认为 `tcp`，Naive 默认为 `http`；Hysteria2/TUIC 默认为 `quic`。不支持的组合会在 `check`、保存草稿和应用前被拒绝。

VMess 使用 `sing-vmess`；VLESS 使用从 Polaris 移植的 sing-vmess 扩展，AnyTLS 使用 `sing-anytls`，Hysteria2/TUIC 使用 `sing-quic`。Trojan 在项目内按[原始协议](https://trojan-gfw.github.io/trojan/protocol)实现，地址解析、数据包缓冲和转发仍使用 sing。

## 配置

完整示例见 [protocols.yaml](../examples/protocols.yaml)，包含六个新增协议的监听器。示例绑定回环地址，部署时按实际情况修改监听地址、端口和证书文件。

```yaml
schema_version: 1
credentials:
  - id: device
    secret_env: LUNARIS_UUID
certificates:
  - id: server
    certificate_file: fullchain.pem
    private_key_file: privkey.pem
listeners:
  - id: vless-main
    protocol: vless
    address: 127.0.0.1
    port: 8443
    credential_refs: [device]
    certificate_ref: server
    transport:
      type: ws
      path: /proxy
      host: node.example.com
```

- `certificate_ref` 启用 TLS；VLESS/VMess 使用 tcp/ws/httpupgrade 且不设置它时是明文载体；REALITY 使用独立的私钥配置。TCP TLS 最低版本为 1.2，QUIC 为 1.3。
- `ws` 和 `httpupgrade` 必须设置绝对 `path`，服务端精确匹配转义后的路径。路径不含 query/fragment；请求中的查询参数不参与路径匹配。
- 可选 `host` 精确匹配 HTTP Host（大小写不敏感，端口属于 Host 的一部分）。省略它表示不限制 Host。
- HTTP 传输使用 HTTP/1.1。WebSocket 只接受二进制数据帧，不启用压缩；单消息上限 1 MiB。HTTPUpgrade 升级后直接承载协议字节流。
- VLESS 的 `options.flow` 与 `options.decryption_ref` 见 [Encryption 与 Vision](vless-encryption-vision.md)。
- 凭据来源仍为 `secret`、`secret_env`、`secret_file` 三选一。VLESS/VMess 的 secret 是 UUID；SS2022 是 Base64 密钥；其他协议是密码。新增协议可在 `credential_refs` 中列多个用户，不允许重复协议身份。
- VMess、Trojan、AnyTLS 和 Hysteria2 当前没有额外 `options`，省略或写 `{}`。未知选项会报错，不会静默忽略。

TUIC 通过 UUID 区分用户，密码保持为独立凭据资产。`options.users` 必须与 `credential_refs` 一一对应：

```yaml
credential_refs: [phone, laptop]
certificate_ref: server
options:
  congestion_control: cubic # cubic / new_reno / bbr
  users:
    - uuid: c8820ed3-e4ee-47ad-a5bd-ece70763e32c
      credential_ref: phone
    - uuid: ab20e8ef-131d-448d-a58d-b6d81e25073b
      credential_ref: laptop
```

Hysteria2 使用自适应带宽模式；本轮不暴露固定 Brutal 带宽或混淆配置。TUIC 的 0-RTT 关闭，Hysteria2/TUIC 客户端 ALPN 使用 `h3`。

## 证书资产与重载

证书与私钥必须是匹配的 PEM，每个文件限制为 1 MiB。相对路径基于 YAML 所在目录。加载时校验 PEM 和密钥匹配；证书的域名、有效期和信任链由客户端 TLS 验证，本节点不自动签发或续期。

文件模式下，替换证书文件后发送 SIGHUP，内容变化会重建所有引用它的监听器并关闭旧会话。没有变化的证书和监听器保持原实例。解析失败会在停止旧监听器之前被拒绝。将两个文件替换完毕后再发送重载信号。

管理模式导入时将证书链和私钥保存为 SQLite 不可变资产，配置版本绑定资产 ID。更新证书生成新资产，历史版本仍绑定原内容；重启从 committed 版本恢复，不依赖原 PEM 文件。草稿不会自动生效。备份和还原包含证书与私钥，数据库和备份使用原有的目录/文件权限控制，不提供额外数据库加密。

运行时指纹包含实际证书内容；状态、版本元数据和错误信息不返回私钥。证书的历史保留、回退、备份流程与[持久化配置服务](persistent-configuration.md)一致。

## 生命周期和资源边界

所有协议通过独立的协议注册表与传输注册表组装；Shadowsocks 的原生 TCP/UDP 和 QUIC 监听也由传输实例持有。实现与扩展契约见[工厂注册表](factory-registries.md)。

流式监听器在接收连接时登记所有载体，包括尚未认证的 TLS 和已经升级的 HTTP 连接。握手超时、待认证名额和总连接数覆盖这些载体。`net/http` 升级后会清除期限，适配层恢复原握手期限；收到首个已认证的转发回调后释放待握手名额。

QUIC 在 transport 的连接回调中限制总连接和进行中的 TLS 握手；协议层还执行认证。限制双向流数、单向流数和接收窗口；共享 relay 分别限制 TCP 流和 UDP 会话。停止时同时关闭 QUIC listener、transport 和 UDP socket，回收已接受会话。HTTP/3 控制流和 TUIC 认证流另预留少量协议名额，因此即使 TCP/UDP 流上限设置为 1 也能完成握手。

这些限制约束 Lunaris 持有的连接和流；上游协议库内部仍有自己的排队、缓冲和拥塞控制策略，不能将它们解释为整个进程的严格内存上限。

## 验证与边界

自动回归包含协议/传输组合的真实 TCP/UDP 回环、分片握手、错误凭据、升级后握手超时、停止旧会话、证书轮换、未变化连接保留、版本绑定和备份还原。网络测试使用上游客户端库，Trojan 用协议帧测试。

独立客户端验证脚本：

```sh
make build
python3 scripts/test-interop.py --client /path/to/sing-box --server bin/lunaris
```

脚本只绑定回环地址，生成临时证书和配置，不下载客户端、不设置系统代理。使用正式发行客户端进程测试 19 个协议/传输/TLS 组合（包含原生 Shadowsocks）；所有组合均测试 TCP 和 UDP，AnyTLS UDP 使用内建 UoT v2。VLESS/VMess 客户端设置 `packet_encoding: ""` 使用原生 UDP 帧，避免启用额外封装。

验证记录：2026-11-01，macOS arm64 上使用官方 sing-box 1.14.4（发行 SHA-256 已核对）完成 18 个组合。正式发行客户端是独立进程，但与服务端共享部分 SagerNet 协议库来源；此结果不代表所有其他客户端实现都已验证。独立工厂注册表重构后，同一发行客户端再次通过 19 个组合，新增 Shadowsocks 原生 TCP/UDP 覆盖。

已增加 [UoT、sing-mux 和 REALITY](connection-extensions.md)，包括可选的旧客户端兼容。新增 [Naive 与 Shadowsocks 2022](naive-ss2022.md)，包含 AES 同端口多用户。已移植 [XHTTP](xhttp.md) 和 [VLESS Encryption、Vision、XUDP](vless-encryption-vision.md)。仍不宣称支持 gRPC、WebSocket early-data 或 PacketAddr 扩展。部分库能解析额外指令，不作为已验证产品能力。

本地互通和交叉编译不等同于真实 Linux、公网丢包/MTU、长期运行和压力验证；这些环境验收仍待完成。

Snell、Mieru、ShadowsocksR 的详细配置、版本限制及独立客户端证据见[说明](snell-mieru-ssr.md)。

Shadowsocks classic AEAD 与 SS2022 已支持[六类内置插件](shadowsocks-plugins.md)。插件在传输注册表中选择；kcptun 使用 UDP 套接字，其余插件使用 TCP，UDP 转发通过显式启用的 UoT 提供。
