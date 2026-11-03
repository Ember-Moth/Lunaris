# 源进源出与 PROXY protocol

节点默认保留连接进入的本机 IP，并在建立同地址族的出站连接时使用该 IP。出站端口仍由系统分配。功能属于连接运行时，不新增节点配置开关，也不改变 SQLite schema。启动设置和管理 API 的可信反代策略保持独立。

## 地址语义

- **客户端地址**：普通连接来自 socket 对端；带有效 PROXY header 时来自 header 的 source 地址。
- **入口本机地址**：普通 TCP 来自已接受 socket 的 LocalAddr，原生 UDP 来自每个数据报的目标地址；PROXY header 的 destination 可提供前置转发前的入口地址。
- **代理目标地址**：由通过认证的代理协议请求指定；不把它误当作入口地址。

入口地址在连接上下文中记录一次。TLS、WebSocket、HTTPUpgrade、插件、UoT、sing-mux 和协议内部复用继承原入口，不用逻辑子流的 LocalAddr 覆盖它。QUIC 在接受连接时记录实际入口，Hysteria2/TUIC 的 TCP 与 UDP 子流均继承；TUIC 的预读缓存保持原字节所有权。Naive HTTP/1.1–3 与 XHTTP 使用 HTTP 连接的本地端点；XHTTP 上下行分离时，协议流沿用下载连接的入口地址。

## 出站规则

1. 入口 IP 为有效单播地址，且不是回环或链路本地地址时，优先绑定该 IP。
2. TCP 出站复制拨号器后设置 LocalAddr，不修改共享拨号器。域名保留双栈解析，再选择匹配入口的候选；只有另一地址族时按规则回退。
3. UDP 关联最多创建 IPv4、IPv6 各一个 socket；同一个关联访问两种地址族时均可工作，同族 socket 绑定入口 IP。
4. 对端只有另一地址族，或入口地址未分配在本机而产生 EADDRNOTAVAIL 时，回退到系统选源。连接拒绝、普通拨号超时等错误不会触发换源重试。
5. 回环、链路本地、未知入口继续由系统路由选源，避免反代回环接入把所有公网出站绑定在回环地址上。

源进源出不创建网卡地址、路由、策略路由、透明代理或 NAT 规则。前置转发声明的公网地址若不属于本机，不能凭 header 使内核从该地址发包。系统 DNS 查询和启动时的 REALITY 目标探测没有某个客户端入口；按系统路由运行。已接入连接的 REALITY 回落、ShadowTLS/Restls 目标拨号则继承入口。

## UDP 多入口

Linux 和 macOS 的通配 UDP socket 使用内核 ancillary data 获取每个数据报的本地目标，并从相同本地地址回复。明确绑定的 socket 直接使用其绑定地址。

- Shadowsocks classic、SSR 会话包含本地端点，避免同一客户端访问节点多个 IP 时混用关联。
- SS2022 的同一加密会话固定入口，换本地目标必须创建新的加密会话；保留原有重放保护。
- Mieru UDP 会话同时区分远端、本地端点和会话 ID；回复使用保存的本地地址。
- KCP 按本地目标分配虚拟 socket，各端点共享连接、待认证和流数量限制。最多 64 个本地端点，全部待处理报文合计最多 16 MiB；关闭节点时一并回收。
- QUIC 保留原生 UDPConn，让 quic-go 自身的 packet info 与回包选源继续工作。

其他操作系统不宣称支持通配 UDP 的源地址保留；启动此类监听会明确报错。Linux/macOS 以外的持久化运行支持仍受数据目录锁等现有平台边界限制。

## PROXY protocol 自动识别

参考 [Polaris 的自动检测器](https://github.com/HyperPteLtd/Polaris/blob/56d52fb44958ef3cc2a7fb841cd240f8206234b2/internal/runtime/proxy_protocol.go)，在所有节点 TCP 载体上、TLS 或协议解码之前自动识别 v1/v2。无需配置 accept_proxy_protocol；普通连接仍走原来的协议路径。

- 支持 TCP4/TCP6；v1 UNKNOWN、v2 LOCAL/UNSPEC 保留真实 socket 端点。
- 支持分片与 header 后附带应用数据；探测不会吞掉普通协议字节。
- 只消费一次头部，不在 TLS 明文、复用子流或 UDP/QUIC 数据报内再次嗅探。
- 已确认是 PROXY 前缀但格式错误、截断或超限时拒绝连接；不回退成普通流量。
- 嗅探按连接惰性执行，不阻塞 Accept 循环。读窗口最多 3 秒，且不会延长原握手期限或覆盖并发更新的读期限。
- v1 总长度最多 108 字节；v2 长度字段最多 65535 字节，以有界缓冲消费附加数据。TLV 不赋予 TLS、用户或权限属性。
- 仅接收 TCP 的 INET/INET6 信息；不提供 UNIX 地址或 UDP PROXY v2 接入。管理 HTTP 监听器不启用这个自动检测器。

## 地址声明与鉴权

自动识别沿用 Polaris 的策略：**接受任何对端提供的有效头部**。这些地址是对端声明的元数据，只有前置代理可信且入口访问受控时，才能把它当作客户端真实 IP。来源声明不能替代协议凭据，不改变管理员身份，也不赋予额外访问权限。

这是一项明确的端口共用策略，不等同于 HAProxy 规范建议的“只接受已配置代理”的部署模型；规范的安全边界见 [PROXY protocol 文档](https://www.haproxy.org/download/3.0/doc/proxy-protocol.txt)。不能把自动识别得到的地址直接用作可信 IP 白名单或鉴权依据。HTTP X-Forwarded-For 不参与节点代理流的地址恢复；管理 API 仍使用单独的 trusted_proxies 校验。

## 验证

Go 回归覆盖 v1/v2、IPv4/IPv6、UNKNOWN/LOCAL、分片、同端口普通连接、非法/截断头、期限、TLS/HTTP 载体、QUIC 缓冲子流、原生 UDP 回包、双栈出站和停止回收。实际 TCP/UDP 目标检查源地址，而非只检查上下文字段。

```sh
make check
make check-web
```

独立 Mieru/SSR/kcptun 客户端还可验证实际数据面的源 IP：

```sh
make build-web
go build -C test/clients/mieru -o ../../../bin/test-mieru-client .
go build -C test/clients/shadowsocksr -o ../../../bin/test-ssr-client .
go build -C test/clients/ssplugins -o ../../../bin/test-ssplugins-client .
python3 scripts/test-origin.py --source-ip "$NODE_IP"
```

`NODE_IP` 必须是本机已分配的非回环 IPv4 地址；目标只监听本机回环地址。脚本经 JSON API 创建临时 SQLite 配置，再以 managed 运行，不修改系统接口、路由或生产数据。本机测试与 Linux 交叉编译不替代 Linux 运行、公网 NAT/负载均衡或真实部署验收。

2026-11-02 验证记录：`make check`、`make check-web`（vet/race）、受影响专项回归重复验证及 Linux amd64/arm64 核心/管理构建全部通过。实际源 IP 检查使用本机已分配的非回环 IPv4；另验证 IPv6 header、IPv4/IPv6 混合 UDP 关联、跨族 TCP 和仅 AAAA 域名的回退。独立 Mieru TCP/UDP underlay、SSR、kcptun 客户端的 TCP/UDP 目标均观察到正确入口 IP。

普通连接兼容性复跑通过 19 个基础协议组合、96 个 Xray VLESS 组合，以及 162 个 Shadowsocks 插件组合和 4 个错误凭据检查。插件矩阵曾在 chacha20 的 WebSocket early-data 组合出现一次断连，随后该组合单独重复 5 次及完整矩阵通过；根因尚未定位，不作为已修复问题。此前 VLESS 的偶发超时也不因本轮通过而宣称已消除。

配置路由/DNS 后，业务与协议目标使用相同配置代次的解析器；DNS 上游主机名保留系统引导解析，避免递归。代理 UDP/53 经自定义解析器处理时仍传递入口地址，DoH 不跨不同入口绑定复用连接。详见[路由和 DNS](routing-dns.md)。
