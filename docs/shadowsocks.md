# Shadowsocks AEAD：当前实现

状态：协议核心与 SQLite 管理模式。使用上游 `sing v0.9.6` 和 `sing-shadowsocks v0.2.9`，没有本地模块替换或 vendor 副本。

## 支持范围

- `aes-128-gcm`、`aes-256-gcm`、`chacha20-ietf-poly1305`。
- TCP 和 UDP，可分别启用；一个监听器可配置多个不同密码，各用户共用监听端口。
- 目标 IP 或域名；直接出口。
- TCP 半关闭、待拨号取消、UDP 多目标会话、空闲回收、启动失败清理和进程退出回收。

支持通过管理 API 应用或 managed 的 SIGHUP 进行差异重载：凭据或运行参数变化时关闭旧会话并重建受影响实例，失败时尝试恢复原配置。本页描述原生 classic AEAD 的基础实现；后续已接入的 SS2022、多用户、mux/UoT 和[插件](shadowsocks-plugins.md)见[当前协议矩阵](protocols.md)。

## 协议与产品职责

TCP 使用 authscan 选择候选凭据后，由上游 Shadowsocks service 完成解析和认证，再交给统一的 sing TCP handler。UDP 复用上游 AEAD packet codec；classic AEAD 每个 UDP 数据报独立加密，入站与出站采用相同的盐、子密钥与地址封装格式。[Shadowsocks AEAD 规范](https://shadowsocks.org/doc/aead.html)。

Lunaris 不调用上游 service 中的旧 UDP 会话缓存，自己在 sing `PacketConn`、`buf.Buffer`、`pipe.Deadline` 接口上组合会话和队列。这样可以明确限制排队和关闭时的缓冲区所有权，无需修改上游代码。

同端口多用户直接在 `credential_refs` 中列出各用户凭据，不设置 `server_key_ref`。TCP 按物理来源 IP 缓存候选，UDP 按来源 IP/端口缓存；UDP 会话键包含用户，回包使用该用户密钥。详细限制见 [authscan](authscan.md)。

## 资源边界

`examples/shadowsocks.json` 给出可配置的握手/拨号/空闲/关闭超时、活动连接、待认证握手、UDP 会话、每会话队列数量和目标数量。UDP 只接收该会话实际联系过的目标端点的响应。

额外固定边界：每个监听器的 UDP 待转发载荷合计最多 16 MiB；数据报入队前缩小接收缓冲，避免每个小包都保留 64 KiB。队列或字节预算用尽时丢弃新 UDP 数据报；关闭会话释放所有待处理缓冲。

经过认证的 TCP/UDP 入站 salt 与 UDP 回包 salt 共用按用户隔离的 60 秒内存重放窗口，最多保留 65,536 个条目；UDP 回包在发出前登记 salt，避免被反射成新请求；正常 UDP 往返通常占用两个条目。窗口满时拒绝新条目直到旧条目过期。此边界也会限制高包速 UDP 场景，当前不宣称完成高吞吐调优。窗口属于实例内存，监听器重建（包括失败恢复）或进程重启会重置它；未重建的实例保留该状态。

## 验证范围

本地测试包含三种方法的 TCP/UDP 回环、TCP 半关闭、IP/域名目标、错误密码拒绝、UDP 重放拒绝、空闲回收、满队列关闭、待拨号取消与迟到上游回收、部分启动失败回收、队列总预算。

另有不使用 sing packet encoder/parser 的 AES-128-GCM UDP wire fixture，按协议格式构造请求并解密响应。它提供独立封装校验，仍不等同于独立客户端软件或真实设备互通。

macOS 本地 UDP 测试采用小于其 socket 单报文上限的载荷。Linux 交叉编译、真实 Linux 执行、外部客户端互通和公网网络测试是不同层次的证据，应分别记录；当前完成情况见开发计划与交付说明。
