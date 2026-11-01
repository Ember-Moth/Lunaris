# VLESS Encryption 与 Vision

VLESS 工厂支持 `mlkem768x25519plus` Encryption 和 `xtls-rprx-vision`。协议服务由 Polaris 的 VLESS 扩展移植，传输、凭据解析、重载和转发继续使用 Lunaris 的现有接口。来源与许可见[第三方声明](../THIRD_PARTY_NOTICES.md)。

## 配置

```sh
bin/lunaris keygen vless
```

输出 JSON 中的 `decryption` 是服务端秘密配置，`encryption` 是客户端配置。生成器使用 X25519 静态认证密钥；协议的 1-RTT 密钥协商仍使用 ML-KEM-768 + X25519。客户端 UUID 与 `credential_refs` 对应。

将完整的服务端 `decryption` 保存为凭据，使用 `options.decryption_ref` 引用，支持 `secret_env`、`secret_file` 或加密凭据存储。不要把私钥直接放进 `options`：监听器配置会出现在管理 API 和配置导出中。

```yaml
schema_version: 1
credentials:
  - id: device
    secret_env: LUNARIS_UUID
  - id: vless-decryption
    secret_env: LUNARIS_VLESS_DECRYPTION
listeners:
  - id: encrypted-vless
    protocol: vless
    address: 127.0.0.1
    port: 8443
    credential_refs: [device]
    options:
      decryption_ref: vless-decryption
      flow: xtls-rprx-vision
    transport:
      type: tcp
```

完整示例：[vless-encryption.yaml](../examples/vless-encryption.yaml)。省略 `flow` 即普通 VLESS Encryption；省略 `decryption_ref` 即关闭 Encryption。引用空值或 `none` 会报错，避免错误配置悄悄关闭加密。同一监听器的全部 UUID 使用相同 flow。

只用 TLS + Vision 时，设置 `certificate_ref`、`transport.type: tcp` 和 `options.flow: xtls-rprx-vision`。REALITY + Vision 使用既有 [REALITY 配置](connection-extensions.md)，添加同一 flow 即可。

## 支持组合

| 外层传输 | Encryption | Vision 不加 Encryption | Encryption + Vision |
|---|---|---|---|
| TCP 明文载体 | 支持 | 拒绝 | 支持 |
| TCP + TLS | 支持 | 支持 | 支持 |
| REALITY | 支持 | 支持 | 支持 |
| WebSocket / HTTPUpgrade，可带 TLS | 支持 | 拒绝 | 支持 |
| XHTTP h1 / h2 / h3 | 支持 | 拒绝 | 支持 |

Vision 直传保留加密层下面的载体：例如 Encryption + WebSocket 仍经过 WebSocket 帧，Encryption + TLS 仍经过外层 TLS。不会解包到物理 socket 而破坏这些传输。新版 REALITY 使用指针形式的缓存，直传时读取其当前缓冲区。

普通 VLESS 支持原生 UDP 帧；Vision 使用 XUDP。`multiplex.enabled` 表示 sing-mux，与 Vision 组合会被拒绝；它不控制 VLESS 自带的 XUDP 帧。XUDP 会话使用独立的读超时，不把单个 UDP 会话的空闲超时设到整个物理连接上。

## Encryption 字符串

服务端格式遵循 [Xray VLESS 配置](https://xtls.github.io/en/config/inbounds/vless.html)：

```text
mlkem768x25519plus.<mode>.<ticket>[.<padding>].<private-key>[.<private-key>...]
```

- `mode`：`native`、`xorpub` 或 `random`。
- `ticket`：`0s` 关闭恢复；或 0–65535 秒及区间，例如 `600s`、`300-600s`。
- 密钥：Base64URL 无填充的 32 字节 X25519 私钥，或 64 字节 ML-KEM-768 seed。支持最多 8 项的链。
- padding：沿用 Xray 的概率/长度/间隔语法，最多 64 段；总长度不超过 65553 字节，总间隔不超过 10 秒，受监听器握手超时进一步约束。

客户端使用相同的 mode、公钥链和 `1rtt`/`0rtt` 字段。X25519 公钥为 32 字节，ML-KEM-768 公钥为 1184 字节。选择 `0rtt` 的客户端首次仍会完成完整握手并取得 ticket，后续连接才恢复。

每个监听器保留最多 `min(4096, max_connections + max_udp_sessions)` 张 ticket；缓存满时继续接受 1-RTT，但不发放可恢复的新 ticket。每张 ticket 最多记住 256 个恢复密钥，重复或超额恢复会失败。该上限避免握手历史无限占用内存；达到上限的客户端需要重新完成 1-RTT。停止/重建监听器清空 ticket 与重放记录。

## 生命周期与验证

- Encryption 握手继承传输握手预算；padding 等待可取消，未认证连接不会提前释放 admission 配额。
- 实际 ticket 清理任务在监听器 Start 时创建，Stop 后回收。构造失败不会启动后台任务。
- 更换 decryption 凭据会重建受影响的监听器，撤销旧连接与 ticket；其他监听器保留。无效新配置在应用前拒绝。
- 保留移植的帧边界、Vision TLS 检测、分片、加密记录和 ticket 恢复测试；新增取消、缓存限额、重复 0-RTT、XUDP deadline、并发写帧、错误 UUID/flow、停止和密钥轮换测试。

独立客户端脚本：

```sh
make build
python3 scripts/test-vless.py --client /path/to/xray
```

脚本使用临时回环监听器和证书，覆盖三种模式、1-RTT/0-RTT、Vision 开关、各传输、XUDP、内层 TLS 1.2/1.3 和大数据传输；同一 Xray 进程连续建连，实际使用恢复 ticket。另测 ML-KEM-768 静态认证与混合密钥链。

2026-11-01 验证结果：`make check`、管理构建 vet/race、Linux amd64/arm64 的 CGO=0 交叉编译，以及 **96 个独立 Xray 互通组合**全部通过。配置示例通过 `lunaris check`。

记录的互通客户端是 Xray 26.10.31，官方源码 `a4a3dff5b20c` 的独立构建。验证仅针对本机回环；公网/CDN、长期负载和真实客户端设备不在本次证据范围内。未接入 Vision seed 参数、ML-DSA、gRPC 或 PacketAddr。
