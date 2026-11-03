# 代理出站

Lunaris 的出站由路由选择，使用独立协议客户端连接上游代理。配置、凭据和应用流程沿用 JSON API 与 SQLite 版本管理。首批提供 SOCKS5、HTTP CONNECT 和 Shadowsocks；直接使用当前锁定的 sing / sing-shadowsocks 模块，无 sing-box 生产依赖。

## 首批能力

| 出站 protocol | TCP | UDP | 认证与传输 |
| --- | --- | --- | --- |
| `socks5` | CONNECT | UDP ASSOCIATE | 原生 TCP 控制连接；匿名或用户名/密码 |
| `http` | HTTP/1.1 CONNECT | 不支持，明确失败 | 原生 HTTP；匿名或 Basic 代理认证 |
| `shadowsocks` | 原生加密流 | 原生加密数据报 | 单用户凭据；classic AEAD 与 SS2022 |

Shadowsocks 方法：`aes-128-gcm`、`aes-256-gcm`、`chacha20-ietf-poly1305`、`2022-blake3-aes-128-gcm`、`2022-blake3-aes-256-gcm`、`2022-blake3-chacha20-poly1305`。SS2022 使用单个规范 base64 密钥：AES-128 为 16 字节，其余为 32 字节。

首批没有出站 TLS/HTTPS CONNECT、SOCKS4、SS2022 多用户身份链、插件、mux/UoT、出站链、测速组或故障转移。入站已经支持的传输组合不自动代表出站也支持。HTTP 与 SOCKS5 的密码认证使用其原生明文控制通道。

## 配置契约

`config.outbounds` 最多 64 项，每个出站包含：

- `id`：唯一且稳定的路由引用，1–64 个 ASCII 字母、数字、下划线或连字符；`direct`、`block`、`dns` 保留。
- `name`：可选展示名称，单独改名不重建连接。
- `protocol`：`socks5` / `http` / `shadowsocks`。
- `address`、`port`：上游域名或裸 IP，以及 1–65535 端口。IPv6 不带方括号，address 不含 URL scheme 或端口。
- `credential_ref`：现有 `credential_assets` 中的逻辑别名。密码不写入 options、URL 或普通 API 响应。
- `options`：SOCKS5/HTTP 使用 `{"username":"alice"}`，匿名时使用 `{}` 并省略 credential_ref；Shadowsocks 使用 `{"method":"aes-128-gcm"}` 并引用密码资产。

路由新增 `action: "route"` 与 `outbound: "出站 ID"`；`direct` 和 `block` 动作不得同时填写 outbound。`route.final` 指定未命中规则时的出站，默认为 `direct`，也可选择 `block` 或某个自定义 ID。`route.block` 仍最先匹配，其余规则保持声明顺序。

以下是 `config` 内的片段，完整请求见 [outbound.json](../examples/outbound.json)：

```json
{
  "outbounds": [
    {
      "id": "upstream",
      "protocol": "shadowsocks",
      "address": "proxy.example.com",
      "port": 8388,
      "credential_ref": "upstream-password",
      "options": {"method": "aes-128-gcm"}
    }
  ],
  "route": {
    "final": "direct",
    "rules": [
      {"action": "route", "outbound": "upstream", "match": ["suffix:example.com"]}
    ]
  }
}
```

配置通过现有 `PUT /api/v1/config/draft`、plan、apply 流程生效。`GET /api/v1/capabilities` 的 `outbound_protocols` 返回每种出站的 TCP/UDP 能力和 Shadowsocks 方法；OpenAPI 与生成的 TypeScript 包含相应字段。

未知协议、重复/保留 ID、缺失引用、无效密码材料或未支持选项会拒绝候选。配置校验和客户端构造不联系上游；应用成功表示本机配置生效，不表示已经验证远端密码或连通性。实际拨号或认证失败会返回该请求的错误，绝不自动改走直连。

## 分层与生命周期

```mermaid
flowchart LR
    I[入站协议] --> R[现有 TCP/UDP relay]
    R --> P[配置代次内的 policy]
    P --> T[route 选择目标]
    T --> D[direct / block / DNS]
    T --> O[出站 ID]
    O --> C[outbound 注册表与客户端]
    C --> B[入口绑源与配置 DNS]
    B --> S[上游代理]
```

`internal/outbound` 定义工厂、能力、严格规范化和客户端生命周期，协议实现分文件组织。客户端统一使用 sing 的 `N.Dialer`、`M.Socksaddr` 与 packet 接口。底层拨号器由 policy 注入，协议客户端不读取数据库、管理会话或本机配置文件。

`policy.Manager` 按配置和凭据材料持有共享代次；每个监听器获取一个 lease。最后一个 lease 释放时取消待完成握手、关闭已返回的 TCP/UDP 连接并等待客户端和解析器清理。单个请求的取消只控制拨号/握手；成功交给 relay 的连接不再绑定已结束的拨号请求。

代理端点、协议选项、路由或出站密码改变都会进入运行时指纹和断连计划。密码材料通过进程内 HMAC 参与代次键与监听器指纹，普通 API 不暴露密码摘要。保存草稿不会更换客户端；应用失败沿用现有补偿恢复。错误引用不能成为默认直连。

本阶段采用全局策略代次：出站行为或凭据变更重建活动监听器，计划要求明确确认连接中断。标签改名保留监听器。握手、拨号、UDP 会话和目标数量继续受现有 limits 限制。

出站配置保存在版本 JSON，凭据复用不可变资产及 revision_credentials，无新增存储表。历史引用保护、备份、恢复和只恢复 committed 的规则均保持适用。

## DNS、路由与源地址

需要区分两个地址：上游代理地址，以及客户端想访问的最终目标。

1. 上游代理域名使用当前配置代次的 DNS 解析器；底层连接使用入口源地址策略，不再次进入目的路由，避免默认代理出站递归。
2. 代理目标是域名且路由未执行 IP 规则解析时，名称原样交给上游 SOCKS/HTTP/SS，由上游解析；不预先用本机系统 DNS 改写它。
3. IP/CIDR/GeoIP 规则需要解析时，实际代理请求使用本地决策获得的 IP。远端不能以第二次域名解析绕过该规则。TCP 可尝试本次结果中的多个地址，UDP 使用第一个结果。
4. DNS 上游传输继续直接拨号；`hijack_udp53` 仍优先于普通路由。本阶段没有 DNS 经代理 detour 配置。

源进源出只约束本机到上游代理这一跳；最终目标看到的出口地址由上游代理决定。每次拨号都携带自己的入口上下文；首批客户端不建立跨入口共享的 QUIC/mux 连接。

## UDP 关联

每一个数据包重新选择出口，同一关联可以混用直连、DNS 和多个代理。代理 socket 按“出站 + 原始目标 + 实际目标”隔离，并与直连/DNS 共同受 `max_udp_destinations` 限制；不会把首包的许可用于后续目标。

代理返回的数据只交付对应目标会话：IP 目标验证 IP 与端口；远端解析的域名目标验证端口及可用的域名信息，依赖该连接上的上游代理提供解析结果。返回给入站的地址保留原始目标。直连数据继续接受已放行端点的回复。

SOCKS5 保持 UDP ASSOCIATE 的 TCP 控制连接，控制连接关闭会关闭关联；未指定的 BND.ADDR 使用该控制连接的实际对端地址。非零 RSV/FRAG 报文明确拒绝。HTTP 被选为 UDP 出口时返回不支持错误。错误包/失败出口会结束当前关联，不影响其他关联。

适配层以完整 UDP 缓冲区接收和解密上游包，再向调用者交付明文，避免小明文缓冲区截断 SOCKS/SS 的封装。容量不足返回 `io.ErrShortBuffer`。

## 验证

```sh
make check
make check-web
make build-web
python3 scripts/test-outbound.py --peer /path/to/sing-box
```

单元/集成测试覆盖认证与域名保留、6 种 Shadowsocks 方法的 TCP/UDP、小缓冲区、关闭待完成握手、重复等待清理、凭据轮换、超时变更、出站引用、失败关闭及 IP 规则解析结果固定。

独立进程脚本使用 sing-box 作为入站客户端和上游代理，真实通过 Lunaris 中继，覆盖 JSON API、远端 DNS、一个 UDP 关联跨出口、HTTP UDP 拒绝、密码轮换断连确认、错误密码不回落直连、重启和完整备份恢复。所有服务使用临时配置与回环端点；本机执行和 Linux 交叉编译不替代 Linux/公网运行验收。

2026-11-02 验证记录：`make check`、`make check-web`、最终受影响包的 race 回归，以及 Linux amd64/arm64 的 CGO=0 核心/内嵌 Web 构建通过。独立 sing-box 1.13.15 在 macOS arm64 上通过 8 组 TCP、7 组代理 UDP及混合直连关联，随后在重启和备份还原后复核；凭据轮换、JSON API、历史资产保护和失败不回落直连通过。`scripts/test-routing.py`、`scripts/test-management.py` 回归通过；上游代理的配置 DNS 与实际入口源地址另有网络集成测试。
