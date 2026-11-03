# 开发计划

更新：2026-11-02。按用户要求先完成节点核心，HTTP 管理接口和 Web 放在最后；现有管理骨架保留，不作为核心开发的前置依赖。

## 依赖与实现约束

- 直接引用上游 Go module 并锁定版本，不维护 Polaris 式本地 vendor、副本模块或本地 replace。
- `github.com/sagernet/sing` 是必选直接依赖。复用 sing-xxx 和项目独立实现的协议，都使用 sing 的网络接口、地址、缓冲区与连接处理基建。
- 不依赖 sing-box 产品模块。上游缺少的能力在 Lunaris 适配层或独立协议中实现，不修改 module cache 来让测试通过。
- 继续使用根目录 `main.go`、`cmd/run.go`、YAML 启动设置和 JSON 管理 API，采用 GPL-3.0-only；HTTP 响应保持 `{code,msg,data}`。

## 实施阶段

| 阶段 | 内容 | 完成标准 |
| --- | --- | --- |
| P1：独立核心 | 不依赖前端构建的核心程序；统一配置校验；直接出口；共享转发；监听器启停；Shadowsocks AEAD TCP/UDP | 完成真实本地 TCP/UDP 传输，启动失败回收、取消与关闭测试通过 |
| P2：运行管理 | 配置差异、监听器重建、稳定实例状态、凭据轮换、资源边界、故障恢复 | 配置失败不会留下失控实例；旧凭据和存量会话按策略撤销 |
| P3：持久化配置服务 | SQLite 资产与配置版本、草稿/应用、幂等操作和离线恢复工具 | 不依赖 HTTP 即可通过应用服务测试提交、补偿和重启恢复 |
| P4：扩展协议与运维 | 按实际需求接入 Hysteria2、VLESS 等，完善证书和 Linux 部署 | 各协议组合通过独立客户端互通；具体列表按需求确定 |
| P5：HTTP 管理接口 | 管理员初始化与认证，Hertz API 接入已经完成的应用服务 | 鉴权、统一信封、并发版本与幂等语义完整 |
| P6：内嵌 Web | React + shadcn/ui 配置、证书、状态与操作反馈 | 浏览器完整管理节点；静态资源随发行二进制内嵌 |

P1 以 classic AEAD Shadowsocks 为第一条实现链路，不代表承诺一次支持全部密码套件、SS2022、多用户复用或所有客户端扩展。每项能力只在完成实现和验证后加入支持列表。

## 当前配置来源

节点 YAML 及 `run`/`check`、CLI `config import`、`managed --source`、HTTP YAML 模板导入/导出已移除。代理配置统一经 JSON API 编辑、校验和应用，持久化在 SQLite。

`serve` 提供管理 API，`managed` 只运行同一数据目录的 committed。二者不能同时持有该目录。启动设置 YAML 仅用于管理监听、数据目录、HTTPS 和可信反代。JSON 示例是 API 请求体，不是新的文件运行模式。

下方 P1–P4 验证记录保留当时的测试范围；历史节点文件入口不再提供。当前验证以 JSON API 和 SQLite 为准。

## 验证与交付

- 单元测试覆盖配置和资源所有权，网络集成测试覆盖实际传输、认证失败、半关闭、取消、端口冲突与退出。
- 运行 race 检查和 Linux amd64/arm64 交叉编译。
- 同库客户端回环属于局部互通证据；独立客户端、真实 Linux 和公网网络验证单独记录，不将其与本地测试混淆。
- 已交付 P1–P3 和首批 P4 协议扩展，P5 已接入，继续推进运维验收与 P6；各阶段保留明确的验收标准，不把未完成接口标为支持。

## 进度

- [x] 调整开发顺序与非 vendor 依赖约束。
- [x] 核心独立构建与统一配置校验。
- [x] 共享 TCP/UDP 转发、资源跟踪与直接出口。
- [x] Shadowsocks AEAD 运行时与启动失败清理。
- [x] 本地集成验证、使用文档和依赖约束检查。

P1 验证记录：`make check`（含 race）、`make check-web`（现有管理骨架兼容性）、Linux amd64/arm64 的 CGO=0 交叉编译、`go mod verify` 均通过。独立核心二进制的 YAML 校验、TCP/UDP 监听启动、敏感值不输出和 SIGTERM 退出已验证；核心依赖图不包含 Hertz、SQLite 或内嵌页面。

## P2 进度

- [x] 统一规范化与不可变输入副本，按实例生成差异计划。
- [x] 保留未变化实例；支持创建、替换、停用、删除和故障恢复。
- [x] 检测凭据文件实际内容变化，关闭旧 TCP/UDP 会话。
- [x] 应用失败后重建基准配置；恢复失败显示降级，未确认资源释放时阻止继续应用。
- [x] 独立状态快照、实例代次和迟到事件隔离。
- [x] SIGHUP 重载与 SIGUSR1 状态，包含子进程信号测试。

P2 的内存配置版本、差异应用与失败恢复已经实现。`make check`、`make check-web`、Linux amd64/arm64 的 CGO=0 交叉编译均通过；验证覆盖真实 TCP/UDP 凭据轮换、未变化连接保留、端口交换、应用/恢复失败、并发与取消、迟到事件、子进程信号，以及独立二进制的 SIGHUP/SIGUSR1/SIGTERM 操作。使用方式见 [运行重载](runtime-reload.md)。

## P3 进度

- [x] 不可变凭据资产与配置版本，草稿 CAS 和无变化去重。
- [x] 幂等应用记录，数据库提交与运行态补偿，结果不确定时冻结写入。
- [x] 重启只恢复 committed，中断操作标为 interrupted，不自动重放。
- [x] managed 模式、本机配置 CLI、SIGHUP 草稿应用与状态查询。
- [x] 迁移前备份、含 WAL 的离线快照、空目录还原与不覆盖保护。
- [x] 存储、服务故障注入、骤停恢复和完整 CLI/进程流程验证。

持久化资产已覆盖凭据和 P4 的证书；管理员与 HTTP/Web 在 P5/P6 接入。P1 的“核心不链接 SQLite”是该阶段记录；P3 起默认程序包含 SQLite 支持；当前节点配置只由 SQLite 提供。

P3 验证记录：`make check`、`make check-web`、受影响存储/配置/CLI 包的 race 回归、Linux amd64/arm64 的 CGO=0 交叉编译均通过。独立程序验证了导入、幂等应用、源凭据文件缺失时恢复已提交资产、错误重载后 SIGKILL、备份还原和历史请求重试；测试进程覆盖提交前后退出留下的 WAL 恢复。说明见 [持久化配置服务](persistent-configuration.md)。

P3 时尚未执行真实 Linux 运行、外部客户端软件或公网网络验证；P4 客户端验证另见下文。

## P4 首批协议与传输

- [x] VLESS、VMess AEAD、Trojan、AnyTLS、Hysteria2、TUIC v5。
- [x] TCP/TLS、WebSocket、HTTPUpgrade、原生 QUIC 的组合校验。
- [x] 多凭据适配，全部协议复用 sing relay 和监听器生命周期。
- [x] PEM 导入、不可变证书版本、内容轮换、恢复与备份。
- [x] 真实回环 TCP/UDP、分片握手、错误凭据、超时和会话回收测试。

范围与使用方法见[协议、传输与证书](protocols.md)。该阶段尚未包含 REALITY/Vision、gRPC/XHTTP；后续扩展见下文。Linux 部署与公网/压力验收继续保留为 P4 运维后续工作。

P4 本轮验证：`make check`、管理构建的 vet/race、`make check-web`、`go mod verify` 和 Linux amd64/arm64 的 CGO=0 交叉编译通过。官方 sing-box 1.14.4 发行客户端在 macOS arm64 上完成全部 18 个协议/传输/TLS 组合（AnyTLS 为 TCP，其余为 TCP+UDP）；可通过 `scripts/test-interop.py` 复跑。最终关闭流程调整后，受影响回归与全部客户端组合再次通过。

## 独立工厂注册表

- 协议注册表：七个协议各自提供工厂，负责协议选项、凭据和处理器构造。
- 传输注册表：native、TCP、WebSocket、HTTPUpgrade、QUIC 五种工厂，负责监听与载体生命周期；TLS 保持为可选封装。
- `internal/inbound` 负责组合校验与组装，管理 API 与持久化服务复用该入口。
- 新增自定义工厂真实转发、无效组合提前拒绝、能力快照和停止超时后继续清理测试。

详细接口与扩展方式见[工厂注册表](factory-registries.md)。

注册表重构验证：核心 `make check`、管理构建的 vet/race、Linux amd64/arm64 的 CGO=0 交叉编译通过；sing-box 1.14.4 发行客户端验证 19 个组合（新增 Shadowsocks 原生 TCP/UDP）。协议/传输扩展测试和证书材料隔离测试均通过。

## UoT、mux 与 REALITY

- [x] UoT v1/v2、固定/每包目标、AnyTLS UDP。
- [x] sing-mux 的 smux、yamux、h2mux，含 padding、子流限制和回收。
- [x] 直接依赖最新版 xtls/reality；按 ClientHello 分流到可选的旧握手兼容后端。
- [x] REALITY 私钥资产、轮换、目标探测取消、普通 TLS 回落与客户端认证验证。
- [x] Go 1.27 工具链与 CI 同步，核心/管理构建检查和 Linux 双架构编译。

sing-box 1.14.4 的 20 个新增组合及 Xray 26.10.31 的 3 个 REALITY 组合互通通过。详细配置、客户端兼容开关和证据范围见[连接扩展](connection-extensions.md)。本轮新功能尚未包含 Vision、XUDP、gRPC 或 XHTTP。

UDP 接入约束已核对 sing-box 1.14.4：AnyTLS 固定内建 UoT v2；Shadowsocks 可同时接收原生 UDP、UoT 和 mux 客户端。sing-box 出站开启 UoT 时不创建 mux client，这个客户端优先级不作为服务端的互斥限制。

## Naive 与 Shadowsocks 2022

- [x] Naive HTTP/1.1、HTTP/2、HTTP/3，用户名/凭据映射和 UoT。
- [x] SS2022 三种方法、AES 同端口多用户、原生 UDP/UoT/mux。
- [x] 服务端身份密钥资产、配置校验、重载撤销、UDP 重放与生命周期回归。
- [ ] Naive HTTP/3 独立发行客户端验收（本机客户端连接原版服务端也失败）。

实现、配置与验证记录见 [Naive 与 SS2022](naive-ss2022.md)。

## Polaris XHTTP 移植

- [x] 三种上传模式与 auto，HTTP/1.1–3，VLESS/VMess/Trojan TCP/UDP。
- [x] 乱序队列、缓冲与会话限额、配置/生命周期接入及 MPL 来源声明。
- [x] 原始移植测试、节点回归、独立 Xray 47 个组合。

实现与验证边界见 [XHTTP](xhttp.md)。

## Snell、Mieru 与 ShadowsocksR

- [x] 直接依赖 sing-snell，接入 v5/v6 TCP、UDP 与复用。
- [x] 从 Polaris 移植 Mieru 与 SSR 的协议实现，接入现有工厂、凭据和生命周期。
- [x] 独立客户端、Mieru 受控丢包、SSR 经典方法与混淆、多用户验证及资源回收回归。

支持范围与已知客户端问题见 [协议说明](snell-mieru-ssr.md)。

## VLESS Encryption / Vision

- [x] 三种 Encryption 模式、1-RTT/0-RTT、X25519/ML-KEM-768 认证及密钥链。
- [x] Vision + TLS/REALITY，以及 Encryption + Vision 的所有流式传输；XUDP。
- [x] 凭据引用、取消与缓存限额、轮换和停止回归。
- [x] 96 个独立 Xray 互通组合、完整检查、管理构建和 Linux 双架构交叉编译。

配置、互通脚本与证据范围见 [VLESS Encryption 与 Vision](vless-encryption-vision.md)。

## Shadowsocks 插件

- [x] simple-obfs、v2ray-plugin、gost-plugin、ShadowTLS、Restls、kcptun。
- [x] 独立传输工厂、凭据引用、流/会话认证预算、目标连接生命周期、密码轮换。
- [x] 原始 Mihomo v1.19.33 客户端的 162 个 classic AEAD / SS2022 组合和 4 个错误凭据拒绝/恢复检查。

配置与证据范围见[Shadowsocks 插件](shadowsocks-plugins.md)。

## P5：HTTP 管理 API

- [x] 单管理员初始化、一次性 token 文件、Argon2id、持久化会话、改密撤销与离线恢复。
- [x] HTTPS/可信反代、严格 Host/Origin、CSRF、登录及资源限制。
- [x] 配置/资产 API、ETag、应用计划、持久化幂等受理与后台任务。
- [x] 状态、有限日志、重新认证后的连接参数、脱敏 JSON 配置查询。
- [x] 管理端口保护、代理恢复失败后的修复入口、不确定提交状态与恢复后的会话撤销。
- [x] OpenAPI、生成类型、真实 HTTP/进程/转发和恢复验证。

接口与运行方法见 [P5 说明](management-implementation.md)。P6 页面交互仍未接入，不将 API 验证当作浏览器管理流程完成。

## 节点 YAML 退役

- [x] 删除节点文件解析、运行/校验命令、CLI 导入与 managed source。
- [x] 删除 HTTP YAML 模板和导入端点，更新 OpenAPI 与生成类型。
- [x] 保留启动设置 YAML，协议示例改为 JSON API 请求体。
- [x] 互通与压测脚本通过 API 建立 SQLite committed，再运行 managed 数据面。
- [x] 信号回归覆盖 committed 恢复、草稿显式应用、重复应用和关闭；退役入口明确拒绝。

退役验证：核心 `make check`、管理构建 `make check-web`、8 份 JSON 示例的真实 API 校验、独立管理/备份/恢复流程、移除入口拒绝测试及 Linux amd64/arm64 核心/管理版 CGO=0 构建通过。协议脚本现在通过 JSON API 写入并应用临时配置，停止管理进程，再从 committed 启动 managed，覆盖 SQLite 恢复后的真实转发。

迁移后通过的独立客户端验证：19 个基础组合；20 个扩展组合、7 个同端口 Shadowsocks 模式及 3 个 Xray REALITY 组合；43 个 Naive/SS2022 组合（显式跳过已有未通过的 Naive HTTP/3）；47 个 XHTTP 组合；162 个 Shadowsocks 插件组合与 4 个错误凭据检查；59 个 Snell/Mieru/SSR 代理组合与 5 个官方 Mieru API 用例（含受控丢包）。

VLESS 96 组合的最终复跑仍出现 TCP/XHTTP 的 0-RTT 与 UDP 超时，因此本轮不将完整 VLESS 矩阵记为通过；启动阶段还曾出现 REALITY 目标探测失败，后续恢复启动成功，不宣称根因已修复。测试 TLS 目标改为在线程内执行有界握手，避免 accept 循环串行阻塞。协议实现和第三方依赖保持原版本。

压测脚本迁移冒烟通过：原生 AES-128-GCM 的单流/8 流上传与下载，以及 32/128 条已认证空闲连接的采样。该检查只验证脚本与 managed 启动流程，不是新的完整性能报告；原 2026-11-01 数据保持不变。
