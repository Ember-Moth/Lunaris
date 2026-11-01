# 开发计划

更新：2026-11-01。按用户要求先完成节点核心，HTTP 管理接口和 Web 放在最后；现有管理骨架保留，不作为核心开发的前置依赖。

## 依赖与实现约束

- 直接引用上游 Go module 并锁定版本，不维护 Polaris 式本地 vendor、副本模块或本地 replace。
- `github.com/sagernet/sing` 是必选直接依赖。复用 sing-xxx 和项目独立实现的协议，都使用 sing 的网络接口、地址、缓冲区与连接处理基建。
- 不依赖 sing-box 产品模块。上游缺少的能力在 Lunaris 适配层或独立协议中实现，不修改 module cache 来让测试通过。
- 继续使用根目录 `main.go`、`cmd/run.go`、YAML 配置和 GPL-3.0-only；后续 HTTP 响应保持 `{code,msg,data}`。

## 实施阶段

| 阶段 | 内容 | 完成标准 |
| --- | --- | --- |
| P1：独立核心 | 不依赖前端构建的核心程序；严格 YAML 节点配置；检查命令；直接出口；共享转发；监听器启停；Shadowsocks AEAD TCP/UDP | 可以仅靠 YAML 启动节点，完成真实本地 TCP/UDP 传输，启动失败回收、取消与关闭测试通过 |
| P2：运行管理 | 配置差异、监听器重建、稳定实例状态、凭据轮换、资源边界、故障恢复 | 配置失败不会留下失控实例；旧凭据和存量会话按策略撤销 |
| P3：持久化配置服务 | SQLite 资产与配置版本、草稿/应用、幂等操作和离线恢复工具 | 不依赖 HTTP 即可通过应用服务测试提交、补偿和重启恢复 |
| P4：扩展协议与运维 | 按实际需求接入 Hysteria2、VLESS 等，完善证书和 Linux 部署 | 各协议组合通过独立客户端互通；具体列表按需求确定 |
| P5：HTTP 管理接口 | 管理员初始化与认证，Hertz API 接入已经完成的应用服务 | 鉴权、统一信封、并发版本与幂等语义完整 |
| P6：内嵌 Web | React + shadcn/ui 配置、证书、状态与操作反馈 | 浏览器完整管理节点；静态资源随发行二进制内嵌 |

P1 以 classic AEAD Shadowsocks 为第一条实现链路，不代表承诺一次支持全部密码套件、SS2022、多用户复用或所有客户端扩展。每项能力只在完成实现和验证后加入支持列表。

## 文件模式与管理模式

核心开发阶段提供 `run --config <node.yaml>` 与 `check --config <node.yaml>`。文件模式以该 YAML 为配置来源，直接组装协议运行时，不同时从 SQLite 拉取另一份配置。命令不启动 HTTP，也不依赖 Node.js。

P3 管理模式由本机配置服务提供已提交快照，复用相同的校验、协议工厂、转发与运行时；HTTP/Web 将作为后续调用方。文件模式和管理模式不能同时拥有同一个监听端点，避免配置源互相覆盖。

## 验证与交付

- 单元测试覆盖配置和资源所有权，网络集成测试覆盖实际传输、认证失败、半关闭、取消、端口冲突与退出。
- 运行 race 检查和 Linux amd64/arm64 交叉编译。
- 同库客户端回环属于局部互通证据；独立客户端、真实 Linux 和公网网络验证单独记录，不将其与本地测试混淆。
- 已交付 P1–P3 和首批 P4 协议扩展，继续推进运维验收与 P5/P6；各阶段保留明确的验收标准，不把未完成接口标为支持。

## 进度

- [x] 调整开发顺序与非 vendor 依赖约束。
- [x] 核心独立构建与 YAML 配置检查。
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
- [x] managed 模式、本机配置 CLI、SIGHUP 导入/应用与状态查询。
- [x] 迁移前备份、含 WAL 的离线快照、空目录还原与不覆盖保护。
- [x] 存储、服务故障注入、骤停恢复和完整 CLI/进程流程验证。

持久化资产已覆盖凭据和 P4 的证书；管理员与 HTTP/Web 在 P5/P6 接入。P1 的“核心不链接 SQLite”是该阶段记录；P3 默认程序包含 SQLite 支持，文件模式仍不访问它。

P3 验证记录：`make check`、`make check-web`、受影响存储/配置/CLI 包的 race 回归、Linux amd64/arm64 的 CGO=0 交叉编译均通过。独立程序验证了导入、幂等应用、源凭据文件缺失时恢复已提交资产、错误重载后 SIGKILL、备份还原和历史请求重试；测试进程覆盖提交前后退出留下的 WAL 恢复。说明见 [持久化配置服务](persistent-configuration.md)。

P3 时尚未执行真实 Linux 运行、外部客户端软件或公网网络验证；P4 客户端验证另见下文。

## P4 首批协议与传输

- [x] VLESS、VMess AEAD、Trojan、AnyTLS、Hysteria2、TUIC v5。
- [x] TCP/TLS、WebSocket、HTTPUpgrade、原生 QUIC 的组合校验。
- [x] 多凭据适配，全部协议复用 sing relay 和监听器生命周期。
- [x] PEM 导入、不可变证书版本、内容轮换、恢复与备份。
- [x] 真实回环 TCP/UDP、分片握手、错误凭据、超时和会话回收测试。

范围与使用方法见[协议、传输与证书](protocols.md)。REALITY/Vision、gRPC/XHTTP 和其他扩展不在本轮。Linux 部署与公网/压力验收继续保留为 P4 运维后续工作。

P4 本轮验证：`make check`、管理构建的 vet/race、`make check-web`、`go mod verify` 和 Linux amd64/arm64 的 CGO=0 交叉编译通过。官方 sing-box 1.14.4 发行客户端在 macOS arm64 上完成全部 18 个协议/传输/TLS 组合（AnyTLS 为 TCP，其余为 TCP+UDP）；可通过 `scripts/test-interop.py` 复跑。最终关闭流程调整后，受影响回归与全部客户端组合再次通过。

## 独立工厂注册表

- 协议注册表：七个协议各自提供工厂，负责协议选项、凭据和处理器构造。
- 传输注册表：native、TCP、WebSocket、HTTPUpgrade、QUIC 五种工厂，负责监听与载体生命周期；TLS 保持为可选封装。
- `internal/inbound` 负责组合校验与组装，文件模式和持久化服务复用该入口。
- 新增自定义工厂真实转发、无效组合提前拒绝、能力快照和停止超时后继续清理测试。

详细接口与扩展方式见[工厂注册表](factory-registries.md)。

注册表重构验证：核心 `make check`、管理构建的 vet/race、Linux amd64/arm64 的 CGO=0 交叉编译通过；sing-box 1.14.4 发行客户端验证 19 个组合（新增 Shadowsocks 原生 TCP/UDP）。协议/传输扩展测试和证书材料隔离测试均通过。
