# Polaris 参考与 Lunaris 的采用范围

核对日期：2026-10-31。参考本地 Polaris 源码快照 `56d52fb44958ef3cc2a7fb841cd240f8206234b2`，远端为 `HyperPteLtd/Polaris`。本次只读检查源码和测试入口，未运行 Polaris 的测试或性能基准，也没有迁入其源码。

本文记录可以采用的工程经验。Polaris 文档中的面板、用户和代次管理要求属于 Polaris，自身不会自动成为 Lunaris 的产品要求。

## 1. 产品与依赖边界

| 方面 | Polaris 当前实现 | Lunaris 的选择 |
| --- | --- | --- |
| 配置来源 | 面板 Provider、轮询与规范化快照 | 内嵌 Web / JSON API、SQLite 配置版本 |
| 控制职责 | controller / supervisor、用户同步、流量和在线状态上报 | 本机配置、管理员认证、监听实例与应用操作 |
| 数据面 | 协议服务 → 共享 flow → 路由与出站 | 协议服务 → 共享 relay → 必需的解析与直接出口 |
| 身份模型 | 面板用户 UID、设备限制、限速和计量 | 监听器 ID、实例代次、本地凭据引用 |
| 更新方式 | 候选代次、准入门、用户发布、旧代次排空 | SQLite 草稿/已提交版本、受影响监听器重建与补偿 |
| 协议基础 | 大量本地 replace 的 sing 模块与项目移植模块 | 必选 sing；按需引用 sing-xxx 或基于 sing 独立实现 |
| 管理界面 | 本次核对未发现 React 前端或内嵌 Web 管理工程 | 已确定 React + shadcn/ui、Hertz、`{code,msg,data}` |

依据：[Polaris 架构](https://github.com/HyperPteLtd/Polaris/blob/56d52fb44958ef3cc2a7fb841cd240f8206234b2/docs/architecture.md)、[启动组装](https://github.com/HyperPteLtd/Polaris/blob/56d52fb44958ef3cc2a7fb841cd240f8206234b2/cmd/server.go)、[依赖配置](https://github.com/HyperPteLtd/Polaris/blob/56d52fb44958ef3cc2a7fb841cd240f8206234b2/go.mod)。

## 2. 值得采用的工程经验

### 协议引擎与产品适配分开

Polaris 的 Nowhere 引擎通过 sing 的 `TCPConnectionHandlerEx`、`UDPConnectionHandlerEx` 和认证上下文交付连接，产品侧再组合监听、配置和业务服务。这与 Lunaris“独立协议也必须使用 sing 基建”的要求一致。[协议引擎入口](https://github.com/HyperPteLtd/Polaris/blob/56d52fb44958ef3cc2a7fb841cd240f8206234b2/pkg/sagernet/sing-nowhere/portal.go)。

Lunaris 的协议实现应遵循同一边界：协议引擎负责握手、认证、编解码和协议会话；适配器负责将本地配置与资产转换为引擎参数。引擎不导入 Hertz、SQLite、管理员会话或配置应用协调器。引擎是否需要单独 Go module，等出现独立复用需求后再决定。

建议每个实际接入的协议按职责组织 `config.go`、`server.go`、`adapter.go`、`runtime.go`；项目独立实现的 wire 逻辑可放在该协议的 `engine` 子包。无需为未实现协议创建空目录。

### 每种协议共用一套转发入口

Polaris 的 `flow.Handler` 将准入、上游拨号、转发与连接撤销集中在协议之外。Lunaris 应在 `internal/relay` 中统一处理认证后的 TCP/UDP 流，使各协议无需重复编写拨号、半关闭、超时与完成回调。[共享 Handler](https://github.com/HyperPteLtd/Polaris/blob/56d52fb44958ef3cc2a7fb841cd240f8206234b2/internal/protocol/flow/handler.go)。

Polaris 的 flow 直接依赖其路由、用户、限速、设备会话和计量模型，不能作为无改动的通用库导入。Lunaris 按当前需求实现较小的 relay，只保留必要的资源跟踪、取消和聚合运行计数。

### 在上游拨号前登记流的所有权

Polaris 会先登记待连接流，再拨号；拨号完成后将其提升为活动转发。如果拨号期间用户被撤销，取消拨号或释放刚建立的连接，避免产生未跟踪的中继。[TCP 流处理](https://github.com/HyperPteLtd/Polaris/blob/56d52fb44958ef3cc2a7fb841cd240f8206234b2/internal/protocol/flow/tcp.go)。

Lunaris 的对应规则是：从目标解析/拨号之前登记到监听实例和凭据引用，成功后转为活动流；监听器重建、凭据撤销或进程停止时，等待中的工作同样可取消。转发连接与关闭回调在成功、失败、取消路径都只释放一次。

### 共享生命周期，但保留传输差异

Polaris 的 runtimekit 区分准备监听、提交接入、停止接受、等待排空和最终关闭，并跟踪连接与处理协程。QUIC 等由协议库持有接收循环的实现保留专门的适配路径。[共享生命周期](https://github.com/HyperPteLtd/Polaris/blob/56d52fb44958ef3cc2a7fb841cd240f8206234b2/internal/protocol/runtimekit/listener.go)、[Hysteria2 组装](https://github.com/HyperPteLtd/Polaris/blob/56d52fb44958ef3cc2a7fb841cd240f8206234b2/internal/protocol/hysteria2/runtime.go)。

Lunaris 保持当前 `Factory` / `Instance` 入口；首个协议接入时，在 `node` 和 `transport` 中实现共享的资源所有权与关闭流程，不为每个协议复制一套。`StopAccepting`、`Drain`、`Close` 是需要明确区分的内部职责，不要求现在就新增一组没有消费者的公共接口。

初版配置应用仍会关闭受影响实例的存量连接；普通进程退出使用有界排空。凭据撤销不能通过“保留旧会话排空”延迟执行。QUIC 必须同时处理接受路径、底层连接和子流，不能只关闭 UDP listener 就视为结束。

### 连接包装要保留 sing 的能力

Polaris 的 `TrackedConn` 转发 `CloseRead`、`CloseWrite`、`WriteBuffer`，并通过 `Upstream` 暴露原连接，使 sing 的接口探测仍可工作。[连接包装实现](https://github.com/HyperPteLtd/Polaris/blob/56d52fb44958ef3cc2a7fb841cd240f8206234b2/internal/protocol/runtimekit/listener.go#L558)。

Lunaris 不能将目前用于 Hertz 的管理连接追踪器原样当作代理数据面的包装器。代理连接还需要保留半关闭、扩展 I/O、TLS/Vision 探测和正确的 buffer 所有权。计数或限速包装器尤其不能无条件照搬 `ReaderReplaceable` / `WriterReplaceable = true`，否则优化后的复制可能绕过它需要执行的逻辑。

### 发布阶段与准入门需要明确

Polaris 在候选运行时完成用户发布与 listener 提交后才打开共享准入门，并对过期候选做校验；失败候选的清理在释放发布锁之后执行。[代次发布](https://github.com/HyperPteLtd/Polaris/blob/56d52fb44958ef3cc2a7fb841cd240f8206234b2/internal/supervisor/publish.go)。

Lunaris 可以借鉴“未完成初始化的实例不向 relay 放行”和“慢资源回收不占状态查询锁”。但它的成功条件还包含 SQLite 中的配置提交，不能直接用 Polaris 的内存代次切换代替自己的持久化与崩溃恢复规则。若引入显式准入门，要同时设计提交前、提交后和开门前崩溃的状态；当前仍以 [配置生命周期](configuration-lifecycle.md) 的约定为准。

### CLI 与日志保持可测试

Polaris 把参数、stdout/stderr 作为 Invocation 注入，并区分参数错误和运行错误的退出码；有效配置日志经过脱敏。[命令入口](https://github.com/HyperPteLtd/Polaris/blob/56d52fb44958ef3cc2a7fb841cd240f8206234b2/cmd/root.go)、[配置脱敏](https://github.com/HyperPteLtd/Polaris/blob/56d52fb44958ef3cc2a7fb841cd240f8206234b2/internal/controller/config/config.go)。

Lunaris 后续扩展 CLI 时可采用可注入输出和稳定退出码，继续使用用户指定的根目录 `main.go` 与 `cmd/run.go`。没有必要仅因 Polaris 使用 Cobra 就更换当前命令解析器。协议错误必须脱敏，HTTP 错误仍统一为 Lunaris 的响应信封。

## 3. 本地补丁与直接复用的限制

Polaris 的根 `go.mod` 使用多项 `replace => ./pkg/...`。其 [本地模块说明](https://github.com/HyperPteLtd/Polaris/blob/56d52fb44958ef3cc2a7fb841cd240f8206234b2/pkg/sagernet/README.md) 明确区分上游修改副本、项目移植模块和 sing-box 派生源码子集。

例如 [sing-vmess 修改记录](https://github.com/HyperPteLtd/Polaris/blob/56d52fb44958ef3cc2a7fb841cd240f8206234b2/pkg/sagernet/sing-vmess/MODIFICATIONS.md) 包含用户快照原子发布；[sing-quic 修改记录](https://github.com/HyperPteLtd/Polaris/blob/56d52fb44958ef3cc2a7fb841cd240f8206234b2/pkg/sagernet/sing-quic/MODIFICATIONS.md) 包含 UDP 队列、分片与连接关闭处理。这些记录解释了它的实现前提，不能证明 Lunaris 锁定的上游版本具有相同补丁。

因此：

- 参考具体行为时，同时核对调用方、被调用的本地库和对应测试，不能只复制调用代码。
- Lunaris 继续使用自己锁定的 sing 版本；不将 Polaris 的本地 replace 配置整体迁入。
- 独立实现可以借鉴其 sing handler 边界，但项目移植模块不能被标为 SagerNet 官方库。
- 不将 `pkg/sagernet/sing-box/transport/trojan` 当成独立的上游 sing-xxx 库。其源码来源需单独识别。
- 真正需要移入某项补丁时，先对比 Lunaris 选定的上游版本，保留来源与许可证记录，再执行对应回归与客户端互通验证。
- 如果将来使用嵌套 Go module，需要单独测试；仓库根的 `go test ./...` 不覆盖嵌套模块。

## 4. 对后续实现顺序的影响

1. 保留已经完成的入口、启动 YAML、Hertz、React/shadcn、SQLite 和 API 信封骨架。
2. 接入首个协议，同时完成共享 relay、实例资源追踪和必要的生命周期工具，通过结构化配置与 CLI 验证。
3. 实现配置应用与持久化服务，加入部分启动失败、拨号期间撤销、旧会话关闭和重启恢复测试。
4. 再接入不同传输模型的协议，验证抽象对 TCP、UDP 和 QUIC 的适用边界。
5. 最后实现管理员认证、HTTP 管理接口和 Web，接入已经完成的核心应用服务。

用户已明确不采用本地 vendor 模块；Lunaris 使用锁定的上游 module，本文中的 Polaris 本地模块仅作为行为与边界的参考。实施进度以 [开发计划](development-plan.md) 为准。

可参考的回归测试入口（本次未执行）：

- [准备/提交/关闭与排空](https://github.com/HyperPteLtd/Polaris/blob/56d52fb44958ef3cc2a7fb841cd240f8206234b2/internal/protocol/runtimekit/listener_test.go)
- [拨号期间撤销](https://github.com/HyperPteLtd/Polaris/blob/56d52fb44958ef3cc2a7fb841cd240f8206234b2/internal/protocol/flow/revoke_test.go)
- [关闭准入时无拨号和转发副作用](https://github.com/HyperPteLtd/Polaris/blob/56d52fb44958ef3cc2a7fb841cd240f8206234b2/internal/protocol/flow/admission_proof_test.go)
- [Hysteria2 的阶段化生命周期](https://github.com/HyperPteLtd/Polaris/blob/56d52fb44958ef3cc2a7fb841cd240f8206234b2/internal/protocol/hysteria2/runtime_lifecycle_test.go)

这些是参考实现与用例入口，不代表 Lunaris 已经提供对应功能，也不构成 Polaris 当前性能或生产兼容性的验证结论。
