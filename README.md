# Lunaris

Lunaris 是面向个人自用、自托管的专用代理节点端，内置 Web 管理界面。以 SagerNet 的 `sing` 为必选基础设施，按需复用 `sing-xxx` 或在项目内独立实现协议，并将前端构建产物嵌入同一个可执行文件。

项目不 fork sing-box，也不将 sing-box 作为运行时依赖。sing-box 可作为库接入方式与客户端互通的参考。

## 项目定位

用户在自己的服务器上安装并启动 Lunaris 后，通过浏览器管理协议监听、凭据、证书和节点配置。产品重点是容易部署、容易配置、协议互通和低维护成本，Web 界面是日常管理的主要入口。

核心建设方向：

- 前端静态资源内嵌，管理页面、管理 API 和代理运行时随程序一起发布。
- 通过 Web 界面配置、启用或停用一个或多个协议监听器。
- 管理协议凭据与 TLS 证书，配置和私钥持久化在服务器本地。
- 稳定的 TCP/UDP 转发、域名解析、连接超时和资源回收。
- 配置表单、后端校验、保存与应用操作，以及明确的生效状态和错误提示。
- 单程序部署、服务托管和优雅退出。
- 管理员登录、节点状态和用于排障的日志。

自用场景可以需要多个设备或多份凭据，但不以机场运营为默认模型。内置 Web 界面管理当前节点；外部机场面板对接、套餐配额、计费级用量上报、集中式用户管理和跨节点调度不在当前范围内。

Lunaris 也不承担桌面或移动端 VPN、TUN、系统代理、客户端策略组、自动选节点等通用代理平台功能。

## 复用方向

`sing` 必须作为直接依赖。项目独立实现的协议也必须使用 sing 的网络接口、地址类型、缓冲区与连接处理能力；上游库适配和独立实现共用同一套监听器生命周期与转发接口。

| 上游库 | 计划用途 |
| --- | --- |
| [`sing`](https://github.com/SagerNet/sing) | 必选基础：网络接口、地址元数据、缓冲区、复制和 UDP 会话等能力 |
| [`sing-shadowsocks`](https://github.com/SagerNet/sing-shadowsocks) | Shadowsocks / Shadowsocks 2022 协议服务 |
| [`sing-vmess`](https://github.com/SagerNet/sing-vmess) | VMess 与 VLESS 协议服务 |
| [`sing-quic`](https://github.com/SagerNet/sing-quic) | Hysteria2、TUIC 等 QUIC 协议服务 |
| [`sing-anytls`](https://github.com/SagerNet/sing-anytls) | AnyTLS 协议服务 |

除当前已接入的 Shadowsocks AEAD 外，其余为候选依赖，不代表已实现的协议支持。直接使用上游 Go module 并锁定版本，不维护本地 vendor、副本模块或本地 replace。

## 架构与技术栈

- **前端**：React + TypeScript + shadcn/ui + Vite，构建为静态文件并通过 Go embed 内嵌。
- **Web 服务**：CloudWeGo Hertz，提供同源管理页面、认证和管理 API。
- **节点运行时**：Go + sing，按协议管理监听实例；协议可复用 sing-xxx 或基于 sing 独立实现。
- **本机存储**：SQLite，保存配置版本、凭据、证书与管理员状态，无需外部数据库。
- **配置应用**：草稿、成功提交的版本和实际运行状态分离；串行应用并重建受影响监听器，保留管理入口。

设计文档：

- [总体架构](docs/architecture.md)：模块边界、技术选择、协议接入、部署与实施顺序。
- [配置生命周期](docs/configuration-lifecycle.md)：版本、应用流程、失败补偿与崩溃恢复。
- [管理 API 契约](docs/management-api.md)：初始化、认证、配置、资产、状态与幂等交互。
- [Polaris 参考对照](docs/polaris-reference.md)：可采用的协议与生命周期经验，以及本地补丁的复用边界。
- [开发计划](docs/development-plan.md)：先完成节点核心，再实现 HTTP API 与 Web。

## 当前状态

已实现第一阶段的文件模式节点核心：严格 YAML 校验、环境变量/文件凭据、共享 TCP/UDP 转发、直接出口、监听器启动失败清理、关闭与资源限制，以及 Shadowsocks AEAD。

| 方法 | TCP | UDP |
| --- | --- | --- |
| `aes-128-gcm` | 已实现 | 已实现 |
| `aes-256-gcm` | 已实现 | 已实现 |
| `chacha20-ietf-poly1305` | 已实现 | 已实现 |

每个监听器使用一份凭据，可配置多个监听器。当前不支持 SS2022、单端口多用户、Mux/UoT、TLS 插件或配置热更新。修改配置后重启文件模式进程。

管理界面骨架和 SQLite 初始迁移保留。管理员认证、配置版本应用、管理 API 和 Web 操作按开发计划后置；管理骨架尚未连接代理运行时。协议细节与验证范围见 [Shadowsocks 实现说明](docs/shadowsocks.md)。

## 本地开发

节点核心只需要 Go 1.26 或更新版本，不需要 Node.js 或前端构建。

```sh
make install
make build
export LUNARIS_SS_PASSWORD="$(./bin/lunaris keygen)"
./bin/lunaris check --config examples/shadowsocks.yaml
./bin/lunaris run --config examples/shadowsocks.yaml
```

示例在 `127.0.0.1:8388` 同时监听 TCP/UDP；服务器部署时在 YAML 中明确设置所需监听地址，并在客户端使用相同方法和密码。进程入口是根目录 `main.go`，命令分发在 `cmd/run.go`。

```yaml
schema_version: 1
credentials:
  - id: personal
    secret_env: LUNARIS_SS_PASSWORD
listeners:
  - id: ss-main
    protocol: shadowsocks
    address: 127.0.0.1
    port: 8388
    network: [tcp, udp]
    credential_refs: [personal]
    options:
      method: chacha20-ietf-poly1305
```

凭据可使用 `secret_env`、相对于 YAML 文件的 `secret_file` 或直接 `secret`，三者只选一个。`check` 不绑定端口，不输出凭据；文件模式不启动 HTTP，也不读写 SQLite 的受管配置。

```sh
make check       # 依赖约束、go vet、race 测试；无需前端产物
./bin/lunaris version
```

要运行现有的管理骨架，需要额外安装 Node.js 24 与 pnpm 12.16.1：

```sh
make install-web
make build-web
./bin/lunaris-web serve --config config.example.yaml
make check-web
```

管理骨架只允许本机 `127.0.0.1:9080`；`config.example.yaml` 是管理启动设置，`examples/shadowsocks.yaml` 是节点配置，两者用途不同。前端热更新使用 `pnpm --dir web dev`。发行 Web 构建使用 `webui` 标签内嵌静态文件，缺少前端产物时会构建失败；默认核心构建不编入前端和 Hertz。

构建入口保留 `stdjson` 标签以兼容管理骨架。`web/dist` 和 `bin` 是生成产物，不提交；`go.sum`、pnpm lockfile 和生成的 API 类型纳入版本控制。

## HTTP API

统一响应信封为 `{code,msg,data}`：成功 code 为 0，错误为非零整数；同时保留正确的 HTTP 状态码。健康检查不代表代理节点已经配置或可以转发。

```json
{"code":0,"msg":"ok","data":{"status":"ok"}}
```

当前实际接口见 [OpenAPI](api/openapi.yaml)；完整管理功能的规划见 [API 契约](docs/management-api.md)。配置文件使用 YAML，HTTP 请求和响应使用 JSON。

systemd 样例位于 [packaging/systemd](packaging/systemd/lunaris.service)，使用节点文件模式，尚未自动安装到系统。HTTP 管理功能不作为当前核心开发的前置依赖。

## 许可证

项目采用 GNU General Public License v3.0，SPDX 标识为 `GPL-3.0-only`。完整条款见 [LICENSE](LICENSE)。第三方依赖与组件保留各自的版权和许可证声明。
