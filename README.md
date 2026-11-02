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
| [`sing-snell`](https://github.com/SagerNet/sing-snell) | Snell v5/v6 服务 |

已接入上述库的 Shadowsocks AEAD、VLESS、VMess、Hysteria2、TUIC 和 AnyTLS，并基于 sing 独立实现 Trojan。直接使用上游 Go module 并锁定版本，不维护本地 vendor、副本模块或本地 replace。

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
- [文件模式重载与状态](docs/runtime-reload.md)：SIGHUP、凭据轮换、差异重建与失败恢复。
- [UoT、mux 与 REALITY](docs/connection-extensions.md)：多路复用、旧客户端兼容、密钥配置与生命周期。
- [协议与传输工厂注册表](docs/factory-registries.md)：独立注册、组合校验、资源归属与扩展方式。
- [协议、传输与证书](docs/protocols.md)：支持矩阵、TLS 资产、配置示例和客户端互通。
- [持久化配置服务](docs/persistent-configuration.md)：不可变资产、草稿/提交版本、幂等应用、重启恢复与备份。

## 当前状态

已实现节点核心、运行管理、持久化配置服务，以及首批协议与传输扩展。支持文件模式或 SQLite 管理模式，统一严格 YAML 校验、共享转发、直接出口、资源限制和凭据/证书轮换。

新增 VLESS、VMess、Trojan、AnyTLS、Hysteria2、TUIC；支持 TCP/TLS、WebSocket、HTTPUpgrade、原生 QUIC、REALITY 和 XHTTP；已接入 UoT 与 smux/yamux/h2mux。具体组合见[支持矩阵](docs/protocols.md)，配置见 [protocols.yaml](examples/protocols.yaml)。

Shadowsocks 支持以下方法：

| 方法 | TCP | UDP |
| --- | --- | --- |
| `aes-128-gcm` | 已实现 | 已实现 |
| `aes-256-gcm` | 已实现 | 已实现 |
| `chacha20-ietf-poly1305` | 已实现 | 已实现 |

Shadowsocks classic AEAD 每个监听器使用一份凭据；SS2022 的两种 AES 方法支持同端口多用户。SS2022 三种方法和 Naive 的配置见 [协议说明](docs/naive-ss2022.md)。Shadowsocks 插件见[独立说明](docs/shadowsocks-plugins.md)。Linux/macOS 可用 SIGHUP 重载 YAML，只重建受影响的监听器；这些监听器的旧连接会关闭。

配置版本、凭据/证书资产、幂等应用和重启恢复可通过本机 CLI 使用。P5 管理 API 已接入认证、资产、草稿/计划/异步应用、状态和恢复；Web 表单仍属于 P6，当前界面保持骨架。详见 [管理 API 使用说明](docs/management-implementation.md)。协议细节与验证范围见 [Shadowsocks 实现说明](docs/shadowsocks.md)。

## 本地开发

节点核心只需要 Go 1.27 或更新版本，不需要 Node.js 或前端构建。

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

运行后发送 `kill -HUP <pid>` 应用文件变化，`kill -USR1 <pid>` 查看日志中的状态。`secret_file` 可随重载轮换；外部修改环境变量不会更新进程已有环境。重载失败保留或恢复内存中的旧配置，不修改磁盘文件，详见 [重载说明](docs/runtime-reload.md)。

需要跨重启保留最后成功配置时，改用管理模式（与文件模式二选一）：

```sh
./bin/lunaris managed --data-dir ./state --source examples/shadowsocks.yaml
# 在另一终端发送 SIGHUP，显式导入并应用 source
kill -HUP <pid>
```

管理模式启动只恢复已提交版本，不会自动应用 source 或草稿。离线 `config import/apply/show/operations`、`backup`、`restore` 的完整用法见 [持久化配置服务](docs/persistent-configuration.md)。默认程序现在包含 SQLite 支持，但仍不需要 Node.js、前端资源或 Hertz；文件模式依然不访问数据库。

```sh
make check       # 依赖约束、go vet、race 测试；无需前端产物
./bin/lunaris version
```

要运行管理 API 与内嵌页面，需要额外安装 Node.js 24 与 pnpm 12.16.1：

```sh
make install-web
make build-web
./bin/lunaris-web serve --config config.example.yaml
make check-web
```

管理服务默认使用本机 `127.0.0.1:9080`，可显式配置原生 HTTPS 或可信 HTTPS 反代；`config.example.yaml` 是管理启动设置，`examples/shadowsocks.yaml` 是节点配置，两者用途不同。前端热更新使用 `pnpm --dir web dev`。发行 Web 构建使用 `webui` 标签内嵌静态文件，缺少前端产物时会构建失败；默认核心构建不编入前端和 Hertz。

构建入口保留 `stdjson` 标签以使用标准 JSON 编解码。`web/dist` 和 `bin` 是生成产物，不提交；`go.sum`、pnpm lockfile 和生成的 API 类型纳入版本控制。

## HTTP API

统一响应信封为 `{code,msg,data}`：成功 code 为 0，错误为非零整数；同时保留正确的 HTTP 状态码。健康检查不代表代理节点已经配置或可以转发。

```json
{"code":0,"msg":"ok","data":{"status":"ok"}}
```

当前实际接口见 [OpenAPI](api/openapi.yaml)；完整管理功能的规划见 [API 契约](docs/management-api.md)。配置文件使用 YAML，HTTP 请求和响应使用 JSON。

systemd 样例提供[文件模式](packaging/systemd/lunaris.service)和[管理模式](packaging/systemd/lunaris-managed.service)，尚未自动安装到系统。HTTP 管理功能不作为核心开发的前置依赖。

## 许可证

项目采用 GNU General Public License v3.0，SPDX 标识为 `GPL-3.0-only`。完整条款见 [LICENSE](LICENSE)。第三方依赖与组件保留各自的版权和许可证声明。

Naive（HTTP/1.1、HTTP/2、HTTP/3）与 Shadowsocks 2022 单/多用户的配置和验证边界见 [协议说明](docs/naive-ss2022.md)。

已从 Polaris 移植 [XHTTP 传输](docs/xhttp.md)，覆盖三种上传模式与 HTTP/1.1–3；配置见 [xhttp.yaml](examples/xhttp.yaml)。

新增 [Snell、Mieru 与 ShadowsocksR](docs/snell-mieru-ssr.md)，配置见 [示例](examples/snell-mieru-ssr.yaml)。

VLESS 已支持 [Encryption、Vision 与 XUDP](docs/vless-encryption-vision.md)，可用 `lunaris keygen vless` 生成配置；示例见 [vless-encryption.yaml](examples/vless-encryption.yaml)。

已接入 [Shadowsocks 的六类插件](docs/shadowsocks-plugins.md)：simple-obfs、v2ray-plugin、gost-plugin、ShadowTLS、Restls 与 kcptun；配置见 [shadowsocks-plugins.yaml](examples/shadowsocks-plugins.yaml)。

P5 已完成：初始化 token 文件、Argon2id 管理员密码、会话/CSRF、版本化管理 API、敏感连接参数导出及离线恢复。API 入口仍为管理构建的 `serve`；操作方法见 [P5 说明](docs/management-implementation.md)。
