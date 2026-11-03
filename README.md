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
- [源进源出与 PROXY protocol](docs/ingress-addresses.md)：自动地址识别、出站选源、UDP 多入口与信任边界。
- [运行时差异应用与状态](docs/runtime-reload.md)：SIGHUP、凭据轮换、差异重建与失败恢复。
- [UoT、mux 与 REALITY](docs/connection-extensions.md)：多路复用、旧客户端兼容、密钥配置与生命周期。
- [协议与传输工厂注册表](docs/factory-registries.md)：独立注册、组合校验、资源归属与扩展方式。
- [协议、传输与证书](docs/protocols.md)：支持矩阵、TLS 资产、配置示例和客户端互通。
- [持久化配置服务](docs/persistent-configuration.md)：不可变资产、草稿/提交版本、幂等应用、重启恢复与备份。

## 当前状态

已实现节点核心、运行管理、持久化配置服务，以及首批协议与传输扩展。代理配置统一持久化在 SQLite，通过结构化 JSON API 编辑、校验和应用；共享转发、直接出口、资源限制和凭据/证书轮换复用同一运行时。

新增 VLESS、VMess、Trojan、AnyTLS、Hysteria2、TUIC；支持 TCP/TLS、WebSocket、HTTPUpgrade、原生 QUIC、REALITY 和 XHTTP；已接入 UoT 与 smux/yamux/h2mux。具体组合见[支持矩阵](docs/protocols.md)，配置见 [protocols.json](examples/protocols.json)。

Shadowsocks 支持以下方法：

| 方法 | TCP | UDP |
| --- | --- | --- |
| `aes-128-gcm` | 已实现 | 已实现 |
| `aes-256-gcm` | 已实现 | 已实现 |
| `chacha20-ietf-poly1305` | 已实现 | 已实现 |

Shadowsocks classic AEAD 每个监听器使用一份凭据；SS2022 的两种 AES 方法支持同端口多用户。SS2022 三种方法和 Naive 的配置见 [协议说明](docs/naive-ss2022.md)。Shadowsocks 插件见[独立说明](docs/shadowsocks-plugins.md)。配置应用只重建受影响的监听器；这些监听器的旧连接会关闭。

配置版本、凭据/证书资产、幂等应用和重启恢复可通过本机 CLI 使用。P5 管理 API 已接入认证、资产、草稿/计划/异步应用、状态和恢复；Web 表单仍属于 P6，当前界面保持骨架。详见 [管理 API 使用说明](docs/management-implementation.md)。协议细节与验证范围见 [Shadowsocks 实现说明](docs/shadowsocks.md)。

## 本地开发

使用管理 API 配置节点，需要 Go 1.27 或更新版本、Node.js 24 和 pnpm 12.16.1：

```sh
make install-web
make build-web
./bin/lunaris-web serve --config config.example.yaml
```

首次启动创建空数据库和私有的 `data/setup-token` 文件。通过 JSON API 完成管理员初始化、登录、创建凭据/证书资产，再保存草稿、预览计划并显式应用；步骤见 [管理 API 使用说明](docs/management-implementation.md)。P6 表单尚未接入，当前可用 HTTP 客户端操作。

[config.example.yaml](config.example.yaml) 只配置数据目录、管理监听地址、HTTPS 和可信反代。代理监听器使用 [examples 中的 JSON 请求示例](examples/README.md)，替换成实际资产 ID 后提交到 `/api/v1/config/draft`。程序不从这些示例文件启动，也不监视文件变化。

节点 YAML、`run`/`check`、CLI 配置导入、`managed --source` 和 HTTP YAML 模板导入/导出已移除。代理凭据、证书和配置都由 SQLite 保存；无需维护另一份节点文件。

若只需运行已提交配置，可停止 `serve` 后使用不含 HTTP/前端的核心构建：

```sh
make build
./bin/lunaris managed --data-dir ./data
```

`managed` 只恢复 committed，不自动应用草稿；Linux/macOS 的 SIGHUP 显式应用已保存草稿，SIGUSR1 输出状态。两个进程不能同时持有同一数据目录。离线查询、历史版本恢复、应用和备份见 [持久化配置服务](docs/persistent-configuration.md)。

```sh
make check       # 依赖约束、go vet、race；无需前端产物
make check-web   # 前端构建与 lint、管理版 vet/race
make dev         # 构建页面并运行管理服务
```

管理服务默认监听 `127.0.0.1:9080`，也可配置原生 HTTPS 或可信 HTTPS 反代。前端热更新使用 `pnpm --dir web dev`。`webui` 构建标签包含管理入口与内嵌页面；核心构建不编入 Hertz 或前端资源，但包含 SQLite。

构建入口保留 `stdjson` 标签以使用标准 JSON 编解码。`web/dist` 和 `bin` 是生成产物，不提交；`go.sum`、pnpm lockfile 和生成的 API 类型纳入版本控制。

## HTTP API

统一响应信封为 `{code,msg,data}`：成功 code 为 0，错误为非零整数；同时保留正确的 HTTP 状态码。健康检查不代表代理节点已经配置或可以转发。

```json
{"code":0,"msg":"ok","data":{"status":"ok"}}
```

当前实际接口见 [OpenAPI](api/openapi.yaml)；完整管理功能的规划见 [API 契约](docs/management-api.md)。只有部署启动设置使用 YAML；代理配置通过 JSON API 保存到 SQLite。

systemd 样例提供[管理 API 服务](packaging/systemd/lunaris.service)和[无 HTTP 的 managed 服务](packaging/systemd/lunaris-managed.service)，尚未自动安装到系统。两者共用数据目录时只能启用一个。

## 许可证

项目采用 GNU General Public License v3.0，SPDX 标识为 `GPL-3.0-only`。完整条款见 [LICENSE](LICENSE)。第三方依赖与组件保留各自的版权和许可证声明。

Naive（HTTP/1.1、HTTP/2、HTTP/3）与 Shadowsocks 2022 单/多用户的配置和验证边界见 [协议说明](docs/naive-ss2022.md)。

已从 Polaris 移植 [XHTTP 传输](docs/xhttp.md)，覆盖三种上传模式与 HTTP/1.1–3；配置见 [xhttp.json](examples/xhttp.json)。

新增 [Snell、Mieru 与 ShadowsocksR](docs/snell-mieru-ssr.md)，配置见 [示例](examples/snell-mieru-ssr.json)。

VLESS 已支持 [Encryption、Vision 与 XUDP](docs/vless-encryption-vision.md)，可用 `lunaris keygen vless` 生成配置；示例见 [vless-encryption.json](examples/vless-encryption.json)。

已接入 [Shadowsocks 的六类插件](docs/shadowsocks-plugins.md)：simple-obfs、v2ray-plugin、gost-plugin、ShadowTLS、Restls 与 kcptun；配置见 [shadowsocks-plugins.json](examples/shadowsocks-plugins.json)。

P5 已完成：初始化 token 文件、Argon2id 管理员密码、会话/CSRF、版本化管理 API、敏感连接参数导出及离线恢复。API 入口仍为管理构建的 `serve`；操作方法见 [P5 说明](docs/management-implementation.md)。
