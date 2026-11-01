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

这是候选依赖清单，不代表已实现的协议支持。按实际启用的功能引入依赖，具体版本在接入和互通验证后锁定。

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

## 当前状态

已建立可构建、可启动的工程骨架：Hertz 服务、React + shadcn/ui 页面、前端资源内嵌、YAML 启动配置、SQLite 初始迁移与目录锁、sing 协议接口和 OpenAPI 类型生成。

当前仅提供管理服务健康检查和启动页面；管理员初始化、登录、配置应用、证书管理及代理协议尚未实现，未注册任何代理协议。服务暂时只允许绑定回环地址。

首版应打通“安装启动 → 浏览器初始化与登录 → 创建协议监听 → 保存并应用 → 客户端连接”的完整流程。首批协议和具体传输组合尚未确定。

## 本地开发

需要 Go 1.26 或更新版本、Node.js 24 和 pnpm 12.16.1。先构建前端，再编译或测试 Go，确保二进制包含真实前端资源。

```sh
make install
make build
./bin/lunaris serve --config config.example.yaml
```

打开 `http://127.0.0.1:9080`。进程入口是根目录 `main.go`，命令与依赖组装在 `cmd/run.go`。YAML 中的相对数据目录以配置文件所在目录为基准，命令行参数可覆盖地址与数据目录。

```yaml
data_dir: ./data
admin:
  listen: 127.0.0.1:9080
```

需要前端热更新时，先启动上述后端，再在另一终端执行 `pnpm --dir web dev`；Vite 将 `/healthz` 和 `/api` 代理到本机 9080 端口。

```sh
make check       # 前端构建与 lint、go vet、race 测试
./bin/lunaris version
```

构建入口使用 Hertz 的 `stdjson` 标签，避免管理 API 的 JSON 加速库受 Go 内部实现变化影响。`web/dist` 和 `bin` 是生成产物，不提交；`go.sum`、pnpm lockfile 和生成的 API 类型纳入版本控制。

## HTTP API

统一响应信封为 `{code,msg,data}`：成功 code 为 0，错误为非零整数；同时保留正确的 HTTP 状态码。健康检查不代表代理节点已经配置或可以转发。

```json
{"code":0,"msg":"ok","data":{"status":"ok"}}
```

当前实际接口见 [OpenAPI](api/openapi.yaml)；完整管理功能的规划见 [API 契约](docs/management-api.md)。配置文件使用 YAML，HTTP 请求和响应使用 JSON。

目标目录中的 `node`、`relay`、`egress` 等模块会随实际协议接入创建，不用空实现冒充运行能力。systemd 样例位于 [packaging/systemd](packaging/systemd/lunaris.service)，尚未自动安装到系统。

## 许可证

项目采用 GNU General Public License v3.0，SPDX 标识为 `GPL-3.0-only`。完整条款见 [LICENSE](LICENSE)。第三方依赖与组件保留各自的版权和许可证声明。
