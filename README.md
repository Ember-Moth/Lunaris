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

项目处于架构设计阶段，尚无可运行程序。文档中的 API、模块和 CLI 是实现约定。

首版应打通“安装启动 → 浏览器初始化与登录 → 创建协议监听 → 保存并应用 → 客户端连接”的完整流程。首批协议和具体传输组合尚未确定。

## 许可证

项目采用 GNU General Public License v3.0，SPDX 标识为 `GPL-3.0-only`。完整条款见 [LICENSE](LICENSE)。第三方依赖与组件保留各自的版权和许可证声明。
