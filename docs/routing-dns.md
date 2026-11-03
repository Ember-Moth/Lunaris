# 路由、DNS 与 GeoData

路由匹配器、索引、GeoSite/GeoIP 解码及 DNS 传输/缓存移植自 Polaris `56d52fb44958ef3cc2a7fb841cd240f8206234b2` 的 `internal/route` 与 `internal/dns`。Lunaris 使用自己的 JSON 配置、SQLite 资产和配置应用服务，不引入面板、计费、用户控制面或代理出站客户端。

当前出口范围是 **direct、block，以及代理 UDP/53 的 DNS 处理**。DNS 支持 UDP、TCP、DoT 和 DoH；DoQ/QUIC DNS 明确拒绝。没有新增公网 DNS 监听端口、FakeIP、流量目标嗅探、代理链或客户端策略组。

## JSON 配置

使用现有 `PUT /api/v1/config/draft` 保存完整候选，随后预览并应用。新增字段都位于 `config` 内：

```json
{
  "route": {
    "block": ["suffix:ads.example"],
    "rules": [
      {"action": "direct", "match": ["full:allowed.example"]},
      {"action": "block", "match": ["geoip:private"]}
    ]
  },
  "dns": {
    "servers": [
      {"protocol": "udp", "address": "127.0.0.1:5353"}
    ],
    "strategy": "prefer_ipv4",
    "timeout": 5000000000,
    "system_cache_ttl": 60000000000,
    "hijack_udp53": true
  }
}
```

这里只展示新增部分。完整请求示例见 [routing-dns.json](../examples/routing-dns.json)，需替换凭据资产 ID 和实际 DNS 地址；本示例不代表本机已经部署了 5353 解析器。时间字段单位为纳秒。未配置 route/dns 时保留原来的系统解析与直接出口；显式设置 DNS 时建立配置代次内的解析器和缓存。

## 路由语义

- `block` 作为最前面的阻断规则；之后按 `rules` 声明顺序匹配，最早命中的规则生效，未命中默认直连。
- 同一规则的 `match` 项是 OR 条件。action 仅接受 `direct` 或 `block`；其他出站不会静默跳过或回退成直连。
- 域名支持 `full:`、`suffix:`/`domain:`、`keyword:`/`plain:`、`regex:`/`regexp:`。裸域名是完整匹配；域名小写并移除末尾点，正则不区分大小写。
- IP 支持 `ip:`、`cidr:`、裸 IP/CIDR 和 `geoip:`。`geoip:private` 使用内置集合，无需上传数据文件。
- `geosite:分类` 支持源模块的布尔属性选择，例如 `geosite:category@cn`；其他分类来自当前版本绑定的资产。
- 不增加端口、进程、源 IP、入站协议或管理员身份等匹配维度。PROXY protocol 的对端声明地址不作为鉴权或路由权限依据。

IP 规则只有可能优先于当前域名匹配时才触发解析；解析结果复用于实际拨号。任何返回地址命中更早的 IP 规则都会影响决策。同规则的诊断优先级沿用 Polaris：普通完整/后缀域名优先，其次 GeoSite，再到普通关键词/正则；CIDR 优先于 GeoIP。

域名规则匹配的是代理请求携带的目标名称，不自动反查 IP，也不从 TLS/HTTP 内容中猜测域名。客户端已经把目标解析为 IP 时，使用 IP/CIDR/GeoIP 规则。

Lunaris 在 IP 规则所需解析失败时拒绝该请求，不通过第二次解析绕过规则。路由模块保留失败诊断，适配层不会把这类不确定结果当作已确认直连。

## DNS 选择、缓存与传输

每个服务器使用 `protocol`、`address`、可选的 `server_name` 和 `domains`：

| protocol | address | TLS |
| --- | --- | --- |
| `udp` | `主机:端口` | 无 |
| `tcp` | `主机:端口` | 无 |
| `tls` | `主机:端口` | DoT，最低 TLS 1.2；IP 地址需显式 server_name |
| `https` | `https://主机/dns-query` | DoH POST，校验证书；可指定 server_name |

IPv6 地址需使用方括号和端口。DoH URL 不接受内嵌账户、查询参数或 fragment，不跟随重定向，也不读取环境代理设置。DNS 上游主机名使用系统引导解析，避免解析器递归调用自己。配置不提供跳过 TLS 验证或私有 CA 上传。

带 `domains` 的服务器按顺序选第一个匹配项；不带 domains 的服务器是默认项，多个默认项时**最后一个生效**。没有多服务器故障转移：已选中的服务器失败就返回失败。域名查询没有匹配项、也没有默认服务器时回退到系统解析器；若要所有查询都走指定上游，应配置默认项。

地址策略：

- `prefer_ipv4` / `prefer_ipv6`：按偏好依次查询两个地址族并排序；第一个查询出错即失败，第二个失败但第一个已有地址时保留已有结果。
- `only_ipv4` / `only_ipv6`：只查询对应地址族；不禁止显式 IP 目标使用另一地址族。

每个配置代次共享缓存。上游响应缓存最多 1024 条，TTL 根据响应并限制在 1 秒至 24 小时，零 TTL 不缓存；NXDOMAIN/NODATA 沿用原模块的 1 秒负缓存，SERVFAIL 等错误不缓存。系统查询结果缓存默认 60 秒，可用 system_cache_ttl 调整。相同查询合并，最多保留 128 个并发待处理键。单个等待者取消不取消其他等待者；最后一个监听器释放代次时取消未完成请求并回收 HTTP 连接池。

普通目标解析由代次共享工作执行；代理 UDP/53 查询使用该流的入口上下文。DNS 上游 TCP/UDP 请求保留源进源出；携带入口绑定的 DoH 请求使用独立连接，避免跨入口复用错误的源地址。

## 代理 UDP/53

`dns.hijack_udp53` 默认关闭。开启后，代理 UDP/53 包先进入 DNS 处理，再按查询名选择 DNS 上游；这一步优先于普通路由规则，与 Polaris 的 DNS 出口顺序一致。没有匹配 DNS 上游时，向客户端原本指定的 DNS 目标转发，并验证响应身份。

UDP 路由**逐包检查**，不把首个目标的许可沿用给后续目标。一个关联中可以混用 DNS 与普通 UDP，且直连保持双栈支持。被阻断或非法数据包会使当前关联失败，其他关联和监听器不受影响。响应仅接受该关联实际放行过的目标。DNS 响应校验请求 ID、问题、类型与类；地址解析只使用问题名或其 CNAME 链上的 A/AAAA，类型长度、名称展开和零 TTL 另有边界检查。DNS 格式依据 [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035.html)；负缓存行为不宣称覆盖 [RFC 2308](https://www.rfc-editor.org/rfc/rfc2308.html) 的全部递归解析器语义。

本阶段不拦截代理 TCP/53，不开启本机 53 端口；原始 DNS 报文转发不使用内部 A/AAAA 查询缓存，保留请求 ID、问题与上游回复语义。

## GeoData 资产

GeoData 由 SQLite 管理，最多分别绑定一份 GeoSite 和 GeoIP。上传原始 V2Ray protobuf `.dat` 内容：

```http
POST /api/v1/geodata?kind=geosite&label=rules
Content-Type: application/octet-stream
Origin: 管理服务的完整来源
X-CSRF-Token: 当前会话的令牌
Cookie: 当前管理员会话
```

请求体直接发送文件字节。响应仍是标准 `{code,msg,data}` JSON 信封，包含不可变 ID、种类、SHA-256、大小、标签和引用元数据；不返回原始文件。

- 每份文件最多 128 MiB，API 同时只处理一个上传；kind 为 `geosite` 或 `geoip`。
- 相同种类、相同内容复用已有 ID，既有标签不被修改。
- 在 `config.geodata` 中绑定返回的 ID，例如 `{"geosite":"geo_example"}`；示例 ID 必须替换为真实值。
- `GET /api/v1/geodata` 分页读取元数据；`DELETE /api/v1/geodata/{id}` 只删除未引用资产。
- 历史版本和已保存草稿引用的资产均受保护；完整数据库备份包含 GeoData，恢复不依赖原 `.dat` 文件。
- 不扫描环境变量目录，不从 API 读取本机文件，也不自动下载或热替换规则文件。更新需上传新资产并保存、应用新的版本。

资产解析和编译有类别、字段、展开选择器及前缀索引预算；损坏文件、分类缺失、错误类型、无效正则或超限数据会拒绝候选配置。不可变材料可以跨规范化快照共享，编译后的分类在同一代次内共享。

## 应用和恢复

路由、DNS 和 GeoData 绑定纳入配置版本及运行摘要。改变全局规则或解析设置会重建受影响监听器，计划会标出已有连接中断，仍需显式确认。保存草稿不改变正在运行的策略。

候选编译失败不改变旧运行态。切换失败走现有补偿恢复；旧代次在最后一个持有者释放前保持有效，回滚可重新构造原配置的解析器。提交结果不确定仍冻结写入，重启只恢复 committed。没有全局可变 DNS 单例或跨配置代次的缓存混用。

Schema migration `0005_routing_geodata.sql` 添加资产与引用表。已有无路由/DNS 的配置仍可使用；迁移前备份、离线恢复和版本前置条件沿用原机制。

## 验证入口

```sh
make check
make check-web
make build-web
go build -C test/clients/ssplugins -o ../../../bin/test-ssplugins-client .
python3 scripts/test-routing.py
```

覆盖原模块的匹配、优先级、DNS wire/传输/缓存回归，以及逐包路由、DNS 取消和关闭、共享代次、HTTP 资产/配置流程、真实代理转发、失败恢复和完整备份恢复。独立进程脚本使用本地 DNS/回显端点和未修改的 Mihomo 客户端；不修改系统 DNS、路由或生产数据。

2026-11-02 本轮验证：

- `make check`、`make check-web`、`go mod verify` 通过；DNS wire 模糊测试完成 231,867 次输入，无失败。
- 最终本机二进制通过 `scripts/test-routing.py` 和 `scripts/test-management.py`，包括实际代理域名解析、GeoSite 阻断、已提交配置重启恢复、资产引用保护与完整备份恢复。
- `scripts/test-origin.py` 使用独立 Mieru、SSR、kcptun 客户端通过，TCP/UDP 目标仍观察到正确入口 IP。
- CGO=0 的 Linux amd64/arm64 核心与内嵌 Web 构建通过；本轮运行验证在 macOS 完成，未执行 Linux 或公网部署验收。

一次全量回归曾在 `TestXHTTPExtensions/h3` 出现偶发失败；随后该项重复 10 次及最终全量回归通过。尚未定位其偶发原因，本次不宣称修复该问题。
