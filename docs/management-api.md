# Web 管理 API 契约

面向 React + shadcn/ui 管理界面的设计契约，尚未实现。由 Hertz 提供同源 HTTP API。具体状态语义见 [配置生命周期](configuration-lifecycle.md)，模块边界见 [总体架构](architecture.md)。实现时将本文转换为 `api/openapi.yaml`，作为 TypeScript 类型生成与契约校验的来源，不同时维护另一份手工协议类型。

## 1. 通用约定

- 路径前缀 `/api/v1`，UTF-8 JSON；时间为 UTC RFC 3339；资源 ID 是不透明字符串。
- 成功返回业务对象；失败返回统一 error 对象，HTTP 状态码表达失败类型，不使用 HTTP 200 包装全部错误。
- 默认需要管理员会话。仅初始化状态、初始化提交、登录端点允许未登录访问，并分别执行 token 或登录校验。
- 普通 GET 没有副作用。所有写操作校验 Origin/Host；会话建立后的写操作另需 `X-CSRF-Token`。
- API 响应设置 `Cache-Control: no-store`。敏感导出、凭据请求体和登录请求不记录原文。
- 请求体、上传、分页、日志读取与并发数有服务端上限。拒绝未知字段、不支持的协议和多余的 JSON 文档。
- `RequestContext`、其 byte slice 和请求取消信号不直接交给后台应用任务；Hertz handler 仅将完整校验并复制的 DTO 传入应用层。

错误示例：

```json
{
  "error": {
    "code": "invalid_configuration",
    "message": "配置包含无效字段",
    "fields": [
      {"path": "listeners[0].port", "code": "out_of_range", "message": "端口超出允许范围"}
    ],
    "request_id": "req_example"
  }
}
```

| HTTP | 用途 |
| --- | --- |
| 400 / 422 | 格式错误 / 字段与协议约束不满足 |
| 401 / 403 | 没有有效会话 / CSRF、来源或操作权限失败 |
| 404 | 资源不存在，包括未知 API 路径 |
| 409 | 配置应用忙、计划过期、资产被引用或幂等键冲突 |
| 412 / 428 | If-Match 版本过期 / 缺少必需的写入前置条件 |
| 413 / 429 | 请求过大 / 超过速率或并发限制 |
| 500 / 503 | 内部失败 / 存储或管理服务暂不可用 |

已经受理的异步应用失败通过 operation 状态表达；查询该 operation 本身成功仍返回 200。

## 2. 初始化与会话

| 方法与路径 | 行为 |
| --- | --- |
| `GET /setup/status` | 仅返回是否需要初始化，不公开版本、地址或现有账户详情 |
| `POST /setup` | 一次性 token + 管理员名称/密码；事务内建立账户并消费 token，返回 201，随后正常登录 |
| `POST /auth/login` | 校验用户名和密码，创建会话 cookie，返回账户摘要与 CSRF token |
| `GET /auth/session` | 返回当前账户摘要、会话过期时间与 CSRF token |
| `POST /auth/logout` | 撤销当前会话并清 cookie，返回 204 |
| `PUT /auth/password` | 当前密码 + 新密码；成功后撤销全部会话，要求重新登录 |
| `POST /auth/reauth` | 再次校验管理员密码，建立短时的敏感操作授权，与当前会话绑定 |

初始化完成后 `/setup` 不再接受创建管理员。初始化幂等竞争在数据库事务中裁决，不能由前端按钮禁用实现。首次 token 过期后通过本机恢复流程重新生成，不允许公网自行获取新 token。

单管理员是首版范围；多份代理凭据不会自动创建多个管理员。退出登录不取消已经受理的配置应用，敏感授权不能跨会话复用。

## 3. 版本、能力和实际状态

| 方法与路径 | 返回 |
| --- | --- |
| `GET /system/version` | 程序版本、构建提交、API schema 标识、前端构建标识 |
| `GET /capabilities` | 已编译并启用的协议及明确支持的 TCP/UDP、TLS、传输、密码套件等组合 |
| `GET /status` | boot_id、runtime_epoch、草稿/已提交版本、当前操作、实际监听状态 |
| `GET /logs?cursor=...&limit=...` | 脱敏日志、下一游标，以及是否发生截断或进程重启 |

库适配与项目独立实现均通过同一能力描述公开，页面不根据实现来源分两套配置流程。尚未实现的协议不能仅因为出现在候选依赖表中就宣称可用。

状态中的监听器至少包含稳定 ID、运行实例代次、实际配置摘要、状态、绑定端点、最近错误和可用的聚合计数。`running` 表示实例就绪，不表示已验证外网防火墙或客户端网络。

日志使用带 boot_id 的游标和有界内存环形缓冲；游标过旧时返回明确截断标记。状态计数与日志不入计费表。页面隐藏后停止轮询，网络错误带退避，不叠加无限并发请求。

## 4. 草稿、计划和应用

| 方法与路径 | 行为 |
| --- | --- |
| `GET /config/draft` | 返回 revision、schema_version 和脱敏配置；附 `ETag: "r17"` 一类版本标识 |
| `PUT /config/draft` | 必须带 If-Match；保存完整候选配置，返回新版本和 ETag |
| `GET /config/committed` | 返回已提交配置快照，仍需结合 `/status` 判断实际状态 |
| `POST /config/validate` | 校验提交的候选配置，不保存、不绑定 socket、不改变实例 |
| `POST /config/plans` | 对当前保存的 draft_revision 与 base_revision 生成应用计划 |
| `POST /config/apply` | 受理一个有效计划；返回 202、operation_id 和 Location |
| `GET /operations/{id}` | 查询应用阶段、影响的监听器、最终结果及脱敏错误 |
| `GET /config/revisions?cursor=...&limit=...` | 有界历史列表；不暴露秘密资产 |
| `POST /config/draft/from-revision` | 将历史版本复制为新草稿；要求 If-Match，不直接切换运行态 |

`PUT /config/draft` 的协议字段使用带判别字段的 schema，并引用 CredentialAsset / CertificateAsset 的 ID。`enabled` 也属于版本化配置：点击启停保存草稿，经过同一计划和应用流程；没有另一条绕过 committed 状态的启停通道。

计划请求指定 `draft_revision` 和 `base_revision`；返回服务端 `plan_id`、有效期、runtime_epoch、create/replace/disable/remove/recover 列表及会中断连接的监听器。计划仅是预览，不是对端口占用的保留。

应用请求示例：

```http
POST /api/v1/config/apply
Idempotency-Key: apply-request-example
X-CSRF-Token: example
Content-Type: application/json

{"plan_id":"plan_example","acknowledge_disconnects":true}
```

如果计划涉及关闭现有连接，要求前端展示影响并发送确认字段；未涉及的计划可省略或发送 false。服务端使用自己保存的计划确定影响，不相信客户端自行提交的影响列表。

幂等键是必填请求标识，不是会话 token。作用域包含管理员与端点；服务端按规范化请求摘要对照。查重先于计划过期检查，使已受理请求在网络断开或进程重启后仍可返回原操作。记录保留期间同键同请求不重复执行，同键不同请求返回 409；记录清理后过期计划也不能被重新执行。

应用期间草稿与资产变更返回 `operation_in_progress`，附可查询的操作 ID；读取保持可用。不能因浏览器请求超时就生成新幂等键重试，先查询原操作。

## 5. 凭据和证书资产

| 方法与路径 | 行为 |
| --- | --- |
| `GET /credentials` | 返回 ID、协议种类、标签与引用情况，不含原文 |
| `POST /credentials` | 提交或生成协议凭据；返回不可变 ID 和非敏感元数据 |
| `DELETE /credentials/{id}` | 仅删除未被受保护版本或执行中操作引用的资产 |
| `GET /certificates` | 返回 ID、证书主题、指纹、有效期、引用情况 |
| `POST /certificates` | 上传证书链与私钥；验证匹配，返回不可变 ID |
| `DELETE /certificates/{id}` | 引用保护规则与凭据一致 |
| `POST /listeners/{id}/connection-info` | 需要短时重新认证；针对运行中的已提交配置生成支持的连接信息 |

替换秘密材料通过创建新资产并更新草稿引用完成，没有原地覆盖密钥的 PUT 接口。前端修改普通字段时保留原资产引用，不能将遮蔽字符串当作新密码提交。

连接信息导出指定预期 committed_revision，并核对监听实例的实际 spec_digest；正在应用或运行版本不匹配时拒绝导出。监听地址可能是通配 IP，导出所需公开主机名、映射端口由用户明确配置，不盲目把 bind 地址写进链接。证书私钥不属于客户端连接信息。

导入、上传、导出都经过服务端大小限制和脱敏规则。资产暂存到持久化与响应之间失败时不假报成功。垃圾回收以配置历史引用为依据，不依赖浏览器保证上传后立即保存。

## 6. 导入、导出和管理边界

`GET /config/template` 返回不含秘密材料的模板；`POST /config/import` 带 If-Match，把模板和明确的资产映射校验后保存为新草稿，不自动应用。无法解析的引用返回字段错误；用户不能将脱敏模板误认为完整备份。

完整数据库备份与还原、管理监听地址变更、管理 HTTPS 引导和丢失管理员密码后的恢复，首版走受控本机 CLI/部署设置。Web 不提供任意命令执行、任意文件读取或在线替换数据库接口。

管理账户、启动设置与代理 NodeConfig 是不同边界。Hertz 可拒绝管理请求而不使已有代理流量依赖会话状态；代理认证由 sing-xxx 或基于 sing 的独立实现完成。

## 7. 实现时的契约验证

- API 路由在 Hertz 上覆盖鉴权、输入限制、错误映射和未知路径，验证不被 SPA fallback 掩盖。
- TypeScript 类型来自 OpenAPI；前端不能自定义后端尚不支持的协议字段。
- 测试初始化竞争、会话注销、CSRF、凭据响应脱敏、ETag 冲突与幂等重试的业务结果。
- 应用任务在 HTTP 连接断开后继续并可查询，不引用被 Hertz 复用的请求内存。
- 浏览器端验证实际表单保存、应用失败反馈和重启后的状态，不只验证静态页面能打开。
