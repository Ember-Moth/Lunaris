# 持久化配置服务

状态：代理配置统一存储在 SQLite，结构化 JSON 管理 API 负责创建资产、编辑和校验草稿。CLI 提供常驻运行、离线查询、历史版本恢复、应用、备份和管理员恢复；不提供节点文件导入。

## 两种运行入口

| 模式 | 配置来源 | 重启行为 | 在线变更 |
| --- | --- | --- | --- |
| `serve --config bootstrap.yaml` | SQLite 的 committed revision | 恢复已提交版本，代理恢复失败保留 HTTP 修复入口 | JSON API 保存草稿、预览和应用 |
| `managed --data-dir DIR` | 同一 SQLite 的 committed revision | 严格恢复已提交版本，失败则退出 | SIGHUP 显式应用已保存草稿 |

`bootstrap.yaml` 只包含管理部署设置，不包含代理配置。节点 YAML、`run`/`check`、`config import`、`managed --source` 和 HTTP YAML 导入/导出均已移除。JSON 示例是 API 请求体，不是替代的节点配置文件。

同一数据目录只有一个持有者，`serve`、`managed` 与离线命令不能同时打开它。首次运行新目录时，草稿和已提交版本都是空配置 `r0`；通过管理 API 设置代理，不会自动启用尚未应用的草稿。

## 版本与资产

保存操作产生不可变的配置版本，包含公开配置和逻辑凭据引用。凭据值单独写入不可变资产表；每个版本固定自己的逻辑名称到资产 ID 的映射。密码变化创建新资产，旧版本继续引用旧值；相邻草稿中没有变化的凭据会复用资产。配置内容和凭据均未变化时，不重复创建草稿版本。

资产创建时保存实际凭据与证书内容。已保存版本不依赖环境变量、原 PEM 文件或其他节点文件；轮换必须创建新资产并保存、应用新草稿。配置详情、历史列表和操作状态不返回凭据原文。

SQLite 数据库与备份文件使用 `0600`，新数据目录使用 `0700`；已有目录不得允许组或其他用户写入。凭据和备份当前没有额外的静态加密，完整备份包含敏感材料。

## 离线配置命令

以下命令要求该数据目录的节点已停止：

```sh
./bin/lunaris config show --data-dir ./state
./bin/lunaris config list --data-dir ./state --limit 20
./bin/lunaris config apply --data-dir ./state --revision <draft-id> --request-id initial-apply
./bin/lunaris config operations --data-dir ./state --limit 20
./bin/lunaris managed --data-dir ./state
```

草稿由 JSON API 保存；离线 `draft-from` 的 `--expect` 检查草稿版本，省略时使用打开目录时读取的当前版本。`apply` 要求明确的目标草稿和请求 ID，可用 `--base` 约束已提交版本。离线 apply 会短暂启动目标监听器验证运行，再提交数据库并关闭临时运行时；常驻服务由 managed 命令启动。

要恢复历史配置，先复制为新的草稿，再显式应用：

```sh
./bin/lunaris config draft-from --data-dir ./state --revision <historical-id> --expect <current-draft-id>
./bin/lunaris config apply --data-dir ./state --revision <new-draft-id> --request-id restore-request
```

CLI 的结构化查询输出是脱敏 JSON 元数据；修改配置使用 JSON API，CLI 不接受配置文件。列表一次最多返回 100 条；当前保留历史版本、资产和请求记录，不自动清理历史。

## 在线本机操作

```sh
./bin/lunaris managed --data-dir ./state
kill -HUP <pid>
kill -USR1 <pid>
```

应用工作串行执行，重复信号会合并成一次追加应用，读取当前 SQLite 草稿。SIGUSR1 的状态区分数据库 heads、运行时版本、应用中、临时状态和写入冻结；读取数据库失败时，返回最后已知的 heads 并标记 `heads_known=false`，不会把缓存当成已确认的数据库状态。

`serve` 的 SIGHUP 不应用草稿，需通过 JSON API 创建并确认计划。`managed` 运行期间独占数据库，修改草稿需先停止它，再用 `serve` 管理该目录。

## 应用与幂等

1. 查找请求 ID；同请求返回原结果，不重复执行。相同请求 ID 搭配不同目标或不同 `--base` 会被拒绝。
2. 校验目标并将应用记录持久化为 running。目标必须是当前草稿；应用期间禁止保存新草稿。
3. 调用 P2 运行时进行差异应用。网络失败时记录失败/回退结果，committed 指针不变。
4. 运行时就绪后，在一个 SQLite 事务中推进 committed 指针并记录 succeeded。

数据库与 socket 不构成原子事务。已启动的目标可能短暂接收流量，失败恢复也不能复活被关闭的旧连接。

如果提交返回错误，会重新读取操作与 committed 指针：

- 确认已提交：保留目标运行时并返回成功结果。
- 确认未提交：恢复操作前的运行配置，再记录失败；恢复失败时停止不能确认的运行时并冻结写操作。
- 无法确认：不猜测回退，保留当前可观测运行态，冻结后续写入，要求重启后依据数据库恢复。

成功、失败或中断的请求 ID 都不会重新执行。需要重试失败操作时使用新的请求 ID。重试一个很早的成功请求只返回历史结果，不会把当前配置改回那个历史版本。

## 重启恢复

数据目录锁确保同一目录只有一个节点/离线命令持有者。打开目录后检查 schema、完整性与外键；先前未结束的 running 记录转为 interrupted，不重放网络操作。managed 随后只解析 committed 对应的配置与资产。

应用在数据库提交前中断，恢复原 committed；事务提交完成但响应丢失，恢复目标 committed。未应用草稿始终保留为草稿。

如果 committed 的协议已不支持、资产损坏或端口不可绑定，managed 启动明确失败并清理本次资源，不退而启用草稿。可通过离线 `draft-from/apply` 恢复可用历史版本；离线 apply 从空运行时验证目标，不要求错误的旧绑定先启动。新配置修复使用 `serve` 的 JSON API。P5 `serve` 管理模式会保留 HTTP 修复入口，见[管理 API 说明](management-implementation.md)；`managed` CLI 模式仍采用这里的严格启动规则。

## 迁移、备份与还原

发现旧 schema 时先生成一致的迁移前备份，再在事务内执行迁移。备份保存在数据目录的 `migration-backups` 下；未知、被改写或不连续的迁移历史会被拒绝。

```sh
# 先停止该数据目录的节点
./bin/lunaris backup --data-dir ./state --output ./backup.db
./bin/lunaris restore --data-dir ./restored-state --input ./backup.db
./bin/lunaris managed --data-dir ./restored-state
```

备份使用 SQLite `VACUUM INTO` 生成一致快照，包含 WAL 中已提交的内容；不会直接复制运行数据库的主文件。生成文件先同步落盘，再以不覆盖现有路径的方式发布。[SQLite VACUUM 文档](https://www.sqlite.org/lang_vacuum.html)。

备份命令不会先升级或改写源数据库。restore 校验备份完整性、外键与迁移历史，只接受空目标目录，不覆盖现有节点数据；后续首次打开还原目录时再执行必要迁移。启动设置、systemd 单元及外部文件需要另行保管，不属于 SQLite 快照。

当前不提供在线替换数据库或强制覆盖恢复。还原后确保文件可由目标服务账号读取；无法确认存储提交结果的节点应先停止，再检查状态或还原到新目录。

## 验证范围

测试覆盖草稿 CAS、资产不可变、凭据版本恢复、应用期间写入冻结、幂等重试、提交前失败/提交后响应丢失/读回失败、运行时绑定失败、离线修复、WAL 中断恢复、迁移前备份与备份不覆盖。子进程验证在提交前/后直接退出，随后从 WAL 备份并恢复正确的 committed。

历史 P3 独立二进制验证覆盖已提交资产脱离源文件后的恢复、应用中断、备份还原及幂等重放。当前脚本通过 JSON API 创建配置后验证重启、离线恢复和只恢复 committed。真实 Linux 执行、外部客户端和公网生产验证仍需单独完成。

P5 备份额外包含管理员账户和密码哈希。还原副本发布前会撤销会话和旧初始化 token，避免恢复已撤销的浏览器身份；原备份保持不变。
