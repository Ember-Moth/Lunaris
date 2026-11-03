# 多用户认证扫描

`internal/authscan` 从 Polaris `56d52fb44958ef3cc2a7fb841cd240f8206234b2` 移植，接入实际候选密钥尝试，配置仍使用现有凭据资产和 `credential_refs`。

| 入站 | 选择方式 | 完整认证与重放 |
| --- | --- | --- |
| Shadowsocks classic AEAD | TCP 先验证加密长度；UDP 逐候选调用上游 packet codec | 上游 TCP 请求解析；共享、按用户隔离的 salt 窗口 |
| VMess AEAD | AuthID AES 解密、CRC32 与时间戳 | 按用户隔离的 AuthID 窗口保留 241 秒，再由上游 service 校验完整头部；alter_id 固定 0 |
| Mieru | 来源候选、username hint、兼容无 hint 的回退；每用户三个 epoch 密钥 | 完整 metadata/payload、首报文方向与会话字段；按凭据隔离的 nonce 重放检查 |
| Snell v5 / v6 unshaped | salt + AEAD 首记录头逐 PSK 尝试 | 完整上游请求解析；共享 PSK/salt 重放过滤器 |
| Snell v6 default | 按完整头长排序探测 PSK 派生的公开填充，再校验 AEAD 头 | 完整上游请求解析；验证头后预留 salt，完整请求后才记候选 |

Snell `unsafe-raw` 不携带认证信息，拒绝多 PSK 配置。SS2022 AES 已使用身份密钥定位用户，本次不改变其认证路径。

## 缓存与预算

- 候选缓存 64 个分片，每片最多 64 个来源，每个来源保留最近 4 个成功用户；超过容量时有界淘汰。
- 每个凭据快照拥有独立 selector。重建监听器或 Mieru 安装新快照会清空旧索引；旧快照上的迟到认证不会写入新缓存。
- classic AEAD TCP、VMess、Snell 和 Mieru 按物理来源 IP 分组；classic AEAD UDP 按来源 IP/端口。缓存命中仍须重新做密码学校验。TCP PROXY 声明地址不作为扫描来源，HTTP 载体也继承物理对端。
- 工作预算以候选检查计：classic AEAD 和 Mieru 每秒 `2^18`，VMess 每秒 `2^22`，Snell 每秒 `max(GOMAXPROCS,1) × 5000`；突发容量为两秒。Mieru 无强制 hint 时为两阶段预留预算，每个候选最多尝试三个 epoch 密钥。
- 并发扫描上限为 `min(max(GOMAXPROCS,1),32)`。只在 CPU 密钥扫描期间持有许可，网络读取和业务连接存活期间不占用扫描槽。
- 完整失败按来源退避，延迟从 25 ms 指数增加到 2 s；30 s 没有失败后重置。失败表每分片最多 64 条。缓存候选允许在来源退避期间重新校验，但仍受全局工作/并发预算约束。
- 未完成握手不会写入候选；EOF、取消或超时不作为密码错误。认证成功后的重放拒绝不会刷新成功缓存或清除退避。

Snell v6 default 的变长头不能仅因为某来源以前属于一个用户，就先读取那个用户较长的头。已缓冲数据不足时按完整头长顺序回退，避免同一 NAT 下较短的合法请求等不到响应。来源退避期间，允许受预算限制的公开填充探测逐步到达已缓存候选；未缓存用户仍不能进行密钥校验。填充探测与密钥校验分别计入工作预算，网络读取不持有扫描槽。这个模式仍可能做 O(n) 的廉价填充比较；通常只为真正匹配的形状派生一次密钥。v5/unshaped、classic AEAD 和 VMess 的冷扫描仍为 O(n)，保护措施限制其总工作量，不能把所有冷认证变成 O(1)。上游完整协议解析保留固定的再次校验成本。

Snell 共享两代 Bloom salt 过滤器，容量与用户数无关；v6 在认证首记录头后占用 salt，后续截断不会释放该 salt。各协议重放窗口属于监听实例，重建或进程重启不保留。

VMess 的额外窗口最多保留 65,536 个用户/AuthID 条目，保留 241 秒以覆盖时间戳前后 120 秒的完整有效范围。Mieru 的 nonce 窗口最多保留 262,144 条、期限 6 分钟，键包含凭据身份，不包含来源地址。两者容量满时拒绝新条目，不提前淘汰仍有效的重放记录。Mieru 的 UDP 会话还按凭据、端点和 sessionID 区分；每个端点保留各活动用户/密钥周期的解密器，最后一个引用关闭时回收。

## 配置与验证

classic AEAD 和 Snell 加密模式直接列出多份不同凭据：

```json
{"credential_refs":["alice-secret","bob-secret"]}
```

classic AEAD 不设置 `server_key_ref`；该字段仅用于 SS2022 AES 的服务端身份密钥。Snell 的每份凭据就是一个独立 PSK。Mieru 仍通过 `options.users` 映射用户名和凭据。

回归包含缓存提交时机、全局预算、来源退避、慢读释放扫描槽、凭据快照替换、VMess 损坏/截断/重放、同源多用户 AEAD UDP 回包隔离、Mieru 无 hint 回退及损坏 payload、Snell 共享重放内存和多 PSK TCP/UDP。独立客户端脚本 `scripts/test-snell-mieru-ssr.py` 覆盖 Snell 两个 PSK 和 Mieru 两个用户名。


2026-11-02 本机验证：

- `make check`（模块约束、stdjson 全仓库 vet/race）以及 `go vet -tags stdjson,webui ./...` 通过。
- macOS 管理版构建、Linux amd64/arm64 管理版交叉编译通过；交叉编译不代表 Linux 实机运行。
- sing-box 1.14.4：classic AEAD 三种方法、VMess TCP/WS/HTTPUpgrade 各两个用户，共 12 个 TCP/UDP 用例通过。
- sing-box 1.14.4：Snell 五种加密/obfs 组合各两个 PSK，加 unsafe-raw 单个配置，共 11 个 TCP/UDP 用例通过。
- Mihomo 1.19.33 的 Mieru TCP/UDP 载体，以及官方 Mieru API 客户端两个用户的 TCP/UDP 和受控丢包，共 7 个用例连续三轮通过；丢包轮次分别丢弃 189、215、206 个数据报。

首次 Mieru 丢包运行受到通用 echo fixture 的 5 秒 idle deadline 提前断连；原始提交对照也出现该超时日志。Mieru fixture 改为 25 秒，超过客户端的 20 秒请求期限，保留客户端期限作为失败判据；没有为此修改协议重传参数。

复现入口：`scripts/test-authscan.py --client <sing-box>`；`scripts/test-snell-mieru-ssr.py --only snell` 或 `--only mieru`（其余客户端路径参数见脚本 `--help`）。所有进程仅使用本机回环，不修改系统代理或路由。


## 2026-11-03 审计修复验证

六项问题已修复并加入永久回归：

| 问题 | 修复与回归 |
| --- | --- |
| Mieru 换端口重放、用户 nonce 冲突 | 凭据身份与 nonce 共同构成重放键；跨端口原密文被拒绝，不同用户同 nonce 互不冲突 |
| classic AEAD UDP 回包反射 | 发包前将响应 salt 加入同一用户的重放集合；三种方法均拒绝反射回包 |
| VMess AuthID 重放记录过早过期 | 额外 241 秒窗口覆盖未来时间戳；时钟驱动回归检查 121/240 秒边界，并重跑真实等待 121 秒的原始复现 |
| Mieru 首报文误提交缓存 | 首报文必须是非零 sessionID 的客户端 open 请求；完成字段、载荷、活动凭据及重放检查后才提交缓存/释放握手配额 |
| Snell v6 长头缓存用户被来源退避误拒绝 | 在全局预算内逐步探测到缓存候选；短头场景保持读取边界，未缓存用户不能借此绕过退避 |
| Mieru 同端点用户 sessionID 冲突 | 会话键加入凭据身份；回归覆盖同 ID 双用户数据隔离、单用户关闭、重新连接以及解密器并发引用回收 |

原始 7 个审计复现全部通过；永久测试另外覆盖重放窗口容量满时拒绝新条目、并发重复保留仅成功一次、Snell 探测预算耗尽和 Mieru 多用户/多 epoch 生命周期。`make check`、管理版 vet、macOS 管理版构建和 Linux amd64/arm64 管理版交叉编译通过。

本轮独立客户端复测：12 个 classic AEAD/VMess 用例、11 个 Snell 用例、2 个 Mihomo Mieru 用例及 5 个官方 Mieru API 用例全部通过；受控丢包场景丢弃 198 个数据报后恢复完成。Linux 交叉编译与本机回环运行分别记录，不代表 Linux 实机或公网验证。
