# Monitor 0.3.x 前置 —— PR-3A 出站探测引擎（issue #33 Phase 3，DARK 交付）

状态：已实现，**整体 DARK**（本 PR 不接线、不激活、不部署任何东西，
数据库不迁移，`VERSION` 保持 0.3.1）。基线：`main @ bb5fc61`。
设计以 issue #33 Phase 3 规格为准；本文档同时是"实现前勘察 + 偏差记录"。

## 1. 结论性摘要

- 新增包：`monitor-v2/diagnostics/`（stdlib-only，Python ≥3.10），核心模块
  `network_probes.py`：独立、无特权、闭合输出 schema 的出站探测引擎。
- 能力（供未来 integration 消费）：VPS 系统 DNS 是否正常；普通 TCP+TLS+HTTPS
  出站是否有合法应答；UDP 是否具备**可验证的 request/response 回程**；当前
  公网出口 IP 是什么（且仅该 probe 可输出 IP 字符串）。
- **Dark 证明（判别式，套件 S0 常驻断言，见 §10）**：Monitor 生产树对
  `diagnostics` 零 import；`sbmon_stage_release` 清单不含该包 —— 不可变
  release 树在物理上不可能携带它；unit 模板零改动；`webapp.py`/`broker.py`/
  `server.py` 字节不变；默认空配置下引擎零外联。
- 测试：`tests/test-monitor-v2-probes.sh`（硬计数门 `EXPECTED_PASS=97`）+
  测试夹具 `tests/monitor-probes/`（一次性自签 TLS 证书，SAN
  localhost/127.0.0.1，仅测试用途）。全部 fake server 绑 loopback，CI 零
  公网依赖。
- 明确偏差：无。规格与仓库现实逐点吻合（下文 §2 记录依据）。

## 2. 实现前勘察（调用边界）

按序完整阅读：

| 对象 | 与本 PR 相关的边界事实 |
|------|------------------------|
| `monitor-v2/webapp.py` | 生产进程唯一启动点（`cmd_serve`）：构造 Collector → IncidentHistory → SnapshotBroker → MonitorWebApp。**没有任何探测相关调用槽位**；PR-3B 若挂 publisher，须走与 `IncidentHistory` 同型的注入式构造。 |
| `monitor-v2/web/broker.py` | publisher 循环 `_publish_loop` 的两个 write-alongside 先例：`_export_health_file` 与 `_record_history`，契约均为"辅助子系统永不杀死 publisher、外层 `except Exception` 双保险"。未来的 probe scheduler 若骑 publisher 节奏，只能采用同型边界；本 PR 不占用该槽位。 |
| `monitor-v2/web/incident_history.py` | schema 现为**严格 v2**（表集恰等断言、forward-only、单事务迁移、v1 行零重写）。probe 样本入库属 PR-3B 的 v2→v3 显式迁移。本 PR 与之零接触。 |
| `monitor-v2/web/server.py` | 唯一 diagnostics 读面 `GET /api/v1/diagnostics/timeline`（session-gated、GET-only、deny-by-default 列白名单）。未来 probe 时间线读面在此之外新增路由，属 PR-3B。 |
| `monitor-v2/deploy/singbox-monitor.service.in` | `ExecStart` 唯一指向 `bin/monitor-service`；hardening 面 `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX` 已覆盖探测所需地址族（loopback fake 与真实 egress 均是 AF_INET/6），**unit 无需任何改动**。`monitor-contract-probe` 是既有的 service.api 契约探针（app-bin，读 release 树 JSON 一行），与网络探测无关，命名上须防混淆。 |
| `monitor-v2/deploy/lib/monitor-deploy-lib.sh` | `sbmon_stage_release` 显式清单：`collector.py` + `webapp.py` + `cp -R api_bridge` + `cp -R web` + 4 个 app-bin + journal_reader 12+1 清单。**`diagnostics/` 不在清单内** → DARK 是打包层面的结构性事实，不是约定。激活（PR-3B 之后的 integration/release-prep）需要显式评审 staging 清单变更。 |
| `docs/monitor-v2-incident-history-p1.md` | §5 禁止持久化清单：连接 ID、源/目的 IP/主机名、UUID、口令、secret、原始日志行等**继续有效**。本 PR 的 egress IP 字段是唯一被逐项审查过的例外（§9），且不进任何 DB —— PR-3A 无持久化。 |
| P2 journal 契约（`journal_reader/ingest_contract.py` + `docs/monitor-v2-journal-reader-p2a.md`） | 本模块沿用的先例：闭合 disposition 词汇、消毒码永不携带 exception text、DI 注入点仅供测试、硬计数测试门、DARK 判别式常驻断言。 |

**能力盘点**：仓库已有 —— publisher write-alongside 边界先例（health-file /
incident history）、严格 schema 门禁先例、闭合词汇消毒先例（journal
audit codes）、loopback 假服务测试先例（E2/E4 hist 套件）。仓库没有 ——
任何主动出站探测（现状全部证据是被动观察：service.api 流、journal 摄取、
health-file）；公网出口 IP 遥测；UDP 回程证据；探测结果的闭合 schema。
PR-3A 填补的正是后半句，且只以库的形态存在。

**Activation point（未来的接线点，本 PR 全部不动）**：
1. PR-3B：probe scheduler（独立线程或 publisher ride，cadence 在评审中冻结）
   → 闭合 `ProbeResult` → `IncidentHistory` v2→v3 迁移 →
   `network_probe_samples` / egress 变更历史表 → bounded 读面。
2. 生产 endpoint 默认值的冻结（§8 候选清单经 review 后写入 PR-3B）。
3. release-prep（VERSION→0.4.0）时才把 `diagnostics/` 加入 staging 清单。

## 3. 模块边界与安全契约

`monitor-v2/diagnostics/network_probes.py` 的全部对外承诺：

* Python ≥3.10 **stdlib only**（`socket/ssl/http.client/ipaddress/struct/
  threading/uuid/time/json/dataclasses`）；套件 S0 用 AST 扫描强制。
* 普通 `sboxweb` 身份即可运行：无特权、无 sudo/root/journald 依赖、无
  文件系统写入（引擎完全无状态，不写任何文件）。
* **不修改**网络/路由/防火墙/DNS 配置；**不操作** sing-box；**无 listener**
  （引擎只做出站 client；测试 fake server 属于测试夹具，不属于模块）。
* 每一次网络操作都在双重 deadline 之下（probe 级 + cycle 级，§7）。
* 任何 probe 的任何异常都不抛给未来的 publisher 主循环：公共入口
  `run_probe_cycle` 永不 raise（含对 `BaseException` 之外的一切 `Exception`
  的最终兜底，兜底路径同样只产出闭合词汇）。
* 结果对象**闭合**：顶层恰为 `v/epoch/cycle_id/dns/https/udp/egress` 六键；
  每个 probe 恰为 `status/latency_ms/error_code`（egress 另恰有一个 `ip`）。
  不允许任何自由文本：exception text、响应正文、hostname 回显、socket 地址、
  HTTP body 均无字段可承载；`error_code` 是闭合词汇（§4）。
* 模块自身**零 logging、零 print**：不存在把结果（或异常）写进日志的通路。

## 4. 输出契约（闭合 schema v1）

```json
{
  "v": 1,
  "epoch": 1730000000.123,
  "cycle_id": "<32 hex>",
  "dns":    {"status": "ok",      "latency_ms": 12,   "error_code": "NONE"},
  "https":  {"status": "failed",  "latency_ms": null, "error_code": "timeout"},
  "udp":    {"status": "failed",  "latency_ms": null, "error_code": "connect_failed"},
  "egress": {"status": "ok",      "latency_ms": 88,   "error_code": "NONE",
             "ip": "203.0.113.7"}
}
```

冻结规则（构造器强制，测试逐键断言）：

* `status ∈ {"ok","failed"}`；`error_code` ∈ 闭合词汇表，且
  `status=="ok"` ⇔ `error_code=="NONE"`；`latency_ms`：ok 时为 ≥0 整数
  （毫秒，int），failed 时恒为 `null`（失败路径不产出"半途时延"这种
  不可比数据）。
* `error_code` 词汇表（冻结，9 项）：
  `NONE`, `timeout`, `dns_failed`, `connect_failed`, `tls_failed`,
  `bad_response`, `protocol_failed`, `parse_failed`, `unavailable`。
  语义：`unavailable` = 该 probe 未被注入显式 spec（PR-3A 默认即此，见
  §8），或引擎内部缺陷被兜底捕获；`dns_failed` 仅表示系统解析失败；
  `connect_failed` = TCP 层被拒/不可达；`tls_failed` = TLS 握手/证书校验
  失败；`bad_response` = 应用层应答违反成功契约（状态码/截断/RCODE）；
  `protocol_failed` = 报文根本不成立（畸形/不匹配）；`parse_failed` =
  成立但内容不可规范化（egress 正文非 IP）。
* `egress.ip` 仅当 `status=="ok"` 时为非 null 字符串，且必为
  `ipaddress.ip_address()` 能解析的 **canonical** 形式；failed 时恒 null。
* `cycle_id`：32 位 hex（uuid4，非机密，测试可注入）；`epoch`：cycle 完成
  时刻的 float 秒；`v`：schema 版本整数 1。
* 结果由构造器一次性组装：先填全量默认（failed/`unavailable`/null），
  每个 probe 至多替换自己槽位一次，替换值先过闭合校验 —— 撕裂结果
  （半结构 + 异常字符串）在类型上不可能出现。

## 5. DNS probe（`dns`）

语义：**VPS 的系统 resolver**（默认 `socket.getaddrinfo`，测试注入点
`DnsProbeSpec.resolver`）能否解析一个审核过的 probe hostname。它证明的是
这台机器按真实系统配置（含 `/etc/resolv.conf`、NSS）做名字解析是否正常。

* 成功契约：resolver 返回非空结果；**解析得到的任何 IP/主机名不进入
  结果**（只计数，输出 success/failure + bounded latency）。
* 失败映射：resolver 抛 `socket.gaierror`/`OSError` → `dns_failed`；超过
  deadline（getaddrinfo 无法内部超时，故在 worker 线程运行、超时时遗弃
  该 daemon 线程）→ `timeout`。
* **UDP round-trip 与它是两个不同的东西**（§6）：udp probe 打到显式 resolver
  地址、只证明 UDP 回程，不证明也不冒充系统 DNS。两者在结果里是两个独立
  槽位，词汇互不重叠。测试断言：伪造 resolver 返回值里的 sentinel IP 绝不
  出现在结果字节中。

## 6. HTTPS/TCP probe（`https`）

语义：普通出站 TCP + TLS + HTTPS request/response（`http.client.
HTTPSConnection`，stdlib）。它只是**原始 evidence**：单个 endpoint 失败
≠ "VPS outbound down"，聚合判定属于未来 correlation 层。

* **direct egress 保证**：`http.client` 按构造从不读取 `HTTP_PROXY`/
  `HTTPS_PROXY`/`NO_PROXY`（区别于 `urllib.request`），故 probe 代表 VPS
  本身出站；套件用"环境注入指向死端点的代理变量、直连仍 ok"判别。
* TLS 校验**永不可关闭**：默认 `ssl.create_default_context()`（可注入
  `cafile`/`server_hostname` 用于测试与私有 endpoint，但无 `verify_mode`
  豁免面；证书不匹配 → `tls_failed`）。
* deadline 双层：probe 级 socket timeout（`spec.timeout_seconds`，作用于
  connect/TLS/每次读写的每一段）+ cycle 级 join 预算（该 slot 的总请求
  deadline 由主线程 `min(spec.timeout, cycle 剩余)` 强制）。任何一段超时
  都归入 `timeout`；worker 超出自预算晚归时其结果被丢弃，永不覆写已判定
  的槽位。
* 成功契约（预先定义，不接受浮动）：HTTP 状态码 ∈ `allowed_statuses`
  （默认恰 {200}）；方法固定 GET；响应正文**读取上限内即丢弃**，任何
  字节不进入结果。
* 失败映射：解析失败 → `dns_failed`；refused/不可达 → `connect_failed`；
  证书/握手失败 → `tls_failed`；任何超时 → `timeout`；状态码不在集合 →
  `bad_response`；HTTP 协议层错乱 → `protocol_failed`。

## 7. UDP probe（`udp`，语义名 `udp_dns_roundtrip`）

**这里拒绝一个常见假阳性：`sendto()` 成功绝不等于 UDP healthy。** Linux
把数据报交给本地协议栈，既不证明远端收到，更不证明回程路径可用。

* v1 契约：**有 application-level reply 的 bounded UDP round-trip**。实现
  为向显式配置的 resolver `host:53` 发出手工构造的标准 DNS query
  （`struct` 打包，随机 16-bit id，查询 `query_hostname`），并等待匹配应
  答。对外语义名固定为 `udp_dns_roundtrip`：它只是**普通 UDP egress +
  return-path 的 evidence**，绝不描述为"所有 UDP/Hysteria2 路径健康"；
  Hysteria2 端到端判断属后续 correlation / remote probe（§12）。
* 配置约束：`resolver_host` 必须是数值 IP（`ipaddress.ip_address` 校验
  通过），否则 `UdpProbeSpec` **构造即抛 `SpecError`**（调用方错误，结果
  通道之外；`run_probe_cycle` 自身仍永不抛）。UDP 路径内不做名字解析，
  避免与 `dns` 槽位混义。
* 成功契约（全部满足才 ok）：应答 ≤ `max_response_bytes`（默认 2048）；
  头部 ≥12 字节可解析；**id 匹配**；QR=1；TC=0；RCODE=0；QDCOUNT=1。
* 失败映射：sendto 后窗口内无任何应答（含"服务端收到但静默丢弃"）→
  `timeout`（判别测试逐点覆盖）；字节数不足/不可解析/id 不匹配 →
  `protocol_failed`；TC=1 或 RCODE≠0 → `bad_response`；connect/send 本身
  失败 → `connect_failed`。
* 无 listener、单 socket、`settimeout` + 剩余预算双保险。

## 8. 公网出口 IP（`egress`）与 endpoint policy

**endpoint policy（PR-3A 冻结的是"不硬编码"）**：四类 endpoint 一律经
`ProbeTargets`（frozen dataclass）显式注入；`run_probe_cycle(ProbeTargets())`
的默认结果是四个槽位全 `failed/unavailable` 且**零外联**（套件以 socket
构造计数器判别）。任何第三方服务在进入默认配置之前必须经过独立评审。

`EgressProbeSpec`：GET（同样 direct egress、TLS 校验不可关）一个
text/ip-echo 型 endpoint；响应正文上限 `max_body_bytes`（默认 64）；
strip 后必须被 `ipaddress.ip_address()` 完全解析，默认 `require_global=True`
（拒绝 loopback/私有/保留地址 —— 防"连接级地址借机入库"；测试 fake 服务
经显式 `require_global=False` 注入）。输出仅 canonical IP 字符串。
超限 → `bad_response`；非 IP → `parse_failed`；其余映射同 §6。
**endpoint 失败 ≠ "IP changed"**：change 判定是纯函数
`classify_egress_change(previous, current)`（§9），failure 参与的转移永不
产出 `changed`。

候选生产 endpoint（**未冻结，仅评审材料**；延迟/开销见 §10）：

| 槽位 | 候选 | 依赖 / 隐私 / 故障含义 |
|------|------|------------------------|
| dns | `monitor-probe.a.marginalia.nu` 类"长期稳定、低价值、专名"主机名，或 Cloudflare `one.one.one.one` | 仅证明系统 resolver；解析结果不出边界；失败=本机解析故障 |
| https | `https://www.gstatic.com/generate_204`（204 需入 allowed_statuses）或 Cloudflare `https://1.1.1.1/`（200） | Google/CF 侧可见 VPS IP（日志隐私面）；204 无 body 泄漏面 |
| udp | Cloudflare `1.1.1.1:53` 或 Quad9 `9.9.9.9:53` | 明文 DNS：query 名会暴露"做过探测"，查询名选择即隐私决策；失败=UDP 53 出站或回程断 |
| egress | `https://api.ipify.org`（纯文本 IP）或 `https://ifconfig.me/ip` | 第三方可见 VPS IP + 请求头；body 合同简单；失败≠IP 变化 |

PR-3B 冻结默认值时须逐项评审：数据流向、隐私、超时含义、被墙/被污染场景
下的误报面。

## 9. 调度、deadline 预算与 egress 变更判定

**cycle 契约（引擎层冻结）**：

* 每 probe 独立 deadline（spec 字段）：`dns 2.0s / https 5.0s（connect
  3.0s，总请求 5.0s）/ udp 3.0s / egress 5.0s`。
* cycle 总 deadline：`total_deadline_seconds`（默认 12.0s ≥
  max(spec deadline) + 调度余量）。四 probe 各占一个 worker 线程并行
  执行；主线程按"该 probe 的 spec deadline 与 cycle 剩余预算取小"逐个
  join。一个 probe 卡死只消耗自己（至多拖到 join 边界），**不能**让其它
  probe 无限等待；超时未归的 worker 被遗弃（daemon 线程 + socket 自有
  timeout 双兜底，无线程泄漏累积路径：每次 cycle 至多创建 4 个终局线程）。
* 结果恒为完整六键（§4 构造器）：引擎在任何失败模式下都产出"全槽位、
  闭合词汇"的结果，绝不产出"部分异常字符串 + 半个结构"。
* 引擎无状态、可重入（每次 `run_probe_cycle` 独立）；生产 cadence 归
  PR-3B 的 scheduler 决定。候选值与开销估算：60s 周期（对齐 incident
  history 5s 聚合之上的一档）≈ 每小时 60 cycle × ≤4 请求 ≈ 4 KiB 量级
  控制面流量 + 每请求 RTT；对 VPS 带宽可忽略，对 endpoint 侧是低频匿名
  流量。快档候选 30s，慢档候选 300s；评审时与 §8 隐私面一并定。

**egress 变更判定（纯函数，PR-3B 的事件源）**：

`classify_egress_change(previous, current)`，两参数为历史与本次的
`egress.ip`（或 None）：先各自过严格 canonical 解析，任何一侧无效 →
`"unknown"`；两侧有效且相等 → `"unchanged"`；不等 → `"changed"`。
因此 **failure→success、success→failure、failure→failure 都只能得到
`"unknown"`**，绝不伪造 change 事件；判别测试逐例覆盖。本函数不读任何
存储、不产生事件 —— 事件持久化属于 PR-3B 的 v3 迁移（§12）。

## 10. 测试矩阵（真判别器）

`tests/test-monitor-v2-probes.sh`，全部 fake server 绑 127.0.0.1（CI 零
公网依赖；POSIX-only 断言在 Windows 上按仓库先例退化为可计数 no-op）：

* **S0 静态门**：py_compile；stdlib-only AST 白名单；模块零 `logging`/
  `print`；**DARK 判别组**（§12）。
* **P1 schema**：默认空配置 → 六键闭合、全 `unavailable`、零外联（socket
  计数器）；`error_code` 词汇表恰 9 项且结果 JSON 往返后逐键相等。
* **P2 DNS**：注入 resolver 成功（ok + latency int）/ 抛 `gaierror`（含
  sentinel 文本）→ `dns_failed` 且 sentinel 不出现在结果/日志；resolver
  睡眠超 deadline → `timeout` 且 cycle 墙钟有界；resolver 返回的 IP
  sentinel 不外泄。
* **P3 HTTPS**：本地 TLS fake 返回 204（allowed）→ ok；refused（bind 后
  释放的端口）→ `connect_failed`；证书 hostname 不符 / 未知 CA →
  `tls_failed`（校验不可关的对偶证明）；状态码 500 → `bad_response`；
  hanging server（accept 不 reply）→ `timeout` 且同 cycle 其它 probe 照常
  出结果；**代理注入判别**：`HTTP_PROXY/HTTPS_PROXY=http://127.0.0.1:<死端
  点>` 环境下直连 fake 仍 ok。
* **P4 UDP**：fake resolver 正常应答 → ok；**收到即丢弃（sendto 成功无回
  程）→ 必须 `timeout`**（反假阳性判别）；应答 id 不匹配 / 短包 →
  `protocol_failed`；TC=1 / NXDOMAIN 码 / 超 `max_response_bytes` →
  `bad_response`；`resolver_host` 传 hostname → 构造抛 `SpecError`（值错
  误判别，不进结果通道）。
* **P5 egress**：body `203.0.113.7` → canonical ok；IPv6 canonical →
  ok；`"not an ip"`/多行 → `parse_failed`；超限 body → `bad_response`；
  超时 → `timeout`；loopback 响应 + 默认 `require_global=True` →
  `parse_failed`；`classify_egress_change` 全转移矩阵 9 格（含非法字符串
  → unknown、两个不同成功样本 → changed、任何含 failure 的转移 →
  unknown）。
* **P6 隐私哨兵**：在所有 fake 的 exception message、HTTP body、TLS 握手
  失败路径、DNS 应答 payload 中植入 UUID/password/私有 IP/hostname
  sentinel；断言结果 JSON、`repr(result)`、以及 `logging` 捕获（root
  logger handler）完全不含任何 sentinel。
* **P7 deadline/并发**：一个 probe 挂死时其它 probe 的墙钟 ≤ 各自 deadline
  + 余量；cycle 总墙钟 ≤ `total_deadline` + 小裕度；连续 3 个 cycle 无线
  程累积（active_count 有界）。
* **硬计数门**：`EXPECTED_PASS=97`，任何静默跳过即红。

## 11. CI 接线

`tests.yml`：fast-checks 增加 `bash -n tests/test-monitor-v2-probes.sh`；
monitor-regression 增加本套件步骤。无新增 LIVE 面（loopback fake 跨基线
行为一致；真实 resolver 行为属于 activation 后的评审，不在本 PR）。

## 12. DARK 零调用证明 + 本 PR 明确不包含

套件 S0 的 DARK 判别组（全部为可失败的断言，非注释）：

1. repo 内（`monitor-v2/**/*.py` 全集，AST 级 import 扫描）除
   `monitor-v2/diagnostics/` 自身外，零文件引用 `network_probes` 或
   `diagnostics.`；`webapp.py`/`web/broker.py`/`web/server.py`/
   `web/incident_history.py` 逐文件断言零出现（且本 PR 对这些文件零 diff）。
2. `sbmon_stage_release` 与 `install-monitor` 路径对 `diagnostics` 零引用
   （grep 判别）；`singbox-monitor.service.in` 与全部 unit 模板零 diff。
3. `VERSION` 保持 0.3.1；`ProbeTargets()` 默认零外联（socket 计数器）。
4. `monitor-v2/diagnostics/` 不出现在任何 `ExecStart`/`app-bin`/shim 中。

本 PR 不做：SQLite schema v2→v3；history persistence；
`/api/v1/diagnostics/timeline` 改动；Incidents UI；outage detection；
fault-domain classification；TT Live 自动登录；Office Remote Probe；多
VPS failover；quality-aware failover；VERSION bump；生产部署；任何真实
endpoint 默认值。PR-3B 预留链路：probe scheduler → 闭合 ProbeResult →
schema v2→v3（继续遵守 strict schema gate、forward-only、单事务、v2 行零
重写）→ `network_probe_samples` / egress 变更历史 → bounded timeline 读
面。Phase 3 全部 integration 通过后再单独做 0.4.0 release-prep。
