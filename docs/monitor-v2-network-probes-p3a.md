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
- 测试：`tests/test-monitor-v2-probes.sh`（硬计数门 `EXPECTED_PASS=126`）+
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
  threading/uuid/time/re/dataclasses`）；套件 S0 用 AST 扫描强制。
* 普通 `sboxweb` 身份即可运行：无特权、无 sudo/root/journald 依赖、无
  文件系统写入（引擎完全无状态，不写任何文件）。
* **不修改**网络/路由/防火墙/DNS 配置；**不操作** sing-box；**无 listener**
  （引擎只做出站 client；测试 fake server 属于测试夹具，不属于模块）。
* 每一次网络操作都在**绝对 deadline** 之下：worker 的 deadline 在 cycle
  开始一刻即固定为 `cycle 起点 + min(spec timeout, cycle 总 deadline)`，
  晚于它的任何 outcome（无论 ok 还是 failed）一律按完成时间戳拒收并判
  `timeout`（§9）。
* 每个 slot 全引擎**至多一个在飞 worker**：占用登记与线程启动在同一条
  锁内**原子**完成（未启动的线程 `is_alive()` 为 False，check 与 start
  若分置于锁两侧，并发 cycle 就能双双认领同一槽位）；上一 cycle 的挂死
  worker 尚未退出时，后续 cycle 不再为它叠加线程，而是把该槽位直接判
  `unavailable`（零 I/O、零线程）直至旧 worker 死去（§9，R2-A6 判别组 J）。
* 任何 probe 的任何异常都不抛给未来的 publisher 主循环：公共入口
  `run_probe_cycle` 永不 raise —— `targets` 经精确类型门（非审核类即
  dark）、`cycle_id` 只接受**精确的小写 32-hex**（与引擎自产 id 同形；
  其余一切调用方值只会被引擎 id 替换、绝不过夜回显，R2-A5）、`clock`
  被强制为有限非负 float（异常则回退引擎自有时钟），最外层还有一条对
  一切 `Exception` 的最终兜底，兜底路径同样只产出闭合词汇。
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
  `ipaddress.ip_address()` 能解析的 **canonical 公网（global）** 形式，
  环回/私有/保留/文档段一律无条件拒收（parse 门与最终 normalize 门双重
  强制，spec 上不存在放宽旋钮，R2-A7）；failed 时恒 null。
* `cycle_id`：32 位 hex（uuid4，非机密）。调用方可注入 id，但只有
  **精确匹配 `^[0-9a-f]{32}$`**（引擎自产 id 的形状）的字符串才原样存活；
  大写、错长度、含非 hex 字符、自由文本、非字符串都被**替换**为引擎生成
  的 hex id —— 调用方文本永不越过结果边界（R1-A1/R2-A5 判别组）。
  `epoch`：cycle 完成时刻的 float 秒，由注入 clock 强制消毒（抛错/非数值/
  NaN/inf/负数 → 回退引擎 `time.time()`）；`v`：schema 版本整数 1。
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
* TLS 校验**永不可关闭**：默认 `ssl.create_default_context()`；可注入
  `cafile`/`server_hostname` 用于测试与私有 endpoint，但 `cafile` 的语义
  是**替换**所咨询的信任库（只会更窄，R1 修订措辞），且不存在任何
  `verify_mode` 豁免面；证书不匹配 → `tls_failed`。
* deadline 双层：probe 级 socket timeout（`spec.timeout_seconds`，作用于
  connect/TLS/每次读写的每一段）+ cycle 级**绝对** deadline —— 主线程
  在 cycle 开始就把该 slot 的截止点钉为 `cycle 起点 + min(spec.timeout,
  cycle 总 deadline)`，按截止点升序 join；worker 的 outcome 带完成时间戳
  入账，任何晚于绝对截止点的 outcome **一律拒收判 `timeout`，无论它是
  ok 还是失败**（R1-A3）。任何一段超时都归入 `timeout`；被判超时后迟到
  的 worker 结果永不覆写已判定槽位。
* 成功契约（预先定义，不接受浮动）：HTTP 状态码 ∈ `allowed_statuses`
  （默认恰 {200}）；方法固定 GET；`https` probe 的契约只看状态码，响应
  正文**根本不读**（头后即关，R1 修订）；`egress` 因需消费正文才读取，
  且上限内即弃，任何字节不进入结果。
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
* **双绑定应答判定（R1-A2）**：应答必须同时满足 **对端绑定** 与 **问题绑
  定** 才算我们的 round trip。对端绑定用 **connected datagram socket**
  （`sock.connect(resolver_host:resolver_port)` 后 `send/recv`）：出向请
  求钉死在配置 peer，来自任何其他源的报文（哪怕字节完全合法）在内核层
  就被丢弃，用户态永远看不到。问题绑定利用 RFC 1035 应答必须逐字回显
  question 段的事实：`data[12:12+len(question)] == question`（qname +
  QTYPE + QCLASS 逐字节相等）—— 答复"别人的查询"不算我们的回程。
* 成功契约（全部满足才 ok）：应答来自配置 peer；≤ `max_response_bytes`
  （默认 2048）；头部 ≥12 字节可解析；**id 匹配**；QR=1；**question 逐字
  回显**；TC=0；RCODE=0；QDCOUNT=1。
* 失败映射：sendto 后窗口内无任何（合法）应答 —— 含"服务端收到但静默丢
  弃"、含"只有错误 peer 在回答" —— → `timeout`（两条反假阳性判别 D2/D12
  逐点覆盖）；字节数不足/不可解析/id 不匹配/**问题不匹配** →
  `protocol_failed`（D13）；TC=1 或 RCODE≠0 → `bad_response`；connect/send
  本身失败、或 connected socket 收到 ICMP port-unreachable →
  `connect_failed`。
* 无 listener、单 socket，`settimeout` + 绝对剩余预算双保险；首个到达的
  应答即被严格裁决，不存在"再听一次"的循环面。

## 8. 公网出口 IP（`egress`）与 endpoint policy

**endpoint policy（PR-3A 冻结的是"不硬编码"）**：四类 endpoint 一律经
`ProbeTargets`（frozen dataclass）显式注入；`run_probe_cycle(ProbeTargets())`
的默认结果是四个槽位全 `failed/unavailable` 且**零外联**（套件以 socket
构造计数器判别）。任何第三方服务在进入默认配置之前必须经过独立评审。

`EgressProbeSpec`：GET（同样 direct egress、TLS 校验不可关）一个
text/ip-echo 型 endpoint；响应正文上限 `max_body_bytes`（默认 64）；
strip 后必须被 `ipaddress.ip_address()` 完全解析且必须是 **global**
地址（R2-A7：拒绝 loopback/私有/保留/文档段，防"连接级地址借机入库"）。
**global 是无条件合同而非开关** —— spec 上不存在 `require_global` 这类
放宽旋钮（传入未知 kwarg 直接 `TypeError`），且 parse 门与最终 normalize
门双重强制（即使假想的缺陷 worker 交出 private ok ip 也会被降级），
`classify_egress_change` 同样把任何非 global 输入判 `unknown`。输出仅
canonical IP 字符串。超限 → `bad_response`；非 IP → `parse_failed`；
其余映射同 §6。
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
  执行；主线程对每个 slot 的 join 预算取自该 slot 的**绝对**截止点
  `cycle 起点 + min(spec.timeout, total)`（按截止点升序推进，不做"相对
  上一次 join 结束时刻"的预算重算，R1-A3）：一个慢 slot 既不能饿死处于
  自己预算内的健康 slot，也不能把 cycle 拖过任何 slot 的绝对 deadline。
  worker 的 outcome 携带完成时间戳；晚于绝对截止点的 outcome 无论内容
  （ok 或 failed）一律拒收判 `timeout`。**跨 cycle 不累积（R1-A4/R2-A6）**：
  引擎为每个 slot 维护"至多一个在飞 worker"的占用登记 —— 占用判定、
  登记与线程启动在同一条锁的**同一临界区**内原子完成（未启动线程
  `is_alive()` 为 False，check/start 分居锁两侧会被并发 cycle 双重认领，
  判别组 J 以延迟 start 的 Thread 子类把该窗口确定性放大）；上一 cycle
  被遗弃的挂死 worker（getaddrinfo 这类无法内部取消的调用）持有自己的
  slot，后续 cycle 遇到占用时零线程、零 I/O、立即判 `unavailable`，直
  至旧 worker 死亡自动恢复。全引擎被挂死 worker 占用的线程数因此恒
  ≤ 4，与运行时长无关。
* 结果恒为完整六键（§4 构造器）：引擎在任何失败模式下都产出"全槽位、
  闭合词汇"的结果，绝不产出"部分异常字符串 + 半个结构"。入口消毒
  （cycle_id/epoch/targets 类型门）+ 最外层兜底使 `run_probe_cycle` 在
  任何调用方输入下都只返回闭合结果。
* 引擎无状态、可重入（每次 `run_probe_cycle` 独立）；生产 cadence 归
  PR-3B 的 scheduler 决定。候选值与开销估算：60s 周期（对齐 incident
  history 5s 聚合之上的一档）≈ 每小时 60 cycle × ≤4 请求 ≈ 4 KiB 量级
  控制面流量 + 每请求 RTT；对 VPS 带宽可忽略，对 endpoint 侧是低频匿名
  流量。快档候选 30s，慢档候选 300s；评审时与 §8 隐私面一并定。

**egress 变更判定（纯函数，PR-3B 的事件源）**：

`classify_egress_change(previous, current)`，两参数为历史与本次的
`egress.ip`（或 None）：先各自过严格 canonical 解析**与 global 校验**，
任何一侧无效或非公网（loopback/私有/保留/文档段）→ `"unknown"`；两侧
均为有效公网样本且相等 → `"unchanged"`；不等 → `"changed"`。
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
* **P4 UDP**：fake resolver 正常应答（逐字回显 question）→ ok；**收到即
  丢弃（sendto 成功无回程）→ 必须 `timeout`**（反假阳性判别）；**配置
  peer 沉默、另一 peer 送出字节完美的合法应答 → `timeout`（对端绑定
  D12）**；**正确 peer + 正确 id 但回显他人问题 → `protocol_failed`
  （问题绑定 D13）**；应答 id 不匹配 / 短包 → `protocol_failed`；TC=1 /
  NXDOMAIN 码 / 超 `max_response_bytes` → `bad_response`；`resolver_host`
  传 hostname → 构造抛 `SpecError`（值错误判别，不进结果通道）。
* **P5 egress**：body `203.0.113.7` → canonical ok；global IPv6 canonical →
  ok；`"not an ip"`/多行 → `parse_failed`；超限 body → `bad_response`；
  超时 → `timeout`；loopback/私有/共享地址（100.64/10、文档段）响应 →
  **无条件** `parse_failed`（R2-A7：spec 无 `require_global` 旋钮，传入
  即 `TypeError`；parse 门与 normalize 门双重强制；classify 对任何非
  global 输入判 unknown）；`classify_egress_change` 全转移矩阵 14 格
  （含非法字符串 → unknown、两个不同**公网**成功样本 → changed、任何含
  failure 或非 global 样本的转移 → unknown）。
* **P6 隐私哨兵**：在所有 fake 的 exception message、HTTP body、TLS 握手
  失败路径、DNS 应答 payload 中植入 UUID/password/私有 IP/hostname
  sentinel；断言结果 JSON、`repr(result)`、以及 `logging` 捕获（root
  logger handler）完全不含任何 sentinel。
* **P7 deadline/并发**：一个 probe 挂死时其它 probe 的墙钟 ≤ 各自 deadline
  + 余量；cycle 总墙钟 ≤ `total_deadline` + 小裕度；连续多个 cycle 无线
  程累积（active_count 有界）。
* **P8 R1 合同判别（A1–A4）**：`cycle_id` 自由文本/超长/非字符串 → 被
  32-hex 引擎 id **替换**且 sentinel 不过夜；抛错/NaN/inf/负数/非数值
  clock → epoch 恒为有限非负 float 且零泄漏；晚于绝对 deadline 的失败
  outcome 判 `timeout` 不判 `dns_failed`、晚归的 ok 同样拒收（H9/H10）；
  挂死 slot 不能把健康 slot 拖出其自身预算（H11）；**多 cycle 永久挂死
  判别**：挂死 worker 被遗弃为 `timeout` 后连跑 3 个 cycle —— 每 cycle
  立即 `unavailable`（墙钟 <0.5s）、`probe-dns` 线程数恒为 1、事件放开
  后槽位自动恢复 ok（I1–I5）。
* **P9 R2 合同判别（A5/A6/A7）**：caller id 只有精确小写 32-hex 存活，
  大写 hex、31/33 长度、含非 hex 字符、旧宽松语法的"安全"串全部被替换
  （A14–A18）；**并发认领判别**：Barrier 对齐的两个 cycle 撞上同一 hang
  resolver，且 Thread.start 被测试子类延迟 0.5s（把 check/start 分居锁
  两侧的缺陷窗口确定性放大为必中）—— 两次结果必须恰为
  {timeout, unavailable}、`probe-dns` 线程增量恒 1、风暴后槽位恢复
  （J1–J3）；egress 公网合同端到端：`require_global` kwarg 被拒（E13）、
  七类非 global 地址在 parse 门全拒（E14）、伪造 ok+private 的 slot 在
  最终 normalize 门被降级（H12）、global ok 样本原样通过（H13）、
  classify 矩阵含私有/回环/共享/文档段各格（F 组）。
* **硬计数门**：`EXPECTED_PASS=126`，任何静默跳过即红。

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

## 13. R1 评审（HOLD）修复记录：A1–A4 + 两处措辞/成本修正

| 项 | 缺陷 | 修复 | 判别测试 |
|----|------|------|----------|
| A1 | 入口未完全收容：`cycle_id` 任意对象/自由文本直接过夜进结果；caller `clock` 抛错或返回非数值即炸 `run_probe_cycle`；junk `targets` 靠 worker 内 try 兜底而非类型门 | `_sanitize_cycle_id`（严格语法 `[A-Za-z0-9][A-Za-z0-9._:-]{0,63}`，不合格一律替换为引擎 uuid hex，绝不过夜回显；R1 的这层语法在 R2-A5 进一步收紧为精确小写 32-hex，见 §14）；`_sanitize_epoch`（clock 抛错/非数值/NaN/inf/负数 → 回退引擎时钟，类型面判定）；`_slot_spec` 精确类型门（非审核 spec 类 = dark，零线程零 I/O，连子类都拒）；最外层绝对兜底返回全 `unavailable` 暗结果 | A11–A16（自由文本/超长/非 str/抛错 clock/junk clock 矩阵 + leak_free）；H1 改走类型门语义 |
| A2 | UDP 应答未绑定来源与问题：unconnected `recv` 会接受任何源发包，头部判定也不核对 question —— 错误 peer 的合法报文可假阳性 | connected datagram socket（`connect` 后 `send/recv`）实现内核级**对端绑定**；RFC 1035 question 段**逐字回显比对**实现问题绑定；ICMP port-unreachable（connected UDP 特有回弹）显式映射 `connect_failed` | D12（配置 peer 沉默、另一 peer 送字节完美应答 → 必须 `timeout`）；D13（正确 peer+正确 id 但回显他人问题 → `protocol_failed`）；D1–D11 全矩阵在新绑定下原样绿 |
| A3 | join 预算按"轮到该 slot 时的相对剩余"计算，可被前序 join 挤压/漂移；晚归的失败 outcome 会被接受进槽位 | slot 截止点在 cycle 开始钉死为绝对时刻 `cycle_started + min(spec.timeout, total)`，按截止点升序 join；worker outcome 附完成时间戳，`completed > deadline` 的 outcome **一律拒收判 timeout（失败也不例外）**；`_finish_slot` 不再自判晚归、由引擎统一裁决 | H9（睡 1.2s 后抛 gaierror，预算 0.5 → `timeout` 而非 `dns_failed`）；H10（晚归 ok 拒收）；H11（挂死 slot 不饿死预算内健康 slot，墙钟有界） |
| A4 | 每 cycle 无登记地 spawn daemon 线程：getaddrinfo 类不可取消调用永久挂死时，线程随 cycle 线性累积 | 引擎级 `_INFLIGHT` 占用登记（锁保护）：slot 有在飞 worker 时后续 cycle 零线程、零 I/O、立即判 `unavailable`；worker 退出自清登记，自动恢复。全局挂死线程数恒 ≤ 4 | I1–I5：Event 门控的永久挂死 resolver 连跑 4 个 cycle —— 首 cycle `timeout`，后 3 个 `unavailable` 且各自墙钟 <0.5s，`probe-dns` 线程增量恒 1，放开事件后槽位恢复 ok |
| 措辞 | "cafile 只加宽信任库"不实 | `create_default_context(cafile=...)` 是**替换**所咨询的信任库（更窄，测试 fake 用途），校验依旧无可关 | §6 与 spec/代码注释同步更正 |
| 成本 | https probe 成功后仍读满 64KiB 正文再丢弃 | 契约只看状态码：`read_cap=None` 路径完全不读正文（头后即关）；仅 egress 消费正文时按 `max_body_bytes+1` 读 | C/E 组在零-drain 下全绿（挂死 fake 的判别点前移到 header） |

测试套件为容纳新契约新增 16 项判别（113 = 97 + 6 A + 2 D + 3 H + 5 I；
S0 静态门计数不变），并在 cycle helper 中加入"测量前排空占用 slot"纪律
（I 组故意持有时除外）。DARK 边界、schema、VERSION、CI 接线均不因 R1
移动。

## 14. R2 评审（HOLD）修复记录：A5–A7

| 项 | 缺陷 | 修复 | 判别测试 |
|----|------|------|----------|
| A5 | R1 的 `cycle_id` 语法门过宽（`[A-Za-z0-9][A-Za-z0-9._:-]{0,63}`）：调用方可注入 64 字符以内的任意"语法安全"串原样过夜，id 通道事实上未收敛到引擎自产形状 | 收紧为 `\A[0-9a-f]{32}\Z`：唯一存活形状 = 引擎自己发出的小写 32-hex；大写、错长度、非 hex、自由文本、非字符串一律替换，绝不过夜回显 | A14 翻转（旧宽松语法的串现在必须被替换）；A17（大写 32-hex 替换）；A18（31/33 长度、含非 hex 字符替换 + 精确小写 32-hex 存活正例）；A7/A8 原语义不变 |
| A6 | `_INFLIGHT` 的 check+登记在锁内、`thread.start()` 在锁外：未启动线程 `is_alive()` 为 False，并发 cycle 可见"已登记但未启动"的占位并二次认领同一 slot（双 worker 双 I/O，登记被后者覆盖） | 占用判定、登记与 `start()` 移入**同一临界区**原子完成；worker 完成后仍"先清登记、再记 outcome"。全局挂死线程上界与 I 组语义保持 | J1–J3（新并发组）：Barrier 对齐两 cycle + 测试用 `SlowStartThread` 把 start 延迟 0.5s —— 修复前该窗口确定性放大为"2 worker / 双 timeout"，修复后恒得 {timeout, unavailable} + 线程增量 1 + 风暴后恢复 |
| A7 | egress 的 global 合同是 spec 字段 `require_global`（默认 True 可关）：关掉开关或伪造 slot 即可让 loopback/私有 IP 通过 normalize 门过夜，且 `classify_egress_change` 对私有地址对判 `changed` —— "公网出口 IP 例外"可被用来搬运连接级地址 | 删除 `require_global` 字段（未知 kwarg 直接 TypeError）；`_parse_egress_answer` 无条件拒非 global；global 校验下沉进 `_canonical_ip`，最终 normalize 门与 classify 纯函数共用同一道门（防御纵深：假想缺陷 worker 交出 private ok slot 也降级 `parse_failed`） | E13（逃生门不存在）；E14（回环/私有/CGNAT/ULA/文档段/v6 回环 多类全拒）；H12/H13（normalize 门降级 private、放行 global）；F 矩阵 10→14 格（私有对、global×private、回环对、100.64/10、2001:db8/32 全 `unknown`；v6 unchanged 正例改用真实 global 的 `2606:4700:4700::64` 展开式） |

R2 另修正 PR body 的过期元数据（head/base/计数）。套件净增 13 项判别
（126 = 113 + 2 A + 2 E + 4 F 格 + 2 H + 3 J；S0 计数不变）。DARK 边界、
闭合 schema 与词汇表、VERSION（0.3.1）、CI 接线均不因 R2 移动。
