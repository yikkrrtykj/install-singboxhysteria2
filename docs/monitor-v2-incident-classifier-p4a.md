# Monitor 0.4.x —— PR-4A 确定性事件分类器（issue #33 Phase 4，DARK）

状态：**DRAFT PR，未合并、未部署**。
基线：`main @ 965751c`（PR-3B 事务预状态，`VERSION = 0.4.0`）。
分支：`codex/incident-classifier-p4a-033`。
交付物：`monitor-v2/web/incident_classifier.py`（纯 stdlib、1151 行）
+ `tests/monitor-classify/classify_groups.py`（七组行为判别器）
+ 两份提交进仓的 fixture + 新车道 `tests/test-monitor-v2-classify.sh`
（`EXPECTED_PASS=582`）。
前序文档：`docs/monitor-v2-incident-history-p1.md`（历史库与禁持久化清单）、
`docs/monitor-v2-journal-reader-p2a.md`（journal 闭合枚举）、
`docs/monitor-v2-network-probes-p3a.md` / `-p3b.md`（探测引擎与入库边界）。

## 1. 结论性摘要

PR-1 到 PR-3B 解决的是"证据留不留得住"。PR-4A 是第一个**读**这些证据并给出
答案的阶段：一次调用、一个有界证据包、一个闭合类型化结论。它刻意**不接线**
——没有任何运行时模块导入它，没有新端点、没有 schema 变更、没有 UI、没有
systemd/scheduler/deploy 改动，`VERSION` 与 `MONITOR_WEB_VERSION` 仍是
`0.4.0`。一个只改变"能回答什么"、不改变任何行为的阶段，才可能只凭逻辑被评审。

分类词表**冻结**为七项（§4）：`vps_process_or_api` / `vps_outbound` /
`reality_tcp_path` / `hysteria2_udp_path` / `common_inbound_client_office` /
`destination_specific` / `insufficient_evidence`，外加一个只用于非事件结果的
`NONE` 哨兵。所有结果**同时**携带闭合的 `evidence` 与 `unknowns`：分类器说
"证据指向哪里"，永远不说"为什么"。

第三轮把"证据指向哪里"这句话收紧成可检查的纪律，八条反例逐条入门（§4、§5）：
目的地身份在 v3 里不存在，因此 `destination_specific` 保留词汇但结构性不可达；
`health.degraded` 只描述证据平面，不再产生进程类事件；探测失败码区分"网络
拒绝"与"证人缺席"，后者不能证明 VPS 出口；只有探测平面的 outage 因端点共因而
拒绝；连接数下降按传输各自的计数读成影响位；`common_inbound_client_office`
要求同期双传输影响 **加** 同期出口/API 健康的正面反证；所有反面健康度按异常
**簇**而非窗口计算；被安静桶隔开的两个簇一律 fail closed。

第四轮按复审改的是**三条语义**，不扩范围：`device_protocol_states` 的真实键是
`(device, inbound, epoch)`，因此"一台机器一个数字"的读法会把遍历顺序当成证据；
本轮改成按 `(device, inbound)` 折叠、epoch 相同取较大计数、并要求窗口内出现过的
每个配对都在本桶**答过** 0 才叫安静——同时把 `all_devices_quiet` **降级为纯上下文
证据**，不再允许它设置影响位，并新增 `device_states_are_change_only` 点名这张表的
change/heartbeat 局限（unknown 词汇因此 27 → 28）；`tls_failed` 与 `protocol_failed`
从"网络拒绝"移到"证人缺席"一侧，期望值由引擎自己的映射函数给出；
`egress_ip_changed` 不再是探测平面独证的 corroboration 证人。§6.1 记录这三条在本轮
最终树上的换回实测（36 红 / 629 绿）与 11 个单规则 mutation 实测。

## 2. 输入契约：只有 v3 真实存在的投影

分类器接受的记录形状**逐列**取自当前 `SCHEMA_VERSION = 3` 的持久化投影：

| 段 | 来源 | 列数 |
| --- | --- | --- |
| `samples` | `timeline_samples` | 19 |
| `device_states` | `device_protocol_states` | 12 |
| `probe_rows` | `network_probe_samples` | 19 |
| `journal_events` | `journal_events` | 8 |
| `audit` | `journal_ingest_audit` | 4 |
| `window` / `health` / `reader` | 三个闭合标量对象 | 2 / 3 / 1 |

- **不假设任何不存在的表。**没有 per-edge 表、没有 Reality-target 表、没有
  net-counter 表——车道用**真实 SQLite**（`IncidentHistory.open()` + 写样本 +
  写探测 + journal 交换目录摄取）把八张表建出来，再用 `PRAGMA table_info`
  逐列比对镜像；镜像漂移是红灯，不是注释。
- **接收列 ⊆ 持久化列**：`SAMPLE_FIELDS` 等五张"读取清单"是白名单，任何不在
  清单里的键（`iso_utc`、`run_id`、`egress_ip`、`fp`、`cycle_id`、
  `snapshot_generated_at`、`last_success_at`）即便出现在输入里也**永不进入
  判定表达式**；这一条既是运行期表（privacy 组），也是 AST 结构门。清单里唯一
  带身份姓名的两项是 `device` 与 `inbound`，两者都**只当不透明计数键**使用
  （按 `(device, inbound)` 配对折叠），永不进入结果面——harness 的 leak probe
  直接把一个真实入口名 `vless-in` 塞进每一行输入，要求它一次都不出现在输出里。
- **词汇镜像**：journal 的 `cls/proto/dcls`、审计 `kind/code`、探测
  `status/error_code/egress_change`、history 的 11 个 `CODE_*`、reader 的六种
  状态、API 的 `CONNECTED/STALE`、device 的 `change/heartbeat`，全部镜像自
  `web/incident_history.py` 与 `diagnostics/network_probes.py`，由 mirrors 组
  断言**恰等**。
- **有界**：窗口必须 60 秒对齐、≤ `MAX_BUCKETS=60` 个桶（一小时），每段
  ≤ `MAX_RECORDS_PER_SECTION=2000` 行（对齐 `QUERY_LIMIT_MAX`）。窗口不可用时
  只拒窗口——行本身没有畸形，只是**无法度量**。

## 3. 输出契约：闭合、确定、不抛异常

`Classification` 是 frozen dataclass，字段恰为
`version, status, category, window_start, window_end, buckets, evidence,
unknowns`——没有能放句子、地址或设备名的位置（车道 S0/S1 与 harness 各自钉
一次，改宽要同时改两个由不同人手写的文件）。

- `evidence` 45 个 token、`unknowns` 28 个 token，两平面**互斥**，全部是小写
  snake_case；词汇字面量同时写在场道 shell 文件里（§7）。
- 两个 tuple 排序去重；输入打乱顺序、并发调用、重复调用**逐字节等值**
  （invariants 组：8 线程 + 400 轮随机 fuzz，fuzz 只允许产生白名单 token）。
- 永不抛异常：非 dict、空 dict、NaN epoch、越窗行、超量段、自由文本 `cls`、
  只读字段被消费……一律结算为 `indeterminate` / `insufficient_evidence` 加
  闭合拒绝 token。
- `CLASSIFIER_VERSION = 1` 随结果输出，供未来接线方判定读的是哪一版权约。
- 可输出类别是 `EMITTABLE_CATEGORIES`（六项）。第七项 `destination_specific`
  仍留在冻结词汇表里——缺口要说清而不是遗忘——但 `_seal()` 结构性拒绝它，
  因此没有任何代码路径能把它送进结果（车道 S1 与 harness 各自钉一次）。

## 4. 判定规则（阈值全部是命名常量）

检测以 60 秒桶进行，前 `MIN_BASELINE_BUCKETS = 3` 个桶只做参考基线，候选桶
只能出现在其后。四个异常族：

| 族 | 触发 | 常量 |
| --- | --- | --- |
| connections | **仅计数列**。某类计数均值 ≤ 基线 ×(1−`COUNT_DROP_RATIO`)，且基线 ≥ `COUNT_DROP_MIN_BASELINE`，绝对降幅 ≥ `COUNT_DROP_MIN_ABSOLUTE` | 0.5 / 5.0 / 3.0 |
| （非族）device | `device_protocol_states` 的真实键是 `(device, inbound, epoch)`，因此一台机器**每个入口各有一行**且两行同时成立：`vmix-01/vless-in=0` 与 `vmix-01/hy2-in=3` 是一台机器的两个事实，谁也不覆盖谁。桶内按 `(device, inbound)` 折叠，**epoch 大的赢**，epoch 相同的**取计数较大的一行**（同一时刻两行互相矛盾时，"这个配对空了"是否不了的负命题）；判定"全安静"要求窗口里出现过的**每一个**配对都在本桶**答过**且为 0，并且配对数 ≥ `ALL_DEVICES_QUIET_MIN`。这张表是 **change/heartbeat 稀疏日志**而不是快照——某配对本桶没有行只意味着"没上报"，绝不折算成"上报了 0"。结论只命名 evidence `all_devices_quiet` 并加 `device_states_are_change_only`，**永不**设置任何影响位 | 2 |
| journal | 某 `(cls, proto, dcls, port)` 键在桶内 `n` 之和 ≥ max(`JOURNAL_BURST_MIN_COUNT`, `JOURNAL_BURST_MULTIPLIER` × 该键基线中位数) | 5 / 3.0 |
| probe | 某 slot **因网络而**连续 ≥ `PROBE_FAIL_MIN_BUCKETS` 个桶失败（防抖：单周期失败只是 blip）。只有 `PROBE_NETWORK_CODES = timeout / dns_failed / connect_failed` 算"引擎抵达了网络并被拒绝" | 2 |
| （非族）probe | `PROBE_SOURCE_CODES = bad_response / parse_failed / unavailable / tls_failed / protocol_failed` 是**证人缺席**而不是故障：端点拒答/无法解析、未启用的 DARK 状态，以及**探测程序自己无法裁决对端**的三类形状——`tls_failed` 是引擎捕获的任意 `ssl.SSLError`（含证书校验失败，这既可能是对端 TLS 配置，也可能是本地信任链/时间），`protocol_failed` 是 HTTP 协议异常、UDP 应答短于 12 字节、或 transaction-id/DNS question 对不上。它们都不证明"路径断了"，因此一律放在缺席一侧；mirrors 组直接调用**引擎自己的** `_classify_client_error` / `_udp_classify_reply` 证明这一点，而不是引用本文档的措辞。不进入任何族、不参与 corroboration，只命名 `probe_source_unavailable` + `probe_evidence_unusable`；缺席不需要防抖，一个桶就足以说明该时刻无法作证 | — |
| process | 桶内 `api_status=STALE` 或 `collector_stale` 占比 ≥ `API_STALE_BUCKET_FRACTION`；或样本数 < `MIN_SAMPLES_PER_BUCKET`（覆盖缺口） | 0.5 / 6 |

`health.degraded` **不是**一个族。它描述的是 diagnostics 自身证据平面的质量，
因此只作为 evidence 命名（`history_degraded`），永远不产生
`vps_process_or_api`，也不参与 corroboration——"我的记录面降级了"既不证明
客户受影响，也不证明客户没受影响。

样本数不足的桶**只**说明 Monitor 当时没在发布（process 信号），绝不推断为
"客户端掉零"。整个窗口一行样本都没有时，不伪造覆盖缺口——那是调用方没给证据。

**簇（cluster）**是极大相邻异常桶串，间隔判据是
`CLUSTER_ADJACENCY_BUCKETS = 1`。凡"需要反面证据"的结论，其健康度只按**簇内**
桶计算（见 G5、G8）：基线时段的健康不能替事故时段作证。

** corroboration 门（规格明令）**：只有 connections 族动过、journal/probe/
process 三族一致沉默时，结果是 `no_incident` + `count_drop_only` +
`no_corroboration`。背景噪声（`eof_cancel` / `reset` 的日常流量）不构成突发，
normal-background 对照夹具因此保持非事件。

## 5. 归因规则与 fail-closed 门

归因先把异常桶折叠成**事实位**，再按**唯一一条**顺序落到类别。事实位分两类，
刻意不混用：

- **故障位**（谁在坏）：`reality` / `hy2`（journal 突发）、`generic_journal`
  （`OTHER` 协议落在 `https443`/`http80`）、`generic_probe`（dns/https/egress
  因网络而失败）、`process`、`destination`（`(dcls, port)` 签名集合）、
  `unattributed`。
- **影响位**（谁的客户端少了）：`reality_impact`、`hy2_impact`。二者**只**从
  各自传输自己的计数列（`hysteria2_connections` / Reality 侧计数）得出。
  **设备表不是影响位的来源**：`device_protocol_states` 是 change/heartbeat
  日志，"全安静"既可能是两条传输都丢了客户，也可能只是采集侧没上报，而分类器
  没有第三种手段区分这两件事——因此它只作为 evidence 命名，加上
  `device_states_are_change_only`，绝不参与 `common_inbound_client_office`。
  `total` 是分项之和，
  Reality 单独塌方必然拖着 `total` 一起下降，因此 `count_drop_total`
  **绝不**算 HY2 的影响——那会把一条路径的中断写成"另一条路径也丢了客户"。

| # | 条件 | 结果 |
| --- | --- | --- |
| G1 | `process` 与任一网络位同时成立 | `incident` + `insufficient_evidence` + `process_and_network_evidence_conflict`（两个独立平面各自都在坏，点名任一个都是越证） |
| G2 | 仅 `process` | `vps_process_or_api` |
| G3 | 存在目标级签名 | 命名 `journal_burst_destination` 后**放下**：v3 只把目的地投影成 `(dcls, port)`——一个类别加一个端口，不是身份——因此加 `no_target_specific_proof`（多签名再加 `multiple_destinations`）。`destination_specific` 在词汇表里但**不可达**：`_seal()` 只承认 `EMITTABLE_CATEGORIES`（七类去掉它本身），所以后来的编辑也无法意外把它输出 |
| G4 | `generic_journal` 或 `generic_probe` | 比任何单一传输更宽的证据存在时抬升为 `vps_outbound`。**但**只有探测平面作证时（`generic_probe` 且无 `generic_journal`），必须另有**另一个平面**的同期证人（reality/hy2 journal 突发、或某传输自己的计数影响位），否则 `probe_endpoint_confounded` + `insufficient_evidence`：dns 与 https 都指向 Cloudflare 叶子、egress 指向 ipify，所以"三个通用槽一起失败"与"单个端点 outage"是同一形状。**`egress_ip_changed` 已从证人名单里删除**：它不是独立平面，它和失败行同出自 `ProbeScheduler` 的同一批行；而且 `changed` 恰恰意味着 ipify 探测**成功拿到了**公网 IP——用被质疑平面自己的一次成功去替它的失败作证，是循环论证。该 token 仍作为 evidence 命名（"网络上下文变了"是事实），只是不再具备 corroboration 资格。同簇内 `timeout`/`dns_failed`/`connect_failed` 这类无歧义网络失败加上一个 journal/影响证人仍会正常抬升 |
| G5 | 双传输影响位，或 `reality` 且 `hy2` | 命名共享入口面 `common_inbound_client_office` 需要**两重同期正面反证**：(a) 同一批簇内桶上两条传输**各自**的客户端都在掉（只有突发没有双影响 → `attribution_ambiguous`）；(b) 同一批桶上 VPS 自身 generic TCP 探测健康 **且** API 视图确实在应答（缺任一项 → `contemporaneous_negatives_unproven`）。基线时段的健康一律不算反证 |
| G6 | `reality` 且非 `hy2` | `reality_tcp_path`（受 G8 约束） |
| G7 | `hy2` 且非 `reality` | `hysteria2_udp_path`（受 G8 约束）；两者皆真却不同时构成影响 → 回到 G5 的拒绝 |
| G8 | 任何"依赖反面证据"的结论，必须先证明反面：journal 视图**完整**（reader `fresh` 且窗口内无 gap/被拒批次）**或** generic TCP 探测在**该簇内**健康（≥ `PROBE_HEALTH_MIN_BUCKETS` 桶三槽皆 `ok` 且既无网络失败也无缺席）。否则 `insufficient_evidence` + `transport_negatives_unproven`；探测平面整段缺席另记 `probe_evidence_absent` | "我看不了" ≠ "我看了没有" |
| G9 | 目标级签名永远不够：无论它在**几个**桶出现、有几个签名，都记 `no_target_specific_proof`（签名多于一个再加 `multiple_destinations`）；若没有其它网络位，整窗 `insufficient_evidence` | 旧的"同一签名跨 ≥ 2 桶复现即可点名"门槛已随 G3 的不可达一起删除——一个永远无法输出结论的门是装饰，不是纪律 |
| G10 | `udp` 探测失败**不**映射为 `hysteria2_udp_path`：引擎的 udp 槽是应用层 DNS 往返，不是 HY2 数据面。它作为 probe 族参与 corroboration，但归因落到 `insufficient_evidence` + `attribution_ambiguous` | 协议同名不等于证据同义 |
| G11 | 异常桶串被安静桶隔开，即**两个簇** | 折叠成一个结论必然把第二段事件的证据接到第一段事件的归因上，因此整窗拒绝：`_collect()` 仍然把看到的都命名出来，再加 `multiple_anomaly_clusters`；相邻（间隔 0）的串是一个事件，不触发本条 |
| G12 | 结果里存在无法安放于任何位的 journal 突发 | 仍命名 `journal_burst_unattributed` + `unattributed_evidence_present`：正结论不冒充完整理解 |

G1–G5 的顺序就是 fail-closed 的顺序：任何一条拒绝路径都会先把自己看到的
evidence 记完再返回，所以"没结论"永远不等于"没内容"。

每个 `incident` 无条件盖上 `root_cause_not_established`。分类器不产生自由文本、
不做 ISP 推断、不把相关性写成因果——这是 `_seal()` 的闭合墙，不是调用纪律。

## 6. 夹具与判别器

提交进仓的两份 fixture 是**决策表输入**本身（`matches_generated_bundle` 把
文件字节与生成结果比对，漂移即红灯；harness 无写权限，S3 末尾还有一次
"整轮跑完后夹具逐字节未变"的证明）：

- `tests/monitor-classify/fixtures/incident-reality-outage.json` ——
  2026-09-22 形状：443 上 Reality 拨号超时突发、HY2 客户端在线、VPS 自身
  出口健康。→ `incident` / `reality_tcp_path`。
- `tests/monitor-classify/fixtures/incident-normal-background.json` ——
  同一批背景噪声、没有任何东西掉。→ `no_incident` / `NONE`。

场道 S2 另外把 Reality 夹具**改四处**并要求四个不同的具名答案，以证明分类器
读的是内容而不是文件名：Reality↔Hysteria2 全量互换 → `hysteria2_udp_path`；
删掉 journal 突发 → `no_incident` + `count_drop_only`；补上 `OTHER`/`https443`
突发 → 升级 `vps_outbound`；把反面证据的可证性抽掉（reader `unreadable` +
无探测行）→ `insufficient_evidence` + `transport_negatives_unproven`。

`scenarios()` 共 43 个场景、419 条断言，覆盖上表每一格（含 G1 冲突、G5 的
两重同期反证、G8 两态、G9 三态、G10 udp、G11 两簇与"相邻即一簇"的正向对照、
覆盖缺口、历史降级、空包、短窗）；`HOSTILES` 19 条畸形输入逐一要求
**恰等**的拒绝 token 集合。

第三轮的每一条反例都配了**判别器**，而且是成对的：反例要求 fail closed，
同时给出同期独立证人齐全的对照，证明新门不是"什么都拒绝"。
`probe_outage_without_clients`（三个通用槽一起失败、没有任何客户受影响）
要求 `probe_endpoint_confounded`；两条真正的对照——客户端真的在掉、
`OTHER`/`https443` journal 突发——各自仍要求 `vps_outbound`。第三轮当时还把
"簇内 `egress_ip` 变更"列为第三条对照，第四轮已把它**改写成反例**（见下）。

判别器的效力不靠声明，而且这两组实测都在**本轮最终模块**上重跑过（清掉本轮
自己引入、却无人读取的 per-bucket `unusable` 标记之后重测；此前的数字作废）。

**换回修改前的模块**（只换 `incident_classifier.py`，夹具、harness、车道都不动）
在 `5962ebd` 实测 **33 条红 / 475 条绿**，其中 2 条是 harness 直接崩在
`EMITTABLE_CATEGORIES` 不存在上（那本身就是 R1 的证据），余下 31 条按本轮八条
语义逐一落位：R1 `destination_proof` 2、R2 `history_degraded` 3 +
`degraded_over_real_incident` 2、R3 `probe_unavailable_is_not_a_fault` 7 +
`probe_endpoint_answers_badly` 6、R4 `probe_outage_without_clients` 2、
R5 `common_inbound_needs_dual_impact` 2、R6 `common_inbound_api_unproven` 2、
R7 `common_inbound_baseline_health_cannot_vouch` 3、R8
`two_clusters_fail_closed` 2——八条语义每条都至少有一条判据在换回旧模块后变红。
`reality_impact_is_not_shared` / `hy2_impact_is_not_shared` 两格**不在**红名单里，
这是如实记录而不是遗漏：旧模块对这两个夹具恰好也给出同样答案，所以它们是
**防回归的守卫**，其判别力由下面的 R5 mutation 证明（旧行为一旦回来即红）。

**反过来只破坏一条规则**（8 个 mutation：加宽 `_seal` 墙、把任何 `failed` 当网络
事实、摘掉端点混淆门、把 `total` 当双传输影响、取消同期反证、把健康度按窗口而非
簇统计、按基线替 API 视图作证、折叠两簇）逐个实测，红数依次是
**2 / 14 / 3 / 16 / 5 / 4 / 3 / 3**，且每个 mutation 跑完后模块还原、整轮重测仍
546/0。红名单里除该规则自己的具名判据外，只会多带 `invariants` 的
`verdicts_survive_shuffling`（乱序等值 witness，任何判据变动它都该红）；R5 额外
红在 `fixtures/reality_outage:classifies_as_expected` 上——把 `total` 当成双传输
影响会直接改写**提交进仓的 Reality 夹具**的答案，这正是该规则禁止的事。
`health.degraded` 那一格由换回模块的实测覆盖，故不重复列入 mutation 清单。

### 6.1 第四轮的三条语义：同一套实测协议重跑

第三轮的两组数字是第三轮最终树（`5962ebd`）的证物，按评审要求**原样保留**；
本轮为新的三条语义在同一协议下另测一遍，数字属于本轮最终树。

**换回修改前的模块**（只把 `incident_classifier.py` 换成第三轮提交在 HEAD 的
字节，夹具、harness、车道都不动）在 665 条车道检查上实测
**36 条红 / 629 条绿**——其中 26 条是 harness 自己的判据，10 条是车道独立钉住
的字面量与 S2 夹具门（"两份不同人手写的文件要同时被破坏才算改契约"在这里生效）。
36 条按本轮三条语义逐一落位：

- **R4-A 设备表**（14 条）：四扇设备窗口各 2 条
  （`device_pairs_are_read_per_inbound`、
  `device_pairs_silent_in_the_bucket_are_not_quiet`、
  `device_rows_that_disagree_answer_not_quiet`、
  `device_quiet_is_evidence_not_dual_impact`——每扇红的都是 `category` 加它自己的
  那条具名 evidence/unknown 判据）、`privacy/device_column_is_counting_only`，加
  车道侧的 `vocab/identity_bearing_names_are_a_closed_tuple`、
  `vocab/unknown_tokens_are_the_pinned_twenty_eight` 与三条具名夹具门。
  其中"一台机器两个入口""同一桶里没答过的配对""同一时刻互相矛盾的三行"
  三种材料旧模块全部答成 `incident common_inbound_client_office` ——评审点名的
  那条越证路径（设备表安静 → 双影响位 → 共享入口结论）被**提交进仓的夹具**
  复现，不是文字推演。
- **R4-B 探测失败码**（17 条）：`probe_tls_failed_is_not_a_network_fault` 6、
  `probe_protocol_failed_is_not_a_network_fault` 6、`mirrors/engine_probe_codes_agree`、
  `mirrors/source_codes_are_not_network_codes`，加车道侧
  `vocab/probe_failure_codes_are_split_by_what_they_prove` 与两条 generic-slot
  夹具门。前两条 mirrors 判据是调用**引擎自己的** `_classify_client_error` /
  `_udp_classify_reply` 得出期望值，所以它红在"分类器和引擎不一致"上，而不是红在
  本文档的措辞上。
- **TIGHTEN 出口变更**（3 条）：`probe_outage_with_egress_change_only` 的
  `category` 与 `unknown:probe_endpoint_confounded`，加车道侧那条具名门。旧模块
  只凭 ipify 行自报的 `changed` 就把探测平面独证抬成 `vps_outbound`。
- 其余 2 条是共犯与汇总，不属于任何单条规则：
  `invariants/verdicts_survive_shuffling`（乱序等值 witness，任何判据变动它都该
  红），以及车道的 `classify_groups.py exited rc=1` 汇总门。

一处**读取注意事项**：本车道 S2 的 `assert_eq` 按仓库既有写法把钉住的字面量放在
第一个实参位，而 helper 的消息模板把第二个实参标为 `want`，所以**失败消息里的
`want` 打印的是被测模块的实际输出**、`got` 打印的是期望字面量。上面"旧模块答成
`common_inbound_client_office`"读的就是那个 `want` 字段。这不改变任何判定（等值
比较对称），只影响日志的措辞，本轮按"不扩大 scope"原则未改动 helper。

**反过来只破坏一条规则**（11 个 mutation，逐个把一轮最终树的模块改坏再跑 harness；
每个 mutation 都从冻结的干净副本重新生成，因此不会叠加上一个的破坏，扫描结束时
按字节校验还原 `RESTORED_EXACT=True`，扫描后的整轮重测仍是 621/0 与 665/0——如实
区分"每次跑完各自还原并重测"与"每个 mutation 从冻结副本重建、末尾统一字节校验"，
这里成立的是后者），红数依次是：

| # | 破坏的规则 | 红 |
| --- | --- | --- |
| M1 | 安静设备表重新获得双影响位 | 2 |
| M2 | 折叠键丢掉 `inbound`（退化成按设备一行） | 1 |
| M3 | 本桶没答过的配对被当成"报了 0" | 1 |
| M4 | 同一 epoch 的矛盾行**后写的赢** | 1 |
| M5 | 同一 epoch 的矛盾行**先写的赢** | 1 |
| M6 | 安静不再点名 change/heartbeat 局限（撤 `device_states_are_change_only`） | 1 |
| M7 | `protocol_failed` 回到网络事实一侧 | 9 |
| M8 | `tls_failed` 回到网络事实一侧 | 9 |
| M9 | `egress_ip` 变更重新充当 corroboration 证人 | 3 |
| M10 | 窗口配对集合按设备收集（`seen` 与它永不大小相等） | 2 |
| M11 | "全安静"不再要求最少配对数（地板撤成 0） | 3 |

M4/M5 是刻意成对的：读取顺序由存储侧决定、分类器无权假设，所以"后写的赢"和
"先写的赢"必须各有一条自己的判据（分别是 `device_rows_that_disagree_answer_not_quiet`
与其反向读入的 `device_rows_that_disagree_in_reverse_answer_not_quiet`）——只钉一个
方向时另一个方向的错误聚合会静默通过。如实记录一处：**反向那一格在"换回旧模块"的
实测里不红**（旧模块对 `(0, 3)` 顺序恰好也答"不安静"），因此它是 M5 的判据而不是
revert 的判据；正向那格同时承担两者。车道 S2 另按 `3,0` 与 `0,3` 两种到达顺序各钉
了一条夹具门，与 harness 分属两个由不同人手写的文件。M10/M11 则从相反方向证明 `seen == pairs_known`
与 `ALL_DEVICES_QUIET_MIN` 两项都是**承重**的：把它们改成"永远不安静"或"一个配对
就算安静"都会红，前者红在 `device_quiet_is_evidence_not_dual_impact` 的正向 evidence
与 unknown 判据上，后者红在空设备表场景（`empty_bundle`）上。M7/M8/M9 的红名单里除
各自的具名场景判据外，都带 `verdicts_survive_shuffling`（同上的共犯性质）与 mirrors
两条；M1/M9 各多带它自己改写结论时必然触碰的夹具/场景判据。

**一处措辞审计（第四轮本身发现，如实回写）**：本轮逐条复核自己的工具日志时发现，第六节记录的那句"每个 mutation 跑完后模块还原、整轮重测仍 546/0"**超出了日志能支撑的粒度**：实际协议是"每个 mutation 从冻结的干净副本重新生成、扫描结束时按字节校验还原、扫描后整轮重测"，而不是"每个 mutation 各自重测一整轮"。本轮的同一句话已按这个粒度改写。第三轮的工具脚本未保存到现在，因此那一段的**数字**（33 红/475 绿、八个 mutation 的 2/14/3/16/5/4/3/3）不变，但"逐条重测整轮"的**粒度**按本轮审计降格为"未再核实"，在此标注而不是静默改写。

## 7. 车道与门计数

`tests/test-monitor-v2-classify.sh`，`EXPECTED_PASS=665`：
（665 是**本轮最终树**的车道硬计数；上面第六节里的 546/0 与 582 属于第三轮最终树（`5962ebd`），两组数字各自有效、**不可互换引用**。）

- S0 静态 + DARK 门 13：`py_compile`；AST 证明 import 集合恰为
  `{__future__, dataclasses}`、无 I/O/时钟/反射/输出调用点；`grep` 证明
  `monitor-v2/` 下**没有**任何 `.py` 导入本模块、server/webapp/history/
  collector/deploy 零引用、文件内无 SQL 关键字；`VERSION` 与
  `MONITOR_WEB_VERSION` 仍 `0.4.0`；**真实建库**证明八张 v3 表恰等且没有新表；
  结果面字段清单冻结；CI 注册；两份夹具非空且非玩具。
- S1 词汇字面量钉死 12：七类、三态、45/28 token、**`_seal` 只承认的六类**、
  探测失败码的 network/source 切分（本轮把 `tls_failed`/`protocol_failed`
  挪过墙，这条字面量因此是本轮语义在场道里的独立证物）、两平面互斥、token 语法、
  结果面闭合、恒等列清单（本轮加入 `inbound`，并断言清单里除 `device`/`inbound`
  这两个不透明计数键之外没有任何身份列进入读取清单）。
- S2 夹具决定且会动 17：锚点、负对照、三跑+乱序等值哈希、四条变异、哨兵不回声、
  垃圾输入不抛（第三轮的 9 条**一条没动**——锚点与四条变异仍给出同一批具名答案，
  这正是"加固了拒绝路径而没有移动结论"的证据），本轮 +8：真安静设备表只当上下文、
  一台机器的另一个入口有客户端就必须"不安静"、同一批行反着遍历必须同答案、
  同一 `(device, inbound)` 在**一个 epoch** 上 3/0 与 0/3 两种到达顺序各一条、
  `tls_failed` 与 `protocol_failed` 各一条、以及只有出口地址变更这一"额外证人"的
  探测 outage。
- S3 行为组 623：mirrors 24、scenarios 419（43 行）、hostiles 116、invariants 16、
  privacy 7、store 25、fixtures 14，外加 harness rc 与夹具未变证明。

433→582 的差额全部是**新写的门**：S1 +2（emittable 六类、探测码切分），
S3 scenarios +143（23→36 行，每条反例及其对照），mirrors +3，invariants +1
（`_seal()` 自身拒绝不可达类别）。582→665 的 +83 同样是写出来的门而不是放宽：
S2 +8（§6.1 列出的八条本轮判别器）、S3 +75（scenarios 344→419：36 行变 43 行，
5 行设备表窗口加 2 行挪动的探测码，每行带自己的判据），S1 的两条字面量在条数上
不变、在内容上移动。这 83 里有 **+11 是本轮末尾补上的**：mutation 实测发现 tie
规则只钉了一个到达方向（"先写的赢"那种聚合能静默通过整轮），于是补了反向场景的
9 条判据与 S2 的 2 条夹具门。没有一格是为了绿灯被放宽的。

本车道纯 Python、无网络、无特权、无 Linux-only 断言，因此开发机与 Linux CI
**必须**给出同一计数；665 是这一命题的证物。

这一等价性要求车道**不读取任何环境供给的变量**。首轮 CI 就是在这一点上红的：
车道使用 `$TMP` 作为暂存目录，却依赖宿主把 `TMP` 导出给它——开发机（Git Bash）
恰好导出，Linux runner 不导出，于是 `set -u` 在 S0 的 `py_compile`、S1 的词汇
探针和 S3 的行为组三处直接中止，而**分类器本身一行未变**。修法与全仓 45 个
车道一致：`TMP="$(mktemp -d)"` 自建、`trap` 自清。同时把这条约束变成静态门：
`tests.yml` 的 fast-checks 新增
"Shell-suite scratch-directory hygiene gate"，任何读取 `$TMP` 却没有用
`mktemp` 自建的车道都会在被执行之前红在 fast-checks 上。该门对修复前的本车道
判红、对当前全仓判绿，因此它是约束而不是装饰。

## 8. 已知边界（PR-4B 的前置条件，不是缺陷清单）

- 分类器**不被调用**：把 `Classification` 变成端点、时间线标注或 UI 徽章属于
  Phase 4B，且必须先解决"谁在什么窗口上调用、结果存到哪、如何避免把推断
  固化成历史事实"。
- 单次调用只看一个有界窗口，没有跨调用状态：它不会"发现"事件开始/结束的
  时刻，只能判定给定窗口内证据指向何处。持续性属于接线方。
- 没有 per-edge / Reality-target / net-counter 证据，目的地只能以
  `(dcls, port)` 签名被**命名**，`destination_specific` 因此不可输出；要真的
  指向一个目标，需要新的 schema 与新的采集面，而不是新的阈值。
- 探测平面的三个通用槽不是三个独立证人（dns/https 同指 Cloudflare，egress 指
  ipify）。在能区分"端点 outage"与"VPS 出口 outage"之前，只有探测证据的窗口
  一律 `probe_endpoint_confounded`；要拆开需要多目标探测，属于 PR-3 侧的采集面
  扩展，不是分类器可以在本轮补上的推理。同一批探测行内部的 `egress_change`
  **不能**替该平面作证：它出自同一个 `ProbeScheduler`，而且 `changed` 是一次
  **成功**应答——被质疑平面自己的成功不是独立证人（本轮已把这条从 G4 删除）。
- 两个簇的窗口一律拒绝（`multiple_anomaly_clusters`）。逐簇分别给出结论需要
  结果对象从"一个窗口一个判定"变成"一个窗口多个判定"，那是 §3 冻结的结果面，
  本轮不放宽。
- `device_protocol_states` 是 **change/heartbeat 稀疏日志**，不是快照：一个配对
  在某桶没有行只说明"没上报"。分类器因此**只**把它当上下文证据
  （`all_devices_quiet` + `device_states_are_change_only`），不再允许它设置任何
  影响位；跨桶 carry-forward 因此也不再影响任何结论——没有任何结论依赖它。要
  让设备面参与 `common_inbound_client_office` 的归因，需要采集侧改成周期性
  全量快照（或显式上报"该入口无连接"事件），那是新的采集面而不是新的阈值。
  该类别现在**只**由两条传输各自的计数影响位加 §5 G5 的两重同期反证得出，
  因而始终是"共享入口面"的结论，不是某台客户端的归因。
- 阈值是针对本部署节奏（5 s 样本 / 60 s 探测 / 10 s journal 摄取）手工冻结的
  常量，不是自适应统计；改变节奏必须同步复审 §4 全表。
