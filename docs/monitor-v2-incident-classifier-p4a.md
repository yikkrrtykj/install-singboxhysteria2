# Monitor 0.4.x —— PR-4A 确定性事件分类器（issue #33 Phase 4，DARK）

状态：**DRAFT PR，未合并、未部署**。
基线：`main @ 965751c`（PR-3B 事务预状态，`VERSION = 0.4.0`）。
分支：`codex/incident-classifier-p4a-033`。
交付物：`monitor-v2/web/incident_classifier.py`（纯 stdlib、993 行）
+ `tests/monitor-classify/classify_groups.py`（七组行为判别器）
+ 两份提交进仓的 fixture + 新车道 `tests/test-monitor-v2-classify.sh`
（`EXPECTED_PASS=433`）。
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
  清单里的键（`iso_utc`、`run_id`、`device`、`egress_ip`、`fp`、`cycle_id`、
  `snapshot_generated_at`、`last_success_at`）即便出现在输入里也**永不进入
  判定表达式**；这一条既是运行期表（privacy 组），也是 AST 结构门。
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

- `evidence` 44 个 token、`unknowns` 23 个 token，两平面**互斥**，全部是小写
  snake_case；词汇字面量同时写在场道 shell 文件里（§7）。
- 两个 tuple 排序去重；输入打乱顺序、并发调用、重复调用**逐字节等值**
  （invariants 组：8 线程 + 400 轮随机 fuzz，fuzz 只允许产生白名单 token）。
- 永不抛异常：非 dict、空 dict、NaN epoch、越窗行、超量段、自由文本 `cls`、
  只读字段被消费……一律结算为 `indeterminate` / `insufficient_evidence` 加
  闭合拒绝 token。
- `CLASSIFIER_VERSION = 1` 随结果输出，供未来接线方判定读的是哪一版权约。

## 4. 判定规则（阈值全部是命名常量）

检测以 60 秒桶进行，前 `MIN_BASELINE_BUCKETS = 3` 个桶只做参考基线，候选桶
只能出现在其后。四个异常族：

| 族 | 触发 | 常量 |
| --- | --- | --- |
| connections | 某类计数均值 ≤ 基线 ×(1−`COUNT_DROP_RATIO`)，且基线 ≥ `COUNT_DROP_MIN_BASELINE`，绝对降幅 ≥ `COUNT_DROP_MIN_ABSOLUTE` | 0.5 / 5.0 / 3.0 |
| connections | 桶内 ≥ `ALL_DEVICES_QUIET_MIN` 台设备且全部为 0 | 2 |
| journal | 某 `(cls, proto, dcls, port)` 键在桶内 `n` 之和 ≥ max(`JOURNAL_BURST_MIN_COUNT`, `JOURNAL_BURST_MULTIPLIER` × 该键基线中位数) | 5 / 3.0 |
| probe | 某 slot 连续 ≥ `PROBE_FAIL_MIN_BUCKETS` 个桶失败（防抖：单周期失败只是 blip） | 2 |
| process | 桶内 `api_status=STALE` 或 `collector_stale` 占比 ≥ `API_STALE_BUCKET_FRACTION`；或样本数 < `MIN_SAMPLES_PER_BUCKET`（覆盖缺口）；或 `health.degraded` | 0.5 / 6 |

样本数不足的桶**只**说明 Monitor 当时没在发布（process 信号），绝不推断为
"客户端掉零"。整个窗口一行样本都没有时，不伪造覆盖缺口——那是调用方没给证据。

** corroboration 门（规格明令）**：只有 connections 族动过、journal/probe/
process 三族一致沉默时，结果是 `no_incident` + `count_drop_only` +
`no_corroboration`。背景噪声（`eof_cancel` / `reset` 的日常流量）不构成突发，
normal-background 对照夹具因此保持非事件。

## 5. 归因规则与 fail-closed 门

归因先折叠成六个事实位（`reality` / `hy2` / `generic` / `process` /
`unattributed` / `destination`），再按**唯一一条**顺序落到类别：

| # | 条件 | 结果 |
| --- | --- | --- |
| G1 | `process` 与任一网络族同时成立 | `incident` + `insufficient_evidence` + `process_and_network_evidence_conflict`（两个独立平面各自都在坏，点名任一个都是越证） |
| G2 | 仅 `process` | `vps_process_or_api` |
| G3 | `generic`（dns/https/egress 任一探测失败，或 `OTHER` 协议在 `https443`/`http80` 上突发） | `vps_outbound`——比任何单一传输更宽的证据存在时，路径结论被抬升 |
| G4 | 只有目标级证据且签名 `(dcls, port)` **唯一**且跨 ≥ `DESTINATION_MIN_BUCKETS` 个桶复现 | `destination_specific`（仍受 G7 约束） |
| G5 | `reality` 且非 `hy2` | `reality_tcp_path`（受 G7 约束） |
| G6 | `hy2` 且非 `reality` → `hysteria2_udp_path`；两者皆真 → `common_inbound_client_office` | 同受 G7 约束 |
| G7 | 上述任何"依赖反面证据"的结论，必须先证明反面：journal 视图**完整**（reader `fresh` 且窗口内无 gap/被拒批次）**或** generic TCP 探测**健康**（≥2 桶三槽全 `ok` 且无失败）。否则 `insufficient_evidence` + `transport_negatives_unproven` | "我看不了" ≠ "我看了没有" |
| G8 | 目标证据只有一个桶出现、或同时出现多个目标签名 | `insufficient_evidence` + `no_target_specific_proof` / `multiple_destinations`——**绝不凭猜测输出** `destination_specific` |
| G9 | `udp` 探测失败**不**映射为 `hysteria2_udp_path`：引擎的 udp 槽是应用层 DNS 往返，不是 HY2 数据面。它作为 probe 族参与 corroboration，但归因落到 `insufficient_evidence` + `attribution_ambiguous` | 协议同名不等于证据同义 |
| G10 | 结果里存在无法安放于任何族的 journal 突发 | 仍命名 `journal_burst_unattributed` + `unattributed_evidence_present`：正结论不冒充完整理解 |

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

`scenarios()` 共 23 个场景、201 条断言，覆盖上表每一格（含 G1 冲突、G8 两态、
G9 udp、覆盖缺口、历史降级、空包、短窗）；`HOSTILES` 19 条畸形输入逐一要求
**恰等**的拒绝 token 集合。

## 7. 车道与门计数

`tests/test-monitor-v2-classify.sh`，`EXPECTED_PASS=433`：

- S0 静态 + DARK 门 13：`py_compile`；AST 证明 import 集合恰为
  `{__future__, dataclasses}`、无 I/O/时钟/反射/输出调用点；`grep` 证明
  `monitor-v2/` 下**没有**任何 `.py` 导入本模块、server/webapp/history/
  collector/deploy 零引用、文件内无 SQL 关键字；`VERSION` 与
  `MONITOR_WEB_VERSION` 仍 `0.4.0`；**真实建库**证明八张 v3 表恰等且没有新表；
  结果面字段清单冻结；CI 注册；两份夹具非空且非玩具。
- S1 词汇字面量钉死 10：七类、三态、44/23 token、两平面互斥、token 语法、
  结果面闭合、恒等列清单。
- S2 夹具决定且会动 9：锚点、负对照、三跑+乱序等值哈希、四条变异、哨兵不回声、
  垃圾输入不抛。
- S3 行为组 401：mirrors 21、scenarios 201、hostiles 116、invariants 15、
  privacy 7、store 25、fixtures 14，外加 harness rc 与夹具未变证明。

本车道纯 Python、无网络、无特权、无 Linux-only 断言，因此开发机与 Linux CI
**必须**给出同一计数；433 是这一命题的证物。

## 8. 已知边界（PR-4B 的前置条件，不是缺陷清单）

- 分类器**不被调用**：把 `Classification` 变成端点、时间线标注或 UI 徽章属于
  Phase 4B，且必须先解决"谁在什么窗口上调用、结果存到哪、如何避免把推断
  固化成历史事实"。
- 单次调用只看一个有界窗口，没有跨调用状态：它不会"发现"事件开始/结束的
  时刻，只能判定给定窗口内证据指向何处。持续性属于接线方。
- 没有 per-edge / Reality-target / net-counter 证据，`destination_specific`
  只能到 `(dcls, port)` 签名粒度；要更细需要新的 schema 与新的采集面。
- 设备维度只用于"是否全部安静"的计数判断，因此
  `common_inbound_client_office` 是一条**共享面**结论，不是某台客户端的归因。
- 阈值是针对本部署节奏（5 s 样本 / 60 s 探测 / 10 s journal 摄取）手工冻结的
  常量，不是自适应统计；改变节奏必须同步复审 §4 全表。
