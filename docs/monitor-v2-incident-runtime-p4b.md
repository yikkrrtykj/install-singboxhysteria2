# Monitor 0.5.0 —— PR-4B 事件运行时 + 判定持久化（issue #33 Phase 4，冻结契约）

状态：**实现前冻结契约**。本文件在写任何功能代码之前写成，是 PR-4B 的
完整规格；实现、判别器测试与 DRAFT PR body 都以本文件为准，实现期间不得
变更契约条款（如需变更必须先改本文件并说明理由）。
**R2 重冻结（review blockers）**：§8/§8.1–§8.3 的“一致 verdict
snapshot”“terminal write 不回读旧行”“`window_limit` → `rearm` 门”、
§5 的 `incident_runtime_state` 两个新列与 CHECK、§7 的 composed bundle
health 是在 owner 复审后重新冻结的条款，**取代**首版的 category 单向拓宽
格；§16 判别器 2/3/5 相应原位改写，并新增 20–30。变更理由：首版把
“历史最具体 category”放在持久化层，会用上一轮归因覆盖当前分类器的
fail-closed 结论，属于跨 generation 拼接字段，语义错误而非计数问题。
**R3 复审修复（本轮，两个状态语义缺陷）**：§5.1 新增“状态行形状闭包”，
取消 R2 读取端 `discovery_floor_epoch IS NULL → 回退 activation_floor_epoch`
的隐式放大（复审 blocker B：不可证明的状态不得等于更宽的历史，DB 与运行时
两侧同时拒绝）；§8.4 新增“`phase` 是从持久 gate 推导的量”，取消 R2 用
“本周期分析了什么/还没评估过任何桶”反推 warmup 的做法（复审 blocker A：
clean close 当轮与 post-clean restart 在第一个周期之前都会误报 `idle`，
分类行为始终正确，错的是状态面）。§16 相应新增判别器 31–34，红证据见
§16.3。两处修复都不改分类规则、不改 schema 版本、不加列；唯一被重写的既有
断言（`close_clears_pointer_and_phase` 的 `phase == "idle"` → `!= "open"`）
在 §15 逐条申报，计数不变。
基线：`origin/main = a180e7dc2def41aeaa246495a8538b3e64f4b8de`（PR-4A
分类器 + PR-3B schema v3，VERSION / MONITOR_WEB_VERSION = 0.4.0，
History SCHEMA_VERSION = 3）。
分支：`codex/incident-runtime-p4b-033`。
上游规格：issue #33 Phase 4；前序文档 `docs/monitor-v2-incident-classifier-p4a.md`
（纯分类器契约）、`docs/monitor-v2-network-probes-p3b.md`（probe 入库 +
部署 prestate 事务）。

## 1. 结论性摘要

- 分类器 `web/incident_classifier.py` 增加**纯元数据出口** `detect()`：
  与 `classify()` 共享同一条 `_analyse` 代码路径，`detect(e).classification`
  与 `classify(e)` 逐字节相等是构造性质而非测试侥幸；检测元数据
  （异常桶位置 / first_signal_epoch / last_signal_epoch）全部从既有
  anomaly/cluster 计算**直接派生**，运行时不存在第二套阈值算法。
- History **schema v4**：恰新增两表 `incident_windows` +
  `incident_runtime_state`；位集（bitset）版本化、DB 上界 CHECK、精确
  往返门；无 JSON1、无身份/IP/UUID/自由文本列。fresh/v1/v2/v3 → v4
  全部单事务、forward-only；回滚 = 精确 v3。
- 新增 `web/incident_runtime.py` / `IncidentScanner`：分类器的**唯一**
  运行时消费者（单消费者静态门取代 PR-4A 的 darkness 门）。闭合错误词表、
  崩溃不外溢：broker / probe scheduler / journal ingest / web server /
  sing-box / sbox-cm 节奏零受影响。
- 生命周期：IDLE 取最近 5 个完整桶（3 基线 + 2 候选）；仅
  `status == "incident"` 开案；`analysis_start` 开案时冻结；同 row 原地
  更新，**更新写入的是“最近一次成功 `detect()` 的一致 verdict snapshot”**
  （category / last_signal / last_classified_end / buckets / evidence_bits /
  unknown_bits 六个字段全部来自同一次分类，持久化层不得跨 generation 拼接，
  也不得用历史最具体 category 覆盖当前分类器的 fail-closed 结论）；3 个
  连续干净桶闭案 `clean_buckets`，闭案由**当轮** terminal `detect()` 结算；
  60 桶上限闭案 `window_limit`，保留最后一次真实分类的 snapshot 并进入
  **`rearm` 门**（自动发现 fail-closed 停止，直到显式 operator re-arm；
  本轮不发明自动恢复分类器，也不加 HTTP/UI）；一个安静桶后的第二簇仍是
  **一个**运维生命周期，不拆行。
- 状态语义（R3）：`incident_runtime_state` 的形状被 DB CHECK 闭合成
  惰性 / 已布防（必有 discovery floor）/ 已解除布防（无 floor、无
  指针）三种，运行时读到不可证明的形状一律 `runtime_state_corrupt`，
  **绝不**回退到更宽的 activation floor；`phase` 是由持久 gate 与网格
  位置**推导**出的读数（§8.4），因此 clean close 的当轮与 post-clean
  warmup 期间的 restart 都不会报出 `idle`。
- reader 负证据连续性：持久化 `reader_fresh_since_epoch`；
  restart/stale/invalid/unreadable/absent 一律打断连续性；之后的 fresh
  **不能**追溯修复更早的 journal 负证据（G8 fail-closed）。
- 可观测面：无 P5 路由、无 UI；既有 timeline 端点只多一个闭合的
  `incident_runtime` 对象（恰 8 键）。
- 部署：复用 PR #60 通用 History prestate 事务（抬 `SCHEMA_VERSION=4`
  即自动触发 v3→v4 prestate），新增 5 条部署判别器。
- 版本钉：`VERSION = 0.5.0`、`MONITOR_WEB_VERSION = 0.5.0`、
  `SCHEMA_VERSION = 4`。

## 2. 冻结版本与冻结常量

| 项 | 值 | 门 |
|----|----|----|
| `monitor-v2/VERSION` | `0.5.0` | hist / classify / packaging / incident-runtime 车道钉住 |
| `MONITOR_WEB_VERSION` | `0.5.0` | 同上 + server.py 文本断言 |
| `SCHEMA_VERSION` | `4` | `_enforce_schema` 严格门 + 迁移阶梯 |
| `CLASSIFIER_VERSION` | `1`（不变） | incident_windows.classifier_version CHECK = 1 |

`web/incident_runtime.py` 模块级冻结常量（评审常量，**不是**配置旋钮；
全模块唯一数字字面量块）：

| 常量 | 值 | 语义 |
|------|----|----|
| `BUCKET_SECONDS` | 60 | 与分类器同值（引用 classifier 导出名，不复写数字） |
| `SCAN_INTERVAL_SECONDS` | 30 | 扫描节拍 |
| `BUCKET_GRACE_SECONDS` | 15 | 桶“完整”判定宽限：now ≥ bucket_end + 15 |
| `DISCOVERY_BUCKETS` | 5 | IDLE 分析最近 5 个完整桶 = 3 基线 + 2 候选 |
| `CLOSE_CLEAN_BUCKETS` | 3 | 3 个连续干净桶闭案 |
| `MAX_ANALYSIS_BUCKETS` | 60 | 分析窗口桶数上限；超出 → `closure_reason=window_limit` |

运行时的全部桶计算必须经由分类器导出名（`BUCKET_SECONDS`、
`MIN_BASELINE_BUCKETS`、`MAX_BUCKETS` 等）；静态 AST 门证明
`incident_runtime.py` 除上述六常量外不存在其他数值阈值。

## 3. 三层架构与单消费者纪律

1. **分类器层**（纯）：`detect(evidence) -> Detection`。纯 stdlib、无时钟、
   无 I/O、无网络、永不抛出（复用 `_refusals` 墙）。PR-4A 的全部纯度门
   （imports == {`__future__`, `dataclasses`}、禁 I/O/时钟/反射调用点）
   **原样保留**并对 `detect` 生效。
2. **存储层**（`web/incident_history.py`）：schema v4 + 内部有界证据读取
   （同一 RLock 下）+ incident windows / runtime state 持久化。存储层
   **不 import 分类器**（读取投影列名是存储自己的列名契约）。
3. **运行时层**（`web/incident_runtime.py`）：唯一接线消费者。import 闭集 =
   {`threading`, `time` 之外仅 stdlib} + `web.incident_classifier` +
   `web.incident_history`（类型构造用）。

单消费者静态门（取代 PR-4A darkness 门，**加强而非放松**）：`grep -rl
incident_classifier monitor-v2 --include='*.py'` 结果恰为
`{web/incident_classifier.py, web/incident_runtime.py}`；server/webapp/
collector/history 任何面包不得引用分类器名。测试树（tests/）不受此门
约束。

## 4. 分类器扩展契约（`detect` / `Detection`）

- `Detection` 为 frozen dataclass，字段恰为：
  `classification: Classification`、`anomaly_bucket_indices: tuple[int, ...]`、
  `first_signal_epoch: float | None`、`last_signal_epoch: float | None`。
- 三个元数据字段**只**从 `_analyse` 已经算出的候选/簇索引派生：
  `anomaly_bucket_indices` = 全部异常桶索引升序去重；
  `first_signal_epoch` = 首个异常桶的桶起点；
  `last_signal_epoch` = 最后一个异常桶的桶终点；分类结果不含异常
  （`no_incident` / `indeterminate` 或无候选）时三者分别为
  `()` / `None` / `None`。
- `detect` 与 `classify` 共享 `_analyse`：`detect(e).classification` 的
  `to_dict()` 与 `classify(e).to_dict()` 在**全部** harness 输入
  （43 场景 + 19 hostile + fuzz 集 + 两个提交夹具）上恒等——判别器在
  harness `group_invariants` 内对 `_all_bundles()` 与夹具逐条断言。
- `Classification` 结果面**不变**（8 字段冻结）；`destination_specific`
  继续结构性不可输出（EMITTABLE 六类不变）。
- `detect` 不读时钟、不打开文件、不抛异常；恶意输入走同一 `_refusals` /
  `_seal` 墙，元数据为 `() / None / None`。

## 5. Schema v4 契约（恰两表，DDL 冻结）

```sql
CREATE TABLE incident_windows (
    incident_id INTEGER PRIMARY KEY,
    classifier_version INTEGER NOT NULL CHECK (classifier_version = 1),
    state TEXT NOT NULL CHECK (state IN ('open','closed')),
    category TEXT NOT NULL CHECK (category IN (
        'common_inbound_client_office', 'hysteria2_udp_path',
        'insufficient_evidence', 'reality_tcp_path',
        'vps_outbound', 'vps_process_or_api')),
    analysis_start_epoch REAL NOT NULL CHECK (analysis_start_epoch >= 0),
    first_signal_epoch REAL NOT NULL
        CHECK (first_signal_epoch >= analysis_start_epoch),
    last_signal_epoch REAL NOT NULL
        CHECK (last_signal_epoch >= first_signal_epoch),
    last_classified_end_epoch REAL NOT NULL
        CHECK (last_classified_end_epoch >= first_signal_epoch),
    closed_epoch REAL CHECK (closed_epoch IS NULL
                             OR closed_epoch >= last_signal_epoch),
    closure_reason TEXT CHECK (closure_reason IS NULL
                               OR closure_reason IN
                                  ('clean_buckets', 'window_limit')),
    buckets INTEGER NOT NULL CHECK (buckets >= 1 AND buckets <= 60),
    evidence_bits INTEGER NOT NULL
        CHECK (evidence_bits BETWEEN 0 AND 35184372088831),   -- 2^45 - 1
    unknown_bits INTEGER NOT NULL
        CHECK (unknown_bits BETWEEN 0 AND 268435455),         -- 2^28 - 1
    created_epoch REAL NOT NULL,
    updated_epoch REAL NOT NULL CHECK (updated_epoch >= created_epoch),
    CHECK ((state = 'open' AND closed_epoch IS NULL
            AND closure_reason IS NULL)
           OR (state = 'closed' AND closed_epoch IS NOT NULL
               AND closure_reason IS NOT NULL))
);
CREATE UNIQUE INDEX ux_incident_windows_one_open
    ON incident_windows(state) WHERE state = 'open';

CREATE TABLE incident_runtime_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    runtime_version INTEGER NOT NULL CHECK (runtime_version = 1),
    activation_floor_epoch REAL NOT NULL CHECK (activation_floor_epoch >= 0),
    last_evaluated_end_epoch REAL NOT NULL
        CHECK (last_evaluated_end_epoch >= 0),
    reader_fresh_since_epoch REAL CHECK (reader_fresh_since_epoch IS NULL
                                         OR reader_fresh_since_epoch >= 0),
    open_incident_id INTEGER CHECK (open_incident_id IS NULL
                                    OR open_incident_id >= 1),
    -- PR-4B R2（重冻结轮）：发现门与 rearm 门，仍是 v4、仍恰 10 表
    discovery_floor_epoch REAL CHECK (discovery_floor_epoch IS NULL
                                      OR discovery_floor_epoch
                                         >= activation_floor_epoch),
    rearm_required INTEGER NOT NULL CHECK (rearm_required IN (0, 1)),
    -- PR-4B R3（§5.1）：形状闭合。rearm 立起时必须无指针、无 floor；
    -- 一旦 activation 落地（floor>0）且未 rearm，discovery floor 就必须存在。
    CHECK ((rearm_required = 0
            OR (open_incident_id IS NULL
                AND discovery_floor_epoch IS NULL))
           AND (activation_floor_epoch <= 0 OR rearm_required = 1
                OR discovery_floor_epoch IS NOT NULL))
);
```

`incident_runtime_state` 的列集因此恰为 8 列；`discovery_floor_epoch` 与
`rearm_required` 是 R2 唯一的新增列，且**不**抬 `SCHEMA_VERSION`：v4 尚未
发布，fresh/v1/v2/v3 迁移直接建出这个最终形状，不为任何旧 PR-head 的临时
v4 形状增加兼容迁移。

- 位集编码：token 按词汇表排序后的位 i ↔ `1 << i`；版本由
  `classifier_version = 1` 钉住（词表 45 evidence / 28 unknown 已由
  classify 车道钉死）。上界 CHECK 是 DB 层拒绝高位的**第二道**门
  （第一道是编码器拒绝未知 token）。
- 禁 JSON1：列全部为 INTEGER / REAL / TEXT 标量。
- `incident_runtime_state` **至多一行**（`id=1` CHECK）；由 scanner 激活时
  `INSERT OR IGNORE` + `UPDATE` 拥有其生命周期；迁移只建表不留行。
- 初始行是**惰性的**：`activation_floor_epoch=0.0`、
  `last_evaluated_end_epoch=0.0`、`reader_fresh_since_epoch=NULL`、
  `open_incident_id=NULL`、`discovery_floor_epoch=NULL`、
  `rearm_required=0`。首次 activation 在同一事务里把
  `discovery_floor_epoch` 钉成 `activation_floor_epoch` 并保持
  `rearm_required=0`；`activation_floor_epoch` 仍是 one-way / 无回填权威，
  任何后续 activation 只能改这两列以外的东西也改不了它。
- `ux_incident_windows_one_open` 部分唯一索引把“同一时刻至多一个 open
  事件”从扫描器承诺升格为 DB 硬约束（去重/崩溃幂等的最后一道墙）。
- 禁列清单（全部不得出现）：raw log、身份、IP、UUID、凭证、自由文本、
  ISP 标签、设备名、`fp`、`egress_ip`、`run_id`、endpoint 地址。

### 5.1 状态行的形状闭包（R3 新增）

`incident_runtime_state` 只允许三种形状，第四种（**已 activation 且未
rearm，却没有 discovery floor**）被 DB 与本契约同时拒绝：

| 形状 | activation_floor | rearm_required | discovery_floor | open_incident |
|---|---|---|---|---|
| 惰性（born inert） | `0` | `0` | `NULL`（或 close 在边界外落下的值） | 任意 |
| 已布防、正在发现 | `> 0` | `0` | **必须非 NULL** | 任意 |
| 已解除布防（rearm 门） | `> 0` | `1` | `NULL` | `NULL` |

理由是 fail-closed 的方向：R2 的读取端把「`discovery_floor` 为 NULL」当作
**回退到 `activation_floor`**，并把这件事写在注释里叫 FAIL-CLOSED。它不是。
activation floor 比任何 discovery floor 都**更宽**（它是 one-way 的最初下界），
所以一次字段损坏/异常写入会让扫描器重新分析 gate 已经排除掉的更旧历史——
"P4B 无法证明状态"绝不能等于"把分析窗口放大"。R3 因此：

- DB 层：上表的第二个合取项使非法形状**无法被写入**（`UPDATE ... SET
  discovery_floor_epoch = NULL` 在已布防的行上直接 IntegrityError）。
- 读取层：`_discovery_gate()` 见到 `rearm=0 且 floor=NULL` 立即
  `_CycleAbort(runtime_state_corrupt)`，**不再**回退；`_activate()` 见到同一
  形状拒绝激活（scanner 保持 DARK、`enabled=false`、零周期），因为启动路径
  上的放大同样不可接受。
- 桶网格仍钉在 `activation_floor_epoch`：收紧的是发现门，不是网格。

## 6. 迁移契约

- fresh / v1 / v2 / v3 全部单事务原子落到 v4；v3→v4 **只**新增上述两表
  + 两索引 + `meta.schema_version='4'`，八个证据表（timeline_samples /
  device_protocol_states / network_probe_samples / journal_runs /
  journal_events / journal_ingest_audit / journal_ingest_state / meta）
  逐列不动。
- v3→v4 判别器：行数全表保全（逐表 count 迁移前后相等）、`quick_check`
  ok、回滚（restore prestate）后形状精确等于 v3、重开幂等（重复迁移
  不重复建表/不丢行）、v1/v2 迁移阶梯的全部既有断言保留。
- `_enforce_schema` 严格门：恰接受 fresh/v1/v2/v3/v4 五种形状，其余
  fail-closed 零字节变更；v4 形状的表集恰为 10 表。
- 失败的迁移必须回滚到迁移前形状（单事务即保证）。

## 7. 存储层内部读取契约

- 新增内部方法（同一 RLock 下，永不抛出，永不越过既有 `query_timeline`
  有界读面）：`classifier_bundle(window_start, window_end, reader_status)`
  返回分类器输入 bundle
  `{"window","samples","device_states","probe_rows","journal_events",
  "audit","health","reader"}`，行投影恰为分类器消费列（存储自身列名），
  每段上界 2000 行（与分类器 `MAX_RECORDS_PER_SECTION` 同值），超出截断
  并按分类器既有“截断即拒/降级”语义由分类器自己结算。
- `reader` 段的状态 token 由**运行时**保守供给（见 §9）；存储层只透传。
- bundle 的 `health` 段是 **classifier 证据平面的 composed health**，与
  `IncidentHistory.health()` 的构成规则逐字一致：
  `degraded = 普通写面 OR journal OR probe`，错误码优先级同为
  写面 > journal > probe（低平面码不被高平面成功写吞掉）。
  **显式排除 `_incident_degraded`**：incident 持久化平面就是这条 bundle 的
  消费者，若它自己的降康回流进 evidence，一次闭案失败就会污染下一次分类的
  证据健康判断（自我反馈）。四向判据：ordinary / journal / probe 任一面
  degraded 必须进入 bundle；仅 incident 面 degraded 绝不进入 bundle，但
  仍必须进入 `health()` 与 `incident_status()`。
- timeline HTTP 面的 journal/raw 表面**不得**因此变宽：无新端点、无新
  查询参数、journal 列白名单不变。

## 8. 扫描器生命周期状态机

- **激活**：`start()` 后进入 `warmup`。`activation_floor_epoch` =
  `ceil(now/BUCKET)*BUCKET`（激活时刻的下一个完整桶边界）；**不做**
  v3 年代历史回填——floor 之前的行永不进入分析窗。同一 activation 把
  `discovery_floor_epoch` 钉成同一个值。
- **warmup → idle**：`discovery_floor_epoch` 之后存在
  `DISCOVERY_BUCKETS=5` 个完整桶后，首次分析；此前 `phase=warmup`、零分类
  调用。等价表述：最近 5 桶窗口的 `window_start` 早于
  `discovery_floor_epoch` 时保持 warmup。R3 §5.1 取消了两处旧回退：读取端
  **不再**在 `discovery_floor_epoch` 为 NULL 时回退到
  `activation_floor_epoch`（那是**放大**历史，不是 fail-closed），启动端也
  不再用“还没有评估过任何桶”来推断 warmup。
- **idle 分析窗**：最近 5 个完整桶 `[last_complete_end-300, last_complete_end]`。
  仅当分类结果 `status == "incident"` 才开案（`insufficient_evidence`
  由 `multiple_anomaly_clusters` 路径开案是合法且被保留的）；其余状态
  一律不开案、不落行。
- **开案（OPEN）**：单事务写 `incident_windows`（state=open）+
  `incident_runtime_state.open_incident_id`。
  `analysis_start_epoch = first_signal_epoch - 3*BUCKET_SECONDS` 开案时
  **冻结**（3 基线桶，与 `MIN_BASELINE_BUCKETS` 同值），此后不滚动。
  `first_signal_epoch` = 首个异常桶起点；`last_signal_epoch` = 末个
  异常桶终点（开案时相等）。
- **OPEN 期间每扫**：窗口 = `[analysis_start, 最后完整桶终点]`；桶数
  `> MAX_ANALYSIS_BUCKETS(60)` → 走 §8.3 的 `window_limit` 闭案分支
  （fail-closed，不是继续拖长窗口）。否则按 `detect` 元数据原地
  **UPDATE 同一行**（`incident_id` 不变），写入的是**本次这一轮
  `detect()` 的一致 snapshot**：
  - `category` = 本次 `classification.category`（**没有任何格**：更具体、
    更不具体、同级都照本次写，见 §8.1）；
  - `evidence_bits / unknown_bits` = 本次分类结果位集；
  - `last_signal_epoch` 推进到新的末个异常桶终点（无新异常则保持持久化值，
    时钟偏移永不把信号末往回移）；
  - `last_classified_end_epoch` = 本次窗口终点；
  - `buckets` = 本次窗口桶数；
  - **no-write 的唯一条件**：本次 `last_classified_end_epoch` 与持久化值
    相同（同一个完整桶被 30 秒节拍重复扫描）**且**上述六个字段全部相同。
    “verdict 内容没变”不等于“没有发生新的 classification”：出现了更新的
    完整桶时，即使 category/bits/last_signal 一字不差，也必须推进
    `last_classified_end_epoch` 与 `buckets`。
- **闭案（CLOSED / clean_buckets）**：尾部出现 `CLOSE_CLEAN_BUCKETS=3` 个
  连续完整桶且其中无任何异常桶 → **结算当轮这次成功的 `detect()`**：单事务
  UPDATE state=closed、`closed_epoch`=判定时刻、
  `closure_reason='clean_buckets'`，并且 category / bits / last_signal /
  `last_classified_end_epoch`=本次 `last_end` / `buckets`=本次 `count` 全部
  取当轮值，**不得**回读 DB 行里上一轮的 category/bits 当作终值。闭案与
  `open_incident_id` 置 NULL、`discovery_floor_epoch` 置本次
  `last_signal_epoch`、`rearm_required=0` 在**同一事务**内完成。
  `last_signal_epoch` 保持为最后一个异常桶终点（不随干净桶外推）。
  效果：刚闭案的三个干净桶成为下一段的 trusted baseline，最近的 5 桶窗口
  在 `window_start` 追上这个新 floor 之前一直是 warmup，即还要再等两个
  候选桶才重新分类。
- **一个安静桶后的第二簇**：窗口内 `quiet,cluster2` 同时可见时分类器给
  `insufficient_evidence + multiple_anomaly_clusters`；扫描器**不拆分**
  故障域判定——同一 open 行继续更新，P4A 的未知 token 位原样进
  `unknown_bits`。本轮的关键差异：这一行的 `category` 此时**真的**变成
  `insufficient_evidence`（分类器已经 fail-closed 到“证据不足”，持久化层
  没有权利替它保留旧的 Reality 归因，见 §8.1）。
- **重启续跑**：`start()` 读 `incident_runtime_state`；若
  `open_incident_id` 非空，直接续 OPEN（analysis_start 从持久化行恢复，
  同一 incident_id），新 run_id 不得制造第二行（DB 部分唯一索引兜底）；
  若 `rearm_required=1`，重启后仍是 `rearm`（门是持久化的，不是内存的）。
  重启后的 `phase` 按 §8.4 从持久 gate 与当前网格位置**推导**，因此落在
  post-clean warmup 中间的重启在第一个周期之前就已经报 `warmup`。

### 8.1 一致 verdict snapshot（取代旧的 category 拓宽格）

**旧契约作废**：PR-4B 首版曾在扫描器里放一张 `_CATEGORY_LATTICE`
（`insufficient_evidence → 四类`、`{reality,hysteria2,common_inbound} →
vps_outbound`）并让持久化 category 只沿格向上移动。本轮明确删除该语义：
`incident_runtime.py` 不再有 `_CATEGORY_LATTICE` / `_broaden`，持久化层
也不得实现任何形式的“历史最具体 category 优先”。

新的唯一规则：`incident_windows` 的
`category / last_signal_epoch / last_classified_end_epoch / buckets /
evidence_bits / unknown_bits` 六列必须是**最近一次成功 `detect()` 的一致
snapshot**，也就是同一次分类的六个输出，来自同一个分类 generation。
由此得到的可判别后果：

1. 已有 `reality_tcp_path` 的 open 行，后来得到
   `insufficient_evidence + multiple_anomaly_clusters` → 同一行 category
   必须**降**为 `insufficient_evidence`，不得保留 stale Reality 归因。
2. 反向移动（`insufficient_evidence → reality_tcp_path`）同样按本次值写：
   两者都只是“照本次分类写”，不存在优先级。
3. 一行永远不可能出现“category 来自第 12 轮、evidence_bits 来自第 9 轮”
   的拼接；闭案写尤其如此（§8.2）。

### 8.2 terminal write 不得回读旧行值

clean 闭案与 update 走同一条一致性要求：终值来自**当轮** `detect()`。
`window_limit` 分支是唯一例外，且是诚实的例外：那一轮**没有**成功的
分类（超预算窗口被拒绝分析，§8.3），所以它结算的是“最后一次真实成功的
snapshot”，即行内已持久化的六列，而不是新造一个。

### 8.3 `window_limit` 之后进入 `rearm` 门

- `count > MAX_ANALYSIS_BUCKETS` 时：单事务闭案
  `closure_reason='window_limit'`，六列保持最后一次成功分类的持久值
  （`last_classified_end_epoch`/`buckets` 不伪造成本次 60 或 61），
  `open_incident_id=NULL`、`discovery_floor_epoch=NULL`、
  `rearm_required=1`。同一事务，三件事一起成立。
- `rearm_required=1` 之后：扫描器**继续正常运行**（周期继续计数、
  连续性协议继续跑、其他平面照旧），但**自动 incident discovery
  fail-closed 停止**：不得开第二行，不得用 outage 期间的行新建 baseline，
  不得“再 warmup 最近 5 桶”自动学习。
- `rearm` 是**正常 phase**，不是错误：`runtime_failures` 不增加、
  `last_error_code` 保持 NULL。phase 词汇因此为
  {`warmup`,`idle`,`open`,`rearm`,`degraded`} 五个 token。
- 本轮**不**发明自动恢复分类器，也**不**增加 HTTP/UI re-arm 入口；
  显式 operator re-arm 属后续阶段。


### 8.4 `phase` 是从持久 gate 推导的，不是本周期做了什么的答案（R3）

R2 的实现把 warmup 记成一条**周期事实**：

```python
self._warmup_gated = (evaluated is None and open_row is None
                      and not self._rearm_required)
```

这一条推论有两个错误的状态面窗口，而且都被 §12 的单一可观测面如实报出去：

- clean close 那一轮：`open_row` 非空、`evaluated` 也非空（闭案确实结算了
  当轮分类），于是 `warmup_gated=False` → `phase=idle`。可是同一事务里
  store 已经把 `discovery_floor_epoch` 抬到了本次 `last_signal_epoch`，
  discovery 从这一轮起就被门挡住。也就是说，**运行时报告 idle 的同时，
  它自己的持久状态正在拒绝 discovery**，直到下一个 30 秒节拍才自愈。
- 重启路径：`_activate()` 用 `last_evaluated_end_epoch is None` 推断
  warmup。重启时该列早就有值，于是新进程在**第一个周期之前**报告 idle，
  即使它刚读到一个仍然挡住 discovery 的 `discovery_floor_epoch`。

R3 因此把 phase 变成**推导量**，与周期动作无关，只与持久 gate 和网格位置
有关。整个模块只有一条判定式（`_warming`）：

```
warming(gate, last_complete_end) =
    last_complete_end - DISCOVERY_BUCKETS * BUCKET_SECONDS < gate
```

三个读取点共用它：`_discovery_cycle()`（是否分析）、`_run_one_cycle()` 的
收尾（本轮结束后的 phase）、`_activate()`（重启后第一个周期之前的 phase）。
闭案路径必须**先**把 store 在同一事务里落下的新 gate 镜像到扫描器缓存
（`_close_clean` 镜像 `discovery_floor_epoch=last_signal`，
`_close_window_limit` 镜像 `rearm_required=1` + floor NULL），推导才可能得
出正确答案——镜像只是把“store 已经写完的那一笔”提前看见，权威始终是存储，
下一周期仍从快照重读。`rearm` 自己拥有 phase（§8.3），所以它不参与 warmup
推导，推导结果也不会把它报成 warmup。

由此得到的两条硬约束（判别器 31、32）：clean close 的**当轮**就必须报
`warmup`；在 post-clean warmup 期间 restart 的扫描器，在**任何周期之前**
就报 `warmup`。

## 9. reader 负证据连续性协议

- 状态行持久化 `reader_fresh_since_epoch`（REAL NULL）。
- 扫描器每次扫描以 History 的 hb 派生 reader 状态（既有
  `_journal_reader_hb_status` 六 token：disabled/absent/unreadable/
  invalid/stale/fresh）。
- 连续性规则：
  1. **激活**：restart 一律打断连续性。reader 当时 fresh →
     `reader_fresh_since_epoch = activation_floor_epoch`；否则 NULL。
  2. **运行中**：hb 状态非 fresh（stale/invalid/unreadable/absent；
     disabled 视同打断）→ 置 NULL；由 NULL 恢复 fresh → 置为**本次观察
     时刻**（永不回溯到更早）。
  3. **供给分类器的保守投影**：bundle `reader.status = "fresh"` 当且仅当
     hb fresh 且 `reader_fresh_since_epoch IS NOT NULL` 且
     `reader_fresh_since_epoch <= window_start`；否则投影为保守非 fresh
     token（`"stale"`），使分类器自己的 `journal_view_state` 按既有
     语义 fail-closed（journal 负证据不被当作连续见证）。
  4. **G8**：之后的 fresh **不能**追溯修复更早窗口已结算的 journal
     负证据——连续性断裂点之前的负证据永远缺席，断裂后只能从新的
     `reader_fresh_since_epoch` 起算。
- 连续性标记的每次变化与当次扫描的窗口推进同事务持久化。

## 10. 保留（retention）契约

- 7 天合同不变（`RETENTION_SECONDS`）。v4 新增：`_cleanup` 的 horizon
  DELETE 追加 `DELETE FROM incident_windows WHERE state='closed' AND
  last_signal_epoch < horizon`（闭案行按信号末龄期剪除）。
- **open 行永不剪除**（WHERE state='closed' 守卫）；`incident_runtime_state`
  **永不**进入 `_PRUNE_SOURCES`，尺寸剪枝的全局最旧时间线不含任何
  incident 表。不新增 30/90 天策略。

## 11. 崩溃隔离与闭合错误词表

- 扫描周期内任何异常（证据读取、分类、持久化）被** containment 在
  扫描器内部**：`runtime_failures += 1`、记录闭合 `last_error_code`、
  本周期放弃，下一节拍照常；绝不抛出到 broker / probe scheduler /
  journal ingest 线程 / web 工作线程，绝不延迟它们。
- 闭合错误词表（恰 4 token，无异常文本/路径/栈）：
  `evidence_read_failed` / `classify_failed` / `persist_failed` /
  `runtime_state_corrupt`。
- incident 持久化失败按 History 写面失败记账（闭合 code
  `history_incident_persist_failed`，加入既有 `CODE_*` 词汇），写面
  降康与既有语义一致。
- `webapp.py finally` 顺序：`scanner.stop()` **先于** `history.close()`；
  `probes.stop()`/`broker.stop()` 顺序不变。扫描器线程为 daemon，与
  ProbeScheduler 同范式。

## 12. 可观测面契约

- 无 P5 `/api/v1/incidents` 路由，无 UI 变更。
- 既有 `GET /api/v1/diagnostics/timeline` 响应恰多一个键
  `incident_runtime`：deny-by-default 闭合投影，键集恰为
  `enabled` / `running` / `phase` / `cycles_completed` /
  `runtime_failures` / `last_error_code` /
  `last_evaluated_end_epoch` / `open_incident`。
- 域：`enabled`/`running`/`open_incident` 恰 bool；`phase` ∈
  {`warmup`,`idle`,`open`,`rearm`,`degraded`} 恰 str（五 token；`rearm`
  是 §8.3 的正常门，跨 restart 从持久化行读出）。`phase` 是 §8.4 的**推导
  值**：它描述当前持久 gate 与网格位置，不是“上一周期做了什么”的记忆，
  所以 clean close 的当轮与 post-clean warmup 期间的 restart 都不会报出
  `idle`；两个 counter 恰 int ≥ 0；
  `last_error_code` 为 NULL 或 §11 四 token 之一；`last_evaluated_end_epoch`
  为 NULL 或有限非负实数。无扫描器时该键为 JSON null（与 `probes` 同
  范式）。`degraded` 的闭合定义：最近一次周期失败且其后尚无成功周期。
  server 端投影是 deny-by-default：域外的 phase 字符串一律投影为
  `warmup`，绝不把任意文本带到 HTTP 面。

## 13. 生产证据边界（负面清单，全部不得实现）

不得新增/推断以下任何证据源或判定：sing-box PID / NRestarts 历史；
FD / conntrack / listen-queue；客户端 ISP 身份；目的地身份；从稀疏设备
状态推断受影响客户端名单；TT 标记；Office Remote Probe。不得声称
“服务器进程肯定没有重启”——除非未来出现持久化源能证明。分类器的
证据平面不变：它读什么、不读什么由 PR-4A 契约钉死，本 PR 不加列。

## 14. 部署契约（复用 PR #60，不重写事务）

- prestate 事务由目标 release 自身 `SCHEMA_VERSION` 驱动：本 PR 把
  `SCHEMA_VERSION` 抬到 4，v3 活库 + v4 候选发布**自动**触发
  pre-v4 snapshot（`history-prestate-<id>.sqlite3` + `.meta`）。
- 新增部署判别器（packaging / deploy 车道，fixture 模式）：
  1. v3 活库 → v4 候选：prestate snapshot 被触发且探针校验通过；
  2. 迁移后激活失败：prestate 恢复 v3（形状精确、quick_check ok）；
  3. 同 schema 部署：no-op，不产生 snapshot；
  4. v4 → v3 回滚：激活前被 schema 门拒绝，且拒绝信息指向保留的
     兼容 prestate；
  5. 成功部署：pre-v4 snapshot 被**有意**保留（审计资产，不自动清理）。
- 回滚 schema 门（live > want 拒绝）对 4→3 自动生效，无需改门逻辑。

## 15. 打包 / 静态门契约

- 单消费者门：见 §3（恰 `{incident_classifier.py, incident_runtime.py}`
  两个文件命中 import 搜索）。
- PR-4A classify 车道的既有静态门按**加强**原则重新设计，不删除：
  - darkness 门（空 importer 集）→ 恰一双消费者允许名单（§3）；
  - 版本门 0.4.0 → 0.5.0（`VERSION` / `MONITOR_WEB_VERSION`）；
  - “活库恰建 8 张 v3 表” → “活库恰建 10 张 v4 表，且分类器读取的
    八个证据表逐列不变”；
  - 纯度门、结果面 8 字段门、词表字面量门、夹具门**原样保留**；
  - harness `group_invariants` 增加 `detect` 恒等/纯性/闭合判定。
- `EXPECTED_PASS` 硬计数只按车道头注释的分节理由变动，逐节记录。
- R2 的静态门面：首版车道里钉 category 拓宽格的门（格边集、格的真理表、
  “向下移动不改写 category”、“第二簇保留旧归因”）钉的是**错误语义**，
  本轮按 §8.1 删除或改写为 snapshot 门，计数因此**下降**；下降的每一条都
  是删除一个错误承诺，不是删除覆盖，且必须逐条写进车道头注释。新增的
  phase token `rearm` 进入 phase 词汇门（四→五 token），HTTP 投影域同步。
- R3 的门面变化：五个门**全部是新增**（store +1、lifecycle +2、containment
  +2），没有门被改名，也没有门的期望被放宽——**除了一条必须逐条申报的重写**：
  `lifecycle/close_clears_pointer_and_phase` 的第三个合取项在 R2 写成
  `phase == "idle"`，而 blocker A 指出的正是“clean close 的当轮报 `idle`”这个
  错误，所以它按 §8.4 重写为 `phase != "open"`（该门只继续钉它本来该钉的：
  指针与行在同一事务落下、`open_incident` 翻假）。这条重写的**计数不变**，
  R3 自己的 warmup 主张由上面两条新增 lifecycle 门承担，不靠放松旧门。

## 16. 判别器清单（34 条，全部必须先红后绿）

1. 3 基线桶 + Reality 掉线 → 恰好开一个 `reality_tcp_path` open 行，
   `analysis_start = first_signal - 180`，单个异常桶时
   `last_signal - first_signal == 60`（记法澄清：§3 冻结定义
   `first_signal` = 桶起点、`last_signal` = 桶终点，故二值不相等；
   车道按 §3 的算术钉，不改分类规则）。
2. 同一个完整桶被节拍重复扫描（六字段一字不差）→ 行数恒 1 且**零写**
   （`updated_epoch` 不动）；出现了更新的完整桶则即使 verdict 相同也必须
   写（见 22）。
3. 新证据使 category 移动（`reality_tcp_path → vps_outbound`）→ 同一
   `incident_id` 原地更新，无新行；**移动方向不再有意义**：更不具体的
   本次分类同样改写该行（见 20）。
4. 尾部 3 个连续干净桶 → 闭案，`closed_epoch` 为判定时刻，
   `closure_reason='clean_buckets'`，`last_signal_epoch` 保持末个异常桶
   终点。
5. 一个安静桶后出现第二簇 → 仍是**一个** open 生命周期；行内保留
   `multiple_anomaly_clusters` 位；扫描器不合并/不拆分故障域判定；
   `category` 同轮降为 `insufficient_evidence`（见 20）。
6. 仅 probe 掉线（客户端计数无恙、journal 无簇）→ 不开案
   （probe-only 不满足开案）。
7. `egress_ip_changed` 单独出现 → 永不作为第二见证开案/拓宽。
8. fresh → stale → fresh：stale 窗口内 journal 负证据不被追溯修复；
   恢复 fresh 后从新的 `reader_fresh_since_epoch` 起算（G8）。
9. 扫描器重启（新 run_id）：`open_incident_id` 非空 → 续同一 incident，
   无第二行。
10. 持久化前崩溃（写 state 先行/写 windows 后崩溃两种序）：重启后幂等
    ——要么看到一致的 open 行，要么看到无 open 行且 state 无悬挂引用；
    部分唯一索引 + 单事务保证无中间态暴露。
11. 窗口跨度超 60 桶 → `closure_reason='window_limit'` fail-closed 闭案，
    并在同一事务进入 §8.3 的 `rearm` 门（`rearm_required=1`、
    `discovery_floor_epoch=NULL`、`open_incident_id=NULL`）。
12. 位集精确往返（全部 45/28 token 单 bit 与组合）+ 第 45/28 位（越界
    高位）在编码器与 DB CHECK 双重拒绝。
13. `destination_specific` 无法落库：编码路径只收 EMITTABLE 六类，DB
    CHECK 第二道拒绝（静态 + 活库注入）。
14. 全表无 raw/自由文本/身份列：PRAGMA table_info 精确列集 + sentinel
    注入往返不得出现。
15. normal 夹具驱动扫描 → 全程零 incident 行。
16. Reality 夹具驱动扫描 → 恰一个 `reality_tcp_path` incident。
17. 扫描器内部故障（注入证据读取/分类/持久化异常）→ broker 发布、
    probe 节奏、journal ingest、web 响应全部不受影响；
    `runtime_failures` 递增、闭合 `last_error_code`、下一周期恢复。
18. classify 车道检查全部保持绿色，除上述**被加强替换**的静态门
   （darkness→单消费者、0.4.0→0.5.0、8 表→10 表）外无任何放宽。
   实测硬计数，基线一律取 `origin/main` = `a180e7d`。两个主机分别测：
   dev host 在临时 worktree 里实跑，Linux 侧直接读 CI 日志（main 跑
   `36664146945` / `36664146961`，本 head 跑 `36693521366` /
   `36693521337`）。packaging 无 `EXPECTED_PASS`，取其 `== RESULT` 行。
   - dev host：classify 665 → 670（+5，本 PR 的 `detect()` 恒等/纯性/
     闭合不变量），hist 240 → 242（+2：schema-v4 平面 +1，未接扫描器时
     `incident_runtime` 必须为 null 的 timeline 表面门 +1），packaging
     269 → 274（+5，T33 单消费者静态门）。
   - Linux CI：classify 665 → 670、hist 240 → 242、新增 incident-runtime
     车道 188，与 dev host 逐条一致；packaging 两个 job 各自
     `771 → 803`（root）与 `755 → 787`（fixture），净 +32/侧。+32 不是
     放宽也不是随机漂移：把两侧 PASS 行名先把 `0.4.0`/`0.5.0`、
     `v2`/`v3`/`v4`、`incident`/`probe` 归一化再做集合差，结果是
     **+32 / −0**——没有任何检查在改名中消失。这 32 条拆开是 5 条 T33
     单消费者静态门（dev host 也跑，就是上面的 +5）加 27 条新增 T32
     “同 schema 升级是静默 no-op”场景门（captured-prestate 必须为零、
     事务日志不得点名任何 prestate 介质、候选确实启动在自己 schema 的
     文件上、失败注入下事务仍回滚且 `releases.history` 不被写、整笔
     事务零 sing-box / 零 sbox-cm 动作、回滚后 unit/链接/字节一致等）；
     后者依赖 Linux 部署事务工具链，dev host 上整节不跑，所以只显示
     +5。其余表面差异全是原位改名（同一检查换钉值）。
   以上都是逐节记录过的加强，不是放宽，也没有删除任何检查。
19. timeline 端点 `incident_runtime` 键集恰 8 键、域闭合；无 P5 路由、
    无新查询参数、journal 表面不变宽。

**PR-4B R2（重冻结轮）新增判别器 20–30**，全部同样必须先红后绿；红
证据见 §16.2。

20. `reality_tcp_path` 已开案，随后一轮得到
    `insufficient_evidence + multiple_anomaly_clusters` → **同一行**的
    `category` 真降为 `insufficient_evidence`（旧格语义下这条必红：它会
    保留 stale Reality 归因）。
21. terminal clean-close 结算**当轮** `detect()`：闭案行的 category /
    bits / `last_classified_end_epoch` / `buckets` 等于当轮分类输出与当轮
    窗口终点/桶数，而不是 DB 行里上一轮的值。
22. verdict 内容一字不差但出现了新的完整桶 → `last_classified_end_epoch`
    与 `buckets` 必须推进（“没变化所以不写”不能吞掉新 generation）。
23. 同一个完整桶被 30 秒节拍重复扫描且六字段全同 → **零写**
    （`updated_epoch` 不动），行数恒 1。
24. 正常节拍一路扫到 bucket 60 → 行必须**真实**记录 `buckets=60`；
    bucket 61 那一轮不再 classify（超预算窗口被拒绝分析），而是用已持久化
    的最后成功 snapshot 以 `window_limit` 闭案，闭案行仍是 `buckets=60`。
25. bucket 20 直接跳到 bucket 65 → 不得伪造 `buckets=60`：闭案行诚实保留
    bucket 20 为最后一次成功分类。
26. `window_limit` 闭案后持续 outage：再跑多个周期仍**不得**出现
    incident #2（自动发现已 fail-closed 停止）。
27. `window_limit` 闭案后 restart：`phase` 仍为 `rearm`、仍不开案
    （门是持久化的，不是内存的）。
28. clean close 后 `discovery_floor_epoch` 钉在闭案行的 `last_signal_epoch`；
    最近 5 桶窗口起点仍早于它时保持 warmup，即三个干净桶成为下一段
    trusted baseline 且还要再两个候选桶才重新分类。
29. 越过该 floor 之后 discovery 恢复正常：outage 证据能再次开案
    （证明 28 是门而不是永久沉默）。
30. `classifier_bundle().health` 是 composed 证据面健康：ordinary /
    journal / probe 任一面 degraded 都进入 bundle（含错误码优先级），
    **仅** incident 面 degraded 绝不进入 bundle（防自我反馈），同时仍
    进入 `health()` 与 `incident_status()`。

**PR-4B R3（本轮复审后新增）判别器 31–34**，同样先红后绿；红证据见
§16.3。

31. clean close 的**当轮**（不再等下一个节拍）：指针已 NULL、
    `open_incident=false`，而 `phase == warmup`；并证其前提——新 floor 落在
    本轮分类窗口内（`window_start + 3*BUCKET <= floor`，即
    `first_signal <= last_signal`），所以刚闭案的三个干净桶此刻**不可能**
    已经是五桶 trusted baseline。
32. post-clean warmup 期间 restart：新扫描器 `start()` 成功（enabled
    true、零周期、无 open 指针），且在**任何 `run_once()` 之前**
    `phase == warmup`——phase 由持久 floor 与当前网格位置推导，不再来自
    “还没有评估过任何桶”。
33. 形状闭包的 DB 半边：在**已 activation、未 rearm** 的状态行上执行
    `UPDATE ... SET discovery_floor_epoch = NULL` 必须
    `sqlite3.IntegrityError`（回滚），非法形状根本进不了存储。
34. 形状闭包的读取半边：扫描器遇到 `rearm_required=0` 且
    `discovery_floor_epoch IS NULL` 的已布防状态时，
    (a) `start()` 拒绝激活（线程不建、`enabled=false`、零周期），
    (b) 运行中的周期以 `runtime_state_corrupt` 闭合失败（failure +1、
    `cycles_completed` 不增、phase degraded），并且**一个证据 bundle 都不
    读**——绝不把窗口放大回 `activation_floor_epoch`。

### 16.1 变异证据（R1 世代的实测记录，dev host，不再重跑）

方法：把 `monitor-v2/` 与 `tests/` 复制进隔离 scratch 树，逐个施加**单点产品
变异**（绝不改动测试期望），要求具名门变红，随后还原。基线 scratch 树
172 verdicts / 0 FAIL / rc=0（R2 之后为 203 verdicts / 车道 219，R3 之后为 208 verdicts / 车道 224，
本表按 R1 世代原文保留）。结果 16/16 检出：

| 变异 | 变红的门 |
| --- | --- |
| M01 `BUCKET_GRACE_SECONDS` 15→0 | `static/constants_frozen` |
| M02a 取消单向激活的 Python 早退 | **EQUIVALENT**（SQL 的 `AND activation_floor_epoch = 0.0` 仍守住；见 M02b） |
| M02b 同时取消两层守护 | `store/activate_is_one_way` |
| M03 去掉 one-open 部分唯一索引 | `store/one_open_index_refuses_second` |
| M04a 使 category CHECK 恒真 | `store/destination_db_check_refuses` |
| M04b 使 Python 类别墙容纳 `destination_specific` | **loud**：第一墙消失后 DB 墙以异常逃逸，车道 rc/缺行门立即变红 |
| M05 忽略拓宽格 | `static/lattice_truth_table`（另 3 个 lifecycle 门同红） |
| M06 关闭时不清指针 | `store/close_clears_the_pointer_atomically`、`lifecycle/close_clears_pointer_and_phase` |
| M07 事件面故障泄漏进 history 面 | `containment/incident_failure_never_degrades_the_history_plane` |
| M08 抬高 60 桶上限 | `lifecycle/window_limit_closes_fail_closed` |
| M09 超预算证据被静默截断 | `store/bundle_over_budget_refuses_all` |
| M10 stale 窗口投影成 fresh | `continuity/projection_is_stale_while_the_window_predates_continuity`、G8 门 |
| M11 取消 warmup 守护 | `lifecycle/warmup_makes_no_classification` |
| M12 谎言 phase 直达表面 | `containment/lying_phase_projects_warmup` |
| M13 保留期误删 open 行 | `retention/open_window_never_pruned` |
| M14 缩小分析基线（3→2 桶） | `lifecycle/analysis_start_frozen_at_first_minus_three` |

其中 **M05 的靶标已在本轮被 §8.1 作废**：`_CATEGORY_LATTICE` / `_broaden`
与 `static/lattice_truth_table` 等四个格门随格一起删除。R2 不重跑这张表，
而是对 R2 **新冻结语义**做五个变异（M1–M5），见 §16.2。

第一轮变异研究暴露并修掉了两处**测试自身的弱点**（产品未改）：
`warmup_makes_no_classification` 原先只在首个周期之前检查，等于用"没有周期"
证明 warmup 不分类；现在让时钟停在完整桶不足处**真的跑一个周期**，并同时钉
住 phase 与 `last_evaluated_end_epoch`。`incident_failure_never_degrades_the_
history_plane` 原先在其它面的写入之后才取样，只能证明标志位自愈；现在在故障
发生的那一刻取样。两处修改后 verdict 计数不变（39+38），车道仍 188 检查。

### 16.2 R2 变异证据（R2 的 5 个**新语义**变异，dev host，实测一次）

方法与 §16.1 相同：把冻结的干净副本复制进隔离 scratch 树，每次只施加一个
**单点产品变异**，测试期望一律不改，随后整树丢弃。基线 scratch 树
203 verdicts / 0 FAIL / rc=0。R1 的 14 个变异本轮**不重跑**（其中 M05 的靶
标格已按 §8.1 删除）。结果 5/5 检出，无 EQUIVALENT、无静默：

| 变异 | 施加位置 | 变红的门 |
| --- | --- | --- |
| M1 恢复 §8.1 已作废的单向拓宽格（重新引入 `_CATEGORY_LATTICE` / `_broaden`，持久化 category 不再等于本轮分类） | `incident_runtime._open_cycle` 的 `category` 赋值 | `static/lattice_surface_deleted`、`lifecycle/narrowing_rewrites_category_to_the_current_verdict`、`lifecycle/second_cluster_downgrades_the_persisted_category`、`lifecycle/egress_change_never_persists_a_destination`、`lifecycle/clean_close_settles_the_current_verdict_bits`、`lifecycle/terminal_clean_close_settles_the_current_cycle` |
| M2 terminal clean-close 回读旧行的 category/bits 当终值 | `incident_runtime._close_clean` | `lifecycle/terminal_clean_close_did_not_reuse_the_old_bits`、`lifecycle/terminal_clean_close_settles_the_current_cycle` |
| M3 `_unchanged` 忽略 generation：不再比较 `last_classified_end_epoch` 与 `buckets` | `incident_runtime._unchanged` | `lifecycle/open_period_settles_the_frozen_window_width` |
| M4 `window_limit` 闭案按 clean 分支落门（`rearm_required=0`、floor=`last_signal`，即闭案后回到自动发现） | `incident_history._incident_close_window_locked` | `store/window_limit_close_raises_rearm`、`store/rearm_survives_reactivation`、`lifecycle/window_limit_raises_the_persistent_rearm_gate`、lifecycle 的 `rearm_stops_discovery_over_many_cycles`、`rearm_survives_restart_and_still_opens_nothing` |
| M5 把 `_incident_degraded` 与其错误码混进 bundle 的 composed 证据面健康 | `incident_history._classifier_bundle_locked` | `store/bundle_health_excludes_the_incident_plane` |

三点诚实说明：

- **其一**，M1 的 6 条红是**同一条语义**的六个表面（"持久化 category 必须
  等于本轮 `detect()` 的分类"），其中包括 D7 那条顺带钉住的 snapshot 等值
  条款——旧格会把 `insufficient_evidence` 的本轮判定挡在行的旧 Reality
  归因之外。terminal 两条红是必然连带：拓宽格作用在传给 `_close_clean` 的
  局部 `category` 上，终值因此也不再是当轮值（§8.1 与 §8.2 是同一件事）。
- **其二**，M4 下 `lifecycle/rearm_is_a_normal_phase_not_an_error` **仍然为
  绿**：扫描器在闭案那一轮把门镜像在内存里，所以当轮 phase 仍是 `rearm`；
  变异暴露的是下一轮起重读存储之后的一切。这正是 §8.3 要的表达——**门的
  所有权在存储**，内存镜像只覆盖当轮，因此红点必须落在存储门与跨周期/跨
  重启的门上。
- **其三**，M3 只让一条门变红，因为它是唯一把"出现更新的完整桶就必须推进"
  与"同一个完整桶重复扫描必须零写"分开的判别器（§16-22 与 §16-23 成对）；
  M3 打破前者，`repeat_scans_never_duplicate` 仍绿，说明这条对偶没有互相
  掩盖。

### 16.3 R3 证据（本轮 4 个新判别器的非空洞性检查，实测一次）

方法与 §16.1/§16.2 相同：整树复制进隔离 scratch 根，每次只施加一个**单点
产品变异**，测试期望一律不改，随后整树丢弃。基线 scratch 树
208 verdicts / 0 FAIL / rc=0。

本轮**不**重跑 R1 的 14 个与 R2 的 5 个变异（复审指示：两处修复都极局部，
17 车道 battery 也不再本地重跑，全量验证交给 GitHub CI）。下面 5 个变异只
为证明判别器 31–34 各自咬住一处真实语义。结果 5/5 检出，**每个变异恰好红
一条具名判别器**——车道里同时变红的只有 harness 自身的 rc 门（任何一条红判
定都会让它红，属机械后果），计数一律是 `222 passed, 2 failed`；无连带、无
EQUIVALENT、无静默：

| 变异 | 施加位置 | 变红的门 |
| --- | --- | --- |
| R3-1 clean close 不把 store 在同一事务落下的新 floor 交给扫描器（镜像那一行改成自赋值，等价于删掉它，缓存留在上一周期读到的旧 floor） | `incident_runtime._close_clean` | `lifecycle/clean_close_immediately_reports_warmup` |
| R3-2 启动端仍用“还没有评估过任何桶”推断 warmup（回到 R2 的表达式） | `incident_runtime._activate` | `lifecycle/restart_in_post_clean_warmup_reports_warmup` |
| R3-3 启动端接受不可证明的状态形状（§5.1 的形状守卫条件置假，其余不动） | `incident_runtime._activate` | `containment/unprovable_state_keeps_activation_dark` |
| R3-4 运行端在 floor 缺失时回退到 `activation_floor_epoch`（恢复 R2 被批评的行为） | `incident_runtime._discovery_gate` | `containment/active_missing_discovery_floor_is_runtime_state_corrupt` |
| R3-5 状态行不再钉住“已布防必有 floor”（DDL 第二个合取项改成恒真） | `incident_history` 的 `incident_runtime_state` DDL | `store/state_check_refuses_active_without_discovery_floor` |

三点诚实说明：

- **其一**，R3-1 只红一条，不红 `post_clean_close_discovery_stays_warmup`
  与 `clean_close_pins_the_discovery_floor`：那两个周期动作在下一拍确实会
  自愈（扫描器从快照重读 floor）。变异的靶子正是复审指出的那段状态面误差
  ——闭案的**当轮**报 `idle`，而分类行为始终正确。
- **其二**，判别器 33 与 34 是同一件事的两半：DB 拒绝把非法形状**写进**
  存储，运行时拒绝把它**读成**更宽的历史。去掉任何一半，另一半的判据仍
  绿：R3-5（只松 DDL）不碰两条 containment 门，R3-3/R3-4（只改读取端）不
  碰 store 门。读取端内部的两条半边也各自独立——启动半边（拒绝激活、保持
  DARK）只有 R3-3 能红，运行半边（`runtime_state_corrupt` 且零 bundle 读）
  只有 R3-4 能红，说明四条判据没有互相掩盖。
- **其三**，R3-4 的红点是“回退”而不是“崩溃”。车道之外另跑了一次隔离探针
  （同一 scratch 树、真实 scenario bundle `normal_background`、只打印不判定）：
  干净代码下这个周期读到的窗口列表为 `[]`、`last_error_code=
  runtime_state_corrupt`、`runtime_failures=1`、`cycles_completed=0`、
  `phase=degraded`；施加 R3-4 后同一个假状态行让周期**照常完成**——读到
  1 个 bundle（`[BASE+300, BASE+600]`，即由 `activation_floor_epoch` 而非
  丢失的 discovery gate 放行）、`cycles_completed=1`、`runtime_failures=0`、
  `last_error_code=None`，而 `phase` 仍报 `warmup`（缓存里的 floor 是
  `None`），也就是"已经分析完"和"还在预热"同时成立。桶网格不受影响（网格
  始终钉在 `activation_floor_epoch`），受影响的是发现门与状态面。**若没有
  判别器 34，这个 bug 在所有计数器与错误码上都不可见。**

## 17. 明确不做（禁区）

- 不合并、不部署、不触生产 VPS；PR 全程 DRAFT。
- 不改分类规则让 runtime 测试变绿（用户冻结条款）；
  `destination_specific` 结构性不可输出不动摇。
- 不动 `sbox-cm` 二进制、`lib/client-management.sh`、
  `lib/sbox-cm-state.sh`；不动 sing-box 配置面；无前端变更。
- 无新配置旋钮：§2 六常量为编译期冻结。
- 无 JSON1、无 UUID 列、无身份/IP/自由文本、无第二阈值算法、无第二
  处分类器调用点。

## 18. 版本钉住与车道登记

- `VERSION` / `MONITOR_WEB_VERSION` → `0.5.0`：hist / classify /
  probe-ingest / probes / packaging / incident-runtime 车道的版本断言
  一并抬升，历史文字描述不变。
- 新车道 `tests/test-monitor-v2-incident-runtime.sh`（自有
  `EXPECTED_PASS` 硬计数 + 分节注释）；登记进
  `.github/workflows/tests.yml`（`bash -n` + monitor-regression 两行）。
- classify / hist 车道的计数变化逐节记录于各车道头注释。
