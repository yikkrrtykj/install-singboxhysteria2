# Monitor 0.5.0 —— PR-4B 事件运行时 + 判定持久化（issue #33 Phase 4，冻结契约）

状态：**实现前冻结契约**。本文件在写任何功能代码之前写成，是 PR-4B 的
完整规格；实现、判别器测试与 DRAFT PR body 都以本文件为准，实现期间不得
变更契约条款（如需变更必须先改本文件并说明理由）。
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
  更新（category 只沿钉死的格向上拓宽）；3 个连续干净桶闭案；
  60 桶上限闭案 `window_limit`；一个安静桶后的第二簇仍是**一个**运维
  生命周期，P4A 的 `insufficient_evidence + multiple_anomaly_clusters`
  原样保留。
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
                                    OR open_incident_id >= 1)
);
```

- 位集编码：token 按词汇表排序后的位 i ↔ `1 << i`；版本由
  `classifier_version = 1` 钉住（词表 45 evidence / 28 unknown 已由
  classify 车道钉死）。上界 CHECK 是 DB 层拒绝高位的**第二道**门
  （第一道是编码器拒绝未知 token）。
- 禁 JSON1：列全部为 INTEGER / REAL / TEXT 标量。
- `incident_runtime_state` **至多一行**（`id=1` CHECK）；由 scanner 激活时
  `INSERT OR IGNORE` + `UPDATE` 拥有其生命周期；迁移只建表不留行。
- `ux_incident_windows_one_open` 部分唯一索引把“同一时刻至多一个 open
  事件”从扫描器承诺升格为 DB 硬约束（去重/崩溃幂等的最后一道墙）。
- 禁列清单（全部不得出现）：raw log、身份、IP、UUID、凭证、自由文本、
  ISP 标签、设备名、`fp`、`egress_ip`、`run_id`、endpoint 地址。

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
- timeline HTTP 面的 journal/raw 表面**不得**因此变宽：无新端点、无新
  查询参数、journal 列白名单不变。

## 8. 扫描器生命周期状态机

- **激活**：`start()` 后进入 `warmup`。`activation_floor_epoch` =
  `ceil(now/BUCKET)*BUCKET`（激活时刻的下一个完整桶边界）；**不做**
  v3 年代历史回填——floor 之前的行永不进入分析窗。
- **warmup → idle**：存在 `DISCOVERY_BUCKETS=5` 个 floor 之后的完整桶
  后，首次分析；此前 `phase=warmup`、零分类调用。
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
  `> MAX_ANALYSIS_BUCKETS(60)` → 单事务闭案
  `closure_reason='window_limit'`（fail-closed，不是继续拖长窗口）。
  否则按 `detect` 元数据原地 **UPDATE 同一行**（`incident_id` 不变）：
  - `evidence_bits / unknown_bits` = 最新分类结果位集；
  - `last_signal_epoch` 推进到新的末个异常桶终点（无新异常则保持）；
  - `last_classified_end_epoch` = 本次窗口终点；
  - `category` 只沿 §8.1 格**向上拓宽**；同级/向下移动保持已持久化
    category 不变；
  - 无实质变化（category/bits/last_signal 全同）则**不写**，避免写放大。
- **闭案（CLOSED）**：尾部出现 `CLOSE_CLEAN_BUCKETS=3` 个连续完整桶且
  其中无任何异常桶 → 单事务 UPDATE state=closed、
  `closed_epoch`=判定时刻、`closure_reason='clean_buckets'`，
  `open_incident_id` 置 NULL。`last_signal_epoch` 保持为最后一个异常桶
  终点（不随干净桶外推）。
- **一个安静桶后的第二簇**：窗口内 `quiet,cluster2` 同时可见时分类器给
  `insufficient_evidence + multiple_anomaly_clusters`；扫描器**不拆分**
  故障域判定——同一 open 行继续更新，P4A 的未知 token 位原样进
  `unknown_bits`（判别器见 §16-5）。
- **重启续跑**：`start()` 读 `incident_runtime_state`；若
  `open_incident_id` 非空，直接续 OPEN（analysis_start 从持久化行恢复，
  同一 incident_id），新 run_id 不得制造第二行（DB 部分唯一索引兜底）。

### 8.1 category 拓宽格（边集冻结）

```
insufficient_evidence → {common_inbound_client_office,
                         hysteria2_udp_path, reality_tcp_path,
                         vps_outbound, vps_process_or_api}
reality_tcp_path → vps_outbound
hysteria2_udp_path → vps_outbound
common_inbound_client_office → vps_outbound
```

只允许沿边向上；`reality_tcp_path ↔ hysteria2_udp_path` 等同级移动与
向下移动保持持久化值。格本身在车道里以字面量钉住。

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
  {`warmup`,`idle`,`open`,`degraded`} 恰 str；两个 counter 恰 int ≥ 0；
  `last_error_code` 为 NULL 或 §11 四 token 之一；`last_evaluated_end_epoch`
  为 NULL 或有限非负实数。无扫描器时该键为 JSON null（与 `probes` 同
  范式）。`degraded` 的闭合定义：最近一次周期失败且其后尚无成功周期。

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

## 16. 判别器清单（19 条，全部必须先红后绿）

1. 3 基线桶 + Reality 掉线 → 恰好开一个 `reality_tcp_path` open 行，
   `analysis_start = first_signal - 180`，单个异常桶时
   `last_signal - first_signal == 60`（记法澄清：§3 冻结定义
   `first_signal` = 桶起点、`last_signal` = 桶终点，故二值不相等；
   车道按 §3 的算术钉，不改分类规则）。
2. 重复扫描同一证据 → 行数恒 1（无重复行）。
3. 新证据使 category 拓宽（`reality_tcp_path → vps_outbound`）→ 同一
   `incident_id` 原地更新，无新行，格以下/同级移动不改写 category。
4. 尾部 3 个连续干净桶 → 闭案，`closed_epoch` 为判定时刻，
   `closure_reason='clean_buckets'`，`last_signal_epoch` 保持末个异常桶
   终点。
5. 一个安静桶后出现第二簇 → 仍是**一个** open 生命周期；行内保留
   `insufficient_evidence` + `multiple_anomaly_clusters` 位；扫描器不
   合并/不拆分故障域判定。
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
11. 窗口跨度超 60 桶 → `closure_reason='window_limit'` fail-closed 闭案。
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
   实测硬计数，基线一律取 `origin/main` = `a180e7d`（在临时 worktree 里
   实跑测得；packaging 无 `EXPECTED_PASS`，取其 `== RESULT` 行）：
   classify 665 → 670（+5，本 PR 的 `detect()` 恒等/纯性/闭合不变量），
   hist 240 → 242（+2：schema-v4 平面 +1，未接扫描器时 `incident_runtime`
   必须为 null 的 timeline 表面门 +1），packaging 269 → 274（+5，T33
   单消费者静态门）。三条都是逐节记录过的加强，不是放宽，也没有删除
   任何检查。
19. timeline 端点 `incident_runtime` 键集恰 8 键、域闭合；无 P5 路由、
    无新查询参数、journal 表面不变宽。

### 16.1 变异证据（先红后绿的实测记录，dev host）

方法：把 `monitor-v2/` 与 `tests/` 复制进隔离 scratch 树，逐个施加**单点产品
变异**（绝不改动测试期望），要求具名门变红，随后还原。基线 scratch 树
172 verdicts / 0 FAIL / rc=0。结果 16/16 检出：

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

第一轮变异研究暴露并修掉了两处**测试自身的弱点**（产品未改）：
`warmup_makes_no_classification` 原先只在首个周期之前检查，等于用"没有周期"
证明 warmup 不分类；现在让时钟停在完整桶不足处**真的跑一个周期**，并同时钉
住 phase 与 `last_evaluated_end_epoch`。`incident_failure_never_degrades_the_
history_plane` 原先在其它面的写入之后才取样，只能证明标志位自愈；现在在故障
发生的那一刻取样。两处修改后 verdict 计数不变（39+38），车道仍 188 检查。

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
