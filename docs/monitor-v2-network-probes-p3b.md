# Monitor 0.4.0 —— PR-3B 探测激活 + 结果入库（issue #33 Phase 3，发布准备头）

状态：功能评审 **R3 = PASS / APPROVE**，功能代码**冻结**在头
`27e165c0d032b464e8686b26748ca775d4323be1`（该头 `VERSION` 与
`MONITOR_WEB_VERSION` 为 `0.3.1`）。在此之上只有一个**仅 release-prep** 提交，
把版本元数据与钉住当前发布版本的断言抬到 `0.4.0`（§16）；不合并、不部署。
基线：`main @ 32a06ce`（PR-3A 引擎）。
分支：`codex/pr3b-network-probe-ingest-033`。
上游规格：issue #33 Phase 3；前序文档 `docs/monitor-v2-network-probes-p3a.md`
（引擎）、`docs/monitor-v2-incident-history-p1.md`（历史库禁持久化清单）。

## 1. 结论性摘要

- 新增 `monitor-v2/diagnostics/probe_scheduler.py`：PR-3A 引擎的**唯一**激活
  面。专用 daemon 线程，**不骑 publisher 循环**；节奏、目标集、deadline 全部
  是编译期冻结常量。
- History **schema v3**：新增单表 `network_probe_samples`（19 列），入库边界
  对闭合 `ProbeResult` **再验证一次**（不信任上游），fresh/v1→v3/v2→v3 全部
  单事务、forward-only。
- **egress 变更语义持久化**：`changed/unchanged/unknown` 由"最后一条成功入库
  的公网出口 IP"推导，重启不伪造事件，失败周期不产生事件。
- 读取面**复用**既有 `GET /api/v1/diagnostics/timeline`：同一有界请求多带
  `probe_rows`（列白名单 + `since`/`limit`/`truncated`）与闭合的 `probes`
  状态对象；无新端点、无新查询参数、无 UI。
- 部署面两项：`diagnostics/` 进入**显式不可变 staging 清单**（3 个模块，
  恰等审计）；`install-monitor.sh rollback` 前置 **history schema 兼容门**
  （v3 库不得经普通回滚路径落到 pre-v3 release 之下）。
- 测试：新车道 `tests/test-monitor-v2-probe-ingest.sh`（硬计数门
  `EXPECTED_PASS=307`，含 250 条行为判别器）+ `tests/monitor-probes/`
  （行为夹具 + CI 网络守卫），`tests/test-monitor-v2-probes.sh` 126→138，
  `tests/test-monitor-v2-hist.sh` 239→240，
  `tests/test-monitor-packaging.sh` +21：6 条 diagnostics 清单/发布树审计
  （套件自身清单与库声明恰等、禁目录通配 staging、逐文件强制、release 内
  三文件恰等、无 `__pycache__`；所有平台均执行）+ 末尾新增 T27 15 条端到端
  回滚证明（仅在可建符号链接的平台执行，Linux CI 为真实门禁）。
- 功能评审 R1（B1–B6）的收口：生产目标/状态**配对**可产生正证据（B1）、
  `egress_change` 三值一律由边界**推导**（B2）、持久化出口收敛为**全局单播**
  且引擎与库同拒组播（B3）、opt-in 走**打包 unit 的冻结路径**而非任何出货
  面都不提供的环境变量（B4）、投影数字闭合到**精确类型/有限/非负/JSON 安全
  区间**（B5）、`cycle_id` 收到引擎契约（NOT NULL + 唯一索引 + 重放即拒）
  （B6）。每条反例都有判别器，详见 §14。
- 功能评审 R2（B7–B8）的收口，全部落在**闭合边界**上，不动架构：HTTP 投影
  的三个非数值字段与状态容器本身改为**恰等类型**判定（旗标只认 `bool`、
  source/startup token 先恰 `str` 再查词汇、容器恰 `dict`），因此不可哈希或
  伪造 `__eq__`/`__hash__` 的候选者既不能把一次读取变成 500，也不能被采纳为
  token（B7）；History 入库边界只接受**恰为 `int`** 的 latency，其余边界原语
  （epoch、cycle_id、raw_ip、egress_change、status/error_code 词汇）一律
  恰等类型，且每次恰等类型拒收都必须携带 `history_probe_result_rejected`
  而非落库成功后才报错（B8）。详见 §15。
- 明确偏差：见 §11。

## 2. 实现前勘察（PR-3A §2 预留槽位的兑现）

| 对象 | PR-3A 记录的边界 | PR-3B 的兑现 |
|------|------------------|--------------|
| `webapp.py` | 无探测槽位 | 唯一接线点：`history.open()` 之后构造并 `start()`，`finally` 内 `probes.stop()` 先于 `history.close()` |
| `web/broker.py` | publisher 的 write-alongside 先例 | **未使用**：探测节奏与 publisher 完全隔离（§3） |
| `web/incident_history.py` | 严格 v2、表集恰等 | v3：新增探测表 + 两个迁移 rung + 探测边界 + 探测健康平面 |
| `web/server.py` | 唯一有界读面 | 同一读面增两个键；调度器状态经闭合投影，deny-by-default |
| `deploy/lib/monitor-deploy-lib.sh` | staging 清单不含 `diagnostics/` | 显式 3 模块清单 + 恰等审计（多余/缺失均 fail-closed）；回滚 schema 门；**新增** opt-in 路径的唯一权威解算 + 形状/属主/模式校验 + 第 6 条 unit 渲染 `sed`（B4） |
| `singbox-monitor.service.in` | 地址族已覆盖 | 地址族**仍零改动**（无需放宽）；新增一行 `Environment=` 指向 deploy 解算出的冻结路径（B4），使 opt-in 是一条**可持久、可审计**的运维动作 |

## 3. 激活契约（全部强制、全部有判别器）

1. **显式 opt-in，且只有一样东西**：环境变量
   `SINGBOX_MONITOR_PROBE_TARGETS_FILE` 指向的 JSON 文件存在且形状恰等。
   * 变量未设 → DARK，`startup_error=target_file_not_configured`，零线程、
     零 I/O、零周期。
   * 变量已设但文件**不存在** → DARK，`startup_error=target_file_absent`。
     这是打包部署后的**常态**（unit 永远写明它自己的冻结路径，见 §8），因此
     "缺席"是一次可审计的动作，不是缺陷；该分支在 `isfile` 判定**之前**命中，
     这条路径上零字节读取、零内容解析。
   * 变量指向目录/畸形/非恰等文件 → DARK，
     `startup_error=target_injection_invalid`。
   * **绝不**静默回落到编译期生产目标集：回落会把一次测试配置失误变成真实
     公网流量。
2. **两种闭合文件形状**：
   * 逐槽位对象（CI/loopback 注入）→ `target_source="injected"`；
   * 恰好 `{"v":1,"source":"production"}` → `target_source="production"`。
     选中生产目标集是文件必须**明说**的动作，不由省略产生。
3. **冻结常量**：`CADENCE_SECONDS=60.0`、`STARTUP_DELAY_SECONDS=5.0`、
   `TOTAL_DEADLINE_SECONDS=engine.CYCLE_DEADLINE_SECONDS`（12.0）。三者都不是
   `monitor.conf` 可表达的量（conf 读取器只把 `SBMON_*` 键映射为
   `SBMON_ENV_*`），改它们是一次代码评审。
4. **生产目标集 = 目标/状态配对**：`ProductionEndpointSet`（frozen dataclass）
   + `production_targets()` 仅追加"构造引擎 spec"，**不添加任何 timeout 策略**。
   R1 的 B1 把它换成**每一槽都能真正产生正证据**的一对（2026-09-29 对活端点
   实测）：
   * DNS `one.one.one.one`（系统解析器）；
   * HTTPS `https://1.1.1.1/cdn-cgi/trace` → **200**。裸根路径 `https://1.1.1.1/`
     实测 **301**，而引擎的评审契约是 200-only，因此旧配对**永远不可能**产生
     证据：无论网络多健康，该槽位每周期都是 `bad_response`。主机保持数字字面量
     （DNS 槽位才负责解析器），Cloudflare 该叶子的证书 SAN 含
     `IP Address:1.1.1.1`，故 TLS 校验（结构性开启、无绕过旋钮）对字面量成立。
   * UDP 向 `1.1.1.1:53` 发一条 `example.com` 的 A/IN 查询。引擎**只在
     NOERROR 上**给出正证据，而 RFC 6761 规定 `.invalid` 必然 NXDOMAIN，所以旧
     查询名是**确定性错误**：正确的解析器只能让该槽失败，而能回答它的解析器
     是在说谎——评审主机上确实测到了 NXDOMAIN-shim，即把缺陷变成假阳性。
     `example.com` 是 RFC 819 文档域名，确实可解析；应答字节照旧全部丢弃。
   * Egress `https://api.ipify.org/` → 200、一行纯文本全局单播地址、64 字节
     上限。
   B1 的修法**只换目标**：`allowed_statuses` 仍是 `{200}`，两条车道各有反作弊
   判别器（放宽状态契约"修不好"B1 会被抓住，见 §14）。
5. **线程纪律**：恰好一个 daemon 线程（名 `monitor-probes`）；`start()` 幂等；
   `stop()` 后不再启动；周期内异常只累加闭合计数，循环存活；慢周期不阻塞
   `status()`/`stop()`（锁 convoy 判别器）。
6. **状态词汇闭合**：`status()` 的 10 个键 + `target_source` 三值 +
   `startup_error` 三 token，是外部世界能知道的**全部**。调度器不读写文件系统
   （除那一次 opt-in 文件读取），不接触 DB 之外的持久化。

## 4. History schema v3

- 单表 `network_probe_samples`，19 列 = 周期身份（`epoch`/`iso_utc`/`run_id`/
  `cycle_id`/`result_version`）+ 四槽位 `(status, latency_ms, error_code)` +
  `egress_ip` + `egress_change`。引擎 v1 结果**扁平成一行**，不建第二张表。
- CHECK 墙 + 索引：状态/错误码/变更值域、latency 区间、`egress_ip` 的
  canonical-text 约束、`result_version=1`、`cycle_id` 的**精确形状**
  （`length=32` 且只含 `[0-9a-f]`）、`cycle_id NOT NULL` 与
  `CREATE UNIQUE INDEX idx_probe_samples_cycle`——这就是 B6 的"周期身份"：
  一个 `cycle_id` 恰一行，重放的周期（重复投递、生产者 bug、手工重放文件）
  既不能重复计数一条样本，也不能二次移动出口基线。套件用 22 条 raw-INSERT
  逐条撞墙（含 NULL/空串/31 位/大写/点分），另以一条合法行证明墙不是误杀，
  并用重复 id 的直接 INSERT 证明唯一索引在**绕过边界**时仍然开火。
- 入库边界 `_probe_boundary_validate_locked`（不信任引擎）：**每个原语在
  被判定之前先被要求恰等类型**（R2-B8），然后才是键集恰等、状态/码/版本在
  闭合词汇内、latency 为 `0..PROBE_LATENCY_MAX_MS(120000)` 的**恰为 `int`**
  的值、`epoch` 与 now 偏差 `<= PROBE_CYCLE_FRESHNESS_SECONDS(30.0)`、
  `cycle_id` 必须是 32 位 hex（**非字符串也在此拒绝**，不让 TypeError 逃出
  边界）、`run_id` 绑定、`egress_ip` 只接受再canonical 化的**全局单播**地址、
  `egress_change` **一律由库自己推导**并与生产方声明比对（§5）。
- 为什么"恰等类型"而不是 `isinstance`/数值相等（R2-B8 的反例）：词汇表用
  `in` 判定，而 `in` 拿 `__eq__` 提问——一个"逢比必真"的对象在旧边界会被
  **采纳**为 `ok`/`NONE`/`unchanged`；`12 == True == 12.0 == "12"`，所以旧
  的 `latency != _as_int(latency)` 判定把布尔、整数化浮点与数字串都当成
  延迟，而列的 INTEGER affinity 会把 `'12'` **静默转换后落库**，表里存的
  就是引擎从未发出的强制值（引擎自身的 normalize 门答 `int(round(...))`，
  永远是 plain int）；`str` 的子类令 `ip != raw_ip` 这条 canonical 同一性
  比较由**候选者自己回答**，非规范原文因此可被洗白入库。四类反例各有矩阵：
  11 例 latency 表（dns 与 egress 两族交替，共用同一 `_closed_code_slot`）、
  6 例 failed 槽"必须恰为 NULL"、9 例词汇冒充、20 例其他原语
  （`v`/`epoch`/`cycle_id`/`ip`/`egress_change`）。
- 这些拒收**不只断言 `False`**：每条都直接要求平面的**拒绝码**
  `history_probe_result_rejected`、`persisted_total` 不动、
  `rejected_total` 恰 +1 且时间线行数不变。理由是"穿透"与"拒收"讲的不是一
  个故事——值一旦落到 INSERT，会撞 DDL 或参数绑定并报
  `history_probe_persist_failed`，那是对**库**的指控，而缺陷在**生产者**。

- `_canonical_global_ip` 与引擎 `_canonical_ip` 是**逻辑同一**（套件用 AST
  比对函数体，允许注释/函数名不同，不允许语义漂移）：loopback/私有/保留/
  文档/链路本地（含 169.254.169.254）**与组播**地址在 DB 侧同样不可能落库。
  `ipaddress.is_global` 对 `224.0.0.0/4` 与 `ff00::/12` 返回 True，因此
  "全局"绝不等于"可持久化的出口"；两侧都显式 `and not …is_multicast`。
- 迁移：`fresh` 直接建到 v3；`v1→v3`、`v2→v3` 单事务、forward-only、零重写
  既有行；表集**恰等**断言。注入式 mid-migration 崩溃证明：崩溃后字节数不变、
  仍是 v2、可重放迁移。
- pre-v3 运行时遇到 v3 库：**fail-soft**（`open()` 永不抛）→ `enabled=False`
  + `last_error_code=history_schema_unsupported` + 拒绝探测行与基线读 + 零字节
  变更。这是 §8 回滚门的运行期半边。

## 5. egress 变更的持久语义

- 基线 = 本库中**最新一条** `egress_status='ok'` 且 `egress_ip` 非空的行，
  且必须落在 `PROBE_EGRESS_BASELINE_WINDOW_SECONDS`（= `RETENTION_SECONDS`，
  7 天）内。
- 判定交给引擎的纯函数 `classify_egress_change`：无基线 → `unknown`；相同 →
  `unchanged`；不同 → `changed`。**入库时该 token 不是生产方的声明，而是库的
  结论**（B2）：边界用当前基线自行推导，再与传入值逐字比对，不一致即整条拒绝。
  `changed`、`unchanged`、`unknown` **三值一律**参与推导与校验——旧实现只校验
  "变化"类声明，一个把真实切换说成 `unknown` 的生产方就能把事件抹掉；现在
  `unknown` 也必须"确实无基线"才成立。
- 判别器覆盖：重启后首条仍是 `unchanged`（不伪造事件）；窗口过期后
  `unknown`；绕过边界用 raw writer 写入私有地址行 → 基线被拒（防御纵深）；
  **组播地址（v4 `224.0.0.1`、v6 `ff00::`）在引擎与库两侧同拒**——
  `ipaddress` 判它们为 global，所以"全局"这一条谓词不够，必须是全局**单播**；
  链路本地元数据地址拒绝，前导零形式 `8.008.8.8` 被 canonical-text 等值门拒绝。
- 三值推导有一张 12 行网格判别器（基线有无 × 出口成功/失败 × 地址同/异）：
  只有"推导出的那个 token"能落库，失败周期永不浮出 `changed`，且
  **引擎的 `classify_egress_change`、库的 `_derive_egress_change` 与测试夹具
  的推导在 14×14 全表上逐格同答**（三份实现不允许在任何组合上分叉）。
- **CI 里 egress 的 ok 行来自注入答案，不来自对端**：loopback TLS 假服务
  响应体 `9.9.9.9` 时入库的是答案；响应体 `127.0.0.1` 时该行是
  `failed/parse_failed` 且 `ip=NULL`，因此 loopback 地址既不能成为出口答案，
  也不能伪造基线。

## 6. 保留与有界读取

- `_PRUNE_SOURCES` 5 项（含 `("network_probe_samples","epoch")`），修剪按
  **全局 epoch 序**跨表进行，尺寸目标/上限不变（48/64 MiB）；探测行不与事件
  历史互相挤出，也不单独保留。全部探测行到期后基线消失 → `unknown`，此时
  带 `changed/unchanged` 的行被边界拒绝（陈旧推导不入库）。
- `query_timeline` 同一 `since`/`limit` 返回 `probe_rows`（列白名单 =
  `PROBE_COLUMNS`）与 `truncated`；`journal_ingest_state` 等游标行在修剪中存活
  有独立判别器。

## 7. 两个证据平面，互不吞并

- 探测平面：`probe_status()` = `enabled`/`degraded`/`last_error_code`/
  `persisted_total`/`rejected_total`；码为
  `history_probe_result_rejected`（形状被拒）、
  `history_probe_persist_failed`（写入失败）、
  `history_schema_unsupported`（§4 运行期拒绝）。
- 网络探测**结果**中的失败（timeout/dns_failed/…）是**数据**，永不构成运行时
  退化；一条合法网络失败周期照常入库并清除探测平面退化。
- 优先级：写面码 > journal 码 > 探测码；一条被接受的探测行只清自己平面，
  写面退化存活。共享 `_failure_count` 仍累加（运维只需看一个总数），
  `_record_probe_failure` 只动探测字段。
- 已关闭/从未打开的 store：静默拒绝，绝不抛。

## 8. 部署面

- **staging 清单**：`DIAGNOSTICS_MODULE_FILES=(__init__.py network_probes.py
  probe_scheduler.py)`，逐文件 staging（**不是** `cp -R diagnostics`），
  staging 后 `sbmon_diagnostics_audit` 恰等审计，多余/缺失均放弃发布；三个
  模块加入发布前 `py_compile` 校验集。这份清单是**启动必需**载荷（`webapp.py`
  import 调度器），因此与 `journal_reader/` 的"可缺省（INERT）"分支不同：源树
  缺任一模块即 fail-closed 拒绝发布，一切自建夹具源树都必须镜像它。新引擎文件
  不会"顺带"进入 release。
- **opt-in 的正式持久路径（B4）**：变量
  `SINGBOX_MONITOR_PROBE_TARGETS_FILE` 由**打包 unit** 提供，值是一条冻结路径
  `@SBMON_PROBE_TARGETS_FILE@` → `$(sbmon_probe_targets_file)`
  （= `$SBMON_CONF_DIR/probe-targets.json`，装机后
  `/etc/singbox-monitor/probe-targets.json`）。因此"开启探测"是一次**唯一可
  审计的动作**——运维者把一个评审过的目标文档放到那条路径上——而不是一行只有
  重启才生效、且任何出货面都不写的 shell 变量。三点配套：
  * `sbmon_render_unit` 增加第 6 条 `sed`，模板里恰一行 `Environment=`，任何
    第二个 `Environment=` 旋钮都被车道抓住；
  * `sbmon_verify_probe_targets` 只**校验边界**：缺席即 `info` + 保持 dark；
    在场则走与 `monitor.conf` 同一套"修复后复验"契约
    （`sbmon_require_regular_or_absent` + `sbmon_verify_runtime_meta 0640`，
    元数据可收敛到 `root:$SBMON_GROUP 0640`，**内容零字节改动**），符号链接、
    目录与其它形状一律 fail-closed。它**绝不**创建、改写或删除该文档，也不
    解释其内容（语义仍是调度器自己的 fail-closed 职责）；
  * 该调用排在 `sbmon_stage_release` **之前**（发布是不可变动作，校验必须更早）。
  持久性由平台事实支撑：`/etc/singbox-monitor` 是 `root` 属主 `0755`（服务用户
  不能种下符号链接），`uninstall` 默认保留 `$SBMON_CONF_DIR`（除非
  `--purge-config`），`ProtectSystem=strict` 仍允许读 `/etc`。
- **回滚 schema 兼容门**（`sbmon_rollback_schema_gate`，在任何 pre-state 捕获
  与变更之前）：
  * 读当前库声明的 `schema_version`（只读 URI，`mode=ro`，2 s 超时）；
  * 读**目标 release 自己**声明的 `SCHEMA_VERSION`（导入该 release 的模块，
    并先把 `""`/`.`/cwd 从 `sys.path` 剔除 —— 由该 release 自己回答，不刮文本；
    导入一律带 `python3 -B`：普通 import 会把 `__pycache__` 写进**不可变
    release 树**，那会让"只读前置检查"本身变成变更者，因此 `-B` 是契约而非
    优化）；
  * 目标声明 < 当前库 → 拒绝；任一侧不可读/非整数/负数 → 拒绝；库不存在 →
    放行（无物可保护）；
  * 拒绝消息只说版本整数，不携带路径、端点或 exception text，并以
    `未做任何变更` 结尾。
  * 判别器分两层：车道 S2 在真文件上驱动函数（21 条决定，含零字节变更、
    "不创建 side file"与"整个 fixture 发布树零 `__pycache__`"——后者已用
    去掉 `-B` 的反向实验证明会失败）；packaging T27 在完整 fixture 上端到端跑
    `install-monitor.sh rollback <pre-v3>` → rc 1、活链/history/DB/重启次数
    全部不变，并对兼容目标证明该门不是"一律拒绝"。

## 9. HTTP 投影

`/api/v1/diagnostics/timeline` 新增 `probes`：仅重发 `PROBE_STATUS_KEYS` 的
10 个键，逐键做值域收敛（bool / 三值 source / 三 token 的 startup_error /
实数 / 整数计数）。B5 把"有限、非负"补成**闭合数值域**：
`closed_probe_seconds` 要求**恰为** `int`/`float`（`bool` 与任何带私有
`__float__` 的子类都算缺陷而非数字）、有限、非负且 `<= 2**53-1`
（`PROBE_STATUS_MAX_NUMBER`，JSON 消费者不丢精度的上界），否则答 `None`；
`closed_probe_counter` 要求**恰为** `int`（`2.5` 不是计数）、同域，否则答 `0`。
理由很直接：`NaN`/`Infinity` 会序列化成 `NaN`/`Infinity` —— 那不是合法 JSON，
一个说谎的调度器就能破坏**所有**读者对整个诊断面的读取。
五个分类集合被车道断言与 `status()` 的键集**恰等**，所以投影的分派不存在
"未分类键"这条暗道。调度器缺失、损坏、抛异常或**说谎**（返回任意字符串、
路径、端点名、`NaN`、负数、`True`）时：`probes=None` 或该字段被压回闭合值，
绝不透传。会话鉴权、
GET-only、loopback 绑定契约均不变。车道 S5 用真 `build_server` 断言投影键集
与 `status()` 键集**恰等**，并断言响应体不含 `/etc`、路径、`targets.json`
或 `api.ipify.org`。

R2-B7 把剩下三个字段也做成**闭合值域**，每个都有各自的失效方式：

- `closed_probe_bool`：旗标只接受**恰为 `bool`**。`bool("yes")` 与 `bool(1)`
  都答 `True`，旧投影因此把一个字符串和一个整数读成"探测已启用且在跑"。
  该字段没有能保持 JSON 类型的"未知"形状，所以缺陷答**拒绝方向** `False`。
- `closed_probe_source` / `closed_probe_startup`： membership 之前**先做
  恰等类型检查**。这是两条不同的漏洞——frozenset 会要求候选者**哈希**，
  于是 `list`/`dict` 直接把 `TypeError` 抛出投影（`try` 只包住 `status()`
  调用，包不住分派循环），一次读取变成 500 而不是闭合最小值；而 membership
  用 `__eq__` 提问，一个伪造 token 哈希、逢比必真的对象会被**采纳**为该
  token，然后原样交给 `json.dumps`——它序列化不了任意对象，于是同一个谎言
  又毁掉所有读者的响应。字符串子类的 token 冒充同样被拒（`"production"`
  的子类在旧路径上能赢过比较）。
- 容器本身：`type(raw) is dict`，**恰等**。`isinstance` 放过 dict 子类，
  而子类可以让 `get()` 对同一个键回答与底层映射不同的值——评审要的那句
  "preferably require an exact dict" 在这里是硬门。
- 反向闭合同样取证：三值 source、三个 startup token 与 `True`/`False`
  在真 HTTP 上仍**逐字透传**（诚实表 9 行），否则"什么都不接受"的收紧
  也能通过全部敌意矩阵。敌意 shape 矩阵（36 行）与敌意数值矩阵（19 行）
  的键集**并起来恰等** `PROBE_STATUS_KEYS`，投影面没有未测字段。

## 10. 测试矩阵

| 车道 | 判别器 |
|------|--------|
| S0 静态 + 镜像（8） | `py_compile` 全集；history↔engine 词汇**活值**恰等；IP 门 AST 同一；bounds/v3/`_PRUNE_SOURCES` 自洽；scheduler↔server 状态面恰等——含**三** token 的 `PROBE_STARTUP_TOKENS`，以及五个投影分类集合与 `status()` 键集**恰等**（B5：分派不得有未分类键）；`web/` 零 `diagnostics` import；**R2-B7/B8 的 AST 反 coercion 门**：投影与边界的七个判据函数体内不得出现 `isinstance`/`bool`/`_as_int` 调用；**latency 墙形状门**：`_closed_code_slot` 原文里必须存在 `type(latency) is not int`、不含 `_as_int`、恰两个调用点（timed/egress），且 `PROBE_LATENCY_MAX_MS == 120000` |
| S1 回滚门接线（6） | 调用点在首处变更之前；拒绝文案承诺零变更；整个门 helper 区无写语句；库恰一次以只读 URI 打开；目标 release 读者不继承调用方 `sys.path`；调用点 die-check |
| S2 回滚门决定（21） | v3→v3/v4 放行，v3→v2、pre-history、缺失 release、无版本声明、非数字、负数、非数据库文件均拒绝；无库放行且不创建任何文件；真 v3 库（由被测模块自建）同判；拒绝文案含两个版本号、不含 fixture 路径；DB 字节与目录集不变；整棵发布树零 `__pycache__`（`-B` 契约） |
| S3 打包 opt-in 面（15） | 打包 unit **经真实 deploy 库渲染**（`sbmon_render_unit` 在临时文件上跑一遍）；渲染结果恰一行 `Environment=` 且它就是 opt-in 路径、无残留 `@SBMON_` token、值等于 `$(sbmon_probe_targets_file)`；出货面（`install-monitor.sh`/`app-bin`/reader unit）无人书写该文档名；`sbmon_verify_probe_targets` 函数体 awk 提取后不含写语句或 `touch/rm/cat/tee/cp/mv/install`；调用行号早于 `sbmon_stage_release`；生成的 `monitor.conf` 无探测键（且键集可枚举，门非空转）；conf 读取器白名单无探测键；`webapp.py` 以 `ProbeScheduler(history)` 唯一构造、不传 cadence/targets；调度器 AST 只有一个 `open(...,"r")`、无写/unlink/`sqlite3`/`shutil`；夹具 AST 的每个 socket 调用点都是 `127.0.0.1`；VERSION/`MONITOR_WEB_VERSION` 恰为**当前发布版本**（发布准备头为 `0.4.0`，见 §16）；tests.yml 已接线 |
| S4 CI 网络守卫自检（7） | 公网 TCP connect / UDP sendto / DNS 解析 / 非 loopback bind / 链路本地元数据地址全部**被拒**；loopback connect 与 `localhost` 解析放行 |
| S5 行为组（250，全程在守卫下运行） | boundary 35（>40 例拒绝矩阵，每条都携带"缺陷世界会兑现的那个 token"，故 B2/B3 的拒收不可被掩盖；**B8 再加 5 条**：11 例 latency 缺陷矩阵、6 行"失败槽位必须是恰 NULL"、9 行词汇冒充者、20 行边界原语恰等类型、以及"每一次恰等类型拒收都携带 `history_probe_result_rejected`"）、durable 25（重启 + 窗口 + raw-writer 防御 + 三值推导网格 + 三份推导 14×14 同答）、schema 31（fresh/v1→v3/v2→v3、崩溃注入、pre-v3 运行时、22 条 CHECK 墙含 NULL/重复 id 的 DDL 撞墙）、retention 12、health 21、activation 38（DARK 默认不起线程、16 例畸形 opt-in、闭合 token/常量冻结、**B1 目标/状态配对的四条实测判别器**）、e2e 21（真调度器 + 127.0.0.1 TLS 假服务）、threads 25（20× start/stop、慢周期不 convoy 且每周期携带**新** `cycle_id`）、http 42（真 server、401、恰等投影、liar/raiser + 19 例敌意数值矩阵与两张闭合域直查表；**B7 再加 12 条**：36 行敌意 shape 矩阵 + 逐行严格 JSON + "敌意形状永不杀投影"、诚实 token 表 3+4+2 行、`SneakyStatus(dict)` 证明容器须恰等 dict、三个闭合器各自的直查表与"闭合器在词汇上全定义/遇不可哈希不抛"） |

**loopback-only 是构造性证明，不是 grep**：`tests/monitor-probes/
no_public_network.py` 装在 CPython audit 钩子上（`socket.connect`/
`socket.bind`/`socket.sendto`/`socket.getaddrinfo`），在被审计操作发生**之前**
抛异常即失败；它位于所有库抽象（`socket`、`http.client`、`ssl`、引擎的
spec 构造）之下，套件日后新增的 import 也绕不过。S5 的 250 条全部在该守卫
下运行，因此"泄漏"表现为崩溃，而崩溃就是 FAIL。守卫自身先跑 S4 自检，
防止一个什么都不拒的守卫冒充证明。

**全车道扫描与 reader 轨道的同批适配**：`diagnostics/` 变为无条件 staging
依赖后，任何自建 monitor 源树的夹具都必须携带它，否则用例在门前就失败。
本地跑遍全部 Monitor 车道抓到两处：`test-monitor-v2-jr-deploy.sh` 的
`build_src` 未携带 → 261 passed / 31 failed 全是"夹具建不出来"噪声（staging
rc=1、空 release 树、unit 缺失），补成与 reader 载荷同规格后 292/0（20 SKIP）；
`test-monitor-v2-p2b-integration.sh` 同样缺载荷（它的 staging 硬门在本平台
SKIP，问题只会在 Linux 显形），外加一条刮文本的 "history schema stays exactly
v2" 门——该门真正的不变量是"reader 集成没有自作主张移动 schema"，因此改为
"恰一个声明、且值为评审过的 3"，硬编码 2 会挡掉本阶段自己的迁移，而任何未评审
漂移仍会被抓住：33/0（4 SKIP）。其余车道经清查不受影响（packaging 的 7 棵夹具
树已同时携带两份载荷，B7 交换访问车道直接指向真实仓库树）。

CI 接线：`.github/workflows/tests.yml` 的 `fast-checks` 增加
`bash -n tests/test-monitor-v2-probe-ingest.sh`；`monitor-regression` 车道
增加该套件步骤。**Linux CI 是真实门禁**；R1 轮在 dev 主机（Windows/Git Bash）
实测 `288 passed / 0 failed`，其余 Monitor 车道同批全绿（`probes=138`、
`hist=240`、`jr=371`、`jr-deploy=292`/20 SKIP、`p2b 集成=33`/4 SKIP、
`e4diag=457`、`packaging=268`（T27 因无符号链接 SKIP，Linux pass 覆盖它）、
`m05` 全绿）。带时序的两组（threads+http，55 条）另以 20× 循环回归取证（见 §14）。

**首轮 CI 红（两条均为 Linux-only 残差，非契约失败）**：① e3 的两条实机车道
`test-m2-live.sh`/`test-m3-deploy.sh` 用 `cp` 自建 monitor 应用树，复制清单
早于 PR-3B，`webapp.py` 在 `from diagnostics.probe_scheduler import …` 处
`ModuleNotFoundError`，三条基线的 LIVE 门全红；m3-deploy 携带同一潜在缺口，
只因步骤首败即停而未显形。② p2b 的 I4 迁移门断言 schema 落到 2，而安装头已
是 v3-aware，packaging-fixture 红于 `want '2', got '3'`。修复：夹具镜像
staging 载荷；I4 改为"一步落到 3"并追加结构断言（v3 探测表随同一 rung 建出），
车道标签不再冻结数字。I4 在本平台 SKIP，因此迁移语义用一棵无符号链接的 stub
发布树离线重放取证：`schema_version 3`、health enabled/degraded false、v1 行
逐字节保留、7 张既有表 + `network_probe_samples` 齐备。

**第二轮 CI 红（一条，同样 Linux-only）与最终取证**：`boundary/harness_dir_mode_600`
在真实平台上永不可过——它把 diagnostics **目录**断成 0600，而生产校验器的规则
是目录 0700、DB 文件 0600（目录缺 `+x` 连自身属主都无法进入）。该门会开火正是
它具备判别力的证据；改名为 `harness_private_evidence_modes` 并在一次测量里同时
证明两半，门数不变（254）。头 `b567e4e` 首试 10/10 全绿，Linux 实测：
hist 240/0、jr 371/0、jr-deploy 464/0/0-SKIP、p2b 集成 132/0/0-SKIP、
probes 138/0、probe-ingest 254/0；packaging fixture 631/0、root 646/0；
三条基线（22.04/24.04/26.04）的 `E3_M1_SYSTEMD`、`E3_M2_LIVE`、`E3_M3_DEPLOY`、
`E3_M3C_PHASE2_LIVE`、`E3_M3C_PHASE3_LIVE` 全 PASS。

**R1 轮的 Linux 实测**：功能评审 R1（B1–B6）头 `9e250ea` 首试 10/10 全绿，
Linux 数字与 dev 主机同批一致且**没有任何门因平台差异而 SKIP 掉**：
probe-ingest 288/0（新硬门数，见 §14）、probes 138/0、hist 240/0、jr 371/0、
jr-deploy 464/0/0-SKIP、p2b 集成 132/0/0-SKIP；packaging fixture 631/0
（T27 的 v3→pre-v3 回滚拒绝门在真实平台执行）、root 646/0；三条基线的
`E3_M1_SYSTEMD`、`E3_M2_LIVE`、`E3_M3_DEPLOY`、`E3_M3C_PHASE2_LIVE`、
`E3_M3C_PHASE3_LIVE` 全 PASS，其中两条自建 monitor 源树的实机车道在本轮
携带了 `B4` 新增的第 6 条 `sed`（渲染 `@SBMON_PROBE_TARGETS_FILE@`），
证明打包 opt-in 路径在真实 `systemd` 单元里也成立。

## 11. 明确偏差

1. P3A §2 曾把"`diagnostics/` 进入 staging 清单"推迟到 release-prep
   （VERSION→0.4.0）。PR-3B 的任务书把"显式不可变 manifest staging"列为本
   阶段交付项，因此清单变更**提前**到功能评审头，并与恰等审计、`py_compile`
   校验集、packaging 判别器同批落地。DARK 性质不受影响：默认无 opt-in 文件
   时线程不启动、零 I/O。
2. P3A §2 设想的"v2→v3 迁移 + 独立读端点"收敛为：迁移照旧，读面**不新增
   端点**，改为在同一有界请求上追加两个键。理由：新增路由会绕开既有
   session/绑定/列白名单审计面，且对消费方（未来 integration）无额外收益。
3. 生产代码三处由测试逼出的硬化（非规格新增）：非字符串 `cycle_id` 在边界内
   显式拒绝；`startup_error` 经 `PROBE_STARTUP_TOKENS` 值域收敛；回滚门读取
   目标 release 的 `SCHEMA_VERSION` 改用 `python3 -B`，以免"只读检查"往不可变
   release 树里写 `__pycache__`。

## 12. 本 PR 明确不包含

sbox-cm 二进制与 `lib/client-management.sh`/`lib/sbox-cm-state.sh` 零接触；
无质量感知 failover；无 UI/static 改动；无生产 VPS 访问、无 SSH、无部署；
`VERSION` 在功能评审各头保持 `0.3.1`，功能 PASS 之后由**唯一一个仅 release-prep**
提交升到 `0.4.0` 并重跑全量 CI（§16，不带任何行为改动）；不合并（需显式指令）；
不引入浏览器/前端；unit 模板**只**新增
一行指向 deploy 解算路径的 `Environment=`（B4），地址族、沙箱、用户、`UMask`
等其余各行零改动；不改 `monitor.conf` 键集（探测节奏与目标集仍不是可配置项）。

## 13. 已知限制

- 探测基线依赖同一 run 的库；跨 run 的库合并（例如手工搬 DB）不在本阶段
  语义范围内。
- `PROBE_LATENCY_MAX_MS=120000` 是"任何真实周期之上、无界整数之下"的评审
  区间，不是容量承诺。
- 网络守卫拒绝的是本套件进程内的公网地址族操作；它不替代 systemd 沙箱，
  生产主机的出站面仍由 unit 的 `RestrictAddressFamilies`/`ProtectSystem`
  与操作者投放的目标文件共同决定。

## 14. 功能评审 R1（B1–B6）：反例与判别器的对账

每条 B 项都以"将修复撤回，观察套件是否变红"取证（真字节还原，逐条独立）：
| 撤回的修复 | 开火的判别器 |
|------------|--------------|
| B3 引擎侧去掉 `is_multicast` | 2 FAIL |
| B3 库侧去掉 `is_multicast` | 7 FAIL |
| B2 边界改为信任生产方声明 | 9 FAIL |
| B6 `cycle_id` 改为可空 | 4 FAIL |
| B6 唯一索引改为普通索引 | 2 FAIL |
| B6 移除重放读取 | 3 FAIL |
| B5 实数改为 `float()` 强转 | 2 FAIL |
| B5 计数改为 `int()` 强转 | 3 FAIL |
| B5 去掉上界 | 3 FAIL |
| B5 去掉有限性 | 3 FAIL |
| B1 HTTPS 路径改回 `/` | 2 FAIL |
| B1 UDP 名改回 `example.invalid` | 2 FAIL |
| B1 用放宽状态集（`{200,301}`）"修"B1 | 2 FAIL（反作弊：状态契约仍是 200-only） |
| B4 模板不再写明路径 | 2 FAIL（S3） |
| B4 渲染 `sed` 移除 | 1 FAIL（S3） |
| B4 模板新增第二个 `Environment=` | 2 FAIL（S3） |
| B4 校验器写入该文档 | 1 FAIL（S3） |

一条诚实的例外：把边界的 `egress_change not in PROBE_CHANGE_VALUES` 成员检查
删掉，套件**全绿**。这不是漏测而是**空变异**——推导函数只会返回三个 token
之一，任何非法声明必然与推导不等；该检查因此是防御纵深，而不是被某条判别器
单独承重的门。不为它编造测试。

`b6_null_allowed`（只放宽"允许 `cycle_id is None`"这一半）最初只被
`rejected_total_matches_matrix` 间接抓住——DDL 墙把拒收变成了持久化失败，
信号正确但不精确。据此补了直指的判别器
`null_cycle_id_refused_with_the_rejection_code`：断言拒收码恰为
`history_probe_result_rejected`，即该形状缺陷在**边界**就被命名，而不是在
写入时才撞上墙。

B6/B2 还回头改写了**夹具自身**的三处纪律，否则新墙会把旧用例变成静默通过：

1. 每条拒绝用例都携带"缺陷世界会兑现的那个 token"（组播/私有/非 canonical
   行声明 `changed`，形状缺陷行声明 `unchanged`）。若继续统一声明 `unknown`，
   边界会因**推导不等**而拒收，B3 的门被削弱也照样绿；
2. 每一条 raw seed / raw wall 都带一个**新的合法 `cycle_id`**（`next_cycle()`），
   除非 id 本身是被测缺陷。否则 NOT NULL + UNIQUE 会让第一次插入的约束成为
   后续所有"撞墙成功"的真实原因，整面矩阵证明不了自己声称的事；
3. `threads` 的慢周期夹具每次投递**重 stamped** 的新 id 与新 `epoch`。旧夹具
   反复交付同一周期，v3 之后它实际测的是重放拒绝循环，而不是它命名的锁 convoy。

带时序的两组（`threads` 25 + `http` 42 = 67 条）在 CI 网络守卫下连跑 **20 轮**，
20/20 全绿、零非零退出；全车道另有一轮同批实测（§10、§15）。

## 15. 功能评审 R2（B7–B8）：闭合边界的最后两个缺口

R2 只动**判定方式**，不动架构、不动数据面：B1–B6 的修复与全部现有契约保持。
两处 blocker 的共同根因是同一件事——**用会 coercion 的谓词做值域收敛**。
`isinstance` 放过子类，`bool()` 把任何非空值读成 `True`，`_as_int()` 会**转换**，
而 `x in (tuple | frozenset)` 是向**候选者**提问（它的 `__hash__`、它的 `__eq__`）。

### B7：HTTP `probes` 投影的剩余三个字段 + 容器

| 反例 | 旧行为 | 现契约 | 判别器 |
|------|--------|--------|--------|
| `{"enabled": "yes", "running": 1}` | `bool()` 双双读成 `True`：一个字符串加一个整数被报告为"探测已启用且在运行" | 旗标只接受**恰为 `bool`**；缺陷答拒绝方向 `False` | `http/liar_bool_not_a_flag_refused`（由 R1 的 `liar_bool_coerced` **翻转**而来）、`http/closed_probe_bool_table` |
| `["dark"] in PROBE_TARGET_SOURCES` | frozenset 先哈希候选者 → `TypeError` 抛出投影；`try` 只包住 `status()` 调用，**包不住分派循环**，于是谎话调度器把一次读取变成 500，毁掉**所有**读者 | membership 之前先 `type(value) is str` | `http/closers_never_raise_on_unhashable`、`http/hostile_shapes_never_kill_the_projection` |
| 伪造 token 哈希、逢比必真的对象 | membership 用候选者的 `__eq__` 提问 → 该对象被**采纳**为 token 并原样交给 `json.dumps`（序列化不了任意对象）；在边界那一侧它被交给 SQLite binder，报的是 `persist_failed`，即"存储坏了"而不是"生产者坏了" | 同上：先恰等类型再查词汇 | `http/hostile_shape_body_is_strict_json`（逐行严格 JSON）、`boundary/closed_vocabularies_refuse_impersonators` |
| `class SneakyStatus(dict)`，其 `get()` 对 `target_source` 回答与底层映射不同的值 | `isinstance(raw, dict)` 放过子类，投影读到的是子类**编造**的值 | 容器必须 `type(raw) is dict`，**恰等** | `http/only_an_exact_dict_is_a_status_container`（6 个容器） |

收紧必须被证明**不是"什么都不接受"**：诚实表（`True`/`False` 旗标、三值
source、两个 startup token 共 3+4+2 行）在真 HTTP 上仍逐字透传，三个闭合器
另有一张"在全部词汇上全定义"的直查表。敌意 shape 矩阵 36 行 × 数值矩阵 19 行
的键集**并起来恰等** `PROBE_STATUS_KEYS`，投影面没有未测字段。

### B8：History 入库边界的原语一律恰等类型

| 字段 | 缺陷世界兑现的形状 | 现契约 | 判别器 |
|------|--------------------|--------|--------|
| `latency_ms` | SQLite 的 INTEGER affinity 会把 `'12'` 静默**转换**后入库，表里存下引擎从未产出过的 coercion；`12.0`/`True`/`Decimal(12)` 同理 | 只接受 `type(latency) is int`，且 `0 <= latency <= 120000` | `boundary/latency_defects_all_refused_with_the_rejection_code`（11 例矩阵，含 `bool`、整值 float、字符串、`nan`、`Decimal`、`LyingInt`） |
| 失败槽位 | `"NONE"`/空串/`0` 被当成 NULL | 失败周期必须**恰为 `None`**（6 行表） | `boundary/failed_slot_demands_exact_null` |
| `epoch` / `cycle_id` / `raw_ip` / `egress_change` / `status` / `error_code` | `Decimal("1.0") == 1`、`LyingStr("8.008.8.8")` 靠重写 `__eq__` 赢过 canonical-identity 门 `ip != raw_ip`（那句比较是向**候选者**提问的），于是非 canonical 的原文被**洗白**成合法出口 | 六个原语全部 `type(...) is T` 先判，再进入范围/词汇/等值判定 | `boundary/boundary_primitives_are_exactly_typed`（20 行）、`boundary/every_exact_type_refusal_carried_the_rejection_code` |

**每一次恰等类型拒收都必须被命名**：断言 `last_error_code ==
history_probe_result_rejected`、`persisted_total` 纹丝不动、
`rejected_total` 恰 +1、timeline 行数不变。这条纪律是 B6 的
`null_cycle_id_refused_with_the_rejection_code` 的推广——一个形状缺陷必须在
**边界**被报告为"生产者缺陷"，而不是等到写入撞 DDL 墙才伪装成"存储坏了"。

### 撤销变异取证（R2）

| 变异 | 被抓 |
|------|------|
| `closed_probe_bool` → `bool(value)` | 4 FAIL：`http/closed_probe_bool_table`、`http/closers_never_raise_on_unhashable`、`http/hostile_shapes_always_collapse`、`http/liar_bool_not_a_flag_refused` |
| source 去掉恰等类型前置 | 崩溃即 FAIL：`TypeError: cannot use 'list' as a set element`（**这正是**漏洞本体——一次读取变 500） |
| startup token 去掉恰等类型前置 | 同上，崩溃即 FAIL |
| `type(raw) is not dict` → `isinstance` | 1 FAIL：`http/only_an_exact_dict_is_a_status_container`（shell 模式下另抓 S0 门 (6)） |
| latency 回到 `_as_int` 判等 | 7 FAIL：`boundary/latency_defects_all_refused_with_the_rejection_code`、`boundary/every_exact_type_refusal_carried_the_rejection_code`、`boundary/closed_vocabularies_refuse_impersonators` 等 + S0 门 (6)(7) |
| 词汇 membership 去前置 | 3 FAIL |
| `epoch` / `cycle_id` 回 `isinstance` | 各 6 FAIL |
| `egress_change` 回 `isinstance` | 3 FAIL |
| `raw_ip` 回 `isinstance`（两处同文件） | 6 FAIL：含 `boundary/baseline_survives_failed_egress`、`boundary/replay_moves_no_baseline` |

### 一条取证工具自身的教训

首轮全车道扫描报 `306 passed / 1 failed`，红在新加的 S0 反 coercion 门
（`a probe gate coerces (isinstance/bool/_as_int is back)`），AST 扫描把命中
指到 `web/incident_history.py` 的 `isinstance(raw_ip, str)`。那不是回归，而是
**我自己的变异工具的残留**：它对多片段 spec 是"逐段快照原件"，而同文件的两段
里第二段快照已含第一段的变异，按序还原就把变异**当原文写了回去**。修法是
两阶段——先把全部原件读完，再一次性写入；修好后 `b8_ip_type` 单跑 6 FAIL 且
`restored` 后工作树与目标内容逐字节一致。该轮的 `306/1` 与同时段的其余结果
全部作废重跑（污染的运行不是证据），§10 的数字来自重跑后的同批扫描。

门数移动：`EXPECTED_PASS` 288 → **307**（+19），S0 6 → 8（两条静态反 coercion
墙），S5 233 → 250（boundary 30 → 35，http 30 → 42）。S1/S2/S3/S4 不动。
VERSION / `MONITOR_WEB_VERSION` 仍为 `0.3.1`，功能评审头不携带发布准备。

### R2 轮的实测取证

dev 主机（Windows/Git Bash）同批全车道扫描：probe-ingest **307/0**、probes
138/0、`m05` 全绿、hist 240/0、jr 371/0、jr-deploy 292/0（20 SKIP）、p2b 集成
33/0（4 SKIP）、e1/e2/e4/e4diag/m2 全绿、journal-time-compat 15/0、
packaging 268/0。带时序的两组（`threads` 25 + `http` 42 = 67 条）在 CI 网络
守卫下连跑 **20 轮**：20/20 全绿，零非零退出。shellcheck（`-S warning`）对两条
探测车道均零告警。

**Linux CI 是真实门禁**：R2 头 `57c6fca` 首试 **10/10 全绿**
（`shell-tests` 36468769284，`monitor-packaging` 36468769283），Linux 实测数字
与 dev 主机**逐条相同，没有任何门因平台差异而 SKIP 掉**：probe-ingest 307/0
（新硬门数）、probes 138/0、hist 240/0、jr 371/0、jr-deploy 464/0/0-SKIP、
p2b 集成 132/0/0-SKIP；packaging fixture 631/0、root 646/0；三条基线
（22.04/24.04/26.04）的 `E3_M1_SYSTEMD`、`E3_M2_LIVE`、`E3_M3_DEPLOY`、
`E3_M3C_PHASE2_LIVE`、`E3_M3C_PHASE3_LIVE` 全 PASS。

另有一条取证纪律值得写明：本轮曾在**同一工作树并发了变异实验与车道扫描**，
于是 `306/1` 的红与一批 `e2` 红都不是被测契约的状态，而是测量环境的状态。
两者全部作废重跑，本节的数字来自"扫描期间工作树零写入"的那一批。

## 16. 发布准备（Monitor 0.4.0）

功能评审 **R3 = PASS / APPROVE**，功能代码**冻结**在 `27e165c`。其上只允许一个
**仅 release-prep** 提交，内容限定为三类：

1. **版本元数据**：`monitor-v2/VERSION` 与 `web/server.py` 的
   `MONITOR_WEB_VERSION` 从 `0.3.1` 抬到 `0.4.0`（两者由 `test-monitor-v2-ui.cjs`
   的等值断言耦合，必须同批移动）。
2. **钉住"当前发布版本"的断言**：`hist` 2 条、`jr` 1 条、`probes` 1 条、
   `probe-ingest` 2 条，以及 `test-monitor-packaging.sh` 里 T26 的**段落标签**
   （它描述"当前候选"，数值仍从 VERSION 动态读取，不是断言）。**各车道门数不变**：
   probe-ingest 仍 307、probes 仍 138、hist 仍 240、jr 仍 371。
3. **版本立场措辞**：本文头部、§10 S3 行、§12，以及 `monitor-v2/README.md`
   新增的 `### 0.4.0` 变更条目。

刻意**不**机械替换的 `0.3.x` 字样（它们是历史与 fixture 证据，不是过期元数据）：
`install.sh` 与 `tests/test-install-host-deps.sh` 里描述 0.3.1 依赖 bootstrap 的
注释、`.github/workflows/tests.yml` 里描述实机门所及祖先 release 的注释、
`monitor-v2/README.md` 的 `0.3.0` / `0.3.1` 条目、`deploy/README.md` §20/§21 的
轮次记录、`docs/monitor-v2-network-probes-p3a.md` 的版本立场、本文 §14/§15
里"评审头 `VERSION` 仍为 `0.3.1`"的实测记录（那对 `27e165c` 恰好为真）、
packaging T22–T26 里描述被升级**祖先** release 的注释，以及
`tests/monitor-probes/probe_ingest_groups.py` 夹具的 `monitor_version="0.3.1"`
占位值——它只是 `created_by_version` 的写入样本，没有任何门把它与 VERSION 比较。

判别力（发布准备也要能被证伪，**已实测**）：只把 `monitor-v2/VERSION` 退回
`0.3.1` → hist / jr / probes / probe-ingest **各 1 条**变红（共 **4**）；
`VERSION` 与 `MONITOR_WEB_VERSION` **同时**退回 → 再点亮 hist 与 probe-ingest
各自的 `MONITOR_WEB_VERSION` 门（共 **6**，即当前版本断言的全部）。两组实验测完
后都把两个文件按字节还原，`git diff` 只剩这两行。packaging 不在此列：T26 的候选
版本是从 VERSION **动态**读的，段落标签只是散文。另注：`tests/test-monitor-v2-ui.cjs`
里有一条"server 常量 == VERSION 文件"的等值断言，它把两个数字耦在一起，但该车道
**未接入 CI**，所以 CI 可见的耦合由上面那 2 条 `MONITOR_WEB_VERSION` 门承担。
因此这些断言是真承重，不是装饰。

边界：无行为、无 schema、无端点、无调度器、无部署事务变更；不碰 sing-box 与
`sbox-cm`；不合并（仍需显式指令）；不部署、不访问生产。CI 在该发布准备头上
重跑**全量**。

发布准备头的本地取证（dev 主机 Windows/Git Bash，扫描期间工作树零写入）：
probes 138/0、probe-ingest **307/0**、hist 240/0、jr 371/0、jr-deploy 292/0
（20 SKIP）、p2b 集成 33/0（4 SKIP）、`m05`/`e1`/`e2`/`e4`/`e4diag`/`m2` 全绿、
journal-time-compat 15/0、packaging 268/0（T27 的 15 条在无符号链接平台 SKIP，
由 Linux 覆盖）；`threads`+`http` 67 条在 CI 网络守卫下连跑 **20 轮**全绿；
shellcheck `-S warning` 对本轮改动的 5 条车道（hist / jr / probes / probe-ingest /
packaging）零告警。**Linux CI 才是真实门禁**，该头的全量数字以 CI 为准。
