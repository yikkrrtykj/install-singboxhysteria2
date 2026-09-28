# Monitor 0.3.x —— PR-3B 探测激活 + 结果入库（issue #33 Phase 3，功能评审头）

状态：已实现，**功能评审头**（`VERSION` 与 `MONITOR_WEB_VERSION` 保持
`0.3.1`；不合并、不部署）。基线：`main @ 32a06ce`（PR-3A 引擎）。
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
  `EXPECTED_PASS=254`，含 204 条行为判别器）+ `tests/monitor-probes/`
  （行为夹具 + CI 网络守卫），`tests/test-monitor-v2-probes.sh` 126→138，
  `tests/test-monitor-v2-hist.sh` 239→240，
  `tests/test-monitor-packaging.sh` +21：6 条 diagnostics 清单/发布树审计
  （套件自身清单与库声明恰等、禁目录通配 staging、逐文件强制、release 内
  三文件恰等、无 `__pycache__`；所有平台均执行）+ 末尾新增 T27 15 条端到端
  回滚证明（仅在可建符号链接的平台执行，Linux CI 为真实门禁）。
- 明确偏差：见 §11。

## 2. 实现前勘察（PR-3A §2 预留槽位的兑现）

| 对象 | PR-3A 记录的边界 | PR-3B 的兑现 |
|------|------------------|--------------|
| `webapp.py` | 无探测槽位 | 唯一接线点：`history.open()` 之后构造并 `start()`，`finally` 内 `probes.stop()` 先于 `history.close()` |
| `web/broker.py` | publisher 的 write-alongside 先例 | **未使用**：探测节奏与 publisher 完全隔离（§3） |
| `web/incident_history.py` | 严格 v2、表集恰等 | v3：新增探测表 + 两个迁移 rung + 探测边界 + 探测健康平面 |
| `web/server.py` | 唯一有界读面 | 同一读面增两个键；调度器状态经闭合投影，deny-by-default |
| `deploy/lib/monitor-deploy-lib.sh` | staging 清单不含 `diagnostics/` | 显式 3 模块清单 + 恰等审计（多余/缺失均 fail-closed）；回滚 schema 门 |
| `singbox-monitor.service.in` | 地址族已覆盖 | **零改动**（`RestrictAddressFamilies` 无需放宽） |

## 3. 激活契约（全部强制、全部有判别器）

1. **显式 opt-in，且只有一样东西**：环境变量
   `SINGBOX_MONITOR_PROBE_TARGETS_FILE` 指向的 JSON 文件存在且形状恰等。
   * 变量未设 → DARK，`startup_error=target_file_not_configured`，零线程、
     零 I/O、零周期。
   * 变量指向缺失/目录/畸形/非恰等文件 → DARK，
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
4. **生产目标集**：`ProductionEndpointSet`（frozen dataclass）+ 
   `production_targets()` 仅追加"构造引擎 spec"，**不添加任何 timeout 策略**。
5. **线程纪律**：恰好一个 daemon 线程（名 `monitor-probes`）；`start()` 幂等；
   `stop()` 后不再启动；周期内异常只累加闭合计数，循环存活；慢周期不阻塞
   `status()`/`stop()`（锁 convoy 判别器）。
6. **状态词汇闭合**：`status()` 的 10 个键 + `target_source` 三值 +
   `startup_error` 两 token，是外部世界能知道的**全部**。调度器不读写文件系统
   （除那一次 opt-in 文件读取），不接触 DB 之外的持久化。

## 4. History schema v3

- 单表 `network_probe_samples`，19 列 = 周期身份（`epoch`/`iso_utc`/`run_id`/
  `cycle_id`/`result_version`）+ 四槽位 `(status, latency_ms, error_code)` +
  `egress_ip` + `egress_change`。引擎 v1 结果**扁平成一行**，不建第二张表。
- CHECK 墙 + 索引：状态/错误码/变更值域、latency 区间、`egress_ip` 的
  canonical-text 约束、`result_version=1`、`cycle_id` 唯一性；套件用 18 条
  raw-INSERT 逐条撞墙，并以一条合法行证明墙不是误杀。
- 入库边界 `_probe_boundary_validate_locked`（不信任引擎）：键集恰等、状态/
  码/版本在闭合词汇内、latency 为 `0..PROBE_LATENCY_MAX_MS(120000)` 整数、
  `epoch` 与 now 偏差 `<= PROBE_CYCLE_FRESHNESS_SECONDS(30.0)`、
  `cycle_id` 必须是 32 位 hex（**非字符串也在此拒绝**，不让 TypeError 逃出
  边界）、`run_id` 绑定、`egress_ip` 只接受再canonical 化的**全局**地址。
- `_canonical_global_ip` 与引擎 `_canonical_ip` 是**逻辑同一**（套件用 AST
  比对函数体，允许注释/函数名不同，不允许语义漂移）：loopback/私有/保留/
  文档/链路本地（含 169.254.169.254）地址在 DB 侧同样不可能落库。
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
  `unchanged`；不同 → `changed`。
- 判别器覆盖：重启后首条仍是 `unchanged`（不伪造事件）；窗口过期后
  `unknown`；绕过边界用 raw writer 写入私有地址行 → 基线被拒（防御纵深）；
  多播地址（`ipaddress` 判为 global）按引擎语义放行，链路本地元数据地址拒绝，
  前导零形式 `8.008.8.8` 被 canonical-text 等值门拒绝。
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
10 个键，逐键做值域收敛（bool / 三值 source / 两 token 的 startup_error /
有限实数 / 非负整数）。调度器缺失、损坏、抛异常或**说谎**（返回任意字符串、
路径、端点名）时：`probes=None` 或该字段被压回闭合值，绝不透传。会话鉴权、
GET-only、loopback 绑定契约均不变。车道 S5 用真 `build_server` 断言投影键集
与 `status()` 键集**恰等**，并断言响应体不含 `/etc`、路径、`targets.json`
或 `api.ipify.org`。

## 10. 测试矩阵

| 车道 | 判别器 |
|------|--------|
| S0 静态 + 镜像（6） | `py_compile` 全集；history↔engine 词汇**活值**恰等；IP 门 AST 同一；bounds/v3/`_PRUNE_SOURCES` 自洽；scheduler↔server 状态面恰等（含 `PROBE_STARTUP_TOKENS`）；`web/` 零 `diagnostics` import |
| S1 回滚门接线（6） | 调用点在首处变更之前；拒绝文案承诺零变更；整个门 helper 区无写语句；库恰一次以只读 URI 打开；目标 release 读者不继承调用方 `sys.path`；调用点 die-check |
| S2 回滚门决定（21） | v3→v3/v4 放行，v3→v2、pre-history、缺失 release、无版本声明、非数字、负数、非数据库文件均拒绝；无库放行且不创建任何文件；真 v3 库（由被测模块自建）同判；拒绝文案含两个版本号、不含 fixture 路径；DB 字节与目录集不变；整棵发布树零 `__pycache__`（`-B` 契约） |
| S3 出货面卫生（10） | deploy 树零引用 opt-in 变量；生成的 `monitor.conf` 无探测键（且键集可枚举，门非空转）；conf 读取器白名单无探测键；`webapp.py` 以 `ProbeScheduler(history)` 唯一构造、不传 cadence/targets；调度器 AST 只有一个 `open(...,"r")`、无写/unlink/`sqlite3`/`shutil`；VERSION/`MONITOR_WEB_VERSION` 仍 0.3.1；tests.yml 已接线 |
| S4 CI 网络守卫自检（7） | 公网 TCP connect / UDP sendto / DNS 解析 / 非 loopback bind / 链路本地元数据地址全部**被拒**；loopback connect 与 `localhost` 解析放行 |
| S5 行为组（204，全程在守卫下运行） | boundary 25（36 例拒绝矩阵）、durable 16、schema 27（fresh/v1→v3/v2→v3、崩溃注入、pre-v3 运行时、18 条 CHECK 墙）、retention 12、health 21、activation 33（DARK 默认不起线程、16 例畸形 opt-in、闭合 token/常量冻结）、e2e 21（真调度器 + 127.0.0.1 TLS 假服务）、threads 25（20× start/stop、慢周期不 convoy）、http 24（真 server、401、恰等投影、liar/raiser） |

**loopback-only 是构造性证明，不是 grep**：`tests/monitor-probes/
no_public_network.py` 装在 CPython audit 钩子上（`socket.connect`/
`socket.bind`/`socket.sendto`/`socket.getaddrinfo`），在被审计操作发生**之前**
抛异常即失败；它位于所有库抽象（`socket`、`http.client`、`ssl`、引擎的
spec 构造）之下，套件日后新增的 import 也绕不过。S5 的 204 条全部在该守卫
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
增加该套件步骤。**Linux CI 是真实门禁**；dev 主机（Windows/Git Bash）实测
`254 passed / 0 failed` 连续 5 次，`probes=138`、`hist=240` 未因本次生产
改动移动，packaging 在该平台 `268 passed / 0 failed`（T27 因无符号链接
SKIP，Linux pass 覆盖它）。

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
`VERSION` 保持 `0.3.1`（功能 PASS 后再以**仅 release-prep** 提交升到 `0.4.0`
并重跑全量 CI）；不合并（需显式指令）；不引入浏览器/前端；不改 unit 模板；
不改 `monitor.conf` 键集。

## 13. 已知限制

- 探测基线依赖同一 run 的库；跨 run 的库合并（例如手工搬 DB）不在本阶段
  语义范围内。
- `PROBE_LATENCY_MAX_MS=120000` 是"任何真实周期之上、无界整数之下"的评审
  区间，不是容量承诺。
- 网络守卫拒绝的是本套件进程内的公网地址族操作；它不替代 systemd 沙箱，
  生产主机的出站面仍由 unit 的 `RestrictAddressFamilies`/`ProtectSystem`
  与操作者投放的目标文件共同决定。
