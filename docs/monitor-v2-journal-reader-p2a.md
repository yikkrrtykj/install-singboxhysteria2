# Monitor 0.3.x 前置 —— sbox-journal-reader PR-2A（issue #33 Phase 2，DARK 交付）

状态：已实现，**整体 DARK**（本 PR 不接线、不激活、不部署任何东西）。设计以
issue #33 冻结链为准：v1 (5776315515) → R1–R11 → v2 → B1–B4 → v3 → C1–C5 →
v4 → D1–D5 → **v5 (5777432304)** → 签署 (5777527361, APPROVED/FROZEN)。
基线：`main @ b6e3307a366cb4c971d91c570fd77a32439174ce`（PR #44 的精确 merge SHA）。

## 1. 结论性摘要

- 新增包：`monitor-v2/journal_reader/`（12 个 stdlib-only 模块）；unit 模板
  `monitor-v2/deploy/singbox-journal-reader.service.in`；运行入口
  `monitor-v2/deploy/app-bin/sbox-journal-reader`；部署库新增 7 个
  `sbmon_sboxjr_*` DARK helper；测试 `tests/test-monitor-v2-jr.sh`（364 检查，
  硬计数门）+ `tests/journal-reader/jr_groups.py`（20 组 305 项行为检查）+
  LIVE 门 `tests/journal-reader/test-jr-live.sh`（三基线矩阵，
  `SBOX_JR_REQUIRE_LIVE=1` fail-closed，无 SKIP 绿灯）。
- **Dark 证明（判别式，套件 S0 常驻断言）**：`sbmon_stage_release` 清单不含
  reader；`install-monitor.sh` 对 `sbmon_sboxjr_` 零调用点；Monitor
  web/collector 对 `journal_reader` 零 import；`VERSION` 保持 0.2.0；
  reader 全进程只读一个环境变量（`SBOX_JR_UNIT`，严格正则校验）。
- 探索期内发现并修复的实现级缺陷 3 处（均先由判别测试暴露）：B1
  "ERROR/WARN 无 class → other+fp" 路由丢失（cls 未置 None）；row-3/4 repoll
  结算后 `reset_from_now` 拒绝继续；overflow-fold `limited++` 在 header 之后
  才递增导致漏计。

## 2. 最终状态模型（签署冻结，逐点实现）

- `committed = {v, seq, epoch, durable boundary, tagged source anchor
  (cursor|since)}`；`pending = {v, run, seq, epoch, boundary,
  source_end(cursor-only)}`（`state.py`，`validate_committed/validate_pending`
  为唯一守门人，全部 tmp+fsync+rename+dir-fsync，0600）。
- C1 五步提交配方：pending 先行落盘 → ev 文件 fsync/rename/dir-fsync →
  committed 原子替换 → unlink pending + dir fsync → 心跳/保留。scratch 命名
  `X.tmp-<run>`，启动时 `clean_scratch` 回收。
- C2 恢复表 rows 1–8 全量实现（`evaluate_recovery`）。**row 2 执行与原周期
  完全相同的逻辑 step-4**（committed.seq/epoch/source := pending，boundary →
  NONE，然后 durable 移除 pending），绝不改写已落盘 ev 文件；rows 5/6/8 以
  `journal_state_corruption` fail-closed 且零写入。stale pending（row 4）经
  配方 unlink 后按 row 1 继续。

## 3. 游标与数据源（D1/D3/D5/C5/B6）

- 游标完全不透明（D5）：`cursor.py` 是唯一校验器 —— str、1..4096 UTF-8
  字节、拒绝控制字符/NUL；绝不假设格式、绝不排序解释、绝不分片。journalctl
  子进程一律 list-form argv 直传，绝不 shell 插值。
- 尾游标（C5，B1 修正）：`journalctl -n 0 --show-cursor`；提取器先匹配
  **真实 framing** `^-- cursor: (\S+)$`（源码级验证：systemd v249/v255/main
  均以 `-- cursor: %s` 打印），fixture 形式 `^cursor: (\S+)$` 作为显式第二
  正则保留；两者之后一律走同一个 D5 不透明校验器，校验器本身未动。
  首个可提交游标之前，durable since 回退串逐字复用（since→cursor 只在第一次
  提交时转换，且 row-2 恢复保留同一转换语义）。
- D1 六行子进程结局表：通用 rc≠0 → fail-stop、committed 零移动、绝不猜测
  陈旧游标；backlog 截断（C4，50,000 解码条目封顶，自杀 SIGTERM =
  truncated_batch）经"最后一条实际处理过的可用 `__CURSOR`"提交；批中途失败
  整批丢弃且游标不动。SOURCE_GAP epoch 只能经评审后的操作员 reset 产生
  （`reset --from-now`），seq 永不重置。
- B6 批完整性契约（review #46）：任何非空输出行若不能 decode 成 dict 且带
  通过 D5 校验的 `__CURSOR`，**整批** `journal_cursor_invalid` 且优先于 rc
  判定——committed 游标绝不跨过它；`pfail` 只计"游标可用、但
  MESSAGE/timestamp 载荷不可用"的条目（这类条目照常提交并推进游标，防
  re-poll 死循环）。D1 row 5 因此只对应"stdout 为空 + rc≠0"的源故障形态。

## 4. Eligibility 与分类（B1/B2、cv=1、v3-B2）

- B1 决策表：ERROR/WARN 恒具资格（不看 PRIORITY）；INFO/DEBUG 丢弃并计数
  （`info_dropped`）；有 token 的 class 命中即资格；无 token 且 class 未命中
  且 PRIORITY 可解析为 0..4 → `other`+fp 路由（cls=None 交 reader 定 fp）；
  其余 drop + `nomatch_dropped`，present-but-unparseable 记
  `priority_unusable`。
- 分类器 cv=1 有序首匹配（顺序即契约）：dns > dial_timeout > reset >
  net_unreachable > tls_handshake > quic_error > eof_cancel > other。
  N1/N2/N3 负例锁定：裸 `dial ` 不判 dial_timeout（须 timeout 专词或
  `dial (tcp|udp)…timeout` 距离式）；裸 `quic` 不判 Hysteria2（tag 优先、
  显式协议词其次、否则 OTHER）；协议 ⟂ 失败类（2026-09-22 事故锚点保持
  `cls=dial_timeout` 且 `proto=Reality` 双字段）。Reality tag=`vless-in`，
  HY2 tag=`hy2-in`。

## 5. 隐私边界（R4 与 exchange 白名单）

- 交换文件只携带白名单字段（`schema.py`：header + 事件，精确键集、跨字段
  确定性规则 `fp` 仅随 `other`、`dcls` 仅随 port），原始日志文本、主机名、
  IP、UUID、口令、secret、配置路径在字节层面就不可能跨界 ——
  `normalize.py` 的归一化结果只是匹配输入，无任何字段可承载它。
- 指纹只有一种：HMAC-SHA256(key, template)[:16hex]（R4），key 32B 位于
  `state/hmac.key` 0600；模板 = 去引号跨度/主机/IP/路径/@/高熵 token 后的
  小写纯字母 ≤12 字符词的前 24 个；残余不安全 → `fp=None` + `limited++`。
  不存在未加盐原像。
- key 装载/创建的完整 fail-closed（B8，review #46）：符号链接键路径直接拒
  （绝不跟随）；`O_NOFOLLOW` + `fstat` regular-only；POSIX 模式必须恰为
  0600（chmod 抵抗 umask）；内容必须恰为 32 字节（读 33 判长，绝不静默重建
  或修复）；创建路径写失败/fsync 失败 ⇒ 删除半成品再抛错（下次干净重试）；
  O_EXCL 竞争仅经由同一安全装载器重开；新建成功后键文件与所在目录双双
  fsync 方可使用。
- stderr 面恰好 5 处、全部 `[sbjr] failure=<code>` / `reset=ok` 消毒码；
  子进程 stderr 直接 DEVNULL。套件含隐私哨兵组：任何哨兵字符串出现在跨界
  字节流即失败。

## 6. Ingest 契约（v2-R6 / v3-B4，PR-2B 的验收合同）

`ingest_contract.py` 在 PR-2A **刻意惰性**（无人 import）：
`journal_terminal_seq` 是唯一连续性权威；文件严格从 terminal+1 升序结算、
不跳过；失败 apply 不结算并阻断更高 seq 至本周期末；终止性 REJECT（schema
非法）恰好推进 terminal 一次并计一次 rejected（无 10 秒死循环，其后合法文件
不记 gap）；被跳过的缺失 seq 在发现时恰好计一次 gap，迟到者按 `seq<=terminal`
规则忽略、不重计不撤销；合法文件的 apply 与 terminal 推进在 PR-2B 必须是
同一 SQLite 事务（`apply_fn` 即注入点）。T24/T25/T27a/b/c 全部为绿色判别
测试（`[ingest]` 组）。单文件硬顶 256KiB、文件名语法 `ev-<seq>.jsonl`、
仅 regular 文件。

## 7. 保留、心跳与耐久故障消毒（B4/B5，review #46）

- out/ 采用最旧优先双限驱逐（720 文件 / 8MiB），驱逐只发生在 committed 已
  越过对应 seq 之后；`hb` 文件每周期重写（Monitor 侧以 >180s 年龄独立判
  staleness）；空窗口只写心跳、零状态移动（D1 row 2）。
- B5：720/8MiB 是硬上界，因此"上界不可验证或不可执行"的一切故障都是
  fail-stop（消毒 `journal_writer_failed`）：目录枚举失败、ev 候选 stat
  失败、候选非常规文件（符号链接/目录/_FIFO 冒充 ev 语法）、仍有界超标时
  unlink 失败、GC 后目录 fsync 失败。仅仅"候选消失"（ENOENT）不构成增长，
  跳过并继续。运行周期在保留失败时立即终止——绝不带着失控的保留继续
  生产新 ev 文件。
- B4：所有预期内的状态 write/fsync/unlink OSErrors 统一经由 `_durably`
  包装转换为 `ReaderFailure(journal_writer_failed)`；异常 repr 只含消毒码，
  绝不泄漏 traceback、路径或载荷（"failure str is the bare code" 判别测试）。
  已加载状态违规则仍是 `journal_state_corruption`——writer 消毒不吞并
  corruption 家族。C1/C2 不变量在注入点之后仍可行：row-2 重放、row-4 结算
  逐一被行为测试覆盖。

## 8. 部署模板与 helper（DARK）

- unit 模板：`User/Group=@SBJR_*@` 占位（身份 = 精确的
  {sbox-jr, systemd-journal, nologin, /nonexistent}，R7，绝不 Supplementary
  -Groups 静默补权）；`RestrictAddressFamilies=AF_UNIX`（reader 无 TCP 面）；
  ProtectSystem=strict + 单一 `ReadWritePaths=@SBJR_DATA_ROOT@`；空
  CapabilityBoundingSet；`StartLimit*` 放 `[Unit]`（三基线放置兼容）。
- helper 七件套（monitor-deploy-lib.sh，SBMON_FIXTURE=1 可全离线演练）：
  身份校验（B3，review #46）在任何变更前先做**精确**核验：shell ∈ nologin、
  home == /nonexistent、主组 == sbox-jr、有效组集恰为 {sbox-jr,
  systemd-journal}（缺组与多组都拒绝）；既有账户走"仅校验、零变更"路径
  ——异常既有身份的 passwd/group/id 存储前后逐字节不变（套件 S5 用 PATH
  桩逐场景判别，含拒绝原因 field= 码、mutlog 零变更、diff -r 字节一致）。
  仅"账户完全缺失"分支可创建：groupadd（若缺）→ useradd → usermod，末尾
  仍以精确校验收敛；绝不 root fallback、绝不静默修复。数据树
  root:sbox-jr 0750 / state 0700 / out 2750 sbox-jr:sboxweb（符号链接全部
  fail-closed）、显式 12+1 文件清单 staging、模板渲染、unit 安装镜像
  （daemon-reload 仅在内容变化时）、可读性探针（runuser 断言组）。
  **没有任何 enable/start/restart 调用点**；install-monitor.sh 零引用。
- 运行入口 wrapper（B7，review #46）：库路径与解释器是**冻结常量**
  （`SBJR_LIB_DIR=/usr/local/lib/singbox-journal-reader`、
  `SBJR_PYTHON3=/usr/bin/python3`），不接受任何 `SBOXJR_*`/`PYTHONPATH`
  运行时 env 面；生产运行时配置只剩 unit 内冻结的 `SBOX_JR_UNIT` 一条通道。
  测试与 LIVE 的注入路径是直接 `python3 -m journal_reader.reader` + 显式
  PYTHONPATH，从不经由本 shim。库层的 `SBOXJR_*` 默认值仍是部署期可覆盖
  常量——与被移除的**运行时**面是两个不同契约。
- 生产 sbox-jr 用户/组/目录/unit 的创建与激活属于 PR-2B，且需单独评审。

## 9. 测试与 CI 接线

- `tests/test-monitor-v2-jr.sh`：S0 静态 + DARK 判别门、S1 unit/wrapper（含
  B7 冻结常量/零 env 面判别）、S2 CI 注册锁、S3 journal-time Python↔shell
  等价（T31，含 4 个 fail-closed 对偶）、S4 20 组 305 项行为检查（含 T28 全
  矩阵：每个耐久边界（含目录 fsync）前后崩溃 × 恢复表、reset_commit、崩溃
  点交叉探针；新增 `dur` 组 21 项：B4 逐步注入消毒 + B5 保留 fail-closed；
  cursor 组含真实 `-- cursor:` framing 判别；fp 组含 B8 键硬化 12 项；d1 组
  含 B6 批完整性 8 项）、S5 R7 身份 PATH 桩 22 项（B3：五类分歧 × 拒绝码/
  零变更/字节一致 + 两条创建顺序锁 + 幂等）。硬计数门
  `EXPECTED_PASS=364`：任何静默跳过即红。POSIX 语义在 Windows 开发机上退化
  为进程内布尔，计数跨平台稳定。
- tests.yml：fast-checks `bash -n` ×2；monitor-regression 新增本套件步骤；
  兼容矩阵在既有 systemd readiness gate 之后新增 `sudo -n env
  SBOX_JR_REQUIRE_LIVE=1 bash tests/journal-reader/test-jr-live.sh`。
- LIVE 脚本（仅三基线）：JSON 输出一律 `-o json` ——journalctl 长选项表已
  对 v249/v255/v258 源码核验，**不存在 `--output-format`**（getopt 立即
  EINVAL，毫秒级 rc≠0；首轮 CI 的 L3/L6 红即此缺陷，曾被误读为游标契约
  破裂）。失败路径打印 rc + stderr 首两行，游标值经 sed `<cursor-redacted>`
  脱敏。L2 真实 journalctl 尾游标遥测（真实 `-- cursor:`
  framing 提取 + D5 校验器 + 4096 上界假设探针，观测值断言 <4096，不钉死；
  游标值经 0600 文件传给校验器，绝不进 argv/日志）；L3 `--after-cursor` 对
  不透明游标的原样接受；L4 真实 Reader 先 `startup()` 再两个周期（状态
  读取一律按 `(obj, ok)` 解包判 ok；C1 事后状态合法、pending/scratch 无
  残留、committed 0600、ev 全过严格 schema、MESSAGE/PRIORITY 不跨界、空
  周期零移动 + hb）；L5 渲染后 unit 过 `systemd-analyze verify`（镜像生产
  步的 UNRELATED_NOISE fail-closed rc 契约）与支持基线上的 `security
  --offline`；**L6（B9，review #46）**：在三基线 runner 上创建一次性
  exact-shape `sbox-jr` 身份（nologin//nonexistent home/主组 sbox-jr/精确组集，先断言形状），
  再经 `runuser -u sbox-jr` 实证尾游标提取；随后以 `systemd-cat` 注入
  **一条确定性探针日志**，要求该身份在自己尾游标的严格之后 decode ≥1 条
  `__CURSOR`（quiet unit 不可能饿死该证明），再跑完整 Reader 周期（C5 选源
  + C1 配方 + state 0600 + 32B 键 0600）。Reader 周期所用的 `journal_reader`
  包先复制进 `$TMP/l6-lib`（`a+rX`，`$TMP` 设 0711 仅供穿越）——一次性系统
  用户不可穿越 runner 的 home 树，直接 PYTHONPATH 进仓库会静默
  ModuleNotFoundError。root journalctl 不作为该权限证明的替代，全程无 root
  fallback，证明完毕立即 userdel/groupdel 并断言无残留。临时 sing-box.
  service mock 仅在缺失时创建、退出时删除；不 enable/start 任何单元。

## 10. 本 PR 明确不包含（PR-2B / 后续）

生产身份与目录创建接线、unit 实装与 enable/start、`install-monitor.sh`
任何调用点、Monitor 侧 schema-v2 ingest 激活（`incident_history` 新表）、
`sbmon_stage_release` 携带 reader、VERSION 0.3.0、任何 UI/查询端点、探测、
出口 IP、断网判定。P1 §10 的边界承诺在本 PR 逐条保持：sbox-jr +
systemd-journal 仍是唯一被接受的 journal 读取模型；不新增 sudoers、不触碰
root fallback、不触碰生产 VPS。

## 11. Review #46（5780022668）B1–B9 修复记录

| 项 | 修复 | 判别测试 |
|----|------|----------|
| B1 | `cursor.py` 双正则：真实 `-- cursor:` framing 优先，fixture 形式显式其次；D5 校验器一字未动 | cursor 组 +6；LIVE L2 三基线真实解析 |
| B2 | LIVE L4 先 `rd.startup()`，`load_committed/load_pending` 一律 `(obj, ok)` 解包 | LIVE L4 全绿（此前 CI 红即缺陷本体） |
| B3 | `sbmon_sboxjr_validate_identity` 精确核验 shell/home/主组/精确组集；既有账户零变更路径；创建仅限完全缺失分支且顺序锁定 | 套件 S5（PATH 桩，22 项，含 passwd/id 字节一致断言） |
| B4 | `_durably` 把所有预期状态 write/fsync/unlink OSError 消毒为 `journal_writer_failed`；corruption 家族不吞并 | dur 组 12 项（注入 + 恢复不变量 + 裸码 str） |
| B5 | 保留上限不可验证/不可执行 = fail-stop；消失候选除外 | dur 组 9 项（枚举/stat/常规性/unlink/fsync/周期级 fail-stop） |
| B6 | 非空行 decode 失败或游标不可用 ⇒ 整批 `journal_cursor_invalid` 且优先于 rc；`pfail` 只记载荷缺陷条目 | d1 组 +8（含"游标绝不跨过坏行"“payload-only 仍提交”） |
| B7 | wrapper 冻结 `SBJR_LIB_DIR`/`SBJR_PYTHON3` 常量，删除全部运行时 env 面 | S1 +2（常量正判 + `${SBOXJR_`/`PYTHONPATH:+` 负判） |
| B8 | hmac.key：symlink/非常规/fstat/0600/恰 32B/写失败删半成品/竞争仅走安全装载/双 fsync | fp 组 +12（unittest.mock 注入，平台稳定） |
| B9 | LIVE 新增 L6：CI-only 一次性 exact-shape 身份，`runuser` 实证读权限 + 确定性探针条目（尾游标后注入一条 `systemd-cat` 日志并要求严格之后 decode）+ 完整 Reader 周期（包副本 staging），root 不可替代，用后即删 | 三基线矩阵 LIVE 门 |

首轮 CI（HEAD e9f61f6）另暴露一处 LIVE harness 自身缺陷：journalctl 不存在
`--output-format` 长选项（v249/v255/v258 选项表源码核验），L3/L6 三条命令
毫秒级 EINVAL 被误呈现为"游标契约破裂/无条目可读"；同时一次性身份不可穿越
runner home 树，PYTHONPATH 直指仓库导致静默 ModuleNotFoundError。两者均按
上表 §9 的 `-o json` + 脱敏诊断 + staging 副本修复——修复的是证明的呈现
管道，不改变任何被证明的契约。
