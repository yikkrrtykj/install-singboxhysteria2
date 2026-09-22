# Monitor 0.3.x 前置 —— sbox-journal-reader PR-2A（issue #33 Phase 2，DARK 交付）

状态：已实现，**整体 DARK**（本 PR 不接线、不激活、不部署任何东西）。设计以
issue #33 冻结链为准：v1 (5776315515) → R1–R11 → v2 → B1–B4 → v3 → C1–C5 →
v4 → D1–D5 → **v5 (5777432304)** → 签署 (5777527361, APPROVED/FROZEN)。
基线：`main @ b6e3307a366cb4c971d91c570fd77a32439174ce`（PR #44 的精确 merge SHA）。

## 1. 结论性摘要

- 新增包：`monitor-v2/journal_reader/`（12 个 stdlib-only 模块）；unit 模板
  `monitor-v2/deploy/singbox-journal-reader.service.in`；运行入口
  `monitor-v2/deploy/app-bin/sbox-journal-reader`；部署库新增 7 个
  `sbmon_sboxjr_*` DARK helper；测试 `tests/test-monitor-v2-jr.sh`（293 检查，
  硬计数门）+ `tests/journal-reader/jr_groups.py`（19 组 258 项行为检查）+
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
- 尾游标（C5）：`journalctl -n 0 --show-cursor` + `^cursor: (\S+)$` 提取；
  首个可提交游标之前，durable since 回退串逐字复用（since→cursor 只在第一次
  提交时转换，且 row-2 恢复保留同一转换语义）。
- D1 六行子进程结局表：通用 rc≠0 → fail-stop、committed 零移动、绝不猜测
  陈旧游标；backlog 截断（C4，50,000 解码条目封顶，自杀 SIGTERM =
  truncated_batch）经"最后一条实际处理过的可用 `__CURSOR`"提交；批中途失败
  整批丢弃且游标不动。SOURCE_GAP epoch 只能经评审后的操作员 reset 产生
  （`reset --from-now`），seq 永不重置。

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

## 7. 保留与心跳

out/ 采用最旧优先双限驱逐（720 文件 / 8MiB），驱逐只发生在 committed 已
越过对应 seq 之后；`hb` 文件每周期重写（Monitor 侧以 >180s 年龄独立判
staleness）；空窗口只写心跳、零状态移动（D1 row 2）。

## 8. 部署模板与 helper（DARK）

- unit 模板：`User/Group=@SBJR_*@` 占位（身份 = 精确的
  {sbox-jr, systemd-journal, nologin, /nonexistent}，R7，绝不 Supplementary
  -Groups 静默补权）；`RestrictAddressFamilies=AF_UNIX`（reader 无 TCP 面）；
  ProtectSystem=strict + 单一 `ReadWritePaths=@SBJR_DATA_ROOT@`；空
  CapabilityBoundingSet；`StartLimit*` 放 `[Unit]`（三基线放置兼容）。
- helper 七件套（monitor-deploy-lib.sh，SBMON_FIXTURE=1 可全离线演练）：
  身份校验先于任何变更（不匹配即 die）、仅在缺失时创建、数据树
  root:sbox-jr 0750 / state 0700 / out 2750 sbox-jr:sboxweb（符号链接全部
  fail-closed）、显式 12+1 文件清单 staging、模板渲染、unit 安装镜像
  （daemon-reload 仅在内容变化时）、可读性探针（runuser 断言组）。
  **没有任何 enable/start/restart 调用点**；install-monitor.sh 零引用。
- 生产 sbox-jr 用户/组/目录/unit 的创建与激活属于 PR-2B，且需单独评审。

## 9. 测试与 CI 接线

- `tests/test-monitor-v2-jr.sh`：S0 静态 + DARK 判别门、S1 unit/wrapper、
  S2 CI 注册锁、S3 journal-time Python↔shell 等价（T31，含 4 个 fail-closed
  对偶）、S4 19 组 258 项行为检查（含 T28 全矩阵：每个耐久边界（含目录
  fsync）前后崩溃 × 恢复表、reset_commit、崩溃点交叉探针）。硬计数门
  `EXPECTED_PASS=293`：任何静默跳过即红。POSIX 语义在 Windows 开发机上退化
  为进程内布尔，计数跨平台稳定。
- tests.yml：fast-checks `bash -n` ×2；monitor-regression 新增本套件步骤；
  兼容矩阵在既有 systemd readiness gate 之后新增 `sudo -n env
  SBOX_JR_REQUIRE_LIVE=1 bash tests/journal-reader/test-jr-live.sh`。
- LIVE 脚本（仅三基线）：L2 真实 journalctl 尾游标遥测（C5 正则 + D5 校验器
  + 4096 上界假设探针，观测值断言 <4096，不钉死）；L3 `--after-cursor` 对
  不透明游标的原样接受；L4 真实 Reader 两个周期在临时目录跑通（C1 事后状
  态合法、pending/scratch 无残留、committed 0600、ev 全过严格 schema、
  MESSAGE/PRIORITY 不跨界、空周期零移动 + hb）；L5 渲染后 unit 过
  `systemd-analyze verify`（镜像生产步的 UNRELATED_NOISE fail-closed rc 契约）
  与支持基线上的 `security --offline`。临时 sing-box.service mock 仅在缺失
  时创建、退出时删除；不创建 sbox-jr 身份、不 enable/start 任何单元。

## 10. 本 PR 明确不包含（PR-2B / 后续）

生产身份与目录创建接线、unit 实装与 enable/start、`install-monitor.sh`
任何调用点、Monitor 侧 schema-v2 ingest 激活（`incident_history` 新表）、
`sbmon_stage_release` 携带 reader、VERSION 0.3.0、任何 UI/查询端点、探测、
出口 IP、断网判定。P1 §10 的边界承诺在本 PR 逐条保持：sbox-jr +
systemd-journal 仍是唯一被接受的 journal 读取模型；不新增 sudoers、不触碰
root fallback、不触碰生产 VPS。
