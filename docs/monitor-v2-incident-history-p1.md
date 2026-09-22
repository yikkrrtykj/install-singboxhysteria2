# Monitor 0.2.0 — 持久化事件时间线基础（issue #33 Phase 1）

状态：已实现，随 Monitor 0.2.0 交付。范围严格限定于 issue #33 规格 §1–§13 的
Phase 1；本文档同时是 §13 要求的"实现前勘察 + 偏差记录"。

## 1. 结论性摘要

- 新模块：`monitor-v2/web/incident_history.py`（Monitor-only，stdlib sqlite3）。
- 持久化位置：`<state-root>/diagnostics/history.sqlite3`
  （生产即 `/var/lib/singbox-monitor/diagnostics/`，已在现有 unit 的
  `ReadWritePaths` 内 —— **未新增任何 systemd 权限 / ReadWritePaths / sudoers**）。
- 数据源：`SnapshotBroker` publisher 线程在 `_decorate()` 之后、发布成功之时的
  **已装饰 snapshot 的白名单聚合投影**；绝不读取原始 collector 对象图之外的
  连接级字段。
- 读面：`GET /api/v1/diagnostics/timeline?since=<epoch>&limit=<bounded>`，
  session-gated、只读、deny-by-default 列白名单。无 UI（P1 明确不含）。

## 2. 实现前勘察（§13）与偏差

按序勘察了 `broker.py`（publish 循环 / `_decorate` / `_export_health_file`
先例）、`collector.py`（E1 Tracker 快照结构、字段清单）、`webapp.py`
（进程启动点）、`server.py`（路由/会话门禁）、
`deploy/singbox-monitor.service.in`（ProtectSystem=strict +
`ReadWritePaths=@SBMON_STATE_ROOT@`、`UMask=0077`）、
`deploy/lib/monitor-deploy-lib.sh`（`sbmon_stage_release` 以 `cp -R` 整体
staging `web/`，`py_compile web/*.py` glob 覆盖新模块）、
`tests/test-monitor-packaging.sh`（T24/T25 升级回归形态）。

**规格与仓库现实之间未发现任何冲突；无偏差需要申报。** 特别地：
- broker 边界与规格描述逐点吻合（写入钩子与 `_export_health_file` 同槽位、
  同"永不杀死 publisher"契约）；
- diagnostics 目录无需 unit 改动即可写；
- 打包 / 升级流程无需 installer 编辑，新模块自动进入不可变 release 树。

## 3. 存储与模式（§1 / §2）

- 目录 `diagnostics/`：真实目录、0700；拒绝符号链接与非目录占位。
- 文件 `history.sqlite3`：regular、0600；拒绝符号链接与非 regular 占位。
- `journal_mode=DELETE`、`synchronous=FULL`、`foreign_keys=ON`、
  `busy_timeout=2000ms`、`auto_vacuum=INCREMENTAL`。
- `meta.schema_version` 显式版本；迁移 forward-only；发现更高版本 →
  fail-closed（`schema_unsupported`），绝不降级改写。DB 内容永不进日志。
- 表：
  - `timeline_samples`：5s 聚合行（epoch/ISO/run_id/uptime/snapshot 版本/
    generated·success 时间戳/stale/api_status/total·reality·hy2·other
    活跃连接数/聚合上下行速率/skipped·duplicate·conflicts·abandoned 计数器）。
  - `device_protocol_states`：按 (device, inbound) 稀疏行；
    `reason IN ('change','heartbeat')`：活跃数或状态变化立即写；否则
    ≤1 行/60s 心跳；**仅速率变化不写**。
- `run_id`：每进程启动新生成的随机 UUID（`uuid4().hex`，非机密），用于把
  "行"归属到"进程代际"；停机缺口绝不回填假行。

## 4. 协议归类（§3）

`classify_protocol(inbound, inbound_type)`：显式审查过的
tag 表（`vless-in→Reality`，`hy2-in→Hysteria2`）+ `inbound_type` 表
（reality/vless→Reality；hy2/hysteria2→Hysteria2），tag 命中优先；无法识别
→ `OTHER`，永不猜测。不改 E1 Tracker 的身份模型。

## 5. 禁止持久化清单（§4）与测试

连接 ID、源/目的 IP 或主机名、UUID、HY2 口令、私钥、API secret、
admin/session/recovery 数据、配置内容、原始 snapshot、原始日志行 —— 全部
不进入任何投影列。设备显示名与 inbound tag 是允许的最小元数据。
回归用哨兵值（connections/recent_sources/recent_connections/closed_ids/
last_error 内植入）断言其既不出现在行中、也不出现在 DB 文件字节与 HTTP 响应体。

## 6. 保留策略（§5）与 VACUUM 关键事实

7 天时间保留 + 目标 ≤48MiB / 硬顶 64MiB；启动时与每小时清理；只删最旧。
实现教训（判别测试捕获）：SQLite 的 incremental vacuum 只能截断**文件尾部**
空闲页，而"只删最旧"把空闲页留在存活的新行**后面** —— 因此尺寸收缩必须经
一次全量 `VACUUM` 才可被 `page_count` 观测；否则按文件字节驱动的裁剪循环会
先于目标耗尽整表。`_prune_to_target` 由此为：每轮按比例（≥10%、≥512 行）删
最旧前缀 + 全量 VACUUM + 重新测量，天然保证"新行永不先于旧行被删"。
保留失败 → degraded 标志 + 分类码 + 计数 + 最后成功时间，永不 crash、
永不静默。

## 7. 故障边界（§6 / §7）

写入钩子在 broker publisher 内与 `_export_health_file` 同位：外层
`except Exception` 双保险；模块公共面 `open/on_publish/health/query_timeline/
close` 全部 soft（捕获 `_HistoryError` 与 `sqlite3.Error/OSError`）。
持久化故障时 dashboard 照常服务，publisher/consumer/web 线程均不受影响。
健康对象：`enabled, degraded, last_success_at, failure_count,
last_error_code(仅分类码), run_id`。

## 8. 读面契约（§8）

`GET /api/v1/diagnostics/timeline`：`_require_session` 门禁；仅 GET
（POST → 405）；`since` 有界有限非负、`limit` 正整数且硬顶
（`QUERY_LIMIT_MAX`），响应为显式列白名单 + `truncated` 标志；历史未启用
→ sanitize 的 503（"incident history not enabled"），无 traceback。无
Incidents UI。

## 9. 版本与升级（§9）

VERSION / MONITOR_WEB_VERSION → 0.2.0；packaging T26 复刻生产真实
0.1.5→0.2.0 升级（原子切换、0.1.5 树逐字节保留、恰一次 monitor 重启、
sing-box/sbox-cm/helper 零动作）并额外断言新模块进入 release 树。
`monitor.conf` 未改动。

## 10. 后续阶段的安全边界（§12，对未来工作的约束）

不为 sboxweb 授予 journald/root 访问；不为诊断添加 sudoers。未来 sing-box
日志摄取必须经由单独评审的窄权限 root 侧 reader，以严格边界输出已消毒记录；
P1 未为该设计预设任何实现。

## 11. 本 PR 明确不包含（§11）

日志摄取、事件分类、探测、出口 IP、断网判定、任何 UI、TT Live 标记、
Office Probe。
