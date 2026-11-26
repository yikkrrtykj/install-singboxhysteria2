# UM-127 05 — Owner 决策登记与门禁（全部 PENDING）

- 状态：**登记 / 未批准**。本文件只记录问题和建议，不构成批准；任何一项都不得由 Coding AI 自行标记为 APPROVED。
- 依据：PR #126 的 UM-A `07 §2`（18 项）、`08`、本轮 `02`/`03` 提案与 `01` 的现状核对。
- 批准方式：Owner 在本 Issue/PR 中明确回复（逐项或整批），由后续 PR 更新本表并附证据；未明确回复的一律保持 PENDING，不得以“沉默/PR 合并/CI 通过”推断批准。

## A. UM-A 既有 18 项 Owner 决策（全部 PENDING）

| ID | 问题 | 审查建议（仅建议） | 阻塞/影响 | 状态 |
| --- | --- | --- | --- | --- |
| Q-TRACK | 是否设唯一长期 UM 跟踪 Issue | 设 1 个 Owner 授权 Issue；Coding AI 不自行创建 | 已由 Owner 建立 #127；确认即可 | PENDING |
| Q-HOST | 中心主机规格/OS | 独立 2C4G/40 GB Ubuntu 24.04 LTS 新 VPS；最终规格由 UM-E 压测确定 | UM-E/部署 | PENDING |
| Q-SIZE | 磁盘/策略 B 配额 | 40 GB + 策略 B 支持约 150 活跃节点；200 节点需更大磁盘或策略 A | 05 保留策略、容量 | PENDING |
| Q-INGRESS | 机器入口传输 | 评估双入口 Cloudflare Tunnel（web+Access / ingest 无 Access）与 direct TLS 8443 后选择；协议相同 | UM-B2 listener、UM-C | PENDING |
| Q-DNS | 域名/Cloudflare/Access | `monitor.132431.xyz` tunnel+Access；`ingest.132431.xyz` 按 Q-INGRESS；Owner 持有 zone/IdP/`aud`/tunnel token | UM-C、UM-E | PENDING |
| Q-AGENT-OS | Agent OS 矩阵/安装 | Debian/Ubuntu systemd；静态二进制 + 审查过的安装器；一次性 root 编排、非 root 运行 | UM-B3 | PENDING |
| Q-COEXIST | 与每 VPS Monitor 共存 | 只读共存；不修改既有 Monitor 部署 | UM-B3/UM-G | PENDING |
| Q-DATA | 授权本地数据源 | sing-box `service.api`（LoadCredential）、`/proc`、只读 systemd D-Bus；无 journald/root；Mihomo 可选（见 OD-P3） | UM-B3 | PENDING |
| Q-RET | 保留策略 | 策略 B（活跃滚动 30 d；归档保留剩余历史至 T+30 d）+ overlap cap；Owner 确认 | UM-B1 storage、UM-D | PENDING |
| Q-AUD | 审计保留 | 180 d，大小有界，可下调但不低于 30 d | UM-B1/B4 | PENDING |
| Q-BACKUP | 备份/RPO/RTO | 局部 RPO ≤24 h；整机 RPO 需每日加密异地副本；RTO 局部 ≤2 h、整机 ≤1 工作日 | UM-E | PENDING |
| Q-LEDGER | 安全账本异地处理 | 账本 + 签名 checkpoint 纳入每次备份/异地；恢复先隔离并核对，不完整账本保持隔离 | UM-B1/B2、UM-E | PENDING |
| Q-HA | 可用性 | 单中心、无 HA；admin 面 best-effort；业务不受影响 | 部署/UM-E | PENDING |
| Q-ADMIN | 管理员策略 | 所有 admin 强制 TOTP；首期单平台 admin；一次性恢复码；OS 级离线重置 | UM-B4/UM-C | PENDING |
| Q-TECH | 技术栈 | Go 中心+Agent、Vue 3+TS+Vite+uPlot、SQLite WAL 先行（`synchronous=FULL`） | UM-B1..D | PENDING |
| Q-ALIAS | 客户端摘要展示 | 伪匿名 `device_ref` + center 侧显示别名；不存原始代理凭据/连接数据 | UM-B4/UM-D | PENDING |
| Q-UMF | UM-F 边界 | v1 只读平台；UM-F 需单独批准/设计（操作级授权） | UM-F | PENDING |
| Q-ISSUE | 既有 Issue 处理 | #33/#67 不动；**#48 已核实为 CLOSED/completed（2026-11-25T20:49:12Z）**，保留证据与限制；不新建 Issue/PR 除非授权 | 全阶段 | PENDING（#48 状态已核实，见 01 §4） |

## B. 恢复语义提案决策（本文件新增，全部 PENDING）

| ID | 决策 | 建议 | 阻塞 | 状态 |
| --- | --- | --- | --- | --- |
| OD-R1 | 批准 A-1：center 接受 generation 跳号（`MAX_BOOT_GAP=65535`，gap>1 写审计） | 批准 | UM-B1/B2/B3、03 | PENDING |
| OD-R2 | 批准 A-2：新 generation 首个被接受请求允许 `seq>1`，`last_seq` 取该 seq | 批准 | UM-B1/B2、03 | PENDING |
| OD-R3 | 批准 A-3/A-5：ACK `next_seq` 采纳、被取代 attempt 忽略；rotate intent 跨 generation 的顺序与优先级 | 批准 | UM-B1/B2/B3、03 | PENDING |
| OD-R4 | `boot_generation_gap` 审计与安全告警阈值/通知渠道 | UM-B2 给默认值后 Owner 确认 | UM-B2、UM-E | PENDING |
| OD-R5 | 是否将 A-1/A-2 作为 UM-A rev-5 amendment 先于 UM-B1 代码冻结 | 是 | PR-A2、UM-B1 | PENDING |

## C. 双平台契约提案决策（本文件新增，全部 PENDING）

| ID | 决策 | 建议 | 阻塞 | 状态 |
| --- | --- | --- | --- | --- |
| OD-P1 | `node_class`（`linux_vps` / `windows_terminal`）必填枚举 + OS 一致性校验 | 接受 | UM-B1/B2/B3、02 | PENDING |
| OD-P2 | Windows 选路/连接聚合纳入首版 | 纳入（与 #127 目标一致） | UM-B3、UM-D | PENDING |
| OD-P3 | Controller 凭据残余风险：R1（Owner 接受 + 缓解集）或先做 R2 调研 | 先调研 R2，R1 兜底 | UM-B3 Windows | PENDING |
| OD-P4 | A/B ↔ 中心 VPS ID 映射由 center 管理面配置，Agent 只报 token | 接受 | UM-B2/B4、UM-D | PENDING |
| OD-P5 | `stale_after_s` 默认值与 metrics 是否首版纳入 | `max(180,3×cadence)`；metrics 可选 | UM-B3/UM-D | PENDING |
| OD-P6 | 隐私 allowlist 增补（token/计数/时间戳；版本号默认不上报） | 默认不上报 controller 版本 | UM-B2/B3、UM-E | PENDING |
| OD-P7 | Windows Agent 运行账户与 secret 存储（DPAPI/服务账户/用户会话） | UM-B3 给出 ADR 后 Owner 确认 | UM-B3 | PENDING |
| OD-P8 | `terminal` 放在 `report-snapshot` 可选对象（而非新 report type） | 是 | UM-B1/B2、02 | PENDING |

## D. 合并、同步与实施门禁（本文件新增，全部 PENDING/HOLD）

| ID | 门禁 | 当前状态 | 说明 |
| --- | --- | --- | --- |
| OD-G1 | #126 独立审查 PASS + Owner 合并授权 | **未满足**（GitHub 无 review 记录；#126 仍 Draft） | 见 01 §2.3/§2.5 |
| OD-G2 | #126 已合并到 main 且该 merge commit CI 全绿 | 未满足 | 合并后需重新核对 |
| OD-G3 | 授权同步 `codex/um-windows-foundation` 至最新 main（merge，不 force/rebase，保留 3 提交） | **HOLD** | 见 04 §5.2 |
| OD-G4 | 批准 PR-A2（UM-A rev-5 amendment：恢复语义 + 双平台扩展） | **HOLD** | 依赖 OD-R*/OD-P* |
| OD-G5 | 按切片批准 UM-B1..UM-G 的独立 Draft PR | **HOLD** | 每个 PR 单独授权 |
| OD-G6 | 生产部署/发布/凭据/VPS/Cloudflare 资源 | **HOLD** | UM-E 后另行授权 |
| OD-G7 | CI hotfix（#125 windows-exe harness 偶发 flake 的独立修复） | 未授权 | 与 #126 无关；不阻塞本计划 |
| OD-G8 | 恢复/账本演练（异地备份、restore quarantine） | UM-E 范围 | 未开始 |

## E. 其他待确认项（不在 18 项内，但影响计划）

| 项目 | 说明 | 状态 |
| --- | --- | --- |
| 保留策略 A/B 的选择 | Q-RET 的具体数值；05 文档已给比较 | PENDING（并入 Q-RET） |
| Cloudflare ingress A/B | Q-INGRESS 的具体选型 | PENDING（并入 Q-INGRESS） |
| Mihomo 启用设计 | UM-A `04` §11 要求 Owner 批准“只读模式且不授予业务写权限”的设计；本计划 02 §6 明确凭据真实写能力 | PENDING（OD-P3/OD-P2） |
| UM-B 切片批准 | 07 §4 的 B1..B4 拆分需 Owner 批准 | PENDING（并入 OD-G5/G4） |
| #126 是否改为 Ready / 合并 | 需独立审查 PASS + Owner 合并授权 | PENDING（OD-G1/G2） |
| 既有 CI flake 修复 | #125 后 windows-exe 仍可能偶发；建议单独 owner-authorized hotfix | PENDING（OD-G7） |

## F. 审批纪律

1. 本表任何一行在 Owner 明确答复前保持 PENDING；Coding AI 不得在文档/PR/Issue 中写成 APPROVED，也不得用“默认接受/视为通过”处理沉默。
2. 批准记录必须可追溯：Owner 在 #127 或对应 PR 的明确文字 → 后续 PR 更新本表 → 附链接与时间。
3. 单个决策的批准不等于合并授权；合并、同步、部署仍是独立门禁（D 节）。
4. 若 Owner 修改建议（如 MAX_BOOT_GAP 取值、stale 阈值、凭据方案），先更新 02/03 与 `conformance/transport-recovery.cases.json`，再进入实现。
