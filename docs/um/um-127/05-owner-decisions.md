# UM-127 05 — Owner 决策、方向接受与门禁登记（rev-5）

- 状态：**rev-5 历史登记 + 2026-11-27 rev-6 有限 Owner 决策**。本文件记录问题、Owner 已给的方向与建议；除 [10-owner-decisions-rev6.md](10-owner-decisions-rev6.md) 明确记录的 rev-6 有限批准外，不得由 Coding AI 自行标记为 APPROVED。
- 依据：PR #126 UM-A rev-5、Owner Round-2 审查结论（2026-11-26）、#128 规划同步。
- 状态词汇：
  - `PENDING`：未收到 Owner 明确决定；
  - `DIRECTION-ACCEPTED`：Owner Round-2 明确接受方向/要求纳入 rev-5，**不等于** APPROVED 或合并/部署授权；
  - `SUPERSEDED`：Owner 已明确不再采用（如 PR-A2）；
  - `HOLD`：等待前置门禁。

## A. UM-A 既有 18 项 Owner 决策（rev-5 历史状态；2026-11-27 有限更新已标注）

| ID | 问题 | 建议 | 状态 |
| --- | --- | --- | --- |
| Q-TRACK | 唯一 UM 跟踪 Issue | 已有 #127；不创建重复 Issue | PENDING |
| Q-HOST | 中心主机规格/OS | 独立 2C4G/40GB Ubuntu 24.04；最终由 UM-E 压测定 | PENDING |
| Q-SIZE | 磁盘/策略 B 配额 | 40GB + B 支持约 150 节点；200 节点需更大盘或策略 A | PENDING |
| Q-INGRESS | 机器入口传输 | 双入口 CF Tunnel 与 direct TLS 8443 比较后选择 | PENDING |
| Q-DNS | 域名/CF/Access | monitor/ingest 域名、zone、IdP、aud、tunnel token 由 Owner 持有 | PENDING |
| Q-AGENT-OS | Agent OS 矩阵/安装 | Linux Debian/Ubuntu systemd；rev-5 增加 windows_terminal class，但 Windows OS/安装矩阵仍需明确决定 | PENDING |
| Q-COEXIST | 与每 VPS Monitor 共存 | 只读共存，不改既有部署 | PENDING |
| Q-DATA | 授权本地数据源 | sing-box service.api/`/proc`/只读 D-Bus；Windows **R2 优先**、R1 需单独 Owner 风险接受 | **PARTIAL (2026-11-27)**：Windows R1 隔离架构批准；Linux `singbox_api` 仍 disabled；见 [10-owner-decisions-rev6.md](10-owner-decisions-rev6.md) |
| Q-RET | 保留策略 | 策略 B + overlap cap | PENDING |
| Q-AUD | 审计保留 | 180d，可下调不低于 30d | PENDING |
| Q-BACKUP | 备份/RPO/RTO | 局部 RPO≤24h；整机需每日加密异地；RTO 见方案 | PENDING |
| Q-LEDGER | 账本异地处理 | 账本+checkpoint 纳入备份；恢复隔离并核对 | PENDING |
| Q-HA | 可用性 | 单中心无 HA；业务不受影响 | PENDING |
| Q-ADMIN | 管理员策略 | 强制 TOTP、单 admin、恢复码、OS 级重置 | PENDING |
| Q-TECH | 技术栈 | Go + Vue3/TS/Vite/uPlot + SQLite WAL FULL | PENDING |
| Q-ALIAS | 摘要展示 | 伪匿名 device_ref + center 别名（含 terminal route alias） | PENDING |
| Q-UMF | UM-F 边界 | v1 只读；UM-F 单独批准/设计 | PENDING |
| Q-ISSUE | 既有 Issue | #33/#67 不动；#48 已核实 Closed/completed；不新建 Issue/PR 除非授权 | PENDING |

## B. rev-5 恢复/数值/rotation 决策

| ID | 内容 | 状态 |
| --- | --- | --- |
| OD-R1 | A-1：bounded generation forward jump，`MAX_BOOT_GAP=65535`，gap>1 审计 | **DIRECTION-ACCEPTED**（Owner Round-2）；已冻结进 #126 rev-5；实现仍受独立审查/合并门禁 |
| OD-R2 | A-2：新 generation 首接触允许 `seq>1`，`last_seq` 取接受值 | **DIRECTION-ACCEPTED**；同上 |
| OD-R3 | A-3/A-5：ACK next_seq 采纳、superseded attempt、rotation 全量校验/不得绕过 high-water | **DIRECTION-ACCEPTED**；同上 |
| OD-R4 | gap 审计/告警阈值、通知渠道 | **PENDING（运行期参数）**：UM-B2 给默认值后 Owner 确认 |
| OD-R5 | 是否先做独立 PR-A2 | **SUPERSEDED**（Owner 明确不再创建 PR-A2；直接进 #126） |
| OD-R6 | `MAX_NUMERIC=2^63−2`、ACK `next_seq:null` exhaustion、SQLite INTEGER/CHECK | **DIRECTION-ACCEPTED**（由 Owner “明确 uint64 边界/ACK/SQLite”要求纳入 rev-5）；已冻结 |

## C. 双平台/Windows 契约决策（rev-5 方向；rev-6 有限批准见 OD-P3/OD-P7）

| ID | 内容 | 状态 |
| --- | --- | --- |
| OD-P1 | `node_class`（linux_vps/windows_terminal）必填、token scope 绑定 event+class、不可自选 | **DIRECTION-ACCEPTED**；已冻结进 rev-5 schema/enrollment；实现受门禁 |
| OD-P2 | Windows 选路/连接聚合纳入首版；六路径而非仅 A/B | **DIRECTION-ACCEPTED**；已冻结（六 token/schema） |
| OD-P3 | R2 真只读源优先；R1 写能力 controller 凭据需单独 Owner 风险接受、不自动启用 | **APPROVED (limited, 2026-11-27)**：R1 架构/隔离 lab 批准，生产启用 HOLD；见 [10-owner-decisions-rev6.md](10-owner-decisions-rev6.md) |
| OD-P4 | A/B→VPS ID 映射由 center 版本+effective_from 管理，历史不改写；agent 只报 token | **DIRECTION-ACCEPTED**；已冻结契约；UM-B4 实现 |
| OD-P5 | `stale_after_s` 默认值、cadence、metrics 是否首版 | **PENDING（运行期参数）**：默认 `max(180,3×cadence)` 建议；metrics v1 不纳入（已冻结为 deferred） |
| OD-P6 | 隐私 allowlist 增补（token/计数/时间戳；版本号默认不报） | **DIRECTION-ACCEPTED**（rev-5 privacy）；运行期细节 PENDING |
| OD-P7 | Windows Agent 运行账户与 secret 存储（DPAPI/服务账户/用户会话） | **APPROVED (limited, 2026-11-27)**：`NT SERVICE\um-agent`/Session 0/DPAPI CurrentUser；不授权实际操作赛事电脑；见 [10-owner-decisions-rev6.md](10-owner-decisions-rev6.md) |
| OD-P8 | `terminal` 放 report-snapshot 可选对象（非新 report type） | **DIRECTION-ACCEPTED**；已冻结 schema |

**DIRECTION-ACCEPTED 的含义**：Owner 在 Round-2 明确要求按该方向形成 rev-5 最终契约；它不是 APPROVED，也不授权合并、实现或生产。18 项 Q-* 中仅 Q-DATA 的 Windows R1 部分按 2026-11-27 rev-6 记录获批；其余仍 PENDING。

## D. Owner Round-2 审查记录（2026-11-26）

| 项 | Owner 结论 | 处理 |
| --- | --- | --- |
| #128 overall implementation plan | **PASS** | 保留 #128；按 rev-5 同步 |
| Recovery design A-1..A-5 | **ACCEPTED DIRECTION** | 纳入 #126 rev-5；REC-30 保留 |
| Dual-platform architecture | **PASS** | 纳入 node_class/六 token/映射版本 |
| Go migration roadmap | **PASS** | 保留 UM-B1..UM-G 与迁移阶段 |
| Final contract | **TARGETED UPDATE REQUIRED** | 已完成 rev-5（#126 `048fc170`） |
| CI | **PASS WITH RECORDED RERUN** | 记录 flake 与同 HEAD rerun；未弱化测试 |
| Merge / deployment | **Separate owner authorization required** | 未授权；G-2/G-3/G-6 HOLD |

**独立审查仍必需**：Owner Round-2 是 Owner 审查结论，不是 GitHub 独立 review 对象，也不替代 UM-B entry criteria 的 independent review PASS。

## E. 合并/同步/实施门禁（不再有 PR-A2）

| ID | 门禁 | 当前状态 |
| --- | --- | --- |
| OD-G1 | UM-A rev-5 / #128 基线已合并 | **COMPLETE（历史）**：#126 merge `8f1b9ac1`；#128 merge `e889a191`；当前 base `54efc81c` |
| OD-G2 | rev-6 发布：Owner 决策 + 独立审查 PASS + exact-HEAD CI 全绿 + 无阻塞线程 | #132 Draft；条件式 merge 授权已记录在 [10-owner-decisions-rev6.md](10-owner-decisions-rev6.md)，待审查/CI 门禁 |
| OD-G3 | rev-6 普通 Merge Commit 合并并验证 main | HOLD（等待 OD-G2） |
| OD-G4 | B3 #131 同步 rev-6、重新审查/CI；**不授权合并** | HOLD，Owner 单独授权才可合并 #131 |
| OD-G5 | Owner 按切片批准 UM-B1..UM-G 独立 Draft PR | HOLD |
| OD-G6 | 生产部署/发布/凭据/VPS/Cloudflare | HOLD |
| OD-G7 | 已知 Windows harness flake 的独立 hotfix | 保留记录；不混入设计 PR |
| OD-G8 | 恢复/账本/异地备份演练 | UM-E 范围，未开始 |

## F. 设计决策 vs 运行期参数（本轮要求区分）

| 类别 | 内容 | 决策归属 |
| --- | --- | --- |
| **已冻结设计决策**（rev-5） | A-1..A-5 语义；`MAX_BOOT_GAP=65535`；`MAX_NUMERIC=2^63−2`；ACK next_seq exhaustion；SQLite INTEGER/CHECK；node_class/token scope/平台隔离；六 token；独立采样；映射版本+effective_from；rotation 全量校验；R2 优先/R1 不自动启用 | #126 rev-5 冻结；变更需新 amendment + 独立审查 |
| **未来阶段运行参数** | stale_after/cadence 具体值；R1 是否被接受（Owner 风险决定）；Windows 服务账户/secret 存储 ADR；保留容量/磁盘规格；ingress 选型；通知阈值 | UM-B3/UM-B4/UM-E 给出方案后 Owner 确认；不是当前契约前置 |
| **仍 PENDING 的 Owner 决策** | 18 项 Q-* 中除 Q-DATA 的 Windows R1 有限部分；OD-P5；OD-R4；其他运行期参数 | PENDING，不得默认接受 |
| **2026-11-27 rev-6 有限批准** | OD-P3 R1 架构（生产 HOLD）；OD-P7 虚拟账户架构（不授权实际操作）；Q-DATA Windows R1；rev-6 契约方向与 #132 条件式合并授权 | 见 [10-owner-decisions-rev6.md](10-owner-decisions-rev6.md)；不授权 #131/生产 |

## G. 审批纪律

1. 任何一行在 Owner 明确答复前保持 PENDING；DIRECTION-ACCEPTED 也不得写成 APPROVED。
2. 批准记录必须可追溯（#127 或 PR 明确文字 → 本表更新 + 链接/时间）。
3. 单个决策批准 ≠ 合并/同步/部署授权；D/E 节门禁独立。
4. 若 Owner 修改建议，先更新契约（amendment/rev-6 overlay）与规划文档，再进入实现。
5. 2026-11-27 rev-6 决策仅按 [10-owner-decisions-rev6.md](10-owner-decisions-rev6.md) 的有限范围生效；本文件其余 PENDING 项不因该记录自动批准。
6. rev-6 的发布状态只能由合并后的 main 与 exact merge commit CI 证明，不能由 PR Draft 状态声称。
