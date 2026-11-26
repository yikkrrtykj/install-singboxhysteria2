# UM-127 — 统一监控开发基线与 Go 迁移计划（Round 1）

- 状态：**PROPOSED（提案）· DOCS-ONLY · Draft PR**。不构成实现、合并、部署或生产操作授权。
- 唯一跟踪 Issue：[#127 Unified Monitor｜统一监控与 Go 迁移](https://github.com/yikkrrtykj/install-singboxhysteria2/issues/127)
- 设计基线：PR [#126](https://github.com/yikkrrtykj/install-singboxhysteria2/pull/126)（UM-A，Draft，HEAD `5089cdeb`）+ `main` `885171c0`
- Go 开发分支：`codex/um-windows-foundation`（HEAD `24cfd2ff`，基于 rev-3 `089f27a5`，保留不动）

本目录是 UM-127 第一轮交付：核对 UM-A 收口、记录现有 Go 开发分支基线、明确 Linux/Windows 双平台契约扩展与恢复语义、给出 UM-B1..UM-G 的实施顺序与门禁。**所有 Owner 决策均为 PENDING**（见 [05](05-owner-decisions.md)），未批准前不进入实现。

## 1. 本轮范围

| 内容 | 状态 |
| --- | --- |
| #126 最新 HEAD / Tree / CI / 独立审查状态核对 | 完成，见 [01](01-baseline-status.md) |
| 记录 Owner 决策，PENDING 不标 APPROVED | 完成，见 [05](05-owner-decisions.md) |
| Linux VPS / Windows 终端契约扩展 | 提案，见 [02](02-dual-platform-contract.md) |
| Agent 连续离线重启、首次请求失败、generation/seq 恢复语义 | 提案 + 可执行一致性用例，见 [03](03-recovery-semantics.md) 与 [conformance](conformance/transport-recovery.cases.json) |
| Go 分支复用清单、差距矩阵与迁移顺序 | 完成，见 [04](04-implementation-plan.md) |
| 统一基线与实施计划提交 | 本 PR（Draft，docs-only） |
| 实现 UM-B..UM-G / 修改 main / 合并 PR / 同步 Go 分支 / 部署 | **未做，HOLD** |

## 2. 基线摘要

| 对象 | 状态（2026-11-26 核对） |
| --- | --- |
| `main` | `885171c0`（PR #125 merge）；5 个触发 workflow attempt 1 全绿；无分支保护 |
| PR #126 | **OPEN + Draft**；head `5089cdeb`，tree `f1cb4fe4…`，与 merge-ref tree 相同；mergeable/clean；**20/20 CI pass**（一次已知 Windows harness flake 在同 HEAD rerun 通过）；**GitHub 上无任何 review 记录**；18 项 Owner 决策 PENDING |
| UM-A 结论 | **READY FOR PLANNING，不是 APPROVED**；合并前置（独立审查 PASS + Owner 合并授权）未满足 |
| Go 分支 | `codex/um-windows-foundation` @ `24cfd2ff`，3 个开发提交（`17b2f3e2`/`758e75be`/`24cfd2ff`）；CI run `45706557111` 双平台绿；无 PR；基于 rev-3，不含 rev-4 |
| #127 | OPEN，唯一 UM 跟踪 Issue，0 评论 |
| #48 | **CLOSED/completed**（2026-11-25T20:49:12Z，已实时核实）；#33/#67 OPEN 且未变 |

术语说明：PR #126 文档自标注为 **“revision 3 final”**；HEAD `5089cdeb` 是追加的 final corrections commit，没有把标签改成 revision 4。本计划为区分起见把 `5089cdeb` 的最终契约简称 **rev-4**，以文档自身标签与 commit 为准。

## 3. 核心发现

1. **UM-A 未收口**：#126 质量与 CI 达标，但独立审查在 GitHub 记录上不存在，“PASS”只是 PR body/08 的文本声明；18 项决策 PENDING。Coding AI 不代替审查方或 Owner 批准。
2. **rev-4 恢复语义有 4 个未闭合空档**（F1 连续离线重启 generation 跳号、F2 首次请求丢失后 seq、F3 迟到 attempt 处理、F4 rotation intent 跨重启），会导致合法节点在离线重启后永久无法上报。提案 A-1..A-5 给出修正与 30 个可执行用例（REC-01..REC-30），须作为 UM-A rev-5 amendment 先批准。
3. **rev-4 没有 Linux/Windows 节点类别与 Windows 遥测契约**：`linux_vps`/`windows_terminal`、Mihomo 选路、活动连接实际路径计数、独立采样时间、A/B↔中心 VPS ID 映射均未定义；v1 明确禁用 Mihomo，与 #127 首版范围冲突。提案见 [02](02-dual-platform-contract.md)。
4. **Controller 凭据不是只读的**：官方 Mihomo API 含 `PUT/PATCH /configs`、`POST /restart`、`PUT/DELETE /proxies`、`DELETE /connections` 等写操作；GET 白名单只是实现约束，不是授权证明。任何“安全只读”表述必须按真实能力披露，并由 Owner 明确风险决策（OD-P3）。
5. **Go 资产可复用但不可直接合并**：`um/internal/wire` 是 rev-3 签名（缺 `X-UM-Boot-Gen`），`windowsobs` 是 v1 范围外的实验原型；3 个开发提交必须原样保留，等 #126 合并、main CI 绿、Owner 授权后再用 merge（非 rebase/force）同步，且 `docs/um` 冲突一律取 main，绝不能把旧版 UM-A 文档覆盖回新 main。

## 4. 文档索引

| 文件 | 内容 |
| --- | --- |
| [01-baseline-status.md](01-baseline-status.md) | #126 HEAD/Tree/CI/审查核对、main、Go 分支、Issue 状态、复现命令 |
| [02-dual-platform-contract.md](02-dual-platform-contract.md) | `node_class` 模型、Linux VPS 契约、Windows 遥测扩展、A/B 映射、隐私/新鲜度、Controller 凭据授权能力与缓解 |
| [03-recovery-semantics.md](03-recovery-semantics.md) | 连续离线重启、首次请求失败、generation/seq/ACK 恢复语义修正提案、威胁分析与测试要求 |
| [04-implementation-plan.md](04-implementation-plan.md) | 复用资产、差距矩阵、门禁、Go 分支保存/同步、UM-B1..UM-G 切片与 CI 演进、风险 |
| [05-owner-decisions.md](05-owner-decisions.md) | 18 项既有 + 恢复语义 + 双平台 + 门禁决策登记（全部 PENDING） |
| [conformance/transport-recovery.cases.json](conformance/transport-recovery.cases.json) | UM-B1/B2/B3 必须实现的恢复一致性用例（REC-01..REC-30，机器可读） |

## 5. 提议的下一步（全部需要 Owner 授权）

1. Owner 认可本基线，明确 G-1 前置：指定独立审查方完成 #126 审查并给出 merge 授权 → #126 合并 → 核对 main CI。
2. 裁决 [05](05-owner-decisions.md) 中 OD-R1..R5（恢复语义）与 OD-P1..P8（双平台契约）。
3. 授权 PR-A2（UM-A rev-5 amendment：文档 + schema + 正负向量 + 独立审查）。
4. 授权并按序推进 UM-B1（Go 工程/签名/SQLite/一致性测试）→ UM-B2 → UM-B3 → UM-B4 → UM-C/D/E；UM-F 另行授权；UM-G 按 Stage 0→6。
5. 仅在 OD-G2/G3 满足后同步 Go 分支；现有 `codex/um-windows-foundation` 在此之前保持不动。

## 6. 开发边界（本计划再次确认）

- 不创建重复主 Issue；#127 是唯一跟踪 Issue。
- 不直接修改 main；不未经授权合并 PR；本 PR 为 Draft。
- 不将两个 Coding AI 分支的旧协议或重复实现直接混合；签名库/观察器不重复实现。
- 不操作生产 VPS；不修改 Clash Verge、HA-UI、monitor-v2、sbox-cm、#67；不购买 VPS、不创建 Cloudflare 应用、不索取生产凭据。
- 不把旧版 UM-A 文档覆盖到新 main。
- 在 #126 合并 + main CI 通过 + Owner 授权前，不同步 Go 分支。

## 7. 验证说明

- 本 PR 为 docs-only：不修改 workflow、依赖、产品代码；不读取也不影响现有 6 个 workflow。
- 本轮本地检查：JSON 可解析（30 个 REC cases：B1 12 / B2 15 / B3 3）、Markdown 相对链接目标存在、路径引用核对、无真实凭据/敏感值；#126 的 schema/向量验证是 UM-A 作者证据（本计划未独立重新执行 Ed25519 校验，仅核对文件与状态）。
- 本 PR 的 CI 只运行仓库既有回归检查；现有 workflow 不读取 `docs/um/`，本 PR 不新增 CI 覆盖。
