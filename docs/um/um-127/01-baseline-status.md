# UM-127 01 — 基线快照与 UM-A 收口核对

- 记录时间：2026-11-26 07:2x UTC / 10:2x +03:00（本轮调查）。
- 状态：**事实记录 + PROPOSED 判断**；不修改任何现有分支/PR/Issue，不把 PENDING 标为 APPROVED。
- 证据来源：GitHub API（`gh`，账号 `yikkrrtykj`）、`git fetch` 后的 `origin/*`、本地只读 worktree 核对。完整原始 JSON 见 `.agents/um127/research/raw01/`（工作区临时目录，不入库）。

## 1. 仓库与 main

| 项目 | 值 | 说明 |
| --- | --- | --- |
| 仓库 | `yikkrrtykj/install-singboxhysteria2` | public；默认分支 `main` |
| main HEAD | `885171c08210ad0f4e91f0fed0243460d294b15e` | merge PR #125（`fix/quality-windows-process-enumeration`） |
| main 父提交 | `c30e8e72…`（P1）+ `8986cbf1…`（P2） | P2 为 Windows EXE harness 修复 |
| main CI | 885171c0 的 5 个触发 workflow 全部 **attempt 1 成功** | p6b2-foundations、shell-tests、monitor-packaging、quality-receiver、HY2 BBR defaults；HA-UI 因 path filter 未触发（正常） |
| 分支保护 | **无**（GitHub API 404 `Branch not protected`） | 记录为风险；当前依赖 AGENTS.md/流程约束而非平台强制 |
| main 工作流 | 6 个既有 workflow | `tests.yml`、`ha-ui.yml`、`monitor-packaging.yml`、`p6b2-foundations.yml`、`quality-receiver.yml`、`hy2-bbr.yml`；本计划不修改 |
| main 上的 UM 产物 | **无**：无 `docs/um`、无 `um/`、无 `um-go.yml`、无 `go.mod`/`*.go` | 所有 UM 内容都在未合并分支上 |

CI 上下文 nuance：合并前父提交 `c30e8e72` 曾在同一个 Windows EXE harness flake（run 45603760418）上红过；PR #125 修复后 main merge commit 的 CI 为 attempt 1 全绿，按“main CI 通过”记录。

## 2. PR #126 收口核对

### 2.0 版本标签说明

PR #126 内的规范性文档全部自标注为 **“revision 3 final”**（04/05/06/07 标题、contracts/v1 README、um README §Versioning）；不存在“revision 4”标签。HEAD `5089cdeb` 只是追加的 “final contract corrections” 提交。本计划为区分使用 **rev-4 = commit 5089cdeb 的最终契约内容**；引用时以文档标签与 commit 为准，不把“rev-4”当成仓库内已有标签。

### 2.1 HEAD / Tree / 合并状态

| 项目 | 值 |
| --- | --- |
| 编号/标题 | #126 `docs(um): UM-A architecture, technology selection and frozen v1 contracts` |
| 状态 | **OPEN + Draft**（不是 Ready for review） |
| base | `main` @ `885171c0` |
| head 分支 | `docs/um-a-architecture-freeze` |
| head SHA | **`5089cdebc18e98bc8e37446a2404f59d1f5544ef`**（与任务给定一致） |
| head tree | **`f1cb4fe40b0c534fa326797c2fabf8a5be0ff620`** |
| commits | 4：`d2818a78`、`2886619c`、`089f27a5`、`5089cdeb` |
| diff | 39 files，+3,843/−0（`docs/um/**` + `.gitattributes` LF pin） |
| mergeable / mergeStateStatus | `MERGEABLE` / `CLEAN` |
| merge ref | `refs/pull/126/merge` = `985977544f7f38627a61de009bc4f1b10f07b5bb`（parents `885171c0`+`5089cdeb`，GitHub committer）；**tree 与 head tree 相同（empty name-status diff）** |
| labels / assignees / milestone | 均为空 |
| updatedAt | `2026-11-26T07:04:53Z` = 第 6 次 **PR body 编辑**（`lastEditedAt` 相同，`userContentEdits.totalCount=6`）；非 commit/CI/评论事件 |

### 2.2 CI

`gh pr checks 126`：**20/20 pass**，覆盖 5 个 workflow：

| workflow | run | 结果 |
| --- | --- | --- |
| p6b2-foundations | 45706215777 | 5/5 jobs pass |
| shell-tests | 45706215918 | 7/7 jobs pass（含 ci-gate） |
| monitor-packaging | 45706215892 | 3/3 jobs pass |
| HY2 BBR defaults | 45706215877 | pass |
| quality-receiver | 45706215839 | 4/4 pass（attempt 2） |

已知 flake（记录，不隐瞒）：quality-receiver 的 `windows-exe` job **第一次 attempt**（job 139528757307）在 “Native frozen EXE …” 步骤失败：`OSError: [Errno 5] QueryFullProcessImageNameW failed for PID 6408` / `ProcessEnumerationError: … winerror=5`（21:40:19Z）。同 HEAD rerun（attempt 2，21:46:44Z 起）通过，windows-exe 11m19s。本次改动是 docs-only，不触碰该代码路径；PR body 中写的 “11m25s” 与实际 11m19s 差 6 秒，不影响结论。CI 未跳过/弱化任何检查。

### 2.3 独立审查状态：**GitHub 上不存在**

逐一核对：

| 检查 | 结果 |
| --- | --- |
| `reviews` | `[]`（totalCount=0） |
| review comments | `[]` |
| issue comments | `[]` |
| requested reviewers | users/teams 均空 |
| GraphQL `reviewDecision` / `latestReviews` / `reviewRequests` | null / 0 / 0 |
| 4 个 commit 的 commit comments | 均 `[]` |
| timeline | 仅 6 个事件：4 次 push + 2 次 self cross-ref（#48、#127）；无 reviewed/review_requested/review_dismissed |

结论：**“独立审查 PASS”在 GitHub 记录上不成立**。PR body 与 UM-A `08` 文档中的 “OVERALL ARCHITECTURE PASS / TECHNOLOGY SELECTION PASS” 是文本声明，没有 reviewer 身份、时间或 review 对象；`07` 的 “Independent UM-A review PASS for revision 3 final” 复选框仍未勾选。本轮不把它当作 APPROVED，也不代替 Owner/审查方做批准。

### 2.4 Owner 决策

PR body、`07` §2、`08` 均记录：**18 项 Owner 决策全部 PENDING / NOT approved**（Q-TRACK、Q-HOST、Q-SIZE、Q-INGRESS、Q-DNS、Q-AGENT-OS、Q-COEXIST、Q-DATA、Q-RET、Q-AUD、Q-BACKUP、Q-LEDGER、Q-HA、Q-ADMIN、Q-TECH、Q-ALIAS、Q-UMF、Q-ISSUE）。本轮逐项登记在 `05-owner-decisions.md`，未作任何批准动作。

### 2.5 UM-A 入口条件（07 §3）核对

| 条件 | 状态 |
| --- | --- |
| 独立 UM-A review PASS（rev-3 final，P0/P1 + final-correction 关闭） | **不满足**（GitHub 无 review 记录） |
| Owner 回答 §2 或明确接受建议 | **不满足**（18 项 PENDING） |
| Contract v1 rev-3 final 冻结；正负向量可复现 | 文档/向量在 PR #126 中已提交；按 `08` 自述通过本地校验；无独立复现记录 |
| 技术选型接受；依赖登记/审查计划同意 | 部分（PR body 声明 PASS，无审查对象）；依赖登记未决 |
| UM-B 拆成可审查 Draft PR（写范围/测试/证据） | 本基线文档给出拆分提案，尚未获授权 |
| 既有系统未修改；无 sbox-cm/#67/remote-write；生产 HOLD | 满足（PR #126 仅 docs） |

**结论：UM-A 处于 “READY FOR PLANNING / pending independent review”，不是 APPROVED。** #126 合并前置（独立审查 PASS + Owner 合并授权）未满足。

## 3. Go 开发分支基线

| 项目 | 值 |
| --- | --- |
| 分支 | `codex/um-windows-foundation`（远端存在，**无 PR**） |
| HEAD | **`24cfd2ffcd7a400785dbd3848278813be50f3618`**（与任务给定一致） |
| 与 main 关系 | merge-base = `885171c0`；`origin/main..HEAD` 共 6 个提交 = 3 个 UM-A docs 提交（`d2818a78`/`2886619c`/`089f27a5`）+ **3 个 Go 开发提交** |
| 3 个开发提交 | `17b2f3e2` `feat(um): add Go observer for Windows Mihomo paths`；`758e75be` `ci(um): build and test Go observer on Linux and Windows`；`24cfd2ff` `feat(um): implement and verify v1 Go signing primitives` |
| 分支基点 | 直接父提交 `089f27a5`（UM-A rev-3）；**不包含** rev-4 `5089cdeb`（二者为兄弟） |
| 分支内 docs | `docs/um` 为 **rev-3**（38 files，与 `089f27a5` 相同）；没有 rev-4 的 `X-UM-Boot-Gen` 文档 |
| 改动的非 docs 文件 | 8 文件（`um/**` 7 文件 + `.github/workflows/um-go.yml`）；共 +820 行（不含 docs） |
| CI | run `45706557111`（push，attempt 1）**success**；jobs `native (ubuntu-24.04)`、`native (windows-2022)` 均 success |
| 提交身份 | 3 个 Go 提交 + 4 个 UM-A 提交的 author/committer 均为 `yikkrrtykj <152189277+yikkrrtykj@users.noreply.github.com>`（符合 AGENTS.md） |
| 本地验证（只读 worktree） | `go build ./...` / `go vet ./...` / `go test ./... -count=1` 均 PASS；6 个顶层测试/11 个子测试；wire 覆盖 75.0%、windowsobs 92.7%、cmd 0%；`-race` 本地不可用（CGO 关闭），CI 未跑 |
| 关键缺口 | 签名库为 rev-3（缺 `X-UM-Boot-Gen` 15 行签名串）；wire 测试读分支内 rev-3 fixtures；合并 rev-4 文档后会失败；`report-boot-gen-tamper` 负向未处理 |

### 3.1 保存与合并顺序约束

- 在 G-1/G-3 之前：不 rebase、不 force-push、不 cherry-pick、不 merge main 进该分支，保留全部 3 个开发提交 SHA。
- **合并顺序风险**：Go wire 测试读取 `docs/um/contracts/v1/**`。若在 PR #126 合并前把 Go 提交放到 main，仓库没有 `docs/um`，`go test` 会失败；若把分支 rebase/merge 到 rev-4，报告/rotate 向量与签名串会变，当前 wire 测试会失败。因此必须先 #126 合并 + main CI 绿 + Owner 授权，再按 `04-implementation-plan.md` §5.2 用 **merge（非 rebase/force）** 同步，`docs/um` 冲突一律取 main rev-4，且 `git diff origin/main -- docs/um` 为空。
- 同步后 `docs/um` 必须与 main 完全一致（不得用 rev-3 旧文档覆盖新 main）；3 个开发提交必须仍在祖先链上。

## 4. Issue 与边界状态

| Issue | 状态（实时核对） | 说明 |
| --- | --- | --- |
| **#127** | **OPEN**，title `Unified Monitor｜统一监控与 Go 迁移`；0 comments；创建=最后更新 `2026-11-25T21:45:37Z`；由 `chatgpt-codex-connector` 创建 | 唯一 UM 跟踪 Issue；本计划不新建重复 Issue |
| #48 | **CLOSED / completed**，2026-11-25T20:49:12Z 由 `yikkrrtykj` 关闭；4 条评论，最后为归档评论 | 与 UM-A 文档一致；本地缓存 `issue48.json` 的 OPEN 是旧状态，勿再引用 |
| #33 | OPEN，title 未变；最后更新 2026-10-08 | 不触碰、不重开、不重解释 |
| #67 | OPEN，title 未变；最后更新 2026-10-08 | FROZEN；UM 不得修改/启用/依赖其契约 |
| 重复 UM Issue | 无 | open issues 仅为 #127、#67、#33 |

## 4.1 UM-A 文档中需在 amendment 时更正的已知事实/不一致

以下为本轮审计发现、但不属于本 PR 修改范围（不改 rev-4 内容）：

| 项 | 发现 | 处理建议 |
| --- | --- | --- |
| sbox-cm 操作数 | UM-A `01` 写“seven ops”，实际代码注册 **12 个** op（`sbox-cm/sbox-cm:68-86`，含 `client.bundle` 与四个 `probe.*`） | amendment/后续文档更正；UM 不得依赖任一计数 |
| #48 状态 | UM-A 文档写 Closed/Completed；本地旧缓存 `issue48.json` 写 OPEN；**实时核对为 CLOSED/completed（2026-11-25T20:49:12Z）** | 以 01 §4 实时结果为准，不重开/不重解释 |
| 版本标签 | 文档自标 “revision 3 final”，但 HEAD 追加了 final corrections；PR body 使用 “rev-4” 语义 | 见 §2.0；amendment 时统一标签 |
| 命名/引用不一致 | `node_boot` vs 文中 `node_seq`；`seq_dedupe` 在 03 §9/05 §2 的保留表中缺失；错误码 `replay` 未被使用；`pending_activation`/“old key grace” 等 rev-2 残留；11 行/35 case 等历史计数 | amendment 时逐项清理，并在 PR-A2 文档一致性检查中验证 |
| 签名向量覆盖 | 只有 report + enrollment 正向量；**没有 rotate/config 正向量**（只有签名串与 behavioural cases） | PR-A2 或 UM-B1 补 rotate/config 正向量 |
| “PASS” 声明 | PR body/08 的 architecture/technology PASS 无 reviewer 对象 | 不当作独立审查；由 OD-G1 处理 |

## 5. 本轮结论

1. **UM-A 收口未完成**：#126 干净、CI 绿、可合并（MERGEABLE/CLEAN），但 **Draft、无独立审查、18 项 Owner 决策 PENDING**；合并前置不满足。不得擅自改为 Ready、不得合并。
2. **main 基线可用**：885171c0，CI 全绿；但 main 无分支保护，记录为流程风险。
3. **Go 开发分支完整保留**：24cfd2ff，3 个开发提交、CI 绿；基于 rev-3，必须按门禁同步，不能直接混入 rev-4。
4. **契约需要修订才能支撑 #127 首版**：恢复语义（`03`）与双平台扩展（`02`）是提案，需 Owner 决策 + UM-A rev-5 amendment + 独立审查；在此之前 UM-B..UM-E 继续 HOLD。
5. 本轮只提交本基线/计划文档（docs-only），不修改 main、不合并 PR、不改写 Go 分支、不实现、不部署。

## 6. 复现证据索引

```text
gh pr view 126 --json state,isDraft,headRefOid,mergeStateStatus,reviewDecision,updatedAt
gh api repos/yikkrrtykj/install-singboxhysteria2/pulls/126/reviews
gh api repos/yikkrrtykj/install-singboxhysteria2/pulls/126/comments
gh api repos/yikkrrtykj/install-singboxhysteria2/issues/126/comments
gh api repos/yikkrrtykj/install-singboxhysteria2/issues/126/timeline
gh pr checks 126
git rev-parse '5089cdeb^{tree}'            # f1cb4fe4...
git fetch origin refs/pull/126/merge && git rev-parse 'FETCH_HEAD^{tree}'  # 同 tree
gh run view 45706557111 --json jobs
git log --oneline origin/main..origin/codex/um-windows-foundation
gh issue view 48 --json state,stateReason,closedAt
gh api repos/yikkrrtykj/install-singboxhysteria2/branches/main/protection   # 404
```
