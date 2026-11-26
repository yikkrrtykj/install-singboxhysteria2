# UM-127 01 — 基线快照与 #126 rev-5 收口核对

- 记录时间：2026-11-26 08:2x UTC / 11:2x +03:00（Round-2 同步）。
- 状态：**事实记录 + PROPOSED 判断**；不修改现有分支/PR/Issue，不把 PENDING 标为 APPROVED。
- 证据来源：GitHub API（`gh`，账号 `yikkrrtykj`）、`git fetch` 后的 `origin/*`、只读 worktree 核对；原始 JSON 在本地临时工作区（不入库）。

## 1. 仓库与 main

| 项目 | 值 |
| --- | --- |
| 仓库 | `yikkrrtykj/install-singboxhysteria2`（public；默认分支 `main`） |
| main HEAD | `885171c08210ad0f4e91f0fed0243460d294b15e`（PR #125 merge）；CI attempt 1 全绿 |
| 分支保护 | 无（GitHub API 404 `Branch not protected`）——流程风险 |
| main 上的 UM 产物 | 无 `docs/um` / `um/` / `um-go.yml`；所有 UM 内容仍在未合并分支 |

## 2. PR #126（最终契约，rev-5）

### 2.1 HEAD / Tree / 版本

| 项目 | 值 |
| --- | --- |
| 编号/标题 | #126 `docs(um): UM-A architecture, technology selection and frozen v1 contracts` |
| 状态 | OPEN + **Draft**（未 Ready、未合并、无独立 review 记录） |
| base | `main` @ `885171c0` |
| head 分支 | `docs/um-a-architecture-freeze` |
| Round-2 rev-5 HEAD | **`048fc170685da5b7140bebd9e3347616cb3ec656`** |
| rev-5 tree | **`1b726de92d57dfc9cf61c10b8f7d8a063bc97875`** |
| 相对 Round-1 | 新增 `docs(um): freeze rev-5 final contract (recovery, node classes, Windows telemetry)`；重写 24 个契约/文档文件，新增 5 个 examples |
| labels/assignees/milestone | 空 |
| 独立审查 | GitHub reviews/comments/requested reviewers = 0；`reviewDecision` 空；Owner Round-2 结论属 Owner 审查，不是独立 review |

### 2.2 rev-5 契约内容（已冻结进 #126）

- A-1..A-5 恢复语义：bounded generation forward jump（`MAX_BOOT_GAP=65535`）、首接触 `seq>1`、ACK `next_seq` 采纳、superseded attempt 忽略、rotation 全量校验不得绕过 high-water。
- 数值/存储：`MAX_NUMERIC=2^63−2`；canonical decimal；SQLite signed INTEGER + CHECK；`next_seq:null` exhaustion；无 uint64 wrap。
- `node_class`（linux_vps/windows_terminal）+ token scope 绑定 event+class + 平台隔离。
- Windows 六路径（`a_reality/a_hy2/b_reality/b_hy2/direct/unknown`）snapshot/events、独立采样、UNKNOWN/UNAVAILABLE、版本化 A/B→VPS 映射、隐私负例、签名向量。
- 行为向量：45 个 rev-4-origin 更新 + 22 个 rev-5 新增 = 67；`superseded_rev4_expectations` 与 `historical_rev4_enroll_vector` 保留追溯。
- 签名向量：report（rev-4 保留）、Windows terminal report、enroll（rev-5）、rotate、config 全部验证通过；crypto 负例失败符合预期。

### 2.3 CI

#126 rev-5 的 CI 以 PR 检查为准（现有 5 个触发 workflow；含已知 Windows `windows-exe` harness flake 的 recorded rerun，本 PR 不修改测试/workflow）。docs-only 变更不读取 `docs/um`，CI 为回归检查。

## 3. Go 开发分支（保持不动）

| 项目 | 值 |
| --- | --- |
| 分支 | `codex/um-windows-foundation`（远端存在，无 PR） |
| HEAD | **`24cfd2ffcd7a400785dbd3848278813be50f3618`**（与任务给定一致） |
| 与 main 关系 | merge-base `885171c0`；`main..HEAD` 6 个提交 = 3 个 UM-A docs 提交（`d2818a78`/`2886619c`/`089f27a5`）+ **3 个 Go 开发提交** |
| 3 个开发提交 | `17b2f3e2` observer；`758e75be` Go CI；`24cfd2ff` signing primitives |
| 分支基点 | 父提交 `089f27a5`（rev-3）；**不含 rev-4/rev-5** |
| CI | run `45706557111` 双平台 success |
| 提交身份 | 全部 author/committer 为 `yikkrrtykj <152189277+yikkrrtykj@users.noreply.github.com>` |
| 关键缺口 | wire 仍是 rev-3 14 行签名（缺 `X-UM-Boot-Gen`）；`windowsobs` 仅四角色、无 terminal body/服务化；同步 rev-5 后旧测试预期失败（B1 修复，禁止回退契约） |
| 保序规则 | G-4 前不 rebase/force/cherry-pick/merge main；保留 3 个提交 SHA |

## 4. Issue 与边界状态

| Issue | 状态（实时核对） |
| --- | --- |
| **#127** | **OPEN**，唯一 UM 跟踪 Issue；本计划不新建重复 Issue |
| #48 | **CLOSED / completed**（2026-11-25T20:49:12Z，实时核实）；不重开/不重解释 |
| #33 / #67 | OPEN，title 未变，未触碰；#67 契约 frozen |
| 重复 UM Issue | 无 |

## 5. Owner Round-2 记录与门禁

Owner 结论：#128 计划 PASS；恢复设计 A-1..A-5 ACCEPTED DIRECTION；双平台架构 PASS；Go 路线 PASS；最终契约 targeted update（已完成 rev-5）；CI PASS with recorded rerun；**merge/deployment 需单独 Owner 授权**。

| 门禁 | 状态 |
| --- | --- |
| G-1 #126 rev-5 独立审查 PASS | 未满足（GitHub 无 review） |
| G-2 Owner 授权 + 普通 Merge Commit #126 + main CI | HOLD |
| G-3 #128 独立审查/合并门禁 | HOLD |
| G-4 最新 main CI + Owner 授权 → 同步 Go 分支 | HOLD |
| G-5 UM-B1..UM-G 切片授权 | HOLD |
| G-6 生产部署/发布/资源 | HOLD |

## 6. 结论

1. **设计阶段已收口**：rev-5 把恢复、数值/存储、node_class/平台隔离、六路径 Windows 遥测、映射版本、R2/R1 写进 #126；#128 已按 rev-5 同步，不再有 PR-A2。
2. **#126 仍未合并**：Draft、无独立 review、无 Owner 合并授权；main/生产未变。
3. **Go 分支完整保留**：3 个提交、CI 绿、无 PR；同步必须等 G-2/G-4 且保留提交，`docs/um` 取 main、旧签名测试失败在 B1 修复。
4. **下一步**：独立审查 #126 → Owner 合并授权 → 合并/main CI → #128 审查/合并 → 最新 main CI + 授权 → Go 同步 → UM-B1。

## 7. 复现证据

```text
gh pr view 126 --json state,isDraft,headRefOid,mergeStateStatus,reviewDecision
gh api repos/yikkrrtykj/install-singboxhysteria2/pulls/126/reviews
git -C sinbox-um-a rev-parse HEAD 'HEAD^{tree}'
git -C sinbox-um-a log --oneline origin/main..HEAD
gh run view 45706557111 --json jobs
git ls-remote origin refs/heads/main refs/heads/codex/um-windows-foundation
gh issue view 48 --json state,stateReason,closedAt
```
