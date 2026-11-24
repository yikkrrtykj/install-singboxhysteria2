# HA-UI 预验收 PR 审计（2026-11-21）

> 历史文档：本文记录 0.1.0 预验收（#111–#115）。0.2.0 已新增 GUI 双端创建、
> 信任锚刷新与页面重构；创建相关的安全/验收边界以
> `docs/windows-ha-ui-data-path.md` §7、`docs/windows-ha-ui-operator.md` §3 与
> `docs/windows-ha-ui-acceptance.md` C0–C0e 为准。本文的“只读”描述仅适用于
> 0.1.0 生成链，不适用于 0.2.0 新建客户端。

范围：#111–#115 的 exact HEAD、base、merge-base、变更范围、测试证据、CI，以及
#111 ↔ #114 菜单自动化兼容性、#112 → #114 代码依赖。所有 PR 保持 Draft；本审计**不
合并、不部署**。

## 1. Exact HEAD / base / merge-base

| PR | 角色 | Head | Base | Merge-base | Draft | 变更 |
| --- | --- | --- | --- | --- | --- | --- |
| #111 | 菜单 10 提示修复 | `86d9e7948f` | `2a810a99` (`main`) | `2a810a99` | 是 | 2 files, +61/−2 |
| #112 | friendly-export 适配器 + 修复 | `14b59ae97f` | `2a810a99` (`main`) | `2a810a99` | 是 | 3 files, +422/−0 |
| #113 | GUI/SSH/凭据框架 | `07959ab557` | `2a810a99` (`main`) | `2a810a99` | 是 | 29 files, +5516/−0 |
| #114 | 客户端读取/导出/HA 链 UI | `971b210088` | `07959ab557` (#113 head) | `07959ab557` | 是 | 21 files, +5782/−44 |
| #115 | EXE/CI/文档 | `381a52fd89` | `971b210088` (#114 head) | `971b210088` | 是 | 9 files, +946/−0 |

提取命令（可复核）：

```bash
gh pr view <n> --json number,headRefOid,baseRefOid,additions,deletions,changedFiles,isDraft
git merge-base <head> <base>
```

依赖链：`main → #113 → #114 → #115`；#111/#112 独立于 #113–#115（均基于 main），
合并顺序建议 **#111、#112、#113、#114、#115**。堆叠 PR 在对应 base 合并后应 retarget
到 `main`，以去掉重复显示的依赖 diff。

## 2. #111 ↔ #114 菜单自动化兼容性

自动化向现有菜单发送固定输入序列 `10 → 1 → 3 → <client>… → 0`，并要求以下文本出现：
顶层 `10. 客户端管理`、`client_management_menu`、客户端菜单
`3) generate_client_configuration_interactive`、成功行
`客户端 '<name>' 的 Mihomo 配置已生成`。

对 `origin/main` 与 #111 head 的 `install.sh` 逐项静态比对（同一脚本读取 git blob）：

| 标记 | main | #111 |
| --- | --- | --- |
| `10. 客户端管理` | ✅ | ✅ |
| 顶层 `10) → client_management_menu` | ✅ | ✅ |
| 客户端菜单 `1) list_clients` / `3) generate_client_configuration_interactive` / `0) break` | ✅ | ✅ |
| 成功行 `的 Mihomo 配置已生成` | ✅ | ✅ |

#111 仅修改 `generate_client_configuration_interactive` 内的提示/重试/EOF/取消，
不重编号、不改成功文案、不改 `generate_client_configuration` 语义；输入序列与转录
校验在 #111 前后均有效。新增 `tests/test_menu_contract.py` 对当前 main 的菜单结构、
输入映射、成功文案与远程命令边界做自动回归（6 项）。

## 3. #112 修复是否被 #114 正确引用

- `git merge-base --is-ancestor 14b59ae97f 971b210088` → **0（是祖先）**；
- #114 head 中的 `tools/mihomo-competition-ha-friendly-export.py` 与 #112 head
  内容一致（同 commit blob；Windows checkout 下运行文件的逐字节 SHA-256 会被 autocrlf
  影响，因此以 git blob/提交祖先为准，构建 receipt 另行记录实际执行字节的哈希）；
- #114 的生成链调用 #112 的 `export_one`/错误码透传语义，并在本机真实链集成测试中
  覆盖 A-first/B-first、角色绑定、no-clobber、失败回滚；
- #115 包含 #114（`git merge-base --is-ancestor 971b210088 381a52fd89` → 0），
  因此当前 EXE 验收分支同时包含 #112 修复。

## 4. 测试与 CI 证据

| PR | 本机/针对性证据 | GitHub CI（提交时） |
| --- | --- | --- |
| #111 | Git Bash `tests/test-phase-c.sh` 132 pass / 0 fail；同用例在 main 上 12 fail（有效区分） | 20/20 checks green |
| #112 | 适配器单测 8/8；真实链合成 HA-02→03→04→friendly 手工验证；失败码/回滚回归 | 20/20 green |
| #113 | 核心安全套件 336 passed / 2 host skips；`--self-test` OK | 20/20 green |
| #114 | 数据链 77 项 + UI 15 项；全量 428 passed / 2 skips；真实链集成；菜单失败注入（本分支增强后 21 项） | 20/20 green |
| #115 | 434 passed / 2 skips；EXE 构建 + 冷启动 self-test；本机 CI runner；workflow 模板契约 | 20/20 green（既有 CI；新 HA-UI job 未激活） |

预验收加固分支（本审计所属 Draft PR）新增：远程菜单退出状态/超时/部分生成/来源证明
失败注入 21 项、菜单契约 6 项、CI pin gate / 本地 CI runner / 激活助手契约测试；全量
测试与 EXE 重建结果见该 PR 描述与 `.scratch/ci/summary.json`（本地，git-ignored）。

## 5. CI 状态说明（不得夸大）

- #111–#115 的 20 个 checks 来自仓库**既有** CI lanes（bash suites、windows-2022
  contracts/foundations、core-regression 等），不是新的 HA-UI Windows pytest/EXE
  job；
- 新 `ha-ui/ci/ha-ui-workflow.yml` 需维护者用具备 `workflow` scope 的凭据激活；当前
  自动化 token 只有 `repo` scope，**未激活**，不能以“HA-UI CI 已通过”表述；
- 激活与本机镜像步骤见 `docs/windows-ha-ui-build.md` §4。

## 6. 结论与门禁

- 五个 PR 均为 Draft，HEAD/base/merge-base 明确，依赖关系可复核；
- #111 与 #114 菜单自动化兼容；#112 修复已被 #114（及 #115）正确包含；
- 自动/Windows 本机可验证项已覆盖并留证据；
- 仍待完成：真实两台 VPS 只读验收（Layer B）、隔离测试 VPS 生成与 Clash Verge Rev
  导入（Layer C），见 `docs/windows-ha-ui-acceptance.md`；
- 任何 PR 的合并、workflow 激活、生产 VPS 操作均需人工批准，本审计不执行。
