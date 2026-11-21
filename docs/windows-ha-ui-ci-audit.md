# HA-UI Windows CI 最终审计（2026-11-21，PR #116）

本文件记录发布前对 `ha-ui/ci/ha-ui-workflow.yml`、激活助手与本地 CI 镜像的最终检查。
**结论：CI 模板已加固且未激活；现有仓库 20/20 checks 不是新 HA-UI Windows 专项 CI。**

## 1. 依赖与工具链固定

| 组件 | 固定值 | 校验点 |
| --- | --- | --- |
| CPython | 3.13.x（构建脚本 `BUILD_PYTHON=(3,13)`） | `check_pins.py` / build receipt |
| PySide6 | 6.12.0 | requirements + `pip check` + `check_pins.py` + receipt |
| paramiko | 5.1.0 | 同上 |
| keyring | 25.7.0 | 同上 |
| PyInstaller | 6.22.3 | build 脚本强制 + receipt |
| pytest / pytest-qt | 8.4.2 / 4.5.0 | requirements-dev + `check_pins.py` |
| 5 个 HA tool | 逐文件 SHA-256 | build receipt + `verify_receipt.py` |

`ha-ui/ci/check_pins.py` 同时提供 `--static-only`（无依赖环境，static job）与已安装校验
（Windows jobs）；`ha-ui/ci/verify_receipt.py` 复核 EXE 大小/SHA-256、receipt 的
Python/PyInstaller/依赖、source-tree 哈希、5 个 tool 哈希、selftest、signed=false、
configuration_embedded=false。

## 2. EXE / 冷启动 / 哈希

- `build_windows.py`：`--onefile --windowed --noupx`，tools 作为数据文件；构建后以
  offscreen + 构建目录内 TEMP 运行 **EXE 冷启动 self-test**，失败即构建失败。
- receipt 记录：构建时间、Python、PyInstaller、依赖、EXE 名称/大小/SHA-256、
  source-tree SHA-256、每个 tool SHA-256、selftest、git HEAD；
  `signed=false`、`configuration_embedded=false`。
- workflow `windows-exe` 调用 `verify_receipt.py`，不再只比较单层哈希；artifact 上传
  设置 `if-no-files-found: error`，并在 step summary 输出 EXE SHA-256/依赖版本。
- 本机 `run-windows-ci.ps1` 与 CI 同源（pin gate → pytest → self-test → 构建 →
  `verify_receipt.py` → summary）。

## 3. 无 VPS / Clash / TUN / 提权操作

静态门与测试共同确认 workflow：

- 无 `ssh`/`scp`/`apt-get`/`systemctl`/`sing-box`/`servers.json`/`management.active`
  操作；
- 无 `gh pr merge`、部署、TUN/Clash 自动导入；
- `permissions: contents: read`、`persist-credentials: false`；
- 测试 `test_packaging.py::test_ci_workflow_has_no_vps_or_client_import_automation`
  对上述模式做 fail-closed 检查（允许静态门文本中作为“禁止构造”出现的词）。

## 4. workflow scope 与激活（不得绕过）

当前自动化 token 的 scopes 为 `gist, read:org, repo`，**没有 `workflow` scope**；
GitHub 因此拒绝推送 `.github/workflows/` 文件。本仓库：

- 不伪造 token/不绕过权限；
- 保留审查用模板 `ha-ui/ci/ha-ui-workflow.yml`；
- 提供 `ha-ui/ci/activate-workflow.ps1`（默认 dry-run，`-Apply` 只本地复制并逐字节
  校验，不提交/不推送）；
- 维护者最小激活流程与独立 CI PR 方案见 `docs/windows-ha-ui-build.md` §4.2/§4.3。

激活完成的判据：`gh workflow list` 出现该 workflow，且 `gh run list` 至少两次 run
（`windows-tests`、`windows-exe`）成功、EXE artifact 的 receipt/selftest/hash 校验
通过；在此之前不得声称 HA-UI Windows CI 已激活。

## 5. 本机验证证据（2026-11-21）

- `pytest ha-ui/tests -q` → **475 passed, 2 host skips**（当前分支）。
- `run-windows-ci.ps1` 全量通过；最终 EXE 构建 + 冷启动 self-test + `verify_receipt.py`
  通过（hash 见 PR #116 评论/本地 `.scratch/ci/summary.json`，git-ignored）。
- GUI 真实 EXE UIA 验收 A1–A10 通过（详见 PR #116 评论与
  `docs/windows-ha-ui-acceptance.md`）。
