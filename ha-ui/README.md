# HA-UI — Windows 本地双 VPS 主备配置生成器

Issue #110 的 Windows 本地 MVP：读取两台 VPS（A/B）上已存在的同名客户端规范导出，
选择 A-first / B-first，复用仓库既有 HA-02 → HA-03 → HA-04 → friendly-export 链
（每个阶段执行已有 `--check`），生成可人工导入 Clash Verge Rev 的
`<client>-A-first.yaml` / `<client>-B-first.yaml`。

- 本地工具：无公网/本地监听端口，不自动导入 Clash、不开启 TUN、不改系统代理。
- 只读服务器：不修改 `sbconfig_server.json`，不重启 sing-box，不激活 Monitor/E3 管理面。
- 凭据：SSH 密码可选保存到 Windows 凭据管理器；所有含凭据文件位于
  `%LOCALAPPDATA%\HASingbox` 私有 ACL 目录；UI/日志/回执不显示密码、UUID、YAML。
- 复用：不重新实现 HA 算法；直接加载 `tools/` 下已审查的 Python 模块。

## 快速开始

1. 安装依赖并启动（开发态）：

   ```powershell
   py -3.13 -m venv .venv
   .\.venv\Scripts\python.exe -m pip install -r ha-ui\requirements-dev.txt
   cd ha-ui
   ..\.venv\Scripts\python.exe -m ha_ui.app
   ```

2. 构建 Windows EXE：

   ```powershell
   .\.venv\Scripts\python.exe ha-ui\scripts\build_windows.py
   ```

   产物在 `dist\`（`ha-ui.exe`、`receipt.json`、`SHA256SUMS.txt`）。

   Windows CI workflow 已激活为 [`.github/workflows/ha-ui.yml`](../.github/workflows/ha-ui.yml)
   （内容与已审查模板 `ha-ui/ci/ha-ui-workflow.yml` 逐字节一致）；本机 CI 镜像
   `ha-ui/ci/run-windows-ci.ps1`；构建/激活历史见构建文档 §4。

3. **从 GitHub Actions 获取正式 EXE（推荐）**

   Windows EXE 由 HA-UI workflow 构建，不依赖本地开发目录：

   - Workflow 页面：
     <https://github.com/yikkrrtykj/install-singboxhysteria2/actions/workflows/ha-ui.yml>
   - 在 `main` 最近一次成功的 HA-UI run 中下载 artifact **`ha-ui-windows-exe`**
     （含 `ha-ui.exe`、`receipt.json`、`SHA256SUMS.txt`）。workflow 的
     `retention-days: 7`，artifact 约 7 天后过期；过期后从新的 run 下载或按下方
     本地重建，不会自动发布 GitHub Release。
   - 命令行下载：

     ```powershell
     gh run list --workflow ha-ui.yml --branch main --limit 1
     gh run download <run-id> -n ha-ui-windows-exe -D dist
     ```

   - **版本识别**：`receipt.json` 记录 `app_version`、`git_head`（构建 commit）、
     `built_at`、`source_tree_sha256`、`exe_sha256`、`pyinstaller`、`python` 与
     pinned 依赖版本；用这些字段确认产物与预期版本一致。
   - **完整性校验**（在解压后的 `dist` 目录执行，Windows PowerShell）：

     ```powershell
     Get-FileHash .\dist\ha-ui.exe -Algorithm SHA256
     python ha-ui\ci\verify_receipt.py --dist dist
     python ha-ui\ci\verify_artifact_sums.py --dist dist
     ```

     三条都必须通过；`receipt.json` 的 `signed=false` 表示未签名，Windows 可能
     弹 SmartScreen。只能从本仓库 Actions artifact 或本仓库 CI 记录的哈希获取 EXE。
   - **本地重新构建**：按「快速开始」安装 pinned 依赖后执行
     `python ha-ui\scripts\build_windows.py`；要求 Python 3.13、PyInstaller 6.22.3
     与 `requirements.txt` 的 pinned 依赖；产物在 `dist\`。

4. 操作步骤见 [`docs/windows-ha-ui-operator.md`](../docs/windows-ha-ui-operator.md)；
   数据来源与权限边界见
   [`docs/windows-ha-ui-data-path.md`](../docs/windows-ha-ui-data-path.md)；
   安全模型见 [`docs/windows-ha-ui-security.md`](../docs/windows-ha-ui-security.md)；
   构建与 CI 见 [`docs/windows-ha-ui-build.md`](../docs/windows-ha-ui-build.md)；
   Windows CI 最终审计见
   [`docs/windows-ha-ui-ci-audit.md`](../docs/windows-ha-ui-ci-audit.md)；
   三层真实验收见 [`docs/windows-ha-ui-acceptance.md`](../docs/windows-ha-ui-acceptance.md)；
   PR 审计见 [`docs/windows-ha-ui-preacceptance-audit.md`](../docs/windows-ha-ui-preacceptance-audit.md)。

## 目录

```
ha-ui/
  ha_ui/
    app.py                 # QApplication 入口、--self-test
    core/                  # 配置/凭据/ACL/SSH/远程读取/HA 链（无 Qt）
    ui/                    # PySide6 面板与 worker
  ci/                      # 本地 CI 镜像、pin gate、workflow 模板/激活助手
  scripts/                 # PyInstaller 构建入口
  tests/                   # 安全、数据链、UI、打包回归
```

## 状态

Issue #110 的 Windows MVP 已合并到 `main`，Windows 专项 CI 已激活；正式 EXE 从
main 最近一次成功的 HA-UI Actions run 下载并校验（见上节）。真实双 VPS 验收与
Windows 三层验收的部分项目仍待授权/执行，见验收手册；CI 通过不替代真实环境验收。
未签名 EXE 仅从本仓库 Actions artifact 或经核对的本地构建产物获取并核对 SHA-256。
