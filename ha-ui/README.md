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

   Windows CI workflow 模板在 [`ha-ui/ci/ha-ui-workflow.yml`](ci/ha-ui-workflow.yml)；
   本机 CI 镜像 `ha-ui/ci/run-windows-ci.ps1`；激活方式（需要 workflow scope 的维护者）
   见构建文档 §4。

3. 操作步骤见 [`docs/windows-ha-ui-operator.md`](../docs/windows-ha-ui-operator.md)；
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

Draft MVP（Issue #110）。自动测试与 Windows 本机 EXE 冷启动已通过；三层真实验收
（本机 GUI 人工清单 → 两台 VPS 只读 → 隔离测试 VPS 生成/Clash 导入）仍待授权执行，
见验收手册。CI 通过不替代真实环境验收。未签名 EXE 仅从本仓库 CI/构建产物获取并核对
SHA-256。
