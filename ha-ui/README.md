# HA-UI 0.2.0 — Windows 双 VPS 主备配置工具

在 Windows 本机连接两台已安装本仓库 sing-box + `miaomiao` 的 VPS（A/B），完成：

```text
连接 A/B  →  新建或选择同名客户端  →  选择 A-first / B-first  →  生成 YAML
```

生成仍复用仓库既有的 HA-02 → HA-03 → HA-04 → friendly-export 链（每个阶段执行已有
`--check`），输出可人工导入 Clash Verge Rev 的 `<client>-A-first.yaml` /
`<client>-B-first.yaml`。

## 0.2.0 新增

- **新建客户端**：在 GUI 中一次性在 A/B 两端创建同一个逻辑客户端；两端各自生成
  独立的 Reality UUID 与 HY2 密码，不跨服务器同步凭据。
- 创建前弹出明确的写入确认：会修改两台 VPS 的客户端配置，并可能执行 reload。
- 两端写入**不是原子事务**：A 成功、B 失败时保留 A，不自动删除，也不会把部分成功
  显示为已完成。
- 若名称只在一端已存在，默认停止；只有再次确认“仅补齐缺失端”后才会创建缺失端，
  绝不覆盖已有凭据。
- 客户端页精简为名称、A/B 端状态、生成状态与优先节点；技术诊断收起；
  证书正常时只显示简短状态，临近到期才提醒。
- 生成页默认只保留选择摘要、主按钮与结果；探测策略、进度日志、重试/清理折叠在
  “高级选项”中。

## 边界（必须保留）

- 本地工具：无公网/本地监听端口，不自动导入 Clash、不开启 TUN、不改系统代理。
- 新建客户端是**远程写操作**：只走已审查的 `install.sh` 菜单 10 → 2 路径
  （`add_client` → `with_client_lock` → `cm_add_client_candidate_planned` →
  `commit_server_config`），不在 GUI 中直接编辑 `sbconfig_server.json`，不调用
  `sbox-cm` worker 绕过管理面权限。
- 生成 YAML 本身仍是本地操作；`miaomiao` 菜单只用于生成缺失/过期的派生导出。
- 凭据：SSH 密码可选保存到 Windows 凭据管理器；所有含凭据文件位于
  `%LOCALAPPDATA%\HASingbox` 私有 ACL 目录；UI/日志/回执不显示密码、UUID、YAML。
- installer/lib 使用固定 reviewed commit + 独立 SHA-256 校验；**绝不执行 `main` 的
  可变字节**。升级依赖时需重新安全审查并同步常量、文档与测试。

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

3. **从 GitHub Actions 获取正式 EXE（推荐）**

   - Workflow 页面：
     <https://github.com/yikkrrtykj/install-singboxhysteria2/actions/workflows/ha-ui.yml>
   - 在最近一次成功的 HA-UI run 中下载 artifact **`ha-ui-windows-exe`**
     （含 `ha-ui.exe`、`receipt.json`、`SHA256SUMS.txt`）。artifact 约 7 天后过期。
   - 命令行下载：

     ```powershell
     gh run list --workflow ha-ui.yml --branch main --limit 1
     gh run download <run-id> -n ha-ui-windows-exe -D dist
     ```

   - **完整性校验**（在解压后的 `dist` 目录执行）：

     ```powershell
     git checkout <receipt.git_head>
     python ha-ui\ci\verify_receipt.py --dist dist
     python ha-ui\ci\verify_artifact_sums.py --dist dist
     ```

   - `receipt.json` 记录 `app_version`（0.2.0）、`git_head`、`built_at`、
     `source_tree_sha256`、`exe_sha256`、PyInstaller/Python 与 pinned 依赖版本。
     `signed=false` 表示未签名，Windows 可能弹 SmartScreen。

4. 操作步骤见 [`docs/windows-ha-ui-operator.md`](../docs/windows-ha-ui-operator.md)；
   数据来源与权限边界见
   [`docs/windows-ha-ui-data-path.md`](../docs/windows-ha-ui-data-path.md)；
   安全模型见
   [`docs/windows-ha-ui-security.md`](../docs/windows-ha-ui-security.md)；
   构建与 CI 见
   [`docs/windows-ha-ui-build.md`](../docs/windows-ha-ui-build.md)；
   验收见
   [`docs/windows-ha-ui-acceptance.md`](../docs/windows-ha-ui-acceptance.md)。

## 目录

```text
ha-ui/
  ha_ui/
    app.py                 # QApplication 入口、--self-test
    core/                  # 配置/凭据/ACL/SSH/远程读取与创建/HA 链（无 Qt）
    ui/                    # PySide6 页面、对话框与 worker
  ci/                      # 本地 CI 镜像、pin gate、workflow 模板/激活助手
  scripts/                 # PyInstaller 构建入口
  tests/                   # 安全、数据链、创建、UI、打包回归
```

## 状态

0.2.0 的 GUI/创建功能已在隔离 fake/fixture 与 Windows 本机验证；**没有**在用户真实
A/B VPS 上执行创建或生成。真实双 VPS 验收与 Windows 验收仍需按手册授权执行。
CI 通过不替代真实环境验收；未签名 EXE 只从本仓库 Actions artifact 或经核对的本地
构建产物获取并核对 SHA-256。
