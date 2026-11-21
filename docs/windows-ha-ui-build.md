# Windows HA-UI — 构建、测试与交付校验

## 1. 固定工具链

| 组件 | 版本 |
| --- | --- |
| CPython（构建/运行 EXE 打包解释器） | 3.13.x（`BUILD_PYTHON=(3, 13)`） |
| PySide6 | 6.12.0 |
| paramiko | 5.1.0 |
| keyring | 25.7.0 |
| PyInstaller | 6.22.3 |
| pytest / pytest-qt | 8.4.2 / 4.5.0 |

版本同时固定在 `ha-ui/requirements.txt`、`ha-ui/requirements-dev.txt` 与
`ha-ui/scripts/build_windows.py`；CI 的 `static-gates` 任务会校验两者一致，避免漂移。
EXE 用 `--onefile --windowed --noupx` 构建，不嵌入任何配置或凭据；首次运行在
`%LOCALAPPDATA%\HASingbox` 创建私有工作区。

## 2. 本地构建

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r ha-ui\requirements-dev.txt
.\.venv\Scripts\python.exe ha-ui\scripts\build_windows.py
```

产物：

```
dist\ha-ui.exe
dist\receipt.json      # 版本、依赖、source tree 哈希、tool 哈希、EXE SHA-256、self-test
dist\SHA256SUMS.txt
```

构建脚本会：

1. 拒绝非 Windows 主机与非 3.13 解释器；
2. 校验所有依赖为固定版本；
3. 计算应用源码 + 5 个已审查 HA 工具的 source-tree SHA-256；
4. 调用 PyInstaller（含 `tools/` 数据文件、`keyring.backends.Windows` hidden import）；
5. 以 `QT_QPA_PLATFORM=offscreen` + 独立 `HA_UI_HOME` 运行 **EXE 冷启动 self-test**，
   校验退出码与结果文件；
6. 写 `receipt.json`（`signed=false`、`configuration_embedded=false`）与 EXE SHA-256。

`--skip-selftest` 只用于排障；CI 不使用。

## 3. 测试

```powershell
$env:QT_QPA_PLATFORM='offscreen'
cd ha-ui
..\.venv\Scripts\python.exe -m pytest tests -q
```

覆盖（详见各测试文件）：

- 本机 Windows：真实 NTFS ACL 建立/校验、ACL 负例（额外授权用户 → 拒绝）、
  junction/reparse 拒绝、no-clobber、路径逃逸、原子替换；
- 凭据：凭据管理器不可用/写入失败/读回不一致/删除不存在；配置文件拒绝 password 类键；
- SSH：主机指纹匹配/缺失/变化、关闭端口连接失败、下载文件属性校验；
- 远程数据层：fake SSH 会话覆盖 preflight 各拒绝分支、客户端列表 union/不完整/重复、
  PIN 解析与 A/B 重复/过期/有效期不足、菜单生成同意门、远端/本地 SHA 不一致；
- HA 链：真实 HA-02→03→04→friendly 合成 exports 集成测试（Windows 本机），
  A-first/B-first、单客户端/批量、失败阶段清理、取消、旧产物不被覆盖、回执不含凭据；
- UI：`pytest-qt` offscreen 冒烟（服务器/客户端/生成面板）、GUI 冷启动 `--self-test`；
- 打包：版本 pin 一致、PyInstaller 参数、CI workflow 契约。

## 4. CI

审查用 workflow 模板：`ha-ui/ci/ha-ui-workflow.yml`。GitHub 对 OAuth token 的
workflow 文件更新要求 `workflow` scope，本仓库当前自动化 token 只有 `repo` scope，
因此提交时保留了模板而不是直接放入 `.github/workflows/`；由具备该 scope 的维护者
执行一次：

```powershell
Copy-Item ha-ui\ci\ha-ui-workflow.yml .github\workflows\ha-ui.yml
```

激活后（模板与激活文件必须逐字节一致，打包测试会校验）：

| job | 内容 |
| --- | --- |
| `static-gates`（ubuntu） | `py_compile`、requirements/构建脚本 pin 一致、禁止监听/自动导入的静态门 |
| `windows-tests`（windows-2022） | 固定依赖 + offscreen pytest + `--self-test`，上传 JUnit |
| `windows-exe`（windows-2022） | 构建 EXE + 冷启动 self-test + receipt 校验 + 上传 EXE/receipt/SHA256SUMS |

CI 不连接 VPS、不读取真实凭据、不合并/部署任何东西；CI 通过不能替代真实 Windows +
两台已授权 VPS 的手工验收。

## 5. 下载/交付校验

拿到 CI 或本地构建的产物后：

```powershell
Get-FileHash dist\ha-ui.exe -Algorithm SHA256
Get-Content dist\receipt.json -Raw | ConvertFrom-Json | Select-Object exe_sha256,signed,configuration_embedded,selftest
```

要求：`exe_sha256` 与 `Get-FileHash` 一致；`signed=false`（未签名，Windows 可能提示
SmartScreen）；`configuration_embedded=false`；`selftest.ok=true`。只能从本仓库
Actions artifact 或本仓库 CI 记录的哈希获取 EXE，不要使用来源不明的同名文件。

## 6. 回滚/卸载

- 删除 EXE 即移除程序；
- 删除 `%LOCALAPPDATA%\HASingbox` 即移除所有本地私有配置、运行目录与交付文件；
- 在 Windows 凭据管理器删除 `ha-ui-ssh` 下的 `server-A` / `server-B` 条目；
- 本工具不修改服务器，因此无需服务器回滚；HA 交付本身按运行目录内原始
  manifest/文件手工回退。
