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
- 远程菜单生成加固：安装脚本下载后/执行前结构校验（菜单漂移拒绝）、`PIPESTATUS`
  非零/超时/管道失败、缺少结束/退出码标记、转录缺失/部分生成、成功文案但文件未重写、
  非私有/空派生文件、既有派生文件不被误认等失败注入；
- HA 链：真实 HA-02→03→04→friendly 合成 exports 集成测试（Windows 本机），
  A-first/B-first、单客户端/批量、失败阶段清理、取消、旧产物不被覆盖、回执不含凭据；
- UI：`pytest-qt` offscreen 冒烟（服务器/客户端/生成面板）、GUI 冷启动 `--self-test`；
- 打包/CI：版本 pin 一致、PyInstaller 参数、CI workflow 契约与本地 CI runner。

## 4. CI

审查用 workflow 模板：`ha-ui/ci/ha-ui-workflow.yml`；**已激活**为
`.github/workflows/ha-ui.yml`（PR #117，main 合并后启用）。GitHub 对 OAuth token
的 workflow 文件更新要求 `workflow` scope；激活时已由维护者授权，模板与激活文件
保持逐字节一致（`test_packaging.py` 会校验）。历史激活步骤保留在 §4.2，供审计；
已有仓库 CI 仍会跑其它 lane，Windows 专项矩阵由 `ha-ui.yml` 独立运行。

### 4.1 本机镜像（无需 workflow scope，验收必跑）

```powershell
# 从仓库根目录；如未建 venv，先安装 pinned 依赖
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r ha-ui\requirements-dev.txt
powershell -NoProfile -ExecutionPolicy Bypass -File ha-ui\ci\run-windows-ci.ps1 `
  -SkipInstall -Python .\.venv\Scripts\python.exe
```

该脚本与 CI 矩阵同源：Python 3.13 检查、`pip check`、精确 pin gate、offscreen pytest
（含真实 NTFS ACL 测试）、GUI `--self-test`、PyInstaller EXE 构建 + EXE 冷启动
self-test、receipt/EXE SHA-256 校验、`verify_artifact_sums.py` 全文件哈希校验，并把
结果写到 `.scratch/ci/summary.json`（git-ignored）。`-SkipBuild` 可只跑测试。

专用 gate：

```powershell
python ha-ui\ci\check_pins.py --static-only   # 无依赖环境（CI static job）
python ha-ui\ci\check_pins.py                # 已安装环境（Windows jobs）
```

### 4.2 激活步骤（需维护者人工执行；本仓库不自动做）

模板与激活文件必须逐字节一致，`test_packaging.py` 会校验；助手默认 dry-run：

```powershell
# 1. 预演/检查（不写文件）
powershell -NoProfile -ExecutionPolicy Bypass -File ha-ui\ci\activate-workflow.ps1

# 2. 本地复制并校验字节一致
powershell -NoProfile -ExecutionPolicy Bypass -File ha-ui\ci\activate-workflow.ps1 -Apply

# 3. 提交（独立 review 后）
git add .github/workflows/ha-ui.yml
git commit -m "ci(ha-ui): activate reviewed Windows workflow"

# 4. 推送：需要带 workflow scope 的凭据，或在 GitHub Web UI 创建该文件
gh auth refresh -h github.com -s workflow   # 交互式，仅维护者
git push

# 5. 验证（必须看到 workflow 与两次成功 run 才能称为“已激活”）
gh workflow list --repo yikkrrtykj/install-singboxhysteria2
gh run list --workflow ha-ui.yml --repo yikkrrtykj/install-singboxhysteria2 --limit 5
```

### 4.3 独立 CI 激活 PR 方案（推荐；不混入功能 PR）

当前自动化 token 只有 `repo` scope，**不得绕过权限**。推荐由具备 `workflow` scope 的
维护者开一个**只做 CI 激活**的 PR：

1. 从 `main` 建分支 `ci/ha-ui-workflow-activation`；
2. 只把 `ha-ui/ci/ha-ui-workflow.yml` 复制为 `.github/workflows/ha-ui.yml`，**不改任何
   应用代码**；保留 `ha-ui/ci/` 模板与 `check_pins.py --static-only` 作为审计锚点；
3. PR 描述记录模板 SHA-256、`check_pins --static-only` 输出、与模板逐字节一致的
   `sha256sum` 对比；要求独立 review；
4. 合并后由维护者运行 `gh workflow list` + `gh run list`，确认 `windows-tests` 与
   `windows-exe` 两次 run 成功、EXE artifact 的 receipt/selftest/hash 校验通过；
5. 把 run 链接与 EXE SHA-256 回填到本 Issue/验收记录。**在该步骤完成前，不得把
   现有 20/20 仓库 CI 描述为“HA-UI Windows 专项 CI 已通过”。**

### 4.4 激活后的 job

| job | 内容 |
| --- | --- |
| `static-gates`（ubuntu） | `py_compile`、`check_pins.py --static-only`、禁止监听/自动导入静态门 |
| `windows-tests`（windows-2022） | 固定依赖 + `pip check` + 精确 pin gate + offscreen pytest（含 ACL 测试）+ `--self-test`，上传 JUnit |
| `windows-exe`（windows-2022） | 构建 EXE + 冷启动 self-test + `verify_receipt.py`（Python/PyInstaller/依赖/tool/source-tree/EXE 大小与 SHA-256）+ `verify_artifact_sums.py`（SHA256SUMS 中每个文件的落盘哈希）+ step summary + artifact（`if-no-files-found: error`） |

workflow 不连接 VPS、不读取真实凭据、不合并/部署；CI 通过不能替代真实 Windows +
两台已授权 VPS 的验收。

## 5. 下载/交付校验

### 5.1 从 GitHub Actions 获取（推荐）

- Workflow 页面：
  <https://github.com/yikkrrtykj/install-singboxhysteria2/actions/workflows/ha-ui.yml>
- 在 `main` 最近一次成功的 HA-UI run 下载 artifact **`ha-ui-windows-exe`**
  （`ha-ui.exe`、`receipt.json`、`SHA256SUMS.txt`）。workflow 中
  `retention-days: 7`，artifact 约 7 天后过期；过期后从新的 run 下载或按 §5.3
  本地重建。本轮不引入 GitHub Release 自动发布。

```powershell
gh run list --workflow ha-ui.yml --branch main --limit 1
gh run download <run-id> -n ha-ui-windows-exe -D dist
```

### 5.2 版本识别与完整性校验

先看 `receipt.json` 的 `app_version`、`git_head`（构建 commit）、`built_at`、
`source_tree_sha256`、`exe_sha256`、`pyinstaller`、`python` 与 pinned 依赖版本，
确认与预期一致；然后在解压后的 `dist` 目录执行：

```powershell
# receipt/EXE/source-tree/tool 哈希 + selftest/signed/embedded 标志：
python ha-ui\ci\verify_receipt.py --dist dist
# SHA256SUMS 中每一个文件的落盘 SHA-256（错误哈希/文件缺失/篡改/未列出文件都失败）：
python ha-ui\ci\verify_artifact_sums.py --dist dist
# 人工复核：
Get-FileHash dist\ha-ui.exe -Algorithm SHA256
Get-Content dist\receipt.json -Raw | ConvertFrom-Json |
  Select-Object app_version,git_head,built_at,source_tree_sha256,exe_sha256,signed,configuration_embedded,selftest
```

要求：`exe_sha256` 与 `Get-FileHash` 一致；`SHA256SUMS.txt` 中每一项都匹配实际
文件；`signed=false`（未签名，Windows 可能提示 SmartScreen）；
`configuration_embedded=false`；`selftest.ok=true`。只能从本仓库 Actions artifact
或本仓库 CI 记录的哈希获取 EXE，不要使用来源不明的同名文件。

### 5.3 本地重新构建

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r ha-ui\requirements-dev.txt
.\.venv\Scripts\python.exe ha-ui\scripts\build_windows.py
# 构建后必须对 dist 再跑 §5.2 的两条校验
```

要求 Python 3.13、PyInstaller 6.22.3 与 `requirements.txt` 的 pinned 依赖；未签名
EXE 仅作为本地/CI 构建产物，不替代真实环境验收。

## 6. 回滚/卸载

- 删除 EXE 即移除程序；
- 删除 `%LOCALAPPDATA%\HASingbox` 即移除所有本地私有配置、运行目录与交付文件；
- 在 Windows 凭据管理器删除 `ha-ui-ssh` 下的 `server-A` / `server-B` 条目；
- 本工具不修改服务器，因此无需服务器回滚；HA 交付本身按运行目录内原始
  manifest/文件手工回退。
