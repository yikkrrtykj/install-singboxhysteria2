# HA-UI 0.2.0 — 合成数据 UI 截图

这些截图由 0.2.0 开发树的真实 PySide6 窗口在 Windows 本机渲染生成，**全部使用合成
数据**：

- 客户端名称为 `event-vmix01` / `event-vmix02` / `event-final`；
- 服务器 IP 使用 RFC 5737 文档地址，截图中不显示；
- 不使用真实 SSH 密码、UUID、HY2 密码、YAML 或服务器配置；
- 不连接任何 VPS，不读取 Windows 凭据管理器。

| 文件 | 内容 |
| --- | --- |
| `clients-page.png` | 1120×780 逻辑尺寸；正常/待生成/配置异常行、证书提醒、主按钮「新建客户端」、A/B 状态、精简状态列与「查看原因」 |
| `partial-create-result.png` | 1120×780；A 成功、B 失败的持久部分成功提示，保留 A、不自动删除，表格准确显示「缺少 B 端」 |
| `new-client-dialog.png` | 650×405；名称输入、A+B 目标、写入确认、reload/部分成功不自动删除的提示 |
| `generate-page.png` | 1120×780 逻辑尺寸；已选摘要、主按钮「生成 YAML」、成功态「已生成 1 个文件」与打开文件夹；高级选项默认折叠 |

截图仅用于 UI 评审，不证明真实 A/B VPS 创建、生成或 Clash 导入已通过验收；真实
验收边界见 `docs/windows-ha-ui-acceptance.md`。

## PR #124 第一轮复审修复（2026-11-24）

本轮是行为/分类/验收修复，不新增界面截图（界面只有“待确认 / STALE / 已回滚”文案变化）。

| 项 | 结果 |
| --- | --- |
| offscreen pytest（本机 Windows，Python 3.13.15，pinned deps） | `580 passed, 4 skipped`（skip 均为宿主限制：3×symlink、1×真实凭据库） |
| 新增测试 | `tests/test_record_completeness.py`、`tests/test_windows_console_isolation.py` |
| 创建结果分类 | `created` / `failed(pre-write)` / `failed(rolled-back)` / `uncertain(...)`；规则见 `docs/windows-ha-ui-data-path.md` §7 |
| P0 事务安全 | **BLOCKED**：客户端只能检出与不误报，无法提供写入原子性；解除条件见 data-path §8 |
| CMD 弹窗根因 | `icacls.exe` 是控制台子系统程序，windowed EXE 每次私有 ACL 操作都会分配控制台窗口；修复为 `CREATE_NO_WINDOW`（`docs/windows-ha-ui-build.md` §7） |
| CMD 复现（`pythonw.exe`，无控制台） | 旧行为 **6** 个可见控制台窗口；新行为 **0**；正对照 1（检测器有效） |
| EXE 验收 | `ha-ui.exe` SHA-256 `1931d6b5eb31c5d8d8b8794ff7c1088473e73ea2a4553b4dbbf1f64d0c43bf9f`；`--self-test` OK；`check_no_console_popup.py --exe` → `{"checked":true,"positive_control":true,"console_events":0,"ok":true}`；`verify_receipt.py` / `verify_artifact_sums.py` 通过 |

以上数字来自本机 Windows 环境（合成数据、无真实 VPS）；CI 的实测结果见 PR #124 检查列表。
