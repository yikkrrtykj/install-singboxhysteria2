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
