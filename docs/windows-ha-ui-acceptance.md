# Windows HA-UI — 三层真实验收手册（预验收门禁）

本手册定义 HA-UI MVP 进入真实使用前的 **Windows 本机（A）→ 两台 VPS 只读（B）→
隔离测试 VPS 生成（C）** 三层验收。任何一层失败都停止，不进入下一层；三层全部通过且
人工审批完成后，才可讨论生产使用。**本轮代码审查不代表任何一层真实 VPS 验收已完成。**

## 0. 当前状态（2026-11-21）

| 项目 | 状态 | 证据 |
| --- | --- | --- |
| 自动测试（合成凭据，Windows） | ✅ 已通过 | `pytest ha-ui/tests`：461 passed / 2 host skips；真实 HA 链集成、ACL、失败注入、UI |
| Windows EXE 构建 + 冷启动 | ✅ 已通过 | `dist/ha-ui.exe`，EXE self-test OK，`receipt.json` 记录 SHA-256/selftest |
| Windows GUI 实际操作 | ✅ 自动化通过（A1–A10，真实 EXE + UIA） | 真实 `dist\ha-ui.exe`：窗口/三 tab/安全横幅、密码默认隐藏+显示/隐藏、配置保存不含密码、真实 Windows 凭据管理器保存读回/删除、未确认指纹时测试连接与读取客户端均 E_HOSTKEY 拒绝、生成页/取消/策略控件渲染；证据在本地 `.scratch/gui-acceptance-report.json` 与截图（不入库） |
| 真实生成/Cancel（HA 链） | ❌ 未执行 | 需要 Layer C 隔离测试 VPS；本机只验证控件/拒绝路径，不能替代真实生成 |
| 两台 VPS 只读验收（B） | ❌ 未执行 | 未获授权；本 Agent 未连接任何真实 VPS |
| 隔离测试 VPS 生成（C） | ❌ 未执行 | 未获授权；不得在生产 VPS 上执行 |
| 真实 Clash Verge Rev 导入 | ❌ 未执行 | 未授权；需 Layer C 后人工执行 |
| 已泄露凭据轮换 | ❌ 未完成 | 独立人工操作，工具不代替 |

图例：✅ 自动/已做；⚠️ 部分；❌ 待人工/未授权。

## 1. 总则与人工批准

1. **禁止**在任何未经书面授权的 VPS 上运行生成、故障注入、服务重启或配置修改。
2. Layer B 只允许只读命令；**禁止**调用 `miaomiao` 菜单、禁止生成/删除/轮换客户端、
   禁止触碰 `/var/lib/sbox-cm/management.active`、禁止启用 Monitor/E3。
3. Layer C 必须使用隔离测试 VPS（非生产），授权窗口内执行，提前做快照/备份，并保留
   第二条独立 SSH/控制台恢复通道。
4. 任何证据（截图/日志）不得含 SSH 密码、UUID、HY2 密码、完整 YAML、私钥、分享链接；
   服务器 IP 如需记录只放本地私有笔记，不进入 Issue/PR/聊天/CI。
5. 通过/失败以本手册的“通过条件”为准，不以“看起来正常”代替。
6. 任何自动合并/自动部署/自动启用管理面/生产故障注入都在本轮禁止。

## 2. Layer A — Windows 本机

### 2.1 自动前置（每次发布前必跑）

```powershell
# 仓库根目录；pinned venv 已准备
powershell -NoProfile -ExecutionPolicy Bypass -File ha-ui\ci\run-windows-ci.ps1 `
  -SkipInstall -Python .\.venv\Scripts\python.exe
```

通过条件：

- Python 3.13.x；`pip check` 与 `check_pins.py` 通过；
- offscreen pytest 全绿（允许且仅允许已知 2 个宿主 skip）；
- GUI `--self-test` 退出码 0；
- EXE 构建成功，EXE 冷启动 self-test `ok=true`；
- `dist/receipt.json`：`signed=false`、`configuration_embedded=false`、**EXE 实际
  SHA-256 与 receipt 一致**。

### 2.2 人工 GUI 验收清单（必须逐项记录）

> 本轮已在真实 EXE 上自动化执行下表 A1–A10 的可自动部分（UIA；合成数据、真实 Windows
> 凭据管理器、无 VPS 连接），结果见 PR 评论；A5 的“重启后读取”与 A10 的真实生成/Cancel
> 仍需人工或 Layer C。自动化不能替代人工视觉/交互确认。

用**构建出的 `dist\ha-ui.exe`**（非源码运行）在标准 Windows 桌面执行：

| # | 操作 | 通过条件 |
| --- | --- | --- |
| A1 | 启动 EXE，切换三个 tab | 无崩溃；显示安全横幅；客户端/生成页可进入 |
| A2 | 服务器 A/B 填写名称/IP/端口/用户名；密码框输入 | 密码默认显示为圆点；“显示/隐藏”只切换可见性，不写日志/不弹明文 |
| A3 | 不勾“记住密码”保存配置 | `%LOCALAPPDATA%\HASingbox\servers.json` 成功写入且**不含密码**；状态提示“未连接” |
| A4 | 勾“记住密码”后保存；显示后端名 | 成功时明确提示保存到 Windows 凭据管理器；随后可在凭据管理器看到 `ha-ui-ssh` 条目 |
| A5 | 关闭并重启 EXE，读取已保存配置 | 非机密字段恢复；密码不回显；测试连接可从凭据管理器取密码（无真实 VPS 时只验证到“将尝试连接”） |
| A6 | 删除已保存密码 | 凭据管理器条目消失；密码框清空；再次测试提示缺少密码而非静默失败 |
| A7 | 错误场景：错误 IP/端口、未确认指纹 | 显示固定 `E_SSH_*`/`E_HOSTKEY_*` 码 + 安全消息；不自动重试、不泄漏异常文本 |
| A8 | 指纹核对对话框 | 显示算法 + `SHA256:...`；未勾“我已核对”无法确认；指纹变化时有明确警告 |
| A9 | 客户端页/生成页按钮（无可用连接时） | 给出明确未配置/缺指纹/缺密码错误；不崩溃、不伪造数据 |
| A10 | 生成取消/关闭窗口 | 取消按钮最终显示 `E_CANCELLED`；关闭窗口后无残留进程/无未处理异常 |

记录：时间、EXE SHA-256、Windows 版本、逐项结果、截图（脱敏）。失败即停，不用
“重启试一次”掩盖。

## 3. Layer B — 两台 VPS 只读验证（不执行菜单、不生成、不改配置）

> 仅在两台 VPS 的 owner 书面授权后执行。以下命令全部只读。先记录基线，结束时复核
> 基线未变。

### 3.1 主机指纹与系统环境

在 Windows（或受控运维机）执行，**不把 IP 写入工单**：

```powershell
ssh-keyscan -p <PORT> <HOST> | ssh-keygen -lf -     # 与 GUI 显示的 SHA256 指纹逐字比对
ssh -p <PORT> root@<HOST> "id -u; uname -a; . /etc/os-release; echo \"$PRETTY_NAME\"; \
  systemctl is-active sing-box; \
  ls -l /root/sbox/sbconfig_server.json /root/sbox/config /root/sbox/sing-box; \
  command -v miaomiao jq openssl curl timeout sha256sum date; \
  if [ -e /var/lib/sbox-cm/management.active ]; then echo management=active; else echo management=inactive; fi"
```

通过条件：SSH 指纹与 GUI 已确认值一致；`id -u`=0；Linux；sing-box active；
`sbconfig_server.json`/`config` 存在；`miaomiao`＋依赖命令存在；
`management=inactive`（若 active 则**停止**，MVP 不在管理面激活状态生成）。

### 3.2 客户端名单（只读，仅输出名称与协议布尔值）

```bash
jq -r '
  ([.inbounds[]?|select(.tag=="vless-in")]|length) as $rn |
  ([.inbounds[]?|select(.tag=="hy2-in")]|length) as $hn |
  "inbounds reality=\($rn) hy2=\($hn)",
  ([.inbounds[]?|select(.tag=="vless-in")|.users[]?|{n:(.name//""),r:((.uuid//"")|length>0)}]),
  ([.inbounds[]?|select(.tag=="hy2-in")|.users[]?|{n:(.name//""),h:((.password//"")|length>0)}])
' /root/sbox/sbconfig_server.json
```

要求：A/B 各跑一次；只记录名称集合与 Reality/HY2 是否齐全（不得保存原始输出到工单）。

### 3.3 已有规范导出文件（只读元数据 + 哈希）

```bash
for f in /root/sbox/clients/*/mihomo.yaml; do
  [ -e "$f" ] || continue
  stat -c '%n|%a|%u|%s|%y' -- "$f"
  sha256sum -- "$f"
done
```

通过条件：与 GUI 客户端页“导出文件已就绪/需生成”判断一致；属主 root、0600；只记录
文件名/哈希，不复制内容；若缺失/过期，**Layer B 不生成**，留待 Layer C。

### 3.4 HY2 证书 PIN 与有效期（只读）

按 [`docs/mihomo-competition-ha-profile.md`](mihomo-competition-ha-profile.md)
“Obtaining the pin over the trusted SSH management channel”整段执行（只读证书文件，
不读私钥、不改配置），A/B 各一次，记录 `fingerprint= / not_before= / not_after=`。

通过条件：A/B PIN 不同；证书当前有效；剩余有效期满足 [mihomo-competition-ha-profile.md]
的有效期要求（MVP 工具侧还要求 ≥24h，低于 30 天会警告）；与 GUI 读取值一致。

### 3.5 基线不变证明

Layer B 开始/结束各执行一次：

```bash
sha256sum /root/sbox/sbconfig_server.json /root/sbox/config
systemctl show sing-box -p NRestarts
```

通过条件：两个哈希与 NRestarts 均未变化；无客户端/证书/服务变更。**任何变化都视为
Layer B 失败并停止**。

## 4. Layer C — 隔离测试 VPS 生成验收（授权窗口，非生产）

前置：隔离测试 VPS A/B（或与生产同版本快照实例）、`main` 安装、测试客户端已在 A/B
两端同名创建且 Reality/HY2 齐全、测试机无生产业务；准备快照/回滚、第二条独立恢复
通道、书面授权。

| # | 操作 | 通过条件 |
| --- | --- | --- |
| C1 | GUI 连接 A/B，读取客户端 | 列表与两端只读查询一致；单端/不完整客户端被禁止选择 |
| C2 | 选择 1 个客户端 + A-first，勾选菜单生成同意 | 生成完成；显示 `<client>-A-first.yaml` 与 SHA-256 |
| C3 | 同客户端生成 B-first | 4 节点顺序/角色正确；`自动选择` 组为 5s/2000ms；`skip-cert-verify:false` + 正确 A/B pin；HA-03 `<name>-hac.yaml` 保留 60s/5000ms 对照 |
| C4 | 批量 2+ 客户端 | 每客户端独立 A-first/B-first 文件；manifest/文件名/角色一致 |
| C5 | 失败注入（仅在隔离 VPS，经批准）：临时改坏一个客户端/模拟菜单失败/中断网络 | 工具 fail-closed（`E_REMOTE_MENU`/`E_CLIENT_*`/`E_CHAIN_*` 等）；本地不产生交付；旧成功产物不变；无部分 YAML 被接受 |
| C6 | 取消/关闭窗口 | 取消可中断到阶段边界；无残留临时交付；失败运行目录可删除 |
| C7 | SFTP/哈希 | 下载字节与远端 `sha256sum` 一致；本地再校验；私钥/YAML 不进入日志 |
| C8 | Clash Verge Rev 手动导入 | **人工**导入 A-first 与 B-first，确认 4 节点、fallback、探测策略；不自动导入/不开 TUN/不改系统代理；导入后按 [windows-verification](mihomo-competition-ha-windows-verification.md) 验证 |
| C9 | 回滚 | 删除测试客户端/恢复快照；确认测试 VPS sing-box 与配置恢复；本地删除 run 目录与凭据；复核无残留 |

通过条件：C1–C9 全通过 + 自动化测试全绿 + Layer A/B 通过。任何一项失败不得进入生产。

## 5. 失败回滚

- 任何层失败：立即停止；不继续后续层。
- Layer A：删除 EXE/`%LOCALAPPDATA%\HASingbox`，删除 `ha-ui-ssh` 凭据。
- Layer B：只读设计，预期无变更；若基线哈希/NRestarts 变化，立即升级事件、用备份恢复
  并人工核对——不得用本工具“修复”。
- Layer C：删除测试客户端（走既有管理事务/菜单）、恢复快照、轮换测试凭据；确认无生产
  波及；本地删除运行目录与凭据管理器条目。
- 生产：本 MVP 未经上述三层不得用于生产；生产启用需另立审批与变更窗口。

## 6. 审批与 Go/No-Go

| 门 | 批准人 | 记录 |
| --- | --- | --- |
| Layer B 只读访问 | VPS owner / 项目负责人 | 授权时间、范围、执行人 |
| Layer C 隔离测试 VPS 生成/失败注入 | 项目负责人 + 测试环境 owner | 窗口、快照、回滚方案 |
| 生产使用/凭据轮换 | 项目负责人 | 三层通过证据 + 轮换完成确认 |

Go 条件：自动测试全绿；Layer A 人工清单全过；B 基线不变；C1–C9 全过且证书有效期/
凭据独立性满足；已泄露凭据完成轮换；风险清单（见
[`docs/windows-ha-ui-security.md`](windows-ha-ui-security.md)）被接受。
No-Go：任一层失败、管理面激活未审批、证书/PIN 异常、A/B 凭据相同或单端缺失、
CI workflow 激活状态被冒充、真实 Clash 导入未验证。

## 7. 证据模板（本地保存，脱敏后仅提交结论）

```text
layer: A|B|C
date/time (UTC+03):
operator:
exe_sha256 / commit:
windows version:
steps: <A1..A10 / B1..B5 / C1..C9 逐项 pass/fail>
server fact baseline (B): config_sha256_changed=no/yes, state_sha256_changed=no/yes, nrestarts=...
pin summary (B/C): A/B distinct=yes/no, earliest not_after=...
failures: <code + 安全描述>
rollback performed: yes/no
verdict: PASS/FAIL
```
