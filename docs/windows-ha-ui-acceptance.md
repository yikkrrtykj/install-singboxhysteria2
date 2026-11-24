# Windows HA-UI 0.2.0 — 三层真实验收手册（预验收门禁）

本手册定义 HA-UI 0.2.0 进入真实使用前的 **Windows 本机（A）→ 两台 VPS 只读（B）→
隔离测试 VPS 创建/生成（C）** 三层验收。任何一层失败都停止，不进入下一层；三层全部
通过且人工审批完成后，才可讨论生产使用。**本轮代码审查不代表任何一层真实 VPS 验收
已完成。**

## 0. 当前状态（0.2.0 Draft）

| 项目 | 状态 | 证据 |
| --- | --- | --- |
| 自动测试（合成凭据，Windows） | ✅ 已通过 | `pytest ha-ui/tests`：539 passed / 4 host skips（0.2.0 本地） |
| installer 版本/哈希门禁 | ✅ 已通过 | reviewed commit `9402be91…` + installer/lib 独立 SHA-256 + 内嵌 lib pin + host-deps；创建/生成共用 |
| Windows EXE 构建 + 冷启动 | ⏳ 待本轮构建 | 目标 `dist/ha-ui.exe` 0.2.0；receipt/selftest/SHA-256 见 PR 证据 |
| Windows GUI 自动化 | ✅ 合成数据通过（本机 offscreen/Windows Qt） | 新三页、创建对话框、部分成功回执、生成页；截图见 [`docs/evidence/ha-ui-0.2.0`](evidence/ha-ui-0.2.0/README.md) |
| 真实创建（A/B 两端） | ❌ 未执行 | 需要 Layer C 隔离测试 VPS + 书面授权；不得在生产 VPS 首次试跑 |
| 真实生成/Cancel（HA 链） | ❌ 未执行 | 需要 Layer C 隔离测试 VPS；本机只验证控件/拒绝路径 |
| 两台 VPS 只读验收（B） | ❌ 未执行 | 未获授权；未连接任何真实 VPS |
| 隔离测试 VPS 创建/生成（C） | ❌ 未执行 | 未获授权；不得在生产 VPS 上执行 |
| 真实 Clash Verge Rev 导入 | ❌ 未执行 | 未授权；需 Layer C 后人工执行 |
| 已泄露凭据轮换 | ❌ 未完成 | 独立人工操作，工具不代替 |

图例：✅ 自动/已做；⚠️ 部分；⏳ 待本轮；❌ 待人工/未授权。

## 1. 总则与人工批准

1. **禁止**在任何未经书面授权的 VPS 上运行创建、生成、故障注入、服务重启或配置修改。
2. Layer B 只允许只读命令；**禁止**调用 `miaomiao` 菜单、禁止创建/删除/轮换客户端、
   禁止触碰 `/var/lib/sbox-cm/management.active`、禁止启用 Monitor/E3。
3. Layer C 必须使用隔离测试 VPS（非生产），授权窗口内执行，提前做快照/备份，并保留
   第二条独立 SSH/控制台恢复通道。**创建验收不得在生产 VPS 首次执行。**
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
  SHA-256 与 receipt 一致**；
- 无控制台窗口：`python ha-ui\ci\check_no_console_popup.py --exe dist\ha-ui.exe`。
  该脚本先跑正向对照（`CREATE_NEW_CONSOLE` 的 cmd 必须被探测到），再跑目标 EXE；
  detector 可用时必须 `ok=true` 且 `console_events=0`；detector 不可用时输出
  `detector=unavailable`（退出码 2），此时以 `test_windows_console_isolation.py` 的
  creationflags 断言为准，并在证据里写明“detector 不可用”，不得写成已验证。

### 2.2 人工 GUI 验收清单（必须逐项记录）

> 本轮已在真实 EXE 上自动化执行下表 A1–A10 的可自动部分（UIA；合成数据、真实 Windows
> 凭据管理器、无 VPS 连接），结果见 PR 评论；A5 的“重启后读取”与 A10 的真实生成/Cancel
> 仍需人工或 Layer C。自动化不能替代人工视觉/交互确认。

用**构建出的 `dist\ha-ui.exe`**（非源码运行）在标准 Windows 桌面执行：

| # | 操作 | 通过条件 |
| --- | --- | --- |
| A1 | 启动 EXE，切换三个页 | 无崩溃；默认进入「客户端」页；页签为「服务器 / 客户端 / 生成 YAML」；无旧安全横幅/底部调试状态 |
| A2 | 服务器 A/B 填写名称/IP/端口/用户名；密码框输入 | 密码默认显示为圆点；“显示/隐藏”只切换可见性，不写日志/不弹明文 |
| A3 | 不勾“记住密码”保存配置 | `%LOCALAPPDATA%\HASingbox\servers.json` 成功写入且**不含密码**；状态提示“未连接” |
| A4 | 勾“记住密码”后保存；显示后端名 | 成功时明确提示保存到 Windows 凭据管理器；随后可在凭据管理器看到 `ha-ui-ssh` 条目 |
| A5 | 关闭并重启 EXE，读取已保存配置 | 非机密字段恢复；密码不回显；测试连接可从凭据管理器取密码（无真实 VPS 时只验证到“将尝试连接”） |
| A6 | 删除已保存密码 | 凭据管理器条目消失；密码框清空；再次测试提示缺少密码而非静默失败 |
| A7 | 错误场景：错误 IP/端口、未确认指纹 | 显示固定 `E_SSH_*`/`E_HOSTKEY_*` 码 + 安全消息；不自动重试、不泄漏异常文本 |
| A8 | 指纹核对对话框 | 显示算法 + `SHA256:...`；未勾“我已核对”无法确认；指纹变化时有明确警告 |
| A9 | 客户端页/生成页按钮（无可用连接时） | 给出明确未配置/缺指纹/缺密码错误；不崩溃、不伪造数据 |
| A10 | 生成取消/关闭窗口 | 取消按钮最终显示 `E_CANCELLED`；关闭窗口后无残留进程/无未处理异常 |
| A11 | 新建客户端对话框（不连接 VPS） | 名称非法/`legacy` 无法提交；未勾写入确认无法提交；文案明确说明修改两台 VPS + reload + 部分成功不自动删除 |
| A12 | 客户端表格正常/异常态（合成数据或隔离 VPS） | 6 列左右；正常时无“警告：无”/长 UTC/重复诊断；异常行有「查看原因」；证书正常显示简短状态 |
| A13 | 正常使用全程：双击启动、连接、刷新 A/B、新建客户端、生成 YAML、打开输出目录 | **不出现任何 CMD / 控制台黑窗口**；出错时仍有 GUI 错误提示与固定错误码，无被吞掉的诊断 |

记录：时间、EXE SHA-256、Windows 版本、逐项结果、截图（脱敏）。失败即停，不用
“重启试一次”掩盖。

### 2.3 创建结果的四种状态（PR #124 复审新增）

| 状态 | 触发条件（代码事实） | 界面必须显示 | 操作员动作 |
|---|---|---|---|
| `created` / `existing` | 提交行 + 成功行 + live 复核 `exportable` | 成功提示；“可生成” | 继续生成 YAML |
| `failed`（预写拒绝） | `lock`/`consistency`/`exists` 等，且核对 SHA 未变、名称仍不存在 | “创建失败 … 未修改任何客户端” | 按错误码修复后重试 |
| `failed`（`rolled-back`） | 精确句 `已回滚并重新加载上一份配置` **且** SHA 回到写入前 **且** 名称不存在 | “已回滚，配置已恢复（未提交）” | 修复原因后重试 |
| `uncertain` | 超时/断连/回滚失败/回滚未确认/复核不完整/无成功行 | “创建结果待确认：可能已写入服务器”或“远端创建事务尚未结束”，自动刷新；刷新失败显示 `STALE / UNKNOWN` 并禁止重建同名客户端 | 先刷新核实，再决定补齐/人工处理 |
| 待确认的解除条件 | 只读 `pending_transactions` 读到该名称无事务记录（`absent`），或**已证明安全终结**（created/rolled-back/refused）且 live 状态一致；`blocked` 一律保留 | 普通列表刷新**不能**解除；界面会显示“仍有未确认的远端创建事务” | 继续刷新/恢复连接，直到出现终局或确认无事务记录 |

验收时必须实际制造至少一次 `uncertain`（隔离环境断网/超时）并确认：文案没有出现
“未修改任何客户端”；自动刷新确实连接了两端；刷新失败后重建按钮会被拒绝；刷新手动
点“刷新客户端”也不会解除，直到出现终局/无事务记录。

### 2.4 Linux 事务 lab（CI 必跑，不替代真实 VPS 验收）

`ha-ui/ci/linux/tx_mechanism.sh` 与 `ha-ui/ci/linux/tx_lab.py` 由 `linux-tx-lab`
job（ubuntu-22.04）执行，覆盖：BASH_ENV 同进程 hook、加载失败 fail-closed、committed
事务、health 失败回滚、回滚未确认、`reload` 阶段 SIGKILL、并发写者、launcher 被杀、
stdout 消费者退出、pre-commit watchdog、只读状态查询。该 lab 是本机/CI 证据，**不能**
替代真实 A/B VPS 的创建验收。

### 2.4 无控制台窗口（CMD 黑框）验收

1. 双击 `dist\ha-ui.exe`，观察 10 秒：不应出现任何控制台窗口；
2. 依次执行 A1–A13 中的交互，全程无黑框；
3. 运行 `python ha-ui\ci\check_no_console_popup.py --exe dist\ha-ui.exe`；
4. 记录该脚本 JSON（`checked/positive_control/console_events/ok`）与 detector 可用性。

## 3. Layer B — 两台 VPS 只读验证（不执行菜单、不生成、不改配置）

> 仅在两台 VPS 的 owner 书面授权后执行。以下命令全部**只读**：不启动 installer、
> 不调用 `miaomiao` 菜单、不 apt/yum 更新、不重启/重载服务、不写任何文件。
> 先记录基线，结束时复核基线未变。**只允许输出脱敏元数据**：不输出客户端密码、
> UUID、私钥、证书 PEM、完整 YAML 或完整配置；不要把 IP/主机名写入 Issue/PR/聊天。

### 3.1 首次主机指纹信任（必须来自独立可信来源）

**不能**用 `ssh-keyscan` 或一次 SSH 连接本身来建立首次信任——那只是和“网络上自称是
该主机的一方”自证。首次信任必须与 **VPS 控制台的独立视图**（云厂商 Web 控制台/
串口/VNC/已签发的运维清单）核对：

1. 在**云厂商控制台**（或既有独立可信的运维通道，不走本次待验证的 SSH）登录目标
   VPS，执行只读命令，记录 GUI 实际显示算法对应的指纹：

   ```bash
   for f in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf "$f"; done
   ```

   若控制台不可用，则由 owner 提供已签字的 host-key 指纹清单作为独立来源；不得用
   `ssh-keyscan` 结果替代。
2. 与 GUI“获取并确认指纹”对话框显示的 `SHA256:...` **逐字符比对**（注意算法类型，
   通常为 ED25519）。
3. 只有比对一致后，才在 GUI 勾选“我已核对”保存指纹；不一致/无法取得独立来源时
   **停止 Layer B**，不得继续。

完成独立核对后，才可以用 `ssh-keyscan` 做传输层交叉检查（不是信任根）：

```powershell
ssh-keyscan -p <PORT> <HOST> | ssh-keygen -lf -
```

### 3.2 系统环境（只读；PowerShell → ssh stdin，避免引号/变量展开问题）

Windows PowerShell 默认双引号会展开 `$变量`，且引号会被本地 shell 消费；下面统一用
**单引号 here-string 经 stdin 交给远端 `bash -s`**，脚本内不做任何写操作：

```powershell
$ErrorActionPreference = 'Stop'
$HostName = '<VPS_HOST>'; $Port = 22
$script = @'
set -u
id -u
uname -a
. /etc/os-release
printf 'os=%s\n' "$PRETTY_NAME"
printf 'singbox_state=%s\n' "$(systemctl is-active sing-box 2>/dev/null || true)"
for f in /root/sbox/sbconfig_server.json /root/sbox/config /root/sbox/sing-box; do
  if [ -e "$f" ]; then
    stat -c 'file=%n mode=%a uid=%u size=%s' -- "$f"
  else
    printf 'missing=%s\n' "$f"
  fi
done
for c in miaomiao jq openssl curl timeout sha256sum date stat qrencode iptables setfacl getfacl runuser; do
  if command -v "$c" >/dev/null 2>&1; then printf 'dep_%s=present\n' "$c"; else printf 'dep_%s=missing\n' "$c"; fi
done
if [ -e /var/lib/sbox-cm/management.active ] || [ -L /var/lib/sbox-cm/management.active ]; then
  echo management=active
else
  echo management=inactive
fi
'@
$script | ssh -p $Port "root@$HostName" bash -s
```

通过条件：独立来源指纹与 GUI 一致；`id -u`=0；Linux；sing-box active；
`sbconfig_server.json`/`config` 存在；`miaomiao` 与依赖命令 present；
`management=inactive`（若 active 则**停止**，MVP 不在管理面激活状态生成）。

### 3.3 客户端名单（只读，仅名称 + 协议布尔值）

同样经 stdin 执行，**绝不 `jq .` 或 `cat` 配置**：

```powershell
$script = @'
set -u
jq -r '
  ([.inbounds[]?|select(.tag=="vless-in")]|length) as $rn |
  ([.inbounds[]?|select(.tag=="hy2-in")]|length) as $hn |
  "inbounds reality=\($rn) hy2=\($hn)",
  ([.inbounds[]?|select(.tag=="vless-in")|.users[]?|{n:(.name//""),r:((.uuid//"")|length>0)}]),
  ([.inbounds[]?|select(.tag=="hy2-in")|.users[]?|{n:(.name//""),h:((.password//"")|length>0)}])
' /root/sbox/sbconfig_server.json
'@
$script | ssh -p $Port "root@$HostName" bash -s
```

要求：A/B 各跑一次；只记录名称集合与 Reality/HY2 是否齐全（输出脱敏，不保存原始
凭据字段）。

### 3.4 已有规范导出文件（只读元数据 + 哈希）

```powershell
$script = @'
set -u
for f in /root/sbox/clients/*/mihomo.yaml; do
  [ -e "$f" ] || continue
  stat -c '%n|%a|%u|%s|%y' -- "$f"
  sha256sum -- "$f"
done
'@
$script | ssh -p $Port "root@$HostName" bash -s
```

通过条件：与 GUI 客户端页“导出文件已就绪/需生成”判断一致；属主 root、0600；只记录
文件名/哈希，不复制/输出内容；若缺失/过期，**Layer B 不生成**，留待 Layer C。

### 3.5 HY2 证书 PIN 与有效期（只读）

按 [`docs/mihomo-competition-ha-profile.md`](mihomo-competition-ha-profile.md)
“Obtaining the pin over the trusted SSH management channel”整段执行（只读证书文件，
不读私钥、不输出证书 PEM、不改配置），A/B 各一次，只记录
`fingerprint= / not_before= / not_after=`。

通过条件：A/B PIN 不同；证书当前有效；剩余有效期满足
[mihomo-competition-ha-profile.md] 的要求（MVP 工具侧还要求 ≥24h，低于 30 天会警告）；
与 GUI 读取值一致。

### 3.6 基线不变证明

Layer B 开始/结束各执行一次（只读）：

```powershell
$script = @'
set -u
date -u +%Y-%m-%dT%H:%M:%SZ
sha256sum /root/sbox/sbconfig_server.json /root/sbox/config
systemctl show sing-box -p NRestarts
'@
$script | ssh -p $Port "root@$HostName" bash -s
```

通过条件：两个哈希与 NRestarts 均未变化；无客户端/证书/服务变更。**任何变化都视为
Layer B 失败并停止**。

### 3.7 Layer B 明确边界

- **允许**：`id`/`uname`/`stat`/`jq` 只读字段投影/`sha256sum`/`systemctl is-active`/
  `systemctl show`/只读 openssl 证书解析。
- **禁止**：执行 `install.sh` 或 `miaomiao`、触发菜单生成/客户端增删、`apt/yum`、
  `systemctl start|stop|restart|reload|enable`、写 `/root/sbox/**`、修改/删除凭据、
  启动任何监听/隧道。
- **Layer B 通过 ≠ Layer C 通过**：Layer B 只证明两台 VPS 的身份、环境、名单、证书 PIN
  与已有导出元数据可读且基线未变；它**不证明**真实菜单生成、SFTP、SHA、A-first/B-first
  交付或 Clash Verge Rev 导入可用。后者必须在 Layer C 隔离测试 VPS 完成。


## 4. Layer C — 隔离测试 VPS 创建/生成验收（授权窗口，非生产）

前置：隔离测试 VPS A/B（或与生产同版本快照实例）、`main` 安装、测试机无生产业务；
准备快照/回滚、第二条独立恢复通道、书面授权。创建验收会真实写入两台 VPS 的
sing-box 客户端配置并可能 reload，必须单独批准。

| # | 操作 | 通过条件 |
| --- | --- | --- |
| C0 | 在一个全新名称上点「新建客户端」并确认 | 预检两端在线/名称不存在；A 后 B 顺序创建；两端各自生成不同 UUID/HY2 密码；创建后 live 读取两端名称与协议完整；UI 显示成功、自动刷新并入选；无凭据进入 UI/日志 |
| C0a | 注入“A 成功、B 失败”（隔离 VPS/受控网络） | UI 准确显示 A 已创建、B 失败；A 保留不自动删除；不显示“已全部完成”；可刷新看到实际状态 |
| C0b | 名称仅 A 端已存在，首次确认后拒绝补齐 | 不写 B、不改 A；显示 `E_CLIENT_PARTIAL_EXISTS` |
| C0c | 再次确认“仅补齐缺失端” | 只写 B；A 的 UUID/HY2 不变；完成后显示“A 原有、B 新建” |
| C0d | 对同一名称重复点击/并发创建 | 最终只存在一份；已存在端不被覆盖；无静默凭据轮换 |
| C0e | 模拟锁失败/一致性失败/reload 回滚 | 该端不出现成功回执；回滚后 live 清单与创建前一致；UI 显示固定 `E_*` |
| C1 | GUI 连接 A/B，读取客户端 | 列表与两端只读查询一致；单端/不完整客户端被禁止选择 |
| C2 | 选择 1 个客户端 + A-first，勾选菜单生成同意 | 生成完成；显示 `<client>-A-first.yaml` 与 SHA-256 |
| C3 | 同客户端生成 B-first | 4 节点顺序/角色正确；`自动选择` 组为 5s/5000ms（本轮默认；5s/2000ms 需手动选择）；`skip-cert-verify:false` + 正确 A/B pin；HA-03 `<name>-hac.yaml` 保留 60s/5000ms 对照 |
| C4 | 批量 2+ 客户端 | 每客户端独立 A-first/B-first 文件；manifest/文件名/角色一致 |
| C5 | 失败注入（仅在隔离 VPS，经批准）：临时改坏一个客户端/模拟菜单失败/中断网络 | 工具 fail-closed（`E_REMOTE_MENU`/`E_CLIENT_*`/`E_CHAIN_*` 等）；本地不产生交付；旧成功产物不变；无部分 YAML 被接受 |
| C6 | 取消/关闭窗口 | 取消可中断到阶段边界；无残留临时交付；失败运行目录可删除 |
| C7 | SFTP/哈希 | 下载字节与远端 `sha256sum` 一致；本地再校验；私钥/YAML 不进入日志 |
| C8 | Clash Verge Rev 手动导入 | **人工**导入 A-first 与 B-first，确认 4 节点、fallback、探测策略；不自动导入/不开 TUN/不改系统代理；导入后按 [windows-verification](mihomo-competition-ha-windows-verification.md) 验证 |
| C9 | 回滚 | 删除测试客户端/恢复快照；确认测试 VPS sing-box 与配置恢复；本地删除 run 目录与凭据；复核无残留 |

通过条件：C0–C9 全通过 + 自动化测试全绿 + Layer A/B 通过。任何一项失败不得进入生产。
创建相关行（C0–C0e）未完成时，**不得**声称 0.2.0 的 GUI 创建功能已通过真实环境验收。

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
steps: <A1..A12 / B1..B5 / C0..C9 逐项 pass/fail>
create receipt (C): per-side created/existing/failed/uncertain + fixed code; no credentials
server fact baseline (B): config_sha256_changed=no/yes, state_sha256_changed=no/yes, nrestarts=...
pin summary (B/C): A/B distinct=yes/no, earliest not_after=...
failures: <code + 安全描述>
rollback performed: yes/no
verdict: PASS/FAIL
```
