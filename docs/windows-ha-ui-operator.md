# Windows 双 VPS 主备配置生成器（HA-UI）— 操作说明

适用：Windows 10/11 x64 本机；两台已安装本仓库 sing-box + `miaomiao` 管理入口的
VPS（A/B）。本工具是**本地离线助手**：不建公网服务、不监听端口、不自动导入 Clash/
Verge、不开启 TUN、不修改系统代理、不修改服务器 `sbconfig_server.json`、不激活
Monitor/E3 管理面。

> 安全边界与数据来源见 `docs/windows-ha-ui-data-path.md` 与
> `docs/windows-ha-ui-security.md`。首次正式使用前，请确认已在两台 VPS 上人工轮换
> 所有曾暴露的 Reality UUID / HY2 密码并重新生成 HA-02→04 链；本工具不会、也不能
> 代替这步轮换。

## 1. 前置条件

- 两台 VPS 均可用 **root** SSH 登录（MVP 仅支持 root；非 root 会明确报错，不尝试 sudo）。
- 服务器已安装本仓库当前 `main` 的 sing-box + `miaomiao`；`/root/sbox/sbconfig_server.json`
  与 `/root/sbox/config` 存在，`jq`、`openssl`、`sha256sum`、`date` 可用。
- `/var/lib/sbox-cm/management.active` **不存在**（E3/Monitor 管理面未激活）。若存在，
  本工具拒绝生成，因为跨管理事务边界读取不安全；管理面激活是独立审批操作。
- 同一个客户端名必须已在 A、B 两端都存在，且 Reality 与 HY2 都完整；仅单端存在或
  协议不完整的客户端会被禁止生成（不会伪造双活 YAML）。
- 本机输出目录会创建在 `%LOCALAPPDATA%\HASingbox`（受 NTFS ACL 保护，含凭据材料）。
  请勿把该目录同步到网盘/OneDrive，也不要提交到 Git。

## 2. 首次配置 A/B

1. 启动 `ha-ui.exe`，在“服务器”页分别填写 A、B 的：名称/别名、IP 或主机名、SSH 端口、
   用户名（root）、SSH 密码（默认隐藏，可点“显示”核对）。
2. 点“获取并确认指纹”：工具只读取 SSH 主机公钥（不发送密码），显示算法与
   `SHA256:...` 指纹。请与服务器 `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`
   或云厂商控制台显示的指纹**人工核对**，勾选“我已核对”再保存。指纹不符或变更时
   连接会在发送密码前被拒绝。
3. “记住密码”仅在勾选时保存到 **Windows 凭据管理器**；保存后会读回校验，失败会明确
   报错（不会退回明文文件）。不勾选则密码只在本次操作的内存中使用。
4. 点“测试连接”验证：root、Linux、配置文件、`miaomiao` 是否存在（只读，不修改服务器）。

## 3. 读取客户端

1. 在“客户端管理”页点“读取两端客户端”。工具通过已确认的 root SSH 通道只读列出
   A/B 两个 `sbconfig_server.json` 中的客户端名、Reality/HY2 是否存在及凭据是否非空
   （仅布尔），并检查 `/root/sbox/clients/<name>/mihomo.yaml` 是否是新鲜的 root:0600
   私有派生文件。
2. 表格显示：客户端、A/B 是否存在、Reality/HY2、导出文件、问题。仅单端存在、缺少协议、
   凭据为空、重名/无名单/入站数量异常等会直接标红禁止生成。
3. 勾选一个或多个客户端；选择 A-first 或 B-first（默认 A-first）。可按“全选可生成”
   只选中两端完整且一致的客户端。
4. 同时显示两端 HY2 证书有效期；过期、剩余不足 24 小时、A/B 证书 PIN 相同都会阻止生成。

## 4. 生成 A-first / B-first YAML

1. 策略默认 **5s / 2000ms**（HA-04 fast-probe 的 `自动选择` 组）；另可选 3s/1000ms、
   10s/5000ms 做对照。HA-03 的 60s/5000ms 版本不被覆盖，保留在本次运行目录的
   `ha03/<name>-hac.yaml` 作为对照。
2. 若所选客户端的派生导出缺失或过期，需要勾选同意：工具将执行现有 `miaomiao`
   管理脚本（10 → 3）。该脚本每次运行会从本仓库 `main` 更新自身，并做幂等的
   host 依赖/权限基线修复与 `install_shortcut`；菜单 3 只读配置并写派生文件，不修改
   sing-box 配置、不重启服务。若导出已新鲜，则不会执行脚本。
3. 点“生成”。工具在本地私有运行目录内执行：
   规范化导出 → HA-02 生成 → HA-03 生成 + `--check` → HA-04 生成 + `--check` →
   friendly-export 发布。每个阶段的失败都会以固定 `E_...` 码显示；不会覆盖上一次
   成功产物，失败运行的临时目录会被清理。
4. 成功后显示每个客户端的文件名、SHA-256 与运行目录；“打开输出目录”只打开资源管理器，
   不会导入任何客户端。
5. 输出文件名固定为 `<client>-A-first.yaml` / `<client>-B-first.yaml`。原始 HA-02/03/04
   manifest 与文件保留在同一私有运行目录，供审计与回滚。

## 5. 失败、重试与回滚

- **安全重试**：点“重试”会用新的 run id 重新生成；旧的失败目录已清理，不会与新输出冲突。
- **保留旧产物**：历史成功目录不会被覆盖；friendly-export 采用 no-clobber，同名目标
  存在时失败而不是替换。
- **删除失败目录**：如某次失败保留了诊断目录（例如进程被强制结束），可在界面删除该
  失败运行目录；删除范围被限制在私有工作区内。
- **回滚**：本工具不修改服务器。若需回退到手工链，直接使用本次运行目录中的
  HA-02/03/04 原始文件，或按 `docs/mihomo-competition-ha-windows-verification.md`
  手工验证；不要手工改写合并输出。删除本工具影响，只需删除 `%LOCALAPPDATA%\HASingbox`
  与 Windows 凭据管理器中的 `ha-ui-ssh` 条目。

## 6. 常见错误码

| 码 | 含义 | 处理 |
| --- | --- | --- |
| `E_HOSTKEY_MISSING` | 未确认主机指纹 | 先“获取并确认指纹” |
| `E_HOSTKEY_MISMATCH` | 指纹变化 | 停止；通过独立渠道核对服务器是否重装/被劫持 |
| `E_SSH_AUTH` | 用户名或密码错误 | 检查凭据；必要时删除并重新保存 |
| `E_SSH_CONNECT` / `E_SSH_TIMEOUT` | 网络/端口问题 | 检查 IP、端口、防火墙；可重试 |
| `E_REMOTE_NOT_ROOT` | 非 root | 用 root 或按人工流程操作 |
| `E_REMOTE_PREFLIGHT` | 前置检查失败（detail 指明项） | 按 detail 修复；`management-active`/`api-migration` 需人工处理 |
| `E_REMOTE_PIN` / `E_PIN_EXPIRED` / `E_PIN_REUSED` | HY2 证书 PIN/有效期问题 | 续签/换证书后重新读取；A/B 不可同 PIN |
| `E_CLIENT_MISSING` / `E_CLIENT_INCOMPLETE` | 单端缺失或协议不完整 | 先在两端用 `miaomiao` 客户端管理补齐 |
| `E_CHAIN_STAGE` / `E_CHAIN_CHECK` | HA-02/03/04 阶段或 `--check` 失败 | 查看 detail 中的阶段与工具码；修复输入后重试 |
| `E_FRIENDLY_EXPORT` | 交付发布失败（文件名/哈希/角色不符） | 检查 manifest 与目标目录；重试为新 run |
| `E_ACL` | 本地私有目录 ACL 校验失败 | 停止；不要把该目录移到共享/同步目录 |

## 7. 不要做的事

- 不要把 `%LOCALAPPDATA%\HASingbox`、任何 YAML、manifest、截图或日志发到聊天/Issue/PR/CI。
- 不要让多个进程同时操作同一输出目录；每次生成使用独立 run 目录。
- 不要用本工具创建/删除/轮换客户端（MVP 不包含）；此类操作仍走已审查的服务端事务引擎。
- 不要在 Monitor/E3 管理面激活期间使用本工具生成。
