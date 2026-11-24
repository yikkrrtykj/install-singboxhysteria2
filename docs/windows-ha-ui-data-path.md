# Windows HA-UI — 数据获取/创建路径与边界（0.2.0）

适用代码基线：`main@9402be91284551210f2d455f1af42e3b97ccb81e`（0.2.0 Draft PR）。
本文只陈述仓库与运行手册中已有的事实，不包含任何凭据、IP、YAML 或服务器私钥。

## 1. 结论摘要

Windows 前端**不使用** sbox-cm/Monitor 的 `client.list` / `client.export` 特权通道，
而是通过**已确认主机指纹的 root SSH 管理通道**执行仓库既有 `miaomiao` 客户端菜单：

- 读取/生成规范导出：菜单 10 → 3，读取
  `/root/sbox/clients/<name>/mihomo.yaml`；
- 新建同名客户端：菜单 10 → 2，复用既有
  `add_client` → `with_client_lock` → `cm_add_client_candidate_planned` →
  `commit_server_config` 事务链。

两条路径都不绕过 Monitor 会话/step-up/激活边界，也不直接编辑
`sbconfig_server.json`。创建是**远程写操作**，必须由 UI 明确确认；生成 YAML 仍是
本地操作。理由与边界见下。

## 2. `client.list` / `client.export` 的真实调用条件

| 事实 | 证据 |
| --- | --- |
| `client.list`/`client.export` 是 sbox-cm root daemon 的 AF_UNIX RPC；socket 为 `root:sboxweb 0660`，用 `SO_PEERCRED` 认证，**只接受 `sboxweb` uid，root 也被拒绝** | `sbox-cm/sbox-cm` OPS/peer 检查、`sbox-cm/README.md §1/§4` |
| `client.list` 只返回 name/protocols/reserved/mutable/source，零凭据；短持 `config.lock`，degraded 时仍可用 | `sbox-cm/README.md §4`、`sbox-cm-ops` list op |
| `client.export` 是唯一返回凭据材料的只读 op；除 socket peer 外，还要求 **Monitor Web 会话 + CSRF + step-up**（POST-only），且 Broker 要求**新鲜的** `management.status` 满足 `management_active=true`、`helper.degraded=false`、`reconcile=clean`、`lock.acquirable=true` | `monitor-v2/web/server.py` export route、`monitor-v2/web/e3_broker.py::require_export_ready`、`docs/e3-m4-client-export-design.md §7` |
| worker 内部还会在锁内复查管理面 active、非 degraded、配置一致、客户端存在、规范渲染 ≤48 KiB、审计失败则不出 YAML | `sbox-cm/sbox-cm-ops` export op、`sbox-cm/README.md §4/§5` |
| 生产 E3 管理面**未启用**：Phase 1 部署（management disabled）、Phase 2 canary 已结束、Phase 3 未执行（需单独审批） | `docs/e3-m3c-phase3-production-runbook.md` 状态、`sbox-cm/README.md` 状态块 |
| 因此 root SSH 直接/间接调用 `client.export` 会绕过 Monitor 会话/step-up 认证边界；即使绕过 socket peer 检查（冒充 sboxweb 或直调 worker）也不符合现有威胁模型，且当前管理面未激活会返回 `E_ACTIVATION_STATE` | 同上；Issue #110「不得绕过现有权限或事务边界」 |

**结论：**当前不能“仅通过 SSH”安全调用 `client.export`；它需要独立的 Monitor 认证 +
管理面激活（单独审批）。本 MVP 不实现、不激活、不模拟该边界。

## 3. 仍然存在且被仓库文档认可的 SSH 路径

1. **渲染器唯一性**：`lib/client-management.sh::cm_render_client_mihomo_yaml` 是仓库唯一
   Mihomo/Clash Meta YAML 渲染器；`install.sh::generate_client_configuration` 与
   sbox-cm `client.export` 都调用它。前者写 `/root/sbox/clients/<name>/mihomo.yaml`
   （目录 0700、文件 0600）；后者在锁内渲染同一字节。静态回归
   `tests/e3/test-m4-renderer.sh` 证明 install.sh 没有第二套模板。
2. **既有操作员通道**：`miaomiao` → 菜单 10 → 3 生成导出；`ha00-operator-checklist.md`
   的第 63-71 行明确用 `scp root@VPS:/root/sbox/clients/<name>/mihomo.yaml` 取回，
   并说明 Monitor「客户端管理」下载是等价来源。
3. **可信 SSH 通道已用于证书 PIN**：`docs/mihomo-competition-ha-profile.md`
   §「Obtaining the pin over the trusted SSH management channel」给出在 root SSH 上读取
   live 配置引用证书、用 openssl 取 DER SHA-256 与有效期的只读脚本；同一模型被本前端复用。
4. **导出驱动**：`ha00-operator-checklist.md` 的手工链就是 A/B 两端分别生成/取回
   `<name>-mihomo.yaml`，再在本地运行 HA-02→04；GUI 只是把这一步自动化。
5. **创建驱动（0.2.0）**：`install.sh` 菜单 10 → 2 → `add_client` 是仓库已审查的
   单 VPS canonical add：随机生成独立 Reality UUID/HY2 密码、校验名称/保留名/
   一致性、`with_client_lock` 串行化、`sing-box check`、备份、原子替换、
   reload/health 与失败回滚。GUI 只调用这个入口，不复制其凭据生成/JSON 拼接/
   提交逻辑。

因此，GUI 使用 root SSH + 既有 CLI 生成/读取规范导出、创建客户端，属于**已记录的
运维路径**，不是对 Monitor/E3 权限模型的绕过。GUI 不调用 sbox-cm socket、不
activate/deactivate、不触碰 `management.active` 标记；生成路径不修改
`sbconfig_server.json`，创建路径只经 canonical add 事务写入。

## 4. 本版本的实现规则（安全边界）

- 仅 root SSH；非 root 直接报 `E_REMOTE_NOT_ROOT`，不尝试 sudo。
- 连接前必须核对并保存 SHA-256 主机指纹；未知/变化指纹在**发送密码前**拒绝。
- 只执行**固定、无用户字符串插值**的只读命令与既有 CLI 菜单；客户端名先经
  `^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$` 校验，`legacy` 在本地与服务端都被拒绝。
- 列表读取：root 只读 `jq` 取 name + 两协议凭据是否存在（仅布尔），以及派生文件
  的 root/0600/mtime 元数据；不读取凭据值。
- 导出读取：SFTP 下载 `/root/sbox/clients/<name>/mihomo.yaml`，下载前后校验
  普通文件、root 属主、0600、大小上限、lstat/fstat 一致性，并与远端 `sha256sum`
  对比；字节只落本地私有目录，随后由本地 HA 链校验。
- 创建客户端（0.2.0）：仅在 UI 明确确认后执行 pinned menu 10→2；不直接编辑
  `sbconfig_server.json`，不复制凭据生成/提交逻辑；每端独立回执，两端不是原子事务。
  创建后重新读取 live 清单，名称与 Reality/HY2 完整性都出现才报告成功；部分成功
  保留已创建端，不自动删除。
- 生成触发需 UI 明确勾选同意。生成路径从 **reviewed commit**（绝不 `main`）只读下载
  `install.sh` + `lib/client-management.sh`，先校验两者独立嵌入的 SHA-256 与 installer
  内嵌 lib pin，再校验菜单结构，最后在清洗环境中执行**已校验的同一份字节**并使用预置
  lib；用 `timeout` 限制运行、`PIPESTATUS` 捕获真实退出码、逐客户端成功文本 +
  生成前后 stat/SHA-256 变化共同证明“确实重新生成”，部分生成/失败/超时/哈希不匹配
  一律在下载前中止。host 依赖命令由前置检查要求全部存在，因此不会触发 apt/yum 安装
  未锁定代码。现有安装脚本在菜单前仍会做幂等的权限基线修复与 `install_shortcut`；
  菜单 3 只读配置并写派生文件，不改 sing-box 配置；导出已新鲜时完全不执行脚本。
- 若检测到 `/var/lib/sbox-cm/management.active`，**拒绝创建与生成**：此时存在并发的
  Web/E3 管理事务，跨事务边界操作不安全；本工具不处理该状态。
- 若配置缺少 monitor-api secret（`maybe_migrate_existing_api_auth` 会交互提示），
  前置检查直接拒绝，避免管道菜单输入错位。
- 生成的最终文件只在新的 run 目录内以 no-clobber 方式发布；失败不会覆盖任何旧成功
  产物，失败 run 目录会被清理（不含旧产物）。
- 不自动导入 Clash、不开启 TUN、不修改系统代理；不自动做故障注入；不声称已完成
  已泄露凭据的轮换。

## 5. 后续（需单独审批，不在本版本）

- 若未来批准 Monitor/E3 生产管理面：可在 SSH 隧道内用 Monitor 会话 + CSRF + step-up
  调用 `POST /api/v1/clients/export`，从而使用 privileged `client.export` 的锁内渲染；
  但这需要独立的安全审批与 Monitor 凭据存储设计，不能由本 UI 自动激活。
- 批量创建、删除、轮换客户端、跨两端补偿事务：仍留在后续阶段，复用已审查的
  事务引擎；0.2.0 只做“创建 + 单端补齐”，不做自动删除/补偿。

## 6. 预验收加固：远程 CLI 导出的退出状态与来源证明（2026-11-21）

此前实现只依赖 `HAUI_MENU_END` 结束标记，且从 GitHub `main` 下载后执行——菜单字符串
校验不能证明脚本字节可信。现实现（`ha-ui/ha_ui/core/remote.py`）改为**已审查 commit +
SHA-256 双重锚定**，并按以下顺序 fail-closed：

**6.1 不可变信任锚点**（升级必须重新安全审查并同时更新常量/文档/测试）：

| 项 | 值 |
| --- | --- |
| reviewed commit | `9402be91284551210f2d455f1af42e3b97ccb81e` |
| `install.sh` SHA-256 | `1a9923eb31ee29b899ba87651c102e83dbde0d397db91387245a489f2e647f10` |
| `lib/client-management.sh` SHA-256 | `52e08db43b8c94dc42a3c8eea96e8bc3c6adb64155002e82ac3dee985e3b6a53` |

URL 固定为 `raw.githubusercontent.com/.../<reviewed-commit>/...`，**绝不使用 `main`**。
`tests/test_installer_trust.py` 把这两个哈希绑定到仓库文件，并校验 installer 内嵌的
`SB_CLIENT_MANAGEMENT_SHA256` 与独立下载的 lib 哈希一致。

**6.2 执行前校验与内部依赖链**

1. 只读下载 `install.sh`（pinned commit）→ 计算完整字节 SHA-256 → 与
   `INSTALLER_SHA256` 不等立即 `E_INSTALLER_UNTRUSTED installer-hash`，**不执行**。
2. 校验 `install.sh` 内嵌 lib pin 等于 `CLIENT_MANAGEMENT_SHA256`，否则
   `E_INSTALLER_UNTRUSTED lib-pin`。
3. 校验菜单结构标记（顶层 `10. 客户端管理`、`client_management_menu`、`3)
   generate_client_configuration_interactive`、成功文案，以及创建路径的
   `2) add_client_interactive`、`add_client()`、`_add_client_locked()`、
   `已同时添加到 Reality 与 HY2`），不匹配
   `E_REMOTE_MENU precheck-menu-drift`（保留 #116 行为）。
4. 只读下载 `lib/client-management.sh`（同一 pinned commit）→ SHA-256 必须等于
   `CLIENT_MANAGEMENT_SHA256`，否则 `E_INSTALLER_UNTRUSTED lib-hash`。
5. 以**清洗环境**执行已校验字节：`env -i PATH=... HOME=/root LANG=C.UTF-8 TERM=dumb
   SB_CLIENT_MANAGEMENT_REF=<commit> SB_CLIENT_MANAGEMENT_LIB="$d/client-management.sh"
   bash "$d/install.sh"`。installer 的库加载器因此直接使用已校验的本地 lib，**不再从
   网络加载第二份代码**；`SB_CLIENT_MANAGEMENT_REF` 也固定到 reviewed commit，避免
   `main` 漂移。
6. **内部远端代码审计**：在 menu 10→3 路径上，installer 其余网络调用只有
   `show_status` 的 GitHub API 只读查询（数据，不执行）与 `install_shortcut` 写入
   wrapper 文件（不执行）；sing-box 下载/更新、lib 网络拉取均不在该路径（lib 已由
   `SB_CLIENT_MANAGEMENT_LIB` 预置）。installer 的 `install_pkgs` 原本会在缺依赖时
   `apt update/install`（未锁定仓库代码）；前置检查现在要求
   `qrencode/jq/iptables/setfacl/getfacl/runuser` 与校验命令全部 present，缺任何一个
   直接 `E_REMOTE_PREFLIGHT host-deps:...`，因此**不会触发 apt 安装**。故整条自动生成
   执行链为：pinned installer + pinned lib + 已存在系统命令，没有未锁定的可执行远程
   代码。
7. **失败语义与回退**：任一哈希/pin 失败 → `E_INSTALLER_UNTRUSTED`（明确提示
   “自动菜单生成已禁用；已有规范导出仍可读取”），不执行、不下载交付；已有新鲜
   `mihomo.yaml` 的读取模式继续可用（不会因 pin 失败而被禁用）。网络 fetch 失败为
   `E_REMOTE_MENU precheck-fetch`，可重试；哈希不匹配不可重试，必须发新版本。

**6.3 保留的 #116 校验**

1. **真实退出状态**：`printf | timeout env -i bash | sed` 的 `PIPESTATUS` 写入响应；
   menu 124 = 超时，任一非零 = 失败。
2. **转录证明**：客户端菜单标题、`NAME/REALITY/HY2` 表头、每个目标
   `客户端 '<name>' 的 Mihomo 配置已生成`；缺失按 partial/consistency/incomplete/
   permission 固定 token 中止。
3. **来源证明**：生成前后 `%F|%n|%a|%u|%s|%Y|%y` + `sha256sum`；目标必须 root/0600/
   普通文件/大小上限，且 mtime-ns 或 SHA-256 变化；旧的“看起来新鲜”文件不会被误认。
4. **失败清理/部分生成/超时**：一律在下载前中止；服务器侧派生文件可由菜单重生成，
   不是 live 配置；`timeout` 终止进程组。

**剩余副作用（已审计，非未锁定代码执行）**：仅当导出缺失/过期且用户勾选同意时才执行
installer；会出现 `repair_existing_install_security_baseline` 的幂等权限修复、
`install_shortcut` 重写 `/root/sbox/miaomiao.sh` + 符号链接（该 wrapper 的“main 自动
更新”行为是既有正式管理功能，本工具不改变它）、`maybe_migrate_existing_api_auth`
（需迁移时前置检查已拒绝/或零改写跳过）、`show_status` 只读查询。**不修改**
`sbconfig_server.json`、不重启/重载 sing-box、不激活 Monitor/E3、不 apt 安装。

**更安全的导出方案（建议，需服务器端单独 PR/审批，本轮未实施）**：在 `install.sh`
最前面增加只读非交互模式，例如
`install.sh --client-export <validated-name>`：加载 digest-pinned
`lib/client-management.sh`，在 `with_client_lock` 内执行结构/一致性检查后仅用
`cm_render_client_mihomo_yaml` 输出 YAML 到 stdout，不进入安装/修复/菜单路径，不做
任何写操作；退出码固定、无 TTY 依赖。GUI 可先只读探测该能力标记再调用，从而去掉
`install_pkgs`/`install_shortcut` 等副作用。Monitor/E3 生产激活后则优先使用
privileged `client.export`（锁内渲染 + 审计），而不是 shell 菜单。两条路线都必须
单独 review/审批，本轮不修改服务器端代码。


## 7. 创建路径：受管一次性事务 + 持久 journal（0.2.0，PR #124 P0）

创建仍然只走 reviewed 的 `install.sh` 菜单 10→2（`add_client` → `with_client_lock` →
`cm_add_client_candidate_planned` → `commit_server_config`），但执行方式改为
**受管一次性服务端事务**，不再被 GUI 的 420s `timeout -k`、SSH 断开或 stdout 管道
SIGPIPE 直接打断。

### 7.1 生命周期

1. launcher（一次 SSH 命令）先完成 pin/host 预检：拉取并校验 pinned `install.sh` /
   `client-management.sh` 的 SHA-256 与菜单结构标记。此阶段不触碰线上配置。
2. 生成 root-only 事务目录 `/root/sbox/.ha-ui-tx/<name>-<uuid>/`（0700，文件 0600），
   写入菜单输入 `in`、`env.sh`（见 7.2）、`pid`、`started`。
3. 校验 `env.sh` 的 SHA-256 == 客户端计算值；执行同进程探针（见 7.2）；任一失败
   `HAUI_MENU_FAIL=hook-unproven|env-hash`，**写前 fail-closed**。
4. `setsid` 启动 detached worker：菜单的 stdin/stdout 都是普通文件，worker 与 SSH
   通道无管道依赖。launcher 随后 `wait` 它——这只是客户端的等待预算，不是 kill 开关。
5. worker 内 watchdog 只在 journal 尚未出现 `replace` 时允许 TERM 菜单（默认 120s）；
   `replace` 之后不再有任何 hard kill。
6. worker 结束时以 `tmp + mv + fsync` 原子发布 `result`（`rc`/`finished`），删除 `raw`。

### 7.2 BASH_ENV 合同（保持函数名合同，不改 lib）

- 每次尝试生成的 `env.sh` 只做三件事：定义 `ha_ui_tx_journal()`（append + 文件 fsync +
  目录 fsync，失败返回非 0）、设置**非导出**变量 `CM_TX_JOURNAL_HOOK=ha_ui_tx_journal`、
  写加载哨兵 `hook-loaded` 后 `unset BASH_ENV`。
- worker 以 `env -i PATH=... HOME=/root LANG=C.UTF-8 TERM=dumb BASH_ENV="$tx/env.sh"
  SB_CLIENT_MANAGEMENT_LIB=... bash "$d/install.sh"` 启动菜单。非交互 bash 在运行
  installer 前 source `BASH_ENV`，因此 hook 函数定义在**真正执行事务的同一个 shell**。
- fail-closed 证据链（任一失败即写前中止）：`sha256(env.sh)` 匹配 → 哨兵存在 →
  `declare -F ha_ui_tx_journal` 命中 → `env | grep -c '^CM_TX_JOURNAL_HOOK='` 为 0
  （未导出）→ 子 shell 看不到该函数。
- 已实测陷阱：**BASH_ENV 不存在时 bash 退出 0 且不报错**，所以退出码不能作为加载
  成功的证明；必须依赖哨兵 + `declare -F`。
- 不修改 `install.sh` / `lib/client-management.sh`，因此安装器/lib 的既有哈希不变。

### 7.3 持久状态与权限

| 文件 | 权限 | 内容 / 写入协议 |
|---|---|---|
| `env.sh` | 0600 | hook 函数 + 非导出变量；生成后按客户端 SHA-256 校验 |
| `phases` | 0600 | `phase<TAB>epoch<TAB>backup` 追加；每次 append 后文件 fsync + 目录 fsync；解析器拒绝非法 phase |
| `in` | 0600 | 菜单输入（一次性） |
| `pid`/`started` | 0600 | worker pid / 开始时间 |
| `raw`→`out` | 0600 | 转录：去 ANSI、脱敏凭据链接；raw 删除 |
| `result` | 0600 | `rc=` + `finished=`；tmp+mv+fsync |
| `hook-loaded` | 0600 | BASH_ENV 加载哨兵 |

- 唯一性：canonical 名称 + uuid4；同名且未终局的目录存在时拒绝新请求（`tx-exists`）。
- 清理：有 `result` 且目录 mtime > 7 天删除；无 `result` 且 > 30 天删除；pid 存活的
  目录永不删除。
- 目录/文件均由 `umask 077` + 显式 chmod 创建；解析器拒绝非 `[a-z_]` phase。

### 7.4 终局判定（只读证据，不猜测）

```
phases: check → backup → replace → reload → health
        replace 前失败 = 零变更；replace 后失败 = rollback / rollback_manual
terminal: result 存在 = worker 已结束；否则 running(pid) 或 tx-unfinished
```

- `created`：terminal + rc=0 + 提交行 + canonical 成功行 + live 记录 `exportable`。
- `failed(rolled-back)`：精确句「已回滚并重新加载上一份配置」+ live 字节回到写入前 +
  名称不存在。
- `rollback-failed` / `rollback-unconfirmed` / `rollback_manual`：`UNCERTAIN`。
- 运行中 / 无终局 / 有写入证据但无终局：`UNCERTAIN`，且**不解锁重试**。
- 普通列表刷新不能清除 UNCERTAIN；只有 `pending_transaction(name)` 读到 `absent` 或
  `terminal`（再配合 live 校验）才允许解除（见 `clients_panel` 的 pending gate）。

### 7.5 Linux 进程级证据（CI，ubuntu-22.04）

`ha-ui/ci/linux/` 下两个脚本构成 `linux-tx-lab` job：

- `tx_mechanism.sh`（Stage A）：真实 bash 上验证 BASH_ENV 注入、非导出、加载后清理、
  哨兵、缺失 env 的静默行为、篡改检测、真实 `cm_tx_journal_phase` 调用、hook 失败
  fail-closed。
- `tx_lab.py`（Stage B）：用真实 `lib/client-management.sh` 的 `commit_server_config`
  + stub `systemctl`/`sing-box` 验证 committed、health 失败回滚、回滚未确认、
  `reload` 阶段 SIGKILL（新字节 + journal 停在 reload + 锁释放）、并发写者被
  canonical 锁拒绝；用 production worker 文本验证 launcher 被杀、stdout 消费者退出、
  pre-commit watchdog 与只读状态查询。

## 8. P0 残余风险（不承诺“绝不被杀”）

- **已覆盖**：GUI 超时只停止等待；SSH 断开不再通过管道 SIGPIPE/SIGHUP 终止事务；
  stdout 消费者退出不影响事务；`replace` 后不再有 hard kill。
- **不覆盖**：机器断电、内核崩溃、运维人员手工 `kill -9` 整个进程组。这些情况
  没有终局记录，只能被检出为 `UNCERTAIN` 并阻断重试，不能自动恢复。
- `with_client_lock` 的锁 fd 会被子命令继承；父进程被强杀后，锁会由有界子命令
  （`cm_bounded` 的 `timeout`）持有到它退出——CI lab 用进程组 kill 模拟硬故障，
  并验证锁最终释放。
- 结论：P0 的交付目标是“正常 GUI 超时/SSH 断开不会中断关键提交；异常终止可识别、
  不可误报成功”，不包含“物理故障绝不丢事务”。最终 PASS 仍需方案 AI 独立复审。


### 7.6 第四轮复审修复（HEAD 05d02767）

- **只读查询的 glob**：`pending_transactions` 用固定 `TX_ROOT` + 已校验 canonical
  名称 + 未加引号的 `*` 组成检索（`root='...'; name=...; for d in "$root"/"$name"-*/`），
  不再把整段路径放进单引号。Linux lab 用**真实创建的目录**执行 production
  `_pending_tx_command`，断言 running/terminal/damaged/absent 四种结果。
- **terminal ≠ 可解除**：新增 `TxStatus.outcome/release_safe`。只有
  `created`（rc=0 + COMMIT + SUCCESS + 无 live worker）、`rolled-back`（证明恢复）或
  `refused`（预写拒绝）才可解除；`damaged`（resume 缺失/部分写/未 fsync）、
  `worker-alive`（result 已写但 worker 未退出）、`rollback-manual`、
  `unfinished`/`running`、以及 claim 无对应记录一律 `blocked`。service 还要求 live
  记录与该结局一致（created 需 `exportable`，rolled-back/refused 需名称不存在）。
- **watchdog 竞态**：worker **不再向菜单发送任何信号**（检查与 kill 无法与 canonical
  `replace` 边界原子化）。超预算只写 `precommit-stall` 记录，由 canonical 子命令
  超时保证有界；写入后不可能被 watchdog 误杀。lab 分别覆盖 replace 之后与之前两个
  窗口。
- **跨请求同名阻断**：launcher 在创建前扫描**所有**同名目录，任何未完成的
  `result` 缺失 → `tx-in-flight`；并用原子 `mkdir` 的 per-name claim 目录防止两个
  GUI/重启后的实例并发启动。claim 记录 txid；只有引用的 worker 已死且 claim 超过
  1 天才允许接管。**未完成记录永不自动删除**，只有已有 `result` 且超过 7 天的记录
  才清理。
- **fsync fail-closed**：journal hook 对文件与目录分别检查 `sync -f`，失败回退
  `sync` 且失败返回非 0（事务在 replace 前中止）；result 发布的每一步
  （tmp 写入 → mv → 文件/目录 fsync）都有检查，失败写 `publish-failed`，
  解析器将其标记为 `damaged`，绝不当作可信终局。


### 7.7 第五轮复审：服务端执行与 GUI 相同的安全准则（HEAD `0a9fe37f`）

第五轮指出的根因是"GUI 会阻断 ≠ 服务器真的阻断"。现已把同一套判定移到服务端，
guard 与保留策略共用 `ha_ui_tx_safe_terminal()`：

- **safe terminal 的定义**（与 `TxStatus.release_safe` 等价）：`result` 存在且含
  `rc=`/`finished=` 数字字段、无 `publish-failed` 标记、worker pid 已死、且结局是
  ①rc=0 + 提交行 + 成功行（created）；②rc≠0 + 精确回滚句 + 无失败/未确认 +
  `rollback` phase（rolled-back）；③rc≠0 + 无提交 + 无回滚意图 + 拒绝句（refused）。
- **同名 guard**：对**每一个**同名记录执行上述判定；任何 rollback-failed /
  rollback_manual / unconfirmed / damaged / truncated / worker-alive / 未知记录都会
  `tx-in-flight`，且判定在原子 `mkdir` claim 之前完成，claim 本身也是排他资源，
  不存在"检查后被抢跑"的窗口。
- **保留策略**：只有同时满足 safe terminal 且目录 mtime > 7 天的记录才会删除；
  不安全/未完成/待人工恢复的证据**永不自动过期**。用时间让记录消失从而解除阻断是
  被明确禁止的。
- **结果发布失败**：`result.tmp` 写入、`mv`、两级 fsync 任一步失败都会写
  `publish-failed` 并**保留 per-name claim**；即使 marker 本身写失败，claim 仍在，
  下一次请求仍被阻断。claim 与受损记录只能由操作员人工核实/移除。
- **Linux 证据**：`guard-safe-terminal`（8 种记录 × 是否放行）、
  `cleanup-retention`（旧 safe 删除 / 旧 unsafe 与未完成保留）、
  `publish-failure-keeps-claim`（注入失败 sync → claim 保留 + guard 阻断），
  均使用生产 `_tx_guard_script` / `_tx_cleanup_script` / worker 文本。


### 7.8 第六轮复审：claim 生命周期不再自动接管

第六轮指出 `mtime + 1 天 + pid 已死 → rm -rf claim` 会重新打开两个缺口：两个
launcher 同时遇到过期 claim 时的 TOCTOU；以及"发布失败但 marker 也写不进去"时，
唯一可靠的阻断证据（claim）会在一天后被自动删除。

现行规则：

- **claim 只增不接管**：`mkdir` 失败即 `tx-in-flight`，guard 中不存在任何基于
  mtime/pid 的 `rm -rf claim` 路径；异常残留的 claim 只能由操作员核对 live 状态、
  备份目录后人工清理。
- **释放必须证明所有权**：launcher 的失败路径与 worker 的成功路径都先比较
  `claim/txid` 与本次 txid，只有相等才删除；不相等/缺失则保持原样（fail-closed）。
- **保留策略遇 claim 即停**：只要同名 claim 存在，cleanup 不删除该名称的任何记录，
  避免证据被"等过期"清掉；cleanup 在 launcher 中先于 claim 创建执行。
- **Linux 证据**：`claim-guard` 覆盖 aged claim（dead pid + 3 天）不被接管、
  并发首次请求只有一个成功、aged claim 下并发请求全部 15、人工删除后才可重试；
  `publish-failure-keeps-claim` 额外覆盖"marker 缺失 + aged claim"仍 blocked 且
  证据不被 retention 删除。
