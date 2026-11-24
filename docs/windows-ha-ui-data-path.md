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

## 7. 创建路径的证明、分类与超时后核对（0.2.0，PR #124 复审修复）

创建使用同一个 pinned installer，但输入序列固定为 `10 → 2 → <name> → 0`，并在执行前
额外校验 `2) add_client_interactive` / `add_client()` / `_add_client_locked()` /
成功文案这些静态标记。执行后按以下顺序证明：

1. 捕获 `PIPESTATUS`，menu 124 = 超时，任一非零 = 失败；
2. 转录必须出现提交行 `配置已提交`（reload 成功时是 `配置已提交并重载成功`，无进程时
   是 `配置已提交（当前无运行中的 sing-box 进程，跳过 reload）`）**和**
   `客户端 '<name>' 已同时添加到 Reality 与 HY2`；只有成功行、没有提交行不算提交；
   菜单循环本身即使 `add_client` 失败也返回 0，因此退出码 0 不能单独作为成功依据；
3. 重新执行一次只读 `snapshot`（同一条命令同时返回 `sbconfig_server.json` 的 SHA-256 与
   客户端清单），确认名称存在且该记录 `exportable`（= `complete` 且 `problems` 为空）；
4. 只有 2 + 3 都通过才报告该端 `created`。

创建前同样先 `snapshot` 一次：名称已在两端 → `E_CLIENT_EXISTS`；仅一端存在且
`exportable` → 默认 `E_CLIENT_PARTIAL_EXISTS`，只有 UI 第二次确认“仅补齐缺失端”才创建
缺失端；已存在端不 `exportable` → `E_CLIENT_INCOMPLETE`。任一端预检/证书身份失败时，
不写入任何一端。两端不是原子事务：A 成功、B 失败时 A 保留，B 状态准确显示，不自动删除 A。

### 7.1 失败分类（禁止猜测）

`E_REMOTE_CREATE` 的 `detail` 是固定的服务端结果 token，而不是“看起来像失败”。判定
同时使用转录与只读核对，只有满足括号内条件才允许降级为干净失败：

| 服务端结果 | 判定 | 依据 |
|---|---|---|
| `lock` / `consistency` / `incomplete` / `missing-config` / `name-invalid` / `permission` / `reserved` / `create` | `failed`（干净拒绝） | 转录 token **且** 核对显示 config SHA-256 未变、名称仍不存在 |
| 同上，但核对发现 SHA 变化或名称已存在 | `uncertain`（`refusal-after-write`） | 与拒绝矛盾，说明存在并发/竞争写入 |
| `exists` | `E_CLIENT_EXISTS` / `failed` | 同上核对通过才降级；否则 `refusal-after-write` |
| `已回滚并重新加载上一份配置`（`lib/client-management.sh:338`） | `failed`（`rolled-back`） | 精确句 **且** SHA 回到写入前值 **且** 名称不存在 |
| `回滚恢复失败，请立即人工介入`（`:330`） | `uncertain`（`rollback-failed`） | 恢复本身失败 |
| `已回滚配置文件，但服务未能确认恢复`（`:344`） | `uncertain`（`rollback-unconfirmed`） | 字节可能已恢复，但服务状态未确认 |
| 菜单 124（外层 `timeout` 命中） | `uncertain`（`timeout` / `timeout-write`） | 只把“是否观察到写入”作为证据附加，不作为事务状态 |
| SSH 超时/断连 | `uncertain`（`timeout-transport`） | 无法通过该会话核对 |
| 无成功行且无已知 token | `uncertain`（`unconfirmed`）/（`commit-unproven`） | fail-safe |

关键点：`_MENU_FAIL_TOKENS` 不再使用泛化的 `回滚` 子串。服务端三种回滚结局都包含这个
词，只有 `:338` 那一句能证明“写入已撤销”，`:330` / `:344` 必须保持 `uncertain` 并提示
人工介入。

### 7.2 超时后核对（post-timeout reconciliation）

- `RemoteProvider.snapshot()` 用**一条**只读命令返回 `cfgsha=` + `mtime=` + inventory
  JSON，保证两个事实来自同一时刻；`preflight` 也填充 `RemoteFacts.config_sha256` / 
  `RemotePreflight.config_sha256`（不再是永远为 `None` 的占位字段）。
- 哈希只接受严格的小写 64 位十六进制；取不到 = 没有证据，**绝不**当成“未变化”。
- 核对只在失败/超时后执行一次；核对本身失败（连接已断、jq 失败） → `uncertain`。
- **核对只提供可观测性，不提供原子性。** 客户端无法阻止外层 `timeout -k 10 420`
  在 `replace` 与 `reload`/`health`/回滚之间打断服务端事务；也无法阻止 SSH 通道
  断开导致管道 SIGPIPE。`MENU_RUN_TIMEOUT` 没有被调大（复审明确禁止用调大超时当修复）。
- 真正的原子性要求服务端把 commit 放进**独立进程组**并写**持久 phase/结果文件**，且
  UI 路径需要 `CM_TX_JOURNAL_HOOK`（当前 GUI 菜单路径没有 hook，因此不存在可用 journal；
  不得据此编造事务状态）。这需要修改 pinned `install.sh` / `lib/client-management.sh`
  并重算安装器哈希链（`INSTALLER_SHA256` / `CLIENT_MANAGEMENT_SHA256` / 安装器内嵌 pin），
  属于安全评审动作，超出本 PR 允许范围 → **P0 保持 BLOCKED**，见第 8 节。
- `UNCERTAIN` 不自动重试写入；UI 会刷新两端实际状态，刷新失败显示 `STALE / UNKNOWN`，
  并禁止在核对完成前重建同名客户端。

## 8. P0 事务安全：现状与残余风险（BLOCKED，需服务端改动）

已确认的机制（不是猜测）：

1. 服务端执行串是 `printf … | timeout -k 10 420 env -i … bash install.sh 2>&1 | sed …`，
   `timeout` 包住整条菜单，包括 `replace → reload → health → rollback`；
2. 客户端 `exec(timeout=540)` 是另一层，且只关闭通道，不保证终止远端进程；
3. 写入阶段没有对外的原子标记：没有 journal hook，也没有可轮询的 phase 文件；
4. 客户端断开时远端管道的 `sed` 消失，后续 `printf` 会收到 SIGPIPE，同样可能停在
   `replace` 与 `reload` 之间。

因此本 PR 能交付的是**检出与不误报**（分类 + 核对 + `STALE`），不是事务原子性。
解除 BLOCKED 的最小服务端改动（需单独评审）：

- 菜单提交阶段在独立 session/进程组中执行，外层 `timeout` 只覆盖非写入阶段；
- 提交前写入持久 phase 文件（`parse/candidate/check/backup/replace/reload/health/rollback*`），
  并在同一目录原子发布 `result`；
- UI 侧在超时/断连后通过只读命令读取 phase/result 对账，而不是推断。

在这三项落地之前，`PR124-P0-TRANSACTION-SAFETY` 只能记为 `BLOCKED`。
