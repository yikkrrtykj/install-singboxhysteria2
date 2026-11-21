# Windows HA-UI — 数据获取路径与边界（Issue #110 调查结论）

日期：2026-11-21。适用代码基线：`main`（含 PR #107/#108/#109）与 Draft PR #112 的
friendly-export 适配器。本文只陈述仓库与运行手册中已有的事实，不包含任何凭据、IP、
YAML 或服务器私钥。

## 1. 结论摘要

Windows 前端 MVP **不使用** sbox-cm/Monitor 的 `client.list` / `client.export` 特权
通道，而是通过**已确认主机指纹的 root SSH 管理通道**执行仓库既有的
`miaomiao` 客户端管理菜单（10 → 3），读取其生成的规范导出文件
`/root/sbox/clients/<name>/mihomo.yaml`。理由与边界见下。

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

因此，GUI 使用 root SSH + 既有 CLI 生成/读取规范导出，属于**已记录的运维路径**，
不是对 Monitor/E3 权限模型的绕过。GUI 不调用 sbox-cm socket、不 activate/deactivate、
不触碰 `management.active` 标记、不修改 `sbconfig_server.json`。

## 4. 本 MVP 的实现规则（安全边界）

- 仅 root SSH；非 root 直接报 `E_REMOTE_NOT_ROOT`，不尝试 sudo（MVP 范围）。
- 连接前必须核对并保存 SHA-256 主机指纹；未知/变化指纹在**发送密码前**拒绝。
- 只执行**固定、无用户字符串插值**的只读命令与既有 CLI 菜单；客户端名先经
  `^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$` 校验。
- 列表读取：root 只读 `jq` 取 name + 两协议凭据是否存在（仅布尔），以及派生文件
  的 root/0600/mtime 元数据；不读取凭据值。
- 导出读取：SFTP 下载 `/root/sbox/clients/<name>/mihomo.yaml`，下载前后校验
  普通文件、root 属主、0600、大小上限、lstat/fstat 一致性，并与远端 `sha256sum`
  对比；字节只落本地私有目录，随后由本地 HA 链校验。
- 生成触发需 UI 明确勾选同意。生成路径已在本轮预验收审查中加固（见 §6）：只读下载
  main `install.sh` 到 root 临时文件并先校验菜单结构，再执行**已校验的同一份字节**；
  用 `timeout` 限制运行、`PIPESTATUS` 捕获真实退出码、逐客户端成功文本 + 生成前后
  stat/SHA-256 变化共同证明“确实重新生成”，部分生成/失败/超时一律在下载前中止。
  现有安装脚本在菜单前仍会做幂等的 host 依赖/权限基线修复与 `install_shortcut`，
  菜单 3 只读配置并写派生文件，不改 sing-box 配置；导出已新鲜时完全不执行脚本。
- 若检测到 `/var/lib/sbox-cm/management.active`，**拒绝生成**：此时存在并发的 Web/E3
  管理事务，跨事务边界读取不安全；MVP 不处理该状态。
- 若配置缺少 monitor-api secret（`maybe_migrate_existing_api_auth` 会交互提示），
  前置检查直接拒绝，避免管道菜单输入错位。
- 生成的最终文件只在新的 run 目录内以 no-clobber 方式发布；失败不会覆盖任何旧成功
  产物，失败 run 目录会被清理（不含旧产物）。
- 不自动导入 Clash、不开启 TUN、不修改系统代理；不自动做故障注入；不声称已完成
  已泄露凭据的轮换。

## 5. 后续（需单独审批，不在本 MVP）

- 若未来批准 Monitor/E3 生产管理面：可在 SSH 隧道内用 Monitor 会话 + CSRF + step-up
  调用 `POST /api/v1/clients/export`，从而使用 privileged `client.export` 的锁内渲染；
  但这需要独立的安全审批与 Monitor 凭据存储设计，不能由本 UI 自动激活。
- 批量/创建/删除/轮换客户端、跨两端补偿事务：继续留在后续阶段，复用已审查的
  事务引擎，不在 MVP 内。

## 6. 预验收加固：远程 CLI 导出的退出状态与来源证明（2026-11-21）

此前实现只依赖 `HAUI_MENU_END` 结束标记，无法证明 `miaomiao`/`install.sh` 真实退出
成功、也没有证明派生文件是本次生成的。现实现（`ha-ui/ha_ui/core/remote.py`）按以下
顺序 fail-closed：

1. **下载前验证脚本结构**：把 main `install.sh` 只读下载到 root-only 临时文件，校验
   顶层 `10. 客户端管理`、`client_management_menu`、客户端菜单 `3)
   generate_client_configuration_interactive`、成功文案 `的 Mihomo 配置已生成` 全部
   存在；缺任一项立即 `E_REMOTE_MENU`（`precheck-menu-drift`），**不执行**任何字节。
   这消除了“菜单重编号后把 10 当成卸载/重装”的最大风险。
2. **执行已校验字节**：对同一临时文件执行菜单输入（不再让 `miaomiao` wrapper 二次下载
   后再执行另一份内容），`timeout -k 10 420` 以独立进程组限时；临时文件 0600 并在
   trap 中删除。
3. **真实退出状态**：`printf | timeout bash | sed` 管道的 `PIPESTATUS` 被写入响应
   （`HAUI_MENU_RC=printf,menu,sed`）。menu 124 = 超时，任何非零 = 失败；结束标记不再
   能掩盖 CLI 失败。
4. **转录证明**：要求出现客户端菜单标题、`NAME/REALITY/HY2` 表头，以及每个目标
   `客户端 '<name>' 的 Mihomo 配置已生成`；任一缺失按 `partial`/`consistency`/
   `incomplete`/`permission` 等固定 token 中止。
5. **生成前后身份对比**：运行前/后各读一次 `%F|%n|%a|%u|%s|%Y|%y` 与 `sha256sum`；
   要求目标为 root 属主、0600、普通文件、大小 0–64 KiB，且 mtime-ns 或 SHA-256 发生
   变化。预先存在的“看起来新鲜”的旧文件不会因 CLI 失败而被当作新生成结果。
6. **失败语义**：失败/部分生成/超时一律在**下载前**中止，本地不产生交付；服务器侧
   可能已重写的 `/root/sbox/clients/<name>/mihomo.yaml` 是派生文件（root:0600，可由
   菜单重生成），不是 live 配置；重试会重新生成并再次验证。远端超时由 `timeout`
   终止进程组，降低“孤儿进程继续写文件”的窗口。

**副作用审计**：该路径仍执行既有 `install.sh`，因此每次生成（仅当导出缺失/过期且
用户勾选同意时）会出现：从 GitHub `main` 拉取脚本、`install_pkgs` 检查/补齐 host
依赖、`repair_existing_install_security_baseline` 幂等权限修复、`install_shortcut`
重写 `/root/sbox/miaomiao.sh` + 符号链接、`maybe_migrate_existing_api_auth`（本 UI
在前置检查发现需要迁移时直接拒绝）、`show_status` 的只读状态查询。**不修改**
`sbconfig_server.json`、不重启/重载 sing-box、不激活 Monitor/E3。

**更安全的导出方案（建议，需服务器端单独 PR/审批，本轮未实施）**：在 `install.sh`
最前面增加只读非交互模式，例如
`install.sh --client-export <validated-name>`：加载 digest-pinned
`lib/client-management.sh`，在 `with_client_lock` 内执行结构/一致性检查后仅用
`cm_render_client_mihomo_yaml` 输出 YAML 到 stdout，不进入安装/修复/菜单路径，不做
任何写操作；退出码固定、无 TTY 依赖。GUI 可先只读探测该能力标记再调用，从而去掉
`install_pkgs`/`install_shortcut` 等副作用。Monitor/E3 生产激活后则优先使用
privileged `client.export`（锁内渲染 + 审计），而不是 shell 菜单。两条路线都必须
单独 review/审批，本轮不修改服务器端代码。
