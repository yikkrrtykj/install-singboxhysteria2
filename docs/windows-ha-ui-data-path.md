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
- 生成触发需 UI 明确勾选同意：它会执行既有 `miaomiao` 脚本（该脚本每次运行会
  `curl` 更新自身、做幂等的 host 依赖/权限基线修复与 `install_shortcut`；菜单 3 只读
  配置并写派生文件，不改 sing-box 配置）。若派生文件已新鲜则完全不执行脚本。
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
