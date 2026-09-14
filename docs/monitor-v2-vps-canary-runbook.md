# Monitor v2 — VPS Canary Final Runbook (Round 2, rev2.3)

状态：**DESIGN / DOCUMENTATION ONLY — 未执行**。
本文档是 Round 2 的最终 localhost-only VPS canary runbook，供**未来获得明确批准后**的 canary 执行使用。
在获得批准前：不连 VPS、不跑生产命令、不动 PR #16（保持 DRAFT / NOT MERGED / NOT Ready）、E3 不启动、E4 不在服务端暂存。

**rev2 变更（吸收独立 review 的 7 项修正，仅文档，零代码/零执行）**：

1. `/api/v1/session` 契约改为 **R1.1 最小稳定形状**：强制项仅 `authenticated`(bool) / `whitelist_allowed`(bool) / `version`(非空字符串)；`password_configured`/`recovery_configured`/`remote_mode` 为**存在时**才校验的可选项；`current_ip` 仅作信息性上下文；**额外字段绝不导致 FAIL**（不再要求精确六字段）。
2. E1 Reality/HY2 strict canary 认证修正：`tests/monitor-v2-integration-e1.sh` **不向** `collector.py` 传 `--secret-file`，collector 仅经 `BOX_API_SECRET` 或 `--secret-file` 鉴权；新增**受控手动 canary 例外**（环境变量窗口 + 立即 unset），不改冻结代码。
3. 删除两个无效身份硬门禁（"设备键零 IPv4 形状"、"协议键 ⊆ {vless-in, hy2-in}"）：合法用户名可以形似 IP，生产可合法含 `direct-in`/`ss-in` 等额外 inbound tag。身份改由 **严格作用域双 canary**（EXPECT_USER × EXPECT_INBOUND）证明；Source IP 是 metadata 来自**实现契约**，与设备名外观无关。
4. fresh 安装爆炸半径收紧：`install --no-start` → 离线验证（release 树 / symlink / unit / monitor.conf / 派生 secret / **9191 尚未监听** / sing-box 不变）→ 需要时在 inactive 状态跑 `web-setup` → 显式 `systemctl start singbox-monitor`；**首轮 canary 不 enable**（永久 enable 是 canary 后的独立审批）。已有部署则正确分支走 `upgrade`。
5. P5 回滚 drill 改为**条件性**：存在既往成功保留 release → REQUIRED；fresh 首装无既往 release → **NOT APPLICABLE**（不为测试回滚而人为制造生产 release；事务回滚行为已由 Linux CI 覆盖）。
6. restart/reload 证据措辞收敛：PID 不变**不足以**数学证明无 in-process reload；改为采集 MainPID + `NRestarts` + `ExecMainStartTimestampMonotonic` + 哈希 + journal 区间，结合 Packaging 不变量（从不调用 sing-box 生命周期操作），报告措辞为 **"no evidence of restart/reload; all lifecycle/config invariants unchanged"**，不过度声称。
7. journal 泄漏门禁改为**精确已知敏感值硬 FAIL**（service.api secret、Reality UUID 凭据值、HY2 password、Reality private key；仅输出命中计数，绝不打印值）；通用 UUID 形状扫描降级为**仅供参考**。

**rev2.1 cleanup 变更（final cleanup review，仅文档，零代码/零执行）**：

8. canary 鉴权窗口改为**逐命令临时环境赋值**（`BOX_API_SECRET=… cmd` 前缀形式）：值不进入父 shell（废除 `export` 方案）；读取 secret 前强制确认 xtrace/`set -x` 为 OFF；Reality 与 HY2 退出码**独立捕获**（`pipefail` 防止 tee 掩码脚本真实退出码）。
9. journal 泄漏门禁从 `grep -F -f` 模式文件方案**升级为内存态 Python 精确已知敏感值扫描器**：多行 Reality private-key 材料被完整覆盖（grep 逐行模式缺陷消除）、空值字面量被过滤（空模式不可能产生误报）、只输出计数、任一已知敏感字面量命中即 FAIL、**零 secret 落盘临时文件**。

**rev2.2 变更（private-key 扫描器加固，final documentation micro-fix，仅文档，零代码/零执行）**：

10. Reality private-key 检测升级为**三层字面量**：(1) 完整非空 `private_key` 值；(2) 完整值的 **JSON 转义表示**（覆盖日志中 `\n` 转义渲染）；(3) **逐行 key material**（按行 split → strip → 过滤空行 → 过滤 `-----BEGIN…-----` / `-----END…-----` 等 formatting-only 行，保留真实密钥材料行——覆盖逐行拆分/归一化渲染）。其余类别（service.api secret、Reality UUID、HY2 password）保持精确全值扫描不变；输出固定为四类别聚合计数（`service_api_secret_matches` / `reality_uuid_matches` / `hy2_password_matches` / `reality_private_key_matches`）；**任一类别 >0 ⇒ FAIL/STOP**；**任一预期类别收集不到敏感材料 ⇒ fail-closed**（绝不静默通过）。扫描器保持：标准库、短命、内存态、零 secret 落盘、argv 零 secret、无 xtrace、journal 限 canary 区间；空字符串永不成为扫描模式。

**rev2.3 变更（PR #18 独立 source review follow-up 修正，仅文档，零代码/零执行）**：

11. P0-8 service.api JSON 形状修正为冻结基线事实：`.services[]` 条目 `tag=="monitor-api"` / `type=="api"` / `listen=="127.0.0.1"` / `listen_port==9091` / 非空 `secret`；废除错误的 `.listen == "127.0.0.1:9091"` 选择器（B3 相应改写：service.api 形状已确认，仅凭据字段键名仍属扫描器按键收集范畴）。
12. 管线退出码纪律前置：canary 会话自 §1 起全局 `set -o pipefail`；install/upgrade、monitor health、journal 扫描器、E1 strict canary、rollback 等门禁管道一律显式捕获生产者退出码（`${PIPESTATUS[0]}`），tee 永远不可能把 FAIL 掩成 PASS。
13. P3-0 collector 路径修正：`webapp.py` 与 `collector.py` 部署在同一目录（release 树 `app/monitor-v2/`）；同目录引用 `$WEBAPP_DIR/collector.py`（等价替代 = 冻结 checkout 的 `/root/canary-src/monitor-v2/collector.py`）；废除 `$WEBAPP_DIR/../collector.py`。
14. cmdline artifact 拆分：基线 `p0-singbox-cmdline.txt` 仅含 cmdline 输出；ps/lstart 进程元数据单独落 `p0-singbox-process.txt`（信息性）；P4 做同类逐字节比较。
15. 备份集合比较输入格式统一：P0/P4 集合不变量一律用"仅 basename、已排序"的同构文件比较；大小/时间戳元数据移入独立信息性 artifact（`p0-backups-info.txt`）。

---

## 0. 固定锚点与硬性禁令

### 0.1 锚点

| 项 | 值 |
| --- | --- |
| 仓库 | `yikkrrtykj/install-singboxhysteria2` |
| 冻结基线 head | `3ee9a162a3fb53d9fddc95cb6eba95b3bcc5702e`（下文 `$FROZEN`） |
| 权威 CI（head 3ee9a16） | Phase C 121/121 · Phase D 105/105 · S0 133/133 · Legacy 161/161 · E1 188/188 · E2 272/272 · E4 161/161 · Packaging fixture 473/473 · root metadata 488/488 · shellcheck PASS |
| sing-box 配置（唯一事实源） | `/root/sbox/sbconfig_server.json`（root 0600，canary 全程只读） |
| sing-box 状态文件 | `/root/sbox/config`（只读） |
| 配置锁 | `/root/sbox/config.lock`（canary 不触碰） |
| service.api | `.services[]` 条目：`tag=="monitor-api"`、`type=="api"`、`listen=="127.0.0.1"`、`listen_port==9091`、非空 `secret`；仅监听 `127.0.0.1:9091`，gRPC-Web `daemon.StartedService/SubscribeConnections` |
| secret 派生链 | `sbconfig_server.json → /root/sbox/monitor-api.secret（root:root 0600）→ /etc/singbox-monitor/api.secret（root:sboxweb 0640）`，后者 fail-closed 派生 |
| monitor 部署 | `monitor-v2/deploy/install-monitor.sh` + `lib/monitor-deploy-lib.sh`；release 树 `/opt/singbox-monitor-releases`，symlink `/opt/singbox-monitor`，conf `/etc/singbox-monitor/monitor.conf`，state `/var/lib/singbox-monitor`（sboxweb 0700），备份 `/var/backups/singbox-monitor` |
| monitor 服务 | `singbox-monitor.service`，`User=sboxweb`（非 root），默认 `SBMON_WEB_BIND=127.0.0.1:9191`、`SBMON_API_URL=http://127.0.0.1:9091`、`SBMON_MODE=web` |
| monitor runtime shim | `monitor-service`：fail-closed 校验（loopback http URL、secret 文件普通可读非空、web bind 仅回环）、`exec env -u BOX_API_SECRET python3 … webapp.py serve …`。**生产契约 = 文件传递 secret，且显式 unset `BOX_API_SECRET`** |
| 健康探针 | `/opt/singbox-monitor/bin/monitor-health <conf> <state_root>` → 单行 JSON，退出码 0=healthy / 2=degraded / 1=unhealthy |
| E1 集成脚本鉴权事实 | `tests/monitor-v2-integration-e1.sh` **不**向 `collector.py` 传 `--secret-file`；collector 经 `BOX_API_SECRET` 环境变量或 `--secret-file` 参数鉴权 → strict canary 必须显式处理鉴权（§P3-1） |

### 0.2 硬性禁令（canary 全程）

1. **不 restart / reload sing-box**（`systemctl restart sing-box`、`kill -HUP`、`mianyang` 菜单 4 一律禁止）。
2. **不写 `/root/sbox/`** 任何文件；不修改 `sbconfig_server.json`、`/root/sbox/config`、端口、证书、密钥、MTU。
3. **不碰防火墙 / TLS / 反向代理**；不 rotate 凭据；不 expose 9191。
4. **不使用宽泛进程击杀**（`pkill`、`killall`、按名 kill）。任何必须引用进程的命令，**必须先**用 `/proc/$PID/cmdline` 精确验证该 PID 的身份。
5. monitor 安装/升级/回滚**只允许**经 `install-monitor.sh`（单锁事务，仅操作 `singbox-monitor.service`）；fresh 首装**首轮 canary 不 enable**（enable 是 canary 后的独立审批）。
6. 任何输出都不得打印 secret、UUID、password、private key、完整分享 URI；验证一律用"布尔/计数/哈希"表达。手动 canary 窗口内：**不 echo secret 值；读取 secret 前必须确认 xtrace/`set -x` 为 OFF；值只经逐命令临时环境赋值进入该次子进程（绝不 `export` 进父 shell、不进 argv、不持久化到任何配置/unit/文件）**。
7. P4 的证明措辞：只允许 "no evidence of restart/reload; all lifecycle/config invariants unchanged"；**禁止**声称"PID 不变 = 未 reload"。

### 0.3 本文档撰写时发现的事实与 blocker

| # | 发现 | 定性 |
| --- | --- | --- |
| B1 | 本地开发工作区 `feature/proxy-monitor-web` 当前 head 为 `b52b42c…`，**不等于**冻结基线 `3ee9a16`，且本地不存在 `monitor-v2/deploy/`（该目录只在远端 head 3ee9a16 上）。本 runbook 的部署章节依据远端 head 3ee9a16 的真实文件（`install-monitor.sh`、`lib/monitor-deploy-lib.sh`、`app-bin/monitor-service`、`app-bin/monitor-health`）撰写 | **流程性前置**：canary 必须在 VPS 上用干净 clone 检出 `$FROZEN` 执行（§P0-1），绝不以本机工作区为源 |
| B2 | VPS 当前实况未知：`singbox-monitor` 是否已装、`VERSION` 值、python3 版本均未知 | 由 §P0 门禁解析；fresh（`install --no-start`）vs 已有部署（`upgrade`）分支由 P0-6 结果决定，不是 blocker |
| B3 | ~~`service.api` 块确切 JSON 形状未确认~~（rev2.3 修正）：冻结基线事实 = `.services[]` 条目 `tag=="monitor-api"` / `type=="api"` / `listen=="127.0.0.1"` / `listen_port==9091` / 非空 `secret`。凭据字段（uuid/password/private_key）由 P2-7 扫描器**按键名遍历**收集 | P0-8 选择器已按上述基线形状固定；若 VPS 实机凭据键名与扫描器按键集合不同，**只允许调整收集键名集合，绝不打印敏感值**。非阻塞 |
| B4 | E1 canary 流量验证会在窗口内产生**第二个短暂的 service.api consumer**（集成脚本自带的 collector 进程）。与稳态"one Collector / one consumer"约束冲突 | **设计内受控例外**：仅允许在 §P3 明示窗口内发生，窗口前后必须复跑单例断言（§P2-6）。非阻塞，但必须执行复检 |
| B5（rev2 记录，rev2.1 更新方案） | `tests/monitor-v2-integration-e1.sh` 不传 `--secret-file`，strict canary 在有鉴权的生产 service.api 上无法直接运行 | 由 §P3-1 受控手动例外解决（**逐命令临时环境赋值窗口**，值不进父 shell）；不改冻结代码。等价备选方案见 §P3-1 备注 |
| B6（VPS canary 兼容性实机发现，2026-09-14，Ubuntu 22.04） | Ubuntu 22.04 的 `journalctl --since` **拒绝 raw RFC3339 时间戳**（实测输入 `2026-09-14T15:51:50Z`） | 已修复并固化：内部 canary 时间戳保持 RFC3339/UTC；`--since` 前一律经 `journal_time_normalize_jctl`（Python datetime，规范副本 `tests/lib/journal-time.sh`，回归测试 `tests/test-journal-time-compat.sh`）规范化为本地 "YYYY-MM-DD HH:MM:SS"。规范副本见 §1 会话准备 |

除此之外**未发现任何阻断 canary 的技术 blocker**：Round 2 权威 CI 全绿、I0-7 CLOSED、Packaging 与 proxy 树静态隔离、`sbconfig_server.json` 零引用（S0 锚点除外）。

---

## 1. 阶段总览与 artifacts 目录

```text
P0  Preflight（只读快照与门禁）        —— 全部 PASS 才允许 P1
P1  Install/Upgrade（monitor only；fresh = --no-start + 显式 start，不 enable）
P2  Runtime validation（稳态单例/回环/健康/日志卫生）
P3  Identity validation（Reality + HY2 各一次，strict 作用域双 canary + 受控鉴权窗口）
P4  Isolation verification（lifecycle/config 不变量集合证明，非单一 PID 证明）
P5  Monitor rollback drill（条件性：REQUIRED / NOT APPLICABLE）
P6  Final report（PASS/FAIL 模板填写）
```

VPS 上一次性建立 artifacts 目录并全程复用：

```bash
set -o pipefail   # rev2.3：会话全局启用——任一管线中生产者非零退出都使整条管线非零
export FROZEN=3ee9a162a3fb53d9fddc95cb6eba95b3bcc5702e
export ART=/root/canary-artifacts-$(date -u +%Y%m%dT%H%M%SZ)
mkdir -m 0700 -p "$ART"
export T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)   # canary 窗口起点（内部时间戳，恒为 RFC3339/UTC）

# —— journalctl 时间兼容（B6 发现，2026-09-14 Ubuntu 22.04 实机）——
# 事实：Ubuntu 22.04 的 journalctl 拒绝 raw RFC3339（`2026-09-14T15:51:50Z`）。
# 规则：T0 保持 RFC3339/UTC 作为内部时间戳；任何 journalctl --since 之前必须用
# Python datetime 规范化为本地 "YYYY-MM-DD HH:MM:SS"；**绝不**把 raw "...T...Z"
# 直接传给 journalctl。规范化实现以 tests/lib/journal-time.sh（回归测试
# tests/test-journal-time-compat.sh 覆盖）为规范副本；P0-1 checkout 后也可直接
# `source tests/lib/journal-time.sh` 获得同一实现。
journal_time_normalize_jctl() {
  python3 - "$1" <<'PYEOF'
import sys
from datetime import datetime, timezone
raw = (sys.argv[1] if len(sys.argv) > 1 else "").strip()
if not raw:
    print("journal-time: empty timestamp", file=sys.stderr); sys.exit(1)
if "T" not in raw and "Z" not in raw:   # 已规范化形态：幂等透传（严格校验）
    try: datetime.strptime(raw, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        print(f"journal-time: not a valid timestamp: {raw!r}", file=sys.stderr); sys.exit(1)
    print(raw); sys.exit(0)
iso = raw[:-1] + "+00:00" if raw[-1] in ("Z", "z") else raw
try: dt = datetime.fromisoformat(iso)
except ValueError:
    print(f"journal-time: not a valid RFC3339 timestamp: {raw!r}", file=sys.stderr); sys.exit(1)
if dt.tzinfo is None:
    dt = dt.replace(tzinfo=timezone.utc)   # 无显式偏移按 canary 约定视为 UTC
print(dt.astimezone().strftime("%Y-%m-%d %H:%M:%S"))
PYEOF
}
export J0="$(journal_time_normalize_jctl "$T0")"   # 所有 journalctl --since 只用 $J0
```

> **时间戳纪律**：内部记账（T0、artifacts 命名、报告）一律 RFC3339/UTC；`journalctl --since` 一律使用 `$J0`（本地 "YYYY-MM-DD HH:MM:SS"）。输入非法时规范化函数 fail-closed（非零退出），绝不静默给出错误时间窗。

**管线退出码纪律（rev2.3，自 P0 起生效）**：所有门禁管道（install/upgrade、monitor health、journal 扫描器、E1 strict canary、rollback）一律显式捕获**生产者退出码**（`${PIPESTATUS[0]}`）并以其判定；`tee` 的退出码永远不作为判定依据——任何生产者 FAIL 都不可能被 `tee` 掩成 PASS。

---

## 2. P0 — Preflight（只读，零变更）

### P0-1 干净 checkout == $FROZEN

```bash
git clone https://github.com/yikkrrtykj/install-singboxhysteria2 /root/canary-src
cd /root/canary-src && git checkout --detach "$FROZEN"
git rev-parse HEAD                 # 必须逐字符 == $FROZEN
git status --porcelain             # 必须为空（工作区干净）
```

- **PASS**：`rev-parse == $FROZEN` 且 `status --porcelain` 为空。
- **FAIL**：SHA 不匹配或工作区不干净 → 停止，不进入 P1。
- **STOP 动作**：保留 `$ART/p0-checkout.txt`，人工核对来源，绝不"就地凑合"。
- **artifacts**：`$ART/p0-checkout.txt`。

### P0-2 sing-box 进程身份与生命周期计数基线（rev2：多证据采集）

```bash
SBPID=$(systemctl show -p MainPID --value sing-box)
[ -n "$SBPID" ] && [ "$SBPID" != "0" ] || { echo 'FAIL: sing-box MainPID 无效'; exit 1; }
tr '\0' ' ' < /proc/$SBPID/cmdline | tee "$ART/p0-singbox-cmdline.txt"          # 基线 artifact 仅含 cmdline（P4 同类逐字节比较）
ps -o pid=,user=,group=,lstart= -p "$SBPID" | tee "$ART/p0-singbox-process.txt"  # 进程元数据独立留档（信息性；不参与 P4 cmdline 比较）
# 生命周期不变量基线（rev2：PID 不变不足以证明无 in-process reload，需采集集合）
systemctl show sing-box -p MainPID -p NRestarts -p ExecMainStartTimestampMonotonic -p ActiveState -p SubState \
  | tee "$ART/p0-singbox-lifecycle.txt"
```

- **PASS**：`MainPID` 有效；cmdline 可执行文件为 `/root/sbox/sing-box` 且包含 `-c /root/sbox/sbconfig_server.json`；属主 `root`；lifecycle 基线已记录。
- **FAIL**：cmdline 与上述不符（手工进程、路径漂移）→ 停止（先人工恢复 systemd 托管形态，超出本 canary 范围）。
- **artifacts**：`$ART/p0-singbox-cmdline.txt`、`$ART/p0-singbox-process.txt`、`$ART/p0-singbox-lifecycle.txt`。

### P0-3 既有服务状态（决定 P1 分支与 P5 条件）

```bash
for u in sing-box singbox-monitor; do
  printf '%s: active=%s enabled=%s\n' "$u" "$(systemctl is-active $u || true)" "$(systemctl is-enabled $u 2>/dev/null || true)"
done | tee "$ART/p0-service-state.txt"
# 部署现状（决定 fresh / upgrade 分支）：
[ -L /opt/singbox-monitor ] && readlink /opt/singbox-monitor || echo 'no live symlink'
ls -1 /opt/singbox-monitor-releases 2>/dev/null || echo 'no releases tree'
```

- **PASS**：`sing-box` active + enabled；monitor 侧状态如实记录（active / inactive / 未安装三种均合法）。
- **分支判定**：
  - **fresh**（无 live symlink / 无 release 树）→ P1 走 `install --no-start`，P5 = NOT APPLICABLE；
  - **已有部署**（live symlink 存在且曾有成功 release）→ P1 走 `upgrade`，P5 = REQUIRED（若存在既往成功保留 release）。
- **FAIL**：`sing-box` 非 active → 停止。
- **artifacts**：`$ART/p0-service-state.txt`。

### P0-4 监听器清单（基线）

```bash
ss -lntup > "$ART/p0-listeners.txt"
grep -E ':(9091|9191)\b' "$ART/p0-listeners.txt"
grep -c '127\.0\.0\.1:9091' "$ART/p0-listeners.txt"                        # 期望 1
grep -cE '0\.0\.0\.0:9191|\[::\]:9191|\*:(9191)' "$ART/p0-listeners.txt"  # 期望 0
```

- **PASS**：`9091` 仅绑定 `127.0.0.1`（属主为 sing-box PID）；无非回环绑定的 `9191`（fresh 路径下 P1 之后 `9191` 仍不得监听，直到显式 start，见 §P1-3）。
- **FAIL**：`9091` 非回环，或 `9191` 已被其他进程非回环占用 → 停止。
- **artifacts**：`$ART/p0-listeners.txt`。

### P0-5 proxy/config 哈希基线

```bash
sha256sum /root/sbox/sbconfig_server.json /root/sbox/config | tee "$ART/p0-hash-before.txt"
```

- **PASS**：两文件可读、哈希已记录。**FAIL**：任一缺失 → 停止。
- **artifacts**：`$ART/p0-hash-before.txt`。

### P0-6 monitor 安装现状

```bash
if [ -x /root/canary-src/monitor-v2/deploy/install-monitor.sh ]; then
  bash /root/canary-src/monitor-v2/deploy/install-monitor.sh status || true
fi | tee "$ART/p0-monitor-status.txt"
```

- **PASS**：可执行并输出现状（已装：release id/version；未装：明确提示）。
- **FAIL**：脚本缺失或 `monitor-v2/deploy/` 布局不完整 → 停止（checkout 不完整，回 P0-1）。
- **artifacts**：`$ART/p0-monitor-status.txt`。

### P0-7 生产备份文件仍在

```bash
find /root/sbox -maxdepth 1 -name '*.bak.*' -printf '%f\n' | sort | tee "$ART/p0-backups-before.txt"   # 集合不变量输入：仅 basename、已排序（与 P4 同构）
find /root/sbox -maxdepth 1 -name '*.bak.*' -printf '%f %s bytes %TY-%Tm-%Td\n' | sort | tee "$ART/p0-backups-info.txt"   # 信息性元数据（不参与集合比较）
[ -s "$ART/p0-backups-before.txt" ] || echo 'NOTE: /root/sbox 下无 .bak.*（合法，仅记录）'
```

- **PASS**：清单已记录（P4 与 `p4-backups-after.txt` 以同构"仅 basename、已排序"格式做集合比较，要求该集合**只增不减**）。
- **artifacts**：`$ART/p0-backups-before.txt`、`$ART/p0-backups-info.txt`。

### P0-8 service.api 与 monitor secret 锚点（不打印任何敏感值）

```bash
# (a) 根锚点存在且元数据正确（只打印元数据）
stat -c '%U %G %a %s' /root/sbox/monitor-api.secret | tee "$ART/p0-anchors.txt"
[ -s /root/sbox/monitor-api.secret ] || { echo 'FAIL: 根锚点空/缺失'; exit 1; }

# (b) sbconfig_server.json：恰有一个 monitor-api service 条目（127.0.0.1:9091）且 secret 非空（布尔输出）
#     冻结基线形状（rev2.3）：.services[] 条目 tag=="monitor-api" / type=="api" /
#     listen=="127.0.0.1" / listen_port==9091 / secret 非空
jq -e '[.services[]? | select(.tag? == "monitor-api" and .type? == "api"
        and .listen? == "127.0.0.1" and .listen_port? == 9091)] | length == 1' \
   /root/sbox/sbconfig_server.json | tee -a "$ART/p0-anchors.txt"
jq -e '[.services[]? | select(.tag? == "monitor-api" and .type? == "api"
        and .listen? == "127.0.0.1" and .listen_port? == 9091
        and ((.secret? // "") | length > 0))] | length == 1' \
   /root/sbox/sbconfig_server.json | tee -a "$ART/p0-anchors.txt"

# (c) 派生 secret（若 monitor 已装）与根锚点字节一致（比较哈希，不比较内容）
if [ -f /etc/singbox-monitor/api.secret ]; then
  stat -c '%U %G %a' /etc/singbox-monitor/api.secret | tee -a "$ART/p0-anchors.txt"   # 期望 root sboxweb 640
  [ "$(sha256sum /root/sbox/monitor-api.secret | cut -d' ' -f1)" = \
    "$(sha256sum /etc/singbox-monitor/api.secret | cut -d' ' -f1)" ] \
    && echo 'derived secret: MATCH' || echo 'derived secret: DRIFT (P1 会 fail-closed 修复)'
else
  echo 'derived secret: 尚未派生（fresh 安装路径，P1 建立）'
fi | tee -a "$ART/p0-anchors.txt"
```

- **PASS**：根锚点 `root:root 0600` 非空；两条 jq 均为 `true`（恰一个 `monitor-api` service 条目且 secret 非空）；派生 secret（若存在）哈希一致或元数据 `root:sboxweb 0640`。
- **FAIL**：锚点缺失/非 0600、service.api secret 空、`monitor-api` 条目缺失或多于一个 → 停止（S0 基线不成立，先修环境，非本 canary 范围）。
- **artifacts**：`$ART/p0-anchors.txt`。

---

## 3. P1 — Install / Upgrade（monitor only，rev2：分支正确 + fresh 爆炸半径收紧）

### P1-1 分支执行（单锁事务，只操作 `singbox-monitor.service`）

```bash
cd /root/canary-src
if [ -L /opt/singbox-monitor ] && [ -d /opt/singbox-monitor-releases ] && ls /opt/singbox-monitor-releases >/dev/null 2>&1; then
  bash monitor-v2/deploy/install-monitor.sh upgrade        # 已有部署 → upgrade（未装时该命令自身拒绝，绝不退化为全新安装）
else
  bash monitor-v2/deploy/install-monitor.sh install --no-start   # fresh 首装 → 暂存部署，不启动
fi | tee "$ART/p1-install.log"
RC_INSTALL=${PIPESTATUS[0]}    # rev2.3：生产者退出码（pipefail 已全局启用；绝不采信 tee 的 rc）
[ "$RC_INSTALL" -eq 0 ] || { echo "FAIL: install/upgrade rc=$RC_INSTALL"; exit 1; }
printf 'install/upgrade rc=%s\n' "$RC_INSTALL" | tee -a "$ART/p1-install.log"
```

### P1-2 fresh 路径：启动前离线验证（`--no-start` 爆炸半径收紧）

```bash
ls -1 /opt/singbox-monitor-releases | tee "$ART/p1-releases.txt"        # release 树已建
readlink /opt/singbox-monitor | tee -a "$ART/p1-releases.txt"           # live symlink 指向 candidate
test -f /etc/systemd/system/singbox-monitor.service && echo 'unit: present'
stat -c '%U %G %a' /etc/singbox-monitor/monitor.conf                    # 期望 root:sboxweb 640
stat -c '%U %G %a' /etc/singbox-monitor/api.secret                      # 期望 root sboxweb 640（fail-closed 派生自根锚点）
ss -lntp | grep ':9191' && echo 'FAIL: 9191 已监听（--no-start 被违反）' || echo '9191: not listening yet'
diff "$ART/p0-hash-before.txt" <(sha256sum /root/sbox/sbconfig_server.json /root/sbox/config) \
  && echo 'sing-box hashes: UNCHANGED' || echo 'FAIL: HASH DRIFT BEFORE START'
[ "$SBPID" = "$(systemctl show -p MainPID --value sing-box)" ] && echo 'sing-box MainPID: UNCHANGED' || echo 'FAIL: PID CHANGED'
```

（可选，仅当 dashboard 登录验证需要 admin 密码/白名单时）monitor 仍为 inactive 状态执行 setup：

```bash
bash monitor-v2/deploy/install-monitor.sh web-setup    # 以 sboxweb 身份交互配置；不启动、不 enable 服务
```

### P1-3 fresh 路径：显式启动（不 enable）

```bash
systemctl start singbox-monitor        # 显式 start；绝不 enable
systemctl is-active singbox-monitor    # 期望 active
systemctl is-enabled singbox-monitor   # 期望 disabled / 非 enabled —— enable 属 canary 后独立审批
```

### P1-4 已有部署路径（upgrade）

脚本自身单锁事务：candidate 暂存 `py_compile` + `bash -n` 校验 → 原子翻转 symlink → unit 有变先备份再原子覆盖 → 仅重启 `singbox-monitor` → 失败自动回滚 release + unit + active/enabled 状态 → history 只在健康门通过后写入。`monitor.conf` 与 `/var/lib/singbox-monitor` 既有状态/认证数据绝不覆盖（幂等收敛）。

### P1-5 明确禁止的操作（两分支通用）

```bash
# 以下命令在本 canary 中绝对禁止出现（P4 用 journal 复核）：
#   systemctl restart sing-box / reload sing-box / kill <sing-box> / mianyang（菜单 4）
#   ufw / iptables / nftables 任何写操作；对 /root/sbox 下任何文件的写操作
#   systemctl enable singbox-monitor（fresh 首装路径）
```

- **PASS 条件**：install/upgrade 生产者退出码 `RC_INSTALL=0`（`${PIPESTATUS[0]}`，非 tee 的）；release 激活；fresh 路径下 `--no-start` 离线验证全过、显式 start 后 active 且 **非 enabled**；upgrade 路径下服务健康。
- **FAIL 条件**：脚本 CRITICAL（exit 2）、回滚后未恢复、或 fresh 路径验证任一不符（含 9191 提前监听、sing-box 哈希/PID 在 start 前变化）。
- **STOP 动作**：停止 canary，`status` + `history` 取证交人工；**绝不**手工修补 `/opt`、`/etc/systemd`。
- **artifacts**：`$ART/p1-install.log`、`$ART/p1-releases.txt`、`$ART/p1-status.txt`、`$ART/p1-health.json`、`$ART/p1-history.txt`。

---

## 4. P2 — Runtime validation（稳态）

### P2-1 singbox-monitor 服务身份 = sboxweb（精确 PID 验证）

```bash
MPID=$(systemctl show -p MainPID --value singbox-monitor)
[ -n "$MPID" ] && [ "$MPID" != "0" ] || { echo 'FAIL: monitor MainPID 无效'; exit 1; }
[ "$(ps -o user= -p "$MPID")" = "sboxweb" ] || { echo 'FAIL: 运行身份不是 sboxweb'; exit 1; }
tr '\0' ' ' < /proc/$MPID/cmdline | tee "$ART/p2-monitor-cmdline.txt"
# 断言 cmdline 含: python3 …webapp.py serve --listen 127.0.0.1 --port 9191 --url http://127.0.0.1:9091 --secret-file /etc/singbox-monitor/api.secret
# 且 cmdline 中绝不出现 secret 值（shim exec 前 env -u BOX_API_SECRET；生产契约 = 文件传递）
```

- **PASS**：属主 `sboxweb`；cmdline 为 `webapp.py serve`，listen/url 回环，secret 仅以 `--secret-file` 路径传递。
- **FAIL**：身份/绑定/argv 违例 → 停止，journal 取证。
- **artifacts**：`$ART/p2-monitor-cmdline.txt`。

### P2-2 service.api = loopback 127.0.0.1:9091（消费视角）

```bash
ss -lntp | grep ':9091' | tee "$ART/p2-listener-9091.txt"     # 127.0.0.1:9091，属主 PID == $SBPID
grep -E '^SBMON_API_URL=' /etc/singbox-monitor/monitor.conf   # http://127.0.0.1:9091（非 secret 值）
```

### P2-3 dashboard = loopback 127.0.0.1:9191

```bash
ss -lntp | grep ':9191' | tee "$ART/p2-listener-9191.txt"     # 127.0.0.1:9191，属主 PID == $MPID
grep -E '^SBMON_WEB_BIND=|^SBMON_MODE=' /etc/singbox-monitor/monitor.conf
# 外部视角复核（仅批准窗口）：对公网 IP 的 TCP 9191 探测期望 closed/filtered
```

### P2-4 /api/v1/session 语义检查（rev2：R1.1 最小稳定形状）

```bash
curl -fsS http://127.0.0.1:9191/api/v1/session | jq -e '
  (.authenticated     | type == "boolean") and
  (.whitelist_allowed | type == "boolean") and
  ((.version // "")   | length > 0) and
  ((has("password_configured") | not) or (.password_configured | type == "boolean")) and
  ((has("recovery_configured") | not) or (.recovery_configured | type == "boolean")) and
  ((has("remote_mode")         | not) or (.remote_mode         | type == "boolean"))
' | tee "$ART/p2-session-check.txt"
# 信息性上下文（非门禁）：
curl -fsS http://127.0.0.1:9191/api/v1/session | jq -r '.current_ip // "absent"' \
  | tee -a "$ART/p2-session-check.txt"
```

语义依据（`monitor-v2/web/server.py` 本地逐行核对 + review 确认）：该端点在 IP 白名单门**之后**、登录门**之前**；未登录返回 `authenticated:false`；`whitelist_allowed:true` 表示已通过 socket 对端地址白名单门（`X-Forwarded-For` 永不读取）；登录后响应可能**额外**含 `csrf_token`（本检查不登录，不应出现）。

- **PASS**：三个强制断言（authenticated bool / whitelist_allowed bool / version 非空字符串）为 `true`，且可选字段存在时类型正确；**额外字段（含 csrf_token 等任何未来新增字段）不导致 FAIL**；未登录探针 `authenticated:false`。
- **FAIL**：HTTP 非 200、非 JSON、强制字段缺失/类型错误，或 404/401/500（端口上不是 dashboard）→ 停止。`current_ip` 缺失/异常**不构成 FAIL**（仅信息性记录）。
- **artifacts**：`$ART/p2-session-check.txt`。

### P2-5 broker / collector 健康

```bash
bash /root/canary-src/monitor-v2/deploy/install-monitor.sh health | tee "$ART/p2-health.json"
RC_HEALTH=${PIPESTATUS[0]}    # rev2.3：生产者退出码（0=healthy / 2=degraded / 1=unhealthy）；tee 不得掩码
printf 'health rc=%s\n' "$RC_HEALTH" | tee -a "$ART/p2-health.json"
```

判定（`monitor-health` 语义，web 模式）：`overall == "healthy"`（生产者退出码 `RC_HEALTH=0`）；`api_reachable` 且 `api_url_valid`；`broker_health`：`present/wellformed/consumer_alive == true`、`age_stale/collector_stale/stale == false`（窗口 `ceil(5×poll+15)` 秒）；`web_http == "ok"`。

- **FAIL**：`degraded`（`RC_HEALTH=2`）→ 停 P3，`journalctl -u singbox-monitor -n 100 --no-pager` 取证；`unhealthy`（`RC_HEALTH=1`）→ 停止。
- **artifacts**：`$ART/p2-health.json`、`$ART/p2-journal-tail.txt`。

### P2-6 One Collector / One SnapshotBroker / One service.api consumer

```bash
pgrep -fa 'webapp\.py serve' | tee "$ART/p2-singleton.txt"
[ "$(pgrep -fc 'webapp\.py serve')" = "1" ] || { echo 'FAIL: webapp 进程数 != 1'; exit 1; }
ss -ntp 'dport = :9091' | grep -c "pid=$MPID," | tee -a "$ART/p2-singleton.txt"   # 期望 1（精确 PID）
```

- **PASS**：两计数均为 1。**FAIL**：计数 ≠ 1（且不在 P3 明示窗口）→ 停止；处置仅限 `systemctl restart singbox-monitor`，禁止按名/宽泛 kill。
- **artifacts**：`$ART/p2-singleton.txt`。

### P2-7 journal 泄漏门禁（rev2.3：内存态 Python 精确已知敏感值扫描器，private-key 三层检测；退出码经 PIPESTATUS[0] 捕获）

原理：Python（标准库，root 身份，短命进程）在**内存中**收集已知敏感值字面量——live 配置（`/root/sbox/sbconfig_server.json`）中所有 `uuid`（Reality 凭据值）/ `password`（HY2 password）/ `private_key`（Reality）/ `secret`（service.api secret）字符串值，以及根锚点文件 `/root/sbox/monitor-api.secret`，对 `$T0` 以来两个单元的 journal 区间做**完整文本子串计数**，输出**固定四类别聚合计数**。

**private-key 三层检测**（多行 Reality 私钥在日志中可能逐行拆分 / 归一化 / JSON 转义渲染，单一全值扫描不足以覆盖）：

1. **完整非空 `private_key` 值**（覆盖原样出现）；
2. 完整值的 **JSON 转义表示**（`json.dumps(value)[1:-1]`，覆盖 `\n` 转义渲染；与原值相同时不重复加入）；
3. **逐行 key material**：按行 split → strip → 忽略空行 → 忽略 `-----BEGIN …-----` / `-----END …-----` 等 formatting-only 行 → 保留真实密钥材料行（覆盖逐行拆分/归一化渲染）。

其余类别（service.api secret、Reality UUID、HY2 password）保持**精确全值**扫描不变。通用形状扫描（`vless://`/`hysteria2://`/UUID 形状等）如操作员另行执行，仅作信息性记录，不参与判定。

```bash
umask 077
python3 - "$T0" <<'PYEOF' | tee "$ART/p2-journal-scan.txt"
import json, subprocess, sys

T0 = sys.argv[1]

# B6 时间兼容：journalctl --since 绝不接收 raw RFC3339（"...T...Z"）。
# 输入非法时 fail-closed（绝不用错误时间窗静默扫描）。
from datetime import datetime, timezone

def normalize_journal_since(ts):
    text = ts.strip()
    if "T" not in text and "Z" not in text:
        datetime.strptime(text, "%Y-%m-%d %H:%M:%S")   # 已规范化形态：严格校验后透传
        return text
    iso = text[:-1] + "+00:00" if text[-1] in ("Z", "z") else text
    dt = datetime.fromisoformat(iso)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")

J0 = normalize_journal_since(T0)
CFG = "/root/sbox/sbconfig_server.json"
SECRET_FILE = "/root/sbox/monitor-api.secret"
UNITS = ("singbox-monitor", "sing-box")

CATS = ("service_api_secret", "reality_uuid", "hy2_password", "reality_private_key")
literals = {c: set() for c in CATS}   # 敏感值仅存在于本进程内存；空字符串永不成为模式

def add(cat, value):
    if isinstance(value, str) and value.strip():
        literals[cat].add(value)

def walk(node):
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(v, str):
                if k == "secret":
                    add("service_api_secret", v)
                elif k == "uuid":
                    add("reality_uuid", v)
                elif k == "password":
                    add("hy2_password", v)
                elif k == "private_key":
                    # (1) 完整非空值
                    add("reality_private_key", v)
                    # (2) JSON 转义表示（覆盖转义渲染；与原值相同则不重复）
                    esc = json.dumps(v)[1:-1]
                    if esc != v:
                        add("reality_private_key", esc)
                    # (3) 逐行 key material（覆盖逐行拆分/归一化渲染）：
                    #     strip -> 忽略空行 -> 忽略 PEM BEGIN/END 等 formatting-only 行
                    for line in v.splitlines():
                        t = line.strip()
                        if not t:
                            continue
                        u = t.upper()
                        if u.startswith("-----BEGIN") or u.startswith("-----END"):
                            continue
                        add("reality_private_key", t)
            walk(v)
    elif isinstance(node, list):
        for item in node:
            walk(item)

with open(CFG, "r", encoding="utf-8") as f:
    walk(json.load(f))
try:
    with open(SECRET_FILE, "r", encoding="utf-8") as f:
        add("service_api_secret", f.read().strip())
except FileNotFoundError:
    pass

# fail closed：预期存在敏感材料的类别一个字面量都没收集到 -> 绝不静默通过
missing = [c for c in CATS if not literals[c]]
if missing:
    print("scanner: no sensitive material collected for: " + ",".join(missing) + " -> FAIL")
    sys.exit(1)

fail = False
for unit in UNITS:
    try:
        text = subprocess.run(
            ["journalctl", "-u", unit, "--since", J0, "--no-pager", "-o", "cat"],
            capture_output=True, text=True, check=True).stdout
    except subprocess.CalledProcessError as e:
        print(f"{unit}: journalctl failed rc={e.returncode}")
        sys.exit(1)
    counts = {c: sum(text.count(v) for v in literals[c]) for c in CATS}
    print(f"{unit}: service_api_secret_matches={counts['service_api_secret']}"
          f" reality_uuid_matches={counts['reality_uuid']}"
          f" hy2_password_matches={counts['hy2_password']}"
          f" reality_private_key_matches={counts['reality_private_key']}")
    fail = fail or any(counts.values())

sys.exit(1 if fail else 0)
PYEOF
SCAN_RC=${PIPESTATUS[0]}   # rev2.3：生产者（python 扫描器）退出码，而非 tee 的
printf 'scanner rc=%s\n' "$SCAN_RC" | tee -a "$ART/p2-journal-scan.txt"
```

计数语义说明：完整值命中与其组成行命中在"原样出现"场景下会**重复计数**——对本门禁（判定条件 = 任一类别 >0）这是**保守方向**（宁可多报），不构成误判风险。

- **PASS**：两单元四个类别计数全部为 0（`service_api_secret_matches=0 reality_uuid_matches=0 hy2_password_matches=0 reality_private_key_matches=0`）且 `scanner rc=0`。
- **FAIL / STOP**：任一类别计数 > 0、任一预期类别收集不到敏感材料（fail-closed）、或 scanner 非零退出 → 停止 canary，journal 全量封存（`journalctl -u <u> --since "$J0" > $ART/journal-<u>.log`，0600；B6：`--since` 只用规范化后的 `$J0`，绝不传 raw `$T0`）人工分析。
- **卫生（不变）**：标准库 Python、短命、内存态（敏感值仅存在于扫描器进程内存，进程退出即消失）、**零 secret 落盘临时文件**、argv 零 secret 值、无 xtrace、journal 限当前 canary 区间（`--since "$J0"`，由 fail-closed 的规范化从 RFC3339/UTC 的 T0 派生）；空字符串永不成为扫描模式。
- **artifacts**：`$ART/p2-journal-scan.txt`（只有四类别计数与 rc；绝不打印 secret 值 / private-key 材料 / 命中行 / 命中子串）。

---

## 5. P3 — Identity validation（rev2：严格作用域双 canary 证明身份）

rev2 取消的两个**无效不变量**（不得再作为门禁）："设备键零 IPv4 形状"（合法用户名可形似 IP）、"协议键 ⊆ {vless-in, hy2-in}"（生产可合法含 `direct-in`/`ss-in` 等）。Source IP 是 metadata 来自**实现契约**（`monitor-v2/README.md`：`Source IP = metadata（仅展示，绝不作为身份）`），与设备名外观无关。

### P3-0 快照结构健全性（轻量探针，瞬时第二个 consumer 窗口开启）

```bash
WEBAPP_DIR=$(tr '\0' '\n' < /proc/$MPID/cmdline | grep -m1 'webapp\.py' | xargs dirname)
# rev2.3：webapp.py 与 collector.py 部署在同一目录（release 树 app/monitor-v2/）——同目录引用；
#          等价替代 = 冻结 checkout 的 /root/canary-src/monitor-v2/collector.py
python3 "$WEBAPP_DIR/collector.py" --url http://127.0.0.1:9091 \
  --secret-file /etc/singbox-monitor/api.secret --once --pretty > "$ART/p3-collector-once.json"
jq -e '.stale == false and (.identity_conflicts // 0) == 0' "$ART/p3-collector-once.json" >/dev/null \
  || { echo 'FAIL: 探针 stale 或 identity_conflicts>0'; exit 1; }
# 结构投影检查（信息性记录）：connections[] 每行携带 id（lifecycle 键）与 user / inbound（不可变字段）
jq -r '[.connections[]? | has("id") and has("user") and has("inbound")] | all' \
  "$ART/p3-collector-once.json" | tee "$ART/p3-structure.txt"
```

- **PASS**：`stale == false` 且 `identity_conflicts == 0`（HIGH guard）；connections 行携带 `id`/`user`/`inbound` 字段。
- **FAIL**：stale 或 identity_conflicts > 0 → 停止，保留快照取证。
- **不判定**（明确移除）：设备键外观、协议键集合范围。

### P3-1 strict canary 的受控鉴权（rev2.1：逐命令临时环境赋值，不改冻结代码）

事实：`tests/monitor-v2-integration-e1.sh` 不向 `collector.py` 传 `--secret-file`；collector 鉴权来自 `BOX_API_SECRET` 环境变量或 `--secret-file` 参数。生产 service.api 有鉴权 ⇒ strict canary 必须显式供给鉴权。**受控手动例外**（临时手动测试环境，与生产 `singbox-monitor.service` 契约——文件传递 + 显式 `env -u BOX_API_SECRET`——明确区分开）：

```bash
# —— 前置：确认 xtrace OFF（每个窗口读取 secret 之前各自检查）——
[ -o xtrace ] && { echo 'FAIL: xtrace/set -x must be OFF before reading the secret'; exit 1; }
set +x    # 防御性关闭；不产生输出
set -o pipefail   # 使 $? 反映脚本真实退出码，而非 tee

# —— Reality 窗口：逐命令临时环境赋值（值仅进入本次子进程，父 shell 不保留）——
BOX_API_SECRET="$(cat /etc/singbox-monitor/api.secret)" \
EXPECT_USER='<device>' \
EXPECT_INBOUND='vless-in' \
REQUIRE_CLOSED=1 \
LIFECYCLE_WINDOW=30 \
bash tests/monitor-v2-integration-e1.sh 2>&1 | tee "$ART/p3-reality.log"
RC_REALITY=${PIPESTATUS[0]}   # rev2.3：显式捕获生产者退出码（pipefail 之外的第二层明确性）
printf 'reality canary rc=%s\n' "$RC_REALITY" | tee -a "$ART/p3-reality.log"

# —— HY2 窗口：同样逐命令赋值，退出码独立捕获 ——
BOX_API_SECRET="$(cat /etc/singbox-monitor/api.secret)" \
EXPECT_USER='<device>' \
EXPECT_INBOUND='hy2-in' \
REQUIRE_CLOSED=1 \
LIFECYCLE_WINDOW=30 \
bash tests/monitor-v2-integration-e1.sh 2>&1 | tee "$ART/p3-hy2.log"
RC_HY2=${PIPESTATUS[0]}      # rev2.3：显式捕获生产者退出码（pipefail 之外的第二层明确性）
printf 'hy2 canary rc=%s\n' "$RC_HY2" | tee -a "$ART/p3-hy2.log"

# —— 父 shell 无残留确认（rev2.1：取代 rev2 的 export + unset 方案）——
[ -z "${BOX_API_SECRET:-}" ] && echo 'BOX_API_SECRET: not present in parent shell'
```

**窗口纪律**：`<device>` 为现网真实逻辑设备名（如 `legacy`，与 P0-8 确认一致；名字不同只改环境变量值，不改脚本）；两窗口内存在瞬时第二个 service.api consumer（B4 受控例外）；**读取 secret 前必须 `[ -o xtrace ]` 确认 OFF**（xtrace 展开会把 `BOX_API_SECRET=…` 赋值行打上终端/journal）；**绝不 `set -x` / `echo "$BOX_API_SECRET"` / 把值写进任何文件、unit、history**；值经 `VAR=val cmd` 前缀赋值只进入该次子进程的 environment，**不出现在 argv**（`ps` 默认不可见）、**不进入父 shell**（无需 unset——根本没有赋值发生）；两个退出码 `RC_REALITY` / `RC_HY2` 独立捕获、独立记录（`pipefail` + `${PIPESTATUS[0]}` 双保险，tee 不可能掩码脚本 rc）。

**等价备选（若操作员偏好显式子壳）**：不改冻结代码的等价安全法是包装子壳——`bash -c 'set +x; exec env BOX_API_SECRET="$(cat /etc/singbox-monitor/api.secret)" bash tests/monitor-v2-integration-e1.sh'`（`export`/`env` 赋值被限制在该子壳进程内，交互父 shell 同样零残留），窗口纪律与上述完全一致。`--secret-file` 路线需要改测试脚本（传参透传），**明确不采用**（不改冻结 runtime/test 代码）。

### P3-2 canary 硬门槛语义（脚本内置，非人工判断）

- 流量 delta 与 CLOSED delta 全部限定到 `EXPECT_USER` × `EXPECT_INBOUND` 作用域；同一 USER 的兄弟协议增长**不能**替另一协议过关 —— 这正是身份证明：**Device = 精确 API USER，Protocol = 精确 inbound tag，lifecycle 证据绑定 `Connection.id`**。
- `REQUIRE_CLOSED=1`：必须出现 baseline 之外的新关闭 ID（`active_connections > 0` 永远不构成关闭证据）。
- 判定由 `monitor-v2/lifecycle_gate.py` 完成；退出码 PASS=0 / FAIL=1 / INCONCLUSIVE=2（**INCONCLUSIVE 永远不算 PASS**）。
- baseline == final = FAIL（脚本先取 baseline 并提示 "Start client traffic NOW"；流量由操作员用真实客户端生成）。

### P3 门禁

- **PASS 条件**：P3-0 断言 true；Reality（`vless-in`）与 HY2（`hy2-in`）两条 strict canary 均 PASS（`RC_REALITY=0` 且 `RC_HY2=0`，独立捕获）；窗口后 §P2-6 复检回到单例（1/1）；父 shell 确认无 `BOX_API_SECRET` 残留。
- **FAIL 条件**：任一 canary FAIL(1)/INCONCLUSIVE(2)；P3-0 失败；窗口后单例不复位；读取 secret 时 xtrace 为 ON；或发现任何泄漏窗口纪律违规（echo/argv/persist/父 shell 残留）。
- **STOP 动作**：停止 canary；保留 `$ART/p3-*`；monitor 处置仅限 `systemctl restart singbox-monitor`；**绝不触碰 sing-box**。
- **artifacts**：`$ART/p3-collector-once.json`、`$ART/p3-structure.txt`、`$ART/p3-reality.log`、`$ART/p3-hy2.log`、`$ART/p2-singleton.txt`（复检）。

---

## 6. P4 — Isolation verification（rev2：不变量集合证明，非单一 PID 证明）

```bash
# (1) proxy/config 哈希 == P0 基线（字节级）
sha256sum /root/sbox/sbconfig_server.json /root/sbox/config > "$ART/p4-hash-after.txt"
diff "$ART/p0-hash-before.txt" "$ART/p4-hash-after.txt" && echo 'HASH: IDENTICAL' || echo 'FAIL: HASH DRIFT'

# (2) sing-box 生命周期不变量集合（rev2：PID + NRestarts + 单调时钟 + 状态）
systemctl show sing-box -p MainPID -p NRestarts -p ExecMainStartTimestampMonotonic -p ActiveState -p SubState \
  > "$ART/p4-singbox-lifecycle.txt"
diff "$ART/p0-singbox-lifecycle.txt" "$ART/p4-singbox-lifecycle.txt" \
  && echo 'LIFECYCLE INVARIANTS: UNCHANGED' || echo 'FAIL: LIFECYCLE INVARIANT CHANGED'
tr '\0' ' ' < /proc/$SBPID/cmdline | diff - "$ART/p0-singbox-cmdline.txt" && echo 'CMDLINE: IDENTICAL'   # rev2.3：基线 artifact 仅含 cmdline，同类逐字节比较

# (3) sing-box journal：窗口内无任何生命周期操作痕迹
journalctl -u sing-box --since "$J0" --no-pager \
  | grep -Ei 'starting sing-box|shutting down|signal|restart|reload|config file|restarted' \
  | tee "$ART/p4-singbox-journal-lifecycle.txt"      # 期望空文件

# (4) 监听器清单 == P0 基线（新增行只允许 127.0.0.1:9191）
ss -lntup > "$ART/p4-listeners.txt"; diff "$ART/p0-listeners.txt" "$ART/p4-listeners.txt" | tee "$ART/p4-listener-diff.txt"

# (5) 9191 仍仅回环
grep -E '0\.0\.0\.0:9191|\[::\]:9191' "$ART/p4-listeners.txt" && echo 'FAIL: 9191 NOT LOOPBACK-ONLY' || echo '9191: LOOPBACK-ONLY'

# (6) 生产备份集合只增不减
find /root/sbox -maxdepth 1 -name '*.bak.*' -printf '%f\n' | sort > "$ART/p4-backups-after.txt"   # rev2.3：与 p0-backups-before.txt 同构（仅 basename、已排序）
comm -23 "$ART/p0-backups-before.txt" "$ART/p4-backups-after.txt" | grep . \
  && echo 'FAIL: 生产备份文件减少' || echo 'BACKUPS: SUPERSET-OR-EQUAL'
```

- **PASS 条件**：哈希逐字节一致；lifecycle 不变量集合（MainPID / NRestarts / `ExecMainStartTimestampMonotonic` / ActiveState/SubState / cmdline）逐项一致；lifecycle journal 窗口为空；监听器 diff 为空或仅 `+127.0.0.1:9191`；`9191` 仅回环；备份集合 ⊇ 基线。结合 Packaging 既有不变量（Packaging 代码从不调用 sing-box 生命周期操作，Round 0/1 静态断言覆盖），report 措辞为：**"no evidence of restart/reload; all lifecycle/config invariants unchanged"**。
- **FAIL 条件**：任一哈希漂移、任一 lifecycle 不变量变化、journal 非空、`9191` 非回环、备份减少 —— **isolation breach**。
- **STOP 动作**：立即停止封存；sing-box 被意外扰动时**不自行修复**，按 Phase C 双回滚备份人工恢复另案处理。
- **artifacts**：`$ART/p4-hash-after.txt`、`$ART/p4-singbox-lifecycle.txt`、`$ART/p4-singbox-journal-lifecycle.txt`、`$ART/p4-listeners.txt`、`$ART/p4-listener-diff.txt`、`$ART/p4-backups-after.txt`。

---

## 7. P5 — Monitor rollback drill（rev2：条件性）

| 前提（来自 P0-3/P0-6） | P5 判定 |
| --- | --- |
| 存在既往**成功保留**的 monitor release（`history` 有成功提交且目录仍在，或 upgrade 前 live release 仍在） | **REQUIRED**：执行 drill |
| fresh 首装，无任何既往成功 release | **NOT APPLICABLE**：不执行，也**绝不**为测试回滚而人为制造第二个生产 release（事务回滚行为已由 Linux CI 全绿覆盖） |

### REQUIRED 路径

```bash
cd /root/canary-src
bash monitor-v2/deploy/install-monitor.sh history | tee "$ART/p5-history-before.txt"
bash monitor-v2/deploy/install-monitor.sh rollback | tee "$ART/p5-rollback.log"   # 或 rollback <release-id>
RC_ROLLBACK=${PIPESTATUS[0]}    # rev2.3：生产者退出码；tee 不得掩码
printf 'rollback rc=%s\n' "$RC_ROLLBACK" | tee -a "$ART/p5-rollback.log"
bash monitor-v2/deploy/install-monitor.sh status  | tee "$ART/p5-status-after.txt"
bash monitor-v2/deploy/install-monitor.sh health  | tee "$ART/p5-health-after.json"
```

回滚语义（冻结 head 实现）：只翻转 `/opt/singbox-monitor` symlink + 仅重启 `singbox-monitor`；原 active/enabled 状态一并恢复；失败自动恢复原 release，恢复再失败 = CRITICAL（exit 2）；成功才写 history（`rollback` 动作）。

### 验证（REQUIRED 路径）

```bash
# (a) 旧 monitor 已恢复：status 的 release id/version == drill 前一版
# (b) health overall == healthy（退出码 0）
# (c) 单例复位：§P2-6 两断言再过（MPID 重新取值 —— monitor 重启是预期内事件）
# (d) sing-box 不变量集合仍一致：
diff "$ART/p0-singbox-lifecycle.txt" <(systemctl show sing-box -p MainPID -p NRestarts -p ExecMainStartTimestampMonotonic -p ActiveState -p SubState) \
  && echo 'LIFECYCLE: STILL UNCHANGED'
diff "$ART/p0-hash-before.txt" <(sha256sum /root/sbox/sbconfig_server.json /root/sbox/config) && echo 'HASH: STILL IDENTICAL'
```

- **PASS 条件（REQUIRED）**：release 回到目标旧版；health == healthy；单例复位；sing-box 不变量集合与哈希不变。
- **NOT APPLICABLE 路径**：report 中记录 `rollback drill: NOT APPLICABLE (fresh install, no previous successful release; transactional rollback covered by Linux CI)`，无需任何命令。
- **FAIL 条件（REQUIRED）**：CRITICAL 退出（`RC_ROLLBACK != 0`）/ health degraded / sing-box 不变量变化。
- **STOP 动作**：保留 `$ART/p5-*`；monitor 侧仅限再次 `rollback` 或 `install --repair`；**绝不**以"顺手重启 sing-box"排障。
- **artifacts**：`$ART/p5-*`（NOT APPLICABLE 时仅在 report 记录判定依据）。

> 备注：REQUIRED 路径 drill 完成后可选择 `upgrade` 把 monitor 送回 `$FROZEN` 对应版本（monitor-only，重复 P1/P2 门禁）；report 必须如实记录 drill 净终态。

---

## 8. Exact PASS/FAIL matrix（rev2.3）

| Phase | 检查项 | PASS 条件 | FAIL 条件 | STOP 动作 | 必留 artifacts |
| --- | --- | --- | --- | --- | --- |
| P0-1 | checkout==`$FROZEN` 且干净 | SHA 逐字符相等 + `status --porcelain` 空 | SHA 不符/脏工作区 | 人工核对，禁止继续 | `p0-checkout.txt` |
| P0-2 | sing-box 进程身份 + 生命周期基线 | MainPID 有效；cmdline == `/root/sbox/sing-box … -c sbconfig_server.json`；NRestarts/monotonic 基线已录 | cmdline 漂移/手工进程 | 停止，先恢复 systemd 托管形态 | `p0-singbox-cmdline.txt` `p0-singbox-process.txt` `p0-singbox-lifecycle.txt` |
| P0-3 | 服务状态 + 分支判定 | sing-box active+enabled；fresh/upgrade 分支与 P5 条件（REQUIRED/NA）已定 | sing-box 非 active | 停止 | `p0-service-state.txt` |
| P0-4 | 监听器基线 | 9091 仅回环；无非回环 9191 | 9091 非回环 / 9191 非回环占用 | 停止（安全前提不成立） | `p0-listeners.txt` |
| P0-5 | 哈希基线 | 两文件哈希已记录 | 文件缺失 | 停止 | `p0-hash-before.txt` |
| P0-6 | monitor 现状 | status 可读 | 脚本缺失/布局不完整 | 停止，回 P0-1 | `p0-monitor-status.txt` |
| P0-7 | 生产备份在位 | 清单已记录 | —（记录型） | — | `p0-backups-before.txt` |
| P0-8 | secret 锚点 | 根锚点 root:root 0600 非空；`monitor-api` service 条目唯一且 secret 非空；派生一致 | 锚点缺失/0600 违例/secret 空/`monitor-api` 条目缺失或重复 | 停止（S0 基线不成立） | `p0-anchors.txt` |
| P1（fresh） | `install --no-start` + 离线验证 + 显式 start | `RC_INSTALL=0`（PIPESTATUS[0]）；release 树/symlink/unit/monitor.conf/派生 secret 就位；**9191 尚未监听**；sing-box 哈希/PID 在 start 前不变；start 后 active 且**非 enabled** | 任一离线验证不符；提前监听；enable 发生 | 停止取证，禁止手工修补 | `p1-install.log` `p1-releases.txt` |
| P1（已有部署） | upgrade | `RC_INSTALL=0`（PIPESTATUS[0]）；release 激活；health 可执行 | CRITICAL / 回滚后未恢复 | 停止，`status`+`history` 取证 | `p1-install.log` `p1-status.txt` `p1-health.json` `p1-history.txt` |
| P2-1 | 服务身份 sboxweb | 属主 sboxweb；cmdline=webapp serve 回环 + `--secret-file`（无 secret 值） | 身份/绑定/argv 违例 | 停止，journal 取证 | `p2-monitor-cmdline.txt` |
| P2-2/3 | 9091/9191 回环 | 9091=sing-box、9191=monitor 且均 127.0.0.1 | 任一非回环 | 停止 | `p2-listener-*.txt` |
| P2-4 | `/api/v1/session`（R1.1 最小形状） | 200；authenticated/whitelist_allowed 为 bool、version 非空；可选字段存在时类型正确；**额外字段不 FAIL** | 强制字段缺失/类型错；非 200/404/401/500 | 停止 | `p2-session-check.txt` |
| P2-5 | broker/collector 健康 | overall=healthy；broker_health 布尔正确 | degraded→取证；unhealthy→停止 | degraded 停 P3；unhealthy 停 canary | `p2-health.json` `p2-journal-tail.txt` |
| P2-6 | 三单例 | webapp==1；9091 ESTAB 属主 $MPID==1 | 计数≠1（非 P3 窗口） | 仅允许 `systemctl restart singbox-monitor` | `p2-singleton.txt` |
| P2-7 | journal 泄漏（内存态精确值硬门禁，private-key 三层检测） | 双单元四类别计数全 0（`service_api_secret_matches/reality_uuid_matches/hy2_password_matches/reality_private_key_matches`）且 scanner rc=0；private_key = 全值 + JSON 转义 + 逐行 key material 三层覆盖；空模式不可能产生；缺料 fail-closed；**零 secret 落盘** | 任一类别计数>0 / 预期材料缺失 / scanner 非零 | FAIL + STOP；journal 封存（0600）人工分析 | `p2-journal-scan.txt`（仅四类别计数与 rc） |
| P3-0 | 快照结构健全性 | stale=false；identity_conflicts=0；行含 id/user/inbound | stale / identity_conflicts>0 | 停止，快照取证 | `p3-collector-once.json` `p3-structure.txt` |
| P3-1/2 | strict 双 canary（逐命令临时环境窗口） | `RC_REALITY=0` 且 `RC_HY2=0`（独立捕获，pipefail + PIPESTATUS[0]）；读取 secret 前 xtrace 确认 OFF；窗口纪律无违规；父 shell 无 `BOX_API_SECRET` 残留 | FAIL(1)/INCONCLUSIVE(2)/xtrace ON/纪律违规/父 shell 残留 | 停止，保留 p3 日志；处置仅限 restart monitor | `p3-reality.log` `p3-hy2.log` |
| P3-收尾 | 窗口后单例复位 | §P2-6 复检 1/1 | 不复位 | 停止 | `p2-singleton.txt`（复检） |
| P4 | 隔离证明（不变量集合） | 哈希一致；MainPID/NRestarts/monotonic/cmdline/journal-lifecycle/监听 diff/备份超集全过；措辞 = "no evidence of restart/reload; all lifecycle/config invariants unchanged" | 任一不变量变化（breach） | 立即停止封存；不自行修复 sing-box | `p4-*` |
| P5 | 回滚 drill（条件性） | REQUIRED：旧 release 恢复 + healthy + 单例复位 + sing-box 不变量不变。NOT APPLICABLE：fresh 且无既往 release（如实记录，不制造 release） | `RC_ROLLBACK≠0` / degraded / sing-box 变化 | 保留 `p5-*`；monitor 侧仅限再次 rollback / `install --repair` | `p5-*` / report 记录 |

全局规则：**INCONCLUSIVE ≠ PASS**；任一阶段 FAIL 不得跳入下一阶段；重试仅对 P1（脚本事务性重试）合法。

---

## 9. Risk table（rev2.3）

| # | 风险 | 概率 | 影响 | 缓解 | 残留 |
| --- | --- | --- | --- | --- | --- |
| R1 | monitor 进程故障/崩溃 | 低 | 无代理影响（仅监控面） | shim fail-closed + systemd；处置仅限 `systemctl restart singbox-monitor` | 无 |
| R2 | `sbmon_sync_api_secret` 与根锚点漂移 | 低 | monitor 拒绝启动（fail-closed，好事） | P0-8 预检；install/upgrade 自带修复 | 无 |
| R3 | upgrade 期间 monitor 短暂中断 | 确定（秒级） | 无代理影响 | 单锁事务 + 自动回滚；history 只记健康提交 | 秒级监控盲区 |
| R4 | E1 canary 窗口第二个 service.api consumer | 确定（设计内） | 轻微：额外一条 gRPC 流 | 仅限 P3 窗口；窗口前后强制单例复检（B4） | 无 |
| R5 | service.api 被高频订阅拖累 | 低 | 理论上影响 sing-box 资源 | 常驻 1 条订阅（窗口内 2 条瞬时）；官方流空闲零流量 | 无 |
| R6 | journal 泄漏凭据 | 低 | 凭据暴露 | P2-7 内存态 Python 精确已知敏感值硬门禁（四类别聚合计数，不打印值/命中行/子串；private_key 三层覆盖：全值 + JSON 转义 + 逐行 key material；空模式零误报；缺料 fail-closed）+ shim 端 secret 永不入 argv/env/journal；形状扫描仅信息性 | 扫描依赖敏感值按键名收集的配置形状（B3）；重复计数方向保守（宁可多报） |
| R7 | 9191 误暴露公网 | 低 | 管理面暴露 | 默认绑定 fail-closed（remote 四项缺一拒启）；P0-4/P4-5 双向断言；fresh 路径 start 前 9191 必须未监听 | 无 |
| R8 | fresh 首装 enable 遗留 | 低 | 服务随开机自启（超出 canary 审批） | P1-3 显式 start、**禁 enable**；`is-enabled` 断言非 enabled；永久 enable 为 canary 后独立审批 | 无 |
| R9 | 操作员误执行 sing-box 生命周期命令 | 低 | **代理中断**（高危） | §0.2 禁令；P4 以不变量集合反向证明；runbook 命令均不触及 | 依赖纪律 + P4 审计 |
| R10 | VPS 实况与假设不符（B2/B3） | 中 | 门禁 FAIL（提前停止） | P0 全量预检 FAIL-fast | 无（设计即停） |
| R11（rev2.1） | canary 子进程环境内含 secret（逐命令临时赋值） | 确定（设计内、有界、单命令生命周期） | 子进程存续期间环境含 secret | 值仅经 `BOX_API_SECRET=… cmd` 逐命令赋值进入该次子进程（冻结代码官方鉴权通道）；**绝不进入父 shell**；读取前强制 xtrace OFF；不 echo、不进 argv、不持久化；Reality/HY2 退出码独立捕获（pipefail）；与生产 service 文件传递 + `env -u` 契约严格区分 | 子进程存续期间的环境内存驻留（秒级、单管理员 SSH 会话内，可接受） |
| R12（rev2.2） | 扫描器进程内存中驻留敏感值 | 确定（P2-7 期间） | 内存态敏感值集合 | 敏感值仅存在于 Python 扫描器进程内存（标准库、root、短命），进程退出即消失；**零落盘临时文件**（grep -F -f 模式文件方案已废除）；只输出四类别聚合计数，绝不打印值/命中行/子串；预期类别缺料时 fail-closed | 无磁盘残留；仅进程内存（秒级） |
| R13（rev2.3） | tee 掩码生产者退出码导致 FAIL 误判为 PASS | 低 | 门禁误判（假 PASS，直接威胁判定可信度） | 会话全局 `set -o pipefail` + 全部门禁管道（install/upgrade、health、journal 扫描器、E1 canary、rollback）显式 `${PIPESTATUS[0]}` 捕获 | 无 |

---

## 10. 为最终获批 canary 提议的命令清单（rev2.3 汇总）

> 以下为**将来获批后**的执行序列；今日不执行（READ-ONLY 文档交付）。判定一律以 §8 矩阵为准。

```bash
# —— 会话准备 ——
set -o pipefail   # rev2.3：全局启用；门禁管道另显式捕获 PIPESTATUS[0]
export FROZEN=3ee9a162a3fb53d9fddc95cb6eba95b3bcc5702e
export ART=/root/canary-artifacts-$(date -u +%Y%m%dT%H%M%SZ); mkdir -m 0700 -p "$ART"
export T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)   # 内部时间戳恒为 RFC3339/UTC；journalctl --since 只用 $J0（见 §1 B6 规则）
journal_time_normalize_jctl() { python3 - "$1" <<'PYEOF'
import sys
from datetime import datetime, timezone
raw = (sys.argv[1] if len(sys.argv) > 1 else "").strip()
if not raw:
    print("journal-time: empty timestamp", file=sys.stderr); sys.exit(1)
if "T" not in raw and "Z" not in raw:
    try: datetime.strptime(raw, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        print(f"journal-time: not a valid timestamp: {raw!r}", file=sys.stderr); sys.exit(1)
    print(raw); sys.exit(0)
iso = raw[:-1] + "+00:00" if raw[-1] in ("Z", "z") else raw
try: dt = datetime.fromisoformat(iso)
except ValueError:
    print(f"journal-time: not a valid RFC3339 timestamp: {raw!r}", file=sys.stderr); sys.exit(1)
if dt.tzinfo is None:
    dt = dt.replace(tzinfo=timezone.utc)
print(dt.astimezone().strftime("%Y-%m-%d %H:%M:%S"))
PYEOF
}
export J0="$(journal_time_normalize_jctl "$T0")"

# —— P0 preflight ——
git clone https://github.com/yikkrrtykj/install-singboxhysteria2 /root/canary-src
cd /root/canary-src && git checkout --detach "$FROZEN"
git rev-parse HEAD; git status --porcelain
# （checkout 后可 `source tests/lib/journal-time.sh` 获得与回归测试一致的规范实现）
SBPID=$(systemctl show -p MainPID --value sing-box); tr '\0' ' ' < /proc/$SBPID/cmdline
systemctl show sing-box -p MainPID -p NRestarts -p ExecMainStartTimestampMonotonic -p ActiveState -p SubState
systemctl is-active sing-box; systemctl is-enabled sing-box
ss -lntup > "$ART/p0-listeners.txt"
sha256sum /root/sbox/sbconfig_server.json /root/sbox/config | tee "$ART/p0-hash-before.txt"
find /root/sbox -maxdepth 1 -name '*.bak.*' -printf '%f\n' | sort | tee "$ART/p0-backups-before.txt"; find /root/sbox -maxdepth 1 -name '*.bak.*' -printf '%f %s %TY-%Tm-%Td\n' | sort | tee "$ART/p0-backups-info.txt"
stat -c '%U %G %a %s' /root/sbox/monitor-api.secret
jq -e '[.services[]? | select(.tag? == "monitor-api" and .type? == "api" and .listen? == "127.0.0.1" and .listen_port? == 9091)] | length == 1' /root/sbox/sbconfig_server.json
jq -e '[.services[]? | select(.tag? == "monitor-api" and .type? == "api" and .listen? == "127.0.0.1" and .listen_port? == 9091 and ((.secret? // "") | length > 0))] | length == 1' /root/sbox/sbconfig_server.json

# —— P1：分支（fresh vs 已有部署）——
if [ -L /opt/singbox-monitor ] && [ -d /opt/singbox-monitor-releases ]; then
  bash monitor-v2/deploy/install-monitor.sh upgrade
else
  bash monitor-v2/deploy/install-monitor.sh install --no-start
  # 离线验证：release 树 / symlink / unit / monitor.conf / 派生 secret / 9191 未监听 / sing-box 哈希与 PID 不变
  ss -lntp | grep ':9191' || echo '9191: not listening yet'
  diff "$ART/p0-hash-before.txt" <(sha256sum /root/sbox/sbconfig_server.json /root/sbox/config) && echo 'hashes unchanged'
  # （可选）bash monitor-v2/deploy/install-monitor.sh web-setup   # 仅在仍为 inactive 时
  systemctl start singbox-monitor        # 显式 start；绝不 enable
  systemctl is-enabled singbox-monitor   # 期望非 enabled
fi
bash monitor-v2/deploy/install-monitor.sh status; bash monitor-v2/deploy/install-monitor.sh health

# —— P2 runtime validation ——
MPID=$(systemctl show -p MainPID --value singbox-monitor)
ps -o user= -p "$MPID"; tr '\0' ' ' < /proc/$MPID/cmdline
ss -lntp | grep -E ':(9091|9191)'
curl -fsS http://127.0.0.1:9191/api/v1/session | jq -e '(.authenticated|type=="boolean") and (.whitelist_allowed|type=="boolean") and ((.version//"")|length>0) and ((has("password_configured")|not) or (.password_configured|type=="boolean")) and ((has("recovery_configured")|not) or (.recovery_configured|type=="boolean")) and ((has("remote_mode")|not) or (.remote_mode|type=="boolean"))'
bash monitor-v2/deploy/install-monitor.sh health
pgrep -fc 'webapp\.py serve'                    # 期望 1
ss -ntp 'dport = :9091' | grep -c "pid=$MPID,"  # 期望 1
# journal 泄漏门禁（§P2-7 原文：内存态 Python 精确已知敏感值扫描器；private-key 三层检测
#   = 全值 + JSON 转义 + 逐行 key material；固定四类别计数；缺料 fail-closed；零 secret 落盘）

# —— P3 identity validation（逐命令临时环境鉴权窗口）——
WEBAPP_DIR=$(tr '\0' '\n' < /proc/$MPID/cmdline | grep -m1 'webapp\.py' | xargs dirname)
python3 "$WEBAPP_DIR/collector.py" --url http://127.0.0.1:9091 --secret-file /etc/singbox-monitor/api.secret --once --pretty > "$ART/p3-collector-once.json"   # rev2.3：同目录（app/monitor-v2/）；备选 /root/canary-src/monitor-v2/collector.py
jq -e '.stale == false and (.identity_conflicts // 0) == 0' "$ART/p3-collector-once.json"

[ -o xtrace ] && { echo 'FAIL: xtrace must be OFF'; exit 1; }
set +x; set -o pipefail
BOX_API_SECRET="$(cat /etc/singbox-monitor/api.secret)" EXPECT_USER='<device>' EXPECT_INBOUND='vless-in' REQUIRE_CLOSED=1 LIFECYCLE_WINDOW=30 \
  bash tests/monitor-v2-integration-e1.sh 2>&1 | tee "$ART/p3-reality.log"; RC_REALITY=${PIPESTATUS[0]}
printf 'reality rc=%s\n' "$RC_REALITY" | tee -a "$ART/p3-reality.log"
BOX_API_SECRET="$(cat /etc/singbox-monitor/api.secret)" EXPECT_USER='<device>' EXPECT_INBOUND='hy2-in' REQUIRE_CLOSED=1 LIFECYCLE_WINDOW=30 \
  bash tests/monitor-v2-integration-e1.sh 2>&1 | tee "$ART/p3-hy2.log"; RC_HY2=${PIPESTATUS[0]}
printf 'hy2 rc=%s\n' "$RC_HY2" | tee -a "$ART/p3-hy2.log"
[ -z "${BOX_API_SECRET:-}" ] && echo 'BOX_API_SECRET: not present in parent shell'
# 窗口后复检单例（P2-6 两条）

# —— P4 isolation（不变量集合）——
sha256sum /root/sbox/sbconfig_server.json /root/sbox/config | diff - "$ART/p0-hash-before.txt"
systemctl show sing-box -p MainPID -p NRestarts -p ExecMainStartTimestampMonotonic -p ActiveState -p SubState | diff - "$ART/p0-singbox-lifecycle.txt"
journalctl -u sing-box --since "$J0" --no-pager | grep -Ei 'starting|shutting|restart|reload'   # 期望空（B6：--since 只用 $J0）
ss -lntup | diff - "$ART/p0-listeners.txt" || true   # 期望仅 +127.0.0.1:9191
grep -E '0\.0\.0\.0:9191|\[::\]:9191' <(ss -lntp)    # 期望空

# —— P5 rollback drill（条件性）——
# REQUIRED（存在既往成功 release）：
bash monitor-v2/deploy/install-monitor.sh history
bash monitor-v2/deploy/install-monitor.sh rollback
bash monitor-v2/deploy/install-monitor.sh status; bash monitor-v2/deploy/install-monitor.sh health
# NOT APPLICABLE（fresh 首装无既往 release）：跳过，report 记录判定依据；不制造生产 release
# 复检：单例 + sing-box 不变量集合/哈希（同 P4）
```

---

## 11. Final PASS/FAIL report template（P6，canary 执行后填写）

```markdown
# Monitor v2 VPS Canary — Final Report (Round 2, rev2.3)

- date (UTC): <YYYY-MM-DDTHH:MM:SSZ>
- frozen head verified: 3ee9a162a3fb53d9fddc95cb6eba95b3bcc5702e  [PASS/FAIL]
- P0 preflight: <PASS/FAIL>（逐项 P0-1..P0-8，见矩阵）
- P1 install/upgrade: <fresh(--no-start)+explicit start | upgrade | noop> → <PASS/FAIL>
  · release=<id/version> · fresh 离线验证（9191 未提前监听/哈希/PID 不变）=<PASS/FAIL/NA>
  · enabled=<no（首轮 canary 禁 enable）/ n/a（已有部署维持原状）>
- P2 runtime: service identity sboxweb=<Y/N> · 9091 loopback=<Y/N> · 9191 loopback=<Y/N>
  · /api/v1/session minimal contract=<PASS/FAIL>（强制三项；可选字段类型=<ok/absent>；current_ip=<informational>）
  · health overall=<healthy|degraded|unhealthy> · singleton=<Y/N>
  · journal exact-sensitive per unit: service_api_secret_matches=<n> reality_uuid_matches=<n> hy2_password_matches=<n> reality_private_key_matches=<n>
    （in-memory Python scanner rc=<0/1>；private_key 三层：全值/JSON 转义/逐行 key material；缺料 fail-closed；informational shape counts optional）
  · secret-bearing temp files=<none>
- P3 identity: Reality(vless-in) RC_REALITY=<0/1/2> · HY2(hy2-in) RC_HY2=<0/1/2>（独立捕获）
  · Device=API USER（strict 作用域）=<Y/N> · Protocol=inbound tag=<Y/N> · lifecycle evidence=Connection.id=<Y/N>
  · identity_conflicts=<n> · per-command env assignment=<Y/N> · xtrace OFF verified before secret read=<Y/N>
  · parent-shell BOX_API_SECRET residual=<none> · window discipline violations=<none/list>
- P4 isolation: proxy/config hash identical=<Y/N>
  · MainPID=<same/changed> · NRestarts=<same/changed> · ExecMainStartTimestampMonotonic=<same/changed>
  · sing-box lifecycle journal entries=<0/n> · listener diff=<empty|仅+127.0.0.1:9191> · 9191 loopback-only=<Y/N>
  · backups superset=<Y/N>
  · verdict wording: "no evidence of restart/reload; all lifecycle/config invariants unchanged" [Y/N]
- P5 rollback drill: <REQUIRED: target=<release-id>, restored=<Y/N>, health=<healthy|…> | NOT APPLICABLE (fresh install, no previous successful release; transactional rollback covered by Linux CI)>
  · sing-box invariants/hashes unchanged after drill=<Y/N/NA> · final monitor state=<version>
- Deviations / incidents: <无 或 逐条列出>
- Artifacts: $ART=<path>（清单：p0-*…p5-*；零 secret 落盘临时文件——扫描器全程内存态）
- Canary runbook execution-ready: <YES/NO>
- remaining blockers: <none 或逐条>
- VPS: NOT RUN
- production: UNCHANGED
- FINAL VERDICT: <PASS | FAIL — reason>
```

---

## 12. 交付核对（rev2.3）

- [x] 最终 runbook（P0–P6，rev2 → rev2.1 → rev2.2 → rev2.3 修订：R1.1 session 契约、逐命令临时环境鉴权窗口、身份门禁重构、fresh 爆炸半径收紧、条件性回滚 drill、不变量集合证据措辞、内存态精确敏感值泄漏扫描器、**private-key 三层检测 + 四类别固定计数 + 缺料 fail-closed**；rev2.3 = PR #18 独立 review follow-up：service.api 基线形状、全局 pipefail + PIPESTATUS 纪律、collector 同目录路径、cmdline artifact 拆分、备份集合同构比较）
- [x] 风险表（R1–R13）
- [x] 精确 PASS/FAIL 矩阵（§8，逐项含 STOP 动作与 artifacts）
- [x] 获批 canary 的命令清单（§10）
- [x] 发现的事项（B1–B5，均定性为流程性前置/受控例外/记录项，无阻断性技术 blocker）
- [x] rev2/rev2.1/rev2.2 零代码修改、零执行、零 push；PR #16 未动；E3 未启动；E4 未暂存

**STOP — 本交付为纯文档/review，到此为止。**

---

**Monitor v2 VPS Canary Runbook**
revision: **rev2.3**

private-key full-value scan: PASS
private-key linewise-material scan: PASS
temporary secret environment handling: PASS
credential leak gate: PASS

**Canary runbook execution-ready: YES**

**VPS:** NOT RUN
**production:** UNCHANGED
**runtime code:** UNCHANGED
