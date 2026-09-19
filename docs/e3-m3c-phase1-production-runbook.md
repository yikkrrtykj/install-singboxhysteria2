# E3 M3-C Phase 1 — Production preflight + deploy-disabled Runbook

```text
冻结基线                  = f0e1480e1527ffb5906e715dd3acff8b29b8c024
本阶段                    = production preflight + deploy-disabled
management.activate       = 禁止
production client add/delete = 禁止产生实际变更
sing-box reload/restart   = 禁止
M3-C Phase 2              = NOT STARTED
```

本文是生产执行清单，不是执行授权。只有收到 Phase 1 的单独执行批准后，才可在
生产 VPS 上逐段执行。任何 `STOP` 都意味着立即停止后续步骤；尤其不得越过失败
继续调用 `management.activate`。

`e3-deploy-verify.sh` 内含一次负向 `client.add` 请求，用于证明 inactive 状态
fail-closed。该请求必须在 intent 之前以 `E_ACTIVATION_STATE` 被拒绝，实际 client
add/delete 数为零；除此之外不得发起任何生产 mutation RPC。

## 0. 操作约束与固定变量

进入生产 VPS 后使用一个 root shell 执行整份清单，保持变量不丢失：

```bash
sudo -i
```

确认提示符已进入 root shell 后，再执行：

```bash
set -Eeuo pipefail

export FROZEN='f0e1480e1527ffb5906e715dd3acff8b29b8c024'
export SRC='/root/e3-m3c-phase1-src-f0e1480'
export ART='/root/e3-m3c-phase1-artifacts-f0e1480'
export BASELINE="$ART/e3-baseline.json"
export CONFIG='/root/sbox/sbconfig_server.json'
export MONITOR_APP='/opt/singbox-monitor'
export MARKER='/var/lib/sbox-cm/management.active'
export SOCKET_PATH='/run/sbox-cm/sbox-cm.sock'
```

禁止在本阶段运行：

```text
sbox-cm-ops management.activate
任何 client.add / client.delete（deploy-verify 内必然被拒绝的负向探针除外）
手工编辑 /root/sbox/sbconfig_server.json
systemctl reload/restart sing-box.service
touch /var/lib/sbox-cm/management.active（或任何其它 marker 写入）
```

## 1. 干净 checkout 与 HEAD 验证

使用一次性目录；目录已存在时不覆盖、不复用：

```bash
test ! -e "$SRC" || {
  printf 'STOP: checkout path already exists: %s\n' "$SRC" >&2
  exit 1
}

git clone https://github.com/yikkrrtykj/install-singboxhysteria2.git "$SRC"
git -C "$SRC" checkout --detach "$FROZEN"

HEAD_GOT="$(git -C "$SRC" rev-parse HEAD)"
DIRTY_GOT="$(git -C "$SRC" status --porcelain)"
printf 'expected_head=%s\nactual_head=%s\n' "$FROZEN" "$HEAD_GOT"

test "$HEAD_GOT" = "$FROZEN" || {
  printf 'STOP: checkout HEAD mismatch\n' >&2
  exit 1
}
test -z "$DIRTY_GOT" || {
  printf 'STOP: checkout is dirty\n%s\n' "$DIRTY_GOT" >&2
  exit 1
}

for f in \
  monitor-v2/deploy/e3-preflight.sh \
  monitor-v2/deploy/e3-deploy-verify.sh \
  monitor-v2/deploy/e3-rollback.sh \
  monitor-v2/deploy/install-monitor.sh \
  sbox-cm/deploy/install-sbox-cm.sh; do
  test -f "$SRC/$f" || {
    printf 'STOP: required file missing: %s\n' "$f" >&2
    exit 1
  }
done

printf 'PASS checkout: exact frozen HEAD and clean worktree\n'
```

预期：`actual_head` 逐字符等于 `$FROZEN`，工作树为空，最后输出
`PASS checkout: exact frozen HEAD and clean worktree`。

**STOP：** clone/checkout 失败、SHA 不符、工作树非空或任一脚本缺失。此时尚未
修改运行态，不执行 rollback。

## 2. 生产环境只读 inventory

以下命令只读，不写配置、不调用 RPC、不启动任何 unit：

```bash
printf '%s\n' '===== HOST ====='
date -u '+utc=%Y-%m-%dT%H:%M:%SZ'
hostname -f
uname -a
sed -n '1,12p' /etc/os-release

printf '%s\n' '===== SYSTEMD / SERVICES ====='
systemctl is-system-running || true
for unit in sing-box.service singbox-monitor.service sbox-cm.socket sbox-cm.service; do
  printf '%s active=%s enabled=%s\n' \
    "$unit" \
    "$(systemctl is-active "$unit" 2>/dev/null || true)" \
    "$(systemctl is-enabled "$unit" 2>/dev/null || true)"
done
systemctl show sing-box.service \
  -p ActiveState -p ActiveEnterTimestamp -p NRestarts --no-pager

printf '%s\n' '===== CONFIG / MONITOR ====='
sha256sum "$CONFIG"
stat -c 'config owner=%U group=%G mode=%a size=%s' "$CONFIG"
printf 'monitor_link=%s\n' "$(readlink -f "$MONITOR_APP" 2>/dev/null || true)"
test -L "$MONITOR_APP" && printf 'monitor_symlink=yes\n' || printf 'monitor_symlink=no\n'
curl -sS -o /dev/null -w 'monitor_session_http=%{http_code}\n' \
  --max-time 5 http://127.0.0.1:9191/api/v1/session || true

printf '%s\n' '===== FIRST-DEPLOY CAPABILITY INVENTORY ====='
for p in \
  /usr/local/lib/sbox-cm/sbox-cm \
  /usr/local/lib/sbox-cm/sbox-cm-ops \
  /usr/local/lib/sbox-cm/lib/client-management.sh \
  /usr/local/lib/sbox-cm/lib/sbox-cm-state.sh \
  /etc/systemd/system/sbox-cm.socket \
  /etc/systemd/system/sbox-cm.service \
  "$SOCKET_PATH"; do
  if test -e "$p" || test -L "$p"; then
    printf 'PRESENT %s\n' "$p"
  else
    printf 'ABSENT  %s\n' "$p"
  fi
done

if test -d /var/lib/sbox-cm; then
  stat -c 'state_dir owner=%U group=%G mode=%a' /var/lib/sbox-cm
else
  printf 'state_dir=absent\n'
fi
test ! -e "$MARKER" && printf 'activation_marker=absent\n' \
  || printf 'activation_marker=PRESENT\n'
id sboxweb
df -Pm / /var
```

进入 preflight 的最低预期：

- `sing-box.service` 与 `singbox-monitor.service` 为 `active`。
- monitor 是可解析 symlink，`/api/v1/session` 返回 `200`。
- 六个 helper capability 路径全部 `ABSENT`。
- `$SOCKET_PATH` 必须 `ABSENT`；即使它是 `root:sboxweb 0660` 也必须停止。
- marker 必须 `absent`。
- `/var/lib/sbox-cm` 可不存在；若存在，必须是 `root:root 0700`。

**STOP：** inventory 出现任何 helper capability、stale socket 或 marker。FIRST
DEPLOY ONLY 不允许清理后“凑成”首次部署；保留现场并另行评审。其他异常也先停止，
由正式 preflight 给最终判定。此时不执行 rollback。

## 3. 创建证据目录并运行 production preflight

baseline 固定保存为：

```text
/root/e3-m3c-phase1-artifacts-f0e1480/e3-baseline.json
```

目录或 baseline 已存在时停止，防止覆盖旧证据：

```bash
test ! -e "$ART" || {
  printf 'STOP: artifact path already exists: %s\n' "$ART" >&2
  exit 1
}
install -d -m 0700 -o root -g root "$ART"
test ! -e "$BASELINE" || {
  printf 'STOP: baseline already exists: %s\n' "$BASELINE" >&2
  exit 1
}

set +e
bash "$SRC/monitor-v2/deploy/e3-preflight.sh" \
  --baseline-out "$BASELINE" 2>&1 | tee "$ART/01-preflight.log"
PREFLIGHT_RC=${PIPESTATUS[0]}
set -e

if test "$PREFLIGHT_RC" -ne 0 \
    || ! grep -qx 'E3_PREFLIGHT=PASS' "$ART/01-preflight.log" \
    || ! test -f "$BASELINE"; then
  printf 'STOP: production preflight did not PASS; no deployment is allowed\n' >&2
  exit 1
fi

test "$(stat -c '%U %G %a' "$BASELINE")" = 'root root 600' || {
  printf 'STOP: baseline ownership/mode is not root:root 0600\n' >&2
  exit 1
}
jq -e . "$BASELINE" >/dev/null || {
  printf 'STOP: baseline is not valid JSON\n' >&2
  exit 1
}

printf 'PASS preflight gate: E3_PREFLIGHT=PASS and baseline=root:root/0600\n'
```

预期关键输出：

```text
PASS P00 no sbox-cm capability present (clean first-deploy precondition)
INFO P10 sbox-cm socket absent (created when the socket unit starts)
PASS P14 activation marker absent (management plane closed, the safe default)
PASS baseline saved atomically to ... (0600, all checks passed)
E3_PREFLIGHT=PASS
```

任一 `FAIL`、非零退出码、缺失 baseline、JSON 无效或权限不是 `0600` 均为
**STOP**。preflight 失败不会进入部署，也不执行 rollback。

## 4. 打印并冻结 baseline 关键字段

```bash
jq '{
  saved_at,
  config_sha256,
  config_size,
  singbox,
  monitor,
  marker_present,
  helper
}' "$BASELINE" | tee "$ART/02-baseline-summary.json"

jq -e '
  (.config_sha256 | type == "string" and length == 64) and
  (.config_size | type == "number" and . > 0) and
  (.singbox.active == "active") and
  (.monitor.active == "active") and
  (.monitor.enabled | type == "string" and length > 0) and
  (.monitor.release_id | type == "string" and length > 0) and
  (.monitor.release_target | type == "string" and length > 0) and
  (.marker_present == false) and
  (.helper.libexec_present == false) and
  (.helper.socket_unit_present == false) and
  (.helper.service_unit_present == false)
' "$BASELINE" >/dev/null || {
  printf 'STOP: baseline fields violate the Phase 1 contract\n' >&2
  exit 1
}

export CONFIG_SHA_BEFORE="$(jq -er '.config_sha256' "$BASELINE")"
export CONFIG_SIZE_BEFORE="$(jq -er '.config_size' "$BASELINE")"
export SB_TS_BEFORE="$(jq -er '.singbox.active_enter_timestamp' "$BASELINE")"
export SB_RESTARTS_BEFORE="$(jq -er '.singbox.nrestarts' "$BASELINE")"
export BASE_RELEASE="$(jq -er '.monitor.release_id' "$BASELINE")"
export BASE_RELEASE_TARGET="$(jq -er '.monitor.release_target' "$BASELINE")"
export BASE_MONITOR_ACTIVE="$(jq -er '.monitor.active' "$BASELINE")"
export BASE_MONITOR_ENABLED="$(jq -er '.monitor.enabled' "$BASELINE")"
export EXPECTED_BASE_RELEASE_TARGET="/opt/singbox-monitor-releases/$BASE_RELEASE"

printf 'CONFIG_SHA_BEFORE=%s\n' "$CONFIG_SHA_BEFORE"
printf 'CONFIG_SIZE_BEFORE=%s\n' "$CONFIG_SIZE_BEFORE"
printf 'SB_TS_BEFORE=%s\n' "$SB_TS_BEFORE"
printf 'SB_RESTARTS_BEFORE=%s\n' "$SB_RESTARTS_BEFORE"
printf 'BASE_RELEASE=%s\n' "$BASE_RELEASE"
printf 'BASE_RELEASE_TARGET=%s\n' "$BASE_RELEASE_TARGET"
printf 'BASE_MONITOR_ACTIVE=%s\n' "$BASE_MONITOR_ACTIVE"
printf 'BASE_MONITOR_ENABLED=%s\n' "$BASE_MONITOR_ENABLED"

test "$BASE_RELEASE_TARGET" = "$EXPECTED_BASE_RELEASE_TARGET" || {
  printf 'STOP: baseline release_target does not match packaging releases dir\n' >&2
  exit 1
}
test -d "$BASE_RELEASE_TARGET" || {
  printf 'STOP: exact baseline release directory is missing: %s\n' \
    "$BASE_RELEASE_TARGET" >&2
  exit 1
}
test "$(readlink -f "$MONITOR_APP" 2>/dev/null || true)" = "$BASE_RELEASE_TARGET" || {
  printf 'STOP: live monitor target drifted after preflight\n' >&2
  exit 1
}

printf 'PASS rollback-target gate: baseline target equals real packaging path and exists\n'
```

预期：helper 的 libexec/socket-unit/service-unit 三项均为 `false`，marker 为
`false`，sing-box 与 monitor 均为 `active`；`monitor.release_target` 必须精确等于
`/opt/singbox-monitor-releases/$BASE_RELEASE` 且目录存在。这证明后续
`e3-rollback.sh` 的默认 `E3_RELEASES_DIR` 能找到 exact baseline target。任何字段
缺失、路径不等或目录不存在均在 D2 mutation 前 **STOP**。

为后续失败路径定义两个 fail-closed 处理函数。monitor-only 阶段只恢复 baseline
release；helper install 一旦开始，统一调用完整 rollback：

```bash
phase1_monitor_stop() {
  local reason="$1" current_target monitor_active monitor_enabled http_code rc=0
  printf 'STOP: %s\n' "$reason" >&2
  current_target="$(readlink -f "$MONITOR_APP" 2>/dev/null || true)"
  if test "$current_target" != "$BASE_RELEASE_TARGET"; then
    set +e
    bash "$SRC/monitor-v2/deploy/install-monitor.sh" rollback "$BASE_RELEASE" \
      2>&1 | tee "$ART/98-monitor-only-rollback.log"
    rc=${PIPESTATUS[0]}
    set -e
  fi
  current_target="$(readlink -f "$MONITOR_APP" 2>/dev/null || true)"
  monitor_active="$(systemctl is-active singbox-monitor.service 2>/dev/null || true)"
  monitor_enabled="$(systemctl is-enabled singbox-monitor.service 2>/dev/null || true)"
  http_code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 \
    http://127.0.0.1:9191/api/v1/session 2>/dev/null || true)"
  if test "$rc" -eq 0 \
      && test "$current_target" = "$BASE_RELEASE_TARGET" \
      && test "$monitor_active" = "$BASE_MONITOR_ACTIVE" \
      && test "$monitor_enabled" = "$BASE_MONITOR_ENABLED" \
      && test "$http_code" = 200; then
    printf 'ROLLBACK PASS: monitor restored to exact baseline state\n'
  else
    printf 'CRITICAL: monitor-only rollback did not restore the complete baseline state\n' >&2
  fi
  exit 1
}

phase1_full_rollback() {
  local reason="$1" rc
  printf 'STOP+ROLLBACK: %s\n' "$reason" >&2
  set +e
  bash "$SRC/monitor-v2/deploy/e3-rollback.sh" \
    --baseline "$BASELINE" 2>&1 | tee "$ART/99-rollback.log"
  rc=${PIPESTATUS[0]}
  set -e
  if test "$rc" -eq 0 \
      && grep -qx 'E3_M3_ROLLBACK=PASS' "$ART/99-rollback.log"; then
    printf 'ROLLBACK PASS: Phase 1 deployment removed; audit/state retained\n'
  else
    printf 'CRITICAL: rollback incomplete; preserve evidence and escalate manually\n' >&2
  fi
  exit 1
}
```

如果 helper install 开始后因网络断开、终端退出或其它非预期原因离开当前 root
shell，不得从下一节续跑。重新进入 root shell、恢复第 0 节固定变量后，直接执行
第 11 节 full rollback；不得先运行任何 RPC 或 activation。

## 5. 强制 restage frozen monitor release

生产已存在 monitor，因此保留 `upgrade` 的锁内 fail-closed 前置条件（当前未安装时
绝不退化为 fresh install），并显式加入 `--repair`。冻结版本与 live 版本相同时，
普通 `upgrade` 会 `action=noop`、不会 stage 当前 frozen source；`--repair` 会重新
stage frozen source，但仍不覆盖 monitor 配置/auth/state，只 restart monitor，绝不
触碰 sing-box。

D2 前先打印 frozen/live VERSION、当前 release id，并计算本次进程专用的 retention
值。keep 值 = mutation 前所有非 staging release 目录数 + 1，恰好容纳即将新建的
release，因而本次成功切换不会 prune 任何既有 release，尤其不会删除 baseline
rollback target。该值只注入 D2 进程，不修改全局配置：

```bash
export FROZEN_VERSION="$(tr -d ' \t\r\n' < "$SRC/monitor-v2/VERSION")"
export CURRENT_RELEASE_TARGET="$(readlink -f "$MONITOR_APP" 2>/dev/null || true)"
export CURRENT_RELEASE="$(basename "$CURRENT_RELEASE_TARGET")"
export LIVE_VERSION="$(tr -d ' \t\r\n' < "$CURRENT_RELEASE_TARGET/VERSION")"
export RELEASE_COUNT_BEFORE="$(find /opt/singbox-monitor-releases \
  -mindepth 1 -maxdepth 1 -type d ! -name '.staging-*' -printf '%f\n' \
  | wc -l | tr -d '[:space:]')"
export PHASE1_KEEP_RELEASES="$((RELEASE_COUNT_BEFORE + 1))"

{
  printf 'frozen_repo_version=%s\n' "$FROZEN_VERSION"
  printf 'current_live_version=%s\n' "$LIVE_VERSION"
  printf 'current_release_id=%s\n' "$CURRENT_RELEASE"
  printf 'current_release_target=%s\n' "$CURRENT_RELEASE_TARGET"
  printf 'release_count_before=%s\n' "$RELEASE_COUNT_BEFORE"
  printf 'phase1_keep_releases=%s\n' "$PHASE1_KEEP_RELEASES"
} | tee "$ART/03-monitor-before.txt"

test "$FROZEN_VERSION" = '0.1.0' || {
  printf 'STOP: frozen repo VERSION is not the reviewed 0.1.0\n' >&2
  exit 1
}
test "$LIVE_VERSION" = "$FROZEN_VERSION" || {
  printf 'STOP: live VERSION differs; reviewed same-version restage path does not apply\n' >&2
  exit 1
}
test "$CURRENT_RELEASE" = "$BASE_RELEASE" \
  && test "$CURRENT_RELEASE_TARGET" = "$BASE_RELEASE_TARGET" || {
    printf 'STOP: live release no longer matches the preflight baseline\n' >&2
    exit 1
  }
test "$PHASE1_KEEP_RELEASES" -ge 2 || {
  printf 'STOP: computed Phase 1 retention value is invalid\n' >&2
  exit 1
}

set +e
SBMON_KEEP_RELEASES="$PHASE1_KEEP_RELEASES" \
  bash "$SRC/monitor-v2/deploy/install-monitor.sh" upgrade --repair \
  2>&1 | tee "$ART/03-monitor-upgrade.log"
MONITOR_RC=${PIPESTATUS[0]}
set -e

if test "$MONITOR_RC" -ne 0; then
  phase1_monitor_stop 'monitor upgrade failed; installer should have restored its transaction'
fi

export LIVE_RELEASE="$(basename "$(readlink -f "$MONITOR_APP")")"
test -n "$LIVE_RELEASE" && test "$LIVE_RELEASE" != "$BASE_RELEASE" || {
  phase1_monitor_stop 'monitor did not switch to a new release'
}
test "$(systemctl is-active singbox-monitor.service 2>/dev/null || true)" = active || {
  phase1_monitor_stop 'monitor is not active after upgrade'
}
test "$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 \
  http://127.0.0.1:9191/api/v1/session 2>/dev/null || true)" = 200 || {
  phase1_monitor_stop 'monitor read-only API is not HTTP 200 after upgrade'
}

# Pruning protection is a hard gate before helper install.
test -d "/opt/singbox-monitor-releases/$BASE_RELEASE" || {
  printf 'CRITICAL STOP: baseline rollback target was pruned or disappeared: %s\n' \
    "$BASE_RELEASE" >&2
  exit 1
}

# D2 -> D3 fail-fast invariant gate.
export D2_CONFIG_SHA="$(sha256sum "$CONFIG" | awk '{print $1}')"
export D2_CONFIG_SIZE="$(stat -c %s "$CONFIG")"
export D2_SB_TS="$(systemctl show -p ActiveEnterTimestamp --value sing-box.service)"
export D2_SB_RESTARTS="$(systemctl show -p NRestarts --value sing-box.service)"
export D2_SB_ACTIVE="$(systemctl is-active sing-box.service 2>/dev/null || true)"

test "$D2_CONFIG_SHA" = "$CONFIG_SHA_BEFORE" \
  && test "$D2_CONFIG_SIZE" = "$CONFIG_SIZE_BEFORE" \
  && test "$D2_SB_TS" = "$SB_TS_BEFORE" \
  && test "$D2_SB_RESTARTS" = "$SB_RESTARTS_BEFORE" \
  && test "$D2_SB_ACTIVE" = active || {
    phase1_monitor_stop 'INCIDENT: D2 changed config or sing-box state; helper install forbidden'
  }

printf 'PASS D2 gate: repair-restage complete; baseline retained; config/sing-box unchanged\n'
printf 'PASS monitor deploy: baseline=%s live=%s\n' "$BASE_RELEASE" "$LIVE_RELEASE"
```

预期：证据显示 frozen/live VERSION 均为 `0.1.0`；命令以
`action=repair version=0.1.0` 完成；monitor active、HTTP 200、live release id 与
baseline release id 不同；baseline release 目录仍存在；config SHA/size 与 sing-box
timestamp/restarts 完全不变。installer 只允许重启 monitor，绝不 reload/restart
sing-box。

**失败处理：** 此时 helper 尚未安装。monitor installer 非零时其自身事务应恢复
旧 release；立即 STOP，核对 live release 是否等于 `$BASE_RELEASE`。若事务未恢复，
唯一允许的 monitor rollback target 是 baseline：

```bash
bash "$SRC/monitor-v2/deploy/install-monitor.sh" rollback "$BASE_RELEASE"
```

不得从 `releases.history` 猜测目标。回滚后仍异常则保留证据并升级为人工事件；
不得继续安装 helper。

### D2 mutation 后的 shell/SSH interruption contract

一旦 D2 monitor mutation 开始，任何 shell、SSH、终端或操作者流程中断都使本次
Phase 1 失效。重新连接后不得从 D3/D4 或任一中间步骤续跑，也不得先访问 E3 页面、
运行 RPC 或 activation。恢复第 0 节的固定变量并确认 baseline 可读后，只做以下
read-only classification：

```bash
sudo -i
```

进入新的 root shell 后执行：

```bash
set -Eeuo pipefail
export FROZEN='f0e1480e1527ffb5906e715dd3acff8b29b8c024'
export SRC='/root/e3-m3c-phase1-src-f0e1480'
export ART='/root/e3-m3c-phase1-artifacts-f0e1480'
export BASELINE="$ART/e3-baseline.json"
export MONITOR_APP='/opt/singbox-monitor'
export SOCKET_PATH='/run/sbox-cm/sbox-cm.sock'

test -r "$BASELINE" && jq -e . "$BASELINE" >/dev/null || {
  printf 'CRITICAL STOP: baseline unavailable; no automatic continuation is allowed\n' >&2
  exit 1
}
export BASE_RELEASE="$(jq -er '.monitor.release_id' "$BASELINE")"
export BASE_RELEASE_TARGET="$(jq -er '.monitor.release_target' "$BASELINE")"
export BASE_MONITOR_ACTIVE="$(jq -er '.monitor.active' "$BASELINE")"
export BASE_MONITOR_ENABLED="$(jq -er '.monitor.enabled' "$BASELINE")"
test "$BASE_RELEASE_TARGET" = "/opt/singbox-monitor-releases/$BASE_RELEASE" \
  && test -d "$BASE_RELEASE_TARGET" || {
    printf 'CRITICAL STOP: exact baseline rollback target is unavailable\n' >&2
    exit 1
  }

CLASSIFICATION='helper-absent'
for p in \
  /usr/local/lib/sbox-cm/sbox-cm \
  /usr/local/lib/sbox-cm/sbox-cm-ops \
  /usr/local/lib/sbox-cm/lib/client-management.sh \
  /usr/local/lib/sbox-cm/lib/sbox-cm-state.sh \
  /etc/systemd/system/sbox-cm.socket \
  /etc/systemd/system/sbox-cm.service \
  "$SOCKET_PATH"; do
  if test -e "$p" || test -L "$p"; then
    printf 'PRESENT %s\n' "$p"
    CLASSIFICATION='helper-present-or-uncertain'
  else
    printf 'ABSENT  %s\n' "$p"
  fi
done
if test -e "$ART/04-sbox-cm-install.log"; then
  printf 'PRESENT %s\n' "$ART/04-sbox-cm-install.log"
  CLASSIFICATION='helper-present-or-uncertain'
  D3_PROVEN_NOT_STARTED='no'
else
  printf 'ABSENT  %s\n' "$ART/04-sbox-cm-install.log"
  if test "$CLASSIFICATION" = 'helper-absent'; then
    D3_PROVEN_NOT_STARTED='yes'
  else
    D3_PROVEN_NOT_STARTED='no'
  fi
fi
printf 'interruption_classification=%s\n' "$CLASSIFICATION"
printf 'D3_PROVEN_NOT_STARTED=%s\n' "$D3_PROVEN_NOT_STARTED"
```

分类后的唯一动作：

- 七个路径（六个 helper capability + runtime socket）全部 `ABSENT`，且
  `$ART/04-sbox-cm-install.log` 不存在，脚本才设置
  `D3_PROVEN_NOT_STARTED=yes`：执行 monitor-only rollback，target 只取
  `baseline.monitor.release_id`。
- 任一路径存在、`04-sbox-cm-install.log` 已存在，或其它原因无法证明 D3 尚未开始：
  `D3_PROVEN_NOT_STARTED=no`，不允许走 monitor-only rollback，执行第 11 节 full
  rollback / fail-closed recovery。
- rollback 后本次 Phase 1 结束；不得从 D3/D4 续跑。重新尝试必须从全新的
  checkout/inventory/preflight 和全新证据目录开始。

helper 全 absent 时的 monitor-only rollback：

```bash
if test "$CLASSIFICATION" = 'helper-absent' \
    && test "$D3_PROVEN_NOT_STARTED" = yes; then
  set +e
  bash "$SRC/monitor-v2/deploy/install-monitor.sh" rollback "$BASE_RELEASE"
  INTERRUPTION_ROLLBACK_RC=$?
  set -e
  INTERRUPTION_TARGET="$(readlink -f "$MONITOR_APP" 2>/dev/null || true)"
  INTERRUPTION_ACTIVE="$(systemctl is-active singbox-monitor.service 2>/dev/null || true)"
  INTERRUPTION_ENABLED="$(systemctl is-enabled singbox-monitor.service 2>/dev/null || true)"
  INTERRUPTION_HTTP="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 \
    http://127.0.0.1:9191/api/v1/session 2>/dev/null || true)"
  test "$INTERRUPTION_ROLLBACK_RC" -eq 0 \
    && test "$INTERRUPTION_TARGET" = "$BASE_RELEASE_TARGET" \
    && test "$INTERRUPTION_ACTIVE" = "$BASE_MONITOR_ACTIVE" \
    && test "$INTERRUPTION_ENABLED" = "$BASE_MONITOR_ENABLED" \
    && test "$INTERRUPTION_HTTP" = 200 || {
    printf 'CRITICAL: monitor-only rollback did not restore the complete baseline state\n' >&2
    exit 1
  }
  printf 'ROLLBACK PASS: monitor restored to exact baseline state\n'
  exit 1
fi

printf 'FULL ROLLBACK REQUIRED: helper present or D3 state uncertain\n' >&2
set +e
bash "$SRC/monitor-v2/deploy/e3-rollback.sh" \
  --baseline "$BASELINE" 2>&1 | tee "$ART/99-rollback.log"
ROLLBACK_RC=${PIPESTATUS[0]}
set -e
test "$ROLLBACK_RC" -eq 0 \
  && grep -qx 'E3_M3_ROLLBACK=PASS' "$ART/99-rollback.log" || {
    printf 'CRITICAL: interruption rollback incomplete; preserve evidence\n' >&2
    exit 1
  }
printf 'ROLLBACK PASS: interruption full rollback complete; Phase 1 ended\n'
exit 1
```

## 6. 安装 sbox-cm，但保持 disabled/inactive

不得传 `--enable`：

```bash
set +e
bash "$SRC/sbox-cm/deploy/install-sbox-cm.sh" install \
  2>&1 | tee "$ART/04-sbox-cm-install.log"
HELPER_RC=${PIPESTATUS[0]}
set -e

if test "$HELPER_RC" -ne 0; then
  phase1_full_rollback 'sbox-cm install failed or may be partial'
fi

# Installer 对 daemon-reload 仅告警；Phase 1 将其提升为硬门。
systemctl daemon-reload || {
  phase1_full_rollback 'systemctl daemon-reload failed'
}

for p in \
  /usr/local/lib/sbox-cm/sbox-cm \
  /usr/local/lib/sbox-cm/sbox-cm-ops \
  /usr/local/lib/sbox-cm/lib/client-management.sh \
  /usr/local/lib/sbox-cm/lib/sbox-cm-state.sh \
  /etc/systemd/system/sbox-cm.socket \
  /etc/systemd/system/sbox-cm.service; do
  test -e "$p" || {
    phase1_full_rollback "installed capability missing: $p"
  }
done

test "$(systemctl is-active sbox-cm.socket 2>/dev/null || true)" = inactive \
  && test "$(systemctl is-active sbox-cm.service 2>/dev/null || true)" = inactive \
  && test "$(systemctl is-enabled sbox-cm.socket 2>/dev/null || true)" = disabled \
  && test "$(systemctl is-enabled sbox-cm.service 2>/dev/null || true)" = disabled \
  && test ! -e "$MARKER" || {
    phase1_full_rollback 'helper install did not remain disabled/inactive with marker absent'
  }

# D3 -> D4 fail-fast invariant gate（仍未打开 socket）。
export D3_CONFIG_SHA="$(sha256sum "$CONFIG" | awk '{print $1}')"
export D3_CONFIG_SIZE="$(stat -c %s "$CONFIG")"
export D3_SB_TS="$(systemctl show -p ActiveEnterTimestamp --value sing-box.service)"
export D3_SB_RESTARTS="$(systemctl show -p NRestarts --value sing-box.service)"
export D3_SB_ACTIVE="$(systemctl is-active sing-box.service 2>/dev/null || true)"

test "$D3_CONFIG_SHA" = "$CONFIG_SHA_BEFORE" \
  && test "$D3_CONFIG_SIZE" = "$CONFIG_SIZE_BEFORE" \
  && test "$D3_SB_TS" = "$SB_TS_BEFORE" \
  && test "$D3_SB_RESTARTS" = "$SB_RESTARTS_BEFORE" \
  && test "$D3_SB_ACTIVE" = active || {
    phase1_full_rollback 'INCIDENT: D3 changed config or sing-box state; socket enable forbidden'
  }

printf 'PASS helper install: socket/service disabled+inactive; marker absent\n'
printf 'PASS D3 gate: config/sing-box unchanged before opening socket\n'
```

预期 installer 输出包含 `units 默认 disabled + inactive`。任何安装失败、文件缺失、
daemon-reload 失败、unit 意外 active/enabled 或 marker 出现均为 **STOP+ROLLBACK**。
从本步骤开始，失败统一执行第 11 节 full rollback。

## 7. 只 enable/start socket，并冻结 first-RPC 前状态

此步骤之前不得访问 sbox-cm socket、不得打开 E3 页面、不得运行 deploy-verify：

```bash
systemctl enable --now sbox-cm.socket || {
  phase1_full_rollback 'enable --now sbox-cm.socket failed'
}

export SOCKET_ACTIVE="$(systemctl is-active sbox-cm.socket 2>/dev/null || true)"
export SOCKET_ENABLED="$(systemctl is-enabled sbox-cm.socket 2>/dev/null || true)"
export SERVICE_BEFORE_RPC="$(systemctl is-active sbox-cm.service 2>/dev/null || true)"
export SERVICE_ENABLED="$(systemctl is-enabled sbox-cm.service 2>/dev/null || true)"

printf 'socket active=%s enabled=%s\n' "$SOCKET_ACTIVE" "$SOCKET_ENABLED"
printf 'service pre_rpc_active=%s enabled=%s\n' "$SERVICE_BEFORE_RPC" "$SERVICE_ENABLED"

test "$SOCKET_ACTIVE" = active \
  && test "$SOCKET_ENABLED" = enabled \
  && test "$SERVICE_BEFORE_RPC" = inactive \
  && test "$SERVICE_ENABLED" = disabled \
  && test ! -e "$MARKER" || {
    phase1_full_rollback 'socket-only / pre-RPC state violated'
  }

printf 'PASS pre-RPC gate: socket enabled+active; service disabled+inactive; marker absent\n'
```

预期必须逐字满足：socket `enabled/active`，service `disabled/inactive`，marker
absent。service 若已 active，说明 first-RPC 证明已被污染，立即 **STOP+ROLLBACK**。
严禁为了“修正”状态而 enable/start service。

## 8. 运行 deploy-verify（第一次真实 RPC 在脚本内部发生）

```bash
set +e
bash "$SRC/monitor-v2/deploy/e3-deploy-verify.sh" \
  --baseline "$BASELINE" 2>&1 | tee "$ART/05-deploy-verify.log"
VERIFY_RC=${PIPESTATUS[0]}
set -e

if test "$VERIFY_RC" -ne 0 \
    || ! grep -qx 'E3_M3_VERIFY=PASS' "$ART/05-deploy-verify.log"; then
  phase1_full_rollback 'deploy-verify did not PASS; activation remains forbidden'
fi

printf 'PASS deploy-verify gate: E3_M3_VERIFY=PASS\n'
```

必须看到的关键输出：

```text
PASS V01 config SHA256 identical to the baseline (...)
PASS V03 sing-box NOT restarted by the deployment (ts/restarts identical)
PASS V05a sbox-cm.socket active (service activation deferred to the first RPC)
PASS V06 activation marker absent (management plane inactive)
PASS V07 management.status (sboxweb RPC) reports inactive
PASS V05b sbox-cm.service pulled up by the real RPC (socket activation works)
PASS V10 mutation while inactive is fail-closed (E_ACTIVATION_STATE, zero changes)
PASS V11 config SHA256 unchanged after the fail-closed probe
E3_M3_VERIFY=PASS
```

任何 `FAIL` 或非零退出码都必须立即 **STOP+ROLLBACK**。绝不允许把 verify FAIL
当作告警，更不允许继续 activation。

## 9. 独立打印 before/after 不变量

```bash
export CONFIG_SHA_AFTER="$(sha256sum "$CONFIG" | awk '{print $1}')"
export CONFIG_SIZE_AFTER="$(stat -c %s "$CONFIG")"
export SB_TS_AFTER="$(systemctl show -p ActiveEnterTimestamp --value sing-box.service)"
export SB_RESTARTS_AFTER="$(systemctl show -p NRestarts --value sing-box.service)"

printf 'config_sha before=%s after=%s\n' "$CONFIG_SHA_BEFORE" "$CONFIG_SHA_AFTER"
printf 'config_size before=%s after=%s\n' "$CONFIG_SIZE_BEFORE" "$CONFIG_SIZE_AFTER"
printf 'singbox_timestamp before=%s after=%s\n' "$SB_TS_BEFORE" "$SB_TS_AFTER"
printf 'singbox_restarts before=%s after=%s\n' "$SB_RESTARTS_BEFORE" "$SB_RESTARTS_AFTER"

test "$CONFIG_SHA_AFTER" = "$CONFIG_SHA_BEFORE" \
  && test "$CONFIG_SIZE_AFTER" = "$CONFIG_SIZE_BEFORE" \
  && test "$SB_TS_AFTER" = "$SB_TS_BEFORE" \
  && test "$SB_RESTARTS_AFTER" = "$SB_RESTARTS_BEFORE" \
  && test "$(systemctl is-active sing-box.service 2>/dev/null || true)" = active || {
    phase1_full_rollback 'config changed or sing-box restarted/state drifted'
  }

printf 'PASS immutable production state: config byte-identical; sing-box not restarted\n'
```

任何 before/after 不相等均为 **STOP+ROLLBACK + incident**。rollback 工具不会也
不应手工修配置或重启 sing-box；保留证据，不得尝试“修好后继续”。

## 10. 显式确认 management inactive 与 marker absent

deploy-verify 已完成第一次 RPC并拉起 service。使用同一 live monitor runtime 再做
一次只读 `management.status`：

```bash
set +e
export STATUS_JSON="$({
  sudo -n -u sboxweb /usr/bin/python3 -B - \
    "$MONITOR_APP/app/monitor-v2" <<'PY'
import json
import sys
sys.path.insert(0, sys.argv[1])
from web.e3rpc import E3RpcClient
print(json.dumps(E3RpcClient().call("management.status")))
PY
} 2>/dev/null)"
STATUS_RC=$?
set -e

if test "$STATUS_RC" -ne 0 || ! printf '%s' "$STATUS_JSON" | jq -e '
  .ok == true and .data.management_state == "inactive"
' >/dev/null; then
  phase1_full_rollback 'management.status is not inactive'
fi
printf '%s\n' "$STATUS_JSON" | jq . | tee "$ART/06-management-status.json"
test ! -e "$MARKER" || {
  phase1_full_rollback 'activation marker exists'
}
test "$(systemctl is-active sbox-cm.socket 2>/dev/null || true)" = active \
  && test "$(systemctl is-active sbox-cm.service 2>/dev/null || true)" = active || {
    phase1_full_rollback 'socket/service not active after verified first RPC'
  }

printf 'PASS closed plane: management_state=inactive; activation marker absent\n'
```

预期 JSON：`.ok == true` 且 `.data.management_state == "inactive"`；marker 仍不存在。
任何偏差立即 **STOP+ROLLBACK**。

## 11. 失败后的 full rollback

适用范围：第 6 节 helper install 已开始之后的任何失败，或 interruption 分类为
helper present/uncertain。不要手写 release id，rollback target 只能由
`$BASELINE.monitor.release_id` 读取：

```bash
set +e
bash "$SRC/monitor-v2/deploy/e3-rollback.sh" \
  --baseline "$BASELINE" 2>&1 | tee "$ART/99-rollback.log"
ROLLBACK_RC=${PIPESTATUS[0]}
set -e

if test "$ROLLBACK_RC" -eq 0 \
    && grep -qx 'E3_M3_ROLLBACK=PASS' "$ART/99-rollback.log"; then
  printf 'ROLLBACK PASS: Phase 1 deployment removed; audit/state retained\n'
else
  printf 'CRITICAL: rollback incomplete; preserve evidence and escalate manually\n' >&2
fi

exit 1
```

rollback 预期：先关闭 socket/service，恢复 baseline 的 exact monitor release，删除
本轮 helper units/libexec，检查 daemon-reload，保留 `/var/lib/sbox-cm` audit/state，
最后输出 `E3_M3_ROLLBACK=PASS`。rollback 自身任何 FAIL 都是生产事件；仍然禁止
修改 sing-box 配置、reload/restart sing-box 或进入 Phase 2。

### STOP / rollback 决策表

| 失败位置 | 动作 |
| --- | --- |
| checkout / inventory / preflight / baseline gate | STOP；尚未部署，不 rollback |
| monitor `upgrade --repair` 非零 | STOP；installer 应自恢复；只核对 baseline release |
| D2 后 baseline release 目录消失 | CRITICAL STOP；不安装 helper、不运行 RPC；保留现场人工处置 |
| D2 后 config/sing-box 不变量漂移 | monitor-only rollback + incident STOP；不安装 helper |
| monitor 已切换但 helper install 尚未开始，且需撤销 | 仅用 baseline 的 `$BASE_RELEASE` 调用 monitor rollback |
| D2 开始后的 shell/SSH/终端中断 | read-only 分类；7 路径全 absent 且 `04-sbox-cm-install.log` 不存在才令 `D3_PROVEN_NOT_STARTED=yes` 并走 monitor-only rollback；否则 full rollback；本次 Phase 1 结束 |
| helper install 开始后的任一失败 | STOP；执行第 11 节 full rollback |
| D3 后、D4 前 config/sing-box 不变量漂移 | STOP；full rollback + incident；不开 socket |
| socket-only / pre-RPC gate 失败 | STOP；full rollback |
| deploy-verify 任一 FAIL | STOP；full rollback；activation 永久禁止 |
| config SHA/size 漂移或 sing-box timestamp/restarts 漂移 | STOP；full rollback + incident；不手工修配置、不重启 sing-box |
| management 非 inactive 或 marker 出现 | STOP；full rollback + security incident |
| rollback FAIL | CRITICAL STOP；保留全部证据，人工处置；绝不 activation |

## 12. Phase 1 最终成功输出

只有第 8、9、10 节全部 PASS 后才执行：

```bash
if ! {
  test "$(git -C "$SRC" rev-parse HEAD)" = "$FROZEN" \
    && grep -qx 'E3_PREFLIGHT=PASS' "$ART/01-preflight.log" \
    && grep -qx 'E3_M3_VERIFY=PASS' "$ART/05-deploy-verify.log" \
    && test -d "$BASE_RELEASE_TARGET" \
    && test "$LIVE_RELEASE" != "$BASE_RELEASE" \
    && test "$CONFIG_SHA_AFTER" = "$CONFIG_SHA_BEFORE" \
    && test "$CONFIG_SIZE_AFTER" = "$CONFIG_SIZE_BEFORE" \
    && test "$SB_TS_AFTER" = "$SB_TS_BEFORE" \
    && test "$SB_RESTARTS_AFTER" = "$SB_RESTARTS_BEFORE" \
    && printf '%s' "$STATUS_JSON" | jq -e \
      '.ok == true and .data.management_state == "inactive"' >/dev/null \
    && test ! -e "$MARKER" \
    && test "$(systemctl is-active sbox-cm.socket 2>/dev/null || true)" = active \
    && test "$(systemctl is-active sbox-cm.service 2>/dev/null || true)" = active \
    && test "$(systemctl is-enabled sbox-cm.socket 2>/dev/null || true)" = enabled \
    && test "$(systemctl is-enabled sbox-cm.service 2>/dev/null || true)" = disabled
}; then
  phase1_full_rollback 'final Phase 1 gate failed'
fi

printf '%s\n' \
  'PRODUCTION DEPLOYED = YES' \
  'E3 MANAGEMENT ENABLED = NO' \
  'management_state = inactive' \
  'M3-C Phase 2 = NOT STARTED'
```

这四行是 Phase 1 的唯一成功终态。随后立即硬停止：不运行
`management.activate`，不创建/删除生产 client，不写 marker，不 reload/restart
sing-box。Phase 2 必须另开审批。

## Phase 1 gate checklist

- [ ] checkout HEAD 精确等于 `f0e1480e1527ffb5906e715dd3acff8b29b8c024`，工作树干净。
- [ ] 只读 inventory 无 existing/partial helper capability、无 stale socket、无 marker。
- [ ] `E3_PREFLIGHT=PASS`；baseline 由该 PASSing preflight 原子产生且为 root:root 0600。
- [ ] baseline 关键字段已打印并保存；helper capability 的三项 present 均为 false。
- [ ] baseline 的 monitor active/enabled 状态已冻结为 `BASE_MONITOR_ACTIVE/ENABLED`。
- [ ] baseline `release_target` 精确等于 `/opt/singbox-monitor-releases/$BASE_RELEASE` 且目录存在。
- [ ] D2 前 frozen/live VERSION 与 current release id 已打印留证。
- [ ] `SBMON_KEEP_RELEASES` 仅对 D2 进程设置为 pre-D2 release count + 1。
- [ ] monitor `upgrade --repair` 以 `action=repair` 成功，live release 已切换，monitor active、HTTP 200。
- [ ] D2 后 baseline release 目录仍存在；config/sing-box fail-fast gate PASS。
- [ ] sbox-cm 安装后 socket/service 都是 disabled/inactive；独立 daemon-reload PASS。
- [ ] D3 后、D4 前 config/sing-box 第二次 fail-fast gate PASS。
- [ ] 只执行了 `systemctl enable --now sbox-cm.socket`。
- [ ] first RPC 前 service 明确为 disabled/inactive。
- [ ] `E3_M3_VERIFY=PASS`，其中 V01/V03/V06/V07/V10/V11 全部可见。
- [ ] config SHA/size before == after。
- [ ] sing-box ActiveEnterTimestamp/NRestarts before == after，service 仍 active。
- [ ] `management.status = inactive`，activation marker absent。
- [ ] socket enabled/active；service disabled 但已由 first RPC 拉起为 active。
- [ ] 没有实际 production client add/delete；负向 add 仅得到 `E_ACTIVATION_STATE`。
- [ ] 没有手工改配置，没有 reload/restart sing-box，没有写 marker。
- [ ] monitor-only rollback 只有在 symlink target、monitor active/enabled、HTTP 200 全部恢复 baseline 时才声明 PASS。
- [ ] 已接受 D2 后任一 interruption 必须检查 7 路径和 `04-sbox-cm-install.log`；只有二者共同证明 D3 未开始才允许 monitor-only rollback，否则 full rollback，并结束本次 Phase 1。
- [ ] 最终四行状态已输出；Phase 2 未开始并在 activation 前硬停止。
