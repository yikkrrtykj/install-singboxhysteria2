# E3 M3 — 部署上线 Runbook（deploy-disabled 阶段：M3-A / M3-B）

```text
状态       : M3-A / M3-B 已交付；M3-C 按三个独立生产阶段推进
适用范围   : 生产 VPS 上的 E3 部署准备 —— 本文档与脚本本身不执行任何部署
阶段       : Phase 1 = production deploy-disabled；Phase 2 = one production canary，结束 inactive；
             Phase 3 = final persistent go-live enablement（独立 preflight 与批准边界）
历史基线   : M3-A/B main = 6bed1bd；后续阶段使用各自 reviewed merge SHA
```

## M3-A — 部署前 preflight（`monitor-v2/deploy/e3-preflight.sh`）

**M3-B v1 = FIRST DEPLOY ONLY（冻结，无 helper-upgrade 路径）**：preflight 发现任何 sbox-cm capability（sbox-cm / sbox-cm-ops / lib/client-management.sh / lib/sbox-cm-state.sh / socket unit / service unit 任一存在）即 FAIL，提示 `existing sbox-cm deployment requires a separately reviewed upgrade path`。残留的 `/var/lib/sbox-cm` state/audit 树单独存在是允许的（审计记录），但 marker 必须不存在且 owner/mode 必须安全。**残留的 `/run/sbox-cm/sbox-cm.sock`（stale runtime socket）属于 leftover capability，preflight 直接 FAIL。**present-helper 的升级路径不在本版本内，需另行设计评审。

只读。唯一写动作是显式要求的 `--baseline-out FILE`（供 verify/rollback 对照），且 **baseline 仅在全部检查 PASS 后原子写入（tmp+mv，mode 0600）**——任何 FAIL 都不会创建或覆盖既有 baseline。

```bash
sudo bash monitor-v2/deploy/e3-preflight.sh --baseline-out /root/e3-baseline.json
```

检查项（每项独立 PASS/FAIL，任一 FAIL ⇒ `E3_PREFLIGHT=FAIL`，退出码 1）：

| # | 检查 |
| --- | --- |
| P01 | `$E3_MONITOR_APP` 必须是 **symlink**，readlink -f 可解析、target 目录存在、release id 非空；VERSION / webapp.py 在 release 内 |
| P02 | `sing-box.service` active |
| P03 | `singbox-monitor.service` active |
| P04 | 记录当前配置 SHA256 + size（`/root/sbox/sbconfig_server.json`） |
| P05 | `sing-box check -c` 当前配置通过（只读，不落任何文件） |
| P06 | monitor 只读 HTTP `/api/v1/session` 200 |
| P07 | sboxweb user/group 存在 |
| P08 | `/root/sbox` 存在、root 属主、配置在内 |
| P09 | `/var/lib/sbox-cm` owner+group+mode = root/root/0700（不存在则记 INFO） |
| P00 | sbox-cm capability 必须完全 absent（6 个路径逐一检查）；任何一项存在 ⇒ FAIL（first-deploy-only freeze） |
| P10 | `/run/sbox-cm/sbox-cm.sock` 必须不存在；任何已有路径（即使 root:sboxweb 0660）均视为 stale runtime capability 并 FAIL |
| P12 | `/` 与 `/var` 可用空间 ≥ 1024 MB |

baseline 写入（仅全部 PASS 后）：umask 077 + 同目录 mktemp + 写入 + chmod 0600 + jq 校验成功 + 原子 mv——失败绝不覆盖既有 baseline。baseline 冻结 `monitor.release_id/release_target`（live symlink）与 helper 部署前状态（全 false）。
| P13 | systemd 整体 running（degraded 记 INFO 放行） |
| P14 | activation marker **不存在**（部署要求平面处于关闭默认态；存在 ⇒ FAIL） |

保底：脚本除 baseline 输出外零写动作；`sing-box check` 用 `-c` 只读现配置；
systemctl 仅用 is-active/is-enabled/show 等只读查询。

## 生产 packaging layout（M3-B 依赖的真实布局）

```text
/opt/singbox-monitor                    -> /opt/singbox-monitor-releases/<release-id>
<release>/VERSION
<release>/app/monitor-v2/webapp.py      <- runtime entrypoint
<release>/app/monitor-v2/{web,api_bridge}/, collector.py, ...
<release>/bin, <release>/lib
<checkout>/monitor-v2/deploy/e3-rollback.sh
<checkout>/monitor-v2/deploy/install-monitor.sh  <- rollback tooling 的同目录 sibling
```

`E3_MONITOR_APP` = release symlink 根；runtime = `$E3_MONITOR_APP/app/monitor-v2`。preflight 检查 `<release>/VERSION` 与 `<release>/app/monitor-v2/webapp.py`；verify 的 sboxweb RPC probe 从 `app/monitor-v2` 导入 `web.e3rpc`。

## M3-B — deploy-disabled 部署与验收

### 部署步骤（均不打开管理面）

```text
D1  预跑 M3-A preflight，留存 /root/e3-baseline.json；
D2  打包并安装新 monitor release（既有 install-monitor.sh，release-symlink 原子切换）；
D3  安装 sbox-cm（install-sbox-cm.sh install —— 默认 disabled/inactive）；
D4  systemctl enable --now sbox-cm.socket（**只 enable socket**；service 保持 inactive，
    由第一次 RPC 经 socket activation 拉起——验收顺序见 V05a/V05b/V07）；
D5  跑 M3-B 验收（e3-deploy-verify.sh --baseline /root/e3-baseline.json）。
```

部署后必须保持 `management_state = inactive`。D4 只 `enable --now sbox-cm.socket`
（service 由第一次 RPC 经 socket activation 拉起）。验收项（`E3_M3_VERIFY=PASS`）：

```text
V05a  仅要求 sbox-cm.socket active（service 允许 inactive）
V05b  在 V07 的真实 sboxweb RPC 成功之后，要求 sbox-cm.service active
      —— 证明 socket activation 真正拉起了 daemon
```

```text
V01/V02  配置 SHA256 + size 与 baseline 完全一致
V03      sing-box 未被部署触发重启（ActiveEnterTimestamp + NRestarts 与 baseline 一致）
V04      monitor active + 只读 HTTP 200
V05      sbox-cm.socket/.service active（能力在场）
V06      activation marker 不存在 ⇒ 管理面 inactive
V07      sboxweb 上下文 RPC management.status = inactive
V08      sboxweb 上下文 RPC client.list 可读
V09      Web E3 UI 可加载（index + app.js 200，clients 表在页面中）
V10/V11  inactive 下 mutation fail-closed：add 尝试被 E_ACTIVATION_STATE 拒绝
         （helper 在 intent 之前拒绝 ⇒ 零变更，仅留下一条 rejected 审计），
         且拒绝后配置 SHA 不变
```

### 回滚（`monitor-v2/deploy/e3-rollback.sh --baseline /root/e3-baseline.json`）

回滚是 **fail-closed** 的编排：installer 缺失或不可执行、目标 release 缺失、rollback 命令失败、disable 失败、daemon-reload 失败、恢复后 live release id 与 baseline 不一致——任何一步失败 ⇒ `E3_M3_ROLLBACK=FAIL`。**rollback target 唯一来源 = `baseline.monitor.release_id`，不提供任何 override。**

rollback tooling 与 `install-monitor.sh` **必须来自同一个 checkout/source tree 的同一 deploy 目录**（脚本用 `BASH_SOURCE` 解析自身目录作为默认 installer 路径，不再假设 `/opt/...` 下存在该脚本；测试可用 `E3_INSTALL_MONITOR` override）。

```text
R1  关闭特权面：stop+disable sbox-cm.socket（socket 会按连接拉起 service，
    必须先停），再 stop+disable sbox-cm.service；
R2  恢复 monitor release：target **唯一来源 = preflight baseline 的
    monitor.release_id**（不提供 override，不从 releases.history 推断，不从任何其它来源猜测）。
    installer 缺失 / target release 目录不存在 / rollback 命令失败 /
    恢复后 live release id 与 baseline 不一致 ⇒ E3_M3_ROLLBACK=FAIL；
R3  卸载本轮新装的 helper 能力：删除两 unit 与整个 libexec，检查 daemon-reload
    成功，并确认 6 个 capability 路径及 runtime socket 全部消失；state/audit 树
    明确保留（审计记录绝不静默清除）；
R4  验证 monitor 只读 HTTP 恢复 200、配置 SHA256 与 preflight baseline 完全一致、
    activation marker 不存在。全程不触碰 /root/sbox 配置与 sing-box 服务。
```

M3-B v1 只有这一条回滚路径：preflight 已证明 helper capability 在部署前完全
不存在，因此 rollback 只做本轮首次安装的精确逆操作。任何 existing/partial helper
都会在 preflight 阶段 FAIL，不进入部署，也不存在“恢复既有 helper active/enabled
状态”的分支。baseline 的 monitor rollback target 取自 live symlink 的 exact
`release_id`，不从 history 或其它来源推断。

## M3-C — 分阶段生产 rollout

- Phase 1 已实现为 production preflight + deploy-disabled，终态 inactive。
- Phase 2 已实现为一次 production canary：activate → list → add/delete →
  deactivate，并恢复 exact inventory，终态 inactive。
- Phase 3 是最终 persistent go-live：独立 preflight 后再次硬停止，只有收到
  `enable --approve-go-live` 的明确批准才执行一次 `management.activate`，成功后
  保持 active。正常路径不 add/delete client，不 reload/restart sing-box。

各阶段必须使用自身 reviewed/merged HEAD、证据链、锁和 runbook；任何阶段 PASS
都不会自动串联下一阶段。Phase 3 正式清单见
`docs/e3-m3c-phase3-production-runbook.md`。

## 测试

`tests/e3/test-m3-deploy.sh`（CI 三基线，live fixture）按 first-deploy-only 顺序覆盖：
真实 `app/monitor-v2` release layout、preflight PASS 与实测 baseline、无临时残留、
marker 已存在 / 配置 check 拒绝 / monitor 非 symlink / `root:sboxweb 0660` stale
socket / existing helper / partial helper 等 preflight FAIL，以及失败时不创建或覆盖
baseline。随后执行真实 helper installer、socket-only D4、pre-RPC service inactive、
post-RPC service active、verify PASS（inactive mutation fail-closed、配置不变、
sing-box 未重启）与配置被改时 verify FAIL。rollback 覆盖 exact baseline release、
helper absent、state/audit 保留、配置不变及 monitor 存活；missing/non-executable
installer、目标 release 不存在、disable 失败和 daemon-reload 失败均必须 FAIL。
套件以 `EXPECTED_TOTAL=53` 冻结 PASS+FAIL+SKIP 总数，防止断言静默消失。
