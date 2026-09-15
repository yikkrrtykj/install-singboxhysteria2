# Monitor v2 — Packaging / Installer / Deployment Track（skeleton）

状态：**runtime 已接线（Integration Round 1，Draft PR）**。E2 Web Dashboard 已由本部署骨架
真实启动（`SBMON_MODE=web` 默认）；E3（特权 helper）在并行对话开发，
本分支**不实现、不伪造**它们的任何路径；只提供可运行的部署骨架、幂等 helper、测试与设计文档，
最终由 integration 对话接上。

- 基线：`main @ 3c6120441ee99c74faeb41a8122897395b2d7c94`（PR #10 merge 后）
- 分支：`feature/monitor-packaging`
- 本文所有结论以 main 实际代码为准（逐项注明出处），不是凭记忆。

## 兼容性预检与环境诊断（三 Ubuntu LTS 基线）

支持基线：Ubuntu 22.04 / 24.04 / 26.04 LTS（support matrix 见
`monitor-v2/README.md` §"平台支持矩阵与兼容性策略"）。规则：

- **能力检测，不做发行版版本分支**：install / upgrade / rollback / uninstall
  在任何变更前运行 `sbmon_preflight_commands`（deploy lib）——必需命令
  `python3` / `systemctl` / `journalctl` / `jq` / `ss` / `flock` / `stat` /
  `sha256sum` / `mktemp`（可经 `SBMON_REQUIRED_COMMANDS` 覆写；配置的包装器
  `SBMON_PYTHON3` / `SBMON_SYSTEMCTL` / `SBMON_FLOCK` 按自身检查）。缺失
  依赖 = 带清晰诊断 fail-closed，未做任何更改。运行时入口
  （`monitor-service` / `monitor-health`）经 `monitor_env_require_commands`
  执行同一 fail-closed 预检。
- **环境诊断无泄密**：install 路径记录 `/etc/os-release`（ID + VERSION_ID）、
  `python3 --version`、`systemd --version` 首行、`uname -r`；存在 `ssh` 时
  记录 `ssh -V`。绝不记录 conf 值 / secret / 快照内容。
- **systemd unit 可移植子集**：unit 硬化指令取三个基线 systemd 都支持的
  子集。CI 分两级：`systemd-analyze verify` 是**全部基线的硬门**（任何
  "unknown/unsupported directive" 判失败，安全关键指令绝不静默忽略）；
  `systemd-analyze security --offline=yes` 按能力检测——支持的基线上**硬性
  执行**，不支持的基线上明确标注为 informational-only（绝不静默软通过）。
- **journal 时间兼容（B6 实机发现）**：Ubuntu 22.04 `journalctl --since`
  拒绝 raw RFC3339（`...T...Z`）；内部时间戳保持 RFC3339/UTC，传给
  journalctl 前经 `tests/lib/journal-time.sh` 规范化为本地
  `"YYYY-MM-DD HH:MM:SS"`。

---

## 0. 当前 installer 审计（main @ 3c61204 实测）

### 入口

| 文件 | 角色 |
| --- | --- |
| `install.sh`（2904 行） | **唯一服务端安装器**。顶部脚本直接执行：已有安装标记 → 进入 0–10 管理菜单；否则走全新安装。管理快捷方式 `/root/sbox/mianyang.sh` → `ln -sf` 到 `/usr/bin/mianyang`，内容是重新 `curl | bash` 本脚本 |
| `install-linux-gateway.sh`（603 行） | **客户端** mihomo TUN 网关安装器（另一台机器），自带 `--restore` 备份恢复、`/var/backups/mihomo-gateway` 备份根。与服务器栈无关，但它的备份/参数/`set -Eeuo pipefail` 风格是本项目内已有的部署工程先例 |

### 安装路径（全部硬编码在 `/root/sbox`）

| 路径 | 作用 | 出处（install.sh） |
| --- | --- | --- |
| `/root/sbox/sing-box` | 内核 binary；升级时 `sing-box.new` 候选 → check → `sing-box.backup-<ts>` → 原子 mv | `install_singbox` |
| `/root/sbox/sbconfig_server.json` | **唯一事实源**服务端配置（注释明言 "no clients.json"） | `SB_SERVER_CONFIG` |
| `/root/sbox/config` | 平面 KEY='VALUE' 状态文件（SERVER_IP/PUBLIC_KEY/HY_*） | `SB_STATE_FILE`、`set_config_value` |
| `/root/sbox/clients/<name>/mihomo.yaml` | 全部是**派生物** | `SB_CLIENTS_DIR` |
| `/root/sbox/self-cert/` | hy2 自签证书 | 新装流程 |
| `/root/sbox/config.lock` | Phase C/D 事务 flock（现状 fail-open，S0 分支负责加固） | `with_client_lock` |

### systemd 服务

| unit | 要点 |
| --- | --- |
| `/etc/systemd/system/sing-box.service` | `User=root`、`WorkingDirectory=/root/sbox`、CAP_NET_ADMIN/BIND_SERVICE/RAW、`After=network.target nss-lookup.target`、`Restart=on-failure` + `RestartSec=10`、`LimitNOFILE=infinity` |
| `/etc/systemd/system/sing-box-hy2-hopping.service` | `After=network-online.target sing-box.service`、`PartOf=sing-box.service`、iptables NAT 端口跳跃 |

另有 `restart_singbox`/升级路径的守卫：检测到手工 `pgrep sing-box` 时拒绝启动第二个实例。

### service.api（Phase D 锚点）

- 全新安装直接写入 `services[].type=api, tag=monitor-api, listen=127.0.0.1:9091`；
- `phase_d_api_service_exact` 以 jq 精确锁定 tag/listen/port；`phase_d_inject_api_service` 幂等注入；
- 常量：`PHASE_D_API_LISTEN=127.0.0.1`、`PHASE_D_API_PORT=9091`（本骨架的 `SBMON_API_URL` 默认值与其对齐）。

### 菜单架构

单一顶层菜单（0–10）+ 子菜单：`process_singbox`（基础操作 0–5）、`client_management_menu`（Phase C）、
`process_doko/dokoko/ssko`（任意门/SS 解锁）、`process_hy2hopping`（端口跳跃）。全部交互式 `read`。
**未来 Monitor/Web Dashboard 的接入点 = 顶层菜单新增选项**（本分支不改 install.sh，见 §7）。

### Phase C / Phase D 集成

- Phase C：flock → 结构审计 → candidate → `sing-box check` → backup → 原子 mv → reload（systemctl reload，手工进程回退 kill -HUP）→ 健康检查；`audit_client_consistency`；legacy 迁移。
- Phase D：同一把锁下的完整升级事务：身份审计 → 1.14.x stable 候选（拒绝 prerelease）→ check → 双备份（bin+cfg）→ 原子替换 → restart → `phase_d_health_ok` → 双回滚。`update_singbox` 即此事务入口。
- 卸载：`uninstall_singbox` —— 拒绝手工进程运行时卸载；disable hy2 hopping（清 iptables）；`disable --now sing-box`；删除 unit + binary + 配置 + 状态 + 证书 + 快捷方式；`rm -rf /root/sbox`。
- 备份：`backup_current_installation` → `/root/sbox-backup-<ts>.tar.gz`（0600）+ sha256；新装守卫 `has_any_installation_marker` 对不完整安装 fail-closed，破坏性重装需输入 `REINSTALL` 且先做全量备份。

### Monitor v2 现状（E1，已 merge）

`monitor-v2/collector.py`：纯标准库 Python，官方 gRPC-Web 事件流，`Device = API USER`，
secret 仅走 `BOX_API_SECRET`/`--secret-file`（0600），输出统一 `[redacted]`，**只读、无监听、无守护模式**
（`--once`/`--duration`，stdout JSON）。E3 设计分支（rev4）已定：Web 非 root 用户 `sboxweb`、
spool `/var/lib/sbox-cm/spool/`、helper `/usr/local/lib/sbox-cm/sbox-cm` + 单条 sudoers 规则。

---

## 1. 最终文件布局（设计与理由）

```text
/opt/singbox-monitor                      → 符号链接 → /opt/singbox-monitor-releases/<id>
/opt/singbox-monitor-releases/
  <version>-<timestamp>/                  ← 不可变 release 树（root:root 0755/0644）
    VERSION
    app/monitor-v2/                      ← 唯一的服务端运行时树（R1）
      collector.py                       ← E1 collector（唯一一份，无第二个 runtime 树）
      api_bridge/
      webapp.py                          ← E2 真实入口（setup / serve）
      web/{*.py, static/*}               ← E2 后端 + 静态资源
    bin/monitor-service                  ← 运行入口 shim（见 §4）
    bin/monitor-health                   ← 健康探测（见 §6）
    lib/monitor-env.sh
/var/lib/singbox-monitor/                ← sboxweb:sboxweb 0700（E2 DATA ROOT, R1）
  auth.json                             0600  E2 管理认证（admin 口令哈希、recovery key）
  access.json                           0600  E2 白名单（IP/CIDR）
  state/                                0700  运行时文件
    health.json                               broker 健康导出（最小白名单字段，R1-6）
    snapshot.json                             collector-loop 兼容模式的快照
/etc/singbox-monitor/                    root:root 0755
  monitor.conf                           root:sboxweb 0640（服务用户只读）
  api.secret                             root:sboxweb 0640（由 install 从 S0 anchor 派生）
/etc/systemd/system/singbox-monitor.service
/var/backups/singbox-monitor/            root 0700（手工备份位；release 保留本身即回滚备份）
```

**为什么这样放（与任务书提案的差异全部在此说明）：**

1. **`/root/sbox` 之外是硬约束**：`uninstall_singbox` 会 `rm -rf /root/sbox`。Monitor 放进去等于把
   自己的生死交给了代理卸载流程；反向亦然（Monitor-only uninstall 绝不允许碰 `sbconfig_server.json`）。
   两棵树完全分离，靠"互不引用"保证（测试静态断言 deploy 代码中不出现这两个字符串）。
   **唯一例外（review round 1 P6）**：S0 secret bridge 只读 S0 anchor
   `/root/sbox/monitor-api.secret`（root:root 0600，永不 chmod/chgrp/改写它）——
   测试对该路径做了精确豁免，并断言 deploy 代码中该引用恰好出现一次。
2. **release 树 + 符号链接**（对任务书 `/opt/singbox-monitor/app` 平铺的偏离）：任务 7 要求
   "stage → 备份旧版 → **原子**切换"。平铺目录的切换至少要两次 rename，中间窗口是断的；
   `mv -T` 一个符号链接是单次 rename(2)，读侧要么旧要么新。旧 release 目录保留在
   `releases/` 里本身就是回滚备份（零拷贝），`rollback` 只是改回链接 + 重启 monitor。
3. **`/opt` vs `/usr/local/lib`**：E3 设计把 helper 放 `/usr/local/lib/sbox-cm/sbox-cm`（helper 是
   单文件 sudo 程序，合理）；监控应用是"一个前缀下的应用包"，FHS 惯例 `/opt/<package>`。
   两者不冲突。
4. **`/etc/singbox-monitor/monitor.conf` 0640 root:group**：任务 4 要求 Monitor "只 read 自己配置、
   不 write"。组可读、他人不可读、服务用户不可写 —— E2/E3 的配置变更必须走 root/特权桥，不是
   Web 进程自己改文件。
5. **data root 0700 + 扁平文件（R1-3 收敛）**：E2 的事实模型是 `<data-root>/auth.json` /
   `<data-root>/access.json` 两个扁平文件（`ensure_private_dir` 把 data root 收紧到 0700），
   `state/` 放运行时文件。旧安装上遗留的 `auth/`、`access/` 目录**按原样保留、绝不删除或改用途**
   （migration-safe convergence，不是 destructive cleanup）；新安装不再创建它们。
   auth.json / access.json 从不由 install/upgrade/repair/rollback 覆盖。
   它们仍是 E2 的隐私面（口令哈希、recovery key、白名单），只 owner 可进。
   **R1.1-A 权限边界**：`/var/lib/singbox-monitor` 的父目录 `/var/lib` 由 root 控制，所以 root
   只安全地创建/确认**顶层 data root**（必须是真实目录，symlink / 非目录一律 fail-closed）并把它
   收敛为 `sboxweb:sboxweb 0700`。其下一切（`state/`、auth.json …）都在 **sboxweb 拥有的目录**里，
   sboxweb 可以随时替换其中的 child entry，因此 root **绝不对这些 child pathname 做
   chown/chmod**（`check -> chmod/chown` 的 TOCTOU + symlink-follow 会被升级为提权原语，
   仅加 `[ ! -L path ]` 不能修复）。`state/` 的创建与 mode 收敛改为 `sbmon_ensure_state_tree_as_service_user`
   **以 sboxweb 身份**执行；即便 check 与 mutation 之间存在 race，mutation 本身也只在 sboxweb
   权限下运行，无法形成 root 提权。不做整个 data root 的递归 chown/chmod。
6. **VERSION 放在 release 树内**：`upgrade` 判定、`status`、health 都读激活树里的 VERSION，
   单一事实源。

## 2. 用户模型（非 root；round 1 P5 定案 = sboxweb）

```text
系统组  sboxweb          (system, nologin)
系统用户 sboxweb         (system, gid=组, home=/var/lib/singbox-monitor, shell=/usr/sbin/nologin)
```

**P5 定案**：runtime 身份直接采用 E3 rev4 已 approved 的非特权用户 `sboxweb`；产品名 /
service 名（singbox-monitor.service）/ 路径（/opt、/var/lib、/etc 下的 singbox-monitor*）
保持不变——用户名与产品名不需要相同。这样 E3 落地时 spool（root:sboxweb 0710）、
sudoers、exact-token 读权直接复用，不需要迁移 service identity。

- Monitor 今天需要的能力全集：**connect 127.0.0.1:9091 + bind 127.0.0.1:9191（>1024，非特权）+
  读 /etc/singbox-monitor + 写 /var/lib/singbox-monitor**。零 capability → unit 里
  `CapabilityBoundingSet=`（空）。没有以 root 运行的任何硬性理由。
- 只读面/写面的精确切分：代码（/opt）root 只读；配置（/etc）root 写、服务用户读；状态（/var/lib）
  服务用户写。E2 的 read-only Monitor 天然**不拥有** `sbconfig_server.json` 的写权、无 root shell、
  连路径都不可达（`ProtectHome=true` 下 /root 不可见，见 §3）。
- **E3 特权桥设计预留**（不实现）：read-only web 进程 → 需要变更时 → 极窄 privileged helper
  （E3 设计 rev4 的单条 sudoers + verb allowlist + 账本模型）。本骨架把它留成边界：
  Web 用户（见下方命名对齐）将来加入 helper 的 sudoers 目标，helper 独占 config.lock 写权。
  **绝不能**是 "整个 web server 跑 root"。
- 实现上仍是单一常量 `SBMON_USER`/`SBMON_GROUP`（默认 sboxweb），测试断言
  `User=sboxweb` / `Group=sboxweb`。

## 3. systemd 模型（任务 5）

`singbox-monitor.service`（模板 `deploy/singbox-monitor.service.in`）：

- `After=network-online.target sing-box.service` + `Wants=network-online.target`，
  **无 `Requires=sing-box.service`**：`After=` 只是排序。sing-box 启动失败不会拖垮 boot，
  也不会阻止 monitor 启动 —— collector 把不可达流当 stale、持续重连（E1 语义），这正是任务 12
  要的"两个健康信号分开"的运行时基础。
- `Restart=on-failure` + `RestartSec=5s`；`TimeoutStopSec=15s`（collector 周期内可被 TERM 打断）。
- `UMask=0077`（round 1 P8）：snapshot/temp/runtime 文件默认私有。
- `ExecStart=.../monitor-service <conf> <data-root>`（R1-2）：**data root 是显式
  contract**，unit、CLI（install-monitor.sh health/status）都显式传值；`WorkingDirectory` 只是
  便利，不是正确性/安全性事实源。
- 加固逐项（每项都对应真实需求，不是堆砌）：
  - `NoNewPrivileges`：永远不得提权（E3 桥是独立 sudo 路径，不是 web 进程自己提权）；
  - `ProtectHome=yes`：/root、/home 不可见 —— 物理上读不到 `/root/sbox`，误配置也无效；
  - `ProtectSystem=strict`（M0.5 G4，原 `full`）：整个层级只读（/dev、/proc、/sys 除外），
    唯一可写例外由 `ReadWritePaths=@SBMON_STATE_ROOT@` 精确给出 = monitor 自己的 data root；
    `/root/sbox` 与 root-only 的 sbox-cm 运行时目录既不可写也不可读；
  - `PrivateTmp`、`PrivateDevices`：monitor 不需要 /tmp 共享与任何设备；
  - `ProtectKernelTunables/Modules/Logs`、`ProtectControlGroups`：观察者不需要内核接口；
  - `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`：**刻意不收敛为 AF_UNIX-only** ——
    monitor 既 connect 127.0.0.1:9091 又 bind 127.0.0.1:9191（AF_INET/AF_INET6），
    未来还要 connect `/run/sbox-cm/sbox-cm.sock`（AF_UNIX）；只有 sbox-cm 才能做到纯 AF_UNIX，
    两个 unit 的 address-family 合同分开；
  - `CapabilityBoundingSet=`（空）、`AmbientCapabilities=`：零 capability；
  - `RestrictSUIDSGID`、`RestrictRealtime`、`LockPersonality`、`SystemCallArchitectures=native`：常规面收窄。
  - **没有** `MemoryDenyWriteExecute`（CPython 不需要，但不为骨架引入不必要的兼容风险）；
  - **唯一** `ReadWritePaths=` 例外 = `@SBMON_STATE_ROOT@`（M0.5 G4；`ProtectSystem=strict`
    下这是 monitor 唯一的写面，绝不额外打开 `/root/sbox` 或 sbox-cm 运行时目录）。
- 日志：stdout 的生命周期消息进 journal；**collector 的 snapshot JSON（含客户端元数据）重定向到
  0700 状态目录，绝不进 journal**（任务 11，见 §6）。

## 4. 运行入口（shim）与模式

`bin/monitor-service`（bash，严格模式，conf 解析无 eval/source）：

- `SBMON_MODE=web`（**默认，真实可用**，R1-3）：exec 真实入口
  `app/monitor-v2/webapp.py serve`——**一个** E1 Collector → **一个** SnapshotBroker →
  loopback web 监听 + `state/health.json` 健康导出。整个运行时只有一个 collector、
  一个 service.api 流消费者；不存在为 health 或 packaging 另起的第二个 collector。
  web 模式 fail-closed 前置条件：`SBMON_API_SECRET_FILE` 必须已配置且是**存在、普通文件
  （非 symlink）、可读、非空**；exec 前 `unset BOX_API_SECRET`（secret 只经文件传递，
  绝不进 unit 文件/argv/journal）；`SBMON_WEB_BIND` 必须是 loopback 形式（IPv4/IPv6/localhost），
  `0.0.0.0`、LAN/公网地址、畸形端口一律拒绝启动。**R1.1-D**：`SBMON_WEB_POLL_SECONDS` 必须是
  **有限浮点且 > 0**（`monitor-env.sh` 用 Python `float` 解析，而非 Bash 字符检查）；`0`/`0.0`/
  负数/`NaN`/`inf`/`Infinity`/`.`/`1..2`/乱码都 fail-closed，**在 exec webapp 之前**退出
  （`0` 会让 SnapshotBroker publisher 的 `wait(0)` 变成 tight loop）；缺省（键不存在）为 `1`。
- `SBMON_MODE=collector-loop`（**兼容模式**，显式启用）：循环跑 E1 collector——首拍 `--once`
  （秒级拿到 reset 权威快照），此后每拍 `--duration $SBMON_CYCLE_SECONDS`；stdout 原子写
  （tmp + mv）到 `state/snapshot.json`。流失败 → 暂停 5s 重连；每次新订阅的第一条消息就是全量
  权威 reset，无需外部持久化即可重建。这不是伪造 E2，是 E1 唯一诚实的服务化形态。
- Web 管理入口（首次配置）：`install-monitor.sh web-setup`——以 `sboxweb` 身份运行已评审的
  `webapp.py setup`（交互式口令 + 恢复键），使 auth.json/access.json 不会意外变成 root 属主。
  它绝不自动加入白名单、绝不以明文口令非交互运行、绝不记录口令/恢复键；若服务此前 active，
  成功 setup 后**只重启 singbox-monitor**（不触碰 sing-box）。无人值守安装不会自动跑它。
  - **R1.1-E 干净环境**：production 下先以 root `command -v` 解析 python 绝对路径，再通过
    `env -i HOME=<data-root> PATH=/usr/sbin:/usr/bin:/sbin:/bin SSH_CONNECTION=... <pybin> …`
    运行（`sudo -n -u sboxweb`）。**只有** HOME/PATH/SSH_CONNECTION 被转发；`BOX_API_SECRET`、
    token/cookie、任意调用者环境一概不继承；口令/恢复键绝不进 argv / env / journal / 安装日志；
    stdin/stdout/stderr/TTY 保持（setup 是交互式的）。
  - **R1.1-B 无 root 改动**：setup 成功后**删除**了原先对 data root 及 auth.json/access.json 的
    root `chown`/`chmod`。属主/权限由 E2 storage/setup 自己保证（data root `sboxweb:sboxweb 0700`，
    auth.json/access.json `sboxweb:sboxweb 0600`）；安装器只做**非破坏性**后置校验
    （`sbmon_verify_service_owned_tree`），一旦漂移即 fail-closed 并给人工修复提示，**绝不自动
    "救回"** root 属主的数据。setup 失败信息也改为诚实表述（可能已完成部分持久化写入），且
    **不会**因此重启 Monitor。

### 访问 loopback-only dashboard（SSH 端口转发）

web 默认只监听 `127.0.0.1:9191`，**不**对公网开放。从工作站访问的推荐方式
（Windows / Linux / macOS 通用）是 SSH 本地端口转发：

```bash
ssh -L 19191:127.0.0.1:9191 root@SERVER_IP
```

保持该 SSH 会话打开，然后在浏览器访问 `http://127.0.0.1:19191`。

可选的纯隧道形式（`-N`）：`ssh -N -L 19191:127.0.0.1:9191 root@SERVER_IP`。
注意部分 SSH 服务器/服务商环境会终止 `-N` 的纯转发（无 shell）会话；此时改用
上面的普通 shell 形式，或加 keepalive：

```bash
ssh -N \
  -o ServerAliveInterval=10 \
  -o ServerAliveCountMax=6 \
  -o ExitOnForwardFailure=yes \
  -L 19191:127.0.0.1:9191 \
  root@SERVER_IP
```

不要把修改 `sshd_config` 当作常规解法（保持服务器 SSH 配置原样）。

**白名单行为**：`127.0.0.1` / `::1` 隐式放行，因此 SSH 端口转发访问**不需要**
把公网 SSH 来源 IP 加入白名单——隧道连接在 Monitor 看到的对端地址就是 loopback。
在 web-setup 期间回答 "n" 且从未写入过白名单条目时，`access.json` 可能不存在，
这是合法状态，不是错误。web-setup 成功后打印的非敏感访问提示遵守同一契约：
不打印/推断服务器公网 IP、不打印秘密、不自动加白名单、不暴露 9191、
不修改防火墙或 sshd 配置。

- web 进程存活性（systemd active）与 service.api 连通性从第一天就是两个信号（§6）。

## 5. 安装语义（任务 6：fresh / upgrade / repair / uninstall 严格区分）

`install-monitor.sh install`（= converge，幂等）：

| 判定 | 动作 |
| --- | --- |
| 无激活 release | **fresh**：建用户/组 → 建目录 → 写默认 conf（仅首次）→ stage → 激活 → 装 unit → enable --now → 等待激活 → 汇报 health |
| 激活版本 == 仓库 VERSION | **noop**：只修权限；`--repair` 则重 stage 同版本代码（配置/状态仍然不动） |
| 仓库 VERSION 更新 | **upgrade**：新 release 树 → 校验 → 备份历史 → 原子切换 → **只重启 singbox-monitor** → 等待激活，失败自动回滚（§7） |
| 仓库 VERSION 更旧 | 拒绝（fail-closed）；`--allow-downgrade` 显式放行 |
| unit 内容变化 | 旧 unit 备份为 `.bak.<ts>` 后更新 + daemon-reload |

**永不发生**（任何路径）：覆盖 `monitor.conf`、重置 auth/access/state、触碰防火墙、
触碰 `/root/sbox`（含 proxy 凭据/密码/recovery key/whitelist）、重启 sing-box。

**round 2 F2 — fresh install 失败的清理契约**：首次部署没有旧状态可回滚；candidate
启动失败时：删除 live 符号链接、删除新建 unit、daemon-reload、恢复 disabled + inactive；
**保留不可变的 release 树**供排错。绝不留下 active release 或 enabled 的坏服务。

**round 2 F1 — history 是 commit record**：`releases.history` 只在服务门通过（部署成功）
后写入；失败候选、已回滚候选、部分部署候选**绝不进入**成功 release history，因此
`rollback` 的目标选择永远不可能选中失败候选。如需失败审计，将来单独建
failed-attempt log，不污染回滚目标集。

`uninstall`（任务 9，默认保留）：

```text
uninstall                    → 停止+disable、删 unit、删 /opt 链接与 release 树
  默认保留: /var/lib/singbox-monitor（auth.json/access.json/state，以及旧安装遗留的 auth//access/ 目录）、
  /etc/singbox-monitor、/var/backups
  --purge-state             → 追加删除 /var/lib/singbox-monitor
  --purge-config            → 追加删除 /etc/singbox-monitor
  --purge-backups           → 追加删除 /var/backups/singbox-monitor
```

- **Monitor-only uninstall 永不**删除 `sbconfig_server.json`、客户端凭据、sing-box binary
  （deploy 代码里不存在这些路径，测试静态断言）。
- **full proxy stack uninstall = 现有 `uninstall_singbox` + `uninstall --purge-state --purge-config`**
  的组合（文档定义；install.sh 菜单接线留给 integration 对话，见 §8）。
- 任务 9 的"默认保留 auth/access/state？"：默认**保留**（可 `--purge-state`），
  PR review 时如需反转只改默认值 + 测试。

## 6. 日志红线与健康模型（任务 11 / 12）

**journal 红线**（UUID、HY2 password、API secret、admin password、recovery key、session token、
generated YAML —— 一个都不许出现）的实现方式：

1. 这些秘密**本来就不在** monitor 的文件系统可见范围内（/root/sbox 不可达、conf 里只有路径没有秘密）；
2. snapshot JSON（含 USER 名/来源 IP/连接 id 等元数据）写 0700 状态文件，stdout 不进 journal；
3. `api.secret` 由管理员放置（S0 负责供给），collector 走 `--secret-file`，E1 契约已保证 secret
   不进 argv/日志/异常/JSON；
4. deploy/shim 自身的输出只含路径与状态词。测试用假秘密值全量扫描 stdout/stderr/unit 文件验证。

**健康 = 分离信号，绝不合并成一个 health=true**（`bin/monitor-health <conf> <state-dir>`
输出单行 JSON；state-dir 是显式参数，round 1 P1：管理员在任意 cwd 下跑
`install-monitor.sh health/status` 都读同一个 snapshot，绝不从 `$PWD` 推断）：

```json
{"service_active": true|false,     ← web/collector 进程存活（systemd）
 "api_url_valid": true|false,      ← SBMON_API_URL 满足 loopback http contract（round 1 P7）
 "api_reachable":  true|false,     ← sing-box service.api TCP 可达（loopback）
 "snapshot": {"present": bool, "age_seconds": N,
              "wellformed": bool,
              "collector_stale": bool,   ← round 1 P2：E1 snapshot JSON 顶层 stale 字段
              "age_stale": bool,         ← 文件 mtime 超过 2×CYCLE+30s
              "stale": bool},            ← final = malformed ∨ collector_stale ∨ age_stale
 "broker_health": {             ← web 模式：只读 <data-root>/state/health.json（最小记录）
   "present": bool, "wellformed": bool, "age_seconds": int, "age_stale": bool,
   "collector_stale": bool, "consumer_alive": bool, "stale": bool},
 "web_http": "ok"|"unavailable"|"not-applicable",   ← web 模式的未认证 loopback 身份探针（R1.1-C）
 "mode": "web", "overall": "healthy|degraded|unhealthy"}
```

- **P2 语义陈旧**：E1 contract 是"流/API/auth 失败 → 保留 last state → stale=true，
  collector 仍正常输出 snapshot"——所以**文件 mtime 新鲜 ≠ collector 健康**。
  final stale 必须组合：malformed JSON（按 stale=true + degraded 处理）∨ E1 JSON 顶层
  `stale==true` ∨ age 超限。**TCP 9091 reachable + snapshot stale=true → 绝不 overall=healthy**
  （必测）。snapshot 内容（devices/ids/last_error）绝不进日志或输出。
- `overall` 只是汇总词，字段永远单独可读；
- exit：0 healthy / 1 unhealthy（服务死）/ 2 degraded（活着但 api 不可达/URL 非法/snapshot 陈旧）；
- api 不可达在"sing-box 没起来"时是**正确状态**（degraded，不是 crash）——monitor 的职责就是
  把它显示出来；
- `web_http` 在 collector-loop 模式 `not-applicable`；web 模式对 loopback 执行
  **未认证身份探针** `GET /api/v1/session`（无 admin 口令、无 session cookie、无 CSRF token、
  无 recovery key、无 service.api bearer）。**R1.1-C**：探针要求 **HTTP 200** 且 body 是合法
  **JSON object** 并满足最小稳定 shape（`authenticated` / `whitelist_allowed` 为 bool，
  `version` 为非空 string；可选 `password_configured`/`recovery_configured`/`remote_mode` 为 bool）。
  404/401/403/500、或 200 但 body 非 JSON / shape 不符（例如 9191 上跑着别的程序）一律记为
  **degraded**；body 内容永不出现在探针输出里。
- **R1.1-D**：broker 健康新鲜度窗口由 `ceil(5 * SBMON_WEB_POLL_SECONDS + 15)` 计算（Python），
  不再用 `${WEB_POLL%%.*}` 的整数截断；非法 poll 不会让记录"看起来新鲜"（age_stale=true）。
- web 模式**不读** snapshot.json，只读最小健康记录；`auth.json`/`access.json` 内容
  永不被探针读取或输出。

## 7. 升级 / 回滚模型（任务 7）

```text
【事务状态捕获】old_release_id + 旧 unit 内容（同文件系统临时备份）
                 + old_service_active + old_service_enabled（`systemctl is-enabled` 显式记录，绝不推断）
  → stage（releases/.staging-*，py_compile + bash -n 预验证；失败删 staging，生产树零影响）
  → unit 原子写入（同文件系统 temp → chmod → rename；读者永远看不到半个 unit）
  → activate（mv -T 符号链接原子切换；旧树即备份，retention 按 release-tree creation age 保留最近 SBMON_KEEP_RELEASES=3 个，见 §13）
  → systemctl restart singbox-monitor      ← 唯一被重启的服务；sing-box 无感
  → 门：等待 service_active（默认 20s）

失败（review round 1 P3 + round 2 F2：release + unit + 服务状态作为同一个
deployment transaction 回滚，**无论事务前服务是 active 还是 inactive**）：
  → 恢复旧 release（flip 回 old_id）
  → 恢复旧 unit（原子写回事务前内容；unit 原本不存在则删除新 unit）
  → daemon-reload
  → 恢复 enabled 状态（old_enabled=1 → enable；否则 disable）
  → 恢复 active 状态（old_active=1 → restart + 验证 active；否则 stop + 验证 inactive）
  → 任一步失败 → CRITICAL + exit 2，绝不声称 "rollback complete"

rollback 命令 = 人工版同一动作（可指定 release id）；**成功激活并确认 service active 之后**
才追加 `action=rollback` 历史（round 2 F1：rollback 自身失败不得写成功历史）。

**Round 3 — 最终事务边界**：任何在 live release 激活之后的失败 —— 包括 unit 原子写入、
daemon-reload、服务 start/restart、active 门 —— 都进入同一条回滚路径（forward-apply 内的
helper 只 return nonzero，绝不 exit 穿透事务边界）。Manual rollback 本身也是事务：
target 激活/健康失败时恢复原 release（含 enabled/active 状态），恢复亦失败 → CRITICAL exit 2；
失败的 rollback 不写任何 history。fresh 失败清理同样不吞错：任一步失败 → CRITICAL exit 2，
只有全部恢复成功才声明 "restored to uninstalled state"。runtime 文件目标（monitor.conf、
api.secret）若已存在且不是普通文件（directory/symlink/...）→ fail-closed，绝不跟随或替换。
```

Monitor 升级**默认不得重启 sing-box** —— deploy 代码根本没有 sing-box 操作面；测试记录全部
systemctl 调用并断言无 `sing-box` 字样。若某次升级明确涉及 sing-box 配置（如 service.api secret
供给），那是 Phase D 事务（`upgrade_singbox_1_14`）的职责，走既有流程，不属于本骨架。

## 8. install.sh 菜单接入（deferred hook，本分支不接线）

顶层菜单未来新增（例如 `11. Monitor / Web Dashboard`）→ 调用
`monitor-v2/deploy/install-monitor.sh`（离线本机路径，不走 curl）。**本分支不改 install.sh**：
E2/E3/本分支三线并行，避免对共享文件制造冲突；接线由 Integration Round 1 完成。
"install → sing-box 1.14 → service.api loopback → Monitor collector → Web service → systemd units"
的完整链路现已由 web 模式提供（collector-loop 保留为显式兼容模式）。

## 9. 迁移/测试矩阵（任务 8；`tests/test-monitor-packaging.sh`）

全部在 temporary-root fixture 上运行真实部署代码（SBMON_* 覆盖 + systemctl 录制 mock，
不需要 root，不触碰真机路径）：

| 场景 | 测试 |
| --- | --- |
| 静态隔离：部署代码零引用 `/root/sbox`/`sbconfig_server.json`/生产回滚备份；零防火墙命令 | static checks（注释剥离后扫描） |
| A. 全新 VPS | T01 fresh install |
| D. 重复运行 installer | T02 幂等（conf/状态哈希不变、无多余 release、无状态变更 systemctl 调用） |
| E. upgrade old Monitor | T03 升级（只重启 monitor）、T04 坏包 fail-closed、T05 回滚 |
| Monitor-only uninstall | T06（默认保留 state/config/backups；`--purge-*` 才删） |
| 失败注入：启动失败 | T07（unit 保留可诊断、指向 journal） |
| 健康语义分离 | T08（healthy/degraded/unhealthy 三态 + 字段分离） |
| journal 红线（任务 11） | T09（假 secret/UUID 全量扫描 stdout/stderr/unit） |
| 缺依赖 fail-closed | T10（预检在任何文件系统变更之前） |
| 坏权限修复 | T11（0640 修复、内容哈希不变） |
| B/C. 已有 Phase C/D/E1 server | T12（fixture 代理树哈希全程不变 + systemctl 全程无 sing-box 操作） |
| Web 端口契约（任务 10） | T13（127.0.0.1:9191、永不 0.0.0.0） |
| round 1 P3 事务回滚 | T15（升级门失败 → release+unit+服务一起恢复）；T16（恢复也失败 → CRITICAL rc=2，绝不声称回滚完成） |
| round 1 P4 部署锁 | T17（持锁期间 install/rollback/uninstall 全部 fail-closed；link/unit/history 不变；放锁后可继续） |
| round 1 P1 state path | T08b（从 `/`、`$TMP`、随机 cwd 跑 health → 读同一 snapshot） |
| round 1 P2 语义 stale | T08（fresh+stale:true→degraded；old+stale:false→degraded；malformed→degraded；missing→degraded；**api reachable + stale=true 绝不 healthy**） |
| round 1 P6/P7 service fail-closed | T08c（missing/wrong-type secret → 立即退出；非 loopback/带 path 的 URL → 立即退出；IPv6 `[::1]` 合法接受；secret 值零输出） |
| round 1 web 健康 | T18（broker_health + web_http；未认证 `/api/v1/session`） |
| round 1 web-setup | T19（以 sboxweb 身份跑真实 `webapp.py setup`；只重启 monitor；不自动加白名单） |
| **round 1.1-A 权限边界** | R1.1-A（`state/` 正常 → PASS；`state/` 为 symlink → fail-closed 且 **sentinel 的 uid:gid:mode/内容完全不变**；`state/` 非目录 → fail-closed；失败发生在 release/history 变更之前；既有 auth.json/access.json 字节不变） |
| **round 1.1-B 无 root 改动** | T19（web-setup 函数内无 root `chown`/`chmod`；root-owned symlink sentinel 元数据不变；setup 失败信息诚实、且不重启 Monitor；成功时 auth.json/access.json 为 sboxweb:group 0600） |
| **round 1.1-C 身份校验** | T20（真实 E2 session 200+JSON → healthy；404/401/403/500、200 非 JSON、shape 不符、无监听 → degraded；body 内容不出现在输出） |
| **round 1.1-D poll 契约** | T21（`1/1.0/0.5/2.25` 接受；`0/0.0/-1/NaN/inf/Infinity/./1..2/abc/空` 拒绝且不 exec；service 与 health 同一规则；`ceil(5*v+15)`） |
| **round 1.1-E 干净环境** | T19（注入 `BOX_API_SECRET`/任意 env 对 setup 不可见；`SSH_CONNECTION` 可见；`HOME`==data root；`PATH`==批准路径） |

真机 canary（A/B 场景在真实 VPS 上的冒烟）属于部署验收，不在本 PR 内执行；
production 保持 UNCHANGED。

平台说明：原子切换断言依赖符号链接 rename(2)。无法创建符号链接的平台
（如无特权 MSYS/Git Bash）自动运行精简套件（T01/T06–T10/T12/T13）并显式打 SKIP；
完整套件（T02–T05/T11）由 GitHub Actions（ubuntu-latest）执行（`.github/workflows/monitor-packaging.yml`）。

## 10. 已实现 / 明确 deferred

已实现：目录布局 helper、系统用户 helper（sboxweb）、unit 模板、release staging/原子切换/清理、
版本比较、幂等 install/upgrade/repair/uninstall/rollback/health/status、web + collector-loop 运行形态、
web-setup、
分离式健康探测、S0 secret 派生桥（§11.2）、部署锁与完整事务回滚（§7/§11/§12）、
临时根测试装置（T01–T21 + F/R3/R4 系列 + R1.1-A/B/C/D/E）。

Deferred：E3 privileged helper/sudoers；
install.sh 菜单接线；full-stack uninstall 菜单组合；真机 VPS canary；legacy config mutation lock
integration（modify_singbox/process_doko 等的 config.lock 问题）。

---

## 11. Review round 1 设计补遗

### 11.1 部署串行锁（P4）

- 位置：`/run/lock/singbox-monitor-deploy.lock`（`SBMON_LOCK_FILE` 可覆盖，fixture 用临时根）。
- 覆盖范围：**所有 mutating 命令**（install/upgrade/rollback/uninstall）的整个事务——
  user/dir/conf/secret/stage/unit/flip/restart/rollback/prune/history 全部在同一把锁内；
  `health`/`status`/`history` 只读、不加独占锁。
- 契约（fail-closed，绝不 warn-and-continue）：`flock` 缺失、锁文件打开失败、
  `flock -w` 超时（默认 15s，`SBMON_LOCK_TIMEOUT`）、获取失败 → 在**任何 mutation 之前**中止。
- **round 2 F4**：统一 dispatcher `sbmon_with_deploy_lock <locked-fn>` —— install/upgrade/
  rollback/uninstall 都是"acquire lock → precondition 读 → decision → mutation"同锁完成，
  无嵌套 flock。upgrade 的"已安装"前置检查在**锁内**复核：并发 uninstall 先完成时，
  upgrade 拿到锁后必须失败，**绝不退化为 fresh install**。

### 11.2 S0 service.api secret → 非 root Monitor bridge（P6）

- 不变量：单一事实源仍是 sing-box 配置里的 `service.api.secret`；S0 的 root-side anchor
  `/root/sbox/monitor-api.secret`（root:root 0600）**永不**被 chmod/chgrp/改写；
  绝不为读它而放宽 `ProtectHome`。
- 投递：`sbmon_sync_api_secret`（install 内、部署锁内、任何 release 变更之前调用）派生
  `/etc/singbox-monitor/api.secret`（root:sboxweb 0640，temp + 原子 rename）。
  内容一致 → 不重写、无 mtime churn；内容漂移 → 原子修复；写失败 → 安装中止（零变更）。
- fail-closed：conf 声明了 `SBMON_API_SECRET_FILE` 而 anchor 缺失/不可读/类型错误 → 安装中止；
  monitor-service 启动时对配置的 secret 文件做存在/可读/普通文件三查，任一不满足 → 拒绝启动，
  **绝不静默降级为无 auth 连接**。pre-S0 逃生口：conf 中注释掉该行并删除派生文件。
- **round 2 F3 — ownership 是功能要求**：`monitor.conf` 与 `api.secret` 的
  `root:sboxweb 0640` 由调用方显式指定（atomic helper 不隐式决定 ownership）；
  chgrp 必须在 rename **之前**成功（绝不会出现"已替换线上文件但 sboxweb 读不了"）；
  内容一致时仍校验 regular file/mode/owner root/group sboxweb，metadata 漂移原子修复、
  修复失败 abort，绝无 warning-and-continue。Linux CI 以 **root 第二遍**跑真实
  useradd/groupadd/chown/chgrp 并断言 stat uid==0 / gid==sboxweb / mode==0640。
- 静态隔离测试对 anchor 路径做**唯一一次**精确豁免（deploy 代码中该字符串恰好出现一次）。

### 11.3 service.api URL contract（P7）

- 用 Python `urllib.parse` 校验（shell 不再手搓 URL 解析，IPv6 `[::1]` 正确处理）：
  scheme=http、host ∈ {127.0.0.1, localhost, ::1}、合法数值端口、无 userinfo、
  path 仅允许 "" 或 "/"、无 query、无 fragment。
- `monitor-service` 启动时校验（不满足 → 拒绝启动）；health 同时报告 `api_url_valid`。
  不满足契约时绝不发起连接。

---

## 12. Review round 2 决议摘要

1. **F1**：`releases.history` = 成功部署的 commit record（服务门通过后写入）；失败候选、
   已回滚候选不进入 history，rollback 目标永远选不到失败候选。rollback 自身成功后才写
   `action=rollback`。
2. **F2**：事务捕获并恢复完整服务状态（active + enabled 显式记录、显式恢复）；existing
   install 无论事务前 active/inactive/enabled/disabled，candidate 失败都完整回滚；
   fresh install 失败走清理契约（§5）。
3. **F3**：runtime 文件（monitor.conf、api.secret）的 root:sboxweb 0640 是功能契约；
   chgrp 在 rename 前 fail-closed；metadata 漂移修复失败即 abort；CI 以 root 第二遍
   验证真实 uid/gid/mode。
4. **F4**：所有 mutating 命令统一 `sbmon_with_deploy_lock` dispatcher；upgrade 的
   已安装前置检查在锁内复核，绝不退化为 fresh install。

---

## 13. Review round 4.1 — retention contract（最终）

- **retention = actual release-tree creation chronology**（目录 mtime，旧 → 新），与
  `releases.history` 完全解耦：history 只承担审计记录 + rollback 目标选择两个职责，
  不再参与物理树的生命周期排序。
- **rollback activation does not mutate release-tree age**：rollback 只翻转符号链接，
  从不重建/触碰 immutable tree —— 被回滚到的 release 仍按其创建年龄参与 retention。
- **failed candidate 按真实年龄参与 prune**（非 history 树不再是"最新"）。
- **live 永不被 prune**（无论多老）；prune 循环跳过 live 后继续寻找次旧 victim，
  直到满足 KEEP 或只剩 live —— 不会因 skip live 而超量保留。
- history 语义不变（R3-5/F1）：durable successful commit record，prune 永不重写；
  default rollback newest→oldest、skip current、skip 目录已不存在的条目。

---

## 14. Integration Round 1.1 — integration hardening（本轮）

小范围 integration hardening，5 个 fail-closed 修复；**不新增断言删除/弱化，全部 additive**。

- **A 服务自有 state tree 权限边界**：root 只负责顶层 data root（必须真实目录，symlink/非目录
  fail-closed），收敛为 `sboxweb:sboxweb 0700`；`state/` 由
  `sbmon_ensure_state_tree_as_service_user` **以 sboxweb 身份**创建/收敛；root 绝不对 service-owned
  child pathname 做 chown/chmod（`check→chown/chmod` 的 TOCTOU + symlink-follow 不能提权）；
  **已存在但不属于 sboxweb 的 `state/`（例如 root 手工创建）→ fail-closed 并给人工 chown/删除
  提示，绝不自动"救回"**；不递归 chown/chmod；auth/access 迁移安全。
- **B 移除 web-setup 的 root privileged mutation**：删除 setup 成功后对 data root / auth.json /
  access.json 的 root chown/chmod；改为非破坏性后置校验 `sbmon_verify_service_owned_tree`
  （漂移→fail-closed + 人工修复提示，绝不自动救回 root 属主数据）；失败信息诚实（可能部分持久化）
  且不重启 Monitor；成功时只重启 `singbox-monitor`；sing-box 永不被触碰。
- **C web 健康身份校验**：`web_http` 要求 200 + 合法 JSON object + 最小 session shape
  （`authenticated`/`whitelist_allowed` bool、`version` 非空 string）；无关程序/畸形应答 → degraded；
  body 不输出；不增加登录凭据依赖。
- **D poll 严格契约**：`SBMON_WEB_POLL_SECONDS` 必须是有限浮点 > 0（Python float，service 与 health
  同一函数）；非法值在 `exec` 前 fail-closed；缺省=1；健康新鲜度 `ceil(5*poll+15)`。
- **E web-setup 干净环境**：`env -i` + 仅 HOME/PATH/SSH_CONNECTION；root 先 `command -v` 解析
  python 绝对路径；不继承调用者环境；口令/恢复键不进 argv/env/journal；stdin/stdout/stderr/TTY 保留。
