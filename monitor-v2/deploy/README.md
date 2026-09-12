# Monitor v2 — Packaging / Installer / Deployment Track（skeleton）

状态：**deployment skeleton（Draft PR）**。E2（Web Dashboard）/ E3（特权 helper）在并行对话开发，
本分支**不实现、不伪造**它们的任何路径；只提供可运行的部署骨架、幂等 helper、测试与设计文档，
最终由 integration 对话接上。

- 基线：`main @ 3c6120441ee99c74faeb41a8122897395b2d7c94`（PR #10 merge 后）
- 分支：`feature/monitor-packaging`
- 本文所有结论以 main 实际代码为准（逐项注明出处），不是凭记忆。

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
    app/collector/{collector.py, api_bridge/}   ← 今天唯一存在的组件（E1）
    app/web/serve                        ← E2 集成对话交付；骨架里不存在、不伪造
    bin/monitor-service                  ← 运行入口 shim（见 §4）
    bin/monitor-health                   ← 健康探测（见 §6）
    lib/monitor-env.sh
/var/lib/singbox-monitor/                ← singbox-monitor:singbox-monitor 0750
  state/                                 0700  collector snapshot.json、运行状态
  auth/                                  0700  E2 管理认证（admin 口令哈希、recovery key）
  access/                                0700  访问日志（E2）
/etc/singbox-monitor/                    root:root 0755
  monitor.conf                           root:singbox-monitor 0640（服务用户只读）
  api.secret                             （可选）root:singbox-monitor 0640，安装器永不创建
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
5. **`/var/lib` 三子目录 0700**：auth/access/state 是 E2 的隐私面（口令哈希、recovery key、访问日志），
   只 owner 可进。骨架现在就按这个权限创建，E2 落地时不需要再动权限模型。
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
- `ExecStart=.../monitor-service <conf> <state-root>/state`（round 1 P1）：**state root 是显式
  contract**，unit、CLI（install-monitor.sh health/status）都显式传值；`WorkingDirectory` 只是
  便利，不是正确性/安全性事实源。
- 加固逐项（每项都对应真实需求，不是堆砌）：
  - `NoNewPrivileges`：永远不得提权（E3 桥是独立 sudo 路径，不是 web 进程自己提权）；
  - `ProtectHome=true`：/root、/home 不可见 —— 物理上读不到 `/root/sbox`，误配置也无效；
  - `ProtectSystem=full`：/usr、/boot、/etc 只读 —— 配置文件按设计就是只读的；/var 仍可写（状态）；
  - `PrivateTmp`、`PrivateDevices`：monitor 不需要 /tmp 共享与任何设备；
  - `ProtectKernelTunables/Modules/Logs`、`ProtectControlGroups`：观察者不需要内核接口；
  - `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`：只做 TCP loopback（AF_UNIX 留给 libc/NSS）；
  - `CapabilityBoundingSet=`（空）、`AmbientCapabilities=`：零 capability；
  - `RestrictSUIDSGID`、`RestrictRealtime`、`LockPersonality`、`SystemCallArchitectures=native`：常规面收窄。
  - **没有** `MemoryDenyWriteExecute`（CPython 不需要，但不为骨架引入不必要的兼容风险）；
    **没有** `ReadWritePaths=`（ProtectSystem=full 不锁 /var，无需例外）。
- 日志：stdout 的生命周期消息进 journal；**collector 的 snapshot JSON（含客户端元数据）重定向到
  0700 状态目录，绝不进 journal**（任务 11，见 §6）。

## 4. 运行入口（shim）与模式

`bin/monitor-service`（bash，严格模式，conf 解析无 eval/source）：

- `SBMON_MODE=collector-loop`（默认，**真实可用**）：循环跑 E1 collector——首拍 `--once`
  （秒级拿到 reset 权威快照），此后每拍 `--duration $SBMON_CYCLE_SECONDS`；stdout 原子写
  （tmp + mv）到 `state/snapshot.json`。流失败 → 暂停 5s 重连；每次新订阅的第一条消息就是全量
  权威 reset，无需外部持久化即可重建。这不是伪造 E2，是 E1 唯一诚实的服务化形态。
- `SBMON_MODE=web`：**E2 钩子**。仅当 `app/web/serve` 存在且可执行时 exec 它；否则 exit 21
  fail-closed —— unit 状态诚实地显示"未实现"，而不是静默空转。入口名由 E2 对话最终定名。
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
  默认保留: /var/lib/singbox-monitor（auth/access/state）、/etc/singbox-monitor、/var/backups
  --purge-state             → 追加删除 /var/lib/singbox-monitor
  --purge-config            → 追加删除 /etc/singbox-monitor
  --purge-backups           → 追加删除 /var/backups/singbox-monitor
```

- **Monitor-only uninstall 永不**删除 `sbconfig_server.json`、客户端凭据、sing-box binary
  （deploy 代码里不存在这些路径，测试静态断言）。
- **full proxy stack uninstall = 现有 `uninstall_singbox` + `uninstall --purge-state --purge-config`**
  的组合（文档定义；install.sh 菜单接线留给 integration 对话，见 §8）。
- 任务 9 的"默认保留 auth/access state？"：本骨架默认**保留**（可 `--purge-state`），
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
 "web_http": "not-applicable"|"unimplemented"|"ok",   ← E2 钩子
 "mode": "collector-loop", "overall": "healthy|degraded|unhealthy"}
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
- `web_http` 在 collector-loop 模式 `not-applicable`；E2 落地后由 integration 对话补 HTTP 探针。

## 7. 升级 / 回滚模型（任务 7）

```text
【事务状态捕获】old_release_id + 旧 unit 内容（同文件系统临时备份）
                 + old_service_active + old_service_enabled（`systemctl is-enabled` 显式记录，绝不推断）
  → stage（releases/.staging-*，py_compile + bash -n 预验证；失败删 staging，生产树零影响）
  → unit 原子写入（同文件系统 temp → chmod → rename；读者永远看不到半个 unit）
  → activate（mv -T 符号链接原子切换；旧树即备份，保留最近 SBMON_KEEP_RELEASES=3 个）
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
```

Monitor 升级**默认不得重启 sing-box** —— deploy 代码根本没有 sing-box 操作面；测试记录全部
systemctl 调用并断言无 `sing-box` 字样。若某次升级明确涉及 sing-box 配置（如 service.api secret
供给），那是 Phase D 事务（`upgrade_singbox_1_14`）的职责，走既有流程，不属于本骨架。

## 8. install.sh 菜单接入（deferred hook，本分支不接线）

顶层菜单未来新增（例如 `11. Monitor / Web Dashboard`）→ 调用
`monitor-v2/deploy/install-monitor.sh`（离线本机路径，不走 curl）。**本分支不改 install.sh**：
E2/E3/本分支三线并行，避免对共享文件制造冲突；接线与菜单文案由 integration 对话一次完成。
"install → sing-box 1.14 → service.api loopback → Monitor collector → Web service → systemd units"
的完整链路在 E2 落地前，由 collector-loop 模式提供除 Web 外的全部环节。

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

真机 canary（A/B 场景在真实 VPS 上的冒烟）属于部署验收，不在本 PR 内执行；
production 保持 UNCHANGED。

平台说明：原子切换断言依赖符号链接 rename(2)。无法创建符号链接的平台
（如无特权 MSYS/Git Bash）自动运行精简套件（T01/T06–T10/T12/T13）并显式打 SKIP；
完整套件（T02–T05/T11）由 GitHub Actions（ubuntu-latest）执行（`.github/workflows/monitor-packaging.yml`）。

## 10. 已实现 / 明确 deferred

已实现：目录布局 helper、系统用户 helper、unit 模板、release staging/原子切换/清理、
版本比较、幂等 install/upgrade/repair/uninstall/rollback/health/status、collector-loop 运行形态、
分离式健康探测、临时根测试装置（T01–T14）。

Deferred（integration 对话接）：E2 `app/web/serve` 与 `web_http` 探针；E3 helper/sudoers 与
`SBMON_USER` 命名对齐（§2）；install.sh 菜单接线；api.secret 供给策略（S0）；full-stack uninstall
菜单组合。

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
