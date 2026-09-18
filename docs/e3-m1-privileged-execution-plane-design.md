# E3 M1 方案设计：sbox-cm 特权执行平面

状态：**DESIGN / READ-ONLY。本轮零实现、零运行时改动、不部署 VPS、不启用 E3 management、不触碰生产 sing-box。**

上游设计：`docs/e3-rev5-privileged-mutation-design.md`（活跃规范）。本文件只把 rev5 中属于 **M1 交付面** 的部分收敛成可实施的方案，并对唯一真正的接口断点 **M1-A** 给出冻结契约。

**实施状态（本轮更新）**：M1 已在本仓库实现，未部署、未启用管理面。代码落点：

| 交付 | 落点 |
| --- | --- |
| M1-A0 canonical closure | `lib/client-management.sh`（新增/迁移客户端管理语义 + `cm_*` planned credential 原语）；`install.sh` 删除重复定义并更新 digest pin |
| M1-A | `cm_cred_digest_of` / `cm_plan_client_credential` / `cm_render_planned_candidate` / `cm_add_candidate_planned`；CLI `_add_client_locked` 同步改走该路径（`jq --arg uuid` 已从仓库消失） |
| M1-B | `sbox-cm/sbox-cm`（RPC core）+ `sbox-cm/deploy/sbox-cm.socket.in` |
| M1-C/D | `lib/sbox-cm-state.sh`（ledger/journal/audit/marker/degraded，write→fsync(file)→fsync(dir)） |
| M1-B..E | `sbox-cm/sbox-cm-ops`（六 op、锁内固定次序、调和、degraded、派生清理） |
| M1-E | `management.deactivate`（公开 RPC，active_stale 拒绝）+ worker `--maintenance mgmt-deactivate`（root-only 恢复 verb，不在六 op allowlist）+ `sbox-cm mgmt-deactivate` CLI + `install-sbox-cm.sh recover` |
| B-5 | `sbox-cm/deploy/sbox-cm.service.in`（严格候选旗标集 + `-/run/systemd` 最小 carve-out）+ `tests/e3/test-m1-systemd.sh`（真实 PID 1 运行时集成） |
| 测试 | `tests/e3/test-m1-{shared-lib,static,worker,rpc,crash,systemd}.sh` + `tests/e3/m1-rpc-probe.py` |

依赖链事实（已完成，均可作为本方案的基线）：

| 里程碑 | 交付 | 证据 |
| --- | --- | --- |
| M0 / G1 | `lib/client-management.sh` 单份事务引擎 + digest pin | `install.sh:710`（`SB_CLIENT_MANAGEMENT_SHA256`）、`install.sh:712-728`（`verify_client_management_library`）、`tests/e3/test-m0-shared-lib.sh` |
| M0 / G2 | config.lock 永久锚点、marker 迁 `/var/lib/sbox-cm/management.active`、marker 检查锁内化 | `install.sh:2739-2754`、`install.sh:3042-3048`（`_uninstall_singbox_locked`） |
| M0.5 / G3 | step-up 授权门 + 五类吊销 + 四 mutation 路由 501 边界 | `monitor-v2/web/auth.py`、`monitor-v2/web/server.py`（`MUTATION_ROUTES`） |
| M0.5 / G4 | `singbox-monitor.service` 原地硬化（`ProtectSystem=strict` + 单一 `ReadWritePaths`） | `monitor-v2/deploy/singbox-monitor.service.in` |

---

## 0. 目标、边界与交付物

### 0.1 目标结构

```text
Browser
   │  (M2 才接入)
singbox-monitor / sboxweb
   │  AF_UNIX e3-rpc/1
sbox-cm  [root]
   ├── config.lock
   ├── ledger
   ├── journal
   ├── audit
   └── shared transaction engine
          ▼
   sbconfig_server.json
```

### 0.2 M1 交付物

daemon、AF_UNIX/PEERCRED、帧协议、六个固定 op、ledger/journal/reconciliation、degraded 语义。

### 0.3 显式非目标

```text
不含 Web 适配（M2）    不含 E3 激活（M3）   不含生产部署（M3 canary）
不含 rotate/export     不含 legacy 写路径入 RPC（永不）
M1 完成后默认安全态不变：management 仍 inactive ⇒ client.* 一律拒绝
```

**M1 完成 ≠ Web 管理已启用。** 一个在跑的 `sbox-cm` 只是具备能力的通道，激活面由 `/var/lib/sbox-cm/management.active` 决定（默认不存在）。

---

## 1. Daemon 边界冻结

```text
身份      root（唯一特权进程，单点）
监听      AF_UNIX SOCK_STREAM，且仅此一个：
          路径 /run/sbox-cm/sbox-cm.sock
          目录 /run/sbox-cm/   root:root 0755
          socket               root:sboxweb 0660
TCP/UDP   0 个 listener（/proc 扫描断言，INV-2）
鉴权      accept() 后 getsockopt(SOL_SOCKET, SO_PEERCRED)
          · uid == uid(sboxweb)  → 放行
          · 其他任何 uid（含 0） → 回 {E_PEER_AUTH} 后立即 close
          · sboxweb 用户不存在   → 启动即 fail-closed，拒绝一切连接
          拒绝 uid 0 走 socket：root 运维一律走 CLI / 共享库直连，不开后门
连接模型  每连接恰好 1 request + 1 response，随后 close（无流水线、无会话态）
帧        4 字节大端 uint32 长度 L + L 字节 UTF-8 JSON payload
          0 < L ≤ 65536，越界 = 连接级拒绝（不回错误帧，不给协议 oracle）
版本      "v": "e3-rpc/1"（不匹配 → E_SCHEMA）
```

### 1.1 socket 生命周期

```text
1  RuntimeDirectory=sbox-cm → systemd 每次启动重建 /run/sbox-cm（root:root 0755）
2  绑定前检查现存 /run/sbox-cm/sbox-cm.sock：
     · 是 root-owned Unix socket 且无活 listener（connect 得 ECONNREFUSED） ⇒ 判定 stale
     · 任何其他形态（普通文件/目录/符号链接/非 root 属主）= fail-closed 启动失败
3  仅确认 stale 后才 unlink，再 bind + chmod 0660 + chown root:sboxweb
4  绑定后复核 socket 属主/模式；不符 = 退出且不 accept
```

> **设计决策 D-1（待 B-5 定案）**：daemon 自己 `bind` 需要 `CAP_CHOWN` 才能把 socket 交给 `sboxweb` 组。两条路径二选一并实测：
> (a) 保守：`CapabilityBoundingSet` 增加 `CAP_CHOWN`（最小追加）；
> (b) 更优：用 systemd **socket 单元** `sbox-cm.socket`（`ListenStream=/run/sbox-cm/sbox-cm.sock`、`SocketMode=0660`、`SocketGroup=sboxweb`、`SocketUser=root`）把属主、模式、陈旧清理都交给 systemd，service 用 socket activation 接收 fd，从而**不需要 CAP_CHOWN**。
> 无论哪条，daemon 侧独立性复核（第 4 步）都保留为纵深防御。

---

## 2. 内部分层

对外只有 `sbox-cm`。内部两区，边界即"谁能碰什么"：

| 区 | 职责 | 硬性禁止 |
| --- | --- | --- |
| **RPC Core** | socket / SO_PEERCRED / frame / schema / deadline / dispatch / replay cache / 连接级审计入口 | 直接读写 `sbconfig_server.json`、自算 digest、任何 shell/eval/动态路径 |
| **Transaction Backend** | config.lock / ledger / journal / candidate / commit / rollback / derived cleanup | 第二套 commit engine、第二把全局锁、直接写 live 配置 |

原则：**一条通道、一把锁、一套事务、一套 restore。** op 只能进入固定 switch；`argv` 恒空（除固定 op 名与固定字段），禁止 request-controlled shell/eval/动态路径（INV-5）。

### 2.1 进程模型（D-2）

RPC Core 需要 `SO_PEERCRED`、帧解析、fsync、结构化 JSON；Transaction Backend 已是一份 **digest-pinned 的 bash 共享库**。两者不共享运行时。方案：

```text
sbox-cm (Python 3.10 stdlib, 与 monitor-v2 同下限)
  = RPC Core：socket / PEERCRED / frame / schema / deadline /
              dispatch / replay cache / 连接级 audit
  └─ 每个需要锁的 op → fork/exec：
       /usr/local/lib/sbox-cm/sbox-cm-ops <op>        # op ∈ 固定枚举
         stdin  : 已校验的**非敏感**参数 JSON（name / idempotency_key / request_id / actor 指纹）
         stdout : 单行结构化结果 JSON（非敏感）
       worker = Transaction Backend：
         source lib/client-management.sh（同一 SHA pin）
         source lib/sbox-cm-state.sh（ledger / journal / marker / audit）
         固定 switch，"$1" 只能是编译期枚举
```

`client.add` / `client.delete` / `client.list` / `management.activate` / `management.deactivate` 全部经 worker（锁语义与共享库同源）；`management.status` 同样交给 worker——它不取锁、不读 live 配置，但把 marker/degraded/lock/last_transaction 的**判定语义**留在同一份实现里，避免 RPC Core 侧出现第二套状态解释。

> 实现修订（相对首版草案）：最初把 `management.status` 划给 RPC Core 直接应答。实施时改为统一 dispatch，
> 因为 "marker 三态 + degraded + reconcile + lock 可获取性" 的语义只应存在一份；RPC Core 因此保持纯传输
> （socket / PEERCRED / frame / schema / deadline / replay / 连接级审计），这与"一条通道、一套事务"的原则一致。

**凭据零跨界**：worker 自己生成凭据并自己使用，**凭据永不进入 Python 进程**，也永不跨进程边界（见 §3）。

**断连不可中止**：worker 是独立进程；进入 durable mutation 后，daemon 不再设 deadline、不因 socket EOF 杀 worker。worker 的权威结果落 **ledger/journal（fsync）**，stdout 的结果 JSON 只是尽力投递——即使 daemon 崩溃导致管道 EPIPE，事务仍跑到终态，重启后由调和读取。

---

## 3. M1-A：planned credential transaction interface（必须先冻结）

这是现有代码与 rev5 ledger/crash-recovery 合同之间**唯一真正的接口断点**。daemon/RPC 结构已相对成熟，M1-A 不解决则 M1 无法正确落地。

### 3.1 现状断点（代码事实）

`install.sh:979-1031` 的 `_add_client_locked`：

```bash
uuid="$("$SB_SING_BOX_BIN" generate uuid)"                 # ~1004
password="$("$SB_SING_BOX_BIN" generate rand --hex 16)"    # ~1008
candidate="$(new_candidate_path)"                          # ~1013
jq --arg name "$name" --arg uuid "$uuid" --arg password "$password" '...' \
   "$SB_SERVER_CONFIG" > "$candidate"                      # ~1014-1021
commit_server_config "$candidate" "add client $name"       # ~1026
```

四个断点：

| # | 断点 | 后果 |
| --- | --- | --- |
| A-0.1 | **argv 泄漏**：`jq --arg uuid --arg password` 把凭据值放进 jq 进程 argv | `/proc/<pid>/cmdline` 可读 ⇒ 违反 INV-6 / E-9；mutation 期间采样即命中 |
| A-0.2 | **无 planned digest**：没有 ledger 挂钩 | rev5 B.5 的"账本 plan 与 candidate 凭据永远一致"不成立；二次 crash 后调和会拿错 plan |
| A-0.3 | **幂等前置缺失**：直接进 candidate | durable intent 必须先于任何 mutation（rev5 B.7），否则重试语义不成立 |
| A-0.4 | **凭据变量长期存活**：`uuid`/`password` 存到函数结束 | 错误回溯 / `set -x` / trap 都可能外泄 |

> 说明：`--arg name`（名称非敏感）与 `_delete_client_locked`（`jq --arg name`，无凭据）本身不构成泄漏。**只有 add 路径**需要改。

### 3.2 冻结接口

不新建第二套事务引擎：在**同一份** `lib/client-management.sh` 内新增三个原语，作为 `commit_server_config` 的**前置层**。

```bash
# --- 凭据摘要：值只走 stdin（printf 内建 + 管道），无 argv / env ---
# stdin : "uuid\npassword\n"      stdout : sha256 hex
cm_cred_digest()

# --- 计划凭据生成：单个 JSON 对象，只在内存/管道 ---
# 内部调用 $SB_SING_BOX_BIN generate uuid / generate rand --hex 16
# stdout: {"uuid":"<64ish>","password":"<32hex>"}   (单行)
cm_plan_client_credential()

# --- 由**既定凭据**生成 add candidate：凭据经 stdin，绝不进 argv ---
# 参数 : <live_cfg> <name> <candidate_out>
# stdin: {"uuid":"...","password":"..."}
# 实现 : jq --slurpfile cfg <live_cfg> '<filter>'   ← 主输入 = 凭据对象；cfg 走文件
#        jq argv 只含 --slurpfile / cfg 路径 / --arg name / filter（零凭据）
cm_add_candidate_planned()
```

关键实现约束（这三条就是 M1-A 的"接口"本身）：

```text
A-1  cm_cred_digest 的输入只经管道：printf '%s\n%s\n' "$uuid" "$password" | sha256sum
     （printf 为 shell 内建，不产生 argv；sha256sum 只读 stdin）
A-2  cm_add_candidate_planned 用 jq --slurpfile 装载 live 配置，
     凭据对象作为 stdin 主输入，filter 内以 .uuid / .password 引用；
     生成过程不落任何含凭据的临时文件
A-3  调用方在同一 shell 内持有凭据变量期间：关闭 xtrace、不 echo、不在错误分支打印；
     使用后立即 unset
```

### 3.3 执行序列（M1-A 在锁内的固定次序）

```text
with_client_lock（既有，fail-closed）
  0  live reread + audit_client_consistency（既有函数，禁止锁外快照）
  1  ledger lookup(idempotency_key) + reconcile      ← 先于一切 live precondition（B.7）
  2  cm_plan_client_credential → planned_json（内存/管道）
  3  planned_cred_digest = cm_cred_digest <<< planned_json
  4  durable intent：append + flush + fsync(file) + fsync(dir)   ← 失败 = E_LEDGER_UNAVAILABLE，零变更
  5  cm_add_candidate_planned "$SB_SERVER_CONFIG" "$name" "$candidate"  ← 凭据经 stdin
  6  commit_server_config "$candidate"               ← 唯一提交引擎，未改动
  7  derived cleanup / registry advisory
  8  durable outcome：append + fsync(file) + fsync(dir)
  9  连接级 audit → unset 凭据变量 → unlock
```

delete 路径不生成凭据，但必须锁内现算：

```text
old_cred_digest = cm_cred_digest( live 中该 name 的 uuid + password )
```

（现算函数基础已在 `install.sh:1110-1120` `get_client_credentials`。）

### 3.4 M1-A 不变量

```text
MA-1  凭据值零命中 argv / env / 临时文件 / journald / 两份审计 / 错误 detail /
      RPC 响应 / client.list（INV-6、E-9）
MA-2  mutation 实际使用的 planned credentials ⇔ 一个已 fsync 的 ledger digest（B.5）
MA-3  digest 由引擎自算（B.1）；RPC 携带的任何 digest 字段一律拒绝
MA-4  commit 引擎唯一：commit_server_config 无第二份；M1-A 只是它的前置接口
MA-5  生成与使用在同一把 config.lock、同一进程内完成，凭据不跨进程边界
MA-6  CLI 与 daemon 共用同一组原语（L3 精神）；CLI 侧 0/1 返回契约不变
```

---

## 4. 六个 op（保持 rev5 §7 原样，不增不减）

> **Review #2 修订（B6 deadline 合同改版）**：helper **不实施 per-op 整体 deadline**。原因：post-intent 事务绝不可杀，而 pre-intent/post-intent 的 handoff 无法在"dispatch 后即失联"模型下可靠判定。替代合同：
> - 传输层唯一强制的时限是 **5 s 帧读取超时**；
> - worker 内**每个外部子步**（`sing-box check` / `systemctl reload` / health 探测）各自有 bounded timeout（`cm_bounded`，超时按正常事务错误/回滚处理）；
> - **120 s 仅为 M2 调用方等待预算**，不再是任何杀事务的定时器；
> - daemon 为每个连接起独立线程 serve，单个慢 mutation 不阻塞 status/list（worker 层仍由 config.lock 串行化）。

| op | Lock | degraded 时 | active 要求 |
| --- | --- | --- | --- |
| `management.status` | 不等锁 | 可用 | 无 |
| `client.list` | 是 | 可用（或显式报读错） | 无 |
| `management.activate` | 是 | **拒绝** | 无 |
| `management.deactivate` | 是 | **拒绝**（active_stale 亦拒绝，见 §M1-E） | 无 |
| `client.add` | 是 | **拒绝** | active |
| `client.delete` | 是 | **拒绝** | active |

`management.status` 的只读合同（Review #2 B7）：**无锁、零 mutation、零修复**；允许两类**只读、不创建文件**的探针——live config 的存在性/JSON 可解析性（这正是 `active_stale` 的定义依据）与 config.lock 锚点的非阻塞 flock 探测（锚点不存在 = 空闲；探测用只读打开，**绝不 `>>` 创建**）。

`client.list`：锁内读 live config，只返回 `name / protocols / reserved / mutable / source`，≤1000 条 + `truncated`，**零 UUID / password / 私钥 / YAML / 分享 URI**。`source` 只认正向证据（registry 有 `web` 记录），缺失一律 `untracked`，绝不推断 `cli`。`active_stale`（marker 在、配置亡）的人工恢复走 **root CLI**（maintenance verb，见 §M1-E），不做静默自动清除。

---

## 5. Ledger（权威幂等层）

**两套 id 严格分开**：

| 层 | 载体 | 生命周期 | 承担 |
| --- | --- | --- | --- |
| `request_id` | daemon 内存 | 10 min / 512 条环形缓存，重启即失 | 传输层重放降噪 |
| `Idempotency-Key` | root-only ledger（0600） | 持久 | **权威**幂等，不承担降噪 |

```
no record               → live precondition → durable intent → mutation → durable outcome
done   + same digest    → replay（原结果逐字段一致）
done   + diff digest    → E_IDEMPOTENCY_CONFLICT
in_flight + diff digest → E_IDEMPOTENCY_CONFLICT
in_flight + same digest → reconciliation（B.9 矩阵）
```

delete 关键：只有**当前 UUID+password digest 与原 `old_cred_digest` 完全一致**才允许重跑；同名第二代客户端（digest 不同）必须 `E_RECONCILE_CONFLICT`，**绝不删除当前对象**。

文件格式（`/var/lib/sbox-cm/ledger/cm-ledger.jsonl`，0600，append-only）：

```jsonc
// intent
{"v":1,"kind":"intent","key":"<full key, root-only>","op":"client.add","name":"vmix-01",
 "digest":"<helper 自算语义摘要>","planned_cred_digest":"<sha256>","generation":1,
 "state":"in_flight","ts":"...","request_id":"..."}
// outcome（非敏感 result）
{"v":1,"kind":"outcome","key":"...","generation":1,"state":"done","ts":"...",
 "result":{"deleted":true,"derived_cleanup":true,"warnings":[]}}
```

严禁：UUID / password / 私钥 / YAML / 分享 URI / 完整配置。`planned_cred_digest` / `old_cred_digest` 是单向摘要，允许且仅存于 root-only ledger。

---

## 6. Journal 与 crash recovery

```text
/var/lib/sbox-cm/                    root:root 0700
├── management.active                root:root 0644   (§4 激活标记)
├── ledger/cm-ledger.jsonl           root:root 0600
├── journal/<request_id>.json        root:root 0600   (done 后删除)
└── audit/cm.jsonl                   root:root 0600
```

journal 内容：`{"v":1,"request_id","op","phase","backup_path"}` —— **永不含凭据**。

持久化纪律（掉电级承诺的前提，INV-14）：

```text
write → fsync(file) → fsync(parent dir)
覆盖 journal 的创建/更新/删除，以及 ledger 的 intent / outcome
```

**启动流程**（在 `with_client_lock` 下，先于接受任何 mutation）：

```text
acquire lock → scan journal → reconcile → health/reload/rollback
  → durable outcome → audit → clear completed journal → unlock
```

无法证明安全态（journal 损坏 / restore 失败 / health 仍失败）：

```text
degraded = true, reconcile = "manual_intervention"
  · management.status / client.list 仍开放
  · 一切 mutation 返回 E_MANUAL_INTERVENTION（fail-closed）
  · 直至 root CLI 一致性修复后显式清除
```

---

## 7. Deadline 与断连

```text
未进入 durable mutation 前到达 deadline
  → E_TIMEOUT，可安全中止，零变更

已进入 mutation（durable intent 之后）
  → 绝不 cancel；socket 断开也跑完并写 outcome + audit
```

> **Review #2 修订（B6）**：上表原拟的 per-op helper deadline（10/15/30/120 s）**正式取消**。正式合同改为：helper 不设整体 op deadline（不存在 `communicate(timeout=...)`），唯一传输时限为 5 s 帧读取；worker 的外部子步（check/reload/health）以 `cm_bounded` 各自限时并按事务错误/回滚处理；120 s 归属 M2 调用方预算。理由：post-intent 不可杀 ⇒ 任何整体计时器要么违反该承诺、要么需要无法可靠判定的 pre/post-intent handoff。配套：daemon 每连接一线程，慢 mutation 不阻塞 status/list。

**Review #2 修订（B3 delete replay 收尾）**：同 key 重试可携带**新 request_id**；outcome 记录现在也携带 `request_id`（原始 attempt 的）。replay/finalize 路径（done-replay、add 的 digest 吻合、delete 的 name 已亡）一律用 ledger 中**原始 request_id** 收尾：补齐其 audit（原 audit_id，exactly-once 守卫）并清其 journal，而非清当前重试的。 outcome 落盘失败 ⇒ `E_STATE_UNCERTAIN`（F15），绝不假成功；派生目录清理**如实上报**（失败 ⇒ `derived_cleanup:false` + warning）。

**Review #2 修订（B5 audit 闭环）**：终态次序冻结为 **durable outcome → durable audit → journal clear → response**。audit 写失败 ⇒ **不清 journal**、响应携带 `audit_deferred` warning（不是普通成功），由启动调和用**同一 audit_id** 补齐后才清 journal（`cm_audit_has` 守卫防重复）。调和自身同样 gate：audit 未 durable 不清 journal。

`client.add` / `client.delete` 的 120 s 是**调用方等待预算**，不是杀事务的定时器。承诺一句话：**Web / browser 断连 ≠ root transaction abort。**（M0.5 的吊销语义与之对齐：已过授权门的请求不被重新判定、也不被半途中止。）

**Review #2 修订（B1 crash-phase journal）**：commit 引擎新增可选 durable phase hook（`CM_TX_JOURNAL_HOOK`）——worker 注入 `w_journal_hook`，在 `check/backup/replace/reload/health/rollback` **每个 phase 的不可逆动作之前**把 `phase + backup_path` fsync 进 tx journal；尤其 `phase=replace` 必须在真实 `mv` 之前落盘。hook 失败 = fail-closed（pre-replace 零变更中止；post-replace 走正常回滚路径）。崩溃点测试（`test-m1-crash.sh`）**真实 `kill -9` 于各 phase 边界**（经 hook 注入），并验证随后的真实 worker reconcile 收敛：disk 新 ⇒ reload；不可证 ⇒ 从 journal 的 backup_path restore + degraded。**不是第二套 commit engine**——CLI 不设 hook，行为不变。

**Review #2 修订（B2 ledger fail-closed）**：`cm_ledger_validate` 在锁内 lookup 之前验证**整个 ledger 的每一条完整记录**（冻结 schema：`v/kind/key/op/name/digest/generation/ts/request_id` + intent 的 cred digest 或 outcome 的 result 对象）；任何完整 malformed record ⇒ `E_LEDGER_UNAVAILABLE`（拒绝 mutation，绝不当作"无此 key"）。唯一豁免：文件末尾**无换行的 partial tail**——能完整解析 ⇒ 视为仅丢失换行符并补齐；否则视为 torn write（从未 durable）在锁内截断。`generation` 非数字同样 fail-closed。

---

## 8. systemd 硬化（初始候选，B-5 以实测定稿）

```ini
[Service]
User=root
ExecStart=/usr/local/lib/sbox-cm/sbox-cm run
Restart=on-failure
RestartSec=2
RuntimeDirectory=sbox-cm
RuntimeDirectoryMode=0755
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
NoNewPrivileges=yes
RestrictAddressFamilies=AF_UNIX
ReadWritePaths=/run/sbox-cm /root/sbox /var/lib/sbox-cm -/run/systemd
CapabilityBoundingSet=CAP_KILL CAP_DAC_OVERRIDE          # D-1 已定案：socket activation，无 CAP_CHOWN
```

> **Review #2 B-5 实测结论**：`ProtectSystem=strict` 将 `/run` 整体只读，而 `systemctl reload/is-active sing-box` 需要 **connect** 到 manager 私有 socket `/run/systemd/private`（connect 需要对该 inode 的写权限）——故最小 carve-out 为 `ReadWritePaths=-/run/systemd`（`-` 容忍缺席），即 D-6 预判的交互问题的落地修复。socket 属主（D-1）定案为 **systemd socket 单元**（`SocketMode=0660`/`SocketGroup=sboxweb`），daemon 侧 PEERCRED 复核保留为纵深防御。

B-5 实测项（M1 验收内容，`tests/e3/test-m1-systemd.sh` 于真实 PID 1 下强制执行）：

```text
· hardened socket/service 真实启动：socket root:sboxweb 0660，socket activation 生效
· sboxweb 经真实 socket 全流程：status/activate/add(reload 计数)/list/delete/deactivate
· PEERCRED：其他 uid 拒绝；root 也拒绝（无 RPC 后门）
· ExecReload 失败注入 ⇒ 经 hardened unit 自动回滚，config 逐字节还原，daemon 存活
· /var/lib/sbox-cm 属主非 root ⇒ daemon 启动 fail-closed（B8）；修复后正常
· 孤儿 journal + restart ⇒ 启动调和清账
```

---

## 9. M1 实施清单

| # | 工作 | 依赖 | 归属 |
| --- | --- | --- | --- |
| **M1-A** | planned credential / secret-clean candidate 接口（§3，含 CLI 路径改造与 `test-m0-shared-lib.sh` 扩展） | M0 | 先行 |
| **M1-B** | AF_UNIX daemon、socket ownership、PEERCRED、frame/schema/deadline、六 op dispatch | M1-A 的调用契约 | |
| **M1-C** | ledger + Idempotency-Key + generation/supersede/reconciliation | M1-A | |
| **M1-D** | tx journal + crash recovery + degraded + file/dir fsync | M1-C | |
| **M1-E** | management marker、status/list、audit exactly-once（durable 闭环）、registry advisory、root-only `--maintenance mgmt-deactivate`（active_stale 恢复；公开 RPC `management.deactivate` 对 active_stale 拒绝） | M1-B | |
| **M1-F / G6** | frame fuzz、peer-auth、crash points、R1–R12、F1–F22 相关、systemd sandbox、全通道 secret hygiene | M1-E | |

顺序约束：**M1-A 必须最先合入**，它是 M1-B..F 的调用契约；M1 不得先于 M0/M0.5（保护来自 M0）。

---

## 10. 测试与验收

### 10.1 平台口径

```text
Linux CI：SKIP=0 为硬门（TOTAL 必须恰好 PASS+FAIL+SKIP 且 FAIL=SKIP=0）
Windows 本地：POSIX 项允许 SKIP，但 SKIP 不计入 acceptance
```

### 10.2 M1-A 专项断言

```text
· cm_cred_digest 只读 stdin（静态断言：无 --arg 传凭据）
· cm_add_candidate_planned 的 jq 调用 argv 不含凭据（静态断言 + 运行时 /proc 采样）
· planned_cred_digest 在 durable intent 之前不可用于 candidate（次序断言）
· 同 key 重放逐字段一致；异 digest → E_IDEMPOTENCY_CONFLICT
· delete 第二代同名（digest 不同）→ E_RECONCILE_CONFLICT，且 live 未被删
```

### 10.3 动态 hygiene test（强制）

```text
mutation 期间采样 /proc/*/cmdline 与 /proc/*/environ，
经 SB_SING_BOX_BIN mock（test-only wrapper）注入带 sentinel 的 fake UUID/password，
断言 argv / env / journal / audit / journald / RPC 响应 / client.list 全部 0 命中。
production worker 必须拒绝同一 SB_* 注入（E-12）：测试通道与生产通道分离。
```

### 10.4 与既有套件的关系

```text
必须继续全绿：test-m0-shared-lib.sh / test-m0-static-contract.sh /
             test-security-baseline.sh / test-phase-c.sh / test-phase-d.sh /
             test-legacy-config-transactions.sh / test-monitor-v2-{e1,e2,m05}.sh
新增：tests/e3/ 下的 daemon/ledger/journal/frame-fuzz 套件（G6 脚手架）
```

---

## 11. 完成定义

```text
M0 / M0.5                        PASS
M1-A planned credential          PASS
M1 daemon/socket                 PASS
M1 ledger/journal                PASS
M1 crash reconciliation          PASS
M1 degraded semantics            PASS
M1 audit/hygiene                 PASS
G6 fuzz/harness                  PASS
B-5 systemd hardening            CLOSED
M1 COMPLETE                      YES
M2 WEB ADAPTER                   NOT STARTED
E3 MANAGEMENT ENABLED            NO
PRODUCTION DEPLOYED              NO
```

M1 完成后仍保持默认安全态。只有 M2 接入 Web、M3 收口 G1–G6 并获显式 canary 批准，才允许激活管理面。

---

## 12. 未决项与残余风险

| # | 项 | 说明 | 归属 |
| --- | --- | --- | --- |
| ~~D-1~~ | socket 属主责任方 | **已定案**：systemd socket 单元（`sbox-cm.socket`，无 `CAP_CHOWN`）；daemon 保留 PEERCRED/属主复核 | 已闭合 |
| D-2 | daemon 语言 | Python 3.10 stdlib（RPC Core）+ bash worker（Transaction Backend）；契约语言无关 | 已定案 |
| ~~D-3~~ | `mgmt-deactivate` root CLI | **已定案**：worker `--maintenance mgmt-deactivate`（不在六 op allowlist）；公开 RPC 对 active_stale 拒绝 | 已闭合 |
| D-4 | registry | advisory 元数据层尚未存在；`source` 缺省 `untracked`，不得推断 | M1-E |
| D-5 | M0.5 的 `management_active` provider | 必须从阶段性 provider 切换为 `management.status` RPC 读取，Web 永不 stat 标记 | M1-E → M2 |
| ~~D-6~~ | systemd sandbox 与 D-Bus/reload 交互 | **已实测**：`-/run/systemd` 最小 carve-out + `test-m1-systemd.sh` 真实运行时集成 | 已闭合 |

### Review #2 修复清单（本轮，同分支）

| # | 修复 | 测试 |
| --- | --- | --- |
| B1 | commit 引擎 durable phase hook；`phase=replace` 于 `mv` 前 fsync；worker 注入 `w_journal_hook` | `test-m1-crash.sh`（各 phase 真实 kill -9 + reconcile 收敛/restore/degraded） |
| B2 | `cm_ledger_validate` 全量 fail-closed 校验 + partial tail 规则；generation fail-closed | `test-m1-worker.sh` 账本损坏矩阵（malformed/坏 generation/坏 state/坏 key schema/partial tail/无换行完整记录） |
| B3 | replay 用 ledger 原 request_id 收尾旧 journal/audit；outcome 记录带 request_id；F15 `E_STATE_UNCERTAIN`；derived 清理如实上报 | `test-m1-worker.sh`（新 request_id 重试收尾 / 只读 ledger 注入 / 只读 clients 目录注入） |
| B4 | 公开 RPC `management.deactivate` 对 active_stale 拒绝；root 恢复走 `--maintenance mgmt-deactivate` | `test-m1-worker.sh`（RPC 拒绝 + marker 不灭 + maintenance 恢复） |
| B5 | 终态次序 outcome→audit→journal clear→response；audit 失败保留 journal + `audit_deferred`；调和补 audit 后才清 | `test-m1-worker.sh`（只读 audit 文件注入 + reconcile 补账） |
| B6 | 撤销 helper per-op deadline（本文档正式修订）；子步 `cm_bounded` 限时；daemon 每连接一线程 | static 断言 + 全套件回归 |
| B7 | status 只读合同：lock 探测只读不创建；live 探测定位 active_stale | `test-m1-worker.sh`（status 后锚点不存在） |
| B8 | `cm_state_init`/daemon `ensure_state_dir`/installer 三处 root:root 所有权 fail-closed | `test-m1-systemd.sh`（非 root 属主 ⇒ 启动失败） |
| B-5 | `-/run/systemd` carve-out；真实 systemd 运行时集成测试；workflow 中 `security --offline` 的 `|| true` 改为显式能力探测 | `test-m1-systemd.sh`（socket/PEERCRED/add/reload 计数/rollback/reconcile/所有权） |

---

*注：以上为方案设计与范围界定，涵盖目标结构、合同参数与验收标准，不涉及实现细节、部署步骤或代码。*
