# E3 M2 — Web 适配层设计（sbox-cm Web Adapter，rev3）

```text
状态           : IMPLEMENTED（M2-A0…M2-E 已随本 PR 落地；rev3 = 实现收口）
本文性质       : 设计文档 + 冻结裁决记录 + 实现记录
实现面         : M2-A0 helper actor；M2-B/C e3rpc+broker+HTTP adapter；
                 M2-D UI；M2-E live 闸门（tests/e3/test-m2-live.sh）
E3 MANAGEMENT  = NO（M2 交付后仍保持默认安全态；激活属于 M3）
PRODUCTION     = NO TOUCH
前置           : M0 / M0.5 / M1 已合并（main = 2ca99f37…，M1 head 1d4615da…）
```

---

## 1. 定位与红线

M2 = **Web 适配层**：把 M0.5 留下的四个 `501 not_implemented` mutation 边界换成对
sbox-cm 的真实 RPC 转发，并补齐 status / client.list 的展示面。一句话定位：

```text
Web 是翻译者，不是决策者。
```

Web 不做鉴权判定之外的任何安全决策、不做事务、不生成/持有凭据、不直接读写任何
sing-box / sbox-cm 状态文件。三条不可让步红线：

```text
R-W1  zero Web filesystem bypass —— Web 代码永不出现 /root/sbox、/var/lib/sbox-cm、
      sbconfig、management.active（M0.5 T12 静态禁令延伸覆盖 M2 全部新模块）；
R-W2  Web 永不重新成为状态/事务事实源 —— management 状态唯一来源是
      management.status RPC（经本设计的 broker 派生），last_transaction 只是展示；
R-W3  凭据卫生 —— UUID / password / 私钥 / admin 密码 / session token / CSRF token /
      恢复密钥绝不进入 RPC 请求、日志、journald、错误 detail 或浏览器展示
      （rev5 §5.3 S-1…S-5 全文继承）。
```

**M2 不做**：E3 激活（M3，G1–G6 收口 + canary 批准）、export / rotate 子系统
（rev5 明确"推迟"）、生产部署、`ENABLE E3 MANAGEMENT`。M2 全部交付完成后，管理面
默认仍是关闭态（无激活标记，所有 `client.*` RPC 由 helper 以 `E_ACTIVATION_STATE`
拒绝——这个默认态本身就是安全设计，不是缺陷）。

---

## 2. 设计基线（全部为已核实的实现事实）

### 2.1 Web 侧现状（monitor-v2）

| 事实 | 位置 |
| --- | --- |
| HTTP 服务 = Python3 stdlib `ThreadingHTTPServer`，无框架 | `monitor-v2/web/server.py:33,171` |
| 四个 mutation 路由已存在，固定返回 `501 not_implemented, milestone:"M0.5"` | `server.py:51-56`（MUTATION_ROUTES）、`:752-774`（_handle_mutation_boundary） |
| 无 `client.list` 路由；UI 无任何 client 概念 | `server.py` 路由表、`web/static/index.html`（0 处 "client"） |
| `management_active` = 构造注入可调用对象；**生产恒为 `None → False`**；docstring 明确"唯一合法未来来源 = management.status RPC，永不许以文件读取实现" | `server.py:143-168`、`webapp.py:265-267`（生产不注入） |
| step-up 端点 + 300 s 窗口 + 五类立即吊销已实现 | `server.py:608-662`、`auth.py:45-48,204-234` |
| mutation 门 = `_require_session` + CSRF + Origin + `_require_step_up`（401 `reauth_required`） | `server.py:329-361,443-482` |
| monitor unit：`ProtectSystem=strict`、`ProtectHome=yes`、`ReadWritePaths` 恰一条（数据根）、`CapabilityBoundingSet=` 空、`RestrictAddressFamilies` 已含 `AF_UNIX`（注释预告 M2 连接） | `monitor-v2/deploy/singbox-monitor.service.in:28-57` |
| M0.5 测试契约：web 源码禁含 `/root/sbox`、`/var/lib/sbox-cm`、`sbconfig`、`management.active`；unit 断言"恰一条 ReadWritePaths"、"无写路径进 /root/sbox" | `tests/test-monitor-v2-m05.sh:75-81,104-113` |
| Web 侧现有 AF_UNIX / RPC 客户端代码：**无**（`api_bridge/` 是对 sing-box gRPC-Web 的，无关） | 全仓检索确认 |

### 2.2 M1 RPC 契约（已合并实现，本文的对接面）

| 项 | 实现值 |
| --- | --- |
| 传输 | AF_UNIX `/run/sbox-cm/sbox-cm.sock`，`root:sboxweb 0660`，SO_PEERCRED uid==sboxweb；4 字节大端长度前缀 + JSON；`MAX_FRAME=65536`；帧读取超时 5 s；每连接一线程；**无整体 op deadline、无 `communicate(timeout)`** |
| 六 op 白名单 | `management.status`（无 actor，不取锁）/ `management.activate`（optional actor）/ `management.deactivate`（**当前无 actor，M2-A0 补**）/ `client.list`（取锁）/ `client.add`、`client.delete`（required name+idempotency_key，optional actor，均取锁） |
| 形状约束 | `request_id ∈ ^[A-Za-z0-9._-]{16,64}$`；`idempotency_key ∈ ^[A-Za-z0-9._:-]{16,128}$`；`name ∈ ^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$` 且 `legacy` 保留；actor 指纹 `^[0-9a-f]{16}$`；未知字段一律 `E_SCHEMA` |
| 重放屏蔽 | request_id 内存缓存 600 s / 512 条（仅传输去重）；权威幂等 = Idempotency-Key 账本（helper 侧） |
| status data 实际形状 | `{management_state, management_active, helper:{degraded, reconcile}, lock:{path, acquirable}, last_transaction:{generation, op, outcome, ended_at}}` —— **无** `activated_at`、**无** `monitor_running`、**无** pid/uptime/inode |
| list data 实际形状 | `{clients:[{name, protocols[], reserved, mutable, source}], truncated}` |
| add data 实际形状 | `{name, protocols, mutable, source:"untracked", yaml_available:false, credential_delivery:"cli", warnings:["derived_files:generate_via_cli"]}` —— **凭据只存在于 live 配置** |
| delete data 实际形状 | `{deleted:true, derived_cleanup, warnings}` |
| 信封 | 成功：`{ok, v, request_id, op, idempotency{key_fp,replayed,generation}, warnings, data}`；失败：`{ok:false, …, error:{code, stage, retriable, detail, backup}}`。**rev5 §6.1 的 `transaction` 对象 M1 未实现**，M2 不得伪造 |
| 锁等待 | 普通操作 `flock -w 15`（`SB_LOCK_TIMEOUT` 默认 15 s），reconcile 30 s → 这是 `client.list` 预算取 20 s 的依据 |
| degraded | 置位期间 status/list 保持可用，**一切 mutation fail-closed `E_MANUAL_INTERVENTION`** |

### 2.3 CI 基线（M2 的出发闸门，已验收）

```text
merge commit 2ca99f37…（PR #22）push CI run 35346738251，三基线原始日志验收：
  E3 M1 crash points : PASS=30 FAIL=0 SKIP=0  E3_M1_CRASH=PASS     ×3（22.04/24.04/26.04）
  E3 M1 B-5 LIVE     : PASS=36 FAIL=0 SKIP=0  E3_M1_SYSTEMD=PASS   ×3
  其余 M1 套件        : 43/96/106/62/39 均 FAIL=0 SKIP=0
  packaging 套件      : 512 passed, 0 failed ×3
两 gate 均真实执行（每日志 8 次真实 kill -9；B-5 运行时断言齐全）；
原始日志中的既有 SKIP 全部属于 M1 无关套件（packaging uid 探针 ×3、26.04 tzdata ×2），
与合并前同基线计数一致，非 M1 delta 引入。
```

---

## 3. 三条承载性语义结论（G 方向批准时点名保留）

**S-1 调用方超时 ≠ mutation 失败。**
helper 没有 `communicate(timeout)`：一旦 durable intent 落盘，事务**必然**驱动到终态
（commit / rollback / degraded），无论 web 是否还在等。因此 M2 调用方预算耗尽的唯一
正确语义是 **"结果未知（uncertain）"**：

```text
禁止：把超时当失败、自动换新 Idempotency-Key 重试、向用户显示"操作失败"。
必须：显示"事务可能仍在进行或已完成，结果未知"；
      引导查看 management.status 的 last_transaction（generation/op/outcome）；
      如需重试，必须沿用同一 Idempotency-Key（账本将 replay 原结果或补齐收尾，
      恰好一次变更语义由 helper 保证）。
```

**S-2 Web 不得重新成为状态/事务事实源。**
`management_active` 只能来自 broker 对 `management.status` 的**新鲜**读取派生（§7）；
`last_transaction` 只用于展示；Web 永不缓存"激活过"这一事实作为授权依据——每次
mutation 的激活态判定都在 helper 锁内进行，Web 侧的 active 感知纯粹是 UX。

**S-3 `credential_delivery:"cli"` 接受，浏览器不展示新凭据。**
add 成功响应不含 UUID/password（红线），M2 v1 **不为此改 helper**。UI 在 add 成功后
明确提示："客户端已创建，但凭据/客户端配置不会通过网页返回，需要在服务器侧使用现有
客户端管理流程（CLI『客户端管理 → 生成客户端配置』）生成配置"。M2 不偷做 export。

---

## 4. 冻结裁决（方向批准 2026-09-19，对 C.8 四项的定案）

```text
M2 DESIGN DIRECTION                 = APPROVED

M2-A0:
management.deactivate actor         = ADD OPTIONAL ACTOR
activated_at                        = NOT IN M2 V1
helper pid/uptime/lock inode        = NOT IN M2 V1
monitor_running                     = WEB-SUPPLIED

STATUS CACHE TTL                    = 2s
CLIENT LIST CACHE TTL               = 5s
DELETE PREFLIGHT                    = FRESH LIST REQUIRED
BREAKER                             = 3 failures / 10s open / 1 half-open probe
STALE active=true                   = NEVER TRUSTED

CREDENTIAL DELIVERY                 = CLI ONLY
WEB CREDENTIAL DISPLAY              = FORBIDDEN

REV5 DEADLINE ERRATA                = REQUIRED（随本文同 commit 落库）
M2 MUTATION AUTO-RETRY              = FORBIDDEN
M2 PRODUCTION DEPLOYMENT            = NO
E3 MANAGEMENT ENABLED               = NO
```

调用方等待预算（对 C.4 初版的**收窄**，避免单个失联 helper 拖死 Web 线程）：

| op | Web 等待预算 | 依据 |
| --- | --- | --- |
| `management.status` | 5 s | 不取锁；帧读取 5 s 已是上限量级 |
| `client.list` | 20 s | helper 锁等待可达 15 s，留余量 |
| `management.activate` / `deactivate` | 30 s | 锁等待 + 标记写入 |
| `client.add` / `client.delete` | 120 s | 完整事务（check/backup/replace/reload/health/可能的 rollback） |

两个写死的设计细节：

1. **status broker 可缓存"展示状态"，但 `management_active()` 只接受"TTL 内成功获取的
   active"**。TTL 过期且 helper 不可达 ⇒ `management_active=False`；过期的
   `active=true` 绝不能继续当 active 使用（也绝不能用于放行任何东西——放行判定本来
   就在 helper）。
2. **helper 返回值到浏览器必须字段白名单（deny-by-default）**。已知必须排除：
   `lock.path`（`/root/sbox/config.lock`，root 路径绝不外泄）、`error.backup`
   （`/root/sbox/…bak…`，同理）。白名单按 M1 实际返回字段显式枚举（§9），helper
   未来新增字段默认**不**透传。

---

## 5. M2-A0 — RPC contract normalization（先行前置，本提交不含实现）

**改动定义（单一、最小）**：daemon `sbox-cm` 的 `OPS` 表中
`management.deactivate` 的 `optional` 从 `()` 改为 `("actor",)`。
`e3-rpc/1` 版本不变（可选字段按 op spec 放开，不是 schema 破坏性变更）。

**理由**：deactivate 与 activate/add/delete 同为 session + CSRF + step-up 之后的特权
mutation，privileged audit 不应唯独缺失调用者归因。worker 侧**无需改动**：
`main()` 对所有 op 统一解析 `ACTOR_SESSION_FP` / `ACTOR_STEPUP_FP`
（`sbox-cm-ops:899-900`），`w_audit` 已将指纹写入每条审计
（`sbox-cm-ops:87-96`）；activate 的 marker 也已存 `session_fp`。当前唯一缺口就是
daemon 侧对 deactivate 拒绝 `actor` 字段（未知字段 `E_SCHEMA`）。

**不做**（冻结）：`management.status` / `client.list` 维持无 actor（读路径无 step-up
语义，加了反而制造"actor 可选但无意义"的歧义）；`activated_at`、`helper.pid`、
`uptime_s`、`lock.inode` 均不做（M2 v1 不展示，helper 不改）。

**部署次序约束**：helper 先升级、Web 路由后放开。旧 helper 会把带 actor 的
deactivate 以 `E_SCHEMA` 拒绝；Web 客户端对 deactivate 的 `E_SCHEMA` 响应不做自动
重试（S-1 精神），按错误显示。**M2-A0 改动落地必须重跑 M1 全套回归**：
`test-m1-rpc.sh`、`test-m1-worker.sh`、`test-m1-static.sh`、`test-m1-crash.sh`、
`test-m1-systemd.sh`（B-5），三基线原始日志 `FAIL=0`，两个 hard gate 真实执行
`SKIP=0`——沿用 B-5 的"看原始 summary，不看 step 绿"纪律。

---

## 6. 架构与组件

```text
Browser
   │  (session cookie + CSRF header; mutation 另需 step-up 窗口)
   ▼
singbox-monitor.service  User=sboxweb
   ├── server.py 路由层（既有三道门原样保留：whitelist / session / CSRF+Origin）
   ├── e3_broker   status/list 缓存(TTL) + breaker + management_active provider
   ├── e3_mutations 校验(type-to-confirm 服务端复核、name/legacy 双层、指纹派生)
   │                → 组帧 → 白名单映射响应/错误
   └── e3rpc       AF_UNIX 客户端：connect/帧编解码/单请求连接/调用方预算
   │
   │ AF_UNIX e3-rpc/1（/run/sbox-cm/sbox-cm.sock, root:sboxweb 0660）
   ▼
sbox-cm.service  User=root
   └── 既有：RPC core → worker（config.lock / ledger / journal / commit engine）
```

新组件与落点（全部 stdlib，无新依赖；`api_bridge/` 不复用不触碰）：

| 组件 | 文件（建议） | 职责 | 关键约束 |
| --- | --- | --- | --- |
| 传输客户端 | `monitor-v2/web/e3rpc.py` | 帧编解码、connect/收发、per-op 调用方预算、`E_TIMEOUT`/连接错误分类 | socket 路径 = 模块常量 `DEFAULT_E3_SOCKET_PATH="/run/sbox-cm/sbox-cm.sock"`；测试经构造器注入临时路径；**不新增 env key**（monitor-env.sh 六键面不扩大） |
| broker | `monitor-v2/web/e3_broker.py` | status/list TTL 缓存、breaker 状态机、`management_active()` provider、`as_of` 时间戳 | 异常一律 fail-closed；cache/breaker 全部 thread-safe；status/list 各自 single-flight；见 §7 |
| mutation 转发 | `monitor-v2/web/e3_mutations.py` | 请求校验与组装、type-to-confirm 服务端复核、actor 指纹、白名单映射 | 不重试 mutation（S-1）；不落盘 |
| 路由接线 | `server.py`（最小 diff） | 六个 HTTP endpoints（2 GET + 4 mutation POST）换实现/新增；`management_active` provider 换 broker | M0.5 的门与 `MUTATION_ROUTES` 集合不变 |
| UI | `web/static/*`（最小 diff） | status 卡片、client 表、add/delete 确认流、uncertain/degraded 态 | §11 |

`webapp.py` 接线：生产构造 `MonitorWebApp(..., e3_broker=E3Broker(E3RpcClient()))`；
测试注入 mock broker/client（延续 `management_active` 注入先例，生产默认不注入的旧
语义由 broker 的 fail-closed 取代——构造器默认参数的行为变化需在 M0.5 测试中显式
覆盖：无 helper 环境 ⇒ provider=False，全部路由 503/按 §10 映射）。

---

## 7. 缓存、熔断与 management_active 语义（冻结）

### 7.1 status broker

```text
缓存条目   : { payload(白名单后), fetched_at(monotonic), ok }
TTL        : 2 s（冻结值）
管理_active : True 当且仅当 缓存(或当次成功调用)的 management_active==true
              且 fetched_at 距今 ≤ TTL。
              TTL 过期且刷新失败 ⇒ management_active() == False（stale-active 绝不信任）。
as_of      : 每个经 broker 的响应携带 as_of（UTC ISO8601）= 该 payload 的真实获取
             时点；stale 期间保持原值不变（§7.5）。
并发模型   : cache 与 breaker 全部 thread-safe（ThreadingHTTPServer 每请求一线程）。
             status 与 list 各自 single-flight：同一 resource 并发最多一个 refresh
             RPC；TTL 同时过期的并发请求只产生一次 helper RPC，其余等待同一结果
             （成功共享新 snapshot，失败共享同一次失败判定），绝不 fan-out。
transport  : fresh | stale | unavailable 三态（§7.5），与 helper degraded 严格分离。
```

### 7.2 client.list 展示缓存与删除预检

```text
展示缓存 TTL : 5 s（冻结值）。仅用于列表展示。
并发         : 与 status 同一 single-flight 模型，两者相互独立（§7.1）。
删除预检     : 进入 destructive confirm 前必须绕过缓存强制拉一次 fresh list；
               fresh list 失败 ⇒ 不允许进入确认流程（UI 层）。
               delete 路由在派发 delete RPC 前再做一次同样的 fresh-list 预检
               （Web 层纵深防御）：失败 ⇒ 503 list_unavailable，**不派发 delete**。
正确性边界   : 该预检是 UX + 纵深防御，不是正确性的唯一保障——helper 会在锁内
               重新验证（不存在 ⇒ E_NOT_FOUND；被重建/轮换 ⇒ E_RECONCILE_CONFLICT）。
```

### 7.3 breaker（冻结：3 failures / 10s open / 1 half-open probe；status-driven）

```text
驱动（冻结修订）: breaker 只由 management.status 的 transport probe 驱动。
                  counter = 连续失败的 status refresh 尝试；任一次成功即归零。
                  list / mutation 的 transport 失败只作为该次请求的错误返回，
                  【不】递增 global counter；mutation caller timeout ⇒
                  result_unknown，绝不 poison breaker——这保证 result_unknown
                  之后仍能立即通过 status / last_transaction 查询真实结果。
迁移      : closed ----连续 3 次 status refresh 失败----> open（10 s）
            open   ----10 s 到期后的下一个 status 请求----> half-open：
                     全进程严格只允许一个 probe（由 single-flight 胜出者执行），
                     其余并发请求按 open 语义处理、不发 RPC；
            half-open --probe 成功--> closed（该次响应即 fresh）
            half-open --probe 失败--> open（重新计 10 s）
计数边界  : 仅传输层失败 = connect 拒绝/超时、帧读写 I/O 错误、status 预算耗尽。
            协议层错误（helper 返回的 4xx/5xx 语义码，如 E_DUPLICATE_NAME、
            E_ACTIVATION_STATE）【不】计数——那说明 helper 健康，只是本次操作不被允许。
open 期间 : mutation ⇒ 503 e3_unavailable，不派发（UI 整块退化为只读）；
            status ⇒ 有 snapshot 时返回 200 + transport=unavailable/stale，
            附最后已知 payload + 原 as_of，management_active()=False
            （绝不因 transport 失败伪造或改写任何 helper 字段，§7.5）；
            完全无 snapshot ⇒ 503 e3_unavailable（绝不合成空数据）；
            list ⇒ 同三态模型（仅展示）。
```

### 7.4 Web 侧背压（E-15，不充当全局锁）

进程内 mutation 信号量（建议 4 并发）+ 等待上限 30 s；等待超时 ⇒
`503 e3_busy`（retriable）。作用仅是防止失联 helper 造成的线程堆积；真正的串行化
始终是 helper 的 config.lock。

### 7.5 helper degraded 与 Web transport state 严格分离（冻结修订）

```text
helper.degraded : 只能来自真实 management.status 响应中的 helper.degraded 字段。
                  Web 禁止自行制造、覆盖或推导它——transport 失败不是 degraded。
transport state : fresh（TTL 内成功获取）| stale（展示旧 snapshot，as_of 保持
                  原获取时点）| unavailable（不存在任何可证明的 snapshot）。
刷新失败        : 可返回 stale snapshot + 原 as_of 供展示；
                  management_active() 一律 False（fresh-only 规则不变）；
                  UI 横幅按 transport 呈现"数据时点 / helper 不可达"，
                  绝不呈现为"helper degraded"。
为什么必须分开口径: helper 不可达（transport 问题，可能只是重启/抖动/熔断）与
                  helper 自报 degraded（调和无法证明安全态，特权面自身
                  fail-closed、需 root 介入）是两类事件。混用会把一次网络抖动
                  升级成"需要 root 修复"的错误告警，或把真 degraded 当成
                  可等待的暂时故障——两边的运维动作完全不同。
```

### 7.6 post-mutation 立即收敛：确认成功后的定向失效（0.1.3 修订）

问题：一次 CONFIRMED 的 client.add/client.delete 之后，UI 仍需等 status_ttl
(2.0s)/list_ttl (5.0s) 与 attempt-throttle 过期才恢复可写视图——fail-closed
本身正确，但 2–5 秒的"Unavailable"窗口是纯缓存时延造成的错觉。

修订（Monitor-only，helper/RPC 契约零改动）：

```text
失效入口 : E3Broker.invalidate_after_client_mutation()——唯一新增公开方法。
失效对象 : _status_cache / _list_cache（保留 payload，fetched_at 置 -inf，
           即降级为 STALE 供 §7.5 展示回退，fresh-only 可写门拒绝其恢复可写）
           + _status_attempted_at / _list_attempted_at（同时复位，否则
           attempt-throttle 会挡住紧随其后的显式刷新）。
触发时机 : server._handle_e3_mutation 内 verdict.ok==true 且
           op ∈ {client.add, client.delete} 时、写出 200 响应之前，各一次。
           幂等重放再次成功可再次失效（无害）。
绝不失效 : 任何未确认结局——dispatch-only、504 result_unknown/uncertain、
           post-send RpcTransportError、E_RECONCILE_CONFLICT、E_LOCK、
           E_NOT_FOUND、一切错误路径；client.export/client.list/
           management.status 为只读，永不触发失效。
在途竞态 : status/list 各自维护单调 epoch（_status_epoch/_list_epoch），
           每次刷新在 flight 锁内、_mutex 下捕获当前 epoch 后再发 RPC；
           完成时 epoch 不匹配 ⇒ 预失效的旧响应永不成为权威缓存、永不落
           attempted_at（transport 失败计数/breaker 仍如实结算——那是诚实
           的传输信号，不是缓存权威）。旧调用者本人拿到 STALE/UNAVAILABLE；
           失效后读到 STALE，被 flight 锁挡住的下一位随即发出失效之后的
           fresh RPC。实现只复用既有 _mutex/flight 锁次序，无新锁序 ⇒
           无死锁；single-flight、TTL、breaker 语义全部不变。
前端配套 : 确认成功的 then 分支不再 fire-and-forget 双读，改为
           refreshClientsAfterMutation()：先 loadE3Status(true)（背景式读，
           在途不清掉最后已知好视图；失败仍走既有 fail-closed），再
           loadE3Clients()。消息文本由该 helper 之外的分支写入，收敛刷新
           不覆盖"Client created./Client deleted."。
不可弱化 : fail-closed 纪律不变——只有 fresh 且 active 且非 degraded 且
           reconcile clean 且 lock acquirable 且无 pending uncertain 才
           可写；"成功"本身永远不直接使 UI 可写。定时器数值一律不动。
```

### 7.7 convergence 端点：一次读原子收敛（0.1.4 修订）

§7.6 的服务端失效保留原位；0.1.4 替换其"前端配套"段：两次独立 TTL 读仍会
出现 status 已 fresh、list 仍旧（或反之）的半新鲜窗口，且竞态窗口横跨两个
请求。收敛改为一次服务器往返。

```text
broker   : E3Broker.status(force=False)。force=True 仅绕过 TTL 快速路径与
           attempt-throttle；single-flight、breaker 门（open 且冷却未到 ⇒
           零分派，force 也不例外；冷却已过 ⇒ force 可执行 half-open 探针，
           那是 breaker 自身转移，不是绕过）、0.1.3 epoch 规则（在途失效的
           预失效响应照样不得发布）全部不变。每次 force 因 flight 锁串行化
           而各自发出一次真实 RPC。list_clients(force) 自 0.1.0-M2 同构。
端点     : GET /api/v1/clients/convergence——session-gated 只读（仅
           _require_session；无 CSRF、无 step-up、无 Idempotency-Key；
           POST → 405）。顺序：status(force=True) 先行，其后
           list_clients(force=True)；任一 transport 非 fresh ⇒ 503
           e3_unavailable（helper 语义 verdict 走既有错误表映射，如
           E_LOCK→423，不伪装成 unavailable）；两半都 fresh 才 200，
           payload 各自过 sanitize_e3_data（deny-by-default 白名单不变）。
响应     : {"ok":true,"status":{...同 GET management/status 形状...},
           "clients":{...同 GET /api/v1/clients 形状...}}——服务端把新鲜度
           耦合进同一个 JSON 信封，浏览器看到的原子性有单一事实来源。
前端     : 确认成功的 then 分支只调 convergeAfterMutation()（delete 路径
           仍先 loadSession()，session 不覆盖可用性，既有测试钉住）。
           原子性三层：① state.e3Status/e3StatusAt/e3Clients 一起写入后
           才 renderE3Controls()（一次渲染 pass 同时移动徽章、控件、表格）；
           ② supersedePlainReads() 在收敛开始与应用时各抬升一次
           e3StatusGeneration/e3ClientsGeneration——watchdog 或任何在途
           普通 status/list 读的旧响应一律作废（含收敛窗口内新发的读）；
           普通读在 commit 时额外拒绝：若 state.e3Convergence 非空（有收敛
           正持有视图），即便其自身 generation 仍是当前值也丢弃结果——否则
           一个在窗口内启动、抢在收敛之前落地的 watchdog/手动读会渲染出中间
           stale 视图，正是要消除的可见闪烁（0.1.4 评审阻塞点）；
           ③ state.e3Convergence 身份令牌——重叠的收敛后发制前发。
失败     : fail-closed——清 e3Status ⇒ 不可写；列表行保留但无操作按钮；
           无 sleep、无重试循环、绝无假 Available；绝不写 #e3-msg，
           "Client created./Client deleted." 存活。非全 fresh 的 200 信封
           在前端同样按失败处理（纵深防御）。
边界     : Monitor-only（web/server.py、web/e3_broker.py、static/app.js）；
           helper/sbox-cm/sing-box 零改动；VERSION 0.1.3→0.1.4。
```

---

## 8. 调用方等待预算与超时语义（冻结）

per-op 预算见 §4 表。实现上 = `e3rpc` 对 socket I/O 的总预算（ connect + 发帧 + 收帧），
预算内利用 helper 的 5 s 帧读取自然限速；**不向 helper 传任何 deadline 字段**
（协议没有这个字段，也不许有）。

| 场景 | Web 行为 |
| --- | --- |
| status 预算耗尽 | 属于 breaker 的 status transport 失败：计数（§7.3）；该次请求按 §7.3 open/half-open 语义返回（`503 e3_unavailable` 或 stale snapshot） |
| list 预算耗尽 | 仅该次请求 `503 e3_unavailable`；【不】递增 breaker counter（status-driven，§7.3） |
| mutation 预算耗尽 | **绝不计入/毒化 breaker**（status-driven，§7.3）；响应 `504 result_unknown`（retriable=true + `uncertain:true` 标记）；UI 按 S-1 呈现"结果未知"；**禁止自动重试、禁止换 key** |
| helper 返回 `E_TIMEOUT`（帧读取超时） | 透传映射 504（rev5 §2.6 原表；ERRATA 后语义 = 5 s 帧读取超时） |
| deactivate 遇到旧 helper `E_SCHEMA` | 原样映射 400，UI 提示 helper 版本过旧（不自动重试） |

---

## 9. HTTP API 契约与字段白名单

| 方法 | 路径 | 映射 | 门（全部沿用既有实现，不放松） |
| --- | --- | --- | --- |
| GET | `/api/v1/management/status` | `management.status`（broker）+ Web 自供 `monitor_running` | `_require_session` |
| GET | `/api/v1/clients` | `client.list`（broker 缓存 5 s） | `_require_session` |
| POST | `/api/v1/management/activate` | `management.activate` | `_require_session` + CSRF + step-up |
| POST | `/api/v1/management/deactivate` | `management.deactivate` | 同上 |
| POST | `/api/v1/clients/add` | `client.add` | 同上 |
| POST | `/api/v1/clients/delete` | fresh-list 预检 → `client.delete` | 同上 |

`monitor_running` 由 Web 自供（Web 自己就是 monitor，"我在运行"是本地事实，冻结裁决），
不要求 helper 提供。

**响应白名单（deny-by-default，M1 实际字段显式枚举）**：

```text
status  : management_state, management_active, helper.degraded, helper.reconcile,
          lock.acquirable,                       # lock.path 排除（root 路径）
          last_transaction.{generation, op, outcome, ended_at}
          + Web 附加: monitor_running, as_of, transport(fresh|stale|unavailable)
list    : clients[].{name, protocols, reserved, mutable, source}, truncated + as_of
add     : name, protocols, mutable, source, yaml_available, credential_delivery,
          warnings                              # 不含凭据（helper 本就不返回）
delete  : deleted, derived_cleanup, warnings
activate/deactivate : management_state, no_op（以 M1 实际返回为准）
错误    : error.{code, stage, retriable, detail}
          # error.backup 排除（/root/sbox/... 备份路径）；request_id/op 透传
```

`idempotency{key_fp, replayed, generation}` 透传（UI 需要 `replayed` 展示"这是重放结果"）。
`v`、`ok` 由 Web 信封统一承载。

**请求组装**：

```text
request_id      : 每次物理 RPC 尝试新生成（"web-" + uuid4，≤64 字节，匹配 helper 正则）
idempotency_key : client.add / client.delete 经 HTTP 【Idempotency-Key header】送达
                  （冻结修订：单一来源，body 不携带第二份 key）。Web 校验
                  16..128 ASCII [A-Za-z0-9._:-] 后【原样】映射为 helper JSON
                  的 idempotency_key 字段；缺失/非法 ⇒ 400 invalid_idempotency_key
                  （不派发 RPC）。401 step-up 重放与 result_unknown 后用户显式
                  重试必须复用同一 header 值（Browser 确认流状态持有至请求终态）；
                  request_id 仍在每个物理 RPC attempt 重新生成（上行规则不变）。
actor           : {session_fp, stepup_fp}——见 §12 指纹派生；仅 activate/add/delete/
                  （M2-A0 后的）deactivate 携带
name / confirm  : name 双层校验（Web 正则 + legacy 拒绝，helper 再校验）；
                  type-to-confirm 的逐字回显由服务端复核（§11）
```

---

## 10. 错误映射（rev5 §2.6 为权威 + Web 层补充码）

helper 错误码 → HTTP 按 rev5 §2.6 原表透传（`E_LOCK`→423、`E_DUPLICATE_NAME`→409、
`E_RECONCILE_CONFLICT`→409、`E_STATE_UNCERTAIN`→503、`E_ROLLED_BACK`→503、
`E_MANUAL_INTERVENTION`→500、`E_ACTIVATION_STATE`→409 …），**`retriable` 原样透传**，
`detail` 原样透传（helper 侧已做禁凭据卫生）。Web 层新增码：

| code | HTTP | retriable | 语义 |
| --- | --- | --- | --- |
| `e3_unavailable` | 503 | true | helper 不可达且无可服务 snapshot（mutation 派发前拒绝； breaker open 时 mutation 一律此码）；status/list 有 snapshot 时按 §7.3/§7.5 返回 stale 而非本码 |
| `list_unavailable` | 503 | true | delete 预检 fresh-list 失败（未派发 delete） |
| `e3_busy` | 503 | true | 进程内背压等待超时（E-15） |
| `result_unknown` | 504 | true | mutation 调用方预算耗尽；`uncertain:true`；UI 呈现"结果未知"（S-1）；不计入 breaker |
| `invalid_idempotency_key` | 400 | false | Idempotency-Key header 缺失/非法（§9；未派发 RPC） |

两条特殊 UX 映射（E-14）：

```text
E_RECONCILE_CONFLICT(409) : UI 明示"服务器状态已变化，请刷新核对后再操作"，
                            绝不静默重试、绝不自动重放。
E_STATE_UNCERTAIN(503)    : 明示"变更可能已生效但收尾未完成；用同一 Idempotency-Key
                            重试可补齐"，重试动作由用户显式发起。
```

---

## 11. UX 合同

```text
U-1 危险操作明示（E-14）: add/delete/activate/deactivate 前后果明示（将发生什么、
                          影响哪个对象、是否触发 reload）。
U-2 type-to-confirm     : delete 需逐字回显 name；服务端复核 confirm==name，
                          不相等 ⇒ 400 confirm_mismatch（不能只靠前端）。
U-3 step-up 挂钩        : 401 reauth_required ⇒ 弹密码框 ⇒ 成功后自动重放原请求，
                          confirm 与 Idempotency-Key header 值不变（E-6）。
                          step-up 端点、TTL、五类吊销语义全部沿用 M0.5 实现，
                          M2 仅扩展 step_up 记录字段（§12 S-A），不改吊销语义。
U-4 uncertain 态        : result_unknown ⇒ 非失败横幅 + "结果未知" + 指向 status 的
                          last_transaction + （可选）"用同一 key 重试"按钮。
U-5 degraded 态         : status.helper.degraded==true（且该值来自真实 status
                          响应，§7.5）⇒ 全局横幅"特权助手处于 degraded，变更被
                          拒绝，需 root 恢复"；mutation 控件禁用。
U-6 transport 态         : stale ⇒ "数据时点 as_of" 横幅（可继续浏览，mutation
                          控件按 §7.5 fresh-only 规则处理）；unavailable ⇒ 管理
                          块退化为只读 + "helper 不可达"横幅。两者【绝不】显示为
                          "helper degraded"。
U-7 legacy              : 列表中 reserved:true, mutable:false 仅展示；add 名为 legacy
                          与对 legacy 的 delete 在 Web 层直接拒绝（E-7 双层防御的
                          Web 侧）。
U-8 凭据交付            : add 成功 ⇒ "已创建；凭据请在服务器侧用 CLI 生成配置"
                          （S-3 / 冻结裁决，界面永不出现凭据）。
```

---

## 12. 安全边界

```text
S-A 指纹派生与生命周期（M2 对 SessionStore 的进程内存态扩展）:
  现状   : M0.5 SessionStore 的 step_up 仅含 expires_at——没有 granted_at / fp；
           这两项是 M2 的内存态扩展，不持久化、不进任何存储文件。
  grant  : 成功 grant 时同时写入 step_up_granted_at 与 stepup_fp；
           stepup_fp = sha256(session_token + ":" + str(step_up_granted_at))[:16 hex]。
  复用   : 同一 window 内所有 mutation 复用同一 stepup_fp（审计可归因）。
  轮换   : 下一次 grant（含窗口过期后重新 step-up）必须生成新 granted_at ⇒ 新 fp。
  吊销   : 既有五类吊销（logout / password / recovery reset / recovery rotate /
           session TTL 过期；web 进程重启为既有事实）必须把 expires、granted_at、
           stepup_fp 三元组【同时】清除——不允许残留可复用的 fp。
  暴露面 : stepup_fp 与 step_up_granted_at 绝不出现在任何 HTTP 响应/UI；
           仅随 RPC actor 字段发往 helper 做审计归因。
           session_fp 仍 = sha256(session_token)[:16]，随 session 生命周期。
           指纹单向、不可还原 token；helper 侧按 FP_RE 校验、仅作审计归因
           （S-2 rev5）。
S-B helper 永不接收 : 密码、恢复密钥、session cookie、CSRF token、URL、原始身份
                （rev5 §5.3 S-2 全文继承；M2 代码结构上使这些值根本到不了 e3rpc 层）。
S-C 日志卫生  : Web 侧新增日志/异常路径不得记录凭据、token、key 明文；
                idempotency_key 可记 key_fp（helper 返回）或自身前 8 位。
S-D 源码字符串禁令（T12 延伸）: e3rpc/e3_broker/e3_mutations 及 UI 均不得出现
                /root/sbox、/var/lib/sbox-cm、sbconfig、management.active。
S-E 单元依赖  : monitor unit 不加 Requires=/After= sbox-cm（monitor 必须能在
                helper 缺席时照常服务监控面，由 breaker 降级，而不是启动失败）。
S-F 无新配置面: 不新增 env key、不新增配置键；socket 路径为常量 + 测试注入。
```

---

## 13. 运行时实测前置与 unit 契约（B-5 纪律，不可跳过）

**实测结论（M2-E，`tests/e3/test-m2-live.sh`，三基线原始日志）**：
monitor unit（`User=sboxweb`，`ProtectSystem=strict`，`ReadWritePaths` 仅数据根）
连接 `/run/sbox-cm/sbox-cm.sock` **不需要**任何 carve-out——三个 Ubuntu 基线在
无 carve-out 的 shipped unit 下均实测 connect 成功。按 least privilege，
`-/run/sbox-cm` 已从模板移除（final review B5），T12/packaging 的最小权限断言
恢复原样；live 套件改为直接验证 shipped unit 连接真实 helper，并内置
"ReadWritePaths 必须恰为数据根"的 per-baseline 回归守卫。socket DAC
（root:sboxweb 0660）对 sboxweb 组可写，这层无需改动。

```text
预期修正     : singbox-monitor.service.in 的 ReadWritePaths 追加 -/run/sbox-cm
               （前导 '-'，容忍 sbox-cm 未安装）。
测试契约影响 : M0.5 T12 断言"恰一条 ReadWritePaths"、"无 sbox-cm 路径"——该断言
               【必须随本修正有意识地更新】为"恰两条、第二条必须是只读意图的
               -/run/sbox-cm、仍无 /root/sbox 与 /var/lib/sbox-cm 写路径"。
               这是一次有记录的契约变更，不是悄悄放宽；diff 与理由进 PR 描述。
验收方式     : 真实 systemd PID 1 下双 unit 联测（M2-E）——不许用"看起来应该行"代替。
               套件沿用 B-5 教训：退出码契约自检 + SKIP=FAIL 开关
               （SINGBOX_MONITOR_REQUIRE_LIVE=1 类）+ 只认原始 PASS/FAIL/SKIP summary。
```

其余运行时事实（无需改动，记录备查）：`RestrictAddressFamilies` 已含 `AF_UNIX`；
socket DAC 由 systemd `SocketGroup=sboxweb` 保证；helper 侧对 monitor 的 uid 校验即
SO_PEERCRED uid==sboxweb（与 CLI 并存无冲突）。

---

## 14. 测试策略与诚实闸门

```text
T-1 API 契约测试（mock helper，真实 AF_UNIX + 真实帧格式）
    错误映射全表（§10）与 retriable 透传；breaker 三态迁移与计数边界
    （协议错误不计数）；2s/5s TTL 与 as_of；stale-active 永不信任（TTL 过期+
    刷新失败 ⇒ provider=False）；delete 预检（fresh 失败 ⇒ 不派发）；
    Idempotency-Key header 跨 401 重放不变；type-to-confirm 服务端复核；
    name/legacy 双层拒绝；白名单（lock.path / error.backup 永不出现于响应）；
    request_id 每次尝试新生成；deactivate actor 透传（M2-A0 后）。
    并发断言 : 20 线程同时触发过期 TTL 刷新 ⇒ 恰好 1 次 helper RPC
               （status 与 list 各测一组）；half-open 并发 ⇒ 恰好 1 个 status
               probe、其余请求不产生 RPC；cache/breaker 并发压测无 torn state。
    breaker 断言 : counter 仅由 status transport 失败驱动；list/mutation 失败
               （含 caller timeout ⇒ result_unknown）后 counter 与状态不变。
    header 断言 : Idempotency-Key 缺失/非法 ⇒ 400 invalid_idempotency_key 且
               不派发 RPC；重放复用同一 header 值。
T-2 既有回归必须全绿 : test-monitor-v2-m05.sh（T1–T12，含更新后的 T12 契约）、
    test-monitor-v2-e2.sh、test-platform 无关项不触碰（注意：M2 只动 monitor-v2）。
T-2b M0.5 auth regression（M2 扩展）: 五类吊销事件各自断言 step_up 的
    expires / granted_at / stepup_fp 同时清除；grant 轮换产生新 fp；
    全部 HTTP 响应不含 stepup_fp / step_up_granted_at；
    management_active provider 在无 helper 注入时仍 fail-closed False。
T-3 卫生负向扫描 : 新代码路径无凭据泄漏面；journald/Web 日志 fixture 脱敏。
T-4 live 闸门（M2-E）: 真实 singbox-monitor.service + 真实 sbox-cm.socket：
    status → list → add（注入首次 reload 失败 ⇒ rollback 路径）→ delete →
    deactivate 全链路 + unit carve-out 实证 + breaker 真实迁移（停 socket 观察）。
    输出 E3_M2_LIVE=PASS 与 PASS/FAIL/SKIP 计数；SKIP 即失败开关默认在 CI 打开。
T-5 CI 纪律 : 沿用 B-5 结论——验收只认原始日志 summary，step 绿不算数；
    FAIL>0 必须真红（退出码契约自检内置）。
```

---

## 15. 里程碑拆分与完成定义

| 阶段 | 交付 | 闸门 |
| --- | --- | --- |
| **M2-A0** | daemon `OPS` deactivate + actor（单行）+ 契约测试 | M1 全套回归三基线原始日志 `FAIL=0`，B-5 真实执行 `SKIP=0` |
| **M2-B** | `e3rpc` + broker（TTL/breaker/provider）+ webapp 接线 | T-1 契约测试全绿 + M0.5/E2 回归全绿 |
| **M2-C** | 六个 HTTP endpoints（2 GET + 4 mutation POST）+ 错误映射 + 白名单 | T-1 全绿；字符串禁令扫描通过 |
| **M2-D** | UI（status 卡 / client 表 / 确认流 / 三态横幅） | API 层断言 + 静态断言（UI 逻辑保持薄，浏览器侧无新框架） |
| **M2-E** | unit carve-out + live 联测套件 | T-4 原始日志三基线（或至少两基线 + 22.04）真实 `E3_M2_LIVE=PASS` |

```text
M2 COMPLETE 当且仅当 : A0–E 全部闸门绿 + 文档收口（本文 rev2 记录实测结果）
                       + E3 MANAGEMENT ENABLED 仍 = NO
                       + PRODUCTION DEPLOYED 仍 = NO
回滚方式             : 代码级回滚——revert M2 路由接线 commit 即恢复 M0.5 的
                       501 mutation boundary（管理面回"只读展示、变更不可达"）；
                       不存在、也不引入 runtime config/env feature flag。
                       rev5"web 侧熔断 ⇒ 界面回只读"的承诺由 §7.3 breaker 的
                       运行时行为达成（helper 缺席/熔断即只读），不需要开关；
                       helper 侧 A0 为可选字段，向后兼容，可独立回退。
```

---

## 16. 未决项与残余风险

| # | 项 | 状态/缓解 |
| --- | --- | --- |
| O-1 | `/run/sbox-cm` carve-out 是否真需要 | 未实测（§13）；M2-E 用真实双 unit 定案，不预先改断言放行 |
| O-2 | list 展示与 delete 之间的竞态窗口 | helper 锁内复核兜底（E_NOT_FOUND / E_RECONCILE_CONFLICT）；Web 层双重 fresh-list 仅是 UX/纵深 |
| O-3 | helper 升级次序（A0 actor） | §5 部署次序约束；旧 helper 的 `E_SCHEMA` 有明确 UX，不自动重试 |
| O-4 | 指纹碰撞/泄漏面 | 16 hex 截断仅用于归因；不可还原 token；不参与鉴权 |
| O-5 | `transaction` 对象（rev5 §6.1）M1 未实现 | M2 白名单按实际字段，不伪造；未来 helper 若实现，白名单显式扩列 |
| O-6 | rev5 其余与实现有出入的描述 | 本轮仅按冻结裁决修 deadline errata；其余如 G-review 中发现，逐项走 errata 流程，不悄悄改 |
| O-7 | Web 重启丢 step-up/会话（memory-only） | 既有安全默认（S-3）；在途 mutation 结果经 status.last_transaction 观测或同 key 重试（R10） |

---

## 17. rev5 deadline errata 交叉引用

本 commit 同时对 `docs/e3-rev5-privileged-mutation-design.md` 落了纯文档 errata：

```text
§2   头部新增 ERRATA 块：M1 B6 实现 supersede §2.1/§2.4/§2.6 的 helper
     overall-op deadline 描述；现行合同 = 无整体 deadline + 5s 帧读取 +
     cm_bounded 子步限时 + 120s 为 M2 调用方预算；§2.1"单线程串行"同被
     取代为每连接一线程（串行化仍在 config.lock）。
§2.4 表前加 ERRATA 标记行（原文保留作历史）。
§2.6 E_TIMEOUT 行内标注新语义（仅指 5s 帧读取超时）。
```

此后"代码按新合同、reviewer 拿旧 rev5 表判错"的冲突面已消除；rev5 与 M1/M2 文档的
从属关系为：**实现 > M1/M2 设计文档 > rev5 历史文本（经 ERRATA 标注）**。

---

## 18. G-review 记录

```text
2026-09-19  G-review #1（rev1）: 主体方向通过；以下 delta 修订项已在 rev2 并入：
            1. broker 并发合同：cache/breaker thread-safe；status/list 各自
               single-flight；并发 TTL 过期不产生 RPC fan-out；half-open 全进程
               严格单 probe；T-1 增加并发断言（20 线程 ⇒ 1 次 RPC）。
            2. helper degraded 与 Web transport state（fresh|stale|unavailable）
               严格分离（§7.5）：degraded 只来自真实 status 响应；刷新失败可返回
               stale + 原 as_of 但 management_active=False；"helper 不可达"
               绝不描述/呈现为 degraded。
            3. stepup_fp 生命周期补全（§12 S-A）：SessionStore 内存态扩展
               granted_at + fp；grant 创建、窗口内复用、再 grant 必换新；
               五类吊销同时清 expires/granted_at/fp；不暴露 Browser；
               T-2b auth regression。
            4. Idempotency-Key 冻结为 HTTP header（§9）：Web 校验后原样映射
               helper idempotency_key；body 不再设计第二份 key；重放/显式重试
               复用同一 header 值；request_id 每物理 attempt 重新生成。
            5. breaker 改为 status-driven（§7.3）：counter/迁移只由
               management.status transport probe 驱动；list/mutation 失败返回
               本次错误但不递增 counter；mutation caller timeout ⇒
               result_unknown，绝不 poison breaker；open 仍拒绝新 mutation；
               half-open 单 probe；open 期间 status 可返回 stale snapshot
               （保住 uncertain 后的 last_transaction 查询通道）。
            文字修正：路由计数统一为"六个 HTTP endpoints（2 GET + 4 mutation
            POST）"；完成定义回滚方式改为明确的 code rollback / 恢复 501
            boundary（不存在 feature flag）。

2026-09-19  rev3（实现收口，M2-A0…M2-E）：
            * M2-A0：daemon OPS deactivate + optional actor（单行）+ probe/
              worker 回归；
            * M2-B/C：web/e3rpc.py、web/e3_broker.py、auth.py stepup_fp 扩展、
              server.py 六端点 + 白名单 + result_unknown、webapp.py 装配；
            * M2-D：UI（management 卡 transport/degraded/as_of、client 表、
              type-to-confirm 删除流、uncertain/reconcile-conflict 文案、
              add 凭据走 CLI 提示）；
            * M2-E：tests/e3/test-m2-live.sh（carve-out 双向实测 + 全事务 +
              result_unknown 活体证明 + stale-active fail closed + breaker
              恢复 + PEERCRED）；monitor unit 模板加 -/run/sbox-cm；
              m05 T12 断言有意识更新为"数据根 + dash-prefixed carve-out"；
            * 既有回归：M0.5（137 断言）、E2（272 断言）保持全绿（501→503
              fail-closed 契约为有意识变更）。

2026-09-19  Final source/runtime review（rev3 → rev4 delta，5 个 merge
            blocker 全部修复）：
            B1 helper ok:false 语义 verdict 正确传播——broker 不写成功缓存、
               不计 breaker、last-known-good 不被覆盖；HTTP 按 §2.6 表映射
               （status E_INTERNAL→500、list E_LOCK→423、E_CONFIG_INCONSISTENT
               →409）；delete 预检遇语义错误按原语义返回，绝不伪装 E_NOT_FOUND；
            B2 step-up actor 在 gate 内经 step_up_credentials 原子冻结并直传
               handler；handler 不再重读 fp；revoke race 回归证明 dispatch
               时 helper 收到的仍是 gate 时 fp；
            B3 uncertain same-key retry 真正落地：pending {op,name,key} 持久
               于页面状态 + 显式 Retry 按钮复用同一 header 值；terminal
               verdict 清除；无 key 时只能 fresh 核对、绝不称 retry；
            B4 统一 e3Writable 门控（transport==fresh 且非 degraded）——非
               writable 时 activate/deactivate/add 禁用、删除控件不渲染，
               stale 只读展示；修复 loadE3Clients catch 的 ReferenceError；
            B5 撤销未证明必要的 -/run/sbox-cm carve-out（三基线实测无需），
               恢复 M0.5 T12/packaging 最小权限断言（M0.5 137→136：一条
               carve-out 断言删除），live 套件直接验证 shipped unit 连接。
（M2 merge 决策待 review 人）

```
