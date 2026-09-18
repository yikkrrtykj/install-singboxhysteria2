# E3 M2 — Web 适配层设计（sbox-cm Web Adapter，rev1）

```text
状态           : DESIGN FROZEN（方向批准 2026-09-19，待 G-review）
本文性质       : 设计文档 + 冻结裁决记录；本提交为 DOCS-ONLY
实现面         : 本提交不含任何 M2 实现代码
E3 MANAGEMENT  = NO（本文交付后仍保持默认安全态）
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
| broker | `monitor-v2/web/e3_broker.py` | status/list TTL 缓存、breaker 状态机、`management_active()` provider、`as_of` 时间戳 | 异常一律 fail-closed；见 §7 |
| mutation 转发 | `monitor-v2/web/e3_mutations.py` | 请求校验与组装、type-to-confirm 服务端复核、actor 指纹、白名单映射 | 不重试 mutation（S-1）；不落盘 |
| 路由接线 | `server.py`（最小 diff） | 五条路由换实现/新增 list 路由；`management_active` provider 换 broker | M0.5 的门与 `MUTATION_ROUTES` 集合不变 |
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
as_of      : 每个经 broker 的响应携带 as_of（UTC ISO8601），UI 据此展示"数据时点"。
获取时机   : 惰性 + TTL（无后台线程；请求路径上过期即触发一次同步刷新，
             刷新失败回退旧 payload 展示 + as_of 不变 + degraded 标记；
             但 management_active() 的判定只认新鲜值，见上）。
```

### 7.2 client.list 展示缓存与删除预检

```text
展示缓存 TTL : 5 s（冻结值）。仅用于列表展示。
删除预检     : 进入 destructive confirm 前必须绕过缓存强制拉一次 fresh list；
               fresh list 失败 ⇒ 不允许进入确认流程（UI 层）。
               delete 路由在派发 delete RPC 前再做一次同样的 fresh-list 预检
               （Web 层纵深防御）：失败 ⇒ 503 list_unavailable，**不派发 delete**。
正确性边界   : 该预检是 UX + 纵深防御，不是正确性的唯一保障——helper 会在锁内
               重新验证（不存在 ⇒ E_NOT_FOUND；被重建/轮换 ⇒ E_RECONCILE_CONFLICT）。
```

### 7.3 breaker（冻结：3 failures / 10s open / 1 half-open probe）

```text
closed   --连续 3 次【传输层】失败--> open（10 s）
open     --10 s 到期--> half-open（只放一个 status probe）
half-open --probe 成功--> closed
half-open --probe 失败--> open（重新计 10 s）

计数范围 : 仅传输层失败 = connect 拒绝/超时、帧读写 I/O 错误、调用方预算耗尽。
           协议层错误（helper 返回的 4xx/5xx 语义码，如 E_DUPLICATE_NAME、
           E_ACTIVATION_STATE）【不】计数——那说明 helper 健康，只是本次操作不被允许。
open 期间 : status/list ⇒ 503 e3_unavailable（附 as_of=最后成功时点，可展示旧值+横幅）；
            management_active() ⇒ False；
            mutation ⇒ 503 e3_unavailable，不派发（UI 整块退化为只读）。
```

### 7.4 Web 侧背压（E-15，不充当全局锁）

进程内 mutation 信号量（建议 4 并发）+ 等待上限 30 s；等待超时 ⇒
`503 e3_busy`（retriable）。作用仅是防止失联 helper 造成的线程堆积；真正的串行化
始终是 helper 的 config.lock。

---

## 8. 调用方等待预算与超时语义（冻结）

per-op 预算见 §4 表。实现上 = `e3rpc` 对 socket I/O 的总预算（ connect + 发帧 + 收帧），
预算内利用 helper 的 5 s 帧读取自然限速；**不向 helper 传任何 deadline 字段**
（协议没有这个字段，也不许有）。

| 场景 | Web 行为 |
| --- | --- |
| read-only（status/list）预算耗尽 | 计入 breaker 传输失败；`503 e3_unavailable` |
| mutation 预算耗尽 | **不计入 breaker？——计入**（属于传输层不确定）；响应 `504 result_unknown`（retriable=true + `uncertain:true` 标记）；UI 按 S-1 呈现"结果未知"；**禁止自动重试、禁止换 key** |
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
          + Web 附加: monitor_running, as_of
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
idempotency_key : 用户动作发起时生成一次（同规则），存于确认流状态（浏览器侧）；
                  401 step-up 重放与"结果未知后重试"必须携带同一 key（E-6 / S-1）
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
| `e3_unavailable` | 503 | true | breaker open / connect 失败（读路径与 mutation 派发前拒绝） |
| `list_unavailable` | 503 | true | delete 预检 fresh-list 失败（未派发 delete） |
| `e3_busy` | 503 | true | 进程内背压等待超时（E-15） |
| `result_unknown` | 504 | true | mutation 调用方预算耗尽；`uncertain:true`；UI 呈现"结果未知"（S-1） |

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
                          confirm 与 idempotency_key 不变（E-6）。step-up 端点、
                          TTL、五类吊销语义全部沿用 M0.5 实现，M2 不改。
U-4 uncertain 态        : result_unknown ⇒ 非失败横幅 + "结果未知" + 指向 status 的
                          last_transaction + （可选）"用同一 key 重试"按钮。
U-5 degraded 态         : status.helper.degraded==true ⇒ 全局横幅"特权助手处于
                          degraded，变更被拒绝，需 root 恢复"；mutation 控件禁用。
U-6 breaker/离线态      : e3_unavailable ⇒ 管理块退化为只读 + "数据时点 as_of"。
U-7 legacy              : 列表中 reserved:true, mutable:false 仅展示；add 名为 legacy
                          与对 legacy 的 delete 在 Web 层直接拒绝（E-7 双层防御的
                          Web 侧）。
U-8 凭据交付            : add 成功 ⇒ "已创建；凭据请在服务器侧用 CLI 生成配置"
                          （S-3 / 冻结裁决，界面永不出现凭据）。
```

---

## 12. 安全边界

```text
S-A 指纹派生  : session_fp = sha256(session_token)[:16 hex]；
                stepup_fp  = sha256(session_token + ":" + str(stepup_granted_at))[:16]，
                在 grant 时算好存于内存 session 的 step_up 记录中，窗口内复用
                （同一窗口的审计可归因）。指纹单向、不可还原 token；
                helper 侧按 FP_RE 校验、仅作审计归因（S-2 rev5）。
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

## 13. 运行时实测前置与 unit 契约变更（B-5 纪律，不可跳过）

**开放问题（M2-E 的核心验证项）**：monitor unit（`User=sboxweb`，
`ProtectSystem=strict`，`ReadWritePaths` 仅数据根）能否 `connect()` 到
`/run/sbox-cm/sbox-cm.sock`。M1 的 B-5 实测经验：`ProtectSystem=strict` 会把 `/run`
挂成只读，**connect 到 /run 下的 socket 需要写权限路径放行**（sbox-cm 自身为此带
`-/run/systemd` carve-out；socket 文件本身的 DAC（root:sboxweb 0660）对 sboxweb 组
可写，这层没问题）。

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
    idempotency_key 跨 401 重放不变；type-to-confirm 服务端复核；
    name/legacy 双层拒绝；白名单（lock.path / error.backup 永不出现于响应）；
    request_id 每次尝试新生成；deactivate actor 透传（M2-A0 后）。
T-2 既有回归必须全绿 : test-monitor-v2-m05.sh（T1–T12，含更新后的 T12 契约）、
    test-monitor-v2-e2.sh、test-platform 无关项不触碰（注意：M2 只动 monitor-v2）。
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
| **M2-C** | 五条路由 + 错误映射 + 白名单 | T-1 全绿；字符串禁令扫描通过 |
| **M2-D** | UI（status 卡 / client 表 / 确认流 / 三态横幅） | API 层断言 + 静态断言（UI 逻辑保持薄，浏览器侧无新框架） |
| **M2-E** | unit carve-out + live 联测套件 | T-4 原始日志三基线（或至少两基线 + 22.04）真实 `E3_M2_LIVE=PASS` |

```text
M2 COMPLETE 当且仅当 : A0–E 全部闸门绿 + 文档收口（本文 rev2 记录实测结果）
                       + E3 MANAGEMENT ENABLED 仍 = NO
                       + PRODUCTION DEPLOYED 仍 = NO
回滚方式             : web 侧功能开关回退 ⇒ 界面回只读（rev5 M2 行的回滚承诺）；
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
（待 G-review 后回填：结论、修订项、批准人/日期）
```
