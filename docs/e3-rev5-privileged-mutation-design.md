# Monitor v2 — Phase E3 Design rev5: Privileged Mutation Architecture（AF_UNIX RPC 特权变更架构）

状态：**设计稿 rev5（已吸收独立 review 修正 #1–#8；全部代码事实重新锚定于冻结基线 `3ee9a162`；待 final design approval；本轮零实现）**

基线锚点：

| 项 | 值 |
| --- | --- |
| 仓库 | `yikkrrtykj/install-singboxhysteria2` |
| 设计基线 commit（唯一代码事实来源） | `3ee9a162a3fb53d9fddc95cb6eba95b3bcc5702e`（Round 2 head，I0-7 CLOSED） |
| 行号口径 | 本文所有 `install.sh:N` 均为 **`git grep -n` 于 `3ee9a162…` 该 commit** 的结果；本地旧工作树行号一律作废 |
| 上游设计 | `docs/monitor-v2-e3-design.md`（rev4，§编号沿用其语义） |
| Round 2 报告 | `round2-final-report.md`（L5 = provisional activation marker，E3 被阻塞） |
| 模式 | DESIGN / READ-ONLY。不连 VPS、不碰生产、不合并 PR #16/#17、不暴露 9191、不动 TLS/防火墙/凭据 |

---

## 0. rev5 与 rev4 的关系（继承 / 修订 / 推迟）+ review 修正索引

rev5 不推翻 rev4 的事务语义，只**更换特权通道并收敛初始操作面**：

| # | rev4 / rev5 首版 | rev5（本版） | 理由 |
| --- | --- | --- | --- |
| R5-1 | sudo 拉起**短命** helper，stdin/stdout JSON | **常驻 root 守护进程 `sbox-cm`**，AF_UNIX 流式 RPC | 任务书钦定架构。收益：连接级 SO_PEERCRED 鉴权、断连后事务可脱离调用方跑到终态（§8-R10）、无 sudo 日志噪声 |
| R5-2 | verb allowlist 7 个 | **初始 RPC 操作面 6 个**：`management.status / management.activate / management.deactivate / client.list / client.add / client.delete`（§7；review #5 新增 `client.list`） | minimal surface；inventory 读通道独立成 op，不超载 status |
| R5-3 | rev4 账本/审计放 `/root/sbox/web/`；基线 marker 默认 `/root/sbox/web-management.active`（`install.sh:2413`） | 特权运行时状态整体迁往 **`/var/lib/sbox-cm/`（root 0700）**；`SB_MANAGEMENT_ACTIVE_MARKER` 常量名保留、生产默认路径迁出 `/root/sbox`（§4.1–4.2） | 基线 `uninstall_singbox` 仍 `rm -rf /root/sbox/`：放在里面的标记与锁都会被它自己销毁 |
| R5-4 | L5 marker 仅是 provisional（基线 `install.sh:2413/2416/2419`，锁外检查） | **正式化**：路径迁移 + 检查移入锁内 + 锁下生命周期 + 锚点不灭契约（§4.3–4.5） | 消除 activation TOCTOU 与锁 inode 替换漏洞 |
| R5-5 | helper 事务依赖调用方在位 | **断连不可中止事务**（§8-R10） | 守护进程模型下"web 重启于 mutation 途中"是一等失败场景 |
| R5-6 | 失败矩阵 F1–F22 | F1–F22 语义保留并被 RPC 错误码表吸收；新增 R1–R12 竞态矩阵（§8） | 同一套 `commit_server_config`，错误语义同源 |
| R5-7 | rev4 §4.7 锁契约 L1–L6 | **原样继承**；L5 扩展：management.* 也持锁；新增 L7"锁路径名永不 unlink"（§3.2） | 单一互斥点 + 永久锚点 |
| R5-8（review #1） | rev5 首版误判锁 fail-open（引用了本地旧工作树） | **撤销 B-1**。基线 `with_client_lock`（`install.sh:729-745`）在锁目录创建失败（734-735）、锁文件打开失败（738-739）、flock 错误/超时（743-744）三条路径上全部 fail-closed 中止。**Round 2 全局锁前置 = ALREADY PASS** | 事实修正；E3-0 对锁只做 verify + preserve |
| R5-9（review #2） | 首版仅"uninstall 先取锁" | **锁生命周期问题显式解决**：config.lock = 永久控制面锚点；uninstall 保留 `/root/sbox/` 目录与 config.lock 本体；仅在锁内移除运行时/配置/凭据物；任何事务内永不 unlink 锁路径名（§4.4） | unlink 被锁路径名后，他人可重建同名新 inode 并获得**另一把** flock ⇒ 绕过互斥；仅取锁不够 |
| R5-10（review #3） | 首版默认 `commit_server_config` 回滚语义照搬 | **M0 硬化共享事务**：基线回滚在 `install.sh:967` 执行未校验的直接 `cp -a "$backup_path" "$SB_SERVER_CONFIG"`；M0 以已评审的 `restore_file_atomically`（`install.sh:2314`：同目录唯一临时文件 + chmod 0600 + 原子 mv + cmp 逐字节校验）替换之；共享库输出结构化事务结果；CLI 兼容包装继续暴露历史 0/1 行为。**不复制提交引擎**（§3.1） | 通用单文件事务的回滚不允许未校验直接覆盖 live 路径名 |
| R5-11（review #4） | tx journal 语义含糊 | **区分进程崩溃恢复与掉电持久性**：掉电级持久性声明必须 = 文件 fsync + 父目录 fsync；helper 启动/重启必须在**同一把 config.lock** 下调和未完成 journal 后才接受 mutation；无法证明安全态 ⇒ status 仍可用、一切 mutation fail-closed `MANUAL_INTERVENTION`；journal 永不含凭据（§3.2） | 两种故障模型不同，承诺必须分别成立 |
| R5-12（review #5） | clients 摘要塞在 status 里 | 新增只读 `client.list`（锁内、最小净化清单、零凭据），`management.status` 不再携带 clients 数组（§6.2/§6.5） | sboxweb 无权直读 root 注册表/config，service.api 无法枚举离线客户端 |
| R5-13（review #6） | 首版帧模型含糊 | 显式长度前缀帧 + 服务端 accept/read/request 三级 deadline（§2.1） | 半个请求不得无限期卡死串行 helper |
| R5-14（review #7） | step-up 仅有过期语义 | step-up 绑定当前 session，并在 logout / 改密 / recovery 重置或轮换 / session 过期 / web 重启时**立即吊销**；activate/deactivate/add/delete 均要求近期 step-up；helper 永不收到密码、恢复密钥、session cookie、CSRF token（§5） | 撤销是 step-up 的安全闭环 |
| R5-15（review #8） | 首版 verdict 把未实现代码当开始实现的前置 | 三层 readiness 术语（§14）：BEGIN = 批准即可；ENABLE = 实现 + 全部门禁；DEPLOY = 显式 canary 批准 | 门禁只拦它该拦的阶段 |

rev4 中**逐字保留、不在本文复述**的部分：§6.9 幂等账本（intent/outcome + fsync + generation/supersede + 调和矩阵）、§6.9.1 Idempotency-Key schema、§4.7 L1–L6、失败矩阵 F1–F22、危险操作 UX（§7）、日志脱敏（§8.3）。

---

## 1. 信任 / 特权边界（Trust & privilege boundaries）

### 1.1 架构图

```text
┌─────────────────────────────────────────────────────────────────────┐
│ Browser（管理员）                                                      │
│   只读视图随时可看；任何 mutation 前必须完成 step-up（§5）                │
└───────────────┬─────────────────────────────────────────────────────┘
                │ HTTP（127.0.0.1 / 既有 TLS 反代不变；9191 不新增暴露）
┌───────────────▼─────────────────────────────────────────────────────┐
│ 边界 A：E2 web 服务（sboxweb，非特权）                                  │
│   · 运行用户 sboxweb（systemd unit `sboxweb.service`，M0.5 供给）      │
│   · 对 /root/sbox 零文件权限；对 /var/lib/sbox-cm 零文件权限            │
│   · 认证 / CSRF / 限流 / step-up（§5）/ access log 脱敏（E2 提供）      │
│   · E3 变更 = 仅"把白名单 op 的 JSON 发给本地 socket"，                │
│     无任何写盘旁路、无第二把锁、无第二提交引擎                           │
│   · 客户端清单只能来自 client.list RPC（sboxweb 无法直读 root 注册表；   │
│     service.api 无法枚举离线/从未连接的客户端，review #5）               │
└───────────────┬─────────────────────────────────────────────────────┘
                │ AF_UNIX SOCK_STREAM：/run/sbox-cm/sbox-cm.sock
                │ 属主 root:sboxweb 0660；每连接恰好 1 个请求；
                │ 长度前缀帧 + 三级 deadline（§2.1）
                │ SO_PEERCRED：peer uid 必须 == sboxweb（§1.3）
┌───────────────▼─────────────────────────────────────────────────────┐
│ 边界 B：特权守护进程 sbox-cm（root）                                    │
│   · binary /usr/local/lib/sbox-cm/sbox-cm（root 0755，root 属主目录）  │
│   · unit sbox-cm.service：Restart=on-failure；无任何 TCP/UDP 监听       │
│   · 唯一监听 = AF_UNIX socket；对端白名单 = uid(sboxweb)                │
│   · 操作面 = §7 六个 op；argv 恒空；无 shell/eval/动态路径              │
│   · 所有变更经 with_client_lock（fail-closed，基线已达成）→             │
│     lib/client-management.sh → commit_server_config —— 与 CLI 同一引擎 │
│   · 幂等账本 + tx journal（掉电级 fsync 语义）+ JSONL 审计（root-only）  │
└───────────────┬─────────────────────────────────────────────────────┘
                │
   /root/sbox/sbconfig_server.json   ← 唯一事实源（同现状）
   /root/sbox/config.lock            ← 唯一互斥点 = 永久控制面锚点（永不 unlink，§4.4）
   /var/lib/sbox-cm/                 ← 管理面 root-only 状态（§4.2）
   （E1 collector 走 127.0.0.1:9091 service.api，与 E3 完全解耦）
```

### 1.2 特权矩阵

| 组件 | 运行身份 | 文件权限 | 网络能力 | 说明 |
| --- | --- | --- | --- | --- |
| E2 web（sboxweb.service） | `sboxweb:sboxweb`（系统用户，nologin） | 仅自身 data-dir（auth/whitelist） | 仅监听既有 loopback 面；**无** `/root/sbox`、`/var/lib/sbox-cm` 任何权限 | 被攻破时的上限 = 触发 §7 六个 op（residual risk §9） |
| sbox-cm helper | `root` | 读写 `/root/sbox/**`、`/var/lib/sbox-cm/**` | **只**持有 AF_UNIX socket；零 TCP/UDP bind | 单点特权；全部行为在 §7 allowlist + 锁契约内 |
| CLI（mianyang / install.sh） | root（交互） | 同现状 | — | Phase C/D 全部写入器已在锁内（基线实证，§0 R5-8）；破坏性路径锁下重构见 §4.4 |

### 1.3 AF_UNIX socket 与对端校验

```text
路径      /run/sbox-cm/sbox-cm.sock
目录      /run/sbox-cm/            root:root 0755   （仅 root 可放置/替换 socket 文件）
socket    root:sboxweb 0660
校验      accept() 后 getsockopt(SOL_SOCKET, SO_PEERCRED) → struct ucred{pid,uid,gid}
          · uid != uid(sboxweb)      → 回 {E_PEER_AUTH} 后立即 close（含 uid=0：root 进程
            一律走 CLI/lib 直连路径，不开 socket 后门，保持"一条通道"原则）
          · sboxweb 用户不存在       → helper 启动即 fail-closed 拒绝一切连接（宁拒不服务）
          · uid/pid 记入特权审计（追责字段，非鉴权字段）
绑定      启动时 unlink 陈旧 socket（目录 root 属主 ⇒ 第三方无法预置伪造 socket）→ bind → chmod/chown
```

拒绝其他用户的防线是**双层的**：socket 权限位（0660 root:sboxweb）挡住无法 connect 的人；SO_PEERCRED 挡住"同组之外的 uid 恰好能 connect"的配置漂移。两者任一生效即拒绝，不互为依赖。

### 1.4 sbox-cm.service 硬化（M1 阶段实测校验，本文不宣称已验证）

```ini
[Service]
User=root
ExecStart=/usr/local/lib/sbox-cm/sbox-cm run
Restart=on-failure
RestartSec=2
# 需要写 /root/sbox、/var/lib/sbox-cm，并执行 /root/sbox/sing-box check、
# systemctl reload sing-box、kill -HUP：
ProtectSystem=strict
ReadWritePaths=/root/sbox /var/lib/sbox-cm
ProtectHome=read-only
PrivateTmp=yes
NoNewPrivileges=yes
RestrictAddressFamilies=AF_UNIX
CapabilityBoundingSet=CAP_KILL CAP_DAC_OVERRIDE
```

注：`systemctl reload` 依赖 D-Bus 与 systemd 通信，个别 sandbox 指令可能干扰；**精确 unit 旗标集在 M1 以"reload/回滚全部成功"的集成测试定稿**，失败则回退最保守集合。此项为阻塞项 B-5 的验收内容之一。

---

## 2. RPC 协议（AF_UNIX，versioned，allowlist，显式帧）

### 2.1 传输、帧模型与三级 deadline（review #6）

```text
· SOCK_STREAM；每连接恰好一个请求：
    connect → 发送 1 帧请求 → 服务端回 1 帧响应 → close
  帧格式（显式，取代首版"读到 EOF"）：
    [4 字节大端 uint32 payload 长度 L][L 字节 UTF-8 JSON payload]
  · L == 0 或 L > 65536 ⇒ 立即 close（连接级拒绝 + 审计 connection_rejected），
    不回错误帧——非法帧来自非法对端或坏客户端，不给协议 oracle
· 无流水线、无多路复用、无长连接会话状态 ⇒ 协议无中间态机
· helper 单线程串行处理（accept→handle→close）。mutation 的全局串行化本就由
  config.lock 承担（L1/L6），helper 内部并发只会制造排队复杂度
· 三级服务端 deadline（半开连接/慢客户端不得卡死串行 helper）：
    D-accept  待 accept 的积压连接由 backlog 限制（128）+ 每连接独立；
    D-read    收完帧头后，读完整 payload 上限 5 s（SO_RCVTIMEO 生效即断）；
    D-request 每 op 总 deadline（§2.4）从读毕请求起算；
              D-read 超时 / D-request 超时（未进入 mutation）⇒ close 连接 + 审计 timeout
· web 适配层：connect 2s / 帧写入 2s / 响应 = 对应 op deadline + 5s
```

### 2.2 请求 schema（固定版本 `e3-rpc/1`）

```json
// 请求（mutation 类）
{ "v": "e3-rpc/1",
  "request_id": "b7c9e2f4-…",                  // 必填，客户端生成，16–64 ASCII
  "op": "client.add",                          // 必填，∈ §7 白名单，其余一律 E_OP_UNKNOWN
  "actor": { "session_fp": "a1f3…",            // 会话指纹（sha256 前 16 hex，仅审计）
             "stepup_fp": "9d2e…" },           // step-up 事件指纹（仅审计，§5.4）
  "name": "vmix-01",                           // client.add/delete 必填，Phase C 正则
  "idempotency_key": "6f0e…" }                 // client.add / client.delete 必填（rev4 §6.9.1）

// 请求（management / inventory 类）
{ "v": "e3-rpc/1", "request_id": "…", "op": "management.status" }
{ "v": "e3-rpc/1", "request_id": "…", "op": "management.activate",
  "actor": { "session_fp": "…", "stepup_fp": "…" } }
{ "v": "e3-rpc/1", "request_id": "…", "op": "client.list" }
```

schema 规则（parse 阶段强制，先于一切文件访问）：

* 未知字段一律拒绝（`E_SCHEMA`）——不向前兼容静默忽略，版本升级必须换 `v` 并经 review。
* `v != "e3-rpc/1"` → `E_SCHEMA`；`request_id` 缺失/非法形状 → `E_SCHEMA`。
* **协议绝不接受：任何命令、argv、文件路径、配置名、shell 片段、凭据值、
  密码、恢复密钥、session cookie、CSRF token**。op → 行为的映射是 helper 内的固定 switch，不是数据。
* 请求 payload ≤ 64 KiB；`name` ≤ 32 字符且匹配 `^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`，`legacy` 保留名（rev4 §6.5 双层防御同样成立：web 中间件 + helper 内二次硬校验）。

### 2.3 操作 → 行为映射（helper 内固定表）

| op | helper 行为 | config.lock | 激活态要求 | 幂等语义 |
| --- | --- | --- | --- | --- |
| `management.status` | 读标记 + 自身健康 + 锁探测 + 最后事务（§6.2） | **否**（不读 live 配置，无撕裂面） | 否 | 天然幂等只读 |
| `client.list` | 锁内读 live 配置 → 最小净化清单（§6.5） | 是（短持有，防撕裂读） | **否**（激活前 UI 也要能显示） | 天然幂等只读 |
| `management.activate` | 锁内校验前置 → 写标记 → 审计（§4.3） | 是 | —（自身即激活动作；要求近期 step-up） | 已 active → `no_op:true` |
| `management.deactivate` | 锁内删标记 → 审计 | 是 | —（退出动作必须始终可达） | 已 inactive → `no_op:true` |
| `client.add` | rev4 §4.3 流程原样（账本先于 live precondition） | 是 | 是 | Idempotency-Key 账本 |
| `client.delete` | rev4 §4.4 流程原样 | 是 | 是 | 同上 |

锁等待策略：mutation 类 `flock -w 15`（L2，超时 → `E_LOCK`，零写入）；`client.list` 同样 15 s（清单正确性优先于时延）；status 不取锁、不等待。

### 2.4 每操作 deadline（helper 强制；到点仅在**未进入 mutation**的阶段可中止，进入后一律跑到终态，§8-R5/R10）

| op | deadline |
| --- | --- |
| management.status | 10 s |
| client.list | 15 s（含锁等待） |
| management.activate / deactivate | 30 s（锁等待 ≤15 s + 标记写入） |
| client.add / client.delete | 120 s（锁等待 ≤15 s + 完整事务） |

### 2.5 request_id 与重放屏蔽

* helper 维护最近 512 条 `{request_id → 响应摘要}` 环形缓存（内存，重启即失）；
  10 分钟内同 `request_id` 的重复请求 → 返回缓存响应（传输层重放屏蔽）。
* **权威幂等语义只在账本**（`idempotency_key`，rev4 §6.9）；request_id 缓存只是降噪，
  不承担正确性。缓存 miss + 同 key 重试 → 走账本 replay，结果逐字段一致（rev4 E3-T52）。

### 2.6 错误模型（稳定码 + retriable + stage）

```json
{ "ok": false,
  "error": { "code": "E_ROLLED_BACK",
             "stage": "health",             // 失败发生阶段（§2.6 stage 枚举）
             "retriable": true,
             "detail": "reload 后健康检查失败，已自动回滚",   // 禁凭据/YAML/URI
             "backup": "/root/sbox/sbconfig_server.json.bak.20260912-110000.XXXXXX" },
  "request_id": "b7c9e2f4-…" }
```

| code | HTTP 映射 | retriable 默认 | 含义 |
| --- | --- | --- | --- |
| `E_SCHEMA` | 400 | false | 版本/字段/大小/形状非法 |
| `E_OP_UNKNOWN` | 400 | false | op 不在白名单 |
| `E_PEER_AUTH` | 403 | false | SO_PEERCRED 拒绝（正常部署下不可达，防御纵深） |
| `E_RESERVED_NAME` | 403 | false | `legacy` 保留名 |
| `E_LOCK` | 423 | true | config.lock 获取失败/超时（fail-closed，字节级零变更） |
| `E_DUPLICATE_NAME` | 409 | false | 锁内 live 复核命中既有名 |
| `E_NOT_FOUND` | 404 | false | delete 目标不存在（账本调和后仍不满足重跑条件） |
| `E_CONFIG_INCONSISTENT` | 409 | false | live JSON 非法/一致性审计失败/双 inbound 不齐 |
| `E_IDEMPOTENCY_CONFLICT` | 409 | false | 同 key 异 payload / in_flight 异 payload |
| `E_RECONCILE_CONFLICT` | 409 | false | in_flight 期间 live 被外部改动（rev4 §6.9.4） |
| `E_LEDGER_UNAVAILABLE` | 503 | true | intent append/fsync 失败 ⇒ 零变更（F13/F14） |
| `E_STATE_UNCERTAIN` | 503 | true | outcome 落账失败但 commit 已成功（F15，禁回滚健康配置） |
| `E_CANDIDATE_REJECTED` | 500 | false | candidate 审计 / `sing-box check` 失败（未触盘，F4） |
| `E_COMMIT_FAILED` | 500 | true | 备份/mv 失败（F5） |
| `E_ROLLED_BACK` | 503 | true | reload/health 失败已回滚（F6/F7） |
| `E_MANUAL_INTERVENTION` | 500 | false | 回滚后仍不健康（F8）/ journal 调和无法证明安全态（§3.2）⇒ degraded，拒绝一切 mutation |
| `E_ACTIVATION_STATE` | 409 | false | client.* 在未激活时被请求；或 activate/deactivate 竞态残余 |
| `E_TIMEOUT` | 504 | true | op deadline 到期（仅未进入 mutation 时可发生） |
| `E_INTERNAL` | 500 | false | 其余内部错误（审计 CRITICAL） |

stage 枚举沿用 rev4 §4.2：`parse | peer | lock | ledger_intent | revalidate | candidate | check | backup | replace | reload | health | rollback | rollback_manual | outcome | marker | audit`。

---

## 3. 事务集成（复用，绝不重造；M0 硬化共享事务）

### 3.1 client.add / client.delete 在 helper 内的执行序列

**硬性不变量：一条通道、一把锁、一套事务、零旁路（rev4 §4.1 原文继承）。**

```text
0  parse/schema      v/request_id/op/actor/name/Idempotency-Key 校验（无文件访问）
1  lock              with_client_lock —— 同一把 /root/sbox/config.lock，fail-closed
                     （基线 install.sh:729-745 已实证，ALREADY PASS，E3-0 仅 verify+preserve）
2  reread live       【锁内】重新读取 /root/sbox/sbconfig_server.json —— 绝不使用
                     web 传入或锁外缓存的任何状态快照（rev4 §6.7 请求内重读原则）
3  revalidate        JSON 合法性 → 结构审计（fail-closed）→ 存在性/一致性复核 →
                     helper 自算语义 digest → 账本查询/调和（先于一切 live precondition，A-19）
4  durable intent    append → flush → fsync（文件+目录，§3.2）；失败 ⇒ E_LEDGER_UNAVAILABLE，零变更
5  candidate         同目录 mktemp 唯一临时文件（new_candidate_path，install.sh:983）
6  structural audit  candidate_problems fail-closed（commit_server_config，install.sh:899 内）
7  sing-box check    /root/sbox/sing-box check -c candidate
8  backup            new_backup_path（install.sh:987）：mktemp + cp -a + chmod 0600
                     （install.sh:940-950，基线已收紧备份权限）
9  atomic replace    mv -f candidate live
10 reload            systemctl reload sing-box / kill -HUP（reload_running_singbox，install.sh:876）
11 health            sleep 1 + is-active / pgrep（reload_health_ok，install.sh:886）
12 rollback          上述任一失败 → restore_file_atomically（§3.1.1，M0 硬化点）→ reload → health
13 outcome           最终非敏感 result → durable outcome（fsync 文件+目录）→ audit → unlock
```

落实方式与 rev4 完全一致：helper **source 共享库 `lib/client-management.sh`**（M0 从
install.sh 字节级抽取），`commit_server_config`、`with_client_lock`、
`new_candidate_path`、`new_backup_path`、`reload_running_singbox`、`reload_health_ok`、
`restore_file_atomically` **没有任何第二份拷贝**。rev5 明令禁止：

* 在 helper 内重写 commit/备份/回滚逻辑（第二提交引擎）；
* 新增任何锁文件、信号量文件、"web 侧队列"来替代或补充全局保证（第二把锁，L6）；
* helper 直接写 `sbconfig_server.json` 而不经 `commit_server_config`。

**3.1.1 通用事务回滚硬化（review #3，M0 必做）**

基线事实：`commit_server_config` 的回滚路径在 `install.sh:967` 执行
`cp -a "$backup_path" "$SB_SERVER_CONFIG"` —— 一次**未校验的直接覆盖 live 路径名**
（对比：L3 双文件回滚早已使用 `restore_file_atomically`，`install.sh:2314`，其注释明确
"The live pathname is never `cp`'d onto directly"：同目录唯一 `.restore.XXXXXX` 临时
文件 → `chmod 0600` → 原子 `mv` → `cmp -s` 逐字节校验，调用者必须已持锁）。

M0 契约：

```text
T-1  commit_server_config 回滚改调 restore_file_atomically（同一共享库内，非复制）：
     失败任何一步 ⇒ 回滚未发生 ⇒ 事务按 rollback_manual 处理（F8 升格语义不变）
T-2  共享库输出结构化事务结果（phase/changed/reload_performed/rollback_attempted/
     rollback_ok/health_ok/backup_path —— 即 §6.1 transaction 对象的字段来源）；
     现有 CLI 兼容包装继续把结果折叠为历史 0/1 返回码，CLI 行为不变
T-3  Phase D 双文件（binary+config）回滚继续走其既有的成对恢复路径，M0 不改其语义，
     仅确认其与 T-1 共用同一 restore 原语
T-4  不得出现第二份 commit 引擎或第二份 restore 实现
```

### 3.2 tx journal：两种故障模型，两种承诺（review #4）

```text
路径        /var/lib/sbox-cm/journal/<request_id>.json（root 0600，done 后删除）
内容        { "v":1, "request_id", "op", "phase", "backup_path" }   —— 永不含凭据
            （不含 uuid/password/凭据 digest 之外的任何敏感值；digest 本身也无需入 journal）

故障模型 A —— 进程崩溃（helper 被 kill / OOM / bug）：
  · 承诺：进程重启后可恢复到确定终态
  · 手段：每阶段 append + flush + fsync(文件)；flock 随 fd 由内核释放，无死锁残留

故障模型 B —— 掉电 / 宿主失联：
  · 承诺（仅在满足本条时才可宣称"掉电安全"）：
      journal 每阶段写入 = write + fsync(文件) + fsync(父目录 /var/lib/sbox-cm/journal)
    账本 intent/outcome 同等要求（append → fsync(文件) → fsync(目录)）
  · 不满足该语义的实现**不得在文档/代码注释中宣称掉电持久性**——只能宣称模型 A

启动调和（startup reconciliation）：
  · helper 启动/重启后、接受任何 mutation 之前，必须先：
      with_client_lock（同一把锁，fail-closed）→ 扫描 journal 残留 →
      对 phase ≥ replace 的条目执行 reload → health →（失败 → restore_file_atomically
      回滚 → 再 reload → health）→ 写 outcome + 审计 → 清除 journal
  · 调和全程在同一把 config.lock 下进行 ⇒ 与 CLI/后续 mutation 天然互斥
  · 调和结束：
      全部收敛     ⇒ degraded=false，正常接受 mutation
      无法证明安全态（journal 损坏 / restore 失败 / health 仍失败）⇒
        degraded=true：management.status **保持可用**（运维可见），
        一切 mutation（含 activate）fail-closed E_MANUAL_INTERVENTION（§8-R9/R12）
```

---

## 4. management activation lifecycle（`SB_MANAGEMENT_ACTIVE_MARKER` 正式化）

### 4.0 基线现状（重新锚定后的事实）

```text
· 常量已存在：SB_MANAGEMENT_ACTIVE_MARKER="${SB_MANAGEMENT_ACTIVE_MARKER:-/root/sbox/web-management.active}"
  （install.sh:2413；注释明确"subordinate to the final E3/Integration decision and
  MUST be ratified there"——本文即 ratification；env 可覆盖供测试注入，须保留）
· management_is_active（install.sh:2416）= 纯存在性检查
· require_management_inactive（install.sh:2419）已在两处调用：
  uninstall_singbox（2712）与 reinstall 菜单分支（3607）
· 但该检查是【锁外】的，且 uninstall 随后仍 rm -rf /root/sbox/ ⇒
  (a) check-then-destroy 与 activate 之间存在 TOCTOU；
  (b) 标记本体、config.lock 本体都会被卸载删除 —— 闸门随闸门保护的靶子同归于尽
```

### 4.1 定义（rev5 正式化）

```text
SB_MANAGEMENT_ACTIVE_MARKER 生产默认路径 := /var/lib/sbox-cm/management.active
（常量名、env 可覆盖性保留——测试沙箱契约不变；但生产 helper 内嵌路径常量、
  拒绝 SB_* 环境注入，与 rev4 D3 同源：覆盖能力只属于测试 wrapper 与 root CLI）

内容（JSON，root 0644，root:root）：
{ "v": 1, "state": "active",
  "activated_at": "2026-09-14T12:00:00Z",
  "activated_by": { "session_fp": "a1f3…", "request_id": "b7c9…" } }

语义：
· 文件存在且 state=="active"  ⇒ E3 管理面已激活：
    (a) 允许 client.add / client.delete 经 helper 执行；
    (b) 所有 legacy 破坏性路径（§4.4）在锁内检查到它 ⇒ 拒绝执行。
· 文件不存在                   ⇒ 未激活：client.* op 一律 E_ACTIVATION_STATE 拒绝
    （E3 变更面默认关闭；client.list / management.status 不受激活态限制）
· state 字段非 "active" 的任何其他值 ⇒ 视为损坏，按未激活处理 + 审计 CRITICAL
```

### 4.2 `/var/lib/sbox-cm` 作为 root 边界的理由（含对基线路径的否定论证）

| 候选 | 结论 |
| --- | --- |
| `/root/sbox/web-management.active`（**基线默认**，install.sh:2413） | **否**：`uninstall_singbox` 仍会 `rm -rf /root/sbox/`。标记放进去 = "卸载先读闸门、再亲手拆掉闸门"（§4.0(b)） |
| `/etc/sbox-cm/` | 否：/etc 是配置不是运行时状态 |
| `/var/lib/sbox-cm/`（**选定**） | FHS 标准的服务运行时状态位置；整目录 root 0700 root:root ⇒ sboxweb 零文件系统访问，一切读写必经 RPC；与卸载目标异生死 |

布局：

```text
/var/lib/sbox-cm/                    root:root 0700
  management.active                  root:root 0644   激活标记（§4.1）
  ledger/cm-ledger.jsonl             root:root 0600   幂等账本（rev4 §6.9；fsync 文件+目录）
  journal/<request_id>.json          root:root 0600   tx journal（§3.2；fsync 文件+目录）
  audit/cm.jsonl                     root:root 0600   特权审计（rev4 §8.4）
  （spool/ 与 export 一起推迟，§7.2）
```

### 4.3 锁下生命周期（消除 activation TOCTOU）

```text
management.activate：
  parse → with_client_lock（fail-closed）→ 锁内重读 live 配置并校验存在/可解析
        → 锁内重读标记：已 active ⇒ no_op 返回现状（幂等）
        → 前置全绿 ⇒ 原子写标记（mktemp 同目录 + fsync(文件) + fsync(目录) + rename）
        → audit → unlock

management.deactivate：
  parse → with_client_lock → 锁内读标记：不存在 ⇒ no_op 返回现状
        → unlink 标记 → fsync(目录) → audit → unlock
        （helper 单线程串行 ⇒ 同 helper 无并发 mutation；跨进程并发由 config.lock 串行化）
```

### 4.4 锁生命周期问题：config.lock 作为永久控制面锚点（review #2 核心）

**问题陈述**：全局锁路径名是 `/root/sbox/config.lock`（`install.sh:690`），而
`uninstall_singbox`（`install.sh:2708`）以 `rm -rf /root/sbox/` 结束。即便让 uninstall
先 `with_client_lock`，删除被 flock 的**路径名**之后：

```text
T0  helper 持有 /root/sbox/config.lock（inode X）的 flock
T1  uninstall 持锁后 rm -rf /root/sbox/ ⇒ 路径名消失（inode X 仍被 helper 引用）
T2  任何进程重新 open("/root/sbox/config.lock") ⇒ 内核创建 inode Y ⇒
    新 flock（inode Y）与旧 flock（inode X）互不相干 ⇒ 互斥被静默击穿
```

仅"先取锁"不充分。rev5 采用**首选最小方向**：

```text
L-ANCHOR-1  /root/sbox/config.lock 是永久控制面锚点：
            它不再属于"会被卸载的东西"，而是"卸载流程本身必须持有并最终留下的东西"。
L-ANCHOR-2  破坏性 uninstall 重构为：
              with_client_lock _uninstall_singbox_locked
            _uninstall_singbox_locked 内部依次：
              (a) require_management_inactive 检查【移入锁内】（§4.4-b）
              (b) 手工进程运行检测（基线 2714-2716 原样）
              (c) 移除运行时/配置/凭据物（仍在锁内）：sing-box.service unit、
                  sbconfig_server.json、sing-box 二进制、mianyang、self-cert/、
                  状态文件 config、/root/sbox/clients/、备份文件、hy2 hopping
                  unit+规则+脚本 —— 调用**_locked 内部变体**而非公共 helper
                  （disable_hy2hopping 这类公共入口会再次 with_client_lock，
                    违反基线 720-722 的 no-nesting 纪律 ⇒ 一律改调
                    _disable_hy2hopping_locked 等 locked 变体）
              (d) 【保留】/root/sbox/ 目录本身与 /root/sbox/config.lock：
                  不 rm -rf 整目录、永不 unlink 锁路径名
              (e) 报告"已卸载（控制面锚点保留）"
L-ANCHOR-3  任何事务（CLI/Phase D/helper/uninstall）内禁止 unlink / rm
            /root/sbox/config.lock；fresh install 路径同样只 create-if-missing，
            不先删后建
L-ANCHOR-4  测试断言：uninstall 后 config.lock 存在且以 sboxweb 模拟对端仍可
            获得同一 flock（inode 不变）；uninstall 期间并发 client.list 拿到
            E_LOCK 或等待后得到一致的"空清单"，绝不出现半卸载清单
```

**备选方向（评估过、v1 不采纳）**：把全局锁迁出 `/root/sbox`（如
`/var/lib/sbox-cm/config.lock`）。代价 = 必须原子迁移**全部**写入器与测试：

```text
基线 with_client_lock 调用点穷举（3ee9a162，git grep 实证）：
  1003 migrate_legacy_clients / 1059 add_client / 1143 delete_client
  1990 upgrade_singbox_1_14(Phase D) / 2473 modify_singbox(L3)
  2764+2770 process_doko / 2913+2941 process_dokoko / 3065+3084 process_ssko
  3440 enable_hy2hopping / 3475 disable_hy2hopping
  外加：tests/test-phase-c.sh、tests/test-phase-d.sh 的 SB_LOCK_FILE 重定向契约、
  rev4 §4.7 L1 文本、共享库抽取、E3 helper、CI 双套件
```

迁移必须是一个原子的"全部切换 + 全套回归"提交，无灰度价值、引入一次性全局风险；
而 L-ANCHOR-1..4 以"锚点不灭"四条规则达到同等安全强度且改动面显著更小。
**若 M0 实施中发现 L-ANCHOR 方案存在不可接受的运维歧义，备选方向按上述清单整体
执行，禁止只迁一半。**

**4.4-b require_management_inactive 硬化**：

```text
M-1'  uninstall/reinstall 的 marker 检查从锁外（基线 2712/3607 现状）移入
      with_client_lock 临界区内；锁、标记检查、破坏动作三者同一临界区 ⇒
      activate 与 uninstall 严格全序，无 TOCTOU（§8-R3/R4）。
M-2'  其余破坏性/整体替换性入口以同一模式补齐（M0 穷举清单见 L-ANCHOR 备选方向
      的调用点列表——该列表即"全部持锁写入器"清单，破坏性入口为其子集 + 
      uninstall/reinstall）。
M-3'  检查实现留在共享库，CLI 与未来任何调用方自动继承（L3 精神）。
M-4'  陈旧标记（人为绕过 deactivate 强删配置后重装）：
      helper 每次 activate/status 在锁内发现"标记 active 但 sbconfig_server.json
      不存在" ⇒ 状态置 active_stale，status 如实上报 + CRITICAL 审计；
      恢复途径 = root CLI `mgmt-deactivate`（共享库内实现，同锁同审计语义）。
      不做静默自动清除——静默清除本身就是一条绕过审批的写路径。
```

### 4.5 monitor-running ≠ E3-management-active（两个正交布尔）

| 布尔 | 含义 | 观测点 |
| --- | --- | --- |
| `monitor_running` | E1 collector + E2 web 在运行（监控面可用） | web 进程自检 + status 汇总 |
| `management_active` | 标记存在 ⇒ E3 变更面开启 + legacy 破坏性路径被闸 | 标记文件（仅 helper/CLI 可读） |

监控开着**不等于**管理面激活（默认未激活）；激活**不要求**监控在跑（但激活请求只能来自 web ⇒ 事实上 monitor 必然在跑）。`management.status` 同时返回两者，消除运维歧义。

---

## 5. Step-up 认证（web 层；helper 不参与；含吊销语义）

### 5.1 模型

```text
· 普通 admin session（memory-only，rev4 §8.1 既有事实）= 只读级：
    GET clients（经 client.list）/ status / 流量视图 —— 全部放行。
· mutation 级（client.add/delete、management.activate/deactivate）：
    要求 session 内存在未过期的 step-up 授权，否则 401 reauth_required。
· step-up 获取：POST /api/v1/step-up { password }（新增端点，E2 范畴）
    → scrypt 常量时间校验（复用 auth.verify_secret）→ 复用 LoginRateLimiter（同一限速器，
      失败计数共享，防止把 step-up 端点当第二暴力破解面）
    → 成功 ⇒ session 内存态置 step_up = { expires_at = now + 300s }（U-7 默认）
· UI 收到 401 reauth_required ⇒ 弹密码框 → 成功后自动重放原请求
  （confirm / Idempotency-Key 不变；helper 自算 digest 对同一语义请求一致，
   账本 replay 不受影响 —— rev4 §8.2 原文继承）
```

### 5.2 吊销语义（review #7）

step-up 授权与当前 session 生命周期**绑定**，下列任一事件发生 ⇒ **立即吊销**（不等 300s）：

| 事件 | 生效方式 |
| --- | --- |
| `POST /api/v1/logout` | session 销毁 ⇒ step-up 随之消亡 |
| `POST /api/v1/password`（改密成功） | **吊销所有 session 的 step-up**（改密即全量降权；是否连 session 一并失效由 E2 定案，建议保留登录但必重新 step-up） |
| recovery reset / recovery rotate | 同改密：吊销所有 step-up（认证根基变更 ⇒ 授权根基随之变更） |
| session TTL 过期（8h，既有） | session 消亡 ⇒ step-up 消亡 |
| web 进程重启 | memory-only ⇒ session 与 step-up 全部消亡（既有事实，无需新机制） |

实现注：以上均为 web 进程内内存操作（遍历/清空 session 表的 step_up 字段），无持久化、无新攻击面。

### 5.3 凭据边界（任务书红线，review #7 扩展）

```text
S-1  UUID/password/私钥/恢复密钥/admin 密码：绝不进入 RPC 请求、绝不进入 helper、
     绝不出现在 argv / 环境变量 / journald / 两份审计 / 任何日志。
S-2  helper 永不接收：密码、恢复密钥、session cookie、CSRF token（review #7）。
     RPC 的 actor 仅携带指纹（session_fp / stepup_fp，sha256 截断），用于审计归因，
     不承担鉴权——helper 的唯一鉴权 = SO_PEERCRED（§1.3）。
S-3  step-up 状态是 web 进程内存态：web 重启 ⇒ 全部 step-up 失效 ⇒ 任何在途
     mutation 重试会先收到 401（安全默认，代价 = 重新输一次密码）。
S-4  journald 约束：helper 经 systemd 输出仅限 code/stage/name/request_id/
     digest 前缀；rev4 E3-T29/T55 的全链路卫生扫描对 journald fixture 同样生效。
S-5  client.add 的新凭据由 helper 在锁内生成（rev4 §4.3 步骤 5），仅以
     planned_cred_digest 进入账本；值本身留在 live 配置与（未来的）export 通道内。
```

### 5.4 过期 / 重放语义

| 场景 | 行为 |
| --- | --- |
| step-up 过期/被吊销后发起 mutation | 401 reauth_required（web 层拦截，helper 根本收不到） |
| 窗口内同 Idempotency-Key 重试 | 账本 replay 原结果（rev4 E3-T13/T30/T52）；web 层仍要求窗口有效且未被吊销（replay 也是一次"授权读取变更结果"） |
| 同 request_id 重放 | §2.5 传输层缓存返回缓存响应 |
| 窗口内第 N 个不同 mutation | 允许（窗口模型，rev4 U-7 备选为单次令牌） |

---

## 6. 结构化特权结果（stable response contract）

### 6.1 通用信封

```json
{ "ok": true,
  "v": "e3-rpc/1",
  "request_id": "b7c9e2f4-…",
  "op": "client.delete",
  "idempotency": { "key_fp": "9af1…", "replayed": false, "generation": 1 },
  "transaction": {
      "entered": true,              // 是否真正进入事务（false = 被 parse/lock/前置拒绝）
      "phase": "done",              // 最后到达阶段（§2.6 stage 枚举）
      "changed": true,              // live 配置是否发生变更（含回滚还原 = changed:true + rolled_back）
      "reload_performed": true,
      "health_verified": true,
      "rollback_attempted": false,
      "rollback_ok": null,          // 未尝试 = null；尝试并成功 = true；失败 = false
      "backup_path": null,
      "duration_ms": 8421 },
  "warnings": [],
  "data": { "deleted": true, "derived_cleanup": true, "warnings": [] } }
```

字段稳定性承诺：**字段只增不删不改名；`phase`/error.code/`retriable` 枚举受本文约束**；
`transaction` 对象的字段由共享库（§3.1.1 T-2）产出，web 适配层按 §2.6 表映射 HTTP，不得自造语义。

### 6.2 `management.status` 的 data 形状（不再携带 clients，review #5）

```json
{ "management_active": true, "management_state": "active",   // active|inactive|active_stale
  "activated_at": "…", "monitor_running": true,
  "helper": { "pid": 1234, "uptime_s": 86400, "degraded": false,
              "reconcile": "clean" },      // clean|recovered|manual_intervention
  "lock": { "path": "/root/sbox/config.lock", "inode": 94712, "acquirable": true },
  "last_transaction": { "request_id": "…", "op": "client.add", "ended_at": "…",
                        "outcome": "ok" } }
```

### 6.3 `management.activate / deactivate` 的 data 形状

```json
{ "management_state": "active", "no_op": false,
  "activated_at": "2026-09-14T12:00:00Z", "marker_path": "/var/lib/sbox-cm/management.active" }
```

### 6.4 `client.add / client.delete` 的 data 形状

```json
// add 成功
{ "name": "vmix-01", "protocols": ["reality","hy2"],
  "yaml_available": true, "warnings": [],
  "credential_delivery": "cli" }        // §7.3：v1 凭据取回走 CLI，见 U-R5-1
// delete 成功
{ "deleted": true, "derived_cleanup": true, "warnings": [] }
```

### 6.5 `client.list` 的 data 形状（review #5；最小净化清单，零凭据）

```json
{ "clients": [
    { "name": "vmix-01", "protocols": ["reality", "hy2"],
      "reserved": false, "mutable": true, "source": "web" },
    { "name": "legacy",  "protocols": ["reality", "hy2"],
      "reserved": true,  "mutable": false, "source": "untracked" } ],
  "truncated": false }
```

```text
· 真值源 = 锁内 live 配置（防撕裂读，rev4 §6.8）；registry 仅 advisory（rev4 D4），
  缺失 ⇒ source:"untracked"，绝不推断 "cli"（rev4 E3-T19）
· 净化规则：仅 name / protocols / reserved / mutable / source 五字段；
  **零 UUID、零 password、零私钥、零 YAML、零分享 URI**（S-1/S-2 延伸；
  审计与卫生扫描把 client.list 响应纳入零命中断言）
· 上限 1000 条 + truncated 标志（INV-9）
· 激活态无关：未激活也允许（UI 激活前就要能显示现状）
```

---

## 7. 初始操作面（minimal，逐 op 论证）

### 7.1 白名单（6 个，固定）

| op | 论证 |
| --- | --- |
| `management.status` | 运维判断（激活态/锁健康/degraded/reconcile/最后事务）的唯一读通道；不取锁、低险 |
| `management.activate` | 解除 Round 2 阻塞的显式审批动作；是 legacy 破坏性闸门的前提 |
| `management.deactivate` | 激活的逆操作；卸载/重装前必须可达 |
| `client.list`（review #5） | sboxweb 无权直读 root 注册表、service.api 无法枚举离线客户端 ⇒ 清单必须有特权读通道；独立成 op 而非超载 status（形状/锁语义/激活语义均不同） |
| `client.add` | E3 核心价值的最小成立集 |
| `client.delete` | 同上；且与 legacy `modify_singbox` 构成必须分析的交叉竞态（§8-R2） |

### 7.2 明确推迟（进入白名单须新一轮论证 + 本文修订）

| 被推迟 | 理由 |
| --- | --- |
| `client.rotate` | 依赖 rev4 §4.5 双协议共同旋转 + rotation 失效 UX；不阻塞 v1 主线 |
| `client.export` / `consume_export` / spool | rev4 §4.6 是自成一体的子系统（0710 spool、token、消费、清扫）；推迟它把 rev5 阻塞面收敛到"特权通道 + 激活生命周期"本身 |
| `client.get`（单客户端详情） | `client.list` 已覆盖 v1 需求 |
| 任何 legacy 写路径（doko/dokoko/ssko/HY2 hopping/upgrade）经 web | 明确**永不**进入 RPC 白名单：CLI 运维域，混入只会扩大攻击面（rev4 A-1 精神延伸） |

### 7.3 功能缺口（如实声明）

`client.add` 成功后，管理员在本轮**无法经 web 取回凭据**（export 推迟），取回方式 =
CLI。该缺口是"最小白名单"的自觉代价，记为未决决策 **U-R5-1**（v1 建议：接受缺口 +
UI 明示 `credential_delivery:"cli"`；备选：把 `client.export` 提前纳入）。

---

## 8. 失败 / 竞态分析（R1–R12；失败点矩阵 F1–F22 沿用 rev4 §6.4）

| # | 竞态/失败 | 序列 | 保护机制 | 结果 |
| --- | --- | --- | --- | --- |
| R1 | **E3 add vs legacy add** | web `client.add` 与 CLI `add_client`（基线 `install.sh:1059`）并发 | 同一把 config.lock 全序化（fail-closed 已实证）；后到者锁内 reread + revalidate，`client_name_exists` 双向复核 | 败者 `E_DUPLICATE_NAME`（409）或 `E_LOCK`（423）；零 lost update |
| R2 | **E3 delete vs legacy modify** | web delete 与 CLI `modify_singbox`（2473）/`process_doko`（2764）并发 | 同锁串行；helper 锁内重取 `old_cred_digest` 复核；账本调和矩阵（rev4 §6.9.4） | 期间 live 被改 ⇒ `E_RECONCILE_CONFLICT`（409），绝不误删 replacement（rev4 E3-T48） |
| R3 | **E3 activate vs uninstall** | activate 等锁时 uninstall 到来 | M-1'：uninstall 在 `with_client_lock` 临界区内查标记（基线 2712 的锁外检查移入锁内）⇒ 两者严格全序 | 全序二选一：uninstall 先完成 ⇒ activate 因配置缺失拒绝；activate 先完成 ⇒ uninstall 见标记拒绝。无窗口 |
| R4 | **uninstall vs activate**（现状不对称的单列镜像） | 基线 marker 检查在锁外（2712/3607） | M-1' 落地前该 TOCTOU 真实存在 ⇒ PRE-IMPLEMENTATION gate G2 | G2 未绿前 `management.activate` 不允许上线（闸门先于被闸者存在） |
| R5 | **helper crash 而持锁** | helper 进程死亡时持有 flock | flock 随 fd 由内核释放（无死锁残留）；tx journal 留有 phase（文件 fsync ≥ 模型 A） | web 收连接断开 ⇒ `E_STATE_UNCERTAIN`（503）语义 + 提示同 key 重试；helper 重启 → 锁下调和（R6/R12） |
| R6 | **helper crash 在 live replace 后、reload 前** | 崩溃点 ∈ [replace, reload) | journal 已 fsync `phase=replace` + `backup_path`；掉电安全要求文件+目录 fsync（§3.2 模型 B） | 重启锁下调和：reload → health；失败 → restore_file_atomically 回滚 → 再 reload → health；结果落 outcome + CRITICAL 审计。不存在"已换盘但无人 reload 也无记录"的静默态 |
| R7 | **reload 失败** | commit 后 reload 报错 | `commit_server_config` 既有自动回滚（install.sh:899 内；M0 按 T-1 硬化为 restore_file_atomically） | `E_ROLLED_BACK`（503，retriable）；F6 语义：add⇒从未存在、delete⇒仍完整存在 |
| R8 | **health 失败** | reload 成功但进程不健康 | 同上既有回滚路径 | 同 R7（F7） |
| R9 | **rollback 失败 / 调和失败** | 回滚后仍不健康；或 journal 调和无法证明安全态 | F8 语义 + degraded 标志：**status 保持可用，一切 mutation fail-closed `E_MANUAL_INTERVENTION`**（§3.2），直至 root CLI 一致性修复后显式清除 | 防止在未知状态上叠加变更；status 的 `reconcile:"manual_intervention"` 如实上报 |
| R10 | **web 重启于 mutation 途中** | RPC 对端消失 | rev5 硬规则：对端断连不可中止已进入 mutation 的事务；helper 驱动到终态并落 outcome | web 重启 ⇒ session/step-up 失效 ⇒ 无法自动取回结果；运维经 status 观察，或同 key 重试（若浏览器仍持 key）→ replay。幂等保护的是重复执行，不是丢失响应 |
| R11 | **重复/重放 RPC** | 网络层重发 / 用户双击 | 双层：request_id 缓存（§2.5）+ Idempotency-Key 账本（权威） | 同 key 同 payload ⇒ 逐字段一致的 replay；同 key 异 payload ⇒ `E_IDEMPOTENCY_CONFLICT`；恰好一次变更（rev4 E3-T10/T31） |
| R12 | **uninstall 删除锁路径名（inode 替换）** | 锁内 `rm -rf /root/sbox/` 后他人重建同名锁文件获得**另一把** flock | L-ANCHOR-1..4：config.lock = 永久锚点；uninstall 保留目录与锁本体；任何事务内禁止 unlink 锁路径名；测试断言 inode 不变（§4.4） | 互斥不被静默击穿；"先取锁"单独使用不足以防此竞态（review #2 指出的根本问题） |

R 系与 F 系的映射：R1/R2 ⊂ F2/F3/F16 组合；R7/R8 = F6/F7；R9 = F8 扩展；R11 = F13–F16 的事务外壳。rev5 未新增任何"commit_server_config 语义之外"的失败类别；R12 是锁生命周期不变量而非新事务语义。

---

## 9. 安全不变量与 PRE-IMPLEMENTATION gates

### 9.1 不变量（INV，实施后成为静态断言/测试断言）

```text
INV-1  sboxweb 对 /root/sbox/** 与 /var/lib/sbox-cm/** 的文件系统访问 = 0
INV-2  helper 全生命周期仅持有 AF_UNIX socket；无任何 TCP/UDP bind（/proc 扫描断言）
INV-3  socket 0660 root:sboxweb；SO_PEERCRED uid != sboxweb 一律拒绝（含 uid 0）
INV-4  全系统恰一把锁（config.lock）、恰一套提交引擎（commit_server_config）、
       恰一套恢复原语（restore_file_atomically）；仓库 grep 不得出现第二锁文件、
       helper 内直写 live 配置、或未经原语的回滚拷贝
INV-5  op 白名单固定 6；argv 恒空；无 eval/shell 插值/动态路径；固定 PATH
INV-6  密码/UUID/私钥/凭据值/full token/session cookie/CSRF token 在 argv、env、
       journald、两份审计、错误 detail、client.list 响应中零命中
INV-7  标记/账本/journal/审计全部 root-only（0700 目录 + 0600/0644 文件）
INV-8  一切失败路径 fail-closed：锁、peer、schema、live 解析、账本 intent、
       journal 调和失败（R9）
INV-9  资源有界：payload ≤64 KiB；每连接 1 请求；单线程串行；三级 deadline；
       client.list ≤1000 条 + truncated
INV-10 每个 RPC 尝试（无论成败）恰一条特权审计记录；非法帧/超时连接同样入审计
       （connection_rejected / timeout）
INV-11 activate/deactivate 与一切破坏性路径共享同一锁 + 同一锁内标记判定点（M-1'..M-3'）
INV-12 helper degraded 期间：status/list 可用，一切 mutation 拒绝（R9）
INV-13 任何事务内禁止 unlink /root/sbox/config.lock；uninstall 保留目录与锁本体
       （L-ANCHOR；测试断言 inode 不变）
INV-14 掉电持久性声明必须伴随 fsync(文件)+fsync(父目录) 实现；否则文档只许宣称
       进程崩溃恢复（§3.2 模型 A/B 分离）
INV-15 step-up 与 session 绑定，五类事件（§5.2）立即吊销
```

### 9.2 PRE-IMPLEMENTATION gates（G1–G6；review #8 重排：不把未实现代码当"开始实现"的前置）

| Gate | 内容 | 状态 |
| --- | --- | --- |
| ~~原 G1~~ | 全局锁 fail-closed | **ALREADY PASS**（基线 `install.sh:729-745` 三条失败路径实证；E3-0 仅 verify + preserve，绝不重实现/不覆盖） |
| **G1** | 共享事务库抽取 + 通用事务硬化（§3.1.1 T-1..T-4：restore_file_atomically 进回滚、结构化结果、CLI 0/1 兼容包装）+ Phase C/D 回归全绿 | 待实现（实现工作的一部分） |
| **G2** | uninstall/破坏性路径锁下重构 + 锚点不灭（M-1'..M-3'、L-ANCHOR-1..4、no-nesting locked 变体） | 待实现（实现工作的一部分） |
| **G3** | E2 step-up 端点 + §5.2 吊销语义定案（关闭 U-2 web 侧） | 待定案 |
| **G4** | sboxweb systemd 化 + 系统用户供给方案定案 | 待定案 |
| **G5** | 本设计（rev5）final design approval | 待批准 |
| **G6** | 测试脚手架：sbox-cm test wrapper（沙箱 `SB_*` 注入）+ journal/账本 fixture + 帧协议 fuzz（截断帧/超长帧/慢客户端） | 待定义 |

G1/G2/G3/G4 是**实现里程碑**（由 M0/M0.5 交付并各自带测试闸门），不是"动第一行代码"的前置；**唯一的前置是 G5（本设计获批）**。而 **ENABLE E3 MANAGEMENT** 则要求 G1–G6 全部完成（§14）。

---

## 10. 从 Round 2 到 rev5 的迁移计划

| 阶段 | 交付物 | 测试闸门 | 回滚方式 |
| --- | --- | --- | --- |
| **M0 共享库 + 事务硬化**（= G1 + G2） | `lib/client-management.sh` 抽取（字节级）；回滚改 restore_file_atomically（T-1）；结构化事务结果 + CLI 0/1 包装（T-2）；uninstall 锁下重构 + 锚点不灭（M-1'/L-ANCHOR）；marker 生产路径迁 /var/lib/sbox-cm（常量名/env 覆盖保留） | Phase C/D 回归全绿；`bash -n` + shellcheck；新锁生命周期测试（R12 inode 断言、卸载后锚点存活、no-nesting 静态断言） | 逐 commit revert；纯 CLI 侧，无生产影响 |
| **M0.5 供给**（= G3/G4） | sboxweb 用户 + `sboxweb.service`；step-up 端点 + 吊销语义 | E2 回归 + step-up/吊销测试（五类事件各一条断言） | unit 停用即回手动运行；端点独立可关 |
| **M1 helper** | `sbox-cm` 守护进程 + unit；socket/PEERCRED；长度前缀帧 + 三级 deadline；6 op dispatch；账本 + tx journal（文件+目录 fsync）；启动锁下调和；degraded 语义 | E3 套件（rev4 T 系裁剪 + R1–R12 断言）；帧 fuzz（G6）；sandbox 全绿 | `systemctl stop --now sbox-cm` ⇒ 变更面全关（默认态即安全态） |
| **M2 web 适配** | 错误映射、step-up 挂钩、status UI、client.list UI、add/delete 流程 + type-to-confirm + Idempotency-Key | API 契约测试（mock helper）+ S0 安全套件扩展 | web 侧熔断 ⇒ 界面回只读 |
| **M3 激活上线**（= ENABLE 门禁在此收口） | runbook：status → activate → list → add/delete 验证 → deactivate；active_stale 处置 | **G1–G6 全绿 + rev4 §12 适用测试全绿** 方可激活 | deactivate 即关 |
| **M4 硬化** | 失败注入（F1–F22 × R1–R12）、并发 canary、全通道卫生 grep（+journald +client.list 响应）、审计 schema 校验、双图复核刷新 | §9.1 全部 INV 有对应断言且绿 | — |

依赖链：M0 → M0.5 → M1 → M2 → M3 → M4；M1 不得先于 M0（R1/R3/R4/R12 的保护来自 M0）。

---

## 11. 状态机图

### 11.1 事务状态机（client.add / client.delete，helper 内单事务）

```text
            ┌─────────┐  schema 非法      ┌──────────┐
            │ received├─────────────────▶│ rejected │（ok:false, E_SCHEMA…）
            └────┬────┘                  └──────────┘
                 │ schema ok
            ┌────▼────┐  锁不可用/超时
            │ locking ├──────────────────▶ rejected（E_LOCK，字节级零变更）
            └────┬────┘
                 │ locked
            ┌────▼──────────┐  账本 replay    ┌───────────┐
            │ reconcile     ├───────────────▶│ replayed  │（结果逐字段一致）
            │ （账本先于     │  调和冲突       └───────────┘
            │  live 前置）  ├──────────────▶ rejected（E_RECONCILE_CONFLICT / E_IDEMPOTENCY_CONFLICT）
            └────┬──────────┘
                 │ 无记录/调和通过
            ┌────▼────┐  前置失败
            │ intent  ├─────▶ rejected（E_CONFIG_INCONSISTENT / E_DUPLICATE_NAME / E_NOT_FOUND）
            │ fsync ✗ ├─────▶ rejected（E_LEDGER_UNAVAILABLE，零变更）
            └────┬────┘
                 │ intent durable        ══ mutation 不可中止边界（此后 deadline/断连均不中止）══
            ┌────▼────────┐  candidate/check ✗
            │ candidate   ├────▶ terminal: E_CANDIDATE_REJECTED（未触盘）
            └────┬────────┘
            ┌────▼────┐  备份/mv ✗
            │ commit  ├────▶ terminal: E_COMMIT_FAILED
            └────┬────┘
            ┌────▼─────┐  reload/health ✗   ┌──────────────────────┐ restore 后仍病
            │ reload → ├──────────────────▶ │ rollback             ├────▶ E_MANUAL_INTERVENTION
            │ health   │                    │ restore_file_atomically│      + degraded=true
            └────┬─────┘                    │ + reload + health     └──────────────────────┘
                 │ health ok                └────┬──────────────────────┘
            ┌────▼──────────┐                    │ 回滚成功
            │ outcome fsync │ ✗ ──▶ E_STATE_UNCERTAIN（不回滚健康配置，同 key 补账）
            └────┬──────────┘
                 │ ok
            ┌────▼────┐
            │  done   │  audit → journal 清除 → unlock
            └─────────┘
```

### 11.2 启动调和状态机（helper restart，先于一切 mutation）

```text
   ┌────────┐  with_client_lock（fail-closed）
   │ restart├──────────────▶ ┌───────────┐ 无残留 journal
   └────────┘                │ reconcile ├────────────▶ degraded=false（正常服务）
                             └─────┬─────┘
                                   │ 有 phase≥replace 残留
                                   ▼
                             reload → health ──ok──▶ outcome+audit → 清 journal → degraded=false
                                   │ health ✗
                                   ▼
                          restore_file_atomically 回滚 → reload → health
                              ├─ ok ──▶ outcome+audit → degraded=false
                              └─ ✗ ───▶ degraded=true（status 可用；mutation 全拒，
                                                     E_MANUAL_INTERVENTION，待 root CLI 修复）
```

### 11.3 激活状态机（management plane）

```text
                       ┌──────────── activate（锁内，前置绿）┐
                       │                                     ▼
   ┌───────────┐  no_op │                                ┌─────────┐
   │ inactive  ├────────┤                                │ active  │
   └─────▲─────┘        └── status/activate 时发现配置缺失 ─┴────┬────┘
         │                                          ▲           │ deactivate（锁内）
         │         ┌───────────────┐                │           │
         └─────────┤ active_stale  ├◀───────────────┘           │
                   └───────┬───────┘  root CLI mgmt-deactivate  ▼（唯一出边）
                           └──────────────▶ inactive
```

三态语义：

```text
inactive     ：client.add/delete 全拒；client.list/status 可用；破坏性路径放行（默认安全态）
active       ：client.add/delete 放行；破坏性路径拒绝（M-1'）
active_stale ：标记在、配置亡（人为绕过 deactivate 强删后重装）；client.* 全拒；
               activate 类拒绝；status 如实上报 + CRITICAL 审计；
               唯一恢复 = root CLI mgmt-deactivate（M-4'，不静默自动清）
```

---

## 12. RPC schema 汇总（机读版）

```jsonc
// —— 帧格式 ——
Frame = [4-byte big-endian uint32 length L][L-byte UTF-8 JSON]   // 0 < L ≤ 65536
// 服务端 deadline：D-read 5s（帧头后读完 payload）；D-request = op deadline；
// 非法帧/读超时 ⇒ close + 审计，无错误帧

// —— 通用 ——
Request  = { v:"e3-rpc/1", request_id:string(16..64, [A-Za-z0-9._-]), op:Op,
             actor?:{session_fp:string(16), stepup_fp?:string(16)} } & OpPayload
Response = Ok | Err
Ok  = { ok:true, v:"e3-rpc/1", request_id, op, idempotency?:{key_fp, replayed, generation},
        transaction?:Transaction, warnings?:string[], data:object }
Err = { ok:false, request_id, op?, error:{code:ErrorCode, stage:Stage, retriable:bool,
        detail:string, backup?:string} }
Transaction = { entered:bool, phase:Stage, changed:bool, reload_performed:bool,
                health_verified:bool, rollback_attempted:bool, rollback_ok:bool|null,
                backup_path:string|null, duration_ms:int }

// —— op payloads ——
management.status      = {}                                              // deadline 10s，不取锁
management.activate    = {}                                              // deadline 30s，取锁
management.deactivate  = {}                                              // deadline 30s，取锁
client.list            = {}                                              // deadline 15s，取锁（短持有）
client.add             = { name:string, idempotency_key:string(16..128) } // deadline 120s，取锁
client.delete          = { name:string, idempotency_key:string(16..128) } // deadline 120s，取锁

// ErrorCode 枚举与 HTTP 映射：见 §2.6 表（唯一权威）
// Stage 枚举：parse|peer|lock|ledger_intent|revalidate|candidate|check|backup|
//             replace|reload|health|rollback|rollback_manual|outcome|marker|audit
```

---

## 13. 显式阻塞项（全部对基线 `3ee9a162` 重新锚定；review #1/#8 修正后）

| # | 阻塞 | 基线证据 | 归属 |
| --- | --- | --- | --- |
| ~~B-1~~ | ~~锁仍 fail-open~~ | **撤销**：基线 `with_client_lock`（install.sh:729-745）fail-closed 实证；Round 2 全局锁前置 ALREADY PASS | — |
| B-1 | 共享事务库不存在；且 `commit_server_config` 回滚含未校验直接 `cp -a`（install.sh:967），需按 T-1 硬化 | 基线 grep 实证；phase-c 块内嵌 | G1 / M0 |
| B-2 | `uninstall_singbox`（2708）`rm -rf /root/sbox/` 会删除锁与标记本体；marker 检查（2712/3607）在锁外 | 基线 grep 实证 | G2 / M0 |
| B-3 | E2 无 step-up 端点、无吊销语义 | 本分支 web 路由表实证 | G3 / M0.5 |
| B-4 | E2 未服务化（无 sboxweb 用户/unit） | 本分支 grep 实证 | G4 / M0.5 |
| B-5 | sbox-cm.service 硬化旗标未实测（D-Bus/sandbox 交互） | §1.4 注 | M1 验收 |
| B-6 | rev4 的 E3-T/legacy 测试套件不在本分支（CI 计数出自 round2 报告） | 本分支 tests/ 实际清单 | G6（脚手架重建） |

---

## 14. 最终判定（readiness 三层术语，review #8）

| 问题 | 判定 |
| --- | --- |
| **SAFE TO BEGIN E3 IMPLEMENTATION?** | **YES —— 条件：rev5 final design approval（G5）。** 不要求任何未实现的 helper/step-up 代码作为前置；M0（共享库 + 事务硬化 + 锚点不灭）本身就是要实现的第一个里程碑。唯一不可让步的顺序约束：**M1（helper）不得先于 M0**，因为 R1/R3/R4/R12 的保护在 M0 里。 |
| **SAFE TO ENABLE E3 MANAGEMENT?** | **NO —— 直到实现完成且全部 pre-enable gates 通过（G1–G6 全绿 + M3 runbook 就绪）。** 在 B-1（旧编号）被撤销后，剩余硬前置是：T-1 回滚硬化、M-1' 锁内 marker 检查、L-ANCHOR 锚点不灭、step-up 吊销、helper 调和 fail-closed。 |
| **SAFE TO DEPLOY E3 TO VPS?** | **NO —— 直到后续显式 canary approval**（M3 的生产 canary 仅 VPS 人工执行：status → activate → list → 单 client add → delete → deactivate）。 |

一句话：**设计批准即开工；门禁全绿才激活；canary 批准才上 VPS。**

---

## 15. 本轮交付核对

* [x] 设计文档（本文，修订版；8 条 review 修正全部落入正文并标注 review #N）
* [x] 架构图（§1.1）
* [x] 状态机图（§11.1 事务 / §11.2 启动调和 / §11.3 激活）
* [x] RPC schema（§2 + §12 机读汇总；长度前缀帧 + 三级 deadline）
* [x] 竞态/失败矩阵（§8 R1–R12；F1–F22 引用 rev4）
* [x] 实施阶段（§10 M0–M4）
* [x] 显式阻塞项（§13 B-1..B-6；B-1 旧项撤销并留痕）
* [x] 最终判定（§14 三层 readiness）
* [x] 全部代码事实对基线 `3ee9a162` 重新锚定（`git grep -n` 行号，§0/§3/§4/§8/§13）
* [x] **本轮零实现、零运行时改动、未连接 VPS、未触碰 PR #16/#17 / 9191 / TLS / 凭据 —— STOP after revised rev5 design**
