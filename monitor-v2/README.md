# Monitor v2 -- E1 collector（API-first, event-driven）+ E2 read-only Web Dashboard

E1 交付数据层：通过 sing-box 1.14 `service.api` 的**官方 gRPC 事件流**读取逻辑连接，
按 **Device = API USER** 聚合，输出调试 JSON。E2 在其上交付**只读** Web Dashboard
（静态前端 + Python 标准库 HTTP/SSE 后端，详见下文 Phase E2 一节）。
数据层始终：**没有**数据库、conntrack/ss、Prometheus；collector 本身无对外监听，
监听来自 E2 的 web 进程且默认仅 loopback。

## 数据源：真实的 service.api（不是 Clash REST）

sing-box 1.14 的 `service.api` 是 **gRPC / gRPC-Web 服务器**（同端口 h2c 复用）。
连接数据来自官方流式 RPC：

```text
daemon.StartedService/SubscribeConnections   （server-streaming）
```

适配器实现在 `monitor-v2/api_bridge/`：纯 Python 标准库的**最小 gRPC-Web 客户端**
（`application/grpc-web+proto`，原生 socket + select 读流），protobuf 字段号逐条对照
官方 `daemon/started_service.proto`（tag v1.14.0），未 vendor 任何 Go module，
未解析人类可读表格，未使用任何 Clash REST 端点（旧 Clash `/connections` 与本实现无关）。

**请求方向同样使用 length-prefixed 帧**：`0x00 + 4 字节大端长度 + protobuf`
（官方 web_bridge 只改 Content-Type 后原样转发 body，不会替客户端补 envelope）；
响应方向是 `0x00` 数据帧流 + 结尾 `0x80` trailer 帧（grpc-status）。

## 官方事件语义（已对照 v1.14.0 源码 daemon/started_service.go 确认，非猜测）

```text
ConnectionEvents { events[]; reset }

订阅建立后的第一条消息 reset=true：
    全部活跃连接 -> NEW（携带完整 Connection，含权威 uplinkTotal/downlinkTotal）
    最近关闭连接 -> NEW（closedAt 已设置）——注意官方也用 NEW 类型表达
之后：
    NEW    实时推送新连接（完整 Connection）
    UPDATE 仅 id + uplinkDelta + downlinkDelta（无 Connection 对象）；
           delta 归零后补发一次 UPDATE(0,0)；interval（纳秒）仅控制 UPDATE 节奏
    CLOSED id + closedAt（Connection 对象可选）
```

### 本收集器的处理规则

```text
reset=true   -> 用该批次重建快照：批内活跃 id 沿用同一 lifecycle 并刷新权威 totals；
                批内 closedAt 行直接入库（bank 一次）；
                批外旧活跃 id 记为 ABANDONED：不假装 CLOSED、不显示 RECENT，
                但把最后已知 totals 作为 lower bound 入账（累计永不倒退）；
                该 id 后重新出现时先撤销 lower bound 再继续
NEW          -> 活跃 lifecycle 建立/刷新（totals 权威值，非累加）
UPDATE       -> 无 Connection 对象：totals += delta；
                有 Connection 对象：totals = 权威值（替换，绝不双算）
CLOSED       -> 正常携带最终 Connection（含最后一个 ticker 之后传播的流量）：
                先做 identity guard，再用其权威 totals 刷新，然后精确 finalize 一次
防重账守卫    -> 服务端在每次 reset 里重放最近约 1000 条 closed 连接；
                独立的 LRU banked-id 守卫（4096 条，先于展示缓存判定）
                保证同一 id 永远只 bank 一次，与 10 分钟展示 TTL 完全解耦
流失败        -> stale=true，保留 last state，不生成 CLOSED、不清零任何计数；
                连接/响应头有超时上限，但流 body 可以长期静默（官方空闲时
                不发送任何批次）——静默产生心跳批次，绝不误判 stale 或重连
```

## 身份模型（不可变）

```text
Device        = API USER         （逻辑设备，如 vmix-01）
Protocol      = API INBOUND TAG  （vless-in / hy2-in；inboundType 单独存储，不参与身份）
Lifecycle     = API ID           （连接生命周期键，user/inbound 视为不可变字段）
Source IP     = metadata         （仅展示，绝不作为身份）
```

同一 lifecycle 的 `id -> user/inbound` 若在后续事件中变化（identity drift）：
计数 `identity_conflicts`，事件被拒绝，流量绝不迁移到其他设备（HIGH guard）。

## 方向命名：uplink / downlink

全部流量字段使用 sing-box API 原生方向名：

```text
连接:    uplink_total / downlink_total / uplink_rate / downlink_rate
协议级:  protocols.<tag>.uplink_* / downlink_*
设备级:  devices.<name>.uplink_* / downlink_*
```

**暂不**把它们解释成用户视角的 `upload/download`（方向语义需按 API 视角另行说明），
E1 不虚构方向。累计值规则：`banked closed totals + 当前 active lifecycle totals`，
永不下降、永不双算。

## 安全约束

- service.api 只允许 loopback：URL 主机必须是 `127.0.0.1` / `localhost` / `::1`，
  其他目标直接 `fatal configuration error`（fail-closed，secret 绝不外发）；
- secret 优先走环境变量 `BOX_API_SECRET`，或 `--secret-file`（文件建议 0600），
  通过 `Authorization: Bearer` 头传递；不出现在 argv、日志、异常文本、JSON 输出中
  （输出前统一 `[redacted]`）；
- 只读观察：不修改生产 sing-box 配置，不开放端口，不安装任何东西。

## 用法

```bash
# 消费首个 reset 批次后输出快照（快速验证流是否可用）
python3 monitor-v2/collector.py --url http://127.0.0.1:9091 --once --pretty

# 持续消费 30 秒后输出最终状态（真实使用形态）
python3 monitor-v2/collector.py --url http://127.0.0.1:9091 --duration 30 --pretty

# 服务端 UPDATE 节奏（默认 2s，官方 interval 单位为纳秒，由适配器换算）
python3 monitor-v2/collector.py --interval 3 --duration 60

# 启用 secret（二选一）
BOX_API_SECRET=xxx python3 monitor-v2/collector.py --duration 30
python3 monitor-v2/collector.py --secret-file /root/sbox/api.secret --duration 30
```

输出示例（节选，字段名与官方 proto 一一对应）：

```json
{
  "stale": false,
  "batch_count": 31,
  "skipped_events": 0,
  "duplicate_events": 0,
  "identity_conflicts": 0,
  "abandoned_on_reset": 0,
  "active_connections": 2,
  "recently_closed": 1,
  "devices": {
    "vmix-01": {
      "status": "ACTIVE",
      "active_connections": 2,
      "uplink_rate": 1024.0,
      "downlink_rate": 20480.0,
      "uplink_total": 1048576.0,
      "downlink_total": 20971520.0,
      "protocols": {
        "vless-in": {"inbound": "vless-in", "active_connections": 1,
                     "uplink_total": 1000000.0, "downlink_total": 20000000.0},
        "hy2-in":   {"inbound": "hy2-in", "active_connections": 1,
                     "uplink_total": 48576.0, "downlink_total": 971520.0}
      },
      "recent_sources": ["203.0.113.9:51000", "203.0.113.9:51001"]
    }
  }
}
```

## 生命周期状态语义（诚实版）

只输出 `ACTIVE` / `RECENT ACTIVITY` / `IDLE`。**没有** `ONLINE / OFFLINE / Tunnel Down`。
`RECENT ACTIVITY` 按**真实 closed_at** 判定（不是收到事件的时间）：reset 重放的很久以前
关闭的连接不会重新伪装成近期活动。
HY2 多个逻辑连接共享同一 QUIC source endpoint 属正常现象，按独立 ID 分别计数，不合并。

## 测试

```bash
# E1 回归（226 断言：E1-01..E1-22 + 官方事件 fixture + T10 请求/响应双向真帧验证 +
# T11 空闲流心跳 + G1..G8 集成 canary 门槛：合成判定 A-K、USER+INBOUND 作用域
# L1-L4/combo、strict 环境门槛 L5-L8、CLOSE_GRACE_WINDOW 语义 GR1-GR9、
# closed_ids 证据投影与 20-entry 展示缓存 eviction 守卫 G8）。
# 脚本末尾只有唯一 exit，并用 EXPECTED_PASS 门槛强制“跑满 226 且全过”才算成功。
bash tests/test-monitor-v2-e1.sh

# Linux 集成（无门槛的观察运行在非 VPS 环境 SKIP=0）
# 三态退出码：PASS=0 / FAIL=1 / INCONCLUSIVE=2（非法配置也是 FAIL=1）。
bash tests/monitor-v2-integration-e1.sh
```

集成脚本 phase 2 先抓一次 `--once` baseline（提示 DO NOT start client
traffic yet），成功后提示 Start client traffic NOW 并倒计时 2 秒才开窗 --
避免操作者提前产生的流量混进 baseline（baseline == final 会掩盖 delta）。
判定交给 `monitor-v2/lifecycle_gate.py`（纯逻辑，可用合成快照本地回归）。
service.api 初始 reset 会重放 ~1000 条历史关闭连接、累计总量从不清零，所以
裸的 `recently_closed > 0` / `uplink_total > 0` 不构成任何证据；门槛只认
baseline→final 的 delta：traffic delta（本窗口真实字节）与 recent-closed
ID delta（本窗口新 CLOSED/finalize）。`active_connections > 0` 永远不能
替代关闭证据。

环境变量（非法取值 = configuration error，exit 1）：

- `EXPECT_USER=legacy`：硬门槛，devices 里必须出现该 USER，否则 FAIL
  （devices 为空 + 指定了 USER 同样是 FAIL，绝不降级为 INCONCLUSIVE）；
- `EXPECT_INBOUND=vless-in|hy2-in`：硬门槛，**不只是检查协议存在**：它把
  traffic delta 与 CLOSED delta 全部限定到 USER + INBOUND（只读
  `protocols[inbound]` 的 totals、只认该 inbound 的 recent-closed ID），
  同一 USER 的兄弟协议（如 vless-in）的增长或关闭永远帮 hy2-in canary
  过不了关；
- `REQUIRE_CLOSED=1`：必须出现 baseline 之外的新关闭 ID，否则
  FAIL: no CLOSED/finalize evidence observed。
- `CLOSE_GRACE_WINDOW`（默认 240 秒）：**仅当** REQUIRE_CLOSED=1 且 primary
  window 的唯一缺项是 CLOSED/finalize 门禁（USER/INBOUND/traffic delta/
  lifecycle/stale 全部已过）时，进入补窗：**原始 baseline 保持权威**（不重拍）、
  USER/INBOUND 作用域不变、兄弟协议的 closure 与 active 连接**永不**替代
  CLOSED、grace 期间任何 stale / collector 失败 / identity 冲突一律 FAIL；
  补窗内出现 baseline 之外的新 recent-closed `Connection.id` → PASS，
  超时 → FAIL。grace **绝不**"救活" primary window 的 traffic/USER/INBOUND
  失败（那些直接 FAIL，不进补窗）。
- **CLOSED 证据通道与 20-entry 展示缓存 eviction**：`recent_connections` 只是
  RECENT 展示缓存（每设备最新 20 条）；繁忙设备在 240s grace 内关闭 >20 条
  更新连接时可能把目标 id 挤出该缓存。因此快照含 additive 的每设备
  `closed_ids`（≤512、newest-first、行只含 `id`/`inbound`/`closed_at`，
  TTL 内全部 finalize id），gate 的 closed-id delta 读两者的**并集**——
  展示缓存 eviction 不再造成假 FAIL。方向性保证：cap 只丢**最旧**行，
  加上 baseline 差集防重放，eviction 只可能造成假 FAIL，**绝不可能**造成
  假 PASS。
  **残余风险（显式声明）**：若同一设备在 TTL 窗口（≤600s）内出现
  **>512 条更新**的关闭，最旧的 `closed_ids` 行会被丢弃，目标 id 的证据
  可能随之丢失 → false FAIL。这需要单设备约 >2 次/秒的**持续**关闭速率
  贯穿整个 grace 窗口，超出 canary 场景（单客户端生命周期验证）两个数量级；
  且失败方向安全（绝不产生假 PASS）。保留 cap 是为了给快照 JSON 体量一个
  有界上界。

strict canary：只要设置了任一门槛（EXPECT_USER / EXPECT_INBOUND /
REQUIRE_CLOSED=1），sing-box binary 缺失或 service.api 不可达 = FAIL
（exit 1），绝不 SKIP；只有无门槛的观察运行才允许在非 VPS 环境 SKIP
（exit 0）。

没有设置任何门槛且窗口内完全没有真实客户端生命周期时报 `INCONCLUSIVE`
（exit 2），永远不算 PASS；`SOURCE_PRESENT` 只输出布尔值，不参与
identity / traffic 记账 / CLOSED 匹配。

生产 canary 推荐（Reality / HY2 各跑一次，两次都 PASS 才算 E1 canary 通过）：

```bash
# Reality
EXPECT_USER=legacy \
EXPECT_INBOUND=vless-in \
REQUIRE_CLOSED=1 \
LIFECYCLE_WINDOW=30 \
bash tests/monitor-v2-integration-e1.sh

# HY2
EXPECT_USER=legacy \
EXPECT_INBOUND=hy2-in \
REQUIRE_CLOSED=1 \
LIFECYCLE_WINDOW=30 \
bash tests/monitor-v2-integration-e1.sh
```

测试 fixture 位于 `monitor-v2/fixtures/events-*.json`，字段与官方 proto 对应
（NEW/UPDATE/CLOSED、reset、uplinkDelta/downlinkDelta、uplinkTotal/downlinkTotal）。

## 平台支持矩阵与兼容性策略

支持矩阵（经 CI 三版本矩阵实测：Phase C / Phase D / S0 / Legacy / E1 / E2 /
E4 / Packaging / existing-api-auth migration / journal-time 兼容套件全部通过）：

| 平台 | 状态 |
| --- | --- |
| Ubuntu 22.04 LTS | supported / tested |
| Ubuntu 24.04 LTS | supported / tested |
| Ubuntu 26.04 LTS | supported / tested |
| 其他 Ubuntu 版本 / 其他发行版 | not yet guaranteed |

兼容性策略（对 monitor-v2 全部代码路径生效）：

- **能力检测优先**：运行时差异一律按能力/特性检测分支（如 `command -v` 预检、
  systemd 指令验证），**不**以 `/etc/os-release` 版本号做主分支。
- **绝不削弱安全**：不为迁就某个更新/更旧的发行版而削弱加固（unit 硬化指令、
  loopback 契约、鉴权要求）。systemd 指令随版本有差异时，优先采用三者都支持
  的可移植子集；**任何安全关键指令都不会被静默忽略**——CI 在三个基线上跑
  `systemd-analyze verify` 并把 "unknown/unsupported directive" 视为失败。
- **缺失能力 fail-closed**：预检发现必需命令缺失即带清晰诊断立即失败，
  绝不降级运行。命令集按消费者拆分并逐命令记录用途：
  部署变更路径（install/upgrade/rollback/uninstall）要求全集
  `python3` `systemctl` `journalctl` `jq` `ss` `flock` `stat` `sha256sum`
  `mktemp`（`sbmon_preflight_commands`）；运行时 shim 只要求实际依赖
  （monitor-service = `python3`；monitor-health = `python3` `systemctl`
  `stat`，见 `monitor_env_require_commands`）。
  `SBMON_REQUIRED_COMMANDS` 覆写仅限显式测试门
  （fixture / `SBMON_TEST_ALLOW_REQUIRED_COMMANDS_OVERRIDE=1`）之后生效；
  生产调用携带该覆写会被拒绝（fail-closed），预检不可被绕过。
- **service.api 契约全版本一致**：loopback-only URL 契约（`127.0.0.1` /
  `localhost` / `::1`）与鉴权要求（web 模式强制 `SBMON_API_SECRET_FILE`）
  在三个基线上逐字节相同，无任何版本例外。
- **Python 兼容**：以最老支持基线（Ubuntu 22.04 默认 **Python 3.10**）为下限；
  不依赖 3.11+ 语法/stdlib 行为（例如 `datetime.fromisoformat` 不接受 `Z`
  后缀——journal 时间规范化显式转换，见下）。CI 矩阵在三个基线的默认
  解释器上运行全部测试。
- **journal 时间兼容（真实 VPS canary 发现 B6，2026-09-14，Ubuntu 22.04）**：
  Ubuntu 22.04 的 `journalctl --since` **拒绝 raw RFC3339 时间戳**
  （实测 `2026-09-14T15:51:50Z`）。因此：内部 canary 时间戳恒为 RFC3339/UTC；
  任何 `journalctl --since` 之前必须经 `journal_time_normalize_jctl`
  （`tests/lib/journal-time.sh`，Python datetime，fail-closed）规范化为本地
  `"YYYY-MM-DD HH:MM:SS"`；**绝不**把 raw `...T...Z` 直接传给 journalctl。
  回归测试：`tests/test-journal-time-compat.sh`。
- **环境诊断无泄密**：部署与运行时预检记录 `/etc/os-release` 的 `ID` +
  `VERSION_ID`、`python3 --version`、`systemd --version` 首行、`uname -r`，
  存在 `ssh` 时记录 `ssh -V`；绝不打印 conf 值/secret/快照内容。

## Phase E2 -- 只读 Web Dashboard（本次新增）

E2 在 E1 数据层之上交付一个**只读** dashboard：静态前端（vanilla JS/CSS/SVG，
零依赖、零 CDN、断公网可用）+ Python 标准库 HTTP/SSE 后端。**不**创建/删除
客户端、不修改 UUID/password、不触碰 `sbconfig_server.json`、不 reload/restart
sing-box、不引入数据库/conntrack/Prometheus（这些是 E3+ 的事）。

```text
sing-box service.api (127.0.0.1:9091)
        │  SubscribeConnections（gRPC-Web，E1 官方事件流）
        ▼
E1 Collector ── 单进程单实例，长期存活（lifecycle/banked/replay-guard 状态
        │        全在内存；绝不按请求重启）
        ▼
Snapshot Broker（monitor-v2/web/broker.py）
  - collector 线程：consume() 分片循环，永不 raise，stale 语义原样继承
  - publisher 线程：~1s 构建一次装饰后的 snapshot，序列化一次，版本号递增
        │
        ├── GET /api/v1/snapshot   （一次性全量 JSON）
        └── GET /api/v1/stream     （SSE，~1s 推送；浏览器断开不影响 collector）
                ▼
        Web Dashboard（浏览器永远不直接访问 9091）
```

snapshot = E1 原始字段原样透传（`devices` / `connections` / 计数器 /
`stale` / `last_error` / `last_success_at` / `generated_at`），仅**追加**
web 层字段：`web_status`、`api_status`、`monitor_started_at`、
`snapshot_generated_at`、`collector_uptime_seconds`。E1 的
`Tracker.snapshot()` 新增顶层 `connections` 逐连接行（ACTIVE + 有上限的
RECENT，纯投影、无二次记账），供 Connections 表使用；188 项 E1 断言不受影响。

### 0.2.0：持久化事件时间线（issue #33 P1，设计见 docs/monitor-v2-incident-history-p1.md）

publisher 在 `_decorate()` 发布成功后，把 snapshot 的**白名单聚合投影**写入
`<state-root>/diagnostics/history.sqlite3`（0700 目录 / 0600 文件，拒绝符号
链接与非 regular 占位；journal_mode=DELETE + synchronous=FULL；一把可重入
RLock 串行写者、HTTP 读者与 close，见 PR #44 评审 B1）：5s 一条
`timeline_samples` 聚合行，(device, inbound) 稀疏 `device_protocol_states`
行（计数/状态变化立即写、否则 ≤1 次/60s 心跳、仅速率变化不写）。连接 ID、
IP、hostname、UUID、口令、密钥、secret、配置、原始 snapshot 一律不落盘；
设备名与 inbound tag 是允许的最小元数据。保留 7 天 + 48MiB 目标 / 64MiB
硬顶，只删最旧——尺寸裁剪把两表视为**同一条全局 epoch 时间线**，存活集恒为
合并后的最新后缀（评审 B2）；schema 门禁严格：仅"全新库建为 v1"与"恰声明
v1 且表齐全"两种形态被接受，其余（版本 0/畸形/更高、无 meta、缺表）一律
fail-closed 且拒绝时零字节改动（评审 B3）。任何存储/保留失败只记
degraded+分类码，dashboard 与 publisher 永不因此中断。读面仅
`GET /api/v1/diagnostics/timeline?since&limit`（session 门禁、有界、列白名
单、无 UI）。E1 collector 本体、systemd 权限、helper/sbox-cm 边界零改动。

### 请求门顺序（每个普通请求）

```text
socket 对端地址 → IP 白名单 → admin session → 路由
```

- 白名单默认 **空**；仅 `127.0.0.1` / `::1` 隐式放行（本机管理 /
  SSH 隧道 / localhost canary）。支持 IPv4/IPv6 主机与 CIDR
  （`1.2.3.4/32`、`10.10.10.0/24`、`2001:db8::1/128`），`ipaddress` 解析，
  非法条目直接拒绝。唯一例外：`/recovery`（GET 页面 + POST API）。
- **只信 socket 对端地址**：`X-Forwarded-For` / `X-Real-IP` 永远不读；
  反代场景需要另行显式设计 trusted proxy，本版不支持。
- admin 认证：scrypt（N=16384/r=8/p=1 + 随机盐，`hmac.compare_digest` 比较），
  `auth.json` 只存 hash；session token 为 `secrets.token_urlsafe(32)`，
  仅存内存（重启即失效，不落盘）；每个 session 另带独立的 CSRF token
  （`/api/v1/session` 登录后返回，登录后所有 mutation 必须携带
  `X-CSRF-Token`，`hmac.compare_digest` 比较；若浏览器声明 Origin 还须同源）。
  cookie `HttpOnly; SameSite=Strict`，默认 8h；`Secure` 按模式强制：
  remote 监听与任何 TLS 监听**必须**带 Secure，loopback HTTP 监听刻意不带
  （各浏览器对 http://localhost 上的 Secure cookie 行为不一，loopback
  不经过网络，兼容性优先且边界明确）。登录失败按源 IP 限速
  （15 分钟内 5 次失败 → 锁 15 分钟）。
- Recovery：≥128-bit 随机 key（token_urlsafe(24) ≈ 192-bit），明文只显示一次，
  服务器只存 hash。它**只能**把调用方的真实对端地址以 `/32`（或 `/128`）
  加回白名单：不能看 dashboard/白名单、不能指定任意 IP、不能删条目、
  不能改密码、**不建立 admin session**。失败限速更严（3 次失败 → 锁 30 分钟）；
  另有**全进程**预算：每分钟最多 20 次验证尝试、最多 2 个并发 scrypt 验证，
  被拒请求在 scrypt 之前就被 429（带 Retry-After），限速器全部线程安全。
  成功响应只有 "IP added. Please login normally."。
- 日志只记请求行（方法/路径/状态/对端 IP），密码、session token、
  recovery key、sing-box credentials 永不出现在日志。

### 端口与远端模式

默认 `127.0.0.1:9191`。只有用户明确 `--listen 0.0.0.0`（或其他非 loopback
地址）才启用 remote management，且必须**同时**满足：TLS 证书/私钥、admin
password、recovery key、非空白名单——任何一项缺失都 **拒绝启动**（exit 2），
绝不降级为 warning。

**TLS 范围（明确）**：E2 只接受用户自行提供的 `--tls-cert / --tls-key`。
E2 **不**自动申请证书、**不**自动生成自签名证书、不做 Let's Encrypt——
自动证书生成/发放属于后续 Packaging 阶段的职责。响应统一带
`Content-Security-Policy: default-src 'self'`、`X-Content-Type-Options:
nosniff`、`Referrer-Policy: no-referrer`、`X-Frame-Options: DENY`；
HTTP 表面固定为 GET/POST（其余方法一律 405 + `Allow: GET, POST`），
请求体上限 64 KiB（malformed Content-Length → 400，超限 → 413，
chunked → 400 并断连）。

### 访问 loopback-only dashboard（SSH 端口转发）

默认监听 `127.0.0.1:9191`，**不**对公网开放。推荐的访问方式是 SSH 本地端口转发
（Windows / Linux / macOS 通用）：

```bash
ssh -L 19191:127.0.0.1:9191 root@SERVER_IP
```

保持该 SSH 会话打开，然后在浏览器访问：

```text
http://127.0.0.1:19191
```

可选的纯隧道形式（`-N`，不打开远程 shell）：

```bash
ssh -N -L 19191:127.0.0.1:9191 root@SERVER_IP
```

**注意**：部分 SSH 服务器/服务商环境会终止 `-N` 的纯转发（无 shell）会话。
此时请改用上面的普通 shell 形式，或给纯隧道形式加上 keepalive：

```bash
ssh -N \
  -o ServerAliveInterval=10 \
  -o ServerAliveCountMax=6 \
  -o ExitOnForwardFailure=yes \
  -L 19191:127.0.0.1:9191 \
  root@SERVER_IP
```

不要把修改 `sshd_config` 当作常规解法（保持服务器 SSH 配置原样）。

### 白名单行为（为什么隧道访问无需加白）

- `127.0.0.1` 与 `::1` 是**隐式放行**的（白名单默认为空即可本机/隧道访问）；
- 因此 SSH 端口转发访问**不需要**把你的公网 SSH 来源 IP 加入 Monitor 白名单：
  经隧道进来的浏览器连接，在 Monitor 看到的 socket 对端地址就是 loopback；
- 如果在 web-setup 期间回答了 "n"，且从未写入过任何白名单条目，
  `access.json` 可能**不存在**——这是合法状态，不是错误；
- 浏览器连接经由 SSH 隧道到达 Monitor 时，表现为 loopback 来源。

### 数据存放（与 sing-box 配置严格分离）

```text
/var/lib/singbox-monitor/     （POSIX：目录 0700，文件 0600；可用
├── access.json                  SINGBOX_MONITOR_DATA_DIR 覆盖）
│     （白名单；与 Phase C credentials 无任何关系）
└── auth.json （scrypt hash；不含明文密码/recovery key/session token）
```

改白名单/密码/recovery 不 restart、不 reload sing-box，不影响 Reality/HY2
与已生成的 YAML。Stale 语义由 web 原样继承：stale=true 时保留最后快照、
页面横幅显示 "⚠ Data stale + Last successful API event 时间"，不清零、
不伪装 CLOSED、不显示 ONLINE/OFFLINE/Tunnel Down（设备状态只有
`ACTIVE` / `RECENT ACTIVITY` / `IDLE`）。

### 用法

```bash
# 首次配置（检测 $SSH_CONNECTION 提示加白；配置 admin 密码与一次性 recovery key）
sudo python3 monitor-v2/webapp.py setup

# 本地/隧道模式（默认 loopback:9191；无需 TLS）
sudo python3 monitor-v2/webapp.py serve --url http://127.0.0.1:9091

# 远端模式（四项缺一即拒启）
sudo python3 monitor-v2/webapp.py serve --listen 0.0.0.0 \
    --tls-cert /var/lib/singbox-monitor/tls/monitor.crt \
    --tls-key  /var/lib/singbox-monitor/tls/monitor.key
```

### E2 测试

```bash
# E2 回归（182 断言：白名单模型、HTTP 门序、认证/session/限速、SSE 生命周期、
# stale 继承、recovery 语义、只读端点面、setup/serve CLI、远端 TLS 启停；
# 单一 EXPECTED_PASS 出口，与 E1 同风格）
bash tests/test-monitor-v2-e2.sh

# E1 回归必须继续 188/188
bash tests/test-monitor-v2-e1.sh
```

## Phase M0.5 — Step-up 认证（G3）+ Monitor 权限边界定案（G4）

M0.5 **不修改 sing-box，也不实现 sbox-cm**。它只交付 rev5 依赖链
（M0 → M0.5 → M1 → M2 → M3 → M4）里两个前置：Web mutation 的二次认证，
以及既有 `singbox-monitor.service` 的权限边界定型。

### G3：Step-up（`POST /api/v1/step-up`）

普通 admin session 保持只读级：login 之后 Dashboard / traffic / status /
`client.list`（未来）全部放行，**不在页面加载时索要第二次密码**。

只有特权 mutation 要求 step-up。请求门顺序固定为
**session → session-bound CSRF → step-up**：

```text
POST /api/v1/step-up   {"password": "..."}
  200 {"status": "ok", "expires_in": 300}
  401 {"error": "invalid_credentials"}     密码错误
  429 {"error": "rate_limited"}            触发限速（带 Retry-After）

mutation 缺少 step-up
  401 {"error": "reauth_required"}         Web UI 只认这一个码 → 弹密码框 → 重放原请求
```

**step-up 端点自身**同样要求已登录 session **和** 该 session 的 CSRF token
（当然不能要求"已有 step-up"，那是循环依赖），内部顺序固定为：

```text
session → CSRF → rate-limit → verify_password → grant_step_up
```

CSRF 必须早于任何密码工作与计数器变更，这不是装饰：跨站请求虽然猜不到密码，
却可以故意提交错误密码烧掉**共享**的 `LoginRateLimiter` 预算，把真正的管理员
锁在门外（CSRF lockout DoS）。因此被 CSRF 拒绝的请求**不做 scrypt 工作、
不消耗任何限速预算**。

* 窗口 300 秒，记录**只在 Web 进程内存**：`session.step_up_expires`，
  不写数据库、不写磁盘、不写任何 `SB_*` 状态。
* 密码验证复用既有 `auth.verify_password()`；失败计数复用**同一个**
  `LoginRateLimiter`（按 socket 对端地址），Step-up 因此不是第二个无限
  暴力破解入口——两边共享锁定预算（`tests/test-monitor-v2-m05.sh` M3 双向断言）。

**五类吊销（立即生效，不等 300 秒）**：

| 事件 | 处理 |
| --- | --- |
| `POST /api/v1/logout` | session 删除 ⇒ step-up 一起消失 |
| 管理员改密（`POST /api/v1/password`） | **所有** step-up 清空；调用方保留普通登录 session，**其他 session 一律删除**（保持 main 既有语义，绝不为"全量清 step-up"而放宽成所有 session 继续有效） |
| Recovery reset / rotate | `set_recovery_key` ⇒ **所有** step-up 清空（含调用方自己的）；session **不登出**（与改密区分：只降权、不踢人） |
| session TTL 到期 | session 消亡 ⇒ step-up 消亡 |
| Web 进程重启 | memory-only ⇒ session 与 step-up 全部失效 |

**吊销的并发语义（与 M1 的"durable intent 后事务不可取消"对齐）**：

* gate 是**逐请求**求值的。logout / 改密 / recovery reset-rotate 之后，
  所有**尚未通过 mutation authorization gate** 的请求**立即**失去 step-up
  （不是等 300 秒）；
* **已经通过 gate** 的请求不被重新判定，也不会因为随后发生的 logout/改密
  被**半途中止**；
* M0.5 不做任何 dispatch，所以当前不存在"半途事务"这一状态；这条规则现在就
  写死，是因为 M1 继承它：一旦 durable ledger intent 落盘，sbox-cm 侧必须
  把变更驱动到终态，与 Web session 之后做什么无关。

**授权边界（M0.5 交付的是"门"，不是"动作"）**：rev5 §7 的四个特权 op
已作为路由登记，走完整鉴权链：

```text
POST /api/v1/management/activate     → management.activate
POST /api/v1/management/deactivate   → management.deactivate
POST /api/v1/clients/add             → client.add
POST /api/v1/clients/delete          → client.delete
```

通过 step-up 之后返回**固定 501 合同**：

```json
{ "error": "not_implemented", "op": "client.add", "milestone": "M0.5" }
```

501 在这里只表示**一件事**：授权链已全部通过，只缺后端。因此它**永远**不会
早于门禁返回——没有 step-up 时仍然先给 `401 reauth_required`。特权执行面
（sbox-cm / AF_UNIX RPC / 共享 config.lock / 提交引擎）属于 M1/M2。
**本里程碑不读 `/root/sbox`、不写 marker、不 reload、不调用未来 helper，
也不返回任何 success 形态的结果**。M1/M2 只是把这个 handler 的 body 换成
RPC adapter，认证边界一行都不用重新设计。

### M4：`POST /api/v1/clients/export`（只读配置导出）

M1/M2 落地后上述 501 合同已换成真实 RPC adapter（路由登记不变，另见
`docs/e3-m2-web-adapter-design.md` 与 `docs/e3-m4-client-export-design.md`）。
M4 在 E3 路由面上新增且只新增一条：

```text
POST /api/v1/clients/export   → client.export
GET  /api/v1/clients/export   → 405（Allow: POST；导出永远不是可缓存的 GET）
```

* 鉴权链与特权变更完全一致：session → CSRF → step-up → body 形状校验 →
  broker 新鲜度闸门；body 必须**恰好**是 `{"name": "<client>"}`——多一个键、
  少一个键、非对象 JSON、畸形或空 body 一律 400（`invalid_request_body`），
  全部发生在 broker 之前，对应零 export RPC；
* **不接受 `Idempotency-Key`**：header 或 body 出现即 400——`client.export`
  是只读重渲染，不是事务，没有 ledger/journal/reload；
* broker 闸门比 mutation 更严：breaker closed 且一条 **FRESH**
  `management.status` 证明 active / 未 degraded / reconcile clean / lock
  可获得，才允许 dispatch；任一不满足即 503 且**零 export RPC**；
* 成功响应是唯一的 sanctioned 凭据投递形态——文件附件而非 JSON：
  `Content-Type: application/x-yaml; charset=utf-8`、
  `Content-Disposition: attachment; filename="<name>-mihomo.yaml"`（文件名由
  regex 校验过的 name 派生，永不采用 helper 文本）、
  `Cache-Control: no-store, no-cache, must-revalidate` + `Pragma: no-cache` +
  `Expires: 0`；YAML 字节只写进这一个响应；
* 响应超过 48 KiB 一律 502 拒绝，绝不截断；所有失败答案仍是 JSON，
  不含凭据材料，也从不泄漏 `/root/sbox` 路径；
* UI：Clients 表每行都有 Download（Default 也不例外；Delete 依旧永不给
  Default），仅在视图 Available 时可点；401 `reauth_required` 走二次认证后
  **原样重放同一个无 key 请求**；文件进 Blob 即 `revokeObjectURL`，绝不
  自动下载、绝不渲染、绝不落 console/sessionStorage/localStorage。

### `monitor_running` / `management_active`（正交状态）

`GET /api/v1/session` 同时返回两个 **正交** 布尔：

```json
{"monitor_running": true, "management_active": false, "step_up_active": false}
```

* `monitor_running` = E1 collector 线程 + web publisher 线程都存活
  （service.api 不可达的 `stale=true` 仍算 running，这是 E1 合同）；
* `management_active` = 特权变更面是否已激活。**生产默认必须始终 false**；
  M0.5 恒为 false 且 fail-closed：标记位于 root-only 的 sbox-cm 运行时目录，
  sboxweb 对它**零文件系统权限**，唯一未来读通道是 sbox-cm RPC——
  任何不可判定的情况一律返回 false（绝不宣称变更面已打开）。
* 当前实现是一个**阶段性 provider，不是未来的真值源**。M1 之后它**必须**被
  替换为：

  ```text
  Web  →  management.status RPC  →  sbox-cm
  ```

  Web **永远禁止**自己 `stat()/open()` 激活标记（代码里连标记文件名都不允许
  出现，由静态断言 + 权限边界断言共同保证）。

"监控在线 ≠ 允许 Web 修改 sing-box"：两者互不影响，代码与测试都按
正交建模（冻结 publisher 只让 `monitor_running` 降级，`management_active`
与只读快照不受影响）。

### G4：`singbox-monitor.service` 权限边界硬化

**不新建 `sboxweb.service`**：Round 2 起既有 unit 就是 `User=sboxweb`，
本轮只是原地收紧（`monitor-v2/deploy/singbox-monitor.service.in`）：

```text
ProtectSystem=strict        （原 full：现在整个层级只读）
ReadWritePaths=@SBMON_STATE_ROOT@   （唯一可写例外 = 自己的 data root）
ProtectHome=yes             （/root、/home 不可见）
再加：NoNewPrivileges / PrivateTmp / ProtectKernelTunables /
      ProtectKernelModules / ProtectKernelLogs / ProtectControlGroups /
      RestrictSUIDSGID / RestrictRealtime / LockPersonality /
      SystemCallArchitectures=native
CapabilityBoundingSet=       AmbientCapabilities=        （零 capability）
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
```

最后一项**刻意**不收敛为 AF_UNIX-only：monitor 既是 loopback 客户端
（127.0.0.1:9091）又是 loopback 监听者（127.0.0.1:9191），未来还要 connect
`/run/sbox-cm/sbox-cm.sock`。只有 sbox-cm 才能做到纯 AF_UNIX——两个 unit 的
address-family 合同**分开**，不互相借用。

**核心安全边界（INV-1 在 Web 侧的落地）**：sboxweb 对 `/root/sbox/**` 与
root-only 的 sbox-cm 运行时目录**直接文件访问 = 0**。未来即使增加 Client
Manager，也**禁止** `open/jq/mv/chmod/systemctl reload/kill -HUP` 这类旁路，
变更只能走：

```text
Web  →  AF_UNIX  →  sbox-cm  →  shared transaction engine
```

该边界由三层证据共同保证，**不以静态断言为唯一证明**：

1. 静态断言：web 代码零路径引用（含标记文件名）；unit 只开一个 `ReadWritePaths`，
   且不含两个特权树；
2. 内核不变量（实际文件系统检查）：`/root` 必须 root:root owner-only，
   `/root/sbox` 与 sbox-cm 运行时目录必须 absent 或 root:root owner-only
   （M1 创建 `/var/lib/sbox-cm` 后必须复验 root:root 0700）；
3. 主动探测：以**非 root 身份实际尝试**读取 `/root`、`/root/sbox`、
   sbox-cm 运行时目录，必须 `denied`/`absent`（环境无法提供外部身份时打印
   显式 SKIP，绝不静默算过）。

### M0.5 测试

```bash
# M0.5 回归（套件 TOTAL=137：T1-T12 行为断言 + 五类吊销 + 吊销并发语义 +
# step-up 端点自身的 session/CSRF 门与 CSRF lockout DoS 防护 +
# 共享限速双向 + 正交状态模型 + unit 硬化逐项 + 权限边界静态断言 +
# POSIX 内核不变量与实际读探测 6 项）
bash tests/test-monitor-v2-m05.sh

# 既有回归必须继续全绿
bash tests/test-monitor-v2-e1.sh      # E1 collector
bash tests/test-monitor-v2-e2.sh      # E2 web（272/272）
bash tests/test-monitor-packaging.sh  # packaging（unit 断言已随硬化更新）
```

**计数口径**（硬门，杜绝"断言悄悄变少却仍然成功"）：套件大小是**平台无关**的
`TOTAL=137`，每条断言必须落在 PASS / FAIL / SKIP 之一，`PASS + FAIL + SKIP`
必须恰好等于 `TOTAL`，否则判 FAIL。标准 GitHub Ubuntu runner（非 root，外部
身份可得）的期望输出：

```text
PASS=137
FAIL=0
SKIP=0
TOTAL=137
M05_RESULT=PASS
```

环境确实无法提供外部身份时，该节打印并计数 SKIP（例如 `134/0/3/137`），
**绝不**通过下调期望值来凑通过；CI 上同一组数字还会写进 GitHub Actions
step summary。

验收门槛：`G3_STEP_UP` / `G3_REVOCATION` / `G4_SERVICE_BOUNDARY` /
`G4_SYSTEMD_HARDENING` / `E1_REGRESSION` / `E2_REGRESSION` 全 PASS
⇒ **M0.5 = COMPLETE**，方可开始 M1（sbox-cm root helper）。

M0.5 的锁定合同（design review 后）汇总：step-up 端点需 session + CSRF 且
CSRF 先于限速/校验；mutation 缺 step-up 一律 `401 reauth_required`；授权通过后
只给固定 `501 not_implemented`；吊销逐请求生效、已过 gate 的请求不半途中止；
改密保持"调用方 session 保留 / 其他 session 删除"并额外吊销全部 step-up；
recovery rotate 只降权不踢人；`management_active` 是阶段性 provider，M1 必须
换成 `management.status` RPC，Web 永不 stat 标记；unit 硬化使用
`ProtectSystem=strict` + 单一 `ReadWritePaths`；权限边界必须同时有静态断言、
内核不变量与实际读探测三重证据。

## 已知未实现（后续阶段）

- 用户视角 upload/download 方向映射（需按 API 视角说明，E1 不虚构）；
- 数据库 / 历史曲线（totals 为 "Since monitor start"，非 all-time）；
- Client Manager（Phase E3，明确不在本阶段）；
- **mutation 真执行**：`client.add/delete`、`management.activate/deactivate`
  的 sbox-cm 特权后端（AF_UNIX RPC + 共享 config.lock + 提交引擎）属 M1/M2；
  M0.5 只交付已评审的授权门（step-up）与 501 边界，`management_active` 恒 false；
- Reality-only RTT/retrans 增强（ss，可选）；
- expected source IP 机械比对（外部测试阶段）；
- 可信反代（trusted proxy）场景下的白名单来源设计。

## Phase E4 -- Mihomo client API enrichment（OPTIONAL，read-only）

E4 在**客户端本地** Mihomo external-controller 上做可选 enrichment，
是显示层的补充，绝不是身份数据源：

```text
Server truth（不可替代）:  Device = service.api USER / Protocol = INBOUND / Lifecycle = connection ID
Mihomo API（仅补充展示）:  version / mode / selected proxy / delay /
                           local connections / local traffic rate
```

铁律（由代码结构强制，详见 `monitor-v2/mihomo/README.md`）：

* enrichment 输出对象走固定 key 白名单，结构上不可能携带任何身份字段；
  节点显示名（`vmix-01-HY2`、`香港-01`……）原样透传为 `selected_proxy`，
  仅用于展示，绝不参与身份判定/映射/重命名；
* controller URL 只允许 loopback（fail-closed）；Mihomo API 是客户端本地
  服务，绝不公网暴露，服务器侧读取应走显式 agent/隧道设计；
* secret 只经 `Authorization: Bearer` 头传递：不进日志、不进输出对象、
  不进 URL query、错误文本统一 redact（含传输异常/HTTP 错误体内出现的
  secret）；每个 API 请求超时钳制在 1-3 秒（整个 poll 顺序请求可能占用
  多个请求预算；whole-poll deadline 留待真正集成 agent 时单独设计）；
  `--secret-file` 全平台要求 regular file；POSIX 强制 owner-readable 且
  无 group/other 权限位（0600/0400 可用，0000/0200/0644+ 拒绝，校验先于
  读取内容，O_NOFOLLOW 拒绝 symlink）；Windows 不做 POSIX 位拒绝，依赖
  文件系统 ACL（v1 文档化限制）；
* transport 只有 `get(path)` 一个入口——不存在 method 参数，PUT/POST/
  PATCH/DELETE 在结构上无法发出；URL 拒绝 userinfo/非根 path/query/
  fragment，且错误信息绝不回显完整 URL；
* `reachable=false`（unreachable / disabled / wrong secret / offline）只是
  一个观测结果，服务端 Monitor 完全不受影响，设备状态绝不因此改变；
* freshness 双域独立：enrichment 有自己的 `checked_at`（本次轮询完成时间）
  / `updated_at`（最近一次成功取得有效数据的时间，失败轮询为 null 且
  stale=true，绝不出现 unreachable-but-fresh）/ `error`，与
  E1 流的 stale 完全分离；
* `/connections` 语义：`null`/`[]` -> 0（确认空闲），key 缺失或类型错误
  -> None（schema 漂移/未知，绝不伪装成 idle）；
* `/traffic` 是真实无限流：newline 分帧 + 绝对 deadline 的首行读取器，
  读到第一条完整 JSON 立即返回，不等连接关闭、不读第二条；
* 只读：不选节点、不切模式、不 reload、不重启、不关连接、不触发
  delay 主动探测（只读缓存 history）。

文件：`monitor-v2/mihomo/{client.py,model.py,fixtures/}`；
测试：`tests/test-monitor-v2-e4.sh`（E1 回归必须保持 188/188）。

