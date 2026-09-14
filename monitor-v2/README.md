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
# E1 回归（188 断言：E1-01..E1-22 + 官方事件 fixture + T10 请求/响应双向真帧验证 +
# T11 空闲流心跳 + G1..G6 集成 canary 门槛：合成判定 A-K、USER+INBOUND 作用域
# L1-L4/combo、strict 环境门槛 L5-L8）。脚本末尾只有唯一 exit，并用
# EXPECTED_PASS 门槛强制“跑满 188 且全过”才算成功。
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

## 已知未实现（后续阶段）

- 用户视角 upload/download 方向映射（需按 API 视角说明，E1 不虚构）；
- 数据库 / 历史曲线（totals 为 "Since monitor start"，非 all-time）；
- Client Manager（Phase E3，明确不在本阶段）；
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

