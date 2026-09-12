# Monitor v2 -- Phase E1 collector（API-first, event-driven）

E1 只交付数据层：通过 sing-box 1.14 `service.api` 的**官方 gRPC 事件流**读取逻辑连接，
按 **Device = API USER** 聚合，输出调试 JSON。**没有** Web UI、数据库、conntrack/ss、
Prometheus，也没有任何对外监听。

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

## 已知未实现（后续阶段）

- 用户视角 upload/download 方向映射（需按 API 视角说明，E1 不虚构）；
- 数据库 / 历史曲线；
- Web dashboard（Phase E2）；
- Reality-only RTT/retrans 增强（ss，可选）；
- expected source IP 机械比对（外部测试阶段）。

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
  不进 URL query、错误文本统一 redact；超时钳制在 1-3 秒；
* `reachable=false`（unreachable / disabled / wrong secret / offline）只是
  一个观测结果，服务端 Monitor 完全不受影响，设备状态绝不因此改变；
* freshness 双域独立：enrichment 有自己的 `updated_at/stale/error`，与
  E1 流的 stale 完全分离；
* 只读：不选节点、不切模式、不 reload、不重启、不关连接、不触发
  delay 主动探测（只读缓存 history）。

文件：`monitor-v2/mihomo/{client.py,model.py,fixtures/}`；
测试：`tests/test-monitor-v2-e4.sh`（E1 回归必须保持 188/188）。
