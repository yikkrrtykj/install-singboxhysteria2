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
（`application/grpc-web+proto`，标准 length-prefixed 帧），protobuf 字段号逐条对照
官方 `daemon/started_service.proto`（tag v1.14.0），未 vendor 任何 Go module，
未解析人类可读表格，未使用任何 Clash REST 端点（旧 Clash `/connections` 与本实现无关）。

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
                批外旧活跃 id 丢弃但不 bank（服务端未确认 CLOSED，不猜测）
NEW          -> 活跃 lifecycle 建立/刷新（totals 权威值，非累加）
UPDATE       -> 无 Connection 对象：totals += delta；
                有 Connection 对象：totals = 权威值（替换，绝不双算）
CLOSED       -> 精确 finalize 一次：最终 totals 一次性 bank 进 device/protocol，
                行进入 recent 缓存；重复 CLOSED 只计数不重复 bank
流失败        -> stale=true，保留 last state，不生成 CLOSED、不清零任何计数
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
HY2 多个逻辑连接共享同一 QUIC source endpoint 属正常现象，按独立 ID 分别计数，不合并。

## 测试

```bash
# E1 回归（62 断言：E1-01..E1-18 + 官方事件 fixture + T10 真实 gRPC-Web wire 环回）
bash tests/test-monitor-v2-e1.sh

# Linux 集成（仅当 /root/sbox/sing-box 与 127.0.0.1:9091 存在时执行，否则 SKIP）
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
