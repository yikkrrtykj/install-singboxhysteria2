# Monitor v2 -- Phase E1 collector（API-first）

E1 只交付数据层：从 sing-box service.api 读取逻辑连接，按 **Device = API USER** 聚合，
输出调试 JSON。**没有** Web UI、数据库、conntrack/ss，也没有任何对外监听。

## 身份模型（唯一，已由 production canary 实测确认）

```text
Device        = API USER        （逻辑设备，如 vmix-01）
Protocol      = API INBOUND     （vless-in / hy2-in）
Connection    = API ID          （逻辑连接生命周期键）
Source IP     = metadata        （只展示，绝不作为身份）
DESTINATION / RATE / TOTAL / CREATED = 连接属性
```

```text
vmix-01
├─ Reality: USER=vmix-01, INBOUND=vless-in
└─ HY2:     USER=vmix-01, INBOUND=hy2-in
```

## 生命周期状态机

```text
first seen id        -> active（计入 device/protocol 的 active 总量）
same id next poll    -> 更新 rate/total（单调，只增不减）
id 从 poll 中消失     -> finalize：把该 ID 最后 total 一次性存入
                        device/protocol 的 banked 累计值，行进入 recent-closed 缓存
id 重新出现           -> 重新激活同一生命周期（banked 值转回 active，绝不 double count）
closed 缓存 TTL       -> ~10 分钟（600s），仅用于 RECENT ACTIVITY 展示；
                        过期只从缓存移除，累计值已入 banked，永不下降
```

## 状态语义（诚实版）

API 返回的是**逻辑路由连接**，不是传输层心跳。因此只输出：

- `ACTIVE` — 当前 poll 存在该设备的连接
- `RECENT ACTIVITY` — 无活动连接，但 TTL 内有已结束连接
- `IDLE` — 已知设备，当前与 TTL 内均无活动

**没有** `ONLINE / OFFLINE / Tunnel Down`——除非未来拿到真正的传输层/会话级证据。
HY2 多个逻辑连接共享同一 QUIC source endpoint 属正常现象，不会被合并成一台设备。

## 约束

- API 仅 `127.0.0.1:9091`，不开放防火墙，不改 `0.0.0.0`；
- 第一版纯内存，无数据库；
- polling 建议 2–5 秒（`--interval`）；
- `ss` 不参与身份/累计：未来如需 Reality TCP RTT/retrans，只作为 Reality-only 可选增强；
- API 不可达时：保留 last state 并标记 `stale: true`，不丢数据、不崩溃；
- malformed API row：跳过并计数（`skipped_rows`），不污染聚合。

## 用法

```bash
# 单次 poll，输出调试 JSON（在服务器上，root）
python3 monitor-v2/collector.py --url http://127.0.0.1:9091 --once --pretty

# 循环模式，每 3 秒一行 JSON
python3 monitor-v2/collector.py --loop --interval 3
```

输出示例（节选）：

```json
{
  "devices": {
    "legacy": {
      "status": "ACTIVE",
      "protocols": {
        "hy2-in":   {"active_connections": 1, "rate": 2048.0, "total": 2097152.0},
        "vless-in": {"active_connections": 1, "rate": 1024.0, "total": 1048576.0}
      },
      "active_connections": 2,
      "recent_sources": ["203.0.113.9:51000", "203.0.113.9:51001"],
      "total": 3145728.0
    },
    "vmix-01": {
      "status": "ACTIVE",
      "protocols": {
        "hy2-in": {"active_connections": 1, "rate": 512.0, "total": 65536.0}
      }
    }
  }
}
```

## 已知未实现（后续阶段）

- rx/tx 方向拆分（API 行未提供方向字段，不虚构）；
- 数据库 / 历史曲线；
- Web dashboard（Phase E2，等 E1 数据模型与累计算法评审通过）；
- Reality-only RTT/retrans 增强（ss，可选）；
- service.api 鉴权令牌（当前 canary 未启用；`--secret-file` 预留）。
