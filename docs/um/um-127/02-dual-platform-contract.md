# UM-127 02 — Linux VPS / Windows 终端双平台节点契约扩展（提案）

- 状态：**PROPOSED（提案，未批准）**。本文件不改变 PR #126 已冻结的契约，也不构成实现授权。
- 依赖：PR #126（UM-A revision 3 final，HEAD `5089cdeb`；本计划简称 rev-4）的 `docs/um/um-a/04-node-protocol-v1.md` 与 `contracts/v1/`。
- 本文件描述的扩展属于冻结契约变更：新增请求字段、可选 payload 字段、闭合枚举值、节点类别与平台特定数据源。必须按 UM-A §5 走 rev-5 amendment（威胁模型影响、兼容性说明、正负向量、独立审查、Owner 授权），批准后才能进入 UM-B 实现。
- 所有 Owner 决策均为 **PENDING**。

## 1. 现状与缺口

### 1.1 rev-4 已有内容

- 节点身份、Ed25519 签名、enrollment、rotation、撤销、防重放、幂等、spool、断线补传、新鲜度（`04` §1–§7）。
- 通用 payload：`report-snapshot` / `report-metrics` / `report-events`，availability 诚实语义（`ok|partial|unavailable`、nullable、UNKNOWN/STALE 由 center/UI 渲染，`04` §9）。
- Linux VPS 数据源：sing-box `service.api`（默认关闭，需 server-side 授权审计）、`/proc`、只读 systemd D-Bus；Mihomo controller **在 v1 默认关闭、不纳入 v1 验收**（`04` §11）。
- 隐私：不上传 UUID、密码、私钥、token、完整 YAML、client 名称、原始源/目的 IP、URL、命令行、连接记录；只允许聚合计数、协议状态 token、`device_ref` 等（`04` §9）。

### 1.2 本轮产品范围带来的缺口

跟踪 Issue #127 与 Owner 本轮说明要求首版同时纳入：

1. **Linux VPS**：sing-box 服务状态、Reality/Hysteria2 流量、赛事归属；
2. **Windows 终端**：Mihomo 当前选路、活动连接实际路径及计数、A/B 与中心 VPS ID 映射、选路/连接独立采样时间、UNKNOWN/UNAVAILABLE/STALE、隐私限制。

rev-4 的缺口：

| 编号 | 缺口 | 说明 |
| --- | --- | --- |
| P-1 | 没有 `node_class` / 平台类型 | 无法在协议层区分 `linux_vps` 与 `windows_terminal`，也无法按类别校验 payload 与数据源 |
| P-2 | Windows 遥测没有契约字段 | `report-snapshot` 没有 route selection / connection 聚合 / 独立采样时间字段 |
| P-3 | Mihomo controller 在 v1 被禁用 | 与“首版 Windows 采集当前选路和活动连接”直接冲突 |
| P-4 | 没有 A/B ↔ 中心 VPS ID 映射契约 | Go 原型只在本地 profile 里做角色映射，center 侧没有可审计的映射配置与校验 |
| P-5 | Controller 凭据授权能力未说明 | 现有 `windowsobs` 以 GET 白名单实现，但凭据本身可能是写能力的；不能据此宣称安全只读 |

### 1.3 已有 Go 原型的事实

`codex/um-windows-foundation`（HEAD `24cfd2ff`）的 `um/internal/windowsobs` 已经实现：

- 只读 `GET /proxies`、`GET /connections`，固定 loopback 字面地址；
- 本地 profile 的 `group` + `routes` 把本地代理名映射为 `a_reality`/`a_hy2`/`b_reality`/`b_hy2` 角色；
- 选路与活动连接分开采样，活动连接按 chain 归入角色，缺失/歧义归 `unknown`；空列表/null 与缺失/畸形响应区分（观测到的 0 vs 未知）；
- 输出不含本地代理名、目标、连接 ID、controller secret。

该原型是 UM-B3 的复用基础，但**不是契约**：它没有 `node_class`、没有 center 可校验的 payload、没有 route token/A-B 映射，也没有 Owner 批准的凭据风险结论。本提案把这些收编为契约扩展，而不是重写原型。

## 2. 节点类别模型

### 2.1 类别定义

| `node_class` | 适用对象 | 核心遥测 | 不采集 |
| --- | --- | --- | --- |
| `linux_vps` | 赛事 VPS（Linux） | sing-box 服务/入站状态、Reality/Hysteria2 聚合流量、系统资源、可用性 | 原始客户端标识、配置/凭据、连接明细 |
| `windows_terminal` | 赛事 Windows 终端 | Mihomo 当前选路、活动连接按路径聚合计数、独立采样时间、可用性 | 原始连接目标/源 IP/进程/连接 ID、代理名、私有 YAML、凭据 |

### 2.2 Enrollment 扩展

`enroll-request.schema.json` 提案新增字段（rev-5）：

```json
{
  "v": 1,
  "node_class": "linux_vps | windows_terminal",
  "agent_version": "…",
  "host": {"os": "linux|windows", "kernel": "…", "arch": "…"},
  "capabilities": ["…"]
}
```

规则：

1. `node_class` 为必填，闭合枚举；center 校验与 `host.os` 一致（`linux` → `linux_vps`，`windows` → `windows_terminal`），不一致拒绝 `invalid_request`。
2. 类别在注册时由 center 固化，**Agent 不能修改**；变更类别 = 吊销 + 重新注册（新的 node_id），或未来由 UM-B4 提供受审计的管理员重绑定（默认不提供）。
3. 赛事归属仍由 center 决定；Agent 不能自选赛事。
4. signing string 格式不变（enroll 仍只绑定 transport header + body hash），但 enrollment 正向量因 body 变化必须重新生成；旧 rev-4 向量保留为“读取器/负向”回归，不删除。
5. `capabilities[]` 仍为 advisory；center 以 `node_class` + 配置决定允许的数据源，不信 Agent 自述。

### 2.3 Center 侧配置（UM-B4/UM-C 管理面）

- 每个 event 下登记 `linux_vps` 节点与 `windows_terminal` 节点；Windows 节点头像/别名是 center-side 元数据。
- Windows 节点的 route 映射：`terminal_route_map: { "A": <linux_vps node_id>, "B": <linux_vps node_id> }`，只能指向**同一 event 的已注册 `linux_vps` 节点**；`DIRECT`/`UNKNOWN` 为保留 token，不可映射。
- 映射是 center 配置，不进 Agent 上报；Agent 只上报 token。未映射的 token 数据可以存储但 UI 必须显示“未映射/UNKNOWN”，不能猜测或伪造。
- 所有映射变更需审计，且不能影响节点身份。

## 3. 共享契约（两类节点一致，引用 rev-4）

以下内容不因类别而变，直接沿用 rev-4：

- enrollment（active-on-commit、响应丢失的 orphan 处理）、独立 Ed25519 身份、rotation/revocation 状态机；
- 签名 header 与 signing string（Endpoint report/config/rotate）；
- `report_id` / `collected_at` 与每次 attempt 的 `sent_at`/`nonce`/`seq`/`boot_gen` 分离；
- 防重放表、事务顺序、`synchronous=FULL`、ACK 语义、spool/补传/新鲜度；
- 可用性诚实语义：缺失指标为 `null`，不得伪造 0/健康；`unknown` 与 `unavailable` 区分；
- 隐私 allowlist 与 sentinel 负向测试。

## 4. Linux VPS 契约要求（沿用 + 明确）

1. 数据源只允许：sing-box `service.api`（`singbox_api`，默认 false；启用前必须有版本化 server-side 授权审计，证明凭据不能调用配置变更操作）、`/proc`、只读 systemd D-Bus `ActiveState`；禁止 journald、root 采集器、`systemctl` exec fallback。
2. 状态模型：`services[]` 的 `name` 运行时白名单 v1 仅 `sing-box`；`inbound_tag`/`kind` 必须匹配 center 配置的 `expected_inbound_tags`；协议状态只能由可用证据推导，流量缺失 ≠ down/up。
3. 流量：Reality/Hysteria2 的聚合计数（不采集客户端明细）；采样时间、单位、时间边界按 rev-4 校验。
4. 系统：CPU/内存/磁盘/网络计数来自 `/proc`/syscalls；不执行子进程。
5. 客户端摘要（如启用）：只有 pseudonymous `device_ref`（per-event HMAC salt）与聚合计数，不出现 IP/名称/UUID/连接记录。
6. 授权证据：`source_authorization_unproven` 时源保持 `unavailable`，绝不降级为伪造数据。
7. 采样新鲜度：`observed_at` / `metrics.samples[].at` / `events[].at` / `collected_at` 的边界沿用 rev-4 §9；center 由 `now - sampled_at` 计算 STALE。

## 5. Windows 终端契约扩展（提案）

### 5.1 采集边界

- 采集进程只读；**不修改 Mihomo 配置、不切换节点/策略组、不关闭或新建连接、不改变 HA-UI/P6 Remote Probe/#67 行为**。
- 只访问本机 loopback controller（固定 `127.0.0.1`/`::1` + 端口），只允许 `GET /proxies` 与 `GET /connections`；禁止 redirect、环境变量代理、DNS 解析、其他 method/path。
- 采集结果只保留：token、聚合计数、时间戳、可用性/错误码；**不保留**代理名、controller secret、目标地址、源 IP、进程名、连接 ID、规则 payload、YAML。

### 5.2 Payload 扩展（`report-snapshot` 可选 `terminal` 对象）

```json
{
  "terminal": {
    "platform": "windows",
    "selection": {
      "availability": "ok | partial | unavailable",
      "sampled_at": 1700000000,
      "route": "A | B | DIRECT | UNKNOWN | null",
      "reason_code": "controller_unreachable | controller_auth | malformed_response | route_unbound | source_authorization_unproven | null"
    },
    "connections": {
      "availability": "ok | partial | unavailable",
      "sampled_at": 1700000003,
      "total": 42,
      "by_route": {"A": 20, "B": 15, "DIRECT": 5, "UNKNOWN": 2}
    }
  }
}
```

规则：

1. `selection` 与 `connections` **分别采样、分别带 `sampled_at`**，允许时间不同；两者都必须满足 `sampled_at ∈ [collected_at - 300 s, collected_at + 60 s]`（具体边界随 amendment 冻结）。
2. `availability` 与 rev-4 一致：`unavailable` 时所有值 `null`；`partial` 时至少一个字段 `null`；`ok` 时 `total`、`by_route` 均非空，且 `total == sum(by_route)`（不含 `null` token）。
3. `route`/`by_route` 的键只能是 `A`、`B`、`DIRECT`、`UNKNOWN`；不允许任意代理名进入存储。`UNKNOWN` 表示“观测到连接但无法归属”，不是“0”。
4. 空列表/null 区分：API 返回合法空数组 → 观测到的 0；响应缺失/畸形/超时 → `unknown`/`unavailable`，绝不写 0。
5. 选路采样与连接采样**独立**：A/B 切换后，旧连接仍可能走在旧路径；`selection` 表示当前选择，`connections.by_route` 表示实际连接分布，两者不一致是正常状态，不是错误。
6. `reason_code` 为闭合枚举；不进自由文本。可选 `controller_version`（若有）需 review 决定是否上报（默认不上报，见 OD-P8）。
7. 中心存储 NULL/未知，由 UM-D 渲染 UNKNOWN/STALE；禁止由 Agent 伪造“健康”。

### 5.3 Events 扩展（`report-events` 新 kind，闭合）

| kind | detail（闭合） | 用途 |
| --- | --- | --- |
| `terminal_route_changed` | `{previous_route, current_route, sampled_at, source:"mihomo_api"}` | 选路变化时间线 |
| `terminal_source_unavailable` | `{source:"mihomo_api", reason_code}` | 源不可用/授权未证明 |
| `terminal_connection_observed`（可选） | 不建议 v1 | 避免连接级明细进入事件流 |

- 新增 kind 属于闭合枚举扩展；detail 字段 `additionalProperties:false`，不允许文本/目标/IP/代理名。
- 事件时间边界沿用 rev-4；同一 `collected_at` 内去重由 `report_id` 完成。

### 5.4 Metrics 扩展（可选 `terminal_samples[]`）

```json
{"terminal_samples": [
  {"at": 1700000000, "route": "A", "total": 40,
   "by_route": {"A": 20, "B": 15, "DIRECT": 5, "UNKNOWN": 0},
   "availability": "ok"}
]}
```

- `at` 分钟对齐、严格递增、唯一；nullable 规则同 rev-4；不满足则整条 sample 丢弃/标 `partial`。
- 首版可只做 snapshot + events；metrics 作为 UM-D 前可选，Owner 决定（OD-P5）。

### 5.5 A/B ↔ 中心 VPS ID 映射

链路：

```text
本地 Mihomo 选择组/成员名
  ──(Agent 本地 route_bindings: token ← group+member，center 下发)──▶ token A|B|DIRECT|UNKNOWN
  ──(snapshot.terminal.selection.route / connections.by_route)──▶ center
  ──(center terminal_route_map: A→linux_vps node_id)──▶ 赛事视图中的 VPS 节点
```

- `route_bindings` 由 center 在 `/v1/agent/config` 下发，bounded：最多 8 条，`token ∈ {A,B,DIRECT,UNKNOWN}`（DIRECT/UNKNOWN 可为保留不绑定），`group`/`member` 为本地配置名（精确匹配，长度上限 128）；**不下发** node_id、hostname、URL 或凭据给 Agent。该字段是对 `agent-config` 的扩展，会进入 amendment 与隐私/威胁审查；它不包含 URL/host/凭据，也不得被 Agent 回传。
- center 侧 `terminal_route_map` 由管理员配置（UM-B4），只接受同 event 的 `linux_vps` 节点；映射变更审计。
- Agent 只输出 token；不得把本地代理名写入任何上报字段；`route_unbound`（本地没有对应 binding）由 Agent 报 UNKNOWN，`未映射`（center 未配置 A/B→VPS）由 center 判定并显示，双方都不猜测。
- 验收：A/B 切换后，`selection.route` 立即变化，`connections.by_route` 体现旧连接仍在旧路径；二者独立采样；映射到中心 A/B VPS 节点后 UI 能同时展示“当前选路”和“实际连接分布”。

### 5.6 新鲜度 / UNKNOWN / UNAVAILABLE / STALE

| 状态 | 产生方 | 条件 | 展示 |
| --- | --- | --- | --- |
| `unavailable` | Agent | 源开关关闭、凭据不可用、controller 不可达、授权未证明 | 灰显“不可用”，null |
| `unknown` | Agent | controller 可达但响应畸形、无法归属的路径 | 灰显“未知”，null/UNKNOWN |
| `STALE` | Center/UI | `now - sampled_at > stale_after_s` | 显示采样时间与 STALE；不推断健康 |
| `ok` | Agent | 合法响应且解析成功 | 正常 |

`stale_after_s` 提案：`max(180 s, 3 × cadence_seconds)`，每个 event 可配置，范围 `[60, 900]`；具体值 Owner 决定（OD-P5）。center 不因“无上报”推断 down；节点离线只让数据 STALE/UNKNOWN（与 rev-4 失败模型一致）。

## 6. Controller 凭据的实际授权能力（关键结论）

### 6.1 事实：Mihomo external controller 凭据不是只读的

官方 API 文档（MetaCubeX mihomo）明确列出写操作，持有 secret 即可调用：

| 能力 | 方法 / 路径 | 影响 |
| --- | --- | --- |
| 重载配置 | `PUT /configs?force=true` | 替换运行配置 |
| 增量改配置 | `PATCH /configs` | 修改运行参数 |
| 重启内核 | `POST /restart` | 业务中断 |
| 更新内核/面板/Geo | `POST /upgrade`、`/upgrade/ui`、`/upgrade/geo` | 供应链/可用性风险 |
| 选择/清除代理 | `PUT /proxies/{name}`、`DELETE /proxies/{name}` | 切换选路 |
| 更新 provider | `PUT /providers/proxies/{name}`、`PUT /providers/rules/{name}` | 更新节点/规则 |
| 禁用规则 | `PATCH /rules/disable` | 改变分流 |
| 关闭连接 | `DELETE /connections`、`DELETE /connections/{id}` | 断开业务连接 |

来源：<https://wiki.metacubex.one/en/api/>（表中 `PUT/PATCH/POST/DELETE` 项）。Clash Verge Rev 需要用户手动开启 External Controller 并自行承担风险（<https://github.com/clash-verge-rev/clash-verge-rev/discussions/6951>）。

### 6.2 结论：不能仅凭 GET 白名单宣称“安全只读”

Go 原型的 client 只调用 GET，这是**实现约束**，不是**授权证明**：secret 本身仍是写能力的。任何“UM 只读，所以无风险”的表述都不成立。必须按真实能力描述：**write-capable credential held by a read-only client**。

### 6.3 可接受的做法（提案）

| 方案 | 描述 | 评价 |
| --- | --- | --- |
| R1 | Owner 明确接受残余风险；Agent 代码只读 + 隔离 | 首版推荐（若 R2 不可行） |
| R2 | 使用 Clash Verge Rev / Mihomo 提供的真正只读表面（如本地日志/导出，不持有 controller secret） | UM-B3 优先调研；若可行优先 |
| R3 | 本机过滤代理持有 secret，Agent 只访问代理暴露的 GET 子集 | 仍存在本机写能力，但缩小 Agent 暴露面；增加组件与故障面 |
| R4 | 推迟 Windows route/connection 遥测 | 不满足首版范围，仅在 R1 不被批准时 |

推荐：UM-B3 先调研 R2；不可行则采用 **R1 + 最小缓解集**，并由 Owner 在 OD-P3 明确接受残余风险。禁止在任何文档/PR 中宣称“controller 凭据是只读的”。

### 6.4 最小缓解集（R1 必须全部满足）

1. controller 仅绑定 loopback（`127.0.0.1`/`::1`），不监听公网；端口/secret 由 owner 配置。
2. secret 使用专用随机值，不进仓库/日志/上报；Windows 上使用 DPAPI/凭据管理器或 0600 ACL 私有文件；轮换程序化可验证。
3. Agent 进程非管理员运行；HTTP client 固定 method（GET）+ 固定 path + 固定 loopback 字面量，禁用 redirect/proxy env/DNS；响应体上限与超时。
4. 二进制内不存在其他 controller 调用路径：静态测试（allowlist 常量）+ 运行时 mock controller 记录 assert 只出现 `GET /proxies`、`GET /connections`；负向测试禁止 `PUT/PATCH/POST/DELETE`。
5. 启动/退出日志不打印 secret、代理名、目标；错误码闭合。
6. 每次 UM-B3 升级/验证记录 Mihomo/Clash Verge Rev 版本与 controller 能力审计；版本不匹配 → 源 `unavailable`（fail-closed）。
7. UM-E 真实验收：采集前后 Mihomo 配置 hash、当前选路、活动连接集合（数量与关键属性）不因 Agent 运行而变化；HA-UI/P6 无变化。

## 7. 只读与 HA 无干扰验收

| 断言 | 方法 |
| --- | --- |
| 不修改 Mihomo 配置 | 采集窗口内 Agent 不发出配置写请求；采集前后配置文件 SHA-256 对比（自然变更需记录并排除）；mock controller 断言无 `PUT/PATCH /configs` |
| 不切换节点 | Agent 不发出 `PUT/DELETE /proxies`；采集前后 `GET /proxies` 的 `now`/`fixed` 对比（自然切换需排除） |
| 不关闭连接 | Agent 不发出 `DELETE /connections`；mock/真实观测无连接关闭请求（自然流量变化不计入） |
| 不改变 HA 行为 | HA-UI、P6、#67 进程/端口/服务状态不变；UM 采集独立进程 |
| 不上传敏感数据 | 隐私 sentinel 负向测试：目标 IP/URL/进程名/YAML/secret 出现在 response 时被拒绝/剔除，存储/日志/备份均无 |
| 只读失败模型 | controller 不可达/授权未证明 → `unavailable`，不是 down/0 |

## 8. 变更控制与兼容性

- 新增 `node_class` 必填字段、`terminal` 可选对象、事件 kind、metrics 可选数组 → **frozen contract revision**（建议 rev-5，因为当前无生产 Agent，保持 v1 单一 major 比引入 v1.1 更简单）。
- 兼容性：
  - 旧 rev-4 签名格式/向量不变；`report` signing string 不含 payload 字段，故既有 report 向量继续有效；
  - `enroll` 向量需按新 body 重新生成（`node_class` 加入 body）；
  - 新增 Windows 正向量（report snapshot with terminal）与负向量（未知 route token、伪造 0、把代理名/目标塞进 detail、sampling 时间越界、sum≠total、缺映射、controller 只读声明不实等）。
- 未批准前：Windows 遥测只能停留在本地开发/模拟（当前 Go 分支状态），不得接入 center，不得宣称 v1 合规。

## 9. 与 UM-B 切片的映射

| 切片 | 本文件相关工作 |
| --- | --- |
| UM-B1 | `node_class` 与 `terminal` 字段进入 schema/协议库；SQLite 存储与迁移；正负向量回归；不实现 listener |
| UM-B2 | ingest 校验 node_class、terminal payload、隐私/时间/聚合一致性；A/B 映射的 center 端校验；错误码 |
| UM-B3 | Windows Agent 真实采集（R1/R2 决策后）、服务化、凭据存储；Linux Agent；双平台一致性 |
| UM-B4 | event/node 管理、route 映射配置、审计；不实现 Web UI |
| UM-D | UNKNOWN/UNAVAILABLE/STALE 与“当前选路 vs 实际连接”同视图展示 |
| UM-E | 真实 Clash Verge Rev/Mihomo 联调、只读/HA 断言、隐私 sentinel、故障注入 |

## 10. 未决 Owner 决策（本文件相关）

| ID | 决策 | 建议 | 状态 |
| --- | --- | --- | --- |
| OD-P1 | 是否接受 `node_class` 必填枚举（linux_vps / windows_terminal）及 OS 一致性校验 | 接受 | PENDING |
| OD-P2 | Windows 选路/连接聚合是否纳入首版（与 #127 目标一致） | 纳入 | PENDING |
| OD-P3 | Controller 凭据残余风险：接受 R1（含缓解集）还是先做 R2 调研 | 先调研 R2，R1 兜底 | PENDING |
| OD-P4 | A/B ↔ 中心 VPS ID 映射由 center 管理面配置，Agent 只报 token | 接受 | PENDING |
| OD-P5 | `stale_after_s` 默认值与 metrics 是否首版纳入 | `max(180,3×cadence)`；metrics 可选 | PENDING |
| OD-P6 | 隐私 allowlist 增补（token/计数/时间戳；禁止版本号或仅允许受控版本号） | 默认不上报版本 | PENDING |
| OD-P7 | Windows Agent 运行账户与 secret 存储方式（DPAPI/服务账户/用户会话） | UM-B3 给出 ADR 后 Owner 确认 | PENDING |
| OD-P8 | 是否将 `terminal` 放在 `report-snapshot` 可选对象（而不是新 report type） | 是 | PENDING |

以上与 `05-owner-decisions.md` 统一登记，全部 PENDING，不得写成 APPROVED。
