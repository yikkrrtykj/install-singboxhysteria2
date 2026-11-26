# UM-127 02 — Linux VPS / Windows 终端双平台节点契约（最终契约 rev-5）

- 状态：**FINAL（已冻结进 PR #126 rev-5）**。本文是 #128 规划侧的契约说明；规范性文本以 #126 `docs/um/um-a/04-node-protocol-v1.md` 与 `contracts/v1/**` 为准。
- 基线：[PR #126](https://github.com/yikkrrtykj/install-singboxhysteria2/pull/126) HEAD `048fc170`（tree `1b726de9…`），UM-A revision 5。
- 独立审查、Owner 合并授权、生产部署仍单独进行；本文不构成授权。

## 1. 节点类别与注册绑定

| `node_class` | 适用对象 | 允许的遥测 | 禁止 |
| --- | --- | --- | --- |
| `linux_vps` | 赛事 VPS | base snapshot（system/services/protocols/traffic/clients）、metrics、events；sing-box/Reality/Hysteria2 聚合 | `terminal` 对象；跨类 event kind |
| `windows_terminal` | 赛事 Windows 终端 | snapshot 的 `terminal` 对象（六路径 selection/active_connections）、Windows events；不含 metrics（v1） | server fields 非 unavailable 状态；Linux event kind；本地代理名/私有 YAML/凭据 |

- admin 创建一次性 bootstrap token 时绑定 `{event_id, node_class, expires_at, max_uses=1}`；注册请求的 `node_class` 必须与 token scope 一致（否则 `token_scope_mismatch`），且与 `host.os` 一致（否则 `invalid_request`）。注册事务固化 `node_id`/event/class，不可由 agent 修改。
- 类别改变 = admin 吊销 + 重新注册（新 node_id）；不存在 agent 自选 event/class 或跨类迁移。
- center 在存储前执行平台隔离：Linux 发 terminal → `platform_mismatch`；Windows 缺 terminal（在 source 已配置时）或发 server 字段/Windows 之外的 body → `platform_mismatch`；Windows 发 `report-metrics` → `platform_mismatch`。
- `agent-config` 按类下发 `collect` 开关（`system/services/singbox_api/mihomo_api/terminal/events`）与（Linux）`expected_inbound_tags`；Windows 的 expected tags 为空。**本地 route bindings 是 Windows 主机上的 operator-local 文件，不由 center 下发、不上传、center 不持有代理名称**。

## 2. Windows 六路径（不得简化为 A/B）

| Token | 含义 | center 聚合 |
| --- | --- | --- |
| `a_reality` | A 路径，Reality | A |
| `a_hy2` | A 路径，Hysteria2 | A |
| `b_reality` | B 路径，Reality | B |
| `b_hy2` | B 路径，Hysteria2 | B |
| `direct` | 显式本地绑定的直连路径 | DIRECT |
| `unknown` | 观测到但无法归属 | UNKNOWN |

- token 命名与现有 `um/internal/windowsobs` 的 `Role` 枚举一致（`a_reality/a_hy2/b_reality/b_hy2`），新增 `direct`/`unknown`；**只保留这一套枚举**，不得在 center/agent 再造别名枚举。
- center 展示 A = `{a_reality,a_hy2}`、B = `{b_reality,b_hy2}` 汇总，并可按 Reality/Hysteria2 下钻；不把六路径压成 A/B 后丢失协议维度。
- `direct` 只有在 Windows 主机的 operator-local binding 明确把该路径映射为 direct 时才能上报；未映射/歧义一律 `unknown`/null，**绝不自动 DIRECT**。center 无法也不应解析本地名称。

### 2.1 snapshot 的 `terminal` 对象（rev-5 schema）

```json
{
  "terminal": {
    "selection": {
      "availability": "ok|partial|unavailable",
      "sampled_at": 1795622398,
      "route": "a_reality|a_hy2|b_reality|b_hy2|direct|unknown|null",
      "reason_code": "controller_unreachable|controller_auth|malformed_response|route_unbound|source_authorization_unproven|null"
    },
    "active_connections": {
      "availability": "ok|partial|unavailable",
      "sampled_at": 1795622399,
      "total": 42,
      "by_route": {"a_reality":20,"a_hy2":5,"b_reality":10,"b_hy2":2,"direct":3,"unknown":2}
    }
  }
}
```

规则（规范性见 #126 `04` §9.2 / `report-snapshot.schema.json`）：

1. `selection` 与 `active_connections` **独立采样**，各自带 `sampled_at`，允许不同；两者都必须在 `[collected_at−300 s, collected_at+60 s]` 内。
2. 每一条在管连接恰好归入一个 token；`availability=ok` 时 `total == sum(六项)` 且六项、route 均非 null；`unavailable` 全 null；`partial` 至少一个 null。合法空连接列表是 0；缺失/畸形响应是 unknown/unavailable，绝不写 0。
3. A/B 切换后旧连接可能仍在旧路径：`selection` 与 `by_route` 不一致是正常状态，不是错误。
4. 隐私：不上传原始连接目标/源 IP/URL/进程名/连接 ID/代理名/私有 YAML/controller secret；schema 无自由文本字段，sentinel 命中拒绝并审计（值不落日志/响应/存储）。
5. Windows 事件闭合为 `terminal_route_changed`、`terminal_source_unavailable`（detail 只含 token/时间/原因码；R2 只读源用 `source=local_readonly`，R1 controller 用 `mihomo_api`）。

## 3. 版本化 A/B ↔ 中心 VPS ID 映射

- 映射是 center 管理面元数据（UM-B4），版本化且 **append-only**：
  `route_mapping_versions{event_id, windows_node_id, version, effective_from, six-token→linux_vps_node_id, created_by, created_at}`；只能映射到**同一 event 的已注册 linux_vps 节点**。
- 上报只带 token，不带 VPS ID。历史归属按 `effective_from ≤ sample/event time < 下一版本 effective_from` 的版本解析；**新版本不重写历史样本**；旧版本不得 UPDATE/DELETE（事件 purge 除外）。未映射 token 显示“未映射/UNKNOWN”，不猜测。
- 映射变更审计；A/B 汇总与协议下钻在展示层（UM-D）完成。

## 4. 数据源与 R2/R1（关键）

- **事实**：Mihomo/Clash Verge Rev 的 external controller 凭据不是只读的。官方 API 含 `PUT/PATCH /configs`、`POST /restart`、`POST /upgrade`、`PUT/DELETE /proxies`、`PUT providers`、`PATCH /rules/disable`、`DELETE /connections` 等写操作。<https://wiki.metacubex.one/en/api/>；Clash Verge Rev 需用户手动开启并自担风险 <https://github.com/clash-verge-rev/clash-verge-rev/discussions/6951>。
- **结论**：GET-only client 是实现约束，不是授权证明；不得宣称“controller 凭据是只读的”。任何“只读平台”表述必须限定为“write-capable credential used by a read-only client”。
- **R2（优先）**：调研真正只读的本地数据源（不持有 controller secret，例如经验证的本地只读导出/日志面）；若可行则作为 Windows 遥测源，`source=local_readonly`。
- **R1（后置，单独 Owner 接受）**：仅当 R2 不可行，才提交 R1 残余风险方案：loopback-only、专用 secret（DPAPI/私有 ACL）、非管理员 agent、GET+固定 path 白名单、无 redirect/proxy env/DNS、静态+运行时“无写方法”测试、版本审计、负例；Owner 单独接受后才可启用，**绝不自动启用**。
- `collect.terminal`/`mihomo_api` 默认 **false**；源未授权/未证明时 `terminal.availability=unavailable` + `reason_code=source_authorization_unproven`，不伪造数据。
- **只读/HA**：Windows agent 不修改 Mihomo/Clash Verge Rev 配置、不切换节点、不关闭连接、不改变 HA-UI/P6/#67 行为；UM-E 用真实 Clash Verge Rev/Mihomo 验证采集前后配置 hash、当前选路、连接关闭请求均不被 Agent 改变。

## 5. 与 rev-5 其他契约的关系

- 共享：独立 Ed25519 身份、enrollment/rotation/revocation、nonce/seq/boot-gen 防重放、`report_id` 幂等、spool/补传/新鲜度、`synchronous=FULL` 事务、ACK 语义。
- 数值/存储：`boot_gen`/`seq` canonical decimal `1..9223372036854775806`；SQLite signed INTEGER + CHECK；`next_seq:null` 表示 generation 耗尽；generation 跳号 `MAX_BOOT_GAP=65535` 且 gap>1 审计。
- 恢复：A-1..A-5 见 [03](03-recovery-semantics.md) 与 #126 `04` §5–§6.4；REC-01..REC-30 是 UM-B1/B2/B3 的规范性输入。
- Windows observer：`um/internal/windowsobs` 仍是**实验组件**；rev-5 的六 token 与它对齐，但 Windows agent 服务化/R2/R1/真实联调属于 UM-B3/UM-E，不提前服务化、不接入生产。

## 6. 变更控制

- 六路径、terminal schema、平台隔离、映射版本、R2/R1 已冻结在 #126 rev-5；如无独立 review/owner 授权，不得在 UM-B 实现中简化（例如退化为 A/B、删除 direct/unknown、把 unmapped 当 direct、把 center 映射改成可变行）。
- 任何契约变化需新的 amendment：文档 + schema + 正负向量 + 历史追溯 + 独立审查。
