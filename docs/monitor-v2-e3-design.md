# Monitor v2 — Phase E3 Design: Web Client Manager（架构设计，不含实现）

状态：**设计稿（待 review）**。本文档只做架构 / API contract / 安全模型 / 事务流程设计，
**不包含任何生产配置修改、不包含任何 client mutation 实现**。E2 Web Dashboard 由另一条
分支实现；E1 collector（`monitor-v2/`）与 Phase C/D 代码在 E3 落地前一律不动。

前置事实（与现有代码一一对应，均已在仓库中核实）：

| 事实 | 出处 |
| --- | --- |
| 服务端单一事实源 `/root/sbox/sbconfig_server.json`；`/root/sbox/clients/` 全部是派生物 | `install.sh`（`SB_SERVER_CONFIG` / `SB_CLIENTS_DIR` 注释） |
| 事务核心：`flock → 结构审计 → candidate → sing-box check → backup → 原子 mv → reload → 健康检查 → 失败回滚` | `install.sh` `commit_server_config` / `with_client_lock` |
| phase-c 客户端管理块可整体 source（测试即用此机制），所有路径经 `SB_*` 环境变量覆盖 | `install.sh:670-1378` 的 `# >>> phase-c client-management >>>` 标记；`tests/test-phase-c.sh` |
| 客户端命名 `^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`；`legacy` 是保留名 | `install.sh` `CLIENT_NAME_PATTERN` / `RESERVED_CLIENT_NAME` |
| Monitor 身份：`Device = API USER`（`user.name`），不可变 | `monitor-v2/README.md`、`monitor-v2/collector.py` 模块注释 |
| `service.api` 仅监听 `127.0.0.1:9091`，不向公网开放 | 根 `README.md` |
| `rotate` 目前不存在（install.sh 全文 0 处），属于 E3 新增 | `grep -c rotate install.sh == 0` |
| YAML 代理显示名当前为固定的 `Reality` / `Hysteria2` | `install.sh` `write_mihomo_template` |

---

## 0. 目标 UX 与身份链（一条主线，贯穿全文）

```text
Web Dashboard
  → Clients
  → Add Client
      Name: vmix-01
      [x] Reality   [x] HY2
  → Create
  → Download Mihomo YAML
```

身份链（唯一权威在服务端配置，其余全部是派生物）：

```text
POST /api/v1/clients {"name":"vmix-01","reality":true,"hy2":true}
  └─ 服务端（唯一身份写入点，Phase C 事务内完成）
       vless-in.users += { "name": "vmix-01", "uuid": "UUID-A", "flow": "xtls-rprx-vision" }
       hy2-in.users   += { "name": "vmix-01", "password": "PASS-A" }
  └─ Monitor 身份（E1，天然成立，零额外代码）
       Device = API USER = "vmix-01"（Reality 与 HY2 的流量自动聚合到同一设备）
  └─ Mihomo YAML（本地显示名，仅展示用，对 Monitor 身份零影响）
       proxies:
         - name: vmix-01-Reality     # ← 仅客户端 UI 里的显示名
         - name: vmix-01-HY2         # ← 仅客户端 UI 里的显示名
```

硬性规则：

1. **真实身份只来自服务端 `user.name`**。YAML 里的 `vmix-01-Reality` / `vmix-01-HY2`
   是代理条目的本地显示名，改显示名、改 YAML 排序都不影响 Monitor 归属。
2. **Web 层永远不直接 `open(...sbconfig_server.json)`**，也不手改 JSON。Web 层对
   服务端配置文件连读权限都没有（见 §2 权限分离）。
3. 所有服务端变更必须复用 Phase C 事务模型（§4），任何绕过事务的写入路径都不允许存在。
4. `legacy` 永远是 reserved client（§7.4）。
5. whitelist / admin password / recovery key 属于 E2 认证体系，它们的任何变化
   **不得影响**现有 Reality/HY2 YAML（§8.5）。

---

## 1. 架构（Architecture）

### 1.1 分层与信任边界

```text
┌────────────────────────────────────────────────────────────────────┐
│ Browser（管理员）                                                    │
│   Clients 列表 / Add Client 弹窗 / 危险操作 danger-zone / Download  │
└───────────────┬────────────────────────────────────────────────────┘
                │ HTTP（仅 127.0.0.1；远程访问 = SSH 隧道，不开公网端口）
┌───────────────▼────────────────────────────────────────────────────┐
│ 边界 A：E2 Web Dashboard 进程（E3 只定义接口，不实现）                │
│   · 运行用户：sboxweb（非特权，无 /root/sbox 任何读写权）             │
│   · 认证 / 会话 / CSRF / 限流 / Web 侧审计（E2 提供，见 §8 接口）     │
│   · HTTP ↔ JSON contract（§3）                                      │
│   · 进程内绝不保存、绝不记录任何 UUID/password                       │
└───────────────┬────────────────────────────────────────────────────┘
                │ 唯一通道：sudo 调用固定 verb 二进制，stdin/stdout JSON（§4.2）
┌───────────────▼────────────────────────────────────────────────────┐
│ 边界 B：E3 特权 Client Manager（短命 root 进程，E3 的核心交付物）     │
│   · 再次校验 verb + name（不信任调用方）                              │
│   · source phase-c 块（install.sh:670-1378，SB_* 环境变量可覆盖）     │
│   · flock /root/sbox/config.lock（与 mianyang CLI 菜单同一把锁）      │
│   · 输出：JSON 结果 + 退出码；追加 JSONL 审计（§8.4）                 │
│   · 这是唯一能读/写 sbconfig_server.json、SB_STATE_FILE 的 Web 链路  │
└───────────────┬────────────────────────────────────────────────────┘
┌───────────────▼────────────────────────────────────────────────────┐
│ Phase C 事务核心（原样复用，禁止旁路）                                │
│   with_client_lock → candidate_problems → sing-box check →          │
│   backup → atomic mv → reload → reload_health_ok → rollback         │
└───────────────┬────────────────────────────────────────────────────┘
                │
   /root/sbox/sbconfig_server.json   ← 唯一事实源（user.name = Monitor 身份）
   /root/sbox/clients/<name>/mihomo.yaml ← 派生物，可随时再生（0700/0600）
   /root/sbox/config.lock            ← 与 CLI 菜单共享的同一把 flock
   （E1 collector 走 127.0.0.1:9091 service.api，与 E3 完全解耦、互不感知）
```

### 1.2 设计决策与理由

* **D1 特权分离：Web 进程非特权，特权 helper 独立短命进程。**
  即使 Web 层被攻破，攻击者也拿不到任意文件读写，只能触发固定的 5 个 verb。
  residual risk 在 §9.4 明示。
* **D2 事务逻辑只有一份：Phase C 块本身。** helper 通过 source phase-c 块调用
  `with_client_lock` / `commit_server_config` / `_add_client_locked` /
  `_delete_client_locked`（与 `tests/test-phase-c.sh` 同一机制）。E3 在 phase-c 块内
  新增 `rotate_client`，CLI 菜单与 Web 自动共享同一实现，杜绝两套事务逻辑漂移。
* **D3 verb 独立二进制 + sudoers 白名单。** `sbox-cm-add` / `sbox-cm-delete` /
  `sbox-cm-rotate` / `sbox-cm-export` / `sbox-cm-list` 各自是独立入口（薄封装同一
  Python 库），sudoers 逐条白名单且 argv 为空（参数经 stdin JSON 传入），
  sudo 日志天然记录"哪个 verb 被谁调用"。
* **D4 注册表（registry）只是顾问性元数据。** `created_at` / `rotated_at` /
  `credential_version` / actor 存在 `/root/sbox/web/client-registry.json`（helper
  维护，0600）。列表永远以 **live 配置**为准（CLI 创建的客户端自动出现在 Web 里），
  注册表仅补充时间线；两者漂移时以配置为准并在响应中如实标注（§6.3）。
* **D5 不采用 Clash REST 的配置修改模型。** 参考 s-ui / 3x-ui / metacubexd /
  yacd 的展示与 danger-zone 交互，但拒绝 Clash `PUT/PATCH /configs` 式的
  "HTTP 直接改配置"：所有变更必须穿过 §4 事务。

### 1.3 组件清单（E3 新增，全部待实现，本轮零实现）

```text
monitor-v2/client_manager/
  __init__.py
  protocol.py        # stdin/stdout JSON 请求-响应协议 + 错误码表（§4.2）
  names.py           # validate_client_name（与 Phase C 正则逐字一致）+ reserved 集合
  audit.py           # 读写 candidate_problems 结果、结构审计桥接（fail-closed）
  transactions.py    # add/delete/rotate：source phase-c 块、构造 candidate、调 commit_server_config
  yaml_export.py     # 派生 YAML 再生 + 陈旧检测（credential_version 头）+ 流式导出
  registry.py        # 顾问性元数据（可选，损坏/缺失时静默降级）
  auditlog.py        # JSONL 特权审计（§8.4）
  cli.py             # sbox-cm-* 五个入口的薄分发

install.sh           # phase-c 块内新增 rotate_client / _rotate_client_locked（E3-0）
tests/test-phase-e3.sh
```

---

## 2. 权限与文件边界（security boundary 的静态部分）

| 路径 |属主/权限 | Web 进程 | helper | 说明 |
| --- | --- | --- | --- | --- |
| `/root/sbox/sbconfig_server.json` | root 0600 | **无任何权限** | 读写 | 唯一事实源；只允许被事务改写 |
| `/root/sbox/config`（SB_STATE_FILE） | root 0600 | 无 | 读 | SERVER_IP / PUBLIC_KEY / HY_SERVER_NAME / 跳端口区间 |
| `/root/sbox/clients/<name>/` | root 0700 | 无 | 读写 | 派生 YAML，可随时再生 |
| `/root/sbox/config.lock` | root | 无 | flock | 唯一互斥点，与 CLI 共享 |
| `/root/sbox/web/client-registry.json` | root 0600 | 无 | 读写 | 顾问元数据 |
| `/root/sbox/web/audit/cm.jsonl` | root 0600 | 无（append 由 helper） | 追加 | 特权审计（§8.4） |
| E2 会话/认证存储（admin password hash、recovery key、whitelist） | E2 自有 | 读写 | **不读不写** | 与 YAML 生成完全隔离（§8.5） |

sudoers（逐 verb 白名单，argv 固定为空，参数走 stdin）：

```text
sboxweb ALL=(root) NOPASSWD: /usr/local/lib/sbox-cm/sbox-cm-list
sboxweb ALL=(root) NOPASSWD: /usr/local/lib/sbox-cm/sbox-cm-add
sboxweb ALL=(root) NOPASSWD: /usr/local/lib/sbox-cm/sbox-cm-delete
sboxweb ALL=(root) NOPASSWD: /usr/local/lib/sbox-cm/sbox-cm-rotate
sboxweb ALL=(root) NOPASSWD: /usr/local/lib/sbox-cm/sbox-cm-export
```

网络边界：Dashboard 仅绑定 `127.0.0.1`（具体端口归 E2）；远程使用一律 SSH 隧道；
**E3 不新增任何公网监听**，与 service.api 的 loopback 原则一致。

---

## 3. HTTP API contract

通用约定：

* 前缀 `/api/v1`；所有请求/响应 body 为 `application/json; charset=utf-8`
  （YAML 下载除外）。拒绝 `application/x-www-form-urlencoded` / `multipart`（415）。
* 所有响应带 `X-Request-Id`（与 helper `request_id`、审计日志、Web 审计四方可关联）。
* 错误响应统一形状：

```json
{ "error": { "code": "duplicate_name", "message": "client 'vmix-01' already exists",
             "detail": { "stage": "pre_lock" } } }
```

* 错误码 → HTTP 映射表（§3.7）。**任何成功响应、错误响应、日志中都绝不出现
  UUID / password / private key / 完整 sing-box config**（例外见 §3.3 导出）。

### 3.1 GET /api/v1/clients

```json
// 200
{ "clients": [
    { "name": "vmix-01", "protocols": ["reality", "hy2"], "reserved": false,
      "mutable": true, "yaml_available": true,
      "created_at": "2026-09-12T10:00:00Z", "rotated_at": null,
      "credential_version": 1, "source": "web" },
    { "name": "legacy", "protocols": ["reality", "hy2"], "reserved": true,
      "mutable": false, "yaml_available": false,
      "created_at": null, "rotated_at": null,
      "credential_version": null, "source": "cli" }
] }
```

* 列表来自 **live 配置**（helper `list` verb：锁内读两个 inbound 的 name 集合并集 +
  一致性审计结果），注册表仅补充 `created_at/rotated_at/credential_version/source`；
  注册表缺失/损坏时这些字段为 `null`，列表功能不受影响（D4）。
* `source`: `"web"`（注册表可追溯）| `"cli"`（配置里有但注册表无 —— mianyang 菜单
  创建的客户端自动可见，这是"以配置为准"的直接收益）。
* 服务端一致性审计失败时不隐藏真相：`200` + 顶层 `consistency_problems: [...]`
  （只读照实呈现），写操作会被事务拒绝（§6.5）。

### 3.2 GET /api/v1/clients/{name}

```json
// 200
{ "name": "vmix-01", "protocols": ["reality", "hy2"], "reserved": false,
  "mutable": true, "yaml_available": true, "created_at": "...",
  "rotated_at": null, "credential_version": 1, "source": "web" }
// 404 { "error": { "code": "client_not_found" } }
```

### 3.3 GET /api/v1/clients/{name}/mihomo.yaml（唯一允许携带凭据的端点）

```text
GET /api/v1/clients/vmix-01/mihomo.yaml
→ 200 text/yaml; charset=utf-8
   Content-Disposition: attachment; filename="vmix-01-mihomo.yaml"
   Cache-Control: no-store
   X-Content-Type-Options: nosniff
   X-Credential-Version: 1
```

* **响应体本身就是凭据容器**（Reality uuid + HY2 password 在 YAML 内），因此：
  1. 必须带 CSRF 同源头（`X-CSRF-Token`，与变更操作同一 token）才返回 200，
     否则 403 —— 防止跨站 `<a href>` / `<img>` drive-by 拉取；
  2. `no-store` + `attachment` + `nosniff`；不进任何代理/浏览器缓存；
  3. 审计记录"谁在何时导出了谁的 YAML + 字节数"，**不记录内容**（§8.4）。
* 语义：**派生物物化，不是配置变更**。helper 在锁内核对
  `credential_version`（YAML 头注释 vs 注册表），缺失或过期就先再生再流式返回；
  再生失败 → `409 yaml_unavailable`（响应体内绝无半份 YAML）。
* `legacy` → `403 reserved_client`（v1 决策：不通过 Web 导出共享账号凭据；
  服务器上手工操作路径保持不变。见 §10 未决 D-1）。

### 3.4 POST /api/v1/clients（Create）

请求（与任务书逐字一致）：

```json
{ "name": "vmix-01", "reality": true, "hy2": true }
```

成功（与任务书逐字一致）：

```json
// 201
{ "name": "vmix-01", "protocols": ["reality", "hy2"], "yaml_available": true }
```

约束与错误：

| 条件 | 结果 |
| --- | --- |
| `reality` / `hy2` 不同时为 true | `422 protocol_set_unsupported`。Phase C 一致性审计要求两个 inbound 的 name 集合完全一致，单协议客户端会永久破坏该不变量，v1 明确不支持（§10 未决 D-3） |
| name 不匹配 `^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$` | `422 invalid_name`（message 中回显该正则） |
| name == `legacy` | `422 reserved_name` |
| name 已存在（任一 inbound） | `409 duplicate_name`（锁内以 live 配置复核后判定） |
| 请求体不是合法 JSON / 缺字段 | `400 malformed_body` |

`yaml_available` 语义：提交后 helper 尝试物化派生 YAML；**服务端配置提交成功但 YAML
物化失败时仍返回 201 + `yaml_available:false` + 顶层 `warnings:["yaml_generation_failed"]`**
（§6.6 部分失败）。客户端本体（Monitor 身份 + 凭据）已生效。

### 3.5 POST /api/v1/clients/{name}/rotate（危险操作）

```json
// 请求（显式确认：逐字回显客户端名）
{ "confirm": "vmix-01" }
// 头：X-CSRF-Token: …；会话须在 300s 内完成过 step-up 重认证（§8.2）
// 可选：Idempotency-Key: <uuid4>（强烈建议，UI 必须带；见 §6.9）
// 200
{ "name": "vmix-01", "protocols": ["reality", "hy2"], "yaml_available": true,
  "rotated_at": "2026-09-12T11:00:00Z", "credential_version": 2,
  "yaml_invalidated": true,
  "warning": "旧 YAML 与旧凭据已立即失效，所有使用旧 YAML 的设备将断线，必须重新下载" }
```

* 同一事务内替换 Reality UUID 与 HY2 password（两者永远成对轮换，§10 未决 D-3）；
  `user.name` 不变 → **Monitor 身份无缝延续**（E1 的 Device 不感知 rotate）。
* `confirm` 字段与 `{name}` 不一致 → `400 confirm_mismatch`；缺 step-up →
  `401 reauth_required`；旧 YAML 语义上作废，`yaml_invalidated:true` + `warning`
  是 Web UI 必须显著提示的硬性契约（§7.2）。

### 3.6 DELETE /api/v1/clients/{name}（危险操作）

```json
// 请求：同 rotate（confirm 逐字回显 + CSRF + step-up）
{ "confirm": "vmix-01" }
// 200
{ "name": "vmix-01", "deleted": true,
  "warning": "已从 Reality 与 HY2 同时移除；该设备的 Monitor 流量统计随 E1 进程生命周期结束" }
```

* 语义与 Phase C `_delete_client_locked` 逐条一致：先服务端事务提交，成功后
  才删除派生目录；回滚路径上派生目录必须原样保留（"服务端修改失败，客户端配置目录
  保持不变"）。
* 删除后：该 `user.name` 从两个 inbound 消失 → E1 不再收到该设备的新连接；
  E1 无数据库，历史计数随 collector 进程生命周期结束（响应 `warning` 如实说明）。
* `legacy` → `403 reserved_client`。

### 3.7 错误码总表

| HTTP | error.code | 阶段 | 语义 |
| --- | --- | --- | --- |
| 400 | `malformed_body` | 请求解析 | JSON 非法/缺字段 |
| 400 | `confirm_mismatch` | 危险操作 | `confirm` ≠ 路径中的 name |
| 401 | `unauthenticated` | 中间件 | 未登录 |
| 401 | `reauth_required` | step-up | 距上次重认证 > 300s（§8.2） |
| 403 | `csrf_failed` | 中间件 | token 缺失/不匹配/Origin 非法 |
| 403 | `forbidden` | 授权 | 角色不足（v1 只有 admin，理论不可达） |
| 403 | `reserved_client` | helper+Web 双层 | 对 legacy 的 rotate/delete/export |
| 404 | `client_not_found` | helper | 锁内以 live 配置复核后不存在 |
| 409 | `duplicate_name` | 锁内复核 | 已存在（任一 inbound） |
| 409 | `config_inconsistent` | 事务前置审计 | Reality/HY2 集合不一致等，拒绝一切写 |
| 409 | `yaml_unavailable` | 导出 | 派生 YAML 缺失且再生失败 |
| 415 | `unsupported_media_type` | 中间件 | 非 application/json 写请求 |
| 422 | `invalid_name` / `reserved_name` / `protocol_set_unsupported` | 校验 | §3.4 表 |
| 422 | `idempotency_conflict` | rotate | 同 key 不同请求体（§6.9） |
| 423 | `lock_busy` | flock | 锁等待超时（§6.7） |
| 429 | `rate_limited` | 中间件 | 变更限流 |
| 500 | `internal` | 未分类 | 附 request_id 排查 |
| 500 | `candidate_rejected` | 审计/check | candidate 被审计或 `sing-box check` 拒绝（磁盘未动） |
| 500 | `commit_failed` | 备份/原子替换 | mv/备份失败（磁盘未动或已保留备份） |
| 503 | `commit_rolled_back` | reload/健康 | 提交后失败 → 已自动回滚，**服务已恢复** |
| 500 | `rollback_manual_intervention` | 回滚 | 回滚后仍未确认恢复，**需人工**（CRITICAL 审计） |

> `503 commit_rolled_back` 特意区别于 5xx 其他码：对管理员它意味着"失败但系统是好的，
> 可以重试"；`500 rollback_manual_intervention` 意味着"别再点重试，去看服务器"。

---

## 4. Phase C 事务桥（transaction boundary）

### 4.1 原则：一条通道、一套事务、零旁路

* 服务端配置的全部合法写路径 = `with_client_lock` + `commit_server_config`。
  E3 不新增任何并行事务实现；`rotate` 作为 **phase-c 块内的新函数**（E3-0）进入同一块，
  自动获得同一把锁、同一审计、同一回滚语义，且 mianyang CLI 菜单同步可用。
* Web 层被权限模型物理排除在事务之外（§2：无读权限），"禁止 Web 手改 JSON"
  不靠纪律，靠操作系统权限。
* 读也过锁（§6.8）：helper 的所有 verb（含 list/export）都短暂持有排他锁，
  保证导出/列表读到的 uuid-password 对永不撕裂。

### 4.2 helper JSON 协议（进程边界，stdin → stdout）

```json
// stdin（sudoers 下 argv 为空，全部经 stdin；name 在 helper 内再次过 §3.4 正则）
{ "request_id": "b7c9…", "actor": "web-session:a1f3…", "verb": "add", "name": "vmix-01" }
// stdout
{ "ok": true, "data": { "name": "vmix-01", "yaml_available": true,
                        "credential_version": 1 } }
// 或
{ "ok": false,
  "error": { "code": "commit_rolled_back", "stage": "reload",
             "detail": "reload 后健康检查失败，已自动回滚", "backup": "/root/sbox/sbconfig_server.json.bak.20260912-110000.XXXXXX" } }
```

退出码：`0` 成功；`2` 校验失败；`3` 冲突（duplicate/reserved/not_found/inconsistent）；
`4` 锁超时；`5` candidate 被拒（未触盘）；`6` 提交后回滚成功；`7` 回滚需人工；
`8` 导出不可用；`10` 内部错误。HTTP 映射由 Web 适配层按 §3.7 完成。

`stage` 枚举与 `commit_server_config` 的阶段一一对应：
`pre_lock | audit | candidate | check | backup | replace | reload | health |
rollback | rollback_manual | yaml_gen`。

### 4.3 add 事务流程（Create，逐阶段）

```text
0  pre_lock   helper 重校验 verb/name/正则/reserved/参数形状（不信任 Web）
1  lock       flock config.lock（-w 超时 → exit 4）
2  live 复核  【锁内】文件存在 → JSON 合法 → 一致性审计（candidate_problems，
              fail-closed）→ client_name_exists 双向复核
3  creds      sing-box generate uuid；sing-box generate rand --hex 16
              （与 Phase C 同源；凭据从不来自请求体）
4  candidate  jq 同时向 vless-in / hy2-in 追加 {name, uuid, flow} / {name, password}
              （Reality+HY2 原子出现，否则一起不出现）
5  commit     = Phase C commit_server_config：
              审计 candidate → sing-box check → 记录 was_running → 备份 →
              原子 mv → reload（systemctl reload | kill -HUP）→ sleep 1 健康检查
              └ 任一失败：按 §6.4 回滚矩阵处理
6  yaml_gen   【锁内，提交成功后】物化 /root/sbox/clients/<name>/mihomo.yaml
              （0700/0600，代理显示名 ${name}-Reality / ${name}-HY2，带
              credential_version 头注释）；失败不回滚服务端 → yaml_available:false
7  registry   写入 created_at / credential_version=1 / source=web（失败静默降级）
8  audit      JSONL 追加（§8.4），释放锁
```

### 4.4 delete 事务流程

```text
0  pre_lock   reserved 复核（legacy 硬拒）
1  lock       flock
2  live 复核  一致性审计（不一致 → 禁止一切破坏性操作，与 Phase C 同）；
              双 inbound 同时存在才允许删（缺一 → 409 config_inconsistent 引导先修复）
3  candidate  jq 从两个 inbound 同时 map(select(.name != $name))
4  commit     commit_server_config（失败 → §6.4，派生目录保持不动）
5  派生物     仅在提交成功后 rm -rf /root/sbox/clients/<name> + 注册表条目
6  audit      JSONL
```

### 4.5 rotate 事务流程（E3-0 新增 `rotate_client` / `_rotate_client_locked`）

```text
0  pre_lock   reserved 复核（legacy 硬拒）
1  lock       flock
2  live 复核  一致性审计 + 双 inbound 同时存在
3  creds      生成新 UUID-A' 与 password-A'（断言 != 旧值）
4  candidate  jq 原地替换该 name 的 .uuid（vless-in）与 .password（hy2-in）；
              name / flow / 其他用户零改动
5  commit     commit_server_config "rotate client <name>"
              └ reload/健康失败 → 回滚 → 新旧凭据都未生效，重试安全（§6.4 R2）
6  yaml_gen   【锁内】再生派生 YAML（credential_version+1 写入头注释）；
              失败 → 服务端新凭据已生效、磁盘 YAML 陈旧 → 后续 export 自愈/409（§3.3）
7  registry   rotated_at / credential_version+=1
8  audit      JSONL（只记"已轮换"，永不记新旧凭据值）
```

### 4.6 export 流程（GET mihomo.yaml 背后）

```text
0  lock（短暂持有，防止撕裂读：uuid 与 password 必须来自同一份配置快照）
1  live 复核：双 inbound 存在 + 一致性审计
2  get_client_credentials（Phase C 原函数）
3  陈旧检测：注册表 credential_version vs 派生 YAML 头注释
    ├ 匹配且文件存在 → 直接流式返回
    ├ 缺失/不匹配   → 锁内再生（write_mihomo_template + 临时文件 + mv）后返回
    └ 再生失败      → 409 yaml_unavailable
4  audit（name + 字节数，无内容）
```

---

## 5. 凭据处理（credential handling）

```text
生成：sing-box generate uuid / generate rand --hex 16（Phase C 同源；请求体永不携带凭据）
存在：sbconfig_server.json（事实源）；clients/<name>/mihomo.yaml（派生）；
      helper 与 Web 进程内存中的瞬态（请求结束即释放）
禁止：任何 API 响应（除 §3.3 导出）、任何日志（Web 审计 / helper 审计 / stderr）、
      注册表、会话存储、错误 detail、浏览器缓存
传输：Web↔helper 走本机 stdin/stdout 管道；Browser↔Web 走 127.0.0.1（明文 HTTP
      仅限回环，配合 no-store；SSH 隧道端到端加密）
```

硬性卫生断言（写进测试矩阵 E3-T16）：对**所有** API 响应与两份审计日志做正则扫描
（UUID 形状、`uuid:`、`password:`、`private`、`private_key`、inbound JSON 片段），
命中即构建失败。API 永不返回 private key —— Reality 私钥根本不在任何 API 路径上
（它只存在于服务端配置与 `SB_STATE_FILE`，Web 无读权限）。

---

## 6. 专项详细设计

### 6.1 Create — 见 §4.3；错误路径全落 §3.7；响应字段与任务书逐字一致。

### 6.2 Delete — 见 §4.4；危险操作 UX 契约见 §7.3。

### 6.3 Duplicate name

* 请求侧：锁内 `client_name_exists` 以 live 配置复核（Phase C 原语义：任一 inbound
  命中即拒绝）→ `409 duplicate_name`，服务端配置字节不变。
* Web 侧可选预检（减少无谓的 sudo 调用）不算权威，**判定永远在锁内**。

### 6.4 Partial failure / Reload failure / Health failure / Rollback（矩阵）

| # | 失败点 | 磁盘状态 | 服务状态 | helper | HTTP | 后续 |
| --- | --- | --- | --- | --- | --- | --- |
| F1 | name/形状/reserved（pre_lock） | 不变 | 不变 | exit 2/3 | 422/403 | 无 |
| F2 | 锁超时 | 不变 | 不变 | exit 4 | 423 lock_busy | 用户稍后重试 |
| F3 | live 配置 JSON 非法 / 一致性审计失败 | 不变 | 不变 | exit 3 | 409 config_inconsistent | 先跑 CLI 一致性检查 |
| F4 | candidate 生成失败 / candidate 审计失败 / `sing-box check` 失败 | 不变（candidate 被删，live 未动） | 不变 | exit 5 | 500 candidate_rejected | 附审计问题行；系统完好 |
| F5 | 备份失败 / 原子 mv 失败 | live 不变；备份保留 | 不变 | exit 5 | 500 commit_failed | 系统完好，可重试 |
| F6 | reload 失败 | **已自动回滚**（备份覆盖回 live + 再次 reload） | 已恢复 | exit 6 | **503 commit_rolled_back** | 可安全重试 |
| F7 | 健康检查失败（reload 成功但进程死） | 同 F6 回滚 | 已恢复 | exit 6 | **503 commit_rolled_back** | 可安全重试 |
| F8 | 回滚后再 reload/健康仍失败 | 回滚文件已就位 | **未确认恢复** | exit 7 | 500 rollback_manual_intervention | **禁止盲目重试**，人工按备份恢复；审计 CRITICAL |
| F9 | 提交成功后 yaml_gen 失败 | 服务端已生效 | 正常 | ok + warning | 201 + `yaml_available:false` | 下次 export 自愈（§3.3） |
| F10 | 提交成功后 registry 失败 | 服务端已生效 | 正常 | ok + warning | 201（元数据为 null） | 顾问性，无影响 |
| F11 | export 再生失败 | 不变（可能保留旧派生文件） | 正常 | exit 8 | 409 yaml_unavailable | 重试/人工检查 clients 目录 |

R1：F4–F7 全部复用 `commit_server_config` 现有语义（该函数已实现备份保留、
fail-closed 审计、回滚后二次健康确认），E3 只做错误码映射，不改事务内部。
R2：rotate 的 F6/F7 语义 = "轮换从未发生"（新凭据只存在于被回滚的 candidate 里），
因此 rotate 失败后重试是幂等安全的。
R3：create 的 F6/F7 同理 = "客户端从未存在"；delete 的 F6/F7 = "客户端仍然完整存在，
派生目录保持"（Phase C 原有保证，测试 C 系列已覆盖同类路径）。

### 6.5 Legacy protection（reserved client）

| 操作 | legacy 的结果 |
| --- | --- |
| POST create name=legacy | `422 reserved_name` |
| POST rotate legacy | `403 reserved_client` |
| DELETE legacy | `403 reserved_client` |
| GET 列表/详情 | `200`，`reserved:true, mutable:false`（Monitor 照常显示 legacy 流量） |
| GET legacy/mihomo.yaml | `403 reserved_client`（§10 未决 D-1） |

双层防御：Web 中间件拦截 + helper 内部再次硬校验（镜像 Phase C
`_delete_client_locked` 的锁内二次防护）。`legacy` 的 Retirement 属于未来独立功能，
v1 一律拒绝。CLI 路径能力不变（本设计不收紧既有 CLI 行为）。

### 6.6 Partial failure（服务端成功、派生物失败）

见 F9/F10。原则：**服务端事务边界之内是原子的；边界之外的派生物允许最终一致**。
`yaml_available:false` + `warnings[]` 是契约的一部分，Web UI 需显示降级提示，
且导出路径具备自愈能力。

### 6.7 Concurrent requests

* 互斥点只有一个：`/root/sbox/config.lock` 的 flock，CLI 菜单与 Web 的全部变更
  在操作系统层面串行 —— 两个管理员同时操作、CLI 与 Web 同时操作，都是安全的。
* helper `flock -w 15`（超时 → 423）；Web 适配层再加进程内 semaphore(1) + 30s 上限，
  避免请求堆积。
* **请求内重读原则**（Phase C 原文："every judgement below re-reads the LIVE config"）：
  一切判定（存在性、一致性、reserved）都在锁内对 live 配置重新做出，
  先到的请求胜出，后到的从胜者状态出发，绝不基于陈旧快照写入（no lost update）。
* 并发结果示例：10 个并发 create 同名 → 恰好 1 个 201，其余 409；最终配置合法且
  只有一个该用户（E3-T10）。

### 6.8 读取一致性

`mv` 原子替换保证读者要么看到旧文件要么看到新文件，永远完整。但
"uuid 与 password 分两次 jq 读"可能横跨一次 rotate 提交 → 撕裂读。因此
**export 与 list 同样在锁内执行**（§4.1）；锁持有时间为毫秒级，v1 单管理员场景
无性能顾虑。

### 6.9 Idempotency

| 操作 | 幂等语义 |
| --- | --- |
| GET list / get / export | 天然幂等（export 只是物化派生物，无服务端变更） |
| POST create | 天然"查重幂等"：重复提交同名 → 409，且不产生任何副作用 |
| DELETE | 天然：已删除 → 404，无副作用 |
| POST rotate | **不天然幂等**（每次调用生成新凭据）。要求 UI 携带 `Idempotency-Key`：同一 key 重放 → 返回首次结果（不再轮换）；同 key 不同 body → 422 idempotency_conflict。key 存 Web 进程内存（`(key) → {name, response}`，TTL 24h，重启丢失=降级为可能二次轮换，因此 helper 的 rotate 审计里记录 key 的 sha256 前缀以便事后核对） |

双击防护三件套：Idempotency-Key + confirm 回显 + step-up，缺一不可。

### 6.10 Audit log

见 §8.4（两层审计 + schema + 禁记内容清单）。

---

## 7. Rotate / Delete 危险操作语义（danger-zone 契约）

### 7.1 触发链（E3 定义，E2 呈现）

```text
Clients 行 → Rotate / Delete（红色 danger-zone 区域）
→ 模态框：
   · 后果明示（rotate：旧 YAML 立即失效、所有设备断线、必须重新下载；
     delete：双协议凭据同时移除、Monitor 不再统计该设备）
   · type-to-confirm：必须逐字输入客户端名（= body.confirm）
   · step-up：距上次重认证 > 300s → 先弹密码重认证（401 reauth_required 驱动）
→ POST（带 Idempotency-Key）
→ 结果页：rotate 成功后立即高亮"重新下载 YAML"入口
```

### 7.2 Rotate 后旧 YAML 失效的硬契约

* 服务端凭据在事务提交瞬间即已轮换 → 任何**此前下载**的 YAML 立即失效；
* API 返回 `yaml_invalidated:true` + `warning` + 新 `credential_version`；
* Web UI 必须：(a) rotate 前在模态框写明后果；(b) rotate 成功页显著提示
  "旧 YAML 已失效，请重新下载"；客户端列表中 `rotated_at` 晚于用户上次下载时间时
  显示"YAML 已过期"角标（下载时间由前端 localStorage 记录，不进服务端契约）；
* 导出端点以 `X-Credential-Version` 头 + YAML 头注释让"旧文件"可被用户自己识别。

### 7.3 Delete 语义补充

* 先服务端后派生物（§4.4 阶序）；E1 视角：`user.name` 消失 → 设备不再产生新连接，
  内存计数随之终结（E1 无持久化，无需清理动作）。
* 同名重建不受限（create 新 `vmix-01` 即全新身份，`credential_version` 从 1 重新计数，
  与旧身份无关联——注册表按 name 覆盖，如实反映"新客户端"）。

### 7.4 whitelist / admin password / recovery key 与 YAML 的隔离

见 §8.5。核心断言：**这三者的变化对任何 YAML 字节零影响、对服务端配置零接触、
不参与 config.lock 竞争。**

---

## 8. Authorization / CSRF / Audit

### 8.1 授权模型

* v1 单管理员：唯一角色 `admin`。E2 拥有登录态；E3 契约：
  中间件向每个 `/api/v1/clients*` 请求注入
  `client_ctx = {session_id, role, auth_age_seconds, source_ip}`，
  任一 `role != "admin"` → 403 forbidden（防御性，v1 无低权角色）。
* 白名单（IP allowlist，若 E2 实现）在中间件层生效，先于 CSRF。
* recovery key 仅用于 E2 登录恢复；不得出现任何"recovery key 直达 client-manager"
  的路径（否则恢复密钥等价于全部客户端凭据）。

### 8.2 Step-up 重认证（危险操作）

* rotate / delete 要求 `auth_age_seconds ≤ 300`，否则 `401 reauth_required`；
* UI 收到该码 → 弹密码重认证 → 成功后自动重放原请求（confirm/Idempotency-Key 不变）；
* helper 不参与 step-up（它无法验证密码），信任边界 = "Web 中间件保证 5 分钟内
  人工在场"；helper 侧补偿：审计中记录 actor session，便于事后追责。

### 8.3 CSRF

| 层 | 措施 |
| --- | --- |
| Cookie | 会话 cookie `HttpOnly` + `SameSite=Strict`（+ `Secure`，若未来上 TLS 反代） |
| Token | 变更请求（POST/DELETE）与导出 GET 均要求 `X-CSRF-Token`（double-submit，E2 签发） |
| Origin | 校验 `Origin`/`Referer` ∈ 允许集（loopback host）；`Sec-Fetch-Site: cross-site` 一律拒绝 |
| Content-Type | 写请求强制 `application/json`（表单跨站无法伪造 JSON 内容型请求） |
| 导出 GET | 同样要求 CSRF 头（见 §3.3），杜绝 `<a href>` drive-by 下载 |

### 8.4 审计

两层，各司其职：

1. **Web 审计（E2 拥有）**：请求层 —— method、path、actor session、source_ip、
   CSRF 结果、HTTP 状态、时延、request_id。
2. **特权审计（E3，helper 追加）**：事务层 —— JSONL
   `/root/sbox/web/audit/cm.jsonl`（0600，root）：

```json
{ "ts": "2026-09-12T11:00:00Z", "request_id": "b7c9…", "actor": "web-session:a1f3…",
  "verb": "rotate", "name": "vmix-01", "outcome": "ok", "stage": "commit",
  "backup": null, "rolled_back": false, "credential_version": 2,
  "lock_wait_ms": 3, "confirm_echo": true, "idempotency_key_fp": "9af1…" }
```

禁记清单（两层共同）：UUID、password、private key、YAML 内容、完整配置、
完整凭据指纹。导出事件只记 `name + bytes`。`outcome ∈ ok|rejected|rolled_back|
manual_intervention`，`manual_intervention` 级别为 CRITICAL。

### 8.5 认证态与 YAML 的隔离（不变量）

```text
YAML 输入集合 ≡ { sbconfig_server.json, SB_STATE_FILE, client name }
E2 认证存储 ∉ 输入集合
```

* 改 admin password / whitelist / recovery key：只写 E2 认证存储，
  不触碰 `SB_*`、不获取 config.lock、不产生任何 YAML 变化（E3-T17 字节级断言）；
* 反向亦然：create/rotate/delete 不触碰认证存储（账号失窃场景下 rotate
  不会把攻击者锁在门外或锁在门内——两者正交）。

---

## 9. 参考 UX 与明确不采用的模型

* **参考**（交互模式，非代码）：s-ui / 3x-ui 的客户端表格与操作确认；
  metacubexd / yacd 的连接/设备展示语言；通用管理台的 danger-zone + type-to-confirm
  （GitHub 删除仓库范式）+ step-up auth（Google 风格）。
* **明确不采用 Clash REST 配置修改模型**：Clash 允许 `PUT/PATCH /configs`
  直接改运行时配置 —— 本项目拒绝该形态：HTTP 层永远没有"改配置"的能力，
  只有"请求一个事务"的能力；服务端配置的合法写入口只有 Phase C 事务。

## 9.4 Residual risks（如实声明）

1. Web 进程被完全攻破 ⇒ 攻击者可调用 5 个 verb（含导出凭据、删客户端）。
   缓解：极小攻击面、仅回环、无公网、审计完备、step-up 抬高自动化利用成本；
   无法根除，属于"面板类"系统固有风险。
2. sudo + 短命 root 进程仍以 root 运行 ⇒ helper 自身漏洞即 root 漏洞。
   缓解：helper 代码极小、入参仅 stdin JSON、无 shell 解释（参数不经 eval）、
   静态扫描 + 测试覆盖。
3. 127.0.0.1 明文 HTTP：本机其他本地用户可嗅探回环流量（单管理员 VPS 上可接受；
   未来可加 TLS 反代，属 E2 范畴）。

---

## 10. 未决决策（需 review 后定案）

| # | 决策 | v1 建议 | 备选 |
| --- | --- | --- | --- |
| D-1 | legacy 是否允许 Web 导出 YAML | **否**（403；共享账号凭据不走 API） | 允许（与普通客户端一致） |
| D-2 | 注册表文件位置/格式 | `/root/sbox/web/client-registry.json`，单 JSON | 每客户端 `meta.json` 放 clients 目录 |
| D-3 | rotate 粒度 | 永远双协议成对（与 Phase C 原子模型一致） | 按 protocol 单独轮换（破坏 name 集合不变量，需改审计） |
| D-4 | E2 认证/会话接口细节（cookie 名、re-auth 端点形态） | E3 只依赖 §8.1 的 `client_ctx` 注入契约，具体归 E2 | — |
| D-5 | 审计是否合并为一份 | 保持两层（Web/事务职责不同） | 单一 JSONL 双 writer |
| D-6 | 变更限流阈值 | 10 次/分钟/IP（防误触脚本） | 不限（单管理员） |
| D-7 | 导出缺失 YAML 时自动再生 vs 409 | 自动再生（派生物物化，非配置变更） | 409 + 显式 POST /yaml-regen |
| D-8 | 备份保留策略 | 维持 Phase C 现状（不清理） | 引入保留 N 份/GC（独立小任务） |
| D-9 | API 错误 message 语言 | 英文 code + 英文 message（程序消费），UI 层本地化中文 | 双语 message |
| D-10 | rotate/delete 的 step-up 窗口 | 300s | 120s / 600s |

---

## 11. E3 实施阶段（每阶段独立可测，全部尚未实现）

| 阶段 | 交付物 | 测试闸门 |
| --- | --- | --- |
| **E3-0** | phase-c 块内新增 `rotate_client` / `_rotate_client_locked`（纯 Phase C 扩展，CLI 即可用；Web 零代码） | `tests/test-phase-e3.sh`：rotate 成功/回滚/reserved/一致性前置/并发 |
| **E3-1** | 特权 helper 库 + 5 个 verb 入口 + JSON 协议 + 错误码 + 特权审计 + sudoers | 沙箱（SB_* 覆盖 + mock sing-box/systemctl，test-phase-c.sh 同法）逐 verb 契约测试 |
| **E3-2** | Web 适配层（薄）：HTTP ↔ helper 映射、错误码表、CSRF/step-up 中间件挂钩（对接 E2 的 `client_ctx`）、进程内 Idempotency | API 契约测试（mock helper 进程）+ §3.7 全表 |
| **E3-3** | 导出/下载 + credential_version 陈旧检测 + 注册表 + UI 契约字段（warning/yaml_invalidated/角标） | 导出头断言、撕裂读测试（E3-T12）、自愈测试 |
| **E3-4** | 硬化：失败注入（F1–F11）、并发 canary、凭据卫生 grep、审计 schema 校验、文档刷新 | 全矩阵绿 + 生产 canary（仅 VPS 侧人工执行，见约束） |

依赖关系：E3-0 独立可先行；E3-1 依赖 E3-0；E3-2 依赖 E3-1 与 E2 的中间件接口（D-4）；
E3-3/E3-4 依赖 E3-2。

---

## 12. 测试矩阵（v1 必须全绿的集合；命名沿用仓库 `E3-Txx`）

| ID | 场景 | 断言 |
| --- | --- | --- |
| E3-T01 | create happy path（reality+hy2） | 201；两个 inbound 各新增 `{name,uuid,password}`；YAML 含 `${name}-Reality`/`${name}-HY2`；响应体与任务书字段一致 |
| E3-T02 | duplicate name | 409；配置字节不变；无备份残留 |
| E3-T03 | 非法 name（`vmix 01`、`../../x`、`a/b`、空、`-leading`、33 字符、`legacy`） | 422/422 reserved；配置不变 |
| E3-T04 | legacy：create/rotate/delete/export | 422/403/403/403；legacy 在配置中原样存在 |
| E3-T05 | delete 成功 | 双 inbound 移除；`clients/<name>/` 删除；注册表清理；审计 ok |
| E3-T06 | rotate 成功 | name 不变；uuid/password 均变；`credential_version`+1；YAML 更新且头注释版本一致；Monitor 身份= user.name 不变 |
| E3-T07 | rotate 遇 reload 失败 | 503 commit_rolled_back；配置=旧凭据；YAML 未动；重试安全 |
| E3-T08 | create/delete 遇健康检查失败 | 503；create→客户端不存在；delete→客户端完整存在+目录未删 |
| E3-T09 | 回滚后仍不健康（注入回滚 reload 失败） | 500 rollback_manual_intervention；审计 CRITICAL |
| E3-T10 | 10 并发同名 create | 恰好 1×201、9×409；配置只有一个该用户且合法 |
| E3-T11 | 锁被长持时变更请求 | 423 lock_busy；不忙后正常 |
| E3-T12 | rotate 与 export 并发 | 导出结果为完整旧版或完整新版 YAML（uuid-password 配对一致），永不撕裂 |
| E3-T13 | rotate 同 Idempotency-Key 重放 | 只轮换一次；第二次返回首次结果；换 body 同 key → 422 |
| E3-T14 | CSRF：无 token / 错 Origin / 表单编码 / 导出 GET 无头 | 403 / 403 / 415 / 403 |
| E3-T15 | step-up：auth_age > 300s 的 rotate/delete | 401 reauth_required；重认证后重放成功 |
| E3-T16 | 凭据卫生 | 所有 API 响应 + 两份审计日志中 grep UUID/password/private 形状 = 0 命中 |
| E3-T17 | 认证态隔离 | 改 admin password、whitelist、recovery key 前后 YAML 字节相同；期间无 config.lock 竞争 |
| E3-T18 | yaml_gen 注入失败 | 201 + `yaml_available:false` + warnings；后续 export 自愈成功 |
| E3-T19 | CLI（mianyang）创建的客户端 | 出现在 GET /clients，`source:"cli"`、时间戳 null |
| E3-T20 | 导出响应头 | attachment 文件名、no-store、nosniff、X-Credential-Version |
| E3-T21 | 注入坏 candidate（重复 uuid） | 500 candidate_rejected；live 配置未动；审计含问题行 |
| E3-T22 | 失败路径残留检查 | 所有 F1–F11 后无 candidate 临时文件残留（备份文件按 Phase C 语义保留） |
| E3-T23 | 一致性审计失败时写操作 | 409 config_inconsistent；GET 照常返回 + `consistency_problems` |
| E3-T24 | 审计 schema | 每条 JSONL 可解析、字段齐、无禁记内容 |
| E3-T25 | （可选 canary）VPS 生产：create→真实连接→E1 Device= vmix-01→rotate→旧 YAML 断、新 YAML 通→delete | 全链路身份与事务语义 |

---

## 13. 显式非目标（Non-goals）

1. **不实现 E2**（Dashboard UI、登录页、会话存储本身）；E3 只定义并消费其中间件契约。
2. **NAS 集成完全不在范围内**：用户自行下载 YAML 放到 NAS，服务端不感知 NAS。
3. 不开任何公网端口 / 不做 TLS 终结 / 不改 VPS 网络与防火墙。
4. 不修改 `sbconfig_server.json` 的任何 schema、inbound 结构或现有用户；
   不在本轮触碰生产配置（本文档为零生产变更）。
5. 不写任何 client mutation 生产实现（本轮连 E3-0 的 rotate 代码也不落地）。
6. 不 reload/restart sing-box（reload 只存在于未来实现的事务内部，设计文本除外）。
7. 不采用 Clash REST 配置修改模型；不新增任何直接写 JSON 的代码路径。
8. 不做多管理员/RBAC/多租户；不做每协议独立轮换（D-3）；不做 YAML 以外的
   导出格式（sing-box 客户端 JSON、分享链接列表等留待后续）。
9. 不改 E1 collector（身份模型、gRPC-Web 桥、生命周期语义均不动）；
   不做流量历史持久化/数据库。
10. 不管理 whitelist / admin password / recovery key（E2 范畴）；
    不做备份 GC（D-8 留待独立决策）。
11. 不做 E1/E2 已有代码的重构或"顺手优化"。

---

## 14. 本轮交付核对

* 设计文档：本文档（`docs/monitor-v2-e3-design.md`），架构 / API contract /
  事务桥 / 凭据 / YAML 模型 / rotate-delete 语义 / 并发锁 / 回滚矩阵 /
  授权-CSRF-审计 / E3 阶段 / 测试矩阵 / 非目标 —— 12 项齐备。
* 提议 API：§3 六端点逐字对齐任务书，另附错误码总表与导出安全头。
* 事务边界：§4（唯一互斥点 config.lock；唯一写路径 Phase C 事务；读也过锁防撕裂）。
* 安全边界：§2 权限表 + §5 凭据处理 + §8 授权/CSRF/审计 + §9.4 residual risks。
* 未决决策：§10（D-1…D-10）。
* 生产变更：**无**。本轮仅新增本设计文档，未改 install.sh、monitor-v2、tests 及任何配置。
