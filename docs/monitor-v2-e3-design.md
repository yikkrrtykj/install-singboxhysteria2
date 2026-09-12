# Monitor v2 — Phase E3 Design: Web Client Manager（架构设计，不含实现）

状态：**设计稿 rev2（已吸收 design review follow-up，待再 review）**。
rev2 变更摘要：

1. 锁契约改为 fail-closed：如实记录 Phase C `with_client_lock()` 现状是 fail-open，
   E3-0 修复为全路径（CLI + Web）严格锁；锁失败绝不修改配置（§4.7、§6.7、E3-T26..T28）。
2. 新增 credential-silent rendering/export path：helper 的 stdout/stderr/journal/
   audit/error 全程零 UUID/password/YAML/分享 URI（§5、§4.6、E3-T29）。
3. 事务实现收敛到共享库 `lib/client-management.sh`（install.sh CLI 与特权 helper
   共同 source），废除"运行时 source install.sh / awk 截取 phase-c 块"，杜绝两套
   事务实现（§1.2 D2、§11 E3-0）。
4. 特权桥改为**单个** root-owned narrow helper（固定 operation、严格 stdin schema、
   禁止任意 command/path/config/shell）；多 binary 方案被否决并记录理由（§1.2 D3）。
5. 凭据下载重设计为 `POST /clients/{name}/export → one-time token → GET
   /download/{token}`，取代 rev1 的"GET 携带 CSRF 头"（§3.3）。
6. Idempotency-Key 升级为特权侧持久账本（intent/outcome + request digest + 结果
   replay + 失联重试调和），覆盖"事务已成功但 HTTP response 丢失"（§6.9、E3-T30..T32）。
7. v1 决策定案：legacy = Web list-only（禁 delete/rotate/默认禁 export）；
   rotate = Reality + HY2 一次性共同旋转、整份 YAML 失效（§7、§10 已定案）。
8. 失败/测试矩阵扩充：lock unavailable / flock missing / credential-bearing helper
   stdout / response lost / 同 key 重放 / 同 key 异 payload / token replay /
   token expiry（§6.4 F12–F16、§12 E3-T26..T36）。

rev1 基线（仍有效的事实锚点，均已在仓库核实）：

| 事实 | 出处 |
| --- | --- |
| 服务端单一事实源 `/root/sbox/sbconfig_server.json`；`/root/sbox/clients/` 全部是派生物 | `install.sh`（`SB_SERVER_CONFIG` / `SB_CLIENTS_DIR` 注释） |
| 事务核心：`flock → 结构审计 → candidate → sing-box check → backup → 原子 mv → reload → 健康检查 → 失败回滚` | `install.sh` `commit_server_config` |
| **`with_client_lock()` 现状 fail-open**：flock 不可用或获取失败时 `warning "无法获取配置锁…单机低并发场景下继续执行"` 后照常执行 | `install.sh` `with_client_lock`（warning 后继续执行 `"$@"`） |
| **`generate_client_configuration()` 现状会打印携带凭据的分享 URI**（`vless://$uuid@…`、`hysteria2://$password@…`） | `install.sh` `generate_client_configuration` 尾部 `info "Reality 链接…"` / `info "HY2 链接…"` |
| 客户端命名 `^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`；`legacy` 是保留名 | `install.sh` `CLIENT_NAME_PATTERN` / `RESERVED_CLIENT_NAME` |
| Monitor 身份：`Device = API USER`（`user.name`），不可变 | `monitor-v2/README.md`、`monitor-v2/collector.py` |
| `service.api` 仅监听 `127.0.0.1:9091`，不向公网开放 | 根 `README.md` |
| `rotate` 目前不存在 | `grep -c rotate install.sh == 0` |
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
  → Download Mihomo YAML（POST export → token → GET download，见 §3.3）
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

硬性规则（rev2 补充第 5、6 条）：

1. **真实身份只来自服务端 `user.name`**。YAML 里的 `vmix-01-Reality` / `vmix-01-HY2`
   是代理条目的本地显示名，改显示名、改 YAML 排序都不影响 Monitor 归属。
2. **Web 层永远不直接 `open(...sbconfig_server.json)`**，也不手改 JSON。Web 层对
   服务端配置文件连读权限都没有（见 §2 权限分离）。
3. 所有服务端变更必须复用 Phase C 事务模型（§4），任何绕过事务的写入路径都不允许存在；
   事务实现只有一份（`lib/client-management.sh`，§1.2 D2）。
4. `legacy` 永远是 reserved client：Web 视角 **list-only**（§7.4）。
5. **锁是 fail-closed 的**（E3-0 修复 Phase C 现状）：任何 mutation path 在锁不可用/
   获取失败时必须拒绝执行，配置零修改（§4.7）。
6. **helper 输出通道零凭据**：stdout/stderr/journal/audit/error 中不出现
   UUID / password / YAML / 分享 URI；凭据字节只经受控 spool 文件越界（§5、§4.6）。
7. whitelist / admin password / recovery key 属于 E2 认证体系，它们的任何变化
   **不得影响**现有 Reality/HY2 YAML（§8.5）。

---

## 1. 架构

### 1.1 分层与信任边界

```text
┌────────────────────────────────────────────────────────────────────┐
│ Browser（管理员）                                                    │
│   Clients 列表 / Add Client 弹窗 / danger-zone / 导出+下载          │
└───────────────┬────────────────────────────────────────────────────┘
                │ HTTP（仅 127.0.0.1；远程访问 = SSH 隧道，不开公网端口）
┌───────────────▼────────────────────────────────────────────────────┐
│ 边界 A：E2 Web Dashboard 进程（E3 只定义接口，不实现）                │
│   · 运行用户：sboxweb（非特权，无 /root/sbox 任何读写权）             │
│   · 认证 / 会话 / CSRF / 限流 / Web 侧审计（E2 提供，见 §8 接口）     │
│   · HTTP ↔ JSON contract（§3）；token 签发与 download 流式服务        │
│   · 进程内绝不保存、绝不记录任何 UUID/password/YAML 字节              │
└───────────────┬────────────────────────────────────────────────────┘
                │ 唯一通道：sudo 调用单个固定 helper，stdin/stdout JSON（§4.2）
┌───────────────▼────────────────────────────────────────────────────┐
│ 边界 B：E3 特权 helper：/usr/local/lib/sbox-cm/sbox-cm               │
│   （root-owned 0755、短命进程、bash；rev2：单 binary，见 D3）         │
│   · argv 必须为空；operation 仅来自 stdin JSON 的严格 schema          │
│     （verb ∈ 固定枚举；name 过 Phase C 正则；禁止任意                 │
│      command/path/config/shell —— 无 eval、无动态路径）              │
│   · source lib/client-management.sh ← 与 install.sh CLI 共享的       │
│     唯一事务实现（绝不 source 整个 install.sh，绝不运行时截取代码块）  │
│   · fail-closed flock（§4.7）；锁失败 → 退出，零写入                  │
│   · 输出：仅 JSON 结果 + 退出码（零凭据，§5）；                       │
│     凭据字节唯一越界通道 = spool 文件（root:sboxweb 0640，§4.6）       │
│   · JSONL 审计 + 幂等账本（intent/outcome，§6.9）                     │
└───────────────┬────────────────────────────────────────────────────┘
┌───────────────▼────────────────────────────────────────────────────┐
│ lib/client-management.sh（rev2 新增的共享事务库，E3-0 抽取）          │
│   · Phase C 现有函数原样搬入（字节级不变）：with_client_lock /        │
│     commit_server_config / _add_client_locked / _delete_client_locked│
│     / candidate_problems / get_client_credentials / …                │
│   · E3-0 新增：rotate_client / _rotate_client_locked、               │
│     render_client_yaml（credential-silent 渲染核心）、               │
│     with_client_lock 的 fail-closed 语义                             │
│   · install.sh 用 source 本库替换内嵌 phase-c 块；CLI 行为不变        │
└───────────────┬────────────────────────────────────────────────────┘
                │
   /root/sbox/sbconfig_server.json   ← 唯一事实源（user.name = Monitor 身份）
   /root/sbox/clients/<name>/mihomo.yaml ← 派生物（root-only），可随时再生
   /var/lib/sbox-cm/spool/           ← 一次性下载 spool（root:sboxweb，§4.6）
   /root/sbox/config.lock            ← 唯一互斥点（E3-0 起 CLI+Web 全部 fail-closed）
   （E1 collector 走 127.0.0.1:9091 service.api，与 E3 完全解耦、互不感知）
```

### 1.2 设计决策与理由

* **D1 特权分离：Web 进程非特权，特权 helper 独立短命进程。**
  即使 Web 层被攻破，攻击者也拿不到任意文件读写，只能触发固定的 5 个 operation。
  residual risk 在 §9.4 明示。
* **D2（rev2 修订）事务逻辑只有一份：共享库 `lib/client-management.sh`。**
  rev1 的"helper 运行时 source install.sh / awk 截取 phase-c 块"被 review 否决：
  运行时文本抽取脆弱且把整个 install.sh 带进特权执行上下文。rev2 方案：E3-0 把
  phase-c 块函数**原样搬移**（字节级不变）到 `lib/client-management.sh`；
  `install.sh` 以 `source` 该库替换内嵌块；helper source 同一库。函数体没有第二份拷贝，
  CLI 与 Web 的任何行为差异只可能来自调用参数，不可能来自实现漂移。
  抽取闸门：`tests/test-phase-c.sh` 从 awk 截取改为直接 `source lib/client-management.sh`
  （测试机制变更，断言集合不变），全套 C 回归 + `bash -n` + shellcheck 必须全绿。
* **D3（rev2 修订）单个 narrow helper，放弃五个独立 sudo binary。**
  rev1 的多 binary 理由是"sudo 日志逐 verb 可见"。重新评估后否决：(a) 该收益只是
  日志可读性，安全上无增量——多 binary 与单 binary 的进程能力完全相同，攻击面差异
  仅在"verb 白名单在 sudoers 还是 stdin schema"，而 stdin schema 校验（固定枚举 +
  name 正则 + argv 必须为空）已把可执行操作收敛到同一集合；(b) 五份入口 = 五份参数
  解析/校验代码 = 五份出错机会；(c) 操作层面的追责由 E3 JSONL 审计（verb + actor +
  request_id）承担，比 sudo 日志更强。**单 binary 约束**：root-owned 0755、
  代码只做"stdin JSON → 校验 → 调库 → JSON 输出"；不接受任何路径/命令/配置名参数；
  生产路径常量内嵌；`sudoers env_reset` 剥离 `SB_*` 注入（测试经直接非 sudo 调用
  注入沙箱路径）。
* **D4 注册表（registry）只是顾问性元数据。** `created_at` / `rotated_at` /
  `credential_version` / actor 存在 `/root/sbox/web/client-registry.json`（helper
  维护，0600）。列表永远以 **live 配置**为准（CLI 创建的客户端自动出现在 Web 里），
  注册表仅补充时间线；两者漂移时以配置为准并在响应中如实标注（§6.3）。
* **D5 不采用 Clash REST 的配置修改模型。** 参考 s-ui / 3x-ui / metacubexd /
  yacd 的展示与 danger-zone 交互，但拒绝 Clash `PUT/PATCH /configs` 式的
  "HTTP 直接改配置"：所有变更必须穿过 §4 事务。
* **D6（rev2 新增）下载 = 一次性 token + spool 文件。** 凭据字节不允许出现在
  helper 的任何输出通道（review 硬性要求），因此 Web 拿到 YAML 的唯一方式是
  helper 把字节写进 root:sboxweb 受控 spool 文件并返回一次性 token（§4.6）。
* **D7（rev2 新增）渲染核心 credential-silent。** 现 `generate_client_configuration()`
  会打印携带 UUID/password 的分享 URI，Web 链路绝不能复用该行为：库内拆分为
  `render_client_yaml`（纯文件输出、零 stdout 泄漏，helper 专用）与 CLI 交互包装
  （保持现状打印 URI——那是人机交互路径，不在 helper 调用面上，行为不变以保 C 回归）。

### 1.3 组件清单（E3 新增，全部待实现，本轮零实现）

```text
lib/client-management.sh        # 共享事务库（E3-0 从 install.sh phase-c 块抽取
                                #   + rotate + silent 渲染 + fail-closed 锁）
usr/lib/sbox-cm/sbox-cm         # 特权 helper（单 binary，bash，E3-1）
                                #   stdin JSON → 校验 → 调库 → stdout JSON + 退出码
monitor-v2/cm_client/           # Web 侧适配层（非特权，E3-2）
  protocol.py                   #   HTTP ↔ helper JSON 映射、错误码表
  export_tokens.py              #   export token 校验/一次性语义
  adapters.py                   #   sudo 调用封装、超时、并发信号量
tests/test-phase-c.sh           # E3-0：抽取方式改为 source lib（断言不变）
tests/test-phase-e3.sh          # E3 全套（§12）
```

---

## 2. 权限与文件边界（security boundary 的静态部分）

| 路径 | 属主/权限 | Web 进程 | helper | 说明 |
| --- | --- | --- | --- | --- |
| `/root/sbox/sbconfig_server.json` | root 0600 | **无任何权限** | 读写 | 唯一事实源；只允许被事务改写 |
| `/root/sbox/config`（SB_STATE_FILE） | root 0600 | 无 | 读 | SERVER_IP / PUBLIC_KEY / HY_SERVER_NAME / 跳端口区间 |
| `/root/sbox/clients/<name>/` | root 0700 | 无 | 读写 | 派生 YAML（canonical，root-only） |
| `/var/lib/sbox-cm/spool/` | root:sboxweb 0750 | 按文件名直取（无列取必要） | 读写 | 一次性下载文件 `<token>.yaml` + `<token>.meta.json`，0640；这是凭据字节唯一越界通道（§4.6） |
| `/root/sbox/config.lock` | root | 无 | flock | 唯一互斥点；E3-0 起 CLI+Web 全部 fail-closed |
| `lib/client-management.sh` | root 0644 | 无（不经 Web 分发） | source | 与 install.sh 共享的唯一事务实现 |
| `/root/sbox/web/client-registry.json` | root 0600 | 无 | 读写 | 顾问元数据 |
| `/root/sbox/web/cm-ledger.jsonl` | root 0600 | 无 | 读写 | 幂等账本（intent/outcome，§6.9） |
| `/root/sbox/web/audit/cm.jsonl` | root 0600 | 无 | 追加 | 特权审计（§8.4） |
| E2 会话/认证存储（admin password hash、recovery key、whitelist） | E2 自有 | 读写 | **不读不写** | 与 YAML 生成完全隔离（§8.5） |

sudoers（单条规则；`env_reset` 剥离 `SB_*`/`PATH` 注入；argv 必须为空，参数走 stdin）：

```text
Defaults:sboxweb env_reset
sboxweb ALL=(root) NOPASSWD: /usr/local/lib/sbox-cm/sbox-cm
```

网络边界：Dashboard 仅绑定 `127.0.0.1`（具体端口归 E2）；远程使用一律 SSH 隧道；
**E3 不新增任何公网监听**，与 service.api 的 loopback 原则一致。

---

## 3. HTTP API contract

通用约定：

* 前缀 `/api/v1`；所有请求/响应 body 为 `application/json; charset=utf-8`
  （`GET /download/{token}` 的 YAML 除外）。拒绝 `application/x-www-form-urlencoded`
  / `multipart`（415）。
* 所有响应带 `X-Request-Id`（与 helper `request_id`、两份审计日志四方可关联）。
* 错误响应统一形状：

```json
{ "error": { "code": "duplicate_name", "message": "client 'vmix-01' already exists",
             "detail": { "stage": "pre_lock" } } }
```

* 错误码 → HTTP 映射表（§3.7）。**任何成功响应、错误响应、日志中都绝不出现
  UUID / password / private key / 完整 sing-box config / YAML**（唯一例外：
  `GET /download/{token}` 的响应体本身就是 YAML 凭据容器，其安全模型见 §3.3/§4.6）。

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

### 3.3 凭据下载（rev2：two-step token flow，取代 rev1 的 `GET .../mihomo.yaml`）

> rev1 曾按任务书设计 `GET /api/v1/clients/{name}/mihomo.yaml` 并以"GET 携带自定义
> CSRF 头"防护。review 否决该形态：浏览器普通导航/`<a href>` 下载无法携带自定义头，
> "带头的 GET"逼迫前端走 fetch+blob，反而破坏下载语义且防御面含混。
> rev2 采用标准的一次性 token 下载：

**第一步：签发**

```text
POST /api/v1/clients/vmix-01/export
头：X-CSRF-Token: …（变更类防护，与 POST/DELETE 同一 token）
// 200
{ "name": "vmix-01", "token": "b7c9…base64url(256bit)",
  "expires_in": 300, "credential_version": 1,
  "download_url": "/api/v1/download/b7c9…" }
```

* helper 在锁内：一致性审计 → 凭据读取 → （canonical 缺失/过期时）silent 再生
  `clients/<name>/mihomo.yaml` → 写 spool 副本 → 返回 token（§4.6）。
* token：256-bit 随机 base64url；**一次性**；TTL 300s；与签发会话绑定（meta 内
  session 指纹）；token 本体不出现在任何日志（审计只记指纹前缀）。
* `legacy` → `403 reserved_client`（已定案 A-1：默认不允许 Web 导出 legacy 凭据）。

**第二步：下载**

```text
GET /api/v1/download/{token}        ← 浏览器普通导航，不携带自定义头
→ 200 text/yaml; charset=utf-8
   Content-Disposition: attachment; filename="vmix-01-mihomo.yaml"
   Cache-Control: no-store
   X-Content-Type-Options: nosniff
   Referrer-Policy: no-referrer
   X-Credential-Version: 1
```

* 防护模型：token 本身就是一次性 bearer proof（不可枚举、5 分钟、单次、会话绑定），
  下载时 Web 另行校验会话 cookie 仍有效且与 meta 绑定一致。
* **replay**：文件与 meta 在成功下载后立即删除 → 再次请求同一 token →
  `410 token_used`；**expiry**：过期或被惰性清扫删除 → `404 token_expired`。
* Web 崩溃/重启不丢 token：spool 在磁盘上，重启后 token 在 TTL 内仍可用（E3-T36），
  重放防护同样由"文件存在性"保证（无需 Web 内存态）。

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
| `reality` / `hy2` 不同时为 true | `422 protocol_set_unsupported`（已定案 A-2 的伴生决策：Phase C 一致性审计要求两个 inbound 的 name 集合完全一致，单协议客户端会永久破坏该不变量） |
| name 不匹配 `^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$` | `422 invalid_name`（message 中回显该正则） |
| name == `legacy` | `422 reserved_name` |
| name 已存在（任一 inbound） | `409 duplicate_name`（锁内以 live 配置复核后判定） |
| 请求体不是合法 JSON / 缺字段 | `400 malformed_body` |

`yaml_available` 语义：提交后 helper 尝试 silent 再生派生 YAML；**服务端配置提交成功
但 YAML 再生失败时仍返回 201 + `yaml_available:false` + 顶层
`warnings:["yaml_generation_failed"]`**（§6.6 部分失败）。客户端本体（Monitor 身份 +
凭据）已生效。

### 3.5 POST /api/v1/clients/{name}/rotate（危险操作）

```json
// 请求（显式确认：逐字回显客户端名）
{ "confirm": "vmix-01" }
// 头：X-CSRF-Token: …；会话须在 300s 内完成过 step-up 重认证（§8.2）
// 头：Idempotency-Key: <uuid4>（rotate 必填，见 §6.9）
// 200
{ "name": "vmix-01", "protocols": ["reality", "hy2"], "yaml_available": true,
  "rotated_at": "2026-09-12T11:00:00Z", "credential_version": 2,
  "yaml_invalidated": true,
  "warning": "Reality 与 HY2 凭据已同时轮换，整份 YAML 已失效；所有使用旧 YAML 的设备将断线，必须重新下载" }
```

* **已定案 A-2：rotate = Reality + HY2 一次性共同旋转**（同一事务内替换 UUID 与
  password，两者永远成对）；`user.name` 不变 → **Monitor 身份无缝延续**。
* **整份 YAML 失效**：`yaml_invalidated:true` 是对 YAML 文件整体的判定（不做
  "单协议部分失效"的细粒度表述），响应 `warning` 与 UI 文案必须使用该口径。
* `confirm` 字段与 `{name}` 不一致 → `400 confirm_mismatch`；缺 step-up →
  `401 reauth_required`。

### 3.6 DELETE /api/v1/clients/{name}（危险操作）

```json
// 请求：同 rotate（confirm 逐字回显 + CSRF + step-up；Idempotency-Key 建议携带）
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
* `legacy` → `403 reserved_client`（已定案 A-1）。

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
| 404 | `token_expired` | 下载 | token 过期/未知/被清扫 |
| 409 | `duplicate_name` | 锁内复核 | 已存在（任一 inbound） |
| 409 | `config_inconsistent` | 事务前置审计 | Reality/HY2 集合不一致等，拒绝一切写 |
| 409 | `yaml_unavailable` | 导出 | canonical YAML 缺失且 silent 再生失败 |
| 409 | `idempotency_conflict` | 幂等账本 | 同 key 不同 request digest（§6.9） |
| 410 | `token_used` | 下载 | token 已被使用（一次性，文件已删除） |
| 415 | `unsupported_media_type` | 中间件 | 非 application/json 写请求 |
| 422 | `invalid_name` / `reserved_name` / `protocol_set_unsupported` | 校验 | §3.4 表 |
| 423 | `lock_unavailable` | flock（fail-closed） | 锁不可用/获取失败/超时 —— **配置零修改**（§4.7） |
| 429 | `rate_limited` | 中间件 | 变更限流 |
| 500 | `internal` | 未分类 | 附 request_id 排查 |
| 500 | `candidate_rejected` | 审计/check | candidate 被审计或 `sing-box check` 拒绝（磁盘未动） |
| 500 | `commit_failed` | 备份/原子替换 | mv/备份失败（磁盘未动或已保留备份） |
| 500 | `export_failed` | spool | spool 写入失败（无部分文件残留） |
| 503 | `commit_rolled_back` | reload/健康 | 提交后失败 → 已自动回滚，**服务已恢复** |
| 500 | `rollback_manual_intervention` | 回滚 | 回滚后仍未确认恢复，**需人工**（CRITICAL 审计） |

> `503 commit_rolled_back` 特意区别于 5xx 其他码：对管理员它意味着"失败但系统是好的，
> 可以重试"；`500 rollback_manual_intervention` 意味着"别再点重试，去看服务器"。

---

## 4. Phase C 事务桥（transaction boundary）

### 4.1 原则：一条通道、一套事务、零旁路

* 服务端配置的全部合法写路径 = `with_client_lock`（fail-closed，§4.7）+
  `commit_server_config`。E3 不新增任何并行事务实现；`rotate` 与 silent 渲染作为
  **共享库内的新函数**（E3-0）进入同一份实现，CLI 菜单与 Web 自动共享同一把锁、
  同一审计、同一回滚语义。
* Web 层被权限模型物理排除在事务之外（§2：无读权限），"禁止 Web 手改 JSON"
  不靠纪律，靠操作系统权限。
* 读也过锁（§6.8）：helper 的所有 verb（含 list/export）都持有排他锁，
  保证导出/列表读到的 uuid-password 对永不撕裂。

### 4.2 helper JSON 协议（进程边界，stdin → stdout）

```json
// stdin（sudoers 下 argv 必须为空；全部经 stdin；name 在 helper 内再次过 §3.4 正则）
{ "request_id": "b7c9…", "actor": "web-session:a1f3…", "verb": "rotate",
  "name": "vmix-01",
  "idempotency_key": "6f0e…", "request_digest": "sha256:91af…" }
// stdout（零凭据：只有状态、版本号、token 等非敏感字段）
{ "ok": true, "data": { "name": "vmix-01", "yaml_available": true,
                        "credential_version": 2 } }
// 或
{ "ok": false,
  "error": { "code": "commit_rolled_back", "stage": "reload",
             "detail": "reload 后健康检查失败，已自动回滚",
             "backup": "/root/sbox/sbconfig_server.json.bak.20260912-110000.XXXXXX" } }
```

* verb 枚举固定：`list | get | add | delete | rotate | export`。其余一律
  `exit 2`（校验失败）。name 唯一自由文本，必须匹配 Phase C 正则；**不接受任何
  文件路径、命令、配置名**。
* `request_digest` = Web 侧对规范化请求体的 sha256（body 内无凭据，digest 可入审计）；
  `idempotency_key` 由 Web 透传给特权账本（§6.9）。
* 退出码：`0` 成功；`2` 校验失败；`3` 冲突（duplicate/reserved/not_found/
  inconsistent/idempotency_conflict）；`4` 锁不可用（fail-closed）；`5` candidate
  被拒（未触盘）；`6` 提交后回滚成功；`7` 回滚需人工；`8` 导出不可用；`10` 内部错误。
  HTTP 映射由 Web 适配层按 §3.7 完成。
* `stage` 枚举与事务阶段一一对应：
  `pre_lock | lock | audit | candidate | check | backup | replace | reload | health |
  rollback | rollback_manual | yaml_gen | spool | idempotency`。
* **stderr/journal 约束**：helper stderr 只允许出现错误码 + 阶段 + 无害上下文
  （路径、name）；任何凭据、YAML 片段、分享 URI 一律禁止（E3-T29 扫描）。

### 4.3 add 事务流程（Create，逐阶段）

```text
0  pre_lock   helper 重校验 verb/name/正则/reserved/参数形状（不信任 Web）；
              幂等账本查询（§6.9：done+同digest → 直接 replay；in_flight → 调和）
1  lock       flock config.lock，**fail-closed**：不可用/失败/超时 → exit 4，
              此后任何阶段都不执行，配置零修改
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
6  幂等落账   【锁内】账本 intent → done + 结果（先于锁释放，§6.9）
7  yaml_gen   【锁内，提交成功后】render_client_yaml（silent）写
              /root/sbox/clients/<name>/mihomo.yaml（0700/0600，代理显示名
              ${name}-Reality / ${name}-HY2，带 credential_version 头注释）；
              失败不回滚服务端 → yaml_available:false
8  registry   写入 created_at / credential_version=1 / source=web（失败静默降级）
9  audit      JSONL 追加（§8.4），释放锁
```

### 4.4 delete 事务流程

```text
0  pre_lock   reserved 复核（legacy 硬拒）；幂等账本查询/调和
1  lock       flock，fail-closed（同 §4.3 步骤 1）
2  live 复核  一致性审计（不一致 → 禁止一切破坏性操作，与 Phase C 同）；
              双 inbound 同时存在才允许删（缺一 → 409 config_inconsistent 引导先修复）
3  candidate  jq 从两个 inbound 同时 map(select(.name != $name))
4  commit     commit_server_config（失败 → §6.4，派生目录保持不动）
5  幂等落账   【锁内】done
6  派生物     仅在提交成功后 rm -rf /root/sbox/clients/<name> + 注册表条目
7  audit      JSONL
```

### 4.5 rotate 事务流程（E3-0 新增 `rotate_client` / `_rotate_client_locked`）

```text
0  pre_lock   reserved 复核（legacy 硬拒）；账本查询：若 in_flight 且
              digest 匹配 → 读 old_cred_digest 备用（§6.9 调和）
1  lock       flock，fail-closed
2  live 复核  一致性审计 + 双 inbound 同时存在；
              计算 old_cred_digest = sha256(当前 uuid + "\n" + 当前 password)
              （单向摘要，不泄漏凭据本身；供失联重试调和用）
3  creds      生成新 UUID-A' 与 password-A'（断言 != 旧值）
4  candidate  jq 原地替换该 name 的 .uuid（vless-in）与 .password（hy2-in）；
              name / flow / 其他用户零改动
5  commit     commit_server_config "rotate client <name>"
              └ reload/健康失败 → 回滚 → 新旧凭据都未生效，重试安全（§6.4 R2）
6  幂等落账   【锁内】done（先于锁释放）
7  yaml_gen   【锁内】render_client_yaml 再生整份派生 YAML
              （credential_version+1 写入头注释）；失败 → 服务端新凭据已生效、
              canonical 陈旧 → 后续 export 自愈/409（§3.3）
8  registry   rotated_at / credential_version+=1
9  audit      JSONL（只记"已轮换"，永不记新旧凭据值）
```

### 4.6 export/download 流程（GET /download/{token} 背后，rev2）

```text
POST /export 的 helper 部分（verb=export）：
0  pre_lock   reserved 复核（legacy → 403）
1  lock       flock，fail-closed（短暂持有）
2  live 复核  双 inbound 存在 + 一致性审计
3  get_client_credentials（共享库原函数）
4  陈旧检测：注册表 credential_version vs canonical YAML 头注释
    ├ 匹配且文件存在 → 复用
    ├ 缺失/不匹配   → 锁内 render_client_yaml（silent，零 stdout 泄漏）
    └ 再生失败      → 409 yaml_unavailable
5  spool      生成 256-bit token；写 /var/lib/sbox-cm/spool/<token>.yaml（0640
              root:sboxweb）+ <token>.meta.json（session 指纹、name、created_at、
              expires_at、bytes、credential_version）；临时文件 + rename，
              任何失败清理无残留（F13）
6  清扫       惰性清理已过期 spool 文件（每次 export 顺带执行）
7  stdout     {"ok":true,"data":{"token":"…","expires_in":300,…}}（token 仅出现在
              此 JSON 中——它是发给 Web 的能力凭证，不是服务端凭据；
              stderr/journal/audit 只允许 token 指纹前缀）
8  audit      name + 字节数 + token_fp（无内容、无全 token）

GET /download/{token}（Web 进程自身完成，不再调用 helper）：
  读 spool meta → 校验 session 绑定 + expires_at → 流式发送（§3.3 头）→
  删除 .yaml 与 .meta → 之后的重放天然 410 token_used
```

### 4.7 Locking contract（rev2 新增；review follow-up #2 / #9）

**现状如实陈述（fail-open，不可宣称）**：Phase C `with_client_lock()` 在
(a) `flock` 命令不存在、或 (b) 锁文件打开/`flock` 获取失败时，仅
`warning "无法获取配置锁 ($SB_LOCK_FILE)，单机低并发场景下继续执行"` 然后**照常执行**
被包装的 mutation。因此 **当前系统不存在 CLI+Web 的严格全局串行化**，rev1 若作此宣称
即为错误。在 E3-0 修复之前，任何并行 CLI mutation 与 Web mutation 之间都可能出现
lost update —— 这正是 review 指出的 concurrency blocker（follow-up #9）：只要还有
任何一条 mutation path 可以在锁失败后继续执行，Web 侧锁再严格也不构成全局事务保证。

**E3 锁契约（不变量，进入实现验收）**：

```text
L1  全局唯一互斥点：/root/sbox/config.lock 的排他 flock；所有 mutation path
    （install.sh CLI 菜单 + helper 全部 verb）都必须经它。
L2  fail-closed：flock 命令缺失 / 锁文件打开失败 / flock 获取失败 / 等待超时
    （helper -w 15s）→ 一律错误退出（CLI 非零 rc；helper exit 4 → HTTP 423），
    在 candidate 创建、备份、任何写入之前中止。锁失败必须不修改 config（字节不变）。
L3  修复点在共享库：with_client_lock 的 warn-and-continue 分支被删除（E3-0），
    CLI 与 Web 因共用同一函数而同时获得 strict semantics——不存在"只修 Web"的选项。
L4  commit_server_config 维持现状：自身不加锁，由调用方持锁（该前提从"约定"升级为
    由 L2/L3 在所有调用点上强制成立）。
L5  读路径：helper 全部 verb 持锁（§6.8 撕裂读）；CLI 交互式只读显示（list_clients）
    维持无锁现状——display-only，无写风险，不阻塞管理员观察系统。
L6  Web 层不得自行实现第二把锁/队列来"补"全局保证；信号量仅用于请求背压（§6.7）。
```

验收：E3-T26（锁获取失败 → 423 + 配置字节不变）、E3-T27（flock 缺失 → CLI 菜单与
helper 的 mutation 全部拒绝）、E3-T28（长持锁 → 超时拒绝且无 candidate/备份残留）。

---

## 5. 凭据处理（credential handling，rev2 强化）

```text
生成：sing-box generate uuid / generate rand --hex 16（Phase C 同源；请求体永不携带凭据）
存在：sbconfig_server.json（事实源）；clients/<name>/mihomo.yaml（canonical 派生，
      root-only）；spool/<token>.yaml（一次性下载副本，root:sboxweb 0640）；
      helper/Web 进程内存中的瞬态（请求结束即释放）
禁止（rev2 全通道扩展）：
      helper stdout / stderr / journald（sudo 只记命令行，argv 为空故天然安全）/
      两份审计 / 错误 detail / 任何 API 响应（除 §3.3 下载响应体）/ 注册表 /
      幂等账本（除单向摘要）/ 会话存储 / 浏览器缓存
越界通道：凭据字节从特权侧到 Web 的唯一通道 = spool 文件（§4.6）；
      helper 到 Browser 的响应中永不出现 YAML 字节
```

**credential-silent 渲染（review follow-up #3）**：现 `generate_client_configuration()`
的"打印 `vless://$uuid@…` / `hysteria2://$password@…` 分享链接"行为对 Web 链路是
不可接受的泄漏面。E3-0 在共享库内拆分：

```text
render_client_yaml <outfile>   # silent 核心：读配置/state → 写 YAML 文件；
                               # stdout/stderr 零凭据、零 URI；helper 唯一入口
generate_client_configuration  # CLI 交互包装：调 render_client_yaml 后按现状打印
                               # 链接（人机路径，行为与今天逐字节一致 → C 回归不变）
```

硬性卫生断言（E3-T16/T29）：对所有 API 响应、helper stdout/stderr、journald 采样、
两份审计日志做正则扫描（UUID 形状、`uuid:`、`password:`、`private`、`private_key`、
`vless://`、`hysteria2://`、YAML 片段），命中即构建失败。API 永不返回 private key ——
Reality 私钥根本不在任何 API 路径上（它只存在于服务端配置与 `SB_STATE_FILE`，
Web 无读权限）。允许出现的唯一派生值：单向摘要（`old_cred_digest`、token 指纹），
sha-256 不可逆，不入审计的仅限摘要与指纹。

---

## 6. 专项详细设计

### 6.1 Create — 见 §4.3；错误路径全落 §3.7；响应字段与任务书逐字一致。

### 6.2 Delete — 见 §4.4；危险操作 UX 契约见 §7.3。

### 6.3 Duplicate name

* 请求侧：锁内 `client_name_exists` 以 live 配置复核（Phase C 原语义：任一 inbound
  命中即拒绝）→ `409 duplicate_name`，服务端配置字节不变。
* Web 侧可选预检（减少无谓的 sudo 调用）不算权威，**判定永远在锁内**。

### 6.4 Partial failure / Reload failure / Health failure / Rollback（矩阵，rev2 扩充）

| # | 失败点 | 磁盘状态 | 服务状态 | helper | HTTP | 后续 |
| --- | --- | --- | --- | --- | --- | --- |
| F1 | name/形状/reserved（pre_lock） | 不变 | 不变 | exit 2/3 | 422/403 | 无 |
| F2 | 锁不可用/获取失败/**超时**（fail-closed） | **不变（字节级）** | 不变 | exit 4 | **423 lock_unavailable** | 稍后重试；无 candidate/备份残留（E3-T26/28） |
| F3 | live 配置 JSON 非法 / 一致性审计失败 | 不变 | 不变 | exit 3 | 409 config_inconsistent | 先跑 CLI 一致性检查 |
| F4 | candidate 生成失败 / candidate 审计失败 / `sing-box check` 失败 | 不变（candidate 被删，live 未动） | 不变 | exit 5 | 500 candidate_rejected | 附审计问题行；系统完好 |
| F5 | 备份失败 / 原子 mv 失败 | live 不变；备份保留 | 不变 | exit 5 | 500 commit_failed | 系统完好，可重试 |
| F6 | reload 失败 | **已自动回滚**（备份覆盖回 live + 再次 reload） | 已恢复 | exit 6 | **503 commit_rolled_back** | 可安全重试 |
| F7 | 健康检查失败（reload 成功但进程死） | 同 F6 回滚 | 已恢复 | exit 6 | **503 commit_rolled_back** | 可安全重试 |
| F8 | 回滚后再 reload/健康仍失败 | 回滚文件已就位 | **未确认恢复** | exit 7 | 500 rollback_manual_intervention | **禁止盲目重试**，人工按备份恢复；审计 CRITICAL |
| F9 | 提交成功后 yaml_gen 失败 | 服务端已生效 | 正常 | ok + warning | 201 + `yaml_available:false` | 下次 export 自愈（§3.3） |
| F10 | 提交成功后 registry 失败 | 服务端已生效 | 正常 | ok + warning | 201（元数据为 null） | 顾问性，无影响 |
| F11 | export 再生失败 | canonical 可能保留旧版 | 正常 | exit 8 | 409 yaml_unavailable | 重试/人工检查 clients 目录 |
| F12 | **flock 二进制缺失（E3-0 后）** | **不变** | 不变 | exit 4 | 423 lock_unavailable | CLI 菜单 mutation 同样拒绝（L3）；修复依赖 |
| F13 | **spool 写入失败** | 无部分 spool 文件（临时+rename，失败即清理） | 正常 | exit 8 | 500 export_failed | canonical 未受影响，可重试 |
| F14 | **HTTP response 丢失（事务已成功）** | 已提交 | 正常 | done 已落账 | 客户端只见超时 | **同 Idempotency-Key 重试 → replay 原结果，不二次变更**（§6.9，E3-T30） |
| F15 | **token 重放（已下载）** | spool 已清理 | 正常 | n/a | **410 token_used** | 重新 POST /export |
| F16 | **token 过期** | sweeper 已清理 | 正常 | n/a | **404 token_expired** | 重新 POST /export |

R1：F4–F8 全部复用 `commit_server_config` 现有语义（该函数已实现备份保留、
fail-closed 审计、回滚后二次健康确认），E3 只做错误码映射，不改事务内部。
R2：rotate 的 F6/F7 语义 = "轮换从未发生"（新凭据只存在于被回滚的 candidate 里），
因此 rotate 失败后重试是幂等安全的。
R3：create 的 F6/F7 同理 = "客户端从未存在"；delete 的 F6/F7 = "客户端仍然完整存在，
派生目录保持"（Phase C 原有保证）。
R4（rev2）：F2/F12 是 fail-closed 的直接推论——锁失败的失败模式是"什么都不做"，
而不是"没锁也做"。

### 6.5 Legacy protection（已定案 A-1：Web list-only）

| 操作 | legacy 的结果 |
| --- | --- |
| POST create name=legacy | `422 reserved_name` |
| POST rotate legacy | `403 reserved_client` |
| DELETE legacy | `403 reserved_client` |
| POST legacy/export | `403 reserved_client`（**默认不允许 Web 凭据导出**） |
| GET 列表/详情 | `200`，`reserved:true, mutable:false`（Monitor 照常显示 legacy 流量） |

双层防御：Web 中间件拦截 + helper 内部再次硬校验（镜像 Phase C
`_delete_client_locked` 的锁内二次防护）。`legacy` 的 Retirement 属于未来独立功能，
v1 一律拒绝。CLI 路径能力不变（本设计不收紧既有 CLI 行为）。

### 6.6 Partial failure（服务端成功、派生物失败）

见 F9/F10。原则：**服务端事务边界之内是原子的；边界之外的派生物允许最终一致**。
`yaml_available:false` + `warnings[]` 是契约的一部分，Web UI 需显示降级提示，
且导出路径具备自愈能力。

### 6.7 Concurrent requests（rev2 重写）

* 全局保证 = **唯一互斥点 + fail-closed（§4.7）**。E3-0 修复前，CLI（fail-open 现状）
  与 Web 之间不存在全局串行化——这是验收 blocker：E3-0 不落地，E3-1..E3-4 不得开始
  （review follow-up #9 的正面回答）。
* helper `flock -w 15`（超时 → exit 4 → 423）；Web 适配层再加进程内 semaphore(1) +
  30s 上限，避免请求堆积（仅背压用途，不充当全局锁，L6）。
* **请求内重读原则**（Phase C 原文："every judgement below re-reads the LIVE config"）：
  一切判定（存在性、一致性、reserved）都在锁内对 live 配置重新做出，
  先到的请求胜出，后到的从胜者状态出发，绝不基于陈旧快照写入（no lost update）。
* 并发结果示例：10 个并发 create 同名 → 恰好 1 个 201，其余 409；最终配置合法且
  只有一个该用户（E3-T10）。

### 6.8 读取一致性

`mv` 原子替换保证读者要么看到旧文件要么看到新文件，永远完整。但
"uuid 与 password 分两次 jq 读"可能横跨一次 rotate 提交 → 撕裂读。因此
**export 与 list 同样在锁内执行**（§4.1）；锁持有时间为毫秒级，v1 单管理员场景
无性能顾虑。rev2 补充：即便如此，spool 快照进一步把"下载内容"冻结为签发时刻的
完整副本——下载阶段（锁外）永远不可能读到撕裂内容（E3-T12 断言配对一致）。

### 6.9 Idempotency（rev2 重写：特权侧持久账本）

review follow-up #8 要求覆盖"transaction 已成功但 HTTP response 丢失"——这排除了
rev1 的"Web 进程内存"方案（Web 崩溃即丢账 → 二次 rotate）。账本因此上移到特权侧，
与事务同一信任域、同一把锁管理：

```text
存储：/root/sbox/web/cm-ledger.jsonl（root 0600，append-only；GC 由 helper 在锁内做）
记录：intent  = {key, verb, name, request_digest, state:"in_flight",
                 old_cred_digest(仅 rotate), ts, request_id}
      outcome = {key, state:"done", result(非凭据字段), ts}
时序：intent 写于锁内、事务开始前；outcome 写于锁内、锁释放前（F14 的窗口被
      收敛到"提交成功但 outcome 未写"——由调和逻辑闭合，见下）
TTL：24h；过期记录在锁内 GC（compaction：同名 key 只留最新状态）
```

请求匹配规则（helper 在锁内执行）：

| 账本状态 | digest 匹配 | 行为 |
| --- | --- | --- |
| 无记录 | — | 正常执行（写 intent → 事务 → 写 outcome） |
| done | 匹配 | **replay**：返回落账的原始 result，附头 `Idempotency-Replayed: true`，零事务 |
| done | 不匹配 | `422 idempotency_conflict` |
| in_flight | 不匹配 | `422 idempotency_conflict` |
| in_flight | 匹配 | **调和**（崩溃/失联恢复）： |

调和规则（digest 匹配 + in_flight，锁内）：

| verb | live 状态判据 | 结论 |
| --- | --- | --- |
| create | name 已存在于配置 | 上次事务已提交 → 合成成功 result（落 done），零重复创建 |
| create | 不存在 | 上次事务未发生 → 重新执行 |
| delete | name 不存在 | 已删除 → 合成成功 result，零重复删除 |
| delete | 存在 | 重新执行 |
| rotate | 当前 cred 摘要 == intent.old_cred_digest | 轮换未发生 → 重新执行 |
| rotate | != old_cred_digest | 轮换已生效 → 合成成功 result（落 done），**绝不二次轮换** |

* `old_cred_digest` = sha256(旧 uuid + "\n" + 旧 password)，单向不可逆，仅存于
  root-only 账本，不入审计、不入任何响应（§5 白名单）。
* create/delete 天然幂等但统一走账本（简化心智模型 + 统一审计）；
  export 不要求 Idempotency-Key（多签发一个 token 无害，旧 token 自然过期）。
* Web 重启不丢账本（磁盘文件）；Web 必须原样透传重试请求中的同一 key。
* 同 key 的**指纹**（sha256 前 8 位）进入审计，便于事后核对重放次数（E3-T31）。

### 6.10 Audit log

见 §8.4（两层审计 + schema + 禁记内容清单）。

---

## 7. Rotate / Delete 危险操作语义（danger-zone 契约）

### 7.1 触发链（E3 定义，E2 呈现）

```text
Clients 行 → Rotate / Delete（红色 danger-zone 区域）
→ 模态框：
   · 后果明示（rotate：Reality+HY2 凭据同时轮换、整份 YAML 立即失效、
     所有设备断线、必须重新下载；delete：双协议凭据同时移除、
     Monitor 不再统计该设备）
   · type-to-confirm：必须逐字输入客户端名（= body.confirm）
   · step-up：距上次重认证 > 300s → 先弹密码重认证（401 reauth_required 驱动）
→ POST（rotate 必带 Idempotency-Key）
→ 结果页：rotate 成功后立即高亮"重新下载 YAML"入口（重新走 §3.3 两步流程）
```

### 7.2 Rotate 后旧 YAML 失效的硬契约（已定案 A-2 口径：整份失效）

* 服务端凭据在事务提交瞬间即已双双轮换 → 任何**此前下载**的 YAML 立即整体失效；
* API 返回 `yaml_invalidated:true` + `warning` + 新 `credential_version`；
* Web UI 必须：(a) rotate 前在模态框写明"整份 YAML 失效"（不做单协议部分失效的
  表述）；(b) rotate 成功页显著提示"旧 YAML 已失效，请重新下载"；客户端列表中
  `rotated_at` 晚于用户上次下载时间时显示"YAML 已过期"角标（下载时间由前端
  localStorage 记录，不进服务端契约）；
* canonical YAML 在 rotate 事务后立即整份再生（credential_version+1 头注释），
  `X-Credential-Version` 头 + YAML 头注释让旧文件可被用户自己识别。

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
* UI 收到该码 → 弹密码重认证 → 成功后自动重放原请求（confirm/Idempotency-Key 不变，
  digest 不变 → 账本语义一致）；
* helper 不参与 step-up（它无法验证密码），信任边界 = "Web 中间件保证 5 分钟内
  人工在场"；helper 侧补偿：审计中记录 actor session，便于事后追责。

### 8.3 CSRF（rev2：GET 不再承担自定义头）

| 层 | 措施 |
| --- | --- |
| Cookie | 会话 cookie `HttpOnly` + `SameSite=Strict`（+ `Secure`，若未来上 TLS 反代） |
| Token | **变更请求（POST create/rotate/delete/export）** 要求 `X-CSRF-Token`（double-submit，E2 签发） |
| Origin | 变更请求校验 `Origin`/`Referer` ∈ 允许集（loopback host）；`Sec-Fetch-Site: cross-site` 一律拒绝 |
| Content-Type | 写请求强制 `application/json`（表单跨站无法伪造 JSON 内容型请求） |
| 下载 GET | **不依赖自定义头**：一次性 256-bit token（不可枚举）+ 单次使用 + TTL 300s + 会话绑定（meta 内 session 指纹，下载时校验 cookie）构成防护；`Referrer-Policy: no-referrer` 抑制 token 经 Referer 泄漏；token 单次使用后即使泄漏也已失效 |

### 8.4 审计

两层，各司其职：

1. **Web 审计（E2 拥有）**：请求层 —— method、path、actor session、source_ip、
   CSRF 结果、HTTP 状态、时延、request_id、token 指纹（签发/下载/重放事件）。
2. **特权审计（E3，helper 追加）**：事务层 —— JSONL
   `/root/sbox/web/audit/cm.jsonl`（0600，root）：

```json
{ "ts": "2026-09-12T11:00:00Z", "request_id": "b7c9…", "actor": "web-session:a1f3…",
  "verb": "rotate", "name": "vmix-01", "outcome": "ok", "stage": "commit",
  "backup": null, "rolled_back": false, "credential_version": 2,
  "lock_wait_ms": 3, "confirm_echo": true, "idempotency_key_fp": "9af1…",
  "idempotency_replayed": false }
```

禁记清单（两层共同）：UUID、password、private key、YAML 内容、完整配置、
凭据分享 URI、**token 全文**（仅指纹）。导出事件只记 `name + bytes + token_fp`。
`outcome ∈ ok|rejected|rolled_back|manual_intervention|replayed`，
`manual_intervention` 级别为 CRITICAL。

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
  （GitHub 删除仓库范式）+ step-up auth（Google 风格）；一次性下载 token 模式
  （各类"导出报表"的标准做法）。
* **明确不采用 Clash REST 配置修改模型**：Clash 允许 `PUT/PATCH /configs`
  直接改运行时配置 —— 本项目拒绝该形态：HTTP 层永远没有"改配置"的能力，
  只有"请求一个事务"的能力；服务端配置的合法写入口只有 Phase C 事务。

## 9.4 Residual risks（如实声明，rev2 更新）

1. Web 进程被完全攻破 ⇒ 攻击者可调用 5 个 operation（含签发导出 token、删客户端）。
   缓解：极小攻击面、仅回环、无公网、审计完备、step-up 抬高自动化利用成本、
   rotate/delete 有 Idempotency-Key + confirm 双闸。无法根除，属于"面板类"系统固有风险。
2. 特权 helper（root，短命）自身漏洞即 root 漏洞。缓解：单 binary、代码极小、
   入参仅 stdin JSON 且 schema 固定、无 argv、无 eval、无动态路径、sudoers
   `env_reset`、静态扫描 + 测试覆盖。
3. spool 文件是磁盘上的临时凭据副本（root:sboxweb 0640、TTL 300s、下载即删、
   惰性清扫兜底）。风险窗口 = 签发后未下载期间本机 sboxweb 组用户可读。
   单管理员 VPS 上可接受；不接受时可改为 helper 落盘 0600 + Web 经特权流式读取
   （但那会把 YAML 引回 helper stdout，被 review 规则禁止——故 v1 维持 spool）。
4. 下载 token 是 5 分钟内单次有效的 bearer 能力：泄漏窗口内可被本机进程抢先下载
   （它还需要有效会话 cookie——meta 绑定使窃取 token 而无 cookie 亦不可用）。
5. 127.0.0.1 明文 HTTP：本机其他本地用户可嗅探回环流量（单管理员 VPS 上可接受；
   未来可加 TLS 反代，属 E2 范畴）。

---

## 10. 决策记录

### 10.1 已定案（本轮 review，不再开放）

| # | 决策 |
| --- | --- |
| A-1 | **legacy = Web list-only**：GET 可见（reserved/mutable 标记），delete/rotate/credential export 一律 403；retirement 属未来独立功能 |
| A-2 | **rotate = Reality + HY2 一次性共同旋转**，不做按协议拆分；整份 YAML invalidated |
| A-3 | **下载 = POST /export → one-time token → GET /download/{token}**（取代 rev1 的 GET mihomo.yaml） |
| A-4 | **单个 narrow helper**（root-owned、固定 operation、严格 stdin schema、无 argv）；多 binary 否决（理由见 D3） |
| A-5 | **共享事务库 lib/client-management.sh**；禁止 source 整个 install.sh / 运行时截取 phase-c 块 / 两套事务实现 |
| A-6 | **锁契约 fail-closed**，修复 Phase C fail-open 现状，CLI+Web 全 mutation path 生效（§4.7） |
| A-7 | **幂等账本在特权侧持久化**（intent/outcome + digest + 调和），覆盖失联重试（§6.9） |

### 10.2 未决决策（需后续 review 定案）

| # | 决策 | v1 建议 | 备选 |
| --- | --- | --- | --- |
| U-1 | 注册表文件位置/格式 | `/root/sbox/web/client-registry.json`，单 JSON | 每客户端 `meta.json` 放 clients 目录 |
| U-2 | E2 认证/会话接口细节（cookie 名、re-auth 端点形态） | E3 只依赖 §8.1 的 `client_ctx` 注入契约，具体归 E2 | — |
| U-3 | 审计是否合并为一份 | 保持两层（Web/事务职责不同） | 单一 JSONL 双 writer |
| U-4 | 变更限流阈值 | 10 次/分钟/IP（防误触脚本） | 不限（单管理员） |
| U-5 | 备份保留策略 | 维持 Phase C 现状（不清理） | 引入保留 N 份/GC（独立小任务） |
| U-6 | API 错误 message 语言 | 英文 code + 英文 message（程序消费），UI 层本地化中文 | 双语 message |
| U-7 | step-up 窗口 | 300s | 120s / 600s |
| U-8 | 下载 token TTL / spool 清扫策略 | TTL 300s；每次 export 惰性清扫（无常驻 timer） | systemd timer 定期清扫；TTL 缩至 60s |

---

## 11. E3 实施阶段（每阶段独立可测，全部尚未实现）

| 阶段 | 交付物 | 测试闸门 |
| --- | --- | --- |
| **E3-0**（纯 Phase C/CLI 范畴，Web 零代码） | (a) phase-c 块机械抽取为 `lib/client-management.sh`（函数体字节级不变；install.sh 改为 source 该库；`tests/test-phase-c.sh` 改为直接 source 库，断言集合不变）；(b) `with_client_lock` 改 fail-closed，删除 warn-and-continue（全部 mutation path 生效）；(c) `generate_client_configuration` 拆分为 silent 核心 `render_client_yaml` + CLI 交互包装（CLI 输出行为不变）；(d) 新增 `rotate_client`/`_rotate_client_locked`（双协议共同旋转） | C 回归全套 + `bash -n` + shellcheck 全绿（抽取不变性）；新增锁契约测试 E3-T26/27/28；rotate 测试；silent 渲染零泄漏测试 |
| **E3-1** | 单个特权 helper `sbox-cm`（bash）：stdin schema、verb 枚举、JSON 协议+退出码、spool 导出、幂等账本（intent/outcome+调和）、JSONL 审计、sudoers（单规则 + env_reset） | 沙箱（SB_* 覆盖 + mock sing-box/systemctl，直接非 sudo 调用）逐 verb 契约测试；E3-T29 输出通道卫生扫描 |
| **E3-2** | Web 适配层（薄，非特权）：HTTP ↔ helper 映射、§3.7 错误码表、CSRF/step-up 挂钩（对接 E2 `client_ctx`）、POST /export 签发 | API 契约测试（mock helper 进程）+ §3.7 全表 |
| **E3-3** | 下载与 UX 契约：GET /download/{token}（spool 流式 + 一次性 + TTL + 会话绑定）、rotate 失效横幅/角标字段、导出降级提示 | E3-T20/33/34/35/36；撕裂读断言 E3-T12 |
| **E3-4** | 硬化：失败注入（F1–F16）、并发 canary、凭据卫生全通道 grep、审计 schema 校验、文档刷新 | §12 全矩阵绿 + 生产 canary（仅 VPS 侧人工执行，见约束） |

依赖关系：**E3-0 是全局前置（锁 fail-closed 是 E3-1..E3-4 的验收 blocker）**；
E3-1 依赖 E3-0；E3-2 依赖 E3-1 与 E2 的中间件接口（U-2）；E3-3/E3-4 依赖 E3-2。

---

## 12. 测试矩阵（v1 必须全绿的集合；命名 `E3-Txx`）

| ID | 场景 | 断言 |
| --- | --- | --- |
| E3-T01 | create happy path（reality+hy2） | 201；两个 inbound 各新增 `{name,uuid,password}`；YAML 含 `${name}-Reality`/`${name}-HY2`；响应体与任务书字段一致 |
| E3-T02 | duplicate name | 409；配置字节不变；无备份残留 |
| E3-T03 | 非法 name（`vmix 01`、`../../x`、`a/b`、空、`-leading`、33 字符、`legacy`） | 422/422 reserved；配置不变 |
| E3-T04 | legacy：create/rotate/delete/export | 422/403/403/403；legacy 在配置中原样存在；GET 可见 `reserved:true, mutable:false` |
| E3-T05 | delete 成功 | 双 inbound 移除；`clients/<name>/` 删除；注册表清理；审计 ok |
| E3-T06 | rotate 成功 | name 不变；uuid/password **同时**变更；`credential_version`+1；整份 YAML 再生且头注释版本一致；Monitor 身份 = user.name 不变 |
| E3-T07 | rotate 遇 reload 失败 | 503 commit_rolled_back；配置=旧凭据；YAML 未动；重试安全 |
| E3-T08 | create/delete 遇健康检查失败 | 503；create→客户端不存在；delete→客户端完整存在+目录未删 |
| E3-T09 | 回滚后仍不健康（注入回滚 reload 失败） | 500 rollback_manual_intervention；审计 CRITICAL |
| E3-T10 | 10 并发同名 create | 恰好 1×201、9×409；配置只有一个该用户且合法 |
| E3-T11 | 锁被长持时变更请求（helper 路径） | 423 lock_unavailable；锁空闲后正常 |
| E3-T12 | rotate 与 export 并发 | 导出 spool 快照为完整旧版或完整新版 YAML（uuid-password 配对一致），永不撕裂 |
| E3-T13 | 幂等 replay：同 key 同 digest（done） | 返回原结果 + `Idempotency-Replayed:true`；零第二次事务 |
| E3-T14 | CSRF：无 token / 错 Origin / 表单编码 / export POST 无头 | 403 / 403 / 415 / 403 |
| E3-T15 | step-up：auth_age > 300s 的 rotate/delete | 401 reauth_required；重认证后重放成功 |
| E3-T16 | 凭据卫生（响应与审计） | 所有 API 响应 + 两份审计日志中 grep UUID/password/private/YAML 形状 = 0 命中 |
| E3-T17 | 认证态隔离 | 改 admin password、whitelist、recovery key 前后 YAML 字节相同；期间无 config.lock 竞争 |
| E3-T18 | yaml_gen 注入失败 | 201 + `yaml_available:false` + warnings；后续 export 自愈成功 |
| E3-T19 | CLI（mianyang）创建的客户端 | 出现在 GET /clients，`source:"cli"`、时间戳 null |
| E3-T20 | 下载响应头 | attachment 文件名、no-store、nosniff、Referrer-Policy、X-Credential-Version |
| E3-T21 | 注入坏 candidate（重复 uuid） | 500 candidate_rejected；live 配置未动；审计含问题行 |
| E3-T22 | 失败路径残留检查 | 所有 F1–F16 后无 candidate/临时文件残留（备份按 Phase C 语义保留；spool 失败无部分文件） |
| E3-T23 | 一致性审计失败时写操作 | 409 config_inconsistent；GET 照常返回 + `consistency_problems` |
| E3-T24 | 审计 schema | 每条 JSONL 可解析、字段齐、无禁记内容（含 token 全文） |
| E3-T25 | （可选 canary）VPS 生产：create→真实连接→E1 Device= vmix-01→rotate→旧 YAML 断、新 YAML 通→delete | 全链路身份与事务语义 |
| E3-T26 | **锁获取失败（helper mutation）** | exit 4 → 423 lock_unavailable；配置字节不变；无 candidate/备份残留 |
| E3-T27 | **flock 二进制缺失** | **CLI 菜单 mutation 与 helper mutation 全部拒绝执行**；配置字节不变（L3 全路径 fail-closed 验收） |
| E3-T28 | 锁长持超时（> -w 15s） | 拒绝；无任何写入痕迹；锁释放后重试正常 |
| E3-T29 | **helper 输出通道卫生** | stdout/stderr/journald 采样/审计/error detail 中 grep UUID/password/`vless://`/`hysteria2://`/YAML 片段 = 0 命中（含 export 与失败路径） |
| E3-T30 | **HTTP response 丢失后重试** | rotate 提交成功、响应丢失；同 Idempotency-Key 重试 → replay 原结果；服务端恰好一次轮换（审计单条 rotate、credential_version 总增量 = 1） |
| E3-T31 | 同 key 重复提交（显式双击） | 第二次 replay，不轮换；同 key 异 payload → 422 idempotency_conflict |
| E3-T32 | 调和：in_flight 残账（模拟 Web 崩溃于提交后） | create/delete 按 live 状态合成或重跑；rotate 按 old_cred_digest 判定，绝不二次轮换 |
| E3-T33 | **export token 重放** | 首次下载成功后同 token 再取 → 410 token_used；spool 文件已删除 |
| E3-T34 | **export token 过期** | TTL 后请求 → 404 token_expired；惰性清扫已删除文件 |
| E3-T35 | spool 卫生 | 下载/失败/清扫后无残留文件；目录 0750 root:sboxweb、文件 0640；过期文件不累积 |
| E3-T36 | Web 重启后下载 | TTL 内 token 仍可用（spool 持久）；一次性/过期语义不变 |

---

## 13. 显式非目标（Non-goals）

1. **不实现 E2**（Dashboard UI、登录页、会话存储本身）；E3 只定义并消费其中间件契约。
2. **NAS 集成完全不在范围内**：用户自行下载 YAML 放到 NAS，服务端不感知 NAS。
3. 不开任何公网端口 / 不做 TLS 终结 / 不改 VPS 网络与防火墙。
4. 不修改 `sbconfig_server.json` 的任何 schema、inbound 结构或现有用户；
   不在本轮触碰生产配置（本文档为零生产变更）。
5. 不写任何 client mutation 生产实现（本轮连 E3-0 的抽取/rotate 代码也不落地）。
6. 不 reload/restart sing-box（reload 只存在于未来实现的事务内部，设计文本除外）。
7. 不采用 Clash REST 配置修改模型；不新增任何直接写 JSON 的代码路径。
8. 不做多管理员/RBAC/多租户；不做单协议独立轮换（A-2 已定案为共同旋转）；
   不做 YAML 以外的导出格式（sing-box 客户端 JSON、分享链接列表等留待后续）。
9. 不改 E1 collector（身份模型、gRPC-Web 桥、生命周期语义均不动）；
   不做流量历史持久化/数据库。
10. 不管理 whitelist / admin password / recovery key（E2 范畴）；
    不做备份 GC（U-5 留待独立决策）。
11. 不做 E1/E2 已有代码的重构或"顺手优化"。
12. 不做分布式/跨机锁、不做 helper 常驻 daemon（短命进程即可满足 v1 并发模型）。

---

## 14. 本轮交付核对

* 设计文档：本文档 rev2（`docs/monitor-v2-e3-design.md`），architecture / API
  contract / Phase C 事务桥 / credential handling / YAML 生成与下载模型 /
  rotate-delete 语义 / 并发与锁契约 / 回滚失败矩阵 / 授权-CSRF-审计 /
  E3 阶段 / 测试矩阵 / 非目标 —— 12 项齐备。
* 提议 API：六类操作对齐任务书；凭据下载按 review 升级为
  `POST /export → GET /download/{token}` 两步流；另附错误码总表与导出安全头。
* 事务边界：§4（唯一互斥点 config.lock + fail-closed；唯一写路径 = 共享库
  `lib/client-management.sh` 的 Phase C 事务；读也过锁防撕裂；spool 快照兜底）。
* 安全边界：§2 权限表 + §4.7 锁契约 + §5 凭据全通道禁令（含 silent 渲染与 spool）
  + §8 授权/CSRF/审计 + §9.4 residual risks。
* 已定案决策：§10.1（A-1…A-7）；未决：§10.2（U-1…U-8）。
* 生产变更：**无**。rev2 仍只改本文档，未改 install.sh、monitor-v2、tests 及任何配置；
  未 reload/restart sing-box。
