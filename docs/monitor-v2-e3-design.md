# Monitor v2 — Phase E3 Design: Web Client Manager（架构设计，不含实现）

状态：**设计稿 rev3（已吸收第二轮 design review，待再 review）**。
rev3 变更摘要（对应第二轮 review #1–#16；#17 保持不变项未动，#18 为交付方式）：

1. **spool 权限模型重设计（BLOCKER）**：目录 `root:sboxweb 0710`（组仅 traverse，
   不可列举）+ 文件 `0640`；Web 只获得 exact-token traversal/read，不能列举/创建/
   删除 spool 任意内容；一次性消费改由极窄 helper operation `consume_export` 完成
   （输入仅 token，固定 spool 内、无 path、无 arbitrary unlink）（§4.6、§5、§2）。
2. **Web credential boundary 精确化（BLOCKER）**：废除"Web 绝不持有 YAML 字节"的
   不可实现表述，改为：无 canonical 读权、只读已授权 exact-token spool object、
   不 parse/log/persist YAML、不进 API JSON、字节仅在 download response 生命周期
   短暂经过 Web（§5、§1.1）。
3. **统一 404（BLOCKER）**：token used/expired/unknown 一律 `404 download_unavailable`
   ——删除全部记录后服务器无法区分三者，不再为漂亮错误码维护 token oracle；
   安全属性收敛为"第二次绝不 200"（§3.3、§3.7、§4.6）。
4. **Web restart 使未决导出失效（BLOCKER）**：E2 session 为 memory-only（既定事实），
   token 绑定 session ⇒ 重启后 issuing session 不存在 ⇒ 下载永久 404；不为 E3 token
   把 E2 session 改成持久化；spool 残留由 TTL/清扫删除（§3.3、E3-T41）。
5. **digest 所有权归 helper（BLOCKER）**：删除 Web 提供的 `request_digest`；helper
   自行 parse → schema 校验 → 语义 canonicalize（verb/name/protocol-set）→ 自算
   sha256，账本匹配只认 helper 自算值（§4.2、§6.9）。
6. **create/rotate/delete 全部强制 Idempotency-Key（BLOCKER）**：缺失 →
   `400 idempotency_key_required`；delete 失联重试 + 同名重建场景是强制的主要原因
   （retry 绝不允许删掉第二代同名客户端）（§3.4–3.6、§6.9）。
7. **in-flight 调和矩阵重设计（BLOCKER）**：intent 记录 `planned_cred_digest`
   （create/rotate）与 `old_cred_digest`（rotate/delete，均 SHA-256，不记凭据）；
   current ∉ {old, planned} ⇒ `409 idempotency_reconcile_conflict`，禁止自动判成功、
   禁止覆盖/误删他人改动（§6.9）。
8. **账本 durability 定案（BLOCKER）**：intent append→flush→fsync 先于任何 mutation
   （失败 ⇒ 零变更）；outcome append→flush→fsync 先于返回成功；commit 成功但
   outcome fsync 失败 ⇒ 不回滚健康配置，返回
   `503 idempotency_state_uncertain` + "retry with SAME Idempotency-Key"（§6.9、§6.4）。
9. **done outcome 写入时机后移（BLOCKER）**：commit → yaml_gen → registry →
   构建最终非敏感 result → durable outcome → audit → unlock；replay 与首次最终结果
   逐字段一致（含 `yaml_available`/`warnings`）（§4.3/4.5、§6.9）。
10. **export 真值源 = live config（MUST FIX）**：每次 POST /export 在锁内从 live
    凭据全新渲染 spool 快照，绝不以 canonical/registry 决定下载内容；
    `credential_version` 仅 UX/advisory，registry 缺失 ⇒ null，不影响正确性（§4.6）。
11. **source 溯源修正（MUST FIX）**：仅正向证据 ⇒ `web`；否则 `untracked`；
    不再推断 "cli"（Web create 成功但 registry 写失败同样没有 registry 记录）（§3.1）。
12. **token 全链路日志脱敏（BLOCKER）**：E2 access logger 对
    `/api/v1/download/<token>` 强制改写为 `/api/v1/download/[redacted]`；审计只记
    token 指纹；测试扫描 stdout/stderr/journald fixture/Web access log/审计 JSONL，
    full token 命中 = FAIL；浏览器历史可能含 token 如实记录为 residual risk（§8.3/8.4）。
13. **helper 环境自加固（MUST FIX）**：不依赖 sudoers 文本保证安全 —— helper 自身
    `[ "$#" -eq 0 ] || exit 2`、主动 `unset SB_*`、固定 PATH/绝对路径、生产路径常量
    内嵌；测试经 test-only wrapper（非 sudo 白名单）直接注入沙箱（§1.2 D3、§4.2）。
14. **术语统一**：全文以 "固定 verb allowlist（7 个）" 取代易漂移的 "5 operations"
    （list/get/add/delete/rotate/export/consume_export）。
15. **错误码统一**：`idempotency_conflict` 全文 409；新增
    `409 idempotency_reconcile_conflict`（§3.7、§6.9）。
16. **新增设计测试**：§12 补 E3-T37–T58（spool 权限三件套、404 统一契约、restart
    失效、digest 所有权、三 mutation 强制 key、三类 reconcile conflict、ledger
    append/fsync 四失败、outcome 最终性、export live 真值、source=untracked、
    token 日志脱敏、argv/env 拒绝）。

rev2 已定且本轮 review 确认保持不变（#17）：Device = API USER / Protocol = INBOUND、
legacy Web list-only、Reality+HY2 joint rotate、fail-closed config.lock、共享
`lib/client-management.sh`、Web 非 root、narrow privileged helper、Web 不直写
`sbconfig_server.json`、无 NAS、无公网端口。

基线事实锚点（均在仓库核实）：

| 事实 | 出处 |
| --- | --- |
| 服务端单一事实源 `/root/sbox/sbconfig_server.json`；`/root/sbox/clients/` 全部是派生物 | `install.sh`（`SB_SERVER_CONFIG` / `SB_CLIENTS_DIR` 注释） |
| 事务核心：`flock → 结构审计 → candidate → sing-box check → backup → 原子 mv → reload → 健康检查 → 失败回滚` | `install.sh` `commit_server_config` |
| **`with_client_lock()` 现状 fail-open**：flock 不可用或获取失败时 warning 后照常执行 | `install.sh` `with_client_lock` |
| **`generate_client_configuration()` 现状会打印携带凭据的分享 URI**（`vless://$uuid@…`、`hysteria2://$password@…`） | `install.sh` `generate_client_configuration` 尾部 |
| 客户端命名 `^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`；`legacy` 是保留名 | `install.sh` `CLIENT_NAME_PATTERN` / `RESERVED_CLIENT_NAME` |
| Monitor 身份：`Device = API USER`（`user.name`），不可变 | `monitor-v2/README.md`、`monitor-v2/collector.py` |
| **E2 会话为 memory-only：Web restart ⇒ 全部 admin session 失效**（第二轮 review 确认的既定事实） | E2 实现（另一分支） |
| `service.api` 仅监听 `127.0.0.1:9091`，不向公网开放 | 根 `README.md` |
| `rotate` 目前不存在 | `grep -c rotate install.sh == 0` |

---

## 0. 目标 UX 与身份链（一条主线，贯穿全文）

```text
Web Dashboard
  → Clients
  → Add Client
      Name: vmix-01
      [x] Reality   [x] HY2
  → Create
  → Download Mihomo YAML（POST export → token → GET download → helper consume，见 §3.3）
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

硬性规则（rev3 更新第 5、6 条，新增第 8 条）：

1. **真实身份只来自服务端 `user.name`**。YAML 里的 `vmix-01-Reality` / `vmix-01-HY2`
   是代理条目的本地显示名，改显示名、改 YAML 排序都不影响 Monitor 归属。
2. **Web 层永远不直接 `open(...sbconfig_server.json)`**，也不手改 JSON。Web 层对
   服务端配置文件与 canonical 派生 YAML 连读权限都没有（见 §2 权限分离）。
3. 所有服务端变更必须复用 Phase C 事务模型（§4），任何绕过事务的写入路径都不允许存在；
   事务实现只有一份（`lib/client-management.sh`，§1.2 D2）。
4. `legacy` 永远是 reserved client：Web 视角 **list-only**（§7.4）。
5. **锁是 fail-closed 的**（E3-0 修复 Phase C 现状）：任何 mutation path 在锁不可用/
   获取失败时必须拒绝执行，配置零修改（§4.7）。
6. **helper 输出通道零凭据**：stdout/stderr/journal/audit/error 中不出现
   UUID / password / YAML / 分享 URI / full token；凭据字节只经受控 spool 文件越界
   （§5、§4.6）。
7. whitelist / admin password / recovery key 属于 E2 认证体系，它们的任何变化
   **不得影响**现有 Reality/HY2 YAML（§8.5）。
8. **幂等是强制的**：create/rotate/delete 必须携带 Idempotency-Key；账本由 helper
   持久化并以自算 digest 判定；调和冲突绝不自动覆盖（§6.9）。

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
│   · 认证（memory-only session）/ CSRF / 限流 / Web 侧审计（E2 提供）  │
│   · HTTP ↔ JSON contract（§3）；token 签发与 download 流式服务        │
│   · credential boundary（rev3，§5）：                                │
│     - 无 canonical /root/sbox 任何读权限                              │
│     - 只能读取已授权的 exact-token spool object（不可列举 spool）     │
│     - 不 parse YAML / 不 log YAML / 不 persist YAML / 不进 API JSON   │
│     - YAML 字节仅在 download response 生命周期内短暂经过 Web 进程      │
│   · access log 对 download path 强制脱敏为 [redacted]（§8.3）         │
└───────────────┬────────────────────────────────────────────────────┘
                │ 唯一通道：sudo 调用单个固定 helper，stdin/stdout JSON（§4.2）
┌───────────────▼────────────────────────────────────────────────────┐
│ 边界 B：E3 特权 helper：/usr/local/lib/sbox-cm/sbox-cm               │
│   （root-owned 0755、短命进程、bash；单 binary）                      │
│   · 环境自加固（不依赖 sudoers 文本，§4.2）：                         │
│     [ "$#" -eq 0 ] || exit 2；主动 unset SB_*；固定 PATH/绝对路径；    │
│     生产路径常量内嵌                                                  │
│   · operation 仅来自 stdin JSON 的严格 schema：                       │
│     verb ∈ 固定 allowlist（7：list/get/add/delete/rotate/export/     │
│     consume_export）；name 过 Phase C 正则；consume_export 仅收 token；│
│     禁止任意 command/path/config/shell（无 eval、无动态路径）          │
│   · 自算幂等 digest（canonical semantic JSON 的 sha256，§6.9）        │
│   · source lib/client-management.sh ← 与 install.sh CLI 共享的        │
│     唯一事务实现（绝不 source 整个 install.sh，绝不运行时截取代码块）  │
│   · fail-closed flock（§4.7）；锁失败 → 退出，零写入                  │
│   · 输出：仅 JSON 结果 + 退出码（零凭据，§5）；                       │
│     凭据字节唯一越界通道 = spool 文件（§4.6）                          │
│   · JSONL 审计 + 幂等账本（intent/outcome + fsync，§6.9）             │
└───────────────┬────────────────────────────────────────────────────┘
┌───────────────▼────────────────────────────────────────────────────┐
│ lib/client-management.sh（共享事务库，E3-0 抽取）                     │
│   · Phase C 现有函数原样搬入（字节级不变）                            │
│   · E3-0 新增：rotate_client（双协议共同旋转）、render_client_yaml    │
│     （credential-silent 渲染核心）、with_client_lock fail-closed 语义 │
│   · install.sh 用 source 本库替换内嵌 phase-c 块；CLI 行为不变        │
└───────────────┬────────────────────────────────────────────────────┘
                │
   /root/sbox/sbconfig_server.json   ← 唯一事实源（user.name = Monitor 身份）
   /root/sbox/clients/<name>/mihomo.yaml ← canonical 派生物（root-only，CLI 用；
        Web export 的正确性不依赖它，见 §4.6）
   /var/lib/sbox-cm/spool/           ← 一次性下载 spool：dir root:sboxweb 0710，
                                        files 0640（Web 仅 exact-token 可读，
                                        不可列举/写/删，§4.6）
   /root/sbox/config.lock            ← 唯一互斥点（E3-0 起 CLI+Web 全部 fail-closed）
   （E1 collector 走 127.0.0.1:9091 service.api，与 E3 完全解耦、互不感知）
```

### 1.2 设计决策与理由

* **D1 特权分离：Web 进程非特权，特权 helper 独立短命进程。**
  即使 Web 层被攻破，攻击者也拿不到任意文件读写，只能触发固定 verb allowlist 内的
  operation。residual risk 在 §9.4 明示。
* **D2 事务逻辑只有一份：共享库 `lib/client-management.sh`。**
  禁止"helper 运行时 source install.sh / awk 截取 phase-c 块"：运行时文本抽取脆弱且把
  整个 install.sh 带进特权执行上下文。E3-0 把 phase-c 块函数**原样搬移**（字节级不变）
  到共享库；`install.sh` 以 `source` 该库替换内嵌块；helper source 同一库。函数体没有
  第二份拷贝，CLI 与 Web 的任何行为差异只可能来自调用参数，不可能来自实现漂移。
  抽取闸门：`tests/test-phase-c.sh` 从 awk 截取改为直接 `source lib/client-management.sh`
  （测试机制变更，断言集合不变），全套 C 回归 + `bash -n` + shellcheck 必须全绿。
* **D3 单个 narrow helper，环境自加固。**
  多 binary 方案已否决（rev2 记录：安全无增量、五份参数解析 = 五份出错机会、追责由
  JSONL 审计承担）。rev3 强化：安全不依赖 sudoers 文本 —— helper 自身强制
  `[ "$#" -eq 0 ] || exit 2`（argv 必须为空）、主动 `unset SB_SERVER_CONFIG
  SB_STATE_FILE SB_CLIENTS_DIR SB_SING_BOX_BIN SB_LOCK_FILE`、使用固定安全 PATH 或
  全绝对路径调用外部命令、生产路径常量内嵌（与 install.sh 默认值一致）。
  sudoers `env_reset` 保留为第二层纵深，但正确性不依赖它。
  测试不经 sudo：`tests/` 提供 test-only wrapper（非 sudo 白名单）直接 source 共享库
  并注入 `SB_*` 沙箱；production helper 必须拒绝这些环境注入（E3-T57）。
* **D4 注册表（registry）只是顾问性元数据，绝不参与凭据正确性（rev3 收紧）。**
  `created_at` / `rotated_at` / `credential_version` / actor 存于
  `/root/sbox/web/client-registry.json`（0600）。列表以 **live 配置**为准；
  `credential_version` 仅用于 UX（角标/提示），**不得作为凭据新旧/正确性的判据**
  （§4.6）；registry 缺失/损坏 ⇒ 相关字段为 null，功能不受影响。
* **D5 不采用 Clash REST 的配置修改模型。** 参考 s-ui / 3x-ui / metacubexd /
  yacd 的展示与 danger-zone 交互，但拒绝 Clash `PUT/PATCH /configs` 式的
  "HTTP 直接改配置"：所有变更必须穿过 §4 事务。
* **D6（rev3 修订）下载 = 一次性 token + spool 文件 + 特权消费。**
  凭据字节不允许出现在 helper 的任何输出通道，Web 拿到 YAML 的唯一方式是 helper 把
  字节写进 spool 文件并返回一次性 token。权限模型（rev2 的 0750 存在
  "组可列举"与"组不可删"两个矛盾，review 判定 BLOCKER）：

  ```text
  /var/lib/sbox-cm/spool/        root:sboxweb 0710   # 组 = --x：仅 traverse，
                                                     # 无 r ⇒ 不可列目录
    <token>.yaml                 root:sboxweb 0640   # 组可读、不可写
    <token>.meta.json            root:sboxweb 0640
  ```

  Web 只获得 **exact-token traversal/read**：知道完整 token ⇒ 可打开该两个文件；
  不知道 token ⇒ 不可列举（0710 无组 r）；任何时候都不可写/不可删（无组 w）。
  一次性消费不靠 Web unlink，而靠极窄 helper operation `consume_export`（§4.6）。
* **D7 渲染核心 credential-silent。** 现 `generate_client_configuration()` 会打印
  携带 UUID/password 的分享 URI，Web 链路绝不能复用该行为：库内拆分为
  `render_client_yaml`（纯文件输出、零 stdout 泄漏，helper 专用）与 CLI 交互包装
  （保持现状打印 URI——人机交互路径，不在 helper 调用面上，行为不变以保 C 回归）。
* **D8（rev3 新增）export 真值源 = live config。** 每次 POST /export 在锁内从 live
  凭据全新渲染 spool 快照；canonical `/root/sbox/clients/<name>/mihomo.yaml` 继续由
  create/rotate 维护（CLI/人工用），但 Web export 的正确性不依赖它；
  `credential_version` 仅 advisory（D4）。
* **D9（rev3 新增）幂等 digest 所有权 = helper。** Web 不可信其声明"这个请求是什么"：
  helper 自行 parse stdin → schema 校验 → 语义 canonicalize → sha256；Web 提供的
  digest 字段从协议中删除（§4.2、§6.9）。

### 1.3 组件清单（E3 新增，全部待实现，本轮零实现）

```text
lib/client-management.sh        # 共享事务库（E3-0 从 install.sh phase-c 块抽取
                                #   + rotate + silent 渲染 + fail-closed 锁）
usr/lib/sbox-cm/sbox-cm         # 特权 helper（单 binary，bash，E3-1）
                                #   stdin JSON → 校验 → 调库 → stdout JSON + 退出码
                                #   verb allowlist（7）：list/get/add/delete/
                                #   rotate/export/consume_export
monitor-v2/cm_client/           # Web 侧适配层（非特权，E3-2）
  protocol.py                   #   HTTP ↔ helper JSON 映射、错误码表
  export_tokens.py              #   token 签发校验、exact-token spool 读取、
                                #   per-token 互斥与 consumed 集合
  adapters.py                   #   sudo 调用封装、超时、并发信号量
tests/helpers/sbox-cm-test.sh   # test-only wrapper（非 sudo 白名单）：注入 SB_*
                                #   沙箱后 source 共享库并调用同一 dispatch
tests/test-phase-c.sh           # E3-0：抽取方式改为 source lib（断言不变）
tests/test-phase-e3.sh          # E3 全套（§12）
```

---

## 2. 权限与文件边界（security boundary 的静态部分）

| 路径 | 属主/权限 | Web 进程 | helper | 说明 |
| --- | --- | --- | --- | --- |
| `/root/sbox/sbconfig_server.json` | root 0600 | **无任何权限** | 读写 | 唯一事实源；只允许被事务改写 |
| `/root/sbox/config`（SB_STATE_FILE） | root 0600 | 无 | 读 | SERVER_IP / PUBLIC_KEY / HY_SERVER_NAME / 跳端口区间 |
| `/root/sbox/clients/<name>/` | root 0700 | 无 | 读写 | canonical 派生 YAML（root-only；Web export 正确性不依赖它） |
| `/var/lib/sbox-cm/spool/` | **root:sboxweb 0710** | **仅 exact-token traversal/read**（组=--x：不可列目录；文件 0640 可读、不可写） | 读写 | `<token>.yaml` + `<token>.meta.json`（0640）；Web 不可创建/删除任何 spool 内容 —— 消费/清理只能经 `consume_export`（§4.6） |
| `/root/sbox/config.lock` | root | 无 | flock | 唯一互斥点；E3-0 起 CLI+Web 全部 fail-closed |
| `lib/client-management.sh` | root 0644 | 无（不经 Web 分发） | source | 与 install.sh 共享的唯一事务实现 |
| `/root/sbox/web/client-registry.json` | root 0600 | 无 | 读写 | 顾问元数据；**不参与凭据正确性**（D4/D8） |
| `/root/sbox/web/cm-ledger.jsonl` | root 0600 | 无 | 读写+fsync | 幂等账本（intent/outcome，§6.9） |
| `/root/sbox/web/audit/cm.jsonl` | root 0600 | 无 | 追加 | 特权审计（§8.4） |
| E2 会话/认证存储（memory-only session、admin password hash、recovery key、whitelist） | E2 自有 | 读写 | **不读不写** | 与 YAML 生成完全隔离（§8.5）；session memory-only ⇒ restart 使绑定 token 全部失效（§3.3） |

sudoers（单条规则；`env_reset` 为第二层纵深，正确性不依赖它 —— helper 自身强制
空 argv + unset `SB_*` + 固定 PATH，见 D3；参数一律走 stdin）：

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
  UUID / password / private key / 完整 sing-box config / YAML / full token**
  （唯一例外：`GET /download/{token}` 的响应体本身就是 YAML 凭据容器）。

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
      "credential_version": null, "source": "untracked" }
] }
```

* 列表来自 **live 配置**（helper `list` verb：锁内读两个 inbound 的 name 集合并集 +
  一致性审计结果），注册表仅补充 `created_at/rotated_at/credential_version/source`；
  注册表缺失/损坏时这些字段为 `null`，列表功能不受影响（D4）。
* **`source` 溯源（rev3，MUST FIX）**：`"web"` 仅在有**正向证据**（注册表中存在
  该 name 的 web 写入记录）时使用；其余一律 `"untracked"`。不再推断 `"cli"` ——
  Web create 成功但 registry 写失败同样没有 registry 记录，`cli` 是无法证明的断言；
  本设计不声称知道 CLI provenance。
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

### 3.3 凭据下载（two-step token flow；rev3：统一 404 + 特权消费 + 重启失效）

**第一步：签发**

```text
POST /api/v1/clients/vmix-01/export
头：X-CSRF-Token: …（变更类防护，与 POST/DELETE 同一 token）
// 200
{ "name": "vmix-01", "token": "b7c9…base64url(256bit)",
  "expires_in": 300, "credential_version": 1,   // ← advisory，可为 null（D4/D8）
  "download_url": "/api/v1/download/b7c9…" }
```

* helper 在锁内：一致性审计 → **从 live 凭据全新渲染**（不读 canonical、不看
  registry 判新旧，D8）→ 写 spool 快照 → 返回 token（§4.6）。
* token：256-bit 随机 base64url；**一次性**；TTL 300s；与签发会话绑定（meta 内
  session 指纹）；**full token 不进任何日志**（access log 强制脱敏，§8.3）。
* `legacy` → `403 reserved_client`（A-1：不允许 Web 导出 legacy 凭据）。

**第二步：下载**

```text
GET /api/v1/download/{token}        ← 浏览器普通导航，不携带自定义头
→ 200 text/yaml; charset=utf-8
   Content-Disposition: attachment; filename="vmix-01-mihomo.yaml"
   Cache-Control: no-store
   X-Content-Type-Options: nosniff
   Referrer-Policy: no-referrer
   X-Credential-Version: 1          // ← advisory
```

* 防护模型：token 是一次性 bearer proof（不可枚举、5 分钟、单次、会话绑定），
  下载时 Web 另行校验会话 cookie 仍有效且与 meta 绑定一致。
* **一次性语义的组合保证（"第二次绝不 200"）**：
  1. 同进程：Web 发起响应成功后立即调用 helper `consume_export` 删除两个 spool 文件；
     并发/重复 GET 由 Web 侧 per-token 互斥 + consumed 集合拒绝；
  2. Web 在 stream 后、consume 前崩溃：重启 ⇒ session 全部失效（E2 memory-only）
     ⇒ 该 token 的 meta 绑定 session 不存在 ⇒ 下载永久 `404`；
  3. TTL 到期或 Web 重启后的残留文件：由下一次 export 时的惰性清扫删除。
* **错误码统一（rev3，BLOCKER 修正）**：used / expired / unknown 一律返回
  **`404 download_unavailable`** —— 消费后所有记录已删除，服务器无法也**不应该**
  区分三者（避免维护 token oracle）。安全属性只要求第二次绝不 200。
* Web restart 行为（rev3 定案）：**重启使全部未决 export 失效**（session 失效）；
  不为 E3 token 把 E2 session 改成持久化；spool 文件可能暂存到 TTL，但不可下载，
  由清扫删除（E3-T41）。

### 3.4 POST /api/v1/clients（Create）

```json
// 请求（与任务书逐字一致；另必须携带 Idempotency-Key 头）
{ "name": "vmix-01", "reality": true, "hy2": true }
// 201（与任务书逐字一致）
{ "name": "vmix-01", "protocols": ["reality", "hy2"], "yaml_available": true }
```

约束与错误：

| 条件 | 结果 |
| --- | --- |
| **缺 Idempotency-Key 头** | **`400 idempotency_key_required`（rev3：create 强制）** |
| `reality` / `hy2` 不同时为 true | `422 protocol_set_unsupported`（Phase C 一致性审计要求两个 inbound 的 name 集合完全一致） |
| name 不匹配 `^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$` | `422 invalid_name`（message 中回显该正则） |
| name == `legacy` | `422 reserved_name` |
| name 已存在（任一 inbound） | `409 duplicate_name`（锁内以 live 配置复核后判定） |
| 请求体不是合法 JSON / 缺字段 | `400 malformed_body` |

* 带 key 重试的收益（rev3）：response 丢失后同 key 重试 → **replay 原始 201**，
  而不是误导性的 `409 duplicate_name`（§6.9）。
* `yaml_available` 语义：canonical YAML 再生失败不掩盖提交成功 → 仍 201 +
  `yaml_available:false` + 顶层 `warnings:["yaml_generation_failed"]`（§6.6）；
  该字段为 advisory，下载正确性由 export 的 live 渲染保证（D8）。

### 3.5 POST /api/v1/clients/{name}/rotate（危险操作）

```json
// 请求（显式确认：逐字回显客户端名）
{ "confirm": "vmix-01" }
// 头：X-CSRF-Token: …；Idempotency-Key: <uuid4>（**必填**，rev3）
//     会话须在 300s 内完成过 step-up 重认证（§8.2）
// 200
{ "name": "vmix-01", "protocols": ["reality", "hy2"], "yaml_available": true,
  "rotated_at": "2026-09-12T11:00:00Z", "credential_version": 2,
  "yaml_invalidated": true,
  "warning": "Reality 与 HY2 凭据已同时轮换，整份 YAML 已失效；所有使用旧 YAML 的设备将断线，必须重新下载" }
```

* **A-2：rotate = Reality + HY2 一次性共同旋转**（同一事务内替换 UUID 与 password）；
  `user.name` 不变 → Monitor 身份无缝延续。**整份 YAML 失效**：
  `yaml_invalidated:true` 是对 YAML 文件整体的判定。
* `confirm` 与 `{name}` 不一致 → `400 confirm_mismatch`；缺 step-up →
  `401 reauth_required`；缺 key → `400 idempotency_key_required`。

### 3.6 DELETE /api/v1/clients/{name}（危险操作）

```json
// 请求：同 rotate（confirm 逐字回显 + CSRF + step-up）
{ "confirm": "vmix-01" }
// 头：Idempotency-Key: <uuid4>（**必填**，rev3——原因见下）
// 200
{ "name": "vmix-01", "deleted": true,
  "warning": "已从 Reality 与 HY2 同时移除；该设备的 Monitor 流量统计随 E1 进程生命周期结束" }
```

* **为什么 delete 也强制 key（rev3，BLOCKER 修正）**：DELETE 成功但 response 丢失
  后，若另一管理员/CLI 重建同名 `vmix-01`，无幂等保护的浏览器 retry 会**删掉第二代
  同名客户端**。带 key 时重试进入调和：发现 live digest ≠ intent.old_cred_digest ⇒
  `409 idempotency_reconcile_conflict`，绝不删除 replacement（§6.9、E3-T45/48）。
* 语义与 Phase C `_delete_client_locked` 一致：先服务端事务提交，成功后才删派生目录；
  回滚路径上派生目录必须原样保留。
* 删除后 E1 视角：`user.name` 消失 → 设备不再产生新连接；E1 无数据库，历史计数随
  collector 进程生命周期结束（响应 `warning` 如实说明）。
* `legacy` → `403 reserved_client`（A-1）。

### 3.7 错误码总表（rev3：统一 404 / 新增 409 冲突码 / 503 不确定态）

| HTTP | error.code | 阶段 | 语义 |
| --- | --- | --- | --- |
| 400 | `malformed_body` | 请求解析 | JSON 非法/缺字段 |
| 400 | `confirm_mismatch` | 危险操作 | `confirm` ≠ 路径中的 name |
| 400 | `idempotency_key_required` | 幂等（rev3） | create/rotate/delete 缺 Idempotency-Key |
| 401 | `unauthenticated` | 中间件 | 未登录 |
| 401 | `reauth_required` | step-up | 距上次重认证 > 300s（§8.2） |
| 403 | `csrf_failed` | 中间件 | token 缺失/不匹配/Origin 非法 |
| 403 | `forbidden` | 授权 | 角色不足（v1 只有 admin，理论不可达） |
| 403 | `reserved_client` | helper+Web 双层 | 对 legacy 的 rotate/delete/export |
| 404 | `client_not_found` | helper | 锁内以 live 配置复核后不存在 |
| 404 | `download_unavailable` | 下载 | **token used / expired / unknown 统一 404**（不区分原因，避免 token oracle；安全属性 = 第二次绝不 200） |
| 409 | `duplicate_name` | 锁内复核 | 已存在（任一 inbound） |
| 409 | `config_inconsistent` | 事务前置审计 | Reality/HY2 集合不一致等，拒绝一切写 |
| 409 | `yaml_unavailable` | export（canonical 再生失败时） | advisory 状态；spool 下载仍可行（live 渲染） |
| 409 | `idempotency_conflict` | 幂等账本 | 同 key、helper 自算 digest 不同（全文统一 409） |
| 409 | `idempotency_reconcile_conflict` | 幂等调和（rev3） | in_flight 期间 live 状态被外部 actor 改动；禁止自动判成功/覆盖/误删，需人工刷新确认 |
| 415 | `unsupported_media_type` | 中间件 | 非 application/json 写请求 |
| 422 | `invalid_name` / `reserved_name` / `protocol_set_unsupported` | 校验 | §3.4 表 |
| 423 | `lock_unavailable` | flock（fail-closed） | 锁不可用/获取失败/超时 —— **配置零修改**（§4.7） |
| 429 | `rate_limited` | 中间件 | 变更限流 |
| 500 | `internal` | 未分类 | 附 request_id 排查；helper 检测到环境注入/非法 argv 也归此（防御性告警） |
| 500 | `candidate_rejected` | 审计/check | candidate 被审计或 `sing-box check` 拒绝（磁盘未动） |
| 500 | `commit_failed` | 备份/原子替换 | mv/备份失败（磁盘未动或已保留备份） |
| 500 | `export_failed` | spool | spool 写入失败（无部分文件残留） |
| 503 | `commit_rolled_back` | reload/健康 | 提交后失败 → 已自动回滚，**服务已恢复** |
| 503 | `idempotency_ledger_unavailable` | 账本（rev3） | intent append/fsync 失败 ⇒ mutation **从未开始**，零变更；可直接同 key 重试 |
| 503 | `idempotency_state_uncertain` | 账本（rev3） | **commit 已成功但 outcome 持久化失败**：不回滚健康配置；必须同 key 重试，走调和补账 |
| 500 | `rollback_manual_intervention` | 回滚 | 回滚后仍未确认恢复，**需人工**（CRITICAL 审计） |

> `503 commit_rolled_back` = "失败但系统是好的，可重试"；
> `500 rollback_manual_intervention` = "别再点重试，去看服务器"；
> `503 idempotency_state_uncertain` = "变更已生效且服务健康，账本未闭环 ——
> 必须带**同一个** Idempotency-Key 重试以补账，不要新建 key"。

---

## 4. Phase C 事务桥（transaction boundary）

### 4.1 原则：一条通道、一套事务、零旁路

* 服务端配置的全部合法写路径 = `with_client_lock`（fail-closed，§4.7）+
  `commit_server_config`。E3 不新增任何并行事务实现；`rotate` 与 silent 渲染作为
  共享库内的新函数（E3-0）进入同一份实现，CLI 菜单与 Web 自动共享同一把锁、
  同一审计、同一回滚语义。
* Web 层被权限模型物理排除在事务之外（§2：无读权限），"禁止 Web 手改 JSON"
  不靠纪律，靠操作系统权限。
* 读也过锁（§6.8）：helper 的所有 verb（含 list/export）都持有排他锁，
  保证读到的 uuid-password 对永不撕裂。

### 4.2 helper JSON 协议（进程边界，stdin → stdout；rev3 修订）

```json
// stdin（argv 必须为空 —— helper 自行强制 [ "$#" -eq 0 ] || exit 2；全部经 stdin）
{ "request_id": "b7c9…", "actor": "web-session:a1f3…", "verb": "rotate",
  "name": "vmix-01", "idempotency_key": "6f0e…" }
// stdout（零凭据、零 full token：只有状态、版本号、token 等非敏感字段）
{ "ok": true, "data": { "name": "vmix-01", "yaml_available": true,
                        "credential_version": 2 } }
// 或
{ "ok": false,
  "error": { "code": "commit_rolled_back", "stage": "reload",
             "detail": "reload 后健康检查失败，已自动回滚",
             "backup": "/root/sbox/sbconfig_server.json.bak.20260912-110000.XXXXXX" } }
```

* **verb allowlist（固定 7 个，rev3 术语统一）**：
  `list | get | add | delete | rotate | export | consume_export`。
  其余一律 `exit 2`。name 唯一自由文本，必须匹配 Phase C 正则；`consume_export`
  的 operation payload **仅 `token`**（形状校验后只在固定 spool 内操作）；
  **不接受任何文件路径、命令、配置名**。
* **`request_digest` 字段已删除（rev3，BLOCKER 修正）**：Web 无权声明"这个请求是
  什么"。helper 自己 parse stdin → schema 校验 → 语义 canonicalize
  （`{verb, name, protocols}` / `{verb, name}` / `{verb, token}`）→
  `digest = sha256(canonical-json)`；**只有 helper 自算 digest 参与账本匹配**
  （E3-T42：伪造/残留的 request_digest 字段必须被拒绝且无法影响账本）。
* `idempotency_key` 由 Web 透传；`add/delete/rotate` 缺 key ⇒ helper 亦拒绝
  （exit 2 → 400 idempotency_key_required；与 Web 中间件双层强制）。
* 退出码：`0` 成功；`2` 校验失败（含非法 argv / 非法 verb / 缺 key / 环境注入拒绝）；
  `3` 冲突（duplicate/reserved/not_found/inconsistent/idempotency_conflict/
  idempotency_reconcile_conflict）；`4` 锁不可用（fail-closed）；`5` candidate 被拒
  （未触盘）；`6` 提交后回滚成功；`7` 回滚需人工；`8` 导出不可用；**`9` 账本持久化
  失败（rev3）**；`10` 内部错误。HTTP 映射由 Web 适配层按 §3.7 完成。
* `stage` 枚举：`pre_lock | lock | ledger_intent | audit | candidate | check |
  backup | replace | reload | health | rollback | rollback_manual | yaml_gen |
  ledger_outcome | spool | consume | registry`。
* **stderr/journal 约束**：helper stderr 只允许错误码 + 阶段 + 无害上下文（路径、
  name）；任何凭据、YAML 片段、分享 URI、full token 一律禁止（E3-T29/T55）。
* **环境自加固（rev3，MUST FIX）**：production helper 在任何解析之前执行
  `[ "$#" -eq 0 ] || exit 2`；`unset SB_SERVER_CONFIG SB_STATE_FILE
  SB_CLIENTS_DIR SB_SING_BOX_BIN SB_LOCK_FILE`（存在残留即视为注入，直接拒绝）；
  `PATH` 固定安全值或全部绝对路径调用；生产路径常量内嵌。测试经 test-only wrapper
  （非 sudo 白名单）注入沙箱，production helper 必须拒绝同样的注入（E3-T56/57）。

### 4.3 add 事务流程（Create，逐阶段；rev3：planned 凭据 + 账本时序后移）

```text
0  pre_lock   helper 重校验 verb/name/正则/reserved/缺 key 拒绝（不信任 Web）
1  lock       flock config.lock，**fail-closed**：不可用/失败/超时 → exit 4，
              此后任何阶段都不执行，配置零修改
2  live 复核  【锁内】文件存在 → JSON 合法 → 一致性审计（fail-closed）→
              client_name_exists 双向复核
3  intent     【锁内，rev3】生成 planned 凭据（uuid/password），写 durable intent：
              {key, verb:add, name, request_digest(helper 自算 canonical),
               planned_cred_digest=sha256(planned uuid+password), state:in_flight}
              append → flush → **fsync**；失败 ⇒ exit 9 → 503
              idempotency_ledger_unavailable，**mutation 不得开始**（零变更）
4  复核       若账本已有 done（同 key 同 digest）→ 直接 replay（§6.9）；
              若 in_flight → 调和矩阵（§6.9 rev3）先行
5  commit     sing-box check 前置审计已在步骤 2；candidate 写入两个 inbound →
              commit_server_config：审计 candidate → sing-box check → was_running
              → 备份 → 原子 mv → reload → sleep 1 健康检查 └ 失败按 §6.4
6  yaml_gen   【锁内】render_client_yaml（silent）写 canonical（advisory；
              失败 → yaml_available:false + warnings，不回滚服务端）
7  registry   写入 created_at / credential_version=1 / source=web（尽力而为；
              失败 ⇒ 元数据 null + source=untracked，不影响正确性）
8  outcome    【锁内，rev3】构建**最终**非敏感 result（含 yaml_available/warnings）
              → durable outcome（append → flush → fsync）→ 失败（commit 已成功）
              ⇒ **不回滚健康配置** → exit 9 → 503 idempotency_state_uncertain
              （调用方必须同 key 重试补账）
9  audit      JSONL 追加，释放锁，返回
```

### 4.4 delete 事务流程（rev3：old_cred_digest intent + 同样时序）

```text
0  pre_lock   reserved 复核（legacy 硬拒）；缺 key 拒绝；账本查询/调和
1  lock       flock，fail-closed
2  live 复核  一致性审计（不一致 → 禁止一切破坏性操作）；
              双 inbound 同时存在才允许删（缺一 → 409 config_inconsistent）；
              计算 old_cred_digest = sha256(该 name 当前 uuid+password)
3  intent     【锁内】{key, verb:delete, name, digest, old_cred_digest, in_flight}
              + fsync；失败 ⇒ 零变更（同 §4.3 步骤 3）
4  candidate  jq 从两个 inbound 同时 map(select(.name != $name))
5  commit     commit_server_config（失败 → §6.4，派生目录保持不动）
6  yaml/registry 无（无派生 YAML 可删；registry 条目尽力删除）
7  outcome    最终 result → durable outcome（fsync）→ 失败 ⇒ 503 state_uncertain
8  派生物/注册表清理 → audit → 释放锁
```

### 4.5 rotate 事务流程（E3-0 新增；rev3：双 digest intent + 时序后移）

```text
0  pre_lock   reserved 复核（legacy 硬拒）；缺 key 拒绝；账本查询：若 in_flight
              且 digest 匹配 → 按 §6.9 调和矩阵处理（可能直接 replay / 重跑 /
              conflict）
1  lock       flock，fail-closed
2  live 复核  一致性审计 + 双 inbound 同时存在；
              old_cred_digest = sha256(当前 uuid + "\n" + 当前 password)
3  intent     【锁内】生成 planned 新凭据 → {key, verb:rotate, name, digest,
              old_cred_digest, planned_new_cred_digest, in_flight} + fsync；
              失败 ⇒ 零变更
4  candidate  jq 原地替换该 name 的 .uuid（vless-in）与 .password（hy2-in）；
              name / flow / 其他用户零改动
5  commit     commit_server_config "rotate client <name>"
              └ reload/健康失败 → 回滚 → 新旧凭据都未生效，重试安全（§6.4 R2）
6  yaml_gen   【锁内】render_client_yaml 再生整份 canonical
              （credential_version+1 头注释，advisory）；失败 → yaml_available:false
7  registry   rotated_at / credential_version+=1（尽力而为）
8  outcome    最终 result（含 yaml_invalidated/warnings）→ durable outcome（fsync）
              → 失败 ⇒ 503 idempotency_state_uncertain（不回滚健康配置）
9  audit      JSONL（只记"已轮换"，永不记新旧凭据值），释放锁
```

### 4.6 export / download / consume 流程（rev3：live 真值 + 0710 spool + 特权消费）

```text
POST /export 的 helper 部分（verb=export）：
0  pre_lock   reserved 复核（legacy → 403）
1  lock       flock，fail-closed（短暂持有）
2  live 复核  双 inbound 存在 + 一致性审计
3  **live 渲染（rev3，MUST FIX）**：get_client_credentials（LIVE 配置）→
              render_client_yaml 直接写入 spool 快照。
              **不读 canonical、不以 registry/credential_version 判断新旧** ——
              每次 export 都是 live 凭据的全新渲染（客户端数量极少，渲染开销无意义）；
              canonical 仅由 create/rotate 维护（CLI/人工用），与下载正确性解耦
4  spool      生成 256-bit token；写 /var/lib/sbox-cm/spool/<token>.yaml 与
              <token>.meta.json（均 0640 root:sboxweb；meta 含 session 指纹、name、
              created_at、expires_at、bytes）；临时文件 + rename，任何失败清理无残留
5  清扫       惰性清理已过期/孤儿 spool 文件（每次 export 顺带执行；覆盖
              "重启后 session 已失效"的残留）
6  stdout     {"ok":true,"data":{"token":"…","expires_in":300,…}}
              （token 仅出现在此 JSON——发给 Web 的能力凭证，不是服务端凭据；
              stderr/journal/audit 只允许 token 指纹前缀）
7  audit      name + 字节数 + token_fp（无内容、无全 token）

GET /download/{token}（Web 进程自身完成，不调 helper）：
  meta 校验（session 绑定 + expires_at）→ open exact-token .yaml（0710 目录下
  按名直取，不可列目录）→ 流式发送（§3.3 头）→ 关闭
  → 调 helper **consume_export** 删除两个文件（Web 自身无删除权限，E3-T39）
  → 此后同 token 任何请求 = 404 download_unavailable（统一 404，§3.3）

consume_export（rev3 新增的极窄 operation）：
  stdin：{verb:"consume_export", token:"<256-bit base64url>"}（operation payload
         仅 token；request_id/actor 为协议元数据）
  行为：校验 token 形状 → 在**固定** spool 目录内构造 <token>.yaml / <token>.meta
        两个路径 → 删除之（不存在 ⇒ ok(consumed:false)，无 oracle）
  禁止：任何 path 输入、spool 外路径、arbitrary unlink、glob（E3-T58）
  审计：token_fp + consumed 布尔
```

### 4.7 Locking contract（rev2 引入，review 确认保持不变）

**现状如实陈述（fail-open，不可宣称）**：Phase C `with_client_lock()` 在
(a) `flock` 命令不存在、或 (b) 锁文件打开/`flock` 获取失败时，仅
`warning "无法获取配置锁 ($SB_LOCK_FILE)，单机低并发场景下继续执行"` 然后**照常执行**
被包装的 mutation。因此 **当前系统不存在 CLI+Web 的严格全局串行化**。在 E3-0 修复
之前，任何并行 CLI mutation 与 Web mutation 之间都可能出现 lost update —— 只要还有
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
L4  commit_server_config 维持现状：自身不加锁，由调用方持锁（该前提由 L2/L3 在
    所有调用点上强制成立）。
L5  读路径：helper 全部 verb 持锁（§6.8 撕裂读）；CLI 交互式只读显示（list_clients）
    维持无锁现状——display-only，无写风险。
L6  Web 层不得自行实现第二把锁/队列来"补"全局保证；信号量仅用于请求背压（§6.7）。
```

验收：E3-T26（锁获取失败 → 423 + 配置字节不变）、E3-T27（flock 缺失 → CLI 菜单与
helper 的 mutation 全部拒绝）、E3-T28（长持锁 → 超时拒绝且无 candidate/备份残留）。

---

## 5. 凭据处理（credential handling，rev3 精确化）

**Web credential boundary（rev3，BLOCKER 修正——取代 rev2 的"Web 绝不持有 YAML
字节"这一与流式下载物理上不能同时成立的表述）**：

```text
· Web 无 canonical /root/sbox 任何读取权限（服务端配置、派生 YAML 均不可达）
· Web 只能读取「已授权的 exact-token spool object」：
    知道完整 token → open /var/lib/sbox-cm/spool/<token>.yaml(+meta)（0640）；
    不知道 token → 0710 目录不可列举 ⇒ 无法发现任何其他 pending YAML
· Web 不 parse YAML credentials / 不 log YAML / 不 persist YAML /
  不把 YAML 放进任何 API JSON
· YAML 字节仅在 download response 生命周期内短暂经过 Web 进程
  （open → stream → close → consume_export），随响应结束即弃
· 不宣称"Web memory 永远没有 YAML"——流式下载必然在进程内短暂处理字节
```

**全通道禁令与事实分布**：

```text
生成：sing-box generate uuid / generate rand --hex 16（Phase C 同源；请求体永不携带凭据）
存在：sbconfig_server.json（事实源）；clients/<name>/mihomo.yaml（canonical 派生，
      root-only，CLI 用）；spool/<token>.yaml（一次性下载快照，root:sboxweb 0640）；
      helper/Web 进程内存中的瞬态（响应结束即弃）
禁止：helper stdout / stderr / journald（sudo 只记命令行，argv 为空故天然安全）/
      两份审计 / 错误 detail / 任何 API 响应（除下载响应体）/ 注册表 /
      幂等账本（除单向摘要）/ 会话存储 / 浏览器缓存 / Web access log（路径脱敏）
越界通道：凭据字节从特权侧到 Web 的唯一通道 = exact-token spool 文件；
      helper 到 Browser 的 API 响应中永不出现 YAML 字节
```

**credential-silent 渲染**：库内拆分 `render_client_yaml <outfile>`（silent 核心：
stdout/stderr 零凭据、零 URI；helper 唯一入口）与 `generate_client_configuration`
（CLI 交互包装：按现状打印链接，行为与今天逐字节一致 → C 回归不变）。

硬性卫生断言（E3-T16/T29/T55）：对所有 API 响应、helper stdout/stderr、journald
采样、**Web access log**、两份审计日志做正则扫描（UUID 形状、`uuid:`、`password:`、
`private`、`private_key`、`vless://`、`hysteria2://`、YAML 片段、**full token**），
命中即构建失败。允许出现的唯一派生值：单向摘要与指纹（`old_cred_digest`、
`planned_cred_digest`、`planned_new_cred_digest`、token 指纹），sha-256 不可逆。

---

## 6. 专项详细设计

### 6.1 Create — 见 §4.3；错误路径全落 §3.7；响应字段与任务书逐字一致。

### 6.2 Delete — 见 §4.4；危险操作 UX 契约见 §7.3。

### 6.3 Duplicate name

* 锁内 `client_name_exists` 以 live 配置复核（任一 inbound 命中即拒绝）→
  `409 duplicate_name`，服务端配置字节不变。
* 带 key 的 create 若 response 丢失后重试：账本 done → **replay 原始 201**
  （而非 409）——这是 create 强制 key 的直接收益（§6.9）。
* Web 侧可选预检不算权威，**判定永远在锁内**。

### 6.4 失败矩阵（rev3：F1–F23）

| # | 失败点 | 磁盘状态 | 服务状态 | helper | HTTP | 后续 |
| --- | --- | --- | --- | --- | --- | --- |
| F1 | name/形状/reserved（pre_lock） | 不变 | 不变 | exit 2/3 | 422/403 | 无 |
| F2 | 锁不可用/获取失败/超时（fail-closed） | **不变（字节级）** | 不变 | exit 4 | **423 lock_unavailable** | 稍后重试；无 candidate/备份残留（E3-T26/28） |
| F3 | live 配置 JSON 非法 / 一致性审计失败 | 不变 | 不变 | exit 3 | 409 config_inconsistent | 先跑 CLI 一致性检查 |
| F4 | candidate 生成失败 / candidate 审计失败 / `sing-box check` 失败 | 不变（candidate 被删） | 不变 | exit 5 | 500 candidate_rejected | 附审计问题行；系统完好 |
| F5 | 备份失败 / 原子 mv 失败 | live 不变；备份保留 | 不变 | exit 5 | 500 commit_failed | 系统完好，可重试 |
| F6 | reload 失败 | **已自动回滚** | 已恢复 | exit 6 | **503 commit_rolled_back** | 可安全重试 |
| F7 | 健康检查失败 | 同 F6 回滚 | 已恢复 | exit 6 | **503 commit_rolled_back** | 可安全重试 |
| F8 | 回滚后再 reload/健康仍失败 | 回滚文件已就位 | **未确认恢复** | exit 7 | 500 rollback_manual_intervention | **禁止盲目重试**，人工恢复；审计 CRITICAL |
| F9 | 提交成功后 yaml_gen 失败 | 服务端已生效 | 正常 | outcome 记录 warnings | 201 + `yaml_available:false` | advisory；export 按 live 渲染不受影响（D8） |
| F10 | 提交成功后 registry 失败 | 服务端已生效 | 正常 | ok | 201（元数据 null、source=untracked） | 顾问性，无影响（§3.1） |
| F11 | export spool 写入失败 | 无部分 spool 文件 | 正常 | exit 8 | 500 export_failed | 可重试 |
| F12 | **flock 二进制缺失（E3-0 后）** | **不变** | 不变 | exit 4 | 423 lock_unavailable | CLI 菜单 mutation 同样拒绝（L3） |
| F13 | **账本 intent append 失败（rev3）** | **零变更（mutation 未开始）** | 不变 | exit 9 | **503 idempotency_ledger_unavailable** | 同 key 重试安全（E3-T49） |
| F14 | **账本 intent fsync 失败（rev3）** | **零变更** | 不变 | exit 9 | **503 idempotency_ledger_unavailable** | 同 key 重试安全（E3-T50） |
| F15 | **账本 outcome append/fsync 失败——commit 已成功（rev3）** | 已提交（健康） | 正常 | exit 9 | **503 idempotency_state_uncertain** | **不回滚健康配置**；同 key 重试 → 调和补账（E3-T51） |
| F16 | **调和冲突：in_flight 期间 live 被外部 actor 改动（rev3）** | 不变（拒绝动作） | 不变 | exit 3 | **409 idempotency_reconcile_conflict** | 人工刷新页面确认后再操作（E3-T46/47/48） |
| F17 | **download token：used / expired / unknown（rev3）** | used 时 spool 已清 | 正常 | n/a | **404 download_unavailable（统一）** | 重新 POST /export（E3-T40） |
| F18 | **Web restart 后 outstanding token** | spool 可能暂存到 TTL | 正常 | n/a | **404**（session 失效） | 下次 export 重新签发；清扫删残留（E3-T41） |
| F19 | helper 收到非空 argv / 非法 verb / 缺 key | 不变 | 不变 | exit 2 | 400/500（防御性告警） | 修复调用方（E3-T56） |
| F20 | production helper 检测 `SB_*` 环境注入 | 不变 | 不变 | exit 2 | 500 internal（告警） | 排查注入源（E3-T57） |

R1：F4–F8 复用 `commit_server_config` 现有语义，E3 只做错误码映射。
R2：rotate 的 F6/F7 = "轮换从未发生"（新凭据只在被回滚的 candidate 里），重试安全。
R3：create 的 F6/F7 = "客户端从未存在"；delete 的 F6/F7 = "客户端仍完整存在，
派生目录保持"。
R4：F2/F12 是 fail-closed 的直接推论——锁失败的失败模式是"什么都不做"。
R5（rev3）：F13/F14 与 F15 是账本 durability 的两半：intent 失败 ⇒ **什么事都没发生**
（重试安全，无 reconciliation 负担）；outcome 失败 ⇒ **变更已生效**（禁止回滚健康
配置，必须同 key 补账）。

### 6.5 Legacy protection（已定案 A-1：Web list-only）

| 操作 | legacy 的结果 |
| --- | --- |
| POST create name=legacy | `422 reserved_name` |
| POST rotate legacy | `403 reserved_client` |
| DELETE legacy | `403 reserved_client` |
| POST legacy/export | `403 reserved_client`（**默认不允许 Web 凭据导出**） |
| GET 列表/详情 | `200`，`reserved:true, mutable:false, source:"untracked"`（Monitor 照常显示 legacy 流量） |

双层防御：Web 中间件拦截 + helper 内部再次硬校验。Retirement 属未来独立功能。
CLI 路径能力不变。

### 6.6 Partial failure（服务端成功、派生物失败）

见 F9/F10。原则：**服务端事务边界之内是原子的；边界之外的派生物允许最终一致**。
`yaml_available:false` + `warnings[]` 是 advisory 契约；下载正确性由 export 的
live 渲染独立保证（D8），不再依赖 canonical 的状态。

### 6.7 Concurrent requests

* 全局保证 = **唯一互斥点 + fail-closed（§4.7）**。E3-0 修复前，CLI（fail-open 现状）
  与 Web 之间不存在全局串行化——E3-0 不落地，E3-1..E3-4 不得开始。
* helper `flock -w 15`（超时 → exit 4 → 423）；Web 适配层进程内 semaphore(1) + 30s
  上限（仅背压，不充当全局锁，L6）。
* **请求内重读原则**：一切判定（存在性、一致性、reserved、cred digest）都在锁内对
  live 配置重新做出，绝不基于陈旧快照写入。
* 并发结果示例：10 个并发 create 同名（各自带 key）→ 恰好 1 个 201，其余 409（或
  同 key 重试者 replay）。

### 6.8 读取一致性

`mv` 原子替换保证读者要么看到旧文件要么看到新文件，永远完整。但"uuid 与 password
分两次 jq 读"可能横跨一次 rotate 提交 → 撕裂读。因此 **export 与 list 同样在锁内
执行**；spool 快照进一步把"下载内容"冻结为签发时刻的完整副本——下载阶段（锁外）
永远不可能读到撕裂内容（E3-T12 断言配对一致）。

### 6.9 Idempotency（rev3 全面重写：helper 自算 digest / 全 mutation 强制 / 双 digest 调和 / fsync durability）

**所有权（BLOCKER 修正）**：Web 不提供 digest。helper 自己 parse stdin → schema
校验 → 语义 canonicalize（`{verb,name,protocols}` / `{verb,name}` / `{verb,token}`）
→ `digest = sha256(canonical-json)`；**账本匹配只认 helper 自算值**。

**强制范围（BLOCKER 修正）**：`add` / `delete` / `rotate` 三个 mutation **全部**
必填 Idempotency-Key（Web 中间件 400 早拒 + helper exit 2 双层）；缺失 →
`400 idempotency_key_required`。理由：

```text
delete：DELETE 成功但 response 丢失 → 另一管理员/CLI 重建同名 vmix-01 →
        无幂等的 retry 会删除第二代同名客户端（不可接受）
create：response 丢失后同 key 重试应 replay 原始 201，而非误导性 409
rotate：每次调用生成新凭据，天然不幂等，必须有 key 防双击/失联双轮换
```

**账本（特权侧持久化，durability 定案）**：

```text
存储：/root/sbox/web/cm-ledger.jsonl（root 0600；GC/compaction 由 helper 锁内做；
      TTL 24h）
intent（mutation 之前）：{key, verb, name, digest(helper 自算), state:"in_flight",
       planned_cred_digest(仅 add), old_cred_digest(delete/rotate),
       planned_new_cred_digest(仅 rotate), ts, request_id}
       写入次序：append → flush → fsync ⇒ durable 之后才允许任何 config mutation；
       intent 持久化失败 ⇒ exit 9 ⇒ 503 idempotency_ledger_unavailable，零变更
outcome（锁释放之前）：最终非敏感 result {…yaml_available, warnings…}；
       append → flush → fsync ⇒ durable 之后 helper 才允许返回成功；
       失败且 commit 已成功 ⇒ **不回滚健康配置** ⇒ exit 9 ⇒
       503 idempotency_state_uncertain + "retry with the SAME Idempotency-Key"
摘要白名单：planned_cred_digest / old_cred_digest / planned_new_cred_digest 均为
       sha256(凭据拼接)，单向不可逆，仅存 root-only 账本；不入审计/响应
```

**请求匹配规则（helper 锁内）**：

| 账本状态 | digest 匹配 | 行为 |
| --- | --- | --- |
| 无记录 | — | 写 durable intent → 执行事务 → 完成派生 → durable outcome |
| done | 匹配 | **replay**：原样返回落账 result + `Idempotency-Replayed:true`，零事务 |
| done | 不匹配 | `409 idempotency_conflict` |
| in_flight | 不匹配 | `409 idempotency_conflict` |
| in_flight | 匹配 | **调和矩阵**（下表） |

**调和矩阵（rev3，BLOCKER 修正——按 planned/old digest 精确判定，杜绝把外部
actor 的改动误认成自己的成功）**：

| intent | live 状态（锁内核对） | 结论 |
| --- | --- | --- |
| create | name 不存在 | 上次 mutation 未生效 → **重新执行**（生成新 planned 凭据、更新 intent、走完整事务） |
| create | name 存在 ∧ current_cred_digest == planned_cred_digest | 本请求确实已生效 → 完成派生工作（yaml_gen/registry）→ done（replay） |
| create | name 存在 ∧ current_cred_digest != planned_cred_digest | **`409 idempotency_reconcile_conflict`**：同名对象是别的 actor 建的，禁止覆盖、禁止判成功 |
| rotate | current_cred_digest == planned_new_cred_digest | 本请求已生效 → done |
| rotate | current_cred_digest == old_cred_digest | 未生效 → **重新执行**（新 planned 凭据、更新 intent） |
| rotate | current ∉ {old, planned_new} | **`409 idempotency_reconcile_conflict`**：另一 actor 已 rotate/改动，禁止自动判成功、禁止再 rotate |
| delete | name 不存在 | 期望状态已达成 → done |
| delete | name 存在 ∧ current_cred_digest == old_cred_digest | 未生效 → **重新执行 delete** |
| delete | name 存在 ∧ current_cred_digest != old_cred_digest | **`409 idempotency_reconcile_conflict`**：同名客户端已被 rotate/recreate，**绝对不得删除当前对象** |

其中 `current_cred_digest = sha256(该 name 当前 uuid + "\n" + 当前 password)`，
锁内现算。调和后（无论 replay 还是 re-execute）都补完 derived work、写 durable
outcome，保证 replay 与首次最终结果一致（E3-T52）。

* crash 窗口收敛：commit 前 crash ⇒ intent in_flight + live 未变 ⇒ 调和重跑；
  commit 后 outcome 前 crash ⇒ intent in_flight + live 已变 ⇒ 调和判"已生效" ⇒
  补 derived work + outcome。两个窗口都被矩阵闭合（E3-T32/T51）。
* `export` 不要求 key（多签发一个 token 无害，TTL 自然过期）。
* Web 重启不丢账本（磁盘文件 + fsync）；Web 必须原样透传重试请求中的同一 key。
* 同 key 指纹（sha256 前 8 位）进审计（E3-T31）。

### 6.10 Audit log

见 §8.4（两层审计 + schema + 禁记内容清单 + token 脱敏）。

---

## 7. Rotate / Delete 危险操作语义（danger-zone 契约）

### 7.1 触发链（E3 定义，E2 呈现）

```text
Clients 行 → Rotate / Delete（红色 danger-zone 区域）
→ 模态框：后果明示（rotate：双协议同时轮换、整份 YAML 失效、设备断线、必须重新下载；
  delete：双协议凭据同时移除、Monitor 不再统计）+ type-to-confirm（逐字输入客户端名）
  + step-up（>300s 先重认证）
→ POST（rotate/delete 必带 Idempotency-Key）
→ 结果页：rotate 成功后立即高亮"重新下载 YAML"入口（重新走 §3.3 两步流程）
→ 409 idempotency_reconcile_conflict 时：UI 明示"服务器状态已变化，请刷新后
  核对再操作"（不静默重试）
```

### 7.2 Rotate 后旧 YAML 失效的硬契约（A-2 口径：整份失效）

* 服务端凭据在事务提交瞬间即已双双轮换 → 任何**此前下载**的 YAML 立即整体失效；
* API 返回 `yaml_invalidated:true` + `warning` + 新 `credential_version`
  （**advisory**——下载内容永远来自 live 渲染，D8）；
* Web UI 必须：(a) rotate 前明示"整份 YAML 失效"；(b) rotate 成功页显著提示
  "旧 YAML 已失效，请重新下载"；列表角标基于前端记录的下载时间与 `rotated_at`
  比较（localStorage，不进服务端契约）。

### 7.3 Delete 语义补充

* 先服务端后派生物（§4.4 阶序）；E1 视角：`user.name` 消失 → 设备不再产生新连接，
  内存计数随之终结。
* 同名重建不受限（create 即全新身份）；但**旧请求的重试**绝不删除新身份
  （调和矩阵 F16 行，§6.9）。

### 7.4 whitelist / admin password / recovery key 与 YAML 的隔离

见 §8.5。核心断言：这三者的变化对任何 YAML 字节零影响、对服务端配置零接触、
不参与 config.lock 竞争。

---

## 8. Authorization / CSRF / Audit

### 8.1 授权模型

* v1 单管理员：唯一角色 `admin`。E2 拥有登录态（**memory-only session**）；E3 契约：
  中间件向每个 `/api/v1/clients*` 请求注入
  `client_ctx = {session_id, role, auth_age_seconds, source_ip}`，
  任一 `role != "admin"` → 403 forbidden。
* 白名单（IP allowlist，若 E2 实现）在中间件层生效，先于 CSRF。
* recovery key 仅用于 E2 登录恢复；不得出现"recovery key 直达 client-manager"的路径。

### 8.2 Step-up 重认证（危险操作）

* rotate / delete 要求 `auth_age_seconds ≤ 300`，否则 `401 reauth_required`；
* UI 收到该码 → 弹密码重认证 → 成功后自动重放原请求（confirm/Idempotency-Key 不变；
  helper 自算 digest 对同一语义请求天然一致，账本语义不受影响）；
* helper 不参与 step-up；审计记录 actor session 便于追责。

### 8.3 CSRF 与 token 日志脱敏（rev3 修订）

| 层 | 措施 |
| --- | --- |
| Cookie | 会话 cookie `HttpOnly` + `SameSite=Strict`（+ `Secure`，若未来上 TLS 反代） |
| Token | **变更请求（POST create/rotate/delete/export）** 要求 `X-CSRF-Token`（double-submit） |
| Origin | 变更请求校验 `Origin`/`Referer` ∈ 允许集；`Sec-Fetch-Site: cross-site` 一律拒绝 |
| Content-Type | 写请求强制 `application/json` |
| 下载 GET | 不依赖自定义头：一次性 256-bit token + 单次 + TTL 300s + 会话绑定；`Referrer-Policy: no-referrer` |
| **日志脱敏（rev3，BLOCKER）** | E2 access logger 对 `/api/v1/download/<token>` **强制改写为 `/api/v1/download/[redacted]`**（E2 集成硬性要求，否则 token 经 request path 进入 stderr/journal）；Web 审计只记 token 指纹。测试扫描 stdout / stderr / journald fixture / **Web access log** / 两份审计 JSONL，full token 命中 = FAIL（E3-T55） |

**residual risk 如实声明**：navigation-style 下载意味着 token URL 可能出现在浏览器
历史/下载管理器中——以 one-time + TTL 300s + session 绑定 + no-referrer 缓解；
**不宣称浏览器历史不存在 token**。

### 8.4 审计

两层，各司其职：

1. **Web 审计（E2 拥有）**：method、path（**download path 脱敏**）、actor session、
   source_ip、CSRF 结果、HTTP 状态、时延、request_id、token 指纹（签发/下载/消费）。
2. **特权审计（E3，helper 追加）**：JSONL `/root/sbox/web/audit/cm.jsonl`（0600）：

```json
{ "ts": "2026-09-12T11:00:00Z", "request_id": "b7c9…", "actor": "web-session:a1f3…",
  "verb": "rotate", "name": "vmix-01", "outcome": "ok", "stage": "commit",
  "backup": null, "rolled_back": false, "credential_version": 2,
  "lock_wait_ms": 3, "confirm_echo": true, "idempotency_key_fp": "9af1…",
  "idempotency_replayed": false, "token_fp": null }
```

禁记清单（两层共同）：UUID、password、private key、YAML 内容、完整配置、
凭据分享 URI、**token 全文**（仅指纹）、`planned/old_cred_digest` 明文（账本专属）。
导出事件只记 `name + bytes + token_fp`。
`outcome ∈ ok|rejected|rolled_back|manual_intervention|replayed|uncertain`。

### 8.5 认证态与 YAML 的隔离（不变量）

```text
YAML 输入集合 ≡ { sbconfig_server.json（live 读）, SB_STATE_FILE, client name }
E2 认证存储 ∉ 输入集合
```

* 改 admin password / whitelist / recovery key：只写 E2 认证存储，不触碰 `SB_*`、
  不获取 config.lock、不产生任何 YAML 变化（E3-T17 字节级断言）；
* 反向亦然：create/rotate/delete 不触碰认证存储。
* 注意方向性：E2 session（memory-only）**是** download 授权的输入之一（meta 绑定），
  这属于访问控制，不属于 YAML 内容生成 —— restart 使 session 失效 ⇒ 未决下载失效
  （§3.3），但已下载文件与 YAML 内容生成规则不受影响。

---

## 9. 参考 UX 与明确不采用的模型

* **参考**（交互模式，非代码）：s-ui / 3x-ui 的客户端表格与操作确认；
  metacubexd / yacd 的连接/设备展示语言；danger-zone + type-to-confirm（GitHub 范式）
  + step-up auth；一次性下载 token（导出报表的标准做法）。
* **明确不采用 Clash REST 配置修改模型**：HTTP 层永远没有"改配置"的能力，
  只有"请求一个事务"的能力；服务端配置的合法写入口只有 Phase C 事务。

## 9.4 Residual risks（如实声明，rev3 更新）

1. Web 进程被完全攻破 ⇒ 可触发 verb allowlist 内的 operation。spool 模型下其能力
   边界：可读取/消费**它自己获知的 token** 对应的 YAML（它签发的），**不可列举**
   其他 pending YAML（0710）、不可写/删 spool 任意内容、不可读取 canonical。
   缓解：极小攻击面、仅回环、审计完备、step-up、幂等双闸。无法根除。
2. 特权 helper（root，短命）自身漏洞即 root 漏洞。缓解：单 binary、stdin JSON
   固定 schema、无 argv、无 eval、无动态路径、环境自加固（unset SB_* / 固定 PATH）、
   sudoers env_reset 双层、静态扫描 + 测试覆盖。
3. spool 文件是磁盘上的临时凭据副本（0640 root:sboxweb、TTL 300s、consume 即删、
   惰性清扫兜底）。风险窗口 = 签发后未下载期间本机 sboxweb 组可**按名**读取
   （需要知道 token；不可列举）。
4. 下载 token 是 TTL 内单次 bearer 能力 + session 绑定；**浏览器历史/下载管理器
   可能含 token URL**（navigation 下载的固有残留），以 one-time + 短 TTL +
   no-referrer 缓解；token 一经消费即失效。
5. 127.0.0.1 明文 HTTP：本机其他本地用户可嗅探回环流量（单管理员 VPS 可接受；
   未来可加 TLS 反代，属 E2 范畴）。
6. `503 idempotency_state_uncertain` 窗口内（outcome fsync 失败到同 key 补账之间），
   账本短暂落后于 live 配置；期间的新请求（不同 key）不受影响，同 key 重试被
   调和矩阵接管。不会出现"配置已变但账本声称未变且被采信"——调和永远以 live
   digest 为准。

---

## 10. 决策记录

### 10.1 已定案（rev2 A-1…A-7 经本轮确认保持；rev3 新增 A-8…A-18）

| # | 决策 |
| --- | --- |
| A-1 | legacy = Web list-only：GET 可见（reserved/mutable），delete/rotate/credential export 一律 403 |
| A-2 | rotate = Reality + HY2 一次性共同旋转；整份 YAML invalidated |
| A-3 | 下载 = POST /export → one-time token → GET /download/{token} |
| A-4 | 单个 narrow helper（root-owned、固定 operation、严格 stdin schema、无 argv） |
| A-5 | 共享事务库 lib/client-management.sh；禁止 source 整个 install.sh / 运行时截取 |
| A-6 | 锁契约 fail-closed，CLI+Web 全 mutation path 生效（§4.7） |
| A-7 | 幂等账本在特权侧持久化（intent/outcome + 调和） |
| A-8（rev3） | spool 权限模型：dir `root:sboxweb 0710` + files `0640`；Web 仅 exact-token traversal/read；新增极窄 `consume_export` 完成一次性消费（Web 不可列举/创建/删除 spool） |
| A-9（rev3） | token used/expired/unknown **统一 404 download_unavailable**；不维护 token oracle；安全属性 = 第二次绝不 200 |
| A-10（rev3） | **Web restart 使未决 export 全部失效**（E2 session memory-only 是既定事实，不为 token 持久化 session）；spool 残留由 TTL/清扫删除 |
| A-11（rev3） | 幂等 digest 由 **helper 自算**（语义 canonical JSON 的 sha256）；Web 提供的 request_digest 字段从协议删除 |
| A-12（rev3） | **create/rotate/delete 全部强制 Idempotency-Key**（缺失 → 400 idempotency_key_required） |
| A-13（rev3） | in-flight 调和按 planned_cred_digest / old_cred_digest 精确矩阵；外部 actor 改动 ⇒ `409 idempotency_reconcile_conflict`，绝不自动判成功/覆盖/误删 |
| A-14（rev3） | 账本 durability：intent fsync 先于 mutation（失败 ⇒ 零变更）；outcome fsync 先于返回成功；outcome 失败且 commit 已成功 ⇒ `503 idempotency_state_uncertain`，**不回滚健康配置** |
| A-15（rev3） | export 真值源 = **live config 每次全新渲染**；canonical 与 credential_version 仅 advisory，不参与下载正确性 |
| A-16（rev3） | source 溯源：`web` 仅限正向证据；否则 `untracked`；不声称 CLI provenance |
| A-17（rev3） | download token 全链路日志脱敏：access log → `/api/v1/download/[redacted]`；审计/日志仅 token 指纹；测试扫描全部通道 |
| A-18（rev3） | helper 环境自加固：`[ "$#" -eq 0 ] || exit 2` + 主动 unset `SB_*` + 固定 PATH/绝对路径 + 生产路径内嵌；测试走 test-only wrapper（非 sudo 白名单） |

### 10.2 未决决策（需后续 review 定案）

| # | 决策 | v1 建议 | 备选 |
| --- | --- | --- | --- |
| U-1 | 注册表文件位置/格式 | `/root/sbox/web/client-registry.json`，单 JSON | 每客户端 `meta.json`（clients 目录，root-only） |
| U-2 | E2 认证/会话接口细节（cookie 名、re-auth 端点形态） | E3 只依赖 §8.1 `client_ctx` 注入契约，具体归 E2 | — |
| U-3 | 审计是否合并为一份 | 保持两层 | 单一 JSONL 双 writer |
| U-4 | 变更限流阈值 | 10 次/分钟/IP | 不限（单管理员） |
| U-5 | 备份保留策略 | 维持 Phase C 现状（不清理） | 保留 N 份/GC |
| U-6 | API 错误 message 语言 | 英文 code + 英文 message | 双语 message |
| U-7 | step-up 窗口 | 300s | 120s / 600s |
| U-8 | 下载 token TTL / 清扫策略 | TTL 300s；每次 export 惰性清扫（含孤儿文件） | systemd timer；TTL 缩至 60s |
| U-9 | 账本 TTL | 24h（含 GC compaction） | 7 天（利于事后审计比对） |

---

## 11. E3 实施阶段（每阶段独立可测，全部尚未实现）

| 阶段 | 交付物 | 测试闸门 |
| --- | --- | --- |
| **E3-0**（纯 Phase C/CLI 范畴，Web 零代码） | (a) phase-c 块机械抽取为 `lib/client-management.sh`（字节级不变；install.sh 改 source；test-phase-c.sh 改直接 source，断言不变）；(b) `with_client_lock` fail-closed（全 mutation path）；(c) `generate_client_configuration` 拆分 silent 核心 + CLI 包装；(d) `rotate_client`（双协议共同旋转） | C 回归 + `bash -n` + shellcheck 全绿；E3-T26/27/28；rotate 测试；silent 零泄漏测试 |
| **E3-1** | 特权 helper `sbox-cm`（单 binary，bash）：环境自加固（argv/unset SB_*/固定 PATH）、verb allowlist（7）、stdin schema、JSON 协议+退出码、**helper 自算 digest**、账本（intent/outcome + **fsync** + 调和矩阵）、spool 导出 + `consume_export`、JSONL 审计、sudoers（单规则 + env_reset） | 沙箱逐 verb 契约测试（test-only wrapper）；E3-T29/T42/T49–T51/T56–T58 |
| **E3-2** | Web 适配层（薄，非特权）：HTTP ↔ helper 映射、§3.7 错误码表、CSRF/step-up 挂钩（E2 `client_ctx`）、**Idempotency-Key 强制透传**、POST /export 签发 | API 契约测试（mock helper）+ §3.7 全表；E3-T43/44（中间件层 400） |
| **E3-3** | 下载与 UX 契约：GET /download/{token}（exact-token 读取 + stream + consume_export + 统一 404 + **access log 脱敏**）、restart 失效语义、rotate 失效横幅、advisory 角标 | E3-T20/37–T41/T53–T55；撕裂读断言 E3-T12 |
| **E3-4** | 硬化：失败注入（F1–F20）、并发 canary、凭据卫生全通道 grep（含 Web access log）、审计 schema 校验、文档刷新 | §12 全矩阵绿 + 生产 canary（仅 VPS 侧人工执行） |

依赖关系：**E3-0 是全局前置（锁 fail-closed 是 E3-1..E3-4 的验收 blocker）**；
E3-1 依赖 E3-0；E3-2 依赖 E3-1 与 E2 中间件接口（U-2）；E3-3/E3-4 依赖 E3-2。

---

## 12. 测试矩阵（v1 必须全绿；命名 `E3-Txx`；rev3 扩至 T58）

| ID | 场景 | 断言 |
| --- | --- | --- |
| E3-T01 | create happy path（带 key） | 201；双 inbound 各新增用户；YAML 显示名正确；响应与任务书字段一致 |
| E3-T02 | duplicate name | 409；配置字节不变；无备份残留 |
| E3-T03 | 非法 name（空格/路径/空/-leading/33 字符/`legacy`） | 422/422 reserved；配置不变 |
| E3-T04 | legacy：create/rotate/delete/export | 422/403/403/403；legacy 原样存在；GET 可见 `reserved:true, mutable:false` |
| E3-T05 | delete 成功（带 key） | 双 inbound 移除；派生目录删除；注册表清理；审计 ok |
| E3-T06 | rotate 成功 | name 不变；uuid/password 同时变更；整份 canonical 再生；Monitor 身份不变 |
| E3-T07 | rotate 遇 reload 失败 | 503 commit_rolled_back；配置=旧凭据；重试安全 |
| E3-T08 | create/delete 遇健康检查失败 | 503；create→不存在；delete→完整存在+目录未删 |
| E3-T09 | 回滚后仍不健康 | 500 rollback_manual_intervention；审计 CRITICAL |
| E3-T10 | 10 并发同名 create（各自 key） | 恰好 1×201、9×409；配置只有一个该用户且合法 |
| E3-T11 | 锁被长持时变更请求 | 423 lock_unavailable；锁空闲后正常 |
| E3-T12 | rotate 与 export 并发 | spool 快照为完整旧版或完整新版（uuid-password 配对一致），永不撕裂 |
| E3-T13 | 幂等 replay：同 key（helper 自算 digest 同） | 返回原结果 + `Idempotency-Replayed:true`；零第二次事务 |
| E3-T14 | CSRF：无 token / 错 Origin / 表单编码 / export POST 无头 | 403 / 403 / 415 / 403 |
| E3-T15 | step-up：auth_age > 300s 的 rotate/delete | 401 reauth_required；重认证后重放成功 |
| E3-T16 | 凭据卫生（响应与审计） | API 响应 + 两份审计 grep UUID/password/private/YAML = 0 命中 |
| E3-T17 | 认证态隔离 | 改 admin password/whitelist/recovery key 前后 YAML 字节相同；无 config.lock 竞争 |
| E3-T18 | canonical yaml_gen 注入失败 | 201 + `yaml_available:false` + warnings；**export 仍成功且内容 = live 渲染**（D8） |
| E3-T19 | source 溯源（rev3） | registry 有 web 写入 ⇒ `source:"web"`；registry 缺失 ⇒ `source:"untracked"`（**绝不推断 "cli"**，含 legacy 展示行） |
| E3-T20 | 下载响应头 | attachment 文件名、no-store、nosniff、Referrer-Policy、X-Credential-Version（advisory） |
| E3-T21 | 注入坏 candidate（重复 uuid） | 500 candidate_rejected；live 未动；审计含问题行 |
| E3-T22 | 失败路径残留检查 | 所有 F1–F20 后无 candidate/临时/spool 残留（备份按 Phase C 语义保留） |
| E3-T23 | 一致性审计失败时写操作 | 409 config_inconsistent；GET 返回 + `consistency_problems` |
| E3-T24 | 审计 schema | 每条 JSONL 可解析、字段齐、无禁记内容（含 token 全文、cred digest 明文） |
| E3-T25 | （可选 canary）VPS 生产全链路 | create→连接→E1 Device=vmix-01→rotate→旧 YAML 断、新 YAML 通→delete |
| E3-T26 | 锁获取失败（helper mutation） | exit 4 → 423；配置字节不变；无 candidate/备份残留 |
| E3-T27 | flock 二进制缺失 | CLI 菜单 mutation 与 helper mutation 全部拒绝；配置字节不变（L3 验收） |
| E3-T28 | 锁长持超时（> 15s） | 拒绝；无写入痕迹；释放后重试正常 |
| E3-T29 | helper 输出通道卫生 | stdout/stderr/journald 采样/审计/error detail 中 grep UUID/password/URI/YAML = 0（含 export 与失败路径） |
| E3-T30 | HTTP response 丢失后重试（rotate） | 同 key 重试 → replay 原结果；恰好一次轮换（审计单条、credential_version 总增量=1） |
| E3-T31 | 同 key 重复提交 / 同 key 异 payload | 前者 replay；后者（helper 自算 digest 不同）→ 409 idempotency_conflict |
| E3-T32 | 无外部干预的 in_flight 调和（模拟 crash） | create：absent→重跑 / present+planned→replay；rotate：==old→重跑 / ==planned_new→replay；delete：absent→replay / ==old→重跑；调和后补 derived work + outcome |
| E3-T33 | spool 卫生与权限位 | dir 0710 root:sboxweb、files 0640；下载/失败/清扫后无残留；过期/孤儿文件被清扫 |
| E3-T34 | 一次性消费时序 | stream 成功 → consume_export 删除两文件；stream 中断（客户端断开）→ token 仍可重试至 TTL |
| E3-T35 | consume_export 形状约束 | 仅收 token；非法形状/带 path/glob ⇒ exit 2；spool 外任何路径不可达（E3-T58 同源） |
| E3-T36 | **（rev3 重写）Web restart → session 失效** | 重启后旧 session 不存在 ⇒ outstanding token 下载 = 404；spool 残留由清扫删除；不为 token 持久化 E2 session |
| E3-T37 | **Web 不能列举 spool 目录** | 以 sboxweb 身份 readdir(`spool/`) 被拒/为空（0710 组无 r）；无法发现任何 pending token |
| E3-T38 | **Web 仅 exact-token 可读** | 知道完整 token ⇒ 可读 `<token>.yaml`/`meta`；不知文件名 ⇒ 不可发现；对 spool 文件写/truncate 失败（0640 无组 w） |
| E3-T39 | **消费清理走特权边界** | Web 进程 unlink spool 文件必须失败（无目录写权）；删除仅由 `consume_export` 完成 |
| E3-T40 | **token used/expired/unknown 统一 404** | 三种情形全部 `404 download_unavailable`（同一错误码，不区分原因）；第二次绝不 200 |
| E3-T41 | **Web restart 失效语义（详版）** | 重启 → memory-only session 全失效 → meta 绑定落空 → 404；新 export 正常；清扫删除孤儿 |
| E3-T42 | **digest 所有权** | stdin 携带伪造 `request_digest` 字段 → 被拒绝/忽略且**无法影响账本**；账本 digest 与 helper 自算 canonical sha256 一致 |
| E3-T43 | **create 缺 Idempotency-Key** | Web 中间件 400 idempotency_key_required；helper 层同样拒绝（双层） |
| E3-T44 | **rotate 缺 Idempotency-Key** | 400 idempotency_key_required（双层） |
| E3-T45 | **delete 缺 key / 失联+重建** | 缺 key → 400；DELETE 成功 response 丢失 + 外部重建同名 → 同 key retry → 409 idempotency_reconcile_conflict，**replacement 完好** |
| E3-T46 | **create in-flight + 外部 create** | intent in_flight 期间外部建同名 ⇒ retry 调和：current != planned ⇒ 409 reconcile conflict；不覆盖外部对象 |
| E3-T47 | **rotate in-flight + 外部 rotate** | current ∉ {old, planned_new} ⇒ 409 reconcile conflict；不自动判成功、不再 rotate |
| E3-T48 | **delete in-flight + delete/recreate** | name 存在且 current != old ⇒ 409 reconcile conflict；**绝不删除 replacement** |
| E3-T49 | **intent append 失败** | exit 9 → 503 idempotency_ledger_unavailable；**零变更**（配置/派生/spool 全不变）；同 key 重试安全 |
| E3-T50 | **intent fsync 失败** | 同 E3-T49：mutation 不得开始 |
| E3-T51 | **outcome append/fsync 失败（commit 已成功）** | 503 idempotency_state_uncertain；**配置保持已提交且服务健康（不回滚）**；同 key 重试 → 调和补账 → replay 一致结果 |
| E3-T52 | **outcome 最终性** | done result 含最终 `yaml_available`/`warnings`（yaml_gen 失败场景亦然）；replay 与首次最终结果逐字段一致 |
| E3-T53 | **export 真值 = live config** | rotate 后立即 export（canonical 未再生/registry 缺失均可）⇒ 下载内容 == live 新凭据渲染；永不复用旧 canonical 内容；registry 缺失 ⇒ `credential_version:null` 且下载成功 |
| E3-T54 | export 成功率与 registry 解耦 | registry 文件删除/损坏 ⇒ export/add/list 功能正常（advisory 字段 null） |
| E3-T55 | **full token 全链路日志扫描** | 扫描 helper stdout/stderr、journald fixture、**Web access log**、两份审计 JSONL：full token 命中 = FAIL；access log 中路径呈 `/api/v1/download/[redacted]` |
| E3-T56 | **helper 非空 argv** | `[ "$#" -ne 0 ]` ⇒ exit 2，零副作用 |
| E3-T57 | **SB_* 环境注入拒绝** | production helper 在 `SB_*` 存在时拒绝执行（exit 2/500，零副作用）；test-only wrapper 不受影响（非 sudo 白名单） |
| E3-T58 | **consume_export 无任意 unlink** | 固定 spool 内、仅 token 构造路径；携带 path/通配/穿越序列 ⇒ exit 2；spool 外文件不受影响 |

---

## 13. 显式非目标（Non-goals）

1. **不实现 E2**（Dashboard UI、登录页、会话存储本身）；E3 只定义并消费其中间件契约
   （含 access-log 脱敏这一集成要求）。**不为 E3 token 把 E2 session 持久化**（A-10）。
2. **NAS 集成完全不在范围内**：用户自行下载 YAML 放到 NAS，服务端不感知 NAS。
3. 不开任何公网端口 / 不做 TLS 终结 / 不改 VPS 网络与防火墙。
4. 不修改 `sbconfig_server.json` 的任何 schema、inbound 结构或现有用户；
   不在本轮触碰生产配置（本文档为零生产变更）。
5. 不写任何 client mutation 生产实现（本轮连 E3-0 的抽取/rotate 代码也不落地）。
6. 不 reload/restart sing-box（reload 只存在于未来实现的事务内部，设计文本除外）。
7. 不采用 Clash REST 配置修改模型；不新增任何直接写 JSON 的代码路径。
8. 不做多管理员/RBAC/多租户；不做单协议独立轮换（A-2）；不做 YAML 以外的导出格式。
9. 不改 E1 collector；不做流量历史持久化/数据库。
10. 不管理 whitelist / admin password / recovery key（E2 范畴）；不做备份 GC（U-5）。
11. 不做 E1/E2 已有代码的重构或"顺手优化"。
12. 不做分布式/跨机锁、不做 helper 常驻 daemon。
13. 不做 token oracle（used/expired/unknown 不区分，A-9）；不做账本跨机复制。

---

## 14. 本轮交付核对

* 设计文档：本文档 rev3（`docs/monitor-v2-e3-design.md`），architecture / API
  contract / Phase C 事务桥 / credential handling（含 Web boundary 精确化）/
  YAML 生成与下载模型（0710 spool + consume_export）/ rotate-delete 语义 /
  并发与锁契约 / 回滚失败矩阵 F1–F20 / 授权-CSRF-审计（含 token 脱敏）/
  E3 阶段 / 测试矩阵 T01–T58 / 非目标 —— 12 项齐备。
* 提议 API：六类操作 + consume_export（helper 内部）；下载 = 两步 token 流；
  create/rotate/delete 强制 Idempotency-Key；错误码表统一（404 统一 / 409 冲突 /
  503 不确定态）。
* 事务边界：§4（唯一互斥点 + fail-closed；唯一写路径 = 共享库；读过锁；
  planned/old digest intent + 调和矩阵 + fsync durability）。
* 安全边界：§2 权限表（0710 spool）+ §4.7 锁契约 + §5 Web credential boundary
  （精确化，不虚称"Web 无凭据字节"）+ §8（授权/CSRF/审计/token 脱敏）+ §9.4
  residual risks（含浏览器历史 token）。
* 已定案：§10.1（A-1…A-18）；未决：§10.2（U-1…U-9）。
* 生产变更：**无**。rev3 仍只改本文档；E3 实现 **NOT STARTED**；production
  **UNCHANGED**；未 reload/restart sing-box。
