# UM-127 03 — 连续离线重启、首次请求失败与 generation/seq 恢复语义（提案）

- 状态：**PROPOSED（提案，未批准）**。本文件不是已冻结契约，不能作为实现授权。
- 依赖：PR #126（UM-A revision 3 final，HEAD `5089cdeb`）的 `docs/um/um-a/04-node-protocol-v1.md`、`contracts/v1/`；本计划简称其为 **rev-4**。
- 本文件提出的修改属于冻结契约变更，必须走 UM-A 变更控制（书面提案、威胁模型影响、兼容性说明、正负向量更新、独立审查、Owner 授权）后才能进入 UM-B1/B2 代码冻结。
- 本文件中所有 Owner 决策均为 **PENDING**；未获批准前不得标记为 APPROVED。

## 1. 结论摘要

对 rev-4 冻结契约做逐条推演后，发现 4 个未闭合的恢复语义空档：

| 编号 | 空档 | 影响 |
| --- | --- | --- |
| F1 | 连续离线重启产生的 generation 跳号被 rev-4 明确拒绝 | 节点可能永久无法上报，只能运营方吊销重注册 |
| F2 | 新 generation 的“首次请求”被要求 `seq == 1`，但首次请求可能丢失后以 `seq = 2` 重试 | 首次请求失败后节点无法上报 |
| F3 | 跳号后的“迟到旧 seq 请求”如何分类、Agent 如何忽略，未定义 | 可能把良性迟到请求误判为安全事件并停队列 |
| F4 | rotation intent 跨多次离线重启时 generation 跳号，且 intent replay 与 boot high-water 的顺序未定义 | 轮换恢复与 generation 语义冲突 |

本文件提出 5 项修正提案（A-1..A-5），并定义 UM-B1/B2 必须实现的一致性测试用例（`conformance/transport-recovery.cases.json`，REC-01..REC-30）。

**签名串、header 集合、错误码集合均不改变**；修正只放宽 center 对合法请求的接受条件、补全 Agent 侧响应处理规则、并新增审计计数。因此 rev-4 已冻结的正负向量仍有效，但按变更控制仍需 UM-A rev-5 amendment 与独立审查。

## 2. 术语与持久状态

### 2.1 Agent 侧（um-agent）

| 状态 | 内容 | 持久化时机 |
| --- | --- | --- |
| `boot_state` | `{generation: uint64, boot_id: 32hex}` | 每次进程启动、使用前 fsync（file + directory） |
| `next_seq` | 当前 generation 内下一个 attempt 的 seq，从 1 开始 | 每个 attempt 发送前 fsync |
| `spool` | 有界（32 MiB / 7 d，单写者锁）payload 记录：`{report_id, collected_at, type, body}` | 首次发送前 fsync |
| `rotation_intent` | `{rotation_nonce, new_priv, new_pub, old_key_id, body_sha256, state, attempt_count}` | 发送 rotate 前 fsync |
| `single-writer lock` | 防止同一 node 出现两个 Agent 实例 | 启动时获取 |

定义：

- **generation（boot 世代）**：Agent 每次正常启动 +1，随机 `boot_id`；由签名 header `X-UM-Boot-Gen` / `X-UM-Boot-Id` 绑定。
- **attempt（传输尝试）**：一个 payload 的一次发送；每次 attempt 使用新的 `sent_at` / `nonce` / `seq`。
- **首次接触（first contact）**：某 generation 中第一个被 center **接受并提交**的请求。
- **离线重启**：Agent 启动时 center 不可达，或上一次启动后没有任何请求被 center 接受就再次重启。
- **终态响应**：`2xx`（accepted/duplicate/stale_ignored）、不可重试 `4xx`、或 `401 revoked_key`。

### 2.2 Center 侧（um-center）

沿用 rev-4 §5 的持久表：`node_boot`、`seq_dedupe`、`report_dedupe`、`nonce_dedupe`、`boot_registry`、`key_rotations`，全部在单个 SQLite 事务（`synchronous=FULL`）中提交后 ACK。

新增/明确的审计状态（非授权来源）：

| 状态 | 用途 |
| --- | --- |
| `boot_gap_events`（或 security ledger 条目） | 记录 generation 跳号：`{node_id, old_highest, new_gen, gap, first_contact_at}`；只含计数，不含 payload |
| `superseded_attempt` 计数 | 迟到且未被接受的低 seq attempt，限速记录 |
| `boot_identity_conflict` / `stale_boot_generation` 安全事件 | 保持 rev-4 语义，用于告警 |

## 3. rev-4 契约逐条核对

### F1 — 连续离线重启的 generation 跳号

rev-4 `04-node-protocol-v1.md` §5 规定：

- `gen == highest_gen + 1`：正常重启；accepted only if first request (`seq == 1`)；
- `gen > highest_gen + 1`（skip）：`409 boot_identity_conflict`。

反例（合法、无攻击行为）：

1. 节点已注册，center `highest_gen = 0`（或上次接受的是更早 generation）。
2. Agent 启动 → generation 1，离线；重启 → generation 2，离线；重启 → generation 3。
3. 网络恢复，首个请求携带 generation 3、`seq = 1`。
4. rev-4 规则判定 skip（3 > 0 + 1）→ `409 boot_identity_conflict`。

Agent 每次重启必须 +1 且不能复用旧 `boot_id`（防重放），它又无法知道 center 的 `highest_gen`，因此**跳号不可避免**。rev-4 §6.3 的 “Agent restart mid-spool” 只覆盖单次重启，未覆盖连续离线重启。结论：rev-4 的 skip 拒绝规则与 Agent 持久化规则自相矛盾。

### F2 — 首次请求丢失后的 seq

rev-4 规定新 generation 的首个请求必须 `seq == 1`。但 Agent 的 seq 是“每个 attempt +1，发送前持久化”，因为 center 无法区分“请求从未到达”和“请求已提交但 ACK 丢失”：

1. generation g 首次 attempt：`seq = 1`，网络丢包，center 从未收到。
2. Agent 重试（新 nonce/sent_at，`seq = 2`），这次到达 center。
3. center 看到 generation g（= `highest_gen + 1`）但 `seq = 2` → rev-4 要求 `seq == 1` → 拒绝。

若 Agent 改用 `seq = 1` 重试，则当第 1 次 attempt 实际已提交（ACK 丢失）时，center 的 `node_boot.last_seq = 1`，新指纹不同 → `409 sequence_conflict`（rev-4 §5 明确）。两种选择都失败。结论：rev-4 的 “首次请求 seq==1” 约束在首次请求失败场景下不成立。

### F3 — 跳号后迟到旧 seq 请求的处理

按 F2 场景，若首次接触以 `seq = 2` 被接受，而 `seq = 1` 的原请求因网络延迟稍后到达：

- rev-4 规则：`seq < last_seq`，且 `seq_dedupe` 中没有该 fingerprint → `409 sequence_conflict`。
- Agent 可能把任何 409 当作“停止队列，等待运营方”的安全事件（rev-4 §6.2 的 auth/sequence 错误策略），造成良性迟到请求触发停摆。

rev-4 没有定义“已被后续 attempt 取代的 attempt 的迟到响应如何处理”。需要补充 Agent 侧规则，避免把良性迟到误判为需要人工介入。

### F4 — rotation intent 跨离线重启

rev-4 §7 允许 rotate 重试“same nonce/body + 刷新的 sent_at/seq/boot_gen”，并要求 center 按 `(node_id, nonce, old_key_id, body_sha256)` 精确匹配 intent 后重放同一响应。但它没有定义：

1. 若 Agent 在 rotation intent 持久化后连续离线重启，重试请求的 `boot_gen` 跳号时，F1 规则是否仍拒绝、还是 intent replay 优先；
2. boot/seq high-water 的更新与 intent replay 的先后顺序（成功 replay 是 2xx，按 rev-4 §5 的“single durable transaction”应提交 transport state；但 rev-4 未写清）；
3. `stale_boot_generation` 与 intent replay 冲突时谁优先（例如 Agent 从旧快照恢复）。

## 4. 修正提案（normative）

以下 A-1..A-5 为规范性提案。A-1/A-2/A-4 涉及冻结契约变更，A-3/A-5 为补全性澄清（仍需随 amendment 一起审查）。

### A-1 接受单调递增的 generation 跳号

Center 按以下规则处理 node-auth 请求（report/config/rotate 共用；rotate 另见 A-5）：

1. 解析 `gen`、`boot_id`、`seq`，并完成 header/编码/签名/时间窗/nonce 基础校验。
2. 若 `gen < highest_gen` → `409 stale_boot_generation`（不变；退役 generation 永不重新激活）。
3. 若 `gen == highest_gen`：
   - `boot_id == node_boot.boot_id` → 继续 seq 校验（见 A-2/A-3）；
   - 否则 `409 boot_identity_conflict`（不变）。
4. 若 `gen > highest_gen`：
   - 设 `gap = gen - highest_gen`；要求 `1 <= gap <= MAX_BOOT_GAP`（提案值 `65535`，冻结为常量）；
   - 若 `gap > MAX_BOOT_GAP` 或算术溢出 → `409 boot_identity_conflict` + 安全事件，不改变任何状态；
   - 否则接受为“新 generation 首次接触”，在同一事务中设置：
     `highest_gen = gen`、`boot_id`、`last_seq = seq`、`last_fingerprint = fingerprint`；
     写 `boot_registry` 条目；`gap > 1` 时写 `boot_generation_gap` 审计条目（含 gap 值）；
   - 首次接触的 `seq` 可以是任意 `>= 1` 的值（见 A-2），不再要求 `seq == 1`。
5. 新 generation 的首个 report 即使 `report_id` 已存在（duplicate），仍必须在同一事务提交上述 transport high-water（保持 rev-4 的 duplicate-first-report 规则）。
6. 任何后续校验失败导致事务回滚时，上述 high-water 不提交（保持 rev-4 的 commit-before-ACK 语义）。

Agent 侧行为不变：每次启动仍 `generation + 1`、新 `boot_id`、`seq` 从 1 开始。修正只在 center 接受规则。

### A-2 新 generation 的首次接受请求允许 `seq > 1`

1. 对 `gen > highest_gen` 的请求，center 不再要求 `seq == 1`；要求 `seq >= 1`（header grammar 已保证）。
2. 提交时 `node_boot.last_seq = 收到的 seq`（不是固定 1），`last_fingerprint = 该请求 fingerprint`。
3. 之后该 generation 的 seq 规则保持 rev-4：`seq > last_seq` 接受；`seq == last_seq` 且 fingerprint 相同 → duplicate，不同 → `409 sequence_conflict`；`seq < last_seq` 且 `seq_dedupe` 无精确 fingerprint → `409 sequence_conflict`。
4. ACK 的 `next_seq = last_seq + 1`（uint64，溢出保护）。

理由：Agent 无法区分“未到达”和“ACK 丢失”，只能每次 attempt 递增 seq；center 对“从未接受过的 generation”没有可比较的 seq 基准，因此以首个被接受的请求作为基准是唯一自洽语义。

### A-3 ACK `next_seq` 采纳与“被取代 attempt”的响应处理

1. Agent 在每个 attempt 发送前持久化递增后的 `next_seq`（write-before-send）。
2. Agent 收到任一 2xx ACK 后：`next_seq = max(next_seq, ack.next_seq)` 并持久化；删除对应 spool 记录。
3. Agent 必须把“响应”与“attempt”绑定（`report_id` + generation/boot/seq 或内部 attempt id）。若响应对应的 attempt 已被后续 attempt 取代（同一 spool 记录已有终态结果，或进程已重启），忽略该响应，不改变状态。
4. Center 对迟到低 seq 请求维持 `409 sequence_conflict`（rev-4 不变）；该错误对“已被取代的 attempt”是良性的，Agent 记录限速诊断即可，不得停队列。只有当**当前最新 attempt** 收到 `409 sequence_conflict` 时才进入 operator 恢复路径。
5. Center 可增加 `superseded_attempt` 限速计数用于运维观测，不属于契约授权语义。

### A-4 boot-state 丢失 / 快照恢复

保持 rev-4 的 fail-closed 语义，并明确：

1. `boot_state` 缺失、损坏、或从旧快照恢复（generation 低于 center `highest_gen`）：Agent 不重置、不复用旧 `boot_id`，停止上报（本地 `boot_state_corrupt` 条件），保留 spool，等待运营方吊销 + 重新注册。
2. 不允许“原地 generation reset”或“用旧 boot_id 继续”；center 对任何低 generation 请求保持 `409 stale_boot_generation`。
3. Agent 必须做到：`boot_state` 在首次使用前 fsync；`next_seq` 在发送前 fsync；单写者锁；否则不得发送。

### A-5 rotation intent 跨 generation 跳号

1. rotate 重试的 intent key 保持 rev-4：`(node_id, nonce, old_key_id, body_sha256)`；允许刷新 `sent_at`、`seq`、`boot_gen`。
2. Center 处理 rotate 的顺序固定为：identity/key state → signature → nonce intent match → boot/seq 校验 → replay/状态机。
3. 若 intent 存在且未过期：返回与首次相同的 `rotate-response`（200），并且按 A-1/A-2 在同一事务提交 transport high-water；随后新 key 的 proof report 按正常 report 规则处理。
4. 若 intent 已过期/aborted：`409 rotation_expired`，不提交 transport high-water；Agent 走 aborted 路径（删除 provisional key，旧 key 仍 active）。
5. 若 `gen < highest_gen`（例如 Agent 从旧快照恢复后重试旧 intent）：`409 stale_boot_generation` 优先，不重放成功响应；Agent 停止并等待运营方（不得绕过）。
6. 若 `gen > highest_gen` 且在 `MAX_BOOT_GAP` 内：允许 intent replay，并提交 high-water（A-1）。
7. 新 key proof report 若跨越离线重启（generation 跳号）按普通 report 的 A-1/A-2 规则处理；proof 成功的判定保持 rev-4（任一 2xx 新 key 请求即 confirmed）。

## 5. 恢复场景规范表

下表的期望结果均为对 center 持久状态与 Agent 队列行为的断言；`REC-*` 对应 `conformance/transport-recovery.cases.json`。

| ID | 场景 | Agent 行动 | Center 结果 | 状态变化 |
| --- | --- | --- | --- | --- |
| REC-01 | 在线正常重启 | gen+1、新 boot_id、seq=1 | 200 accepted | highest_gen=gen, last_seq=1 |
| REC-02 | 新 generation 首次请求丢失，重试 seq=2 | 新 nonce/sent_at，seq=2 | 200 accepted | highest_gen=gen, last_seq=2 |
| REC-03 | ACK 丢失后重试 | 新 nonce/sent_at，seq=last+1，同 report_id | 200 duplicate | last_seq 前进；spool 删除 |
| REC-04 | ACK 丢失后重启，首请求为重复 report_id | gen+1，seq=1 | 200 duplicate | 新 generation high-water 提交 |
| REC-05 | 连续离线重启 2 次后重连 | gen 跳 2，seq=1 | 200 accepted | highest_gen=gen, gap 审计 |
| REC-06 | 连续离线重启 N 次、spool 回放 | gen 跳 N，oldest-first | 200 accepted/duplicate 混合 | high-water + report_id 去重 |
| REC-07 | 跳号超过 MAX_BOOT_GAP | — | 409 boot_identity_conflict | 无状态变化 |
| REC-08 | 同 generation、不同 boot_id | — | 409 boot_identity_conflict | 无状态变化 |
| REC-09 | 已退役 generation 重放 | — | 409 stale_boot_generation | 永不重新激活 |
| REC-10 | 迟到低 seq attempt（已被取代） | 忽略响应、限速诊断 | 409 sequence_conflict（可预期） | 无状态变化；队列继续 |
| REC-11 | `seq == last_seq` 且 fingerprint 相同 | — | 200 duplicate | 无数据写入 |
| REC-12 | `seq == last_seq` 且 fingerprint 不同 | — | 409 sequence_conflict | 无状态变化 |
| REC-13 | 多次 ACK 丢失后采纳 next_seq | 持久化 max(next_seq, ack.next_seq) | 200 accepted | 无冲突 |
| REC-14 | center 重启后重试 | 重试同 payload | 200 duplicate/accepted | 持久状态存活 |
| REC-15 | 首个请求 503 后重试 | backoff 重试 | 200 accepted | 首次失败不产生 high-water |
| REC-16 | 首个请求 payload 不可重试 | quarantine 记录，继续后续 | 400 | 下一条成为首次接触 |
| REC-17 | Agent boot_state 缺失/损坏 | 停止上报、保留 spool | 无请求 | 运营方吊销+重注册 |
| REC-18 | Agent 从旧快照恢复 | 不得原地重置 | 409 stale_boot_generation | 运营方处理 |
| REC-19 | rotation intent 跨 2 次离线重启 | same nonce/body，刷新 transport | 200 相同 rotate-response | high-water 提交 |
| REC-20 | rotation intent 过期后跨重启 | — | 409 rotation_expired | 走 aborted 路径；旧 key active |
| REC-21 | 撤销期间 spool 积压 | 停止上报、保留 spool | 401 revoked_key | 运营方处理 |
| REC-22 | 首次接触是 config 拉取（body `{}`） | seq>1 重试 | 200 agent-config | 与 report 相同 high-water 规则 |
| REC-23 | 首次接触是 rotate | 见 A-5 | 200 rotate-response | high-water 提交 |
| REC-24 | 注册响应丢失 | 收到 `401 token_used` | — | 运营方吊销 orphan + 新 token；新 key 重注册 |
| REC-25 | `MAX_BOOT_GAP` 边界（正好 65535） | — | 200 accepted | 审计 gap |
| REC-26 | generation/seq uint64 极值/溢出 | — | 409 invalid/conflict | 无状态变化 |
| REC-27 | Agent 掉电后 seq 未持久化 | — | 允许 seq 回退到已提交 last+1 或报 sequence_conflict | 记录诊断 |
| REC-28 | center 掉电后 Agent 重试 | — | 已提交 → duplicate；未提交 → accepted | 无重复应用 |
| REC-29 | 旧快照 report 晚于新快照到达 | — | 200 stale_ignored | 不覆盖 latest |
| REC-30 | 两 generation 的 spool 交错回放 | oldest-first | duplicate/accepted | report_id 去重，无乱序覆盖 |

### 5.1 各状态下 center 的判定顺序（伪代码）

```text
on node_auth_request(req):
  validate headers/encoding/size/time-window      # 400/413/401 stale_timestamp
  authenticate signature                            # 401 bad_signature/unknown key
  node = lookup(req.node_id); event binding         # 401/403
  if req.endpoint == rotate and intent_match(req):  # A-5
      if gen < highest: return 409 stale_boot_generation
      if gap > MAX_GAP: return 409 boot_identity_conflict
      commit(high_water per A-1/A-2 + replay intent)
      return 200 replay(intent.response)
  if gen < highest: return 409 stale_boot_generation
  if gen == highest and boot_id != node_boot.boot_id: return 409 boot_identity_conflict
  if gen > highest:
      gap = gen - highest
      if gap < 1 or gap > MAX_BOOT_GAP: return 409 boot_identity_conflict
      # first contact: accept any seq >= 1 (A-2), last_seq = req.seq
  else: # gen == highest
      check seq per rev-4 §5 (with A-3 for agent-side classification)
  begin tx; nonce/boot/seq/report_id; apply data; commit high_water+data
  return 200 ACK(result, next_seq=last_seq+1)
```

## 6. 威胁与兼容性分析

### 6.1 为什么接受 generation 跳号是安全的

- **不能重新激活退役 generation**：`gen < highest_gen` 仍然 `409 stale_boot_generation`；`boot_registry` 有界不影响该判定。
- **前跳不能被旧身份伪造**：请求必须由当前 active key 签名；rotation confirmed 后旧 key 已吊销。攻击者若已持有 active key，本就可对该 node 身份做任何请求（吊销后失效），generation 前跳不提供额外能力。
- **重放窗口受限**：`|server_time − sent_at| ≤ 300 s` + unique `(node_id, nonce)` + 完整 request fingerprint；捕获的旧请求超出 300 s 即 `stale_timestamp`；300 s 内的重放至多让 center 记录该 node 的一条真实历史请求（report_id 去重、不覆盖更新快照）。
- **不能越过 current boot 接受旧数据**：跳号只抬高 high-water；旧 generation 请求仍被 stale 拒绝；同一 generation 的不同 boot_id 仍 conflict。
- **MAX_BOOT_GAP=65535** 防止损坏/恶意极大值把 high-water 推到不可恢复；超过则 `boot_identity_conflict` + 安全事件，由运营方处理。
- 审计：每次 gap>1 写 `boot_generation_gap` 条目（含 node_id、old/new gen、gap、first_contact_at），便于发现异常重启风暴。
- 残余风险：攻击者在 300 s 内重放一条“尚未被 center 见过”的合法请求，可能让 high-water 提前到该请求的 generation；由于该 generation 必来自该 node 的真实 boot，且真实 Agent 当前 generation 只会 ≥ 它，不会把真实 Agent 阻塞成 stale；同时 report_id 去重避免数据重复。该残余风险与现有 nonce/时间窗/签名重放风险同阶，不因 A-1 放大。

### 6.2 兼容性

- 签名串、header、错误码、schema 均不变；rev-4 的 `test-vectors.v1.json` 与 `negative-vectors.v1.json` 保持有效。
- 旧 Agent（rev-4 实现）行为不变；新 center 对旧 Agent 只放宽接受条件（原先会被拒绝的合法跳号/seq>1 现在被接受），属于向后兼容。
- 该修改仍是对冻结语义的变更：按 UM-A §5 变更控制，必须发布 rev-5 amendment（文档 + 新增 behavioural vectors + 独立审查），不能以“实现细节”为名直接改代码。

### 6.3 被否决的替代方案

| 方案 | 否决理由 |
| --- | --- |
| B：Agent 合并 generation，只发 `last_ack_gen + 1` | Agent 无法知道 center 是否已接受上一 boot 的请求（ACK 丢失歧义）；复用 boot_id 会被同 generation 不同 boot_id 规则拒绝 |
| C：只允许 gap ≤ 1，要求运营方重注册 | 离线重启是正常运维场景，重注册需要吊销 + 人工介入，违背无人值守目标 |
| D：把 generation 改为每 key 的计数器或允许回退 | 破坏重启防重放与 retired-generation 不可激活的核心性质 |
| E：center 保存完整 boot 历史并要求证明 | Agent 无法为“丢失的 boot”提供证明；只会把问题转移 |
| F：用 center 时间/连接次数生成 generation | 需要双向状态，增加新的重放面；且离线时不可用 |

## 7. 对 UM-B1/B2 一致性测试的要求

1. **先红后绿**：UM-B1 必须先提交按 rev-4 文本会失败的用例（F1/F2/F4），再按 amendment 实现并转绿；测试名与 case id 对应，禁止用实现细节绕过。
2. **UM-B1（协议库 + store + 迁移）**：A-1/A-2/A-3 的纯函数/状态机测试、SQLite 事务与重启持久化测试、`node_boot`/`seq_dedupe`/`boot_registry` 断言、MAX_BOOT_GAP 边界、uint64 溢出、冻结正负向量回归。
3. **UM-B2（ingest + 认证 + 去重）**：合成 Agent harness 跑 REC-01..REC-30 全矩阵；center 重启、并发/背压、限速、审计条目；错误码与 ACK 字段逐项断言。
4. **UM-B3（Agent）**：持久化与 fsync、boot-state 丢失/旧快照恢复、spool 回放、rotation intent 跨重启、单写者锁、双平台（Linux/Windows）行为一致。
5. 测试产物：`docs/um/um-127/conformance/transport-recovery.cases.json` 为规范性输入；每个 case 必须能映射到至少一个自动化测试（B1 或 B2/B3 切片），并在 PR 中给出测试名与 CI 链接。
6. 向量冻结要求：新增/修改的 behavioural cases 需要作为 amendment 的一部分独立审查；不得在实现 PR 中私自改 case 期望。

## 8. 未决 Owner 决策（本文件相关）

| ID | 决策 | 建议 | 状态 |
| --- | --- | --- | --- |
| OD-R1 | 是否批准 A-1（接受 generation 跳号，MAX_BOOT_GAP=65535） | 批准 | PENDING |
| OD-R2 | 是否批准 A-2（新 generation 首次接受请求允许 seq>1） | 批准 | PENDING |
| OD-R3 | 是否批准 A-3/A-5 的 Agent 响应规则与 rotation 顺序 | 批准 | PENDING |
| OD-R4 | 是否接受 `boot_generation_gap` 审计条目与安全事件告警策略（阈值/通知渠道） | UM-B2 给出默认值后 Owner 确认 | PENDING |
| OD-R5 | 是否将 F1/F2 作为 rev-5 amendment 先于 UM-B1 代码冻结 | 是 | PENDING |

以上决策与 `05-owner-decisions.md` 统一登记；在本文件或任何 PR 中不得把 PENDING 写成 APPROVED。

## 9. 随 amendment 一并清理的 rev-4 文档不一致（仅记录）

以下问题由本轮逐条核对发现；本文件**不直接修改** rev-4 文档，统一在 PR-A2 amendment 中处理：

| 项 | 问题 | 处理 |
| --- | --- | --- |
| 命名 | UM-A 03/05/06 引用 `node_seq`，04/08 使用 `node_boot` | 统一为 `node_boot` |
| 保留表 | `seq_dedupe` 未列入 UM-A 03 §9/05 §2 的保留表 | 补入并给 bounded 值 |
| 错误码 | `replay` 在 error 枚举中但未被任何规则使用 | 删除或定义使用场景（需向量审查） |
| 残留 | UM-A 06 SEC-38 的 `pending_activation`、NEG-ROT-01/contracts README 的 “old key grace”、UM-A 04 §6.1 的旧表述 | 与 rev-3 final 状态机对齐后删除/改写 |
| 历史计数 | “11 行 state-transition / 35 case” 等旧计数 | 统一为当前 45 behavioural cases + 13 state-transition（如有变动以 amendment 为准） |
| 向量 | 缺 rotate/config 正向量；SPKI “optional” 措辞与 schema 必填/nullable 不一致 | PR-A2 补向量并统一措辞 |
| 签名串文摘 | 历史文摘可能仍按无 boot-gen 的 14 行表述 | amendment 全文检索，统一为 rev-4 的 15 行（含 `boot-gen`） |

这些清理不改变 A-1..A-5 的语义，只是让契约文本自洽；清理本身也需独立审查。
