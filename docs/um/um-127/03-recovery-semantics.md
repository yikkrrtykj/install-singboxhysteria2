# UM-127 03 — 连续离线重启、首次请求失败与 generation/seq 恢复语义（rev-5 最终）

- 状态：**FINAL（已冻结进 PR #126 rev-5）**；规范性文本为 #126 `docs/um/um-a/04-node-protocol-v1.md` §5–§7、§13 与 `contracts/v1/**`。本文记录规划侧语义、REC-01..REC-30 关联与决策状态，不构成实现/合并授权。
- 基线：#126 HEAD `048fc170`（tree `1b726de9…`）。
- 历史：#126 rev-4（`5089cdeb`）的 F1–F4 空档由本 rev-5 修正；旧行为向量期望保留在 `superseded_rev4_expectations`。

## 1. rev-5 修正结果（A-1..A-5）

| 编号 | rev-4 空档 | rev-5 规范结果 |
| --- | --- | --- |
| F1 | 连续离线重启产生 generation 跳号，rev-4 要求 `gen==highest+1` 否则 conflict | center 接受 `1 ≤ gen−highest ≤ MAX_BOOT_GAP(65535)` 的新 generation 首接触；gap>1 写 `boot_generation_gap` 审计；gap>65535 → 409 `boot_identity_conflict`；旧 generation 仍 `stale_boot_generation` |
| F2 | 首次请求丢失后以 `seq=2` 重试被 rev-4 拒绝 | 新 generation 首个**被接受**请求允许任意 `seq≥1`，`last_seq` 取该 seq；不存在“必须先 seq==1” |
| F3 | 跳号后迟到低 seq attempt 的响应未定义 | agent 以 `report_id`+attempt 绑定响应；已被取代 attempt 的迟到响应忽略；只有最新 attempt 的 `sequence_conflict` 才进 operator recovery |
| F4 | rotation intent 跨 generation 跳号与 high-water 顺序未定义 | rotate retry 先做完整 signature/identity/boot/seq/nonce 校验，再做 intent replay；replay 与 high-water 同一事务提交；stale/seq 失败不 replay |
| A-3 | ACK `next_seq` 采纳规则未明确 | agent 持久化 `max(local_next_seq, ack.next_seq)`；`next_seq:null` 表示 generation 数值耗尽，不得复用 seq，需干净重启新一代或 operator recovery |
| A-4 | boot-state 丢失/旧快照恢复 | fail-closed 不变：不重置 generation、不复用旧 boot_id；operator revoke + re-enroll（新 node_id）；旧快照恢复得到 `stale_boot_generation` |
| A-5 | rotate intent 可刷新 transport 字段 | 保留同 nonce/body 刷新 `sent_at`/`seq`/`boot_gen`，但必须通过完整 boot/seq/identity 校验；intent match 只替代“完全相同的 attempt fingerprint”匹配，不绕过 high-water |

**继续 fail-closed**：`gen < highest_gen`、同 generation 不同 boot_id、`gap > MAX_BOOT_GAP`、撤销、boot-state 丢失、不可证明的 rotation 状态。`MAX_BOOT_GAP=65535`、`MAX_NUMERIC=2^63−2` 是设计常量，不是运行期参数。

## 2. 数值边界、ACK 与 SQLite 存储

- `X-UM-Boot-Gen`、`X-UM-Seq`：canonical decimal（无前导零/`+`/空白），范围 `[1, 9223372036854775806]`；越界/非 canonical → 400 `invalid_header`，在任何 `uint64→int64` 转换前拒绝，绝不 wrap。
- `sent_at`：canonical decimal `[0, 2^63−1]`；`collected_at` 等 body 时间仍按 schema 上限。
- generation gap：`gen > highest_gen` 时 `gap = gen−highest`；`1..65535` 接受，`>65535` → 409 `boot_identity_conflict`（不是 invalid_header），无 high-water 变化 + 安全事件。
- ACK `next_seq`：`last_seq<MAX` 时为 `last_seq+1`；`last_seq==MAX` 时为 **null**（generation 耗尽）。agent 不得复用/回绕 seq；center 对同 generation 后续请求（无可用 seq）以 invalid_header 拒绝；generation 达到 MAX 是终局 operator 条件。
- SQLite：所有协议数值以 signed 64-bit `INTEGER` + CHECK 存储，禁止 TEXT/BLOB/REAL；`next_seq` 为 nullable INTEGER；WAL + `synchronous=FULL`，数值 high-water/dedupe/payload 同一事务提交后 ACK。
- 设计参数 vs 运行期参数：以上为**设计决策（现已冻结）**；`stale_after_s`、cadence、R1/R2 最终源选择、保留容量等为运行期/部署参数，见 05 §H。

## 3. rotation retry 的完整校验顺序（不可绕过）

每次 rotate（含同 nonce intent replay）按顺序：

1. header/encoding/size/grammar + class binding；
2. node identity / key state（old key active、provisional 状态、撤销优先）；
3. old-key 签名；
4. boot：`gen<stale`、同 gen 不同 boot_id/gap>MAX → conflict；bounded forward gap 作为新 generation 首接触；
5. seq：完全相同已提交 attempt（同 seq+同 fingerprint）→ 幂等 replay；否则 `seq>last_seq`；`seq<=last_seq` 且无精确 fingerprint → sequence_conflict；
6. nonce intent：同 nonce 必须映射同 `(node_id,nonce,old_key_id,body_sha256)`；改 body/key/endpoint → `nonce_reuse`。

仅当 1–6 全部通过，才可**在同一事务**内 replay persisted `rotate-response` + 更新 `node_boot` high-water + nonce/dedupe。任何 boot/seq/identity 失败返回对应错误且不 replay、不更新 high-water。agent 对 stale/sequence 冲突按 fail-closed operator recovery，不重置状态。

## 4. REC-01..REC-30 关联

30 个用例保留原 ID 与预期（B1 12 / B2 15 / B3 3），见 `conformance/transport-recovery.cases.json`；规范性契约关联在 #126 `04` §6.4。关键更新：

- REC-02/05/06/19/22/23（rev-4 会失败的场景）在 rev-5 下成为**规范正例**；
- REC-26 数值极值改为 `MAX_NUMERIC=2^63−2` 边界 + ACK `next_seq:null`；
- REC-19/20 rotation 跨重启必须通过完整校验；
- REC-10 迟到低 seq 为可预期 `409`，agent 忽略，不停队列；
- REC-18/17 boot-state 丢失/旧快照仍 fail-closed。

用例 JSON 的 `rev4_expected_failure` 字段保留为历史证明标记；`status` 现为 `NORMATIVE`，`contract_revision:5`，`contract_commit` 指向 #126 rev-5 commit。UM-B1/B2/B3 必须全部实现并映射到自动化测试。

## 5. 威胁与兼容性摘要

- 接受 bounded generation 前跳是安全的：不能重新激活旧 generation；前跳不能由旧身份伪造（当前 active key 签名）；300s 新鲜度 + unique nonce + report_id 去重限制重放；bounded gap 防止损坏/恶意极大值；gap>1 审计。
- 签名串/header 不变；rev-4 报告向量仍有效；rev-4 的 skip/seq==1 行为期望已被替换但保留历史。
- 任何“实现细节”不得绕过上述规则；如需改变数值常量或 rotation 顺序，必须新 amendment + 独立审查。

## 6. 决策状态（不得把 PENDING 写成 APPROVED）

| ID | 内容 | 状态 |
| --- | --- | --- |
| OD-R1 | A-1 bounded generation jump + `MAX_BOOT_GAP=65535` | **DIRECTION-ACCEPTED（Owner Round-2）**；已冻结进 #126 rev-5；实现仍受 #126 review/merge 门禁约束 |
| OD-R2 | A-2 首接触 `seq>1` | 同上 |
| OD-R3 | A-3/A-5 ACK 采纳、superseded attempt、rotation 全量校验 | 同上 |
| OD-R4 | gap 审计/告警阈值与通知渠道 | **PENDING（运行期参数）**，UM-B2 给默认值后 Owner 确认 |
| OD-R5 | 是否先做 PR-A2 | **SUPERSEDED（OWNER：不再创建 PR-A2）** |
| Q-* / OD-P* | 既有 Owner 决策与双平台参数 | 见 05，全部非 APPROVED |

**DIRECTION-ACCEPTED 不等于 APPROVED**：Owner Round-2 只接受了方向并要求纳入 rev-5；独立审查、合并授权与运行期参数仍需单独确认。
