# Monitor 0.8.0: event-time device evidence

Status: P6C merged in PR #71 on 2026-10-08 (`79b9aecda9cb7ee6706e339d443c28e8f2323474`); this record retains the implementation and closeout evidence.

Open **事件**, select an incident, then read **设备监测 · 事件时段**. The existing event judgment stays unchanged. The panel separately shows current reporting status and retained samples inside the stored event analysis window. **刷新设备记录** reloads those records; it neither starts a probe nor changes a device, service, Clash or TUN.

Current reporting means a recently retained sample exists, not that a Windows service has been queried. A silent device is unavailable evidence, never proof of path failure. Slot failures describe that specific DNS, HTTPS, TCP, egress or node test. TCP success is only transport reachability. Active delay tests describe the dedicated destination; cached observations may echo those tests and are not an independent second source. Public IP is the client's observed request egress, not necessarily its registered VPS or carrier identity.

Position and network-path labels come only from the current server registry. A retired/disabled/unavailable mapping has no reconstructed labels. Device identifiers are available under technical details. This phase does not read privileged enrollment credentials or join them into the incident response; registered Client/Device download management stays on its existing page.

## HTTP contract

`GET /api/v1/incidents/<incident_id>/remote-probes` passes the existing source whitelist and browser-session gate. It is GET-only; POST is refused. IDs are canonical ASCII positive integers bounded by the existing parser. A malformed/missing ID yields `incident_not_found`; unavailable core incident history yields 503. The server derives both bounds from `analysis_start_epoch` and `last_classified_end_epoch`. Query parameters cannot change the window, identity filter or record limit.

The exact response keys are `v`, `incident_id`, `window`, `retention`, `current_status`, `rows`, `truncated`, `limit`.

- `window`: `start_epoch`, `end_epoch` — the original incident analysis window.
- `retention`: `max_age_seconds`, `retention_cutoff_epoch`, `retained_since_epoch`, `budget_pruned`. Earliest retained time is global to the remote store, not a guarantee for every device or uninterrupted coverage.
- `current_status`: `observed_epoch`, `status`, `subcode`, `probes`. These are **current**, not incident-time status. Each probe has `probe_id`, `status`, `subcode`, `last_sample_epoch`, `site_label`, `path_label`.
- Each row: `sample_epoch`, `probe_id`, `mapping_retired`, `site_label`, `path_label`, `dns`, `https`, `vps_tcp`, `egress`, `mihomo_api`, `flags`, `active`. Slot and flags shapes reuse the accepted closed payload schema, revalidated at presentation to reject malformed or extra nested fields. Each active item exposes only `role`, `source`, `outcome`, `delay_ms`, `independent`.

Reads intersect the incident window with the existing up-to-seven-day evidence horizon and the capture time, enforcing existing store retention. At most 255 samples are returned, oldest first in stable store ordering; a 256th row proves truncation. A truncated response is not a census of all paths. Missing history may mean no upload, expiry, capacity pruning or unavailable storage; it is never presented as healthy. Durable receipts cannot resurrect pruned sample evidence. The route performs no admission or History write; the existing remote-only age/budget maintenance still runs under its original serialization boundary.

The registry lifecycle fence keeps labels coherent during a request. Storage/config failures produce a closed remote-only degradation state with no exception text; core incident history and classifier health remain independent.

## Compatibility and rollout

Only the server/UI release changes. VERSION and MONITOR_WEB_VERSION move together to candidate 0.8.0, and executable release pins are restated. The Windows Agent, signed installer, sample/HMAC schemas, ingest/store/registry implementations, History v5, classifier, presenter and runtime stay unchanged. No credential rotation, Windows signing or long native resource test is required by this presentation change.

CI runs the new real SQLite/HTTP tests plus the existing P5 exact-key, DOM, P6A/P6B, packaging and isolation suites. Existing VPS deployment follows review/merge through the established update flow; it is not performed by opening the panel. P6D and any standalone live device dashboard require separate scope.

## P6C closeout checklist（原 `p6c-todo.md` 合并）

Operator 于 2026-10-08 在 PR #70 合并与 existing-test-VPS 更新后授权。Base：`7c20a8251392d61f7f954292d0fe1ff9e4dbe056`；Monitor 版本 0.8.0；P6C 经评审并于 2026-10-08 随 PR #71 合并（`79b9aecda9cb7ee6706e339d443c28e8f2323474`）。History 保持 v5，remote store 保持 v1。

- [x] 独立 session-gated GET `/api/v1/incidents/<incident_id>/remote-probes`。
- [x] 严格有界 positive canonical incident ID；缺失 incident 404，不可读 History 503。
- [x] 服务端派生 `analysis_start_epoch` → `last_classified_end_epoch`；URL bounds/limits/filters 不能改变它。
- [x] 有界 retained sample projection：255 条 + 一条 truncation witness；receipt 不作为 evidence，不含 run/sequence/test 标识、key、endpoint 或原始请求字节。
- [x] 当前 reporting 状态与历史 incident 记录分离；不从静默推断 Windows 服务停止或路径故障。
- [x] Operator position/path label、retired mapping 不确定性、egress 变化、stale/unavailable 与 retention/budget 限制可见。
- [x] DOM-safe 中文事件呈现，显式刷新，技术标识置于 details，passive cache 标注非独立。
- [x] P5 list/detail keys、History/classifier/runtime/presenter 与 collection/ingest/storage 实现不变。
- [x] 本地 23 项 P6C SQLite/HTTP 测试、129 项 DOM 检查、148 项 P5 行为检查与 230 项 Agent 行为检查通过。
- [x] exact-head CI 验收：`9c8e69a46d2cad80db88935fe903f3a13666f570` 上全部 15 项检查与三个 workflow 通过；覆盖 Linux route/framing 与完整 packaging 回归。首次运行暴露过时的 pre-P6C static reference allowlist，P6C session dispatch 与 closed module-set gates 已在不删除 History/classifier isolation 检查的前提下重述授权范围。
- [x] PR 评审与合并决定：PR #71 已合并；scope、schema、session dispatch 与 protected-path isolation 已评审。
- [ ] 用 P6C 与 retired-device display fix（PR #72）更新现有 VPS；该 server/UI-only 变更无需重装 Windows。

既有 P6B route group 曾在 Windows 上尝试并在故意拒绝的 chunked 请求中因 WinError 10053 中止；其余 143 项 P6B 检查本地通过。保留该限制；Linux CI 仍是必需，不伪造本地全量 PASS。本阶段只做 incident supporting-fact presentation，不新增 standalone live device overview、任意时间窗浏览、classifier 消费、ISP lookup、failover 或 P6D。Position/path label 是当前 operator 断言，不是 incident-time routing 证明；不同 label 不构成独立 uplink。No source silence is reported as network down。History byte/schema/prune 与 classifier 合同不变。

### 历史回执补充（原 `p6c-todo.md`）

PR #72 组合候选在集成 main 后保留两组 UI 测试：135 项 DOM checks 与全部 23 项 P6C SQLite/HTTP tests 本地通过；PR #72 的最终 CI 与合并单独跟踪，成功的代码合并不等于 VPS 部署回执。本地 operator helpers、机器记录、key、下载 ZIP 或临时预览文件不属于该 PR。
