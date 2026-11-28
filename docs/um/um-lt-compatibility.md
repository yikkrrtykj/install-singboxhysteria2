# UM-LT — Compatibility and rollback matrix (rev-7 additive source)

Status: **CANDIDATE compatibility contract for the rev-7 package — docs-only,
pending independent review/CI and the Owner's conditional merge authorization.
NOT published/frozen, NOT merged, NOT implemented.** Normative protocol text:
[`um-a/04-node-protocol-v1.rev7.md`](um-a/04-node-protocol-v1.rev7.md).

The rev-7 source is additive and default-disabled. Nothing in this matrix
weakens the frozen rev-5/rev-6 contract: headers, signing strings, endpoints,
bodies (except the two new closed fields), numeric bounds, replay/dedupe/boot/
rotation/revocation rules, node classes and Windows behavior are unchanged.

## 1. Terms

| Term | Meaning |
| --- | --- |
| **A5** | agent build that only knows revision 5/6 (the current `main` agent behavior) |
| **A7** | agent build with rev-7 support but the source disabled/absent from its applied config |
| **A7+** | rev-7 agent whose applied effective-dated config has `collect.monitor_export = true` |
| **C5** | center build that only knows revision 5/6 (rejects any rev-7 field) |
| **C7** | center build with rev-7 support (may emit `monitor_export` only under the rollout/source gate) |
| **rev-7 record** | a spooled snapshot body containing `contract_revision: 7` / `traffic_observation` |
| **rev-5 record** | any frozen rev-5/rev-6 body (snapshot/metrics/events), byte-identical to today |

## 2. Capability model (no unauthenticated capability authorization)

- The only wire-level rev-7 capability signal is the boolean
  `collect.monitor_export` inside the authenticated, signed-config-pull response.
  There is no new header, no unauthenticated beacon, no environment variable, no
  local file flag and no center-supplied path/URL.
- **Agent rule:** emit rev-7 bodies only while the **latest applied**
  effective-dated center config has `monitor_export = true` (and the node is
  `linux_vps`). Absence/false means A7 behavior: only rev-5 bodies, no export
  read. The agent MUST NOT infer capability from a server banner, a version
  header, an ACK field, the presence of the export file, or a center URL.
- **Center rule (`CFG-REV7` agent-version gate):** a C7 center emits
  `monitor_export` only for a `linux_vps` node that (a) is enabled by the
  operator/rollout gate, (b) has the matching source-authorization audit version
  recorded, and (c) has a latest signed-snapshot `agent.version >= 1.1.0`
  (`MIN_REV7_AGENT_VERSION`; the rev-5 agent is `1.0.0`). The center tracks the
  latest version from a successfully authenticated snapshot and **MUST omit the
  key entirely** (not emit `false`) while the version is unknown, missing or
  older. Once a signed snapshot reports `>= 1.1.0`, the stored source-enable flag
  becomes effective at the **next config pull** (no manual re-enable or extra
  handshake); if a later signed snapshot reports an older version (agent
  rollback), the center omits the key again on the next pull. Comparison uses
  the numeric `major.minor.patch` components (eligible iff `major > 1` or
  `major == 1 and minor >= 1`); suffixes do not make an older build eligible.
  The version is a compatibility hint from an authenticated report, **not** a
  privilege grant: the source authorization is the versioned audit + operator
  gate; a node lying about its version can at most make itself unable to receive
  the key or receive a key its old agent rejects fail-closed. Normative detail:
  overlay §11.1; testable cases `CFG-REV7-01..05`.
- Config is validated per node class: `monitor_export=true` is invalid for
  `windows_terminal`; a Windows agent rejects such a config and keeps running its
  previously applied valid config while retrying the config pull. There is no
  cross-class downgrade.
- Reports are validated against the **effective-dated** config at `collected_at`
  (existing B2 rule). An enable→collect→disable sequence therefore preserves
  authorization for reports collected while enabled; a source never enabled
  cannot retroactively authorize a rev-7 record (`invalid_request`).

## 3. Deployment matrix

| Agent | Center | Config received | Payload emitted | Expected outcome |
| --- | --- | --- | --- | --- |
| A5 | C5 | rev-5 | rev-5 | current behavior, unchanged |
| A5 | C7 | rev-5 (no `monitor_export`) | rev-5 | C7 treats as rev-5; rev-7 tables stay empty for this node; no error |
| A5 (reports `agent.version 1.0.0`) | C7 with the stored source flag enabled | rev-5; **`monitor_export` key omitted entirely** until the latest signed snapshot reports `>=1.1.0` | rev-5 | `CFG-REV7-02`: enabling early is safe but not effective; the key appears only after the upgrade is reported and the next config pull, then behaves like A7+ |
| A7 | C5 | rev-5 (no `monitor_export`) | rev-5 only | A7 falls back to rev-5 behavior; source never read; traffic `unavailable` |
| A7 | C7 | rev-5 or rev-7 with false/absent | rev-5 | source disabled; node shows rev-5 `traffic: unavailable`; no fake zero |
| A7+ | C7 | rev-7 `monitor_export=true` | rev-7 bodies per cadence | validated/stored; lower bounds displayed with freshness/exactness labels |
| A7+ | C5 | impossible by config; if a rev-7 body still reaches C5 (race/rollback) | rev-7 body | C5 rejects with `400 invalid_request` (unknown/forbidden fields), no state change; A7+ quarantines the record (existing non-retryable rejection handling) and stops emitting rev-7 after its config refresh no longer advertises the switch |
| A7 | C7 with `monitor_export=true` sent by mistake | rev-7 key present | A7 build supports it → behaves as A7+; **A5** in the same position | A5's strict config validator requires exactly six collect keys and rejects the seventh → config rejected fail-closed; the frozen agent then retries the config pull immediately (no exponential backoff) and does not queue new snapshots, so collection effectively stalls until a compatible config is served. The center-side `CFG-REV7` gate is therefore mandatory, not defensive |
| Windows A5/A7 | C7 | rev-5 (never `monitor_export`) | rev-5 + terminal | unchanged |
| any Windows | C7 | malformed rev-7 config with `monitor_export` | — | agent rejects config (`platform_mismatch`/invalid), keeps previous config; center must never emit it |

Deployment order by design: upgrade the center first (C7 hardened for rev-5/6
payloads), then agents, then enable the source node-by-node after the rollout
gate. C5 first / A7+ later is also safe because A7 emits rev-5 until a C7 config
advertises the switch.

## 4. Old center rejects rev-7 payloads

- C5 validates against the frozen rev-5 schema (`additionalProperties: false`)
  and rejects a rev-7 body with `400 invalid_request` before data apply, with no
  transport high-water, dedupe or data change (the transaction rolls back).
- A7+ must therefore **never** send rev-7 bodies to a center that has not
  advertised rev-7 support in its applied config. The only supported way to
  detect this is the config pull: after a downgrade/rollback, the applied config
  no longer contains `monitor_export`, and the agent must stop creating rev-7
  records immediately and follow §5.
- The agent MUST NOT work around a C5 rejection by stripping
  `contract_revision`/`traffic_observation`, by re-signing a rewritten body, or
  by relabelling lower bounds as rev-5 totals. Relabelling would change the
  payload identity and would be a data-integrity/privacy violation.
- A rev-7 body rejected by C7 for an unauthorized tag/kind/class/epoch is
  quarantined by the agent (existing bounded quarantine) and never retried in a
  loop; the queue continues with later records and `status` exposes the
  quarantine count.

## 5. Queued rev-7 records on downgrade/rollback

Rules (normative):

1. **Stop creating** new rev-7 records as soon as the applied config no longer
   has `monitor_export=true` (config refresh bound is 300 s in the current
   runtime; operators plan rollback around it).
2. **Preserve identity.** Rev-7 spool records are fsynced payloads: the agent
   MUST NOT rewrite `report_id`, `collected_at`, type, body bytes or the stored
   attempt/fingerprint. Quarantine moves the record out of the send path with its
   bytes intact; it is never re-signed with a modified body.
3. **Drain old reports first.** Rev-5/rev-6 records remain sendable and are
   drained oldest-first under the unchanged replay rules. Rev-7 records are
   separated/quarantined when the center is known not to accept them, so they
   cannot block the rev-5 backlog.
4. **No automatic resurrection.** Rev-7 records quarantined because a C5 center
   or a disabled source cannot accept them are not automatically re-sent after a
   later re-upgrade in v1. They remain bounded, inspectable quarantine for
   operator diagnostics and age out under the frozen spool/quarantine bounds.
   The implementation PR may document an explicit, bounded, operator-triggered
   re-drive only if it preserves payload identity; absent that, quarantine means
   dropped from delivery, not rewritten.
5. **Bounded.** Total spool/quarantine remains within the frozen
   `32 MiB / 7 days` spool contract and the bounded quarantine; a downgrade must
   not cause unbounded growth or delete rev-5 records. If the bounded quarantine
   is full, the agent fails closed (existing behavior) rather than silently
   rewriting/deleting.
6. **Monitor-only disable is not a downgrade.** If the center remains C7 and only
   `monitor_export` is turned off, already-collected rev-7 records remain
   authorized by the effective-dated config at their `collected_at` and may be
   drained normally. The source simply stops producing new observations.

## 6. Rollback drain procedure (summary; full runbook in um-lt-runbook)

1. Operator disables `monitor_export` for the affected nodes (or fleet-wide) and
   observes the source switch off in agent config/status.
2. Wait for the config refresh bound plus normal spool drain; confirm the agent
   spool has no rev-7 records in the send path (or accept quarantine for any
   remainder) and that rev-5 record flow is healthy.
3. Only then roll back the center/agent binaries. Center rollback is
   guarded by the existing fail-closed DB schema-version rule: an old binary
   refuses a newer database instead of serving it; the rollback path is a
   pre-upgrade backup restore or a forward fix, never a silent downgrade of
   storage.
4. If rollback happened first, rev-7 records are rejected by C5, quarantined by
   A7+ (existing `invalid_request` handling); the operator drains rev-5 records,
   inspects the bounded quarantine and proceeds with the rollback.
5. Agent binary rollback: if the rev-7 implementation changes the local state
   schema, the old binary must fail closed on newer state (same rule as the
   center); the supported paths are a state backup restore or a forward fix.
   Implementations SHOULD avoid bumping the agent state version for this
   additive source.
6. Rollback is complete only when: rev-5 behavior is restored, no rev-7 body is
   in the send path, `singbox_api=false`/DISABLED is confirmed, the export writer
   is disabled or absent, and the source is off in every config.

## 7. Mixed fleet

- C7 may serve A5, A7 and A7+ nodes in one center. Per-node config decides the
  body form; rev-5 and rev-7 snapshots coexist in storage and query.
- Fleet aggregation of lower bounds must include only nodes with an available
  observation; rev-5/unavailable nodes render UNKNOWN/UNAVAILABLE, never `0`.
  An aggregate is still a lower bound and must be labelled as such.
- Rev-7 history buckets are separated by node and observation epoch; a Windows
  terminal, a rev-5 Linux node and a rev-7 Linux node never share a series or
  attribution.
- Windows nodes are unaffected in every mixed-fleet combination.

## 8. What the implementation PR must test

Real tests, not only JSON parsing (mapping to the acceptance matrix):

1. A5↔C5 unchanged regression (existing suite).
2. A7+C5: rev-5 only, no export read, source unavailable.
3. A7+C7 disabled: rev-5 only; center stores no rev-7 observation for the node.
4. A7++C7: rev-7 accepted, stored and query-presented with lower-bound labels.
5. C5 receiving a rev-7 body (direct HTTP): `400 invalid_request`, no state
   change, dedupe/seq high-water untouched.
6. A5 receiving a 7-key config: config rejected fail-closed; the frozen agent
   retries the config pull immediately without exponential backoff and does not
   queue new snapshots, so the center-side rollout gate (never emit to a
   non-rev-7 agent) is mandatory.
7. Queued rev-7 record on config downgrade: not sent to C5; quarantine preserves
   `report_id`/body bytes; rev-5 spool records drain and are acknowledged.
8. Center DB downgrade attempt: old binary fails closed on newer schema version.
9. Windows class: never receives/emits rev-7; violation is `platform_mismatch`.
10. `CFG-REV7` version gate (real center config generation, not only schema
    parsing): `CFG-REV7-01` no signed snapshot yet ⇒ key absent entirely;
    `CFG-REV7-02` latest signed snapshot `1.0.0` + stored flag set ⇒ key absent
    entirely (and not `false`); `CFG-REV7-03` signed snapshot `1.1.0` after an
    earlier `1.0.0` ⇒ the next config pull includes `monitor_export=true`
    without a manual re-enable; `CFG-REV7-04` later older reported version ⇒ key
    absent again; `CFG-REV7-05` `windows_terminal`/unknown class ⇒ never emitted.
    The test must observe the actual JSON response (presence/absence), not a
    stored flag.
11. Full negative-vector runner for `rev7/negative-vectors.json`
    (schema + implementation-semantic + `CFG-REV7` config-generation cases).
