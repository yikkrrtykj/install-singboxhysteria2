# UM-A 06 — Threat model, security test plan and performance budget (revision 2)

Status: design freeze for UM-A review. Revision after PR #126 review (P1-02,
P1-03, P1-04, P1-06). No implementation exists; this defines what UM-B..UM-E must
prove. The CI harness flake of run 45688706441 is an existing Windows-acceptance
test-infrastructure issue outside UM-A and is not fixed here (review contract §4).

## 1. Method and honesty note

STRIDE per trust boundary ([03](03-architecture-and-trust-boundaries.md) B1–B9) +
explicit abuse cases + invariants. The center is one process with two listeners:
route/network isolation is real, **process isolation is not**. The security
acceptance targets for SEC-18/19/20 below are written for that architecture; no
"different Handler = different privilege domain" claim is made.

## 2. Assets and actors

Assets: node authenticity (Ed25519 keys, bootstrap tokens, event binding), admin
identity (password/TOTP/recovery/session, Cloudflare Access gateway), monitoring
data (event/node inventory, protocol/traffic/client summaries, fault history,
audit), platform integrity (center binary/config, SQLite DB/backups, master key,
tunnel token), business availability (sing-box/Mihomo/HA must never be affected),
existing systems' contracts/verdicts.

Actors: internet scanner/opportunist; holder of a stolen node key; compromised
event VPS; malicious agent; malicious/compromised event_admin/viewer; stolen
browser session; compromised Cloudflare edge/account/tunnel token; center-host
compromise; backup thief; operator error; flood/resource exhaustion; a hostile
agent sending replayed/historical/forged reports.

## 3. STRIDE summary (revised boundaries)

| Boundary | Spoofing | Tampering | Repudiation | Disclosure | DoS | Elevation |
| --- | --- | --- | --- | --- | --- | --- |
| B1/B2 CF→web | invalid/`alg:none`/wrong-aud JWT; header-only login | request smuggling; header duplication | missing auth-failure audit | verbose errors/caching | CF/Access outage; bot flood | header/JWT treated as login; session not bound to CF subject |
| B3 node→ingest (tunnel option A or direct TLS option B) | forged/stolen key; replayed historical request; enrollment token replay | body substitution; encoding mismatch; endpoint swap; duplicate headers | accept without audit/dedupe | payload privacy; error oracle | flood; gzip/body bombs; slowloris | revoked/pending key accepted; cross-event report; boot replay |
| B4 process→DB | local file access | SQL injection; unsafe migration; restore of stale DB | missing audit | plaintext secrets at rest | DB lock/size exhaustion | DB file writable by another uid |
| B5 backup/ledger | wrong version; forged ledger | backup/ledger tampering | restore without audit | plaintext off-host theft | backup fills disk | restore revives revoked nodes/purged data |
| B6 browser↔admin | session hijack; XSS | CSRF; cookie flags | missing mutation audit | UI leaks | login flood/lockout DoS | scope bypass/IDOR across events |
| B7/B8 agent↔local | reading another user's data; file permission abuse | symlink/TOCTOU on key/spool/credentials | silent spool tampering | credentials in logs | local resource abuse | agent root/socket/exec escalation |
| B9 business systems | — | UM writing config | — | UM centralizing credentials | UM influencing traffic | UM-F unauthorized write |

## 4. Abuse cases and required controls

| # | Abuse case | Control | Test ID |
| --- | --- | --- | --- |
| 1 | Access JWT forged / missing / wrong `aud`/`iss` / `alg:none`/HMAC confusion | cryptographic JWT verification, allowlist algorithms, claims, fail-closed JWKS | SEC-01/02 |
| 2 | Replay an expired Access JWT | exp/nbf + clock skew; session also expires; no header-only login | SEC-03 |
| 3 | Access misconfigured to allow everyone | local password + TOTP + session still required; Access subject bound to session | SEC-04 |
| 4 | Localhost/loopback claims admin | no localhost bypass; local login mandatory | SEC-05 |
| 5 | Login brute force / user enumeration | rate limit, lockout, closed errors, audit | SEC-06 |
| 6 | TOTP replay / recovery-code reuse | single-use counters, hashed one-time codes | SEC-07 |
| 7 | Stolen session / XSS | `__Host-` Secure HttpOnly SameSite=Strict, CSP, rotation, server-side revoke | SEC-08 |
| 8 | CSRF | per-session CSRF + Origin on every mutation; GET never mutates | SEC-09 |
| 9 | Cross-event access (A admin reads B) | server-side scope + SQL predicate; 404 for out-of-scope | SEC-10 |
| 10 | Enrollment token brute force/expiry/reuse | hashed single-use token, TTL ≤15 min, event binding, audit | SEC-11 |
| 11 | Stolen node key forges reports | signature over headers+decoded body; identity binding; revocation; anomaly detection | SEC-12 |
| 12 | Report replay/reorder/old boot | signed operation binding, nonce dedupe, boot/sequence, `report_id` dedupe, persistent center state | SEC-13 |
| 13 | Historical (>300 s old) data re-sent to bypass freshness | transport `sent_at` is fresh each attempt; payload age bounded by spool 7 d; center records ingest lag; dedupe by report_id | SEC-13 |
| 14 | ACK loss / center crash / power loss double-apply or data loss | durable spool-before-send, `synchronous=FULL` commit-before-ACK, idempotent report_id; state-transition tests doc 04 §6.3 | SEC-13 |
| 15 | Agent sends UUIDs/passwords/keys/YAML/source IPs/free text | closed schemas + privacy allowlist + sentinel tests (stored/logged/returned/backup) | SEC-14 |
| 16 | Flood / huge bodies / gzip bombs / slowloris / header duplication | caps before parse, explicit encoding, duplicate-header rejection, timeouts, rate limits | SEC-15 |
| 17 | Center DB stolen | no SSH/root creds/private keys; TOTP secrets encrypted with separate master key; 0600/0700 | SEC-16 |
| 18 | Backup stolen/tampered | encrypted off-host; integrity/shape verification; restore audited + owner-approved | SEC-17 |
| 19 | Web handler compromised (same process) | read-only web paths; no SSH/sbox-cm/VPS write; route separation; sandbox; **acceptance target: monitoring data + admin session memory may be exposed, business/VPS write never** | SEC-18 |
| 20 | Ingest handler compromised (same process) | no VPS write path; node auth separate; **same-process DB/admin-memory exposure accepted in v1**; process split is a future decision, not claimed now | SEC-19 |
| 21 | Center host compromised | blast radius: monitoring data/admin sessions; no business proxy path; no central root credentials; no sbox-cm access | SEC-20 |
| 22 | Agent compromised | only its own node can be forged; no other nodes/events; no local service writes; key revocable; no exec/root | SEC-21 |
| 23 | Unauthorized remote write (UM-F) | no write endpoints/SSH/command channel; route-inventory test | SEC-22 |
| 24 | Malformed/evil JSON (duplicate keys, deep nesting, huge ints, NaN) | strict parser/bounds/schema; closed enums | SEC-23 |
| 25 | Supply-chain compromise | pinned modules/lockfiles/dependency review/build receipt; no CDN | SEC-24 |
| 26 | Attack via existing systems | UM does not modify/embed monitor-v2/sbox-cm/#67/HA-UI; no-touch tests | SEC-25 |
| 27 | Operator error (wrong purge/role grant) | type-to-confirm, audited RBAC, least privilege | SEC-26 |
| 28 | Clock manipulation makes old reports fresh | signed `sent_at` + center clock + 300 s window; monotonic scheduling | SEC-27 |
| 29 | Retention silently fails / disk fills | retention metrics, degraded state, disk guard, accelerated 30 d test | SEC-28 |
| 30 | Header/encoding/endpoint ambiguity or cross-endpoint signature reuse | frozen header inventory, duplicate/missing/invalid-header rejection, encoding allowlist, endpoint/method/path bound in signing string | SEC-29 |
| 31 | Enrollment signed body includes its own signature (circular) or body/header key mismatch | signature only in header; pubkey/body binding; negative vectors | SEC-30 |
| 32 | Agent provisioning: non-root reads root token / root-owned file cleanup / resident root collector | root one-shot installer + pipe to unprivileged enrollment, agent-owned state, token deleted by root, no resident root process | SEC-31 |
| 33 | Agent executes shell/systemctl or widens privileges | seccomp no-exec, D-Bus read-only, LoadCredential, no sudo; static + runtime test | SEC-32 |
| 34 | Missing metric is faked as zero/healthy | availability status + nullable/unknown schema; UI honesty test; no fabricated ONLINE/OFFLINE | SEC-33 |
| 35 | Restore revives revoked node/purged data | security ledger + quarantine restore + replay/owner confirmation | SEC-34 |
| 36 | CF Access identity changes but local session survives / JWT/session mismatch | session bound to Access subject; JWT revalidated per request; mismatch = 403 | SEC-35 |
| 37 | Duplicate header smuggling / key id confusion | raw header-list inspection; single occurrence of each header; mismatch = 400 | SEC-29 |
| 38 | Rotation/enrollment response loss causes duplicate identity or lost rotation | persisted rotate intent, idempotent retry/transition table, pending_activation handling | SEC-36 |
| 39 | Enrollment response loss leaves an unreachable-but-active orphan identity | node is active on commit; admin identifies/revokes orphan; no activation inference from unobservable response | SEC-37 |
| 40 | Rotation grace timer revokes the old key while the agent only has the old key (or bypasses a revoked key) | old key revoked only after new-key proof; expiry aborts only the provisional new key; unprovable state stops reporting for operator recovery; no auto-bypass | SEC-38 |
| 41 | Read-only claim rests on client method allowlist while the credential is server-side write-capable | source switches default false; server-side authorization audit required before enable; unproven source disabled with `unavailable`/`source_authorization_unproven`; Mihomo disabled in v1 | SEC-39 |
| 42 | Restore/ledger incompleteness revives revoked nodes or purged data | security ledger fsynced before commit; latest-version chain/checkpoint; incomplete ledger ⇒ quarantine, no auto ingest | SEC-34 (extended) |
| 43 | Runtime semantics (service name/inbound tag/timestamps/availability) pass schema but are forged/misleading | runtime closed allowlists, tag/kind match against center config, temporal bounds, availability coherence, sentinel scan; reject/quarantine, never render | SEC-39 |

## 5. Security invariants (never regress)

1. Only the header `X-UM-Signature` authenticates node requests; no signed body
   contains a signature field (no circular input, no body-signature ambiguity).
2. Signing strings bind protocol, endpoint, method, path, identity/key/boot/seq,
   authentication time, nonce, content encoding and decoded-body SHA-256.
3. A report is stored only after signature + freshness + nonce/report/boot/seq +
   schema + privacy allowlist validation; all failures are closed codes with no
   payload content and no partial write.
4. `accepted` is returned only after a durable (`synchronous=FULL`) transaction
   covering data + dedupe + sequence; commit failure → 503/no ACK.
5. `report_id` is the idempotency key across retries/restarts; an older
   authenticated snapshot never overwrites a newer applied snapshot.
6. The web listener never serves `/v1/agent/*`; the ingest listener never serves
   `/api/*`, cookies, HTML or session logic.
7. Authentication never depends on source IP/localhost/unverified headers. CF
   Access JWT is verified and bound to the session subject; it is a gateway, not
   a substitute for password+TOTP.
8. The center stores no VPS root credentials, private keys, API secrets, raw
   YAML, UUIDs, passwords, source IPs or raw connection records; missing metrics
   are null/unknown, never fabricated.
9. UM-A..UM-E contain no center→node command channel; remote write requires a
   separate approved UM-F design with operation-level authorization.
10. Agent: unprivileged, no listener, no exec/root/sudo/shell/systemctl,
    `LoadCredential` for API secrets, bounded ordered spool; existing
    Monitor/sing-box/sbox-cm permissions are not widened.
11. Event scope is resolved server-side and applied in SQL; out-of-scope objects
    are indistinguishable from missing.
12. Every administrative mutation, auth failure, revoke/retire, purge and restore
    is audited (closed action/result, no secret content); a restore cannot
    silently re-enable ingest before ledger reconciliation.

## 6. Security test plan by phase

**UM-B**: SEC-11..SEC-15, SEC-16 (storage), SEC-19 (storage/handler boundary),
SEC-21, SEC-23, SEC-24, SEC-25, SEC-27, SEC-28, SEC-29 (protocol half), SEC-30,
SEC-31, SEC-32 (agent), SEC-33, SEC-36, SEC-37 (enrollment orphan lifecycle),
SEC-38 (rotation state machine incl. response loss/restart/expiry/revocation),
SEC-39 (source authorization gating + runtime semantic validation), SEC-34
(ledger half); contract conformance: both positive signed vectors verify,
tampered/wrong-key/cross-endpoint negatives fail, schema negative examples are
rejected, duplicate-header/encoding/config-body/size/boot/nonce/seq-retry cases,
rotation recovery cases and source-disabled data honesty behave.

**UM-C**: SEC-01..SEC-10, SEC-15 (web), SEC-18 (web half, honest same-process
targets), SEC-26, SEC-35; CSP/cookie/header tests, session rebinding, Access
misconfig, login DoS, audit completeness.

**UM-D**: SEC-10 endpoint matrix, XSS/encoding, pagination/authz bounds, retention
visibility, data-honesty tests (UNKNOWN/STALE, nullable metrics, closed details),
alias handling.

**UM-E**: SEC-20, SEC-22 route-inventory, SEC-25 no-touch, SEC-29 both transport
options where applicable, SEC-31/32 agent install/runtime proof, SEC-34
restore/ledger drill (incomplete-ledger quarantine), SEC-37/38 recovery
transitions, SEC-39 source authorization evidence, backup theft/restore, disk
pressure + quota enforcement, center restart, Cloudflare outage vs direct-TLS
ingress failure matrix, center-offline business-independence,
1 h disconnection + agent restart + center restart + lost ACK + revocation +
historical boot replay (doc 04 §6.3), install/upgrade/rollback/uninstall,
load/soak, independent review.

## 7. Performance budget (UM-E acceptance gates)

### 7.1 Center (2 vCPU / 4 GiB / 40 GB, 200 nodes, policy B)

| Metric | Target |
| --- | --- |
| Idle CPU | <2 % of 2 cores |
| Steady CPU at 200 nodes | <25 % of 2 cores |
| RSS at 200 nodes | <512 MiB |
| Ingest p95 (including durable commit) | <150 ms |
| Durable report transaction p95 | <50 ms (`synchronous=FULL`) |
| Web API p95 | <300 ms |
| Backup <10 min; retention <5 min/hour; 30-day DB ≤14 GB policy B at 200 nodes |
| 500-node stress | passes or PostgreSQL gate opens (doc 05 §5); not assumed |

### 7.2 Agent

Same as revision 1: CPU <1 % of one core (30-min avg), RSS <64 MiB, disk ≤150 MiB
(spool ≤32 MiB), egress ≤20 MB/day at default cadence, start-to-first-report
<5 s, 1 h outage replay in order without duplicates, no exec/listener/root, writes
only its own state dir. Add: enrollment + rotation complete within 30 s on a
healthy node; no source-read failure is converted into a fake zero/healthy state.

### 7.3 Frontend

Same as revision 1 (≤300 KiB gzip initial JS, no CDN/external fonts, FCP target
≤1.5 s after API data); each new dependency requires ADR-UM-007 review.

### 7.4 Measurement plan

Synthetic agent harness (N nodes, cadence, replay/failure injection), DB generator
for 30-day volume, scenarios S1–S8 (idle, 200 steady, 500 stress, 10× burst,
backlog replay, retention+backup+dashboard concurrent, accelerated 30-day
DB+restart/restore, restart + admin-plane outage) plus scenario S9: 1 h
disconnection with agent restart, center restart, lost ACK and revocation.
Targets are gates: a miss is reported, not averaged away.

## 8. Residual risks accepted at UM-A (re-evaluate in UM-E)

1. Single center host is a single point of failure for the admin plane and newly
   arriving telemetry; business services are unaffected by design.
2. Single-process center: an ingest-handler compromise can expose monitoring data
   and admin session memory; there is no VPS/business write capability. Process
   isolation is an optional later design, not claimed.
3. Machine ingress Option A exposes payload plaintext to the Cloudflare edge; the
   node signature still authenticates/integrity-protects it. Option B exposes a
   public TLS port that must absorb unauthenticated traffic. Owner decides.
4. Node-key compromise allows forged telemetry for that node until revocation.
5. Center-host compromise exposes monitoring data/admin sessions; no central root
   or VPS write path exists to contain escalation into business systems.
6. Backup confidentiality depends on owner key handling; restore can revive
   revoked/purged state unless the security ledger is reconciled (procedure
   frozen; UM-E must prove it).
7. Human error (wrong purge/role grant) reduced by type-to-confirm/audit, not
   eliminated.
8. Existing Windows acceptance-harness flake (PR #126 CI attempt 1) is a test
   infrastructure risk for a separate owner-authorized hotfix; it is not part of
   the UM design and no test/workflow was modified here.

## 9. Out of scope / deferred

UM-F remote client management (own threat model, operation-level authorization,
not started); formal certification/pen-test beyond the UM-E independent review;
multi-region/HA; SIEM/observability SaaS; any change to existing per-VPS systems.
