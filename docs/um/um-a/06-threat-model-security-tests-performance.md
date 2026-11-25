# UM-A 06 — Threat model, security test plan and performance budget

Status: design freeze for UM-A review. This document defines what UM-B..UM-E
must prove; it does not claim any test has been executed (no implementation
exists yet).

## 1. Method

STRIDE per trust boundary + explicit abuse-case scenarios + invariant tests. The
boundaries are the ones frozen in [03](03-architecture-and-trust-boundaries.md):
B1 Cloudflare edge, B2 tunnel→web listener, B3 internet→ingest listener,
B4 process→DB, B5 backup medium, B6 browser session, B7 local services→agent,
B8 agent private files, B9 existing business systems (never touched).

## 2. Assets

1. Node authenticity: node Ed25519 private keys (on nodes), public key registry,
   bootstrap tokens, event assignment.
2. Admin identity: passwords (Argon2id hashes), TOTP secrets, recovery codes,
   sessions/CSRF tokens, Cloudflare Access gateway configuration.
3. Monitoring data: event/node inventory, protocol/traffic/client summaries,
   fault history, audit log — private customer telemetry.
4. Platform integrity: center binary/config, SQLite DB and backups, master key,
   cloudflared tunnel token.
5. Business availability: sing-box/Mihomo/HA service on each VPS (UM must never
   affect; center outage must be harmless).
6. Existing systems' contracts/verdicts: #33/#48/#67, per-VPS Monitor, HA-UI.

## 3. Actors

- Internet opportunist/scanner; targeted attacker with a stolen node key; a
  compromised event VPS; a malicious/compromised agent; a malicious or
  compromised event_admin/viewer account; a stolen browser session; a compromised
  Cloudflare edge/account or tunnel token holder; a center-host compromise; a
  backup medium thief; accidental operator error; resource-exhaustion/flood.

## 4. STRIDE summary per boundary

| Boundary | Spoofing | Tampering | Repudiation | Information disclosure | DoS | Elevation |
| --- | --- | --- | --- | --- | --- | --- |
| B1/B2 CF → web | forged/missing Access JWT; algorithm confusion; wrong `aud`/`iss` | header injection; request smuggling | audit gap on failed auth | verbose errors; admin data leak via cache | CF/Access outage; bot flood | header-only login bypass |
| B3 node → ingest | forged node signature; stolen key; replay | body tampering (signature must fail); sequence/nonce games | accept without audit trail | payload privacy; error oracle | flood; gzip/body bombs; slowloris | revoked key still accepted; cross-event report |
| B4 process → DB | local privilege to DB file | SQL injection; unsafe migration | missing audit | plaintext secrets at rest | DB lock/size exhaustion | DB file writable by other uid |
| B5 backups | restore of wrong version | corrupted/edited backup | restore without audit | plaintext/off-host theft | backup fills disk | restore used to bypass retention |
| B6 browser ↔ admin | session hijack; XSS-driven actions | CSRF; cookie flags | missing audit for mutations | UI leaks secrets/history | login flood/lockout DoS | role scope bypass; IDOR across events |
| B7/B8 agent ↔ local | reading other users' data | symlink/TOCTOU on key/spool | silent tampering of spool | credentials in logs/UI | local resource abuse | agent root/socket escalation |
| B9 business systems | — | UM writing config | — | UM centralizing credentials | center/agent influencing traffic | UM-F unauthorized writes |

## 5. Abuse cases and required controls (test IDs are the UM security plan)

| # | Abuse case | Control (contract) | Test ID |
| --- | --- | --- | --- |
| 1 | Attacker sends `Cf-Access-Jwt-Assertion` without a valid signature | verify JWT signature via team JWKS, allowlist RS256/ES256 only, validate `iss`/`aud`/`exp`/`nbf`, fail closed on JWKS outage | SEC-01 |
| 2 | `alg: none` / HMAC-key-confusion JWT | algorithm allowlist; reject unknown/`none` | SEC-02 |
| 3 | Replay a captured valid Access JWT after expiry | `exp`/`nbf` + bounded clock skew; no session reused without local login | SEC-03 |
| 4 | Access misconfigured to allow all; attacker reaches login page | local password + TOTP still required; no header-only auth | SEC-04 |
| 5 | Direct loopback/localhost request claims admin | no localhost bypass; local login mandatory | SEC-05 |
| 6 | Login brute force / credential stuffing | rate limit per CF identity + username + peer; lockout; closed errors; audit; no user enumeration | SEC-06 |
| 7 | TOTP replay within the time window | single-use TOTP counter/enrollment tracking; replay rejected | SEC-07 |
| 8 | Stolen session cookie / XSS exfiltration | `__Host-` Secure HttpOnly SameSite=Strict; CSP `default-src 'self'`; session rotation; bounded TTL; server-side revoke | SEC-08 |
| 9 | CSRF from a malicious page | per-session CSRF token + Origin check on all mutations; GET never mutates | SEC-09 |
| 10 | Viewer/event_admin of event A reads event B | server-side scope resolution + SQL scope predicate; 404 for out-of-scope ids | SEC-10 |
| 11 | Unauthorized node enrollment (stolen/expired token) | single-use hashed token, TTL ≤15 min, event binding, one-time use, audit | SEC-11 |
| 12 | Attacker with a stolen node key submits forged data | signature over exact body bytes; key id/node binding; revocation immediate; anomaly detection | SEC-12 |
| 13 | Captured report replay / reorder / gap games | nonce dedupe, timestamp window, boot+seq rules, body hash duplicate rules | SEC-13 |
| 14 | Agent sends UUIDs/passwords/keys/YAML/source IPs in payload | closed schema + privacy allowlist at center; sentinel tests assert not stored/logged/returned | SEC-14 |
| 15 | Flood: millions of reports / huge bodies / gzip bombs / slowloris | per-node + per-IP + global limits; body caps pre-parse; read timeouts; decompression caps; 429/413 | SEC-15 |
| 16 | Center DB stolen | no root SSH/passwords/private keys stored; TOTP secrets encrypted with separate master key; node private keys never central; file perms 0600/0700 | SEC-16 |
| 17 | Backup stolen / tampered | encrypted off-host; integrity/shape verification on restore; restore is audited and owner-approved | SEC-17 |
| 18 | Web process compromised | read-only web paths; no SSH/sbox-cm/VPS write capability; ingest auth separate; systemd sandbox | SEC-18 |
| 19 | Ingest process compromised | no DB beyond monitoring tables; no node-private-key material; no command channel | SEC-19 |
| 20 | Center host compromised | blast radius limited to monitoring data/admin sessions; no business proxy path; no central root credentials | SEC-20 |
| 21 | Node agent compromised | can only forge reports for its own node; cannot affect other nodes/events; cannot write any local service config; key revocable | SEC-21 |
| 22 | Unauthorized remote write attempt (UM-F not authorized) | no write endpoints/SSH/command channel exist in UM-A..UM-E; verified by route inventory test | SEC-22 |
| 23 | Malformed/evil JSON (deep nesting, duplicate keys, huge ints, NaN) | strict parser limits, schema + bounds, closed enums; reject before storage | SEC-23 |
| 24 | Supply-chain compromise (Go module/npm) | pinned versions + lockfiles + dependency review + build receipt; no CDN | SEC-24 |
| 25 | Attack via existing systems | UM does not modify/embed `monitor-v2`, `sbox-cm`, #67, HA-UI; integration tests prove no writes | SEC-25 |
| 26 | Operator error: wrong event purge / role grant | type-to-confirm purge, audited RBAC changes, no self-elevation, least privilege | SEC-26 |
| 27 | Clock manipulation makes old reports fresh | signed timestamps + center time + 300 s window; local wall clock not authoritative | SEC-27 |
| 28 | Data retention silently fails and disk fills | retention run metrics/alerts/degraded state; disk guard; UM-E 30-day accelerated test | SEC-28 |

## 6. Security invariants (must never regress)

1. The web listener never serves `/v1/agent/*`; the ingest listener never serves
   `/api/*`, cookies, HTML or session logic.
2. Authentication is never based on source IP, localhost, or an unverified header.
3. A node report is stored only after signature + freshness + replay + schema +
   privacy allowlist validation; failures are closed codes without payload.
4. Request signing covers the exact body bytes; no JSON canonicalization is
   trusted for authenticity.
5. The center stores no VPS root credentials, private keys, API secrets, raw
   YAML, UUIDs, passwords, source IPs or raw connection records.
6. UM-A..UM-E contain no center→node command channel; remote write requires a
   separate approved design (UM-F) with operation-level authorization.
7. Every administrative mutation and every auth failure is audited with
   actor/target/result and no secret content.
8. Data isolation: an account's allowed event set is resolved server-side and
   applied in SQL; out-of-scope objects are indistinguishable from missing.
9. `sbox-cm`, journald/root, HA-UI SSH paths and existing deployments are not
   reachable from center/agent code.
10. Center outage cannot affect business services (no shared runtime, no
    connection to client traffic, agents only spool).

## 7. Security test plan by phase

**UM-B (node plane / storage)**: SEC-11, SEC-12, SEC-13, SEC-14, SEC-15 (ingest
half), SEC-16 (storage half), SEC-19 (storage half), SEC-21, SEC-23, SEC-24,
SEC-25, SEC-27, SEC-28; contract unit tests reproduce the committed test vector
and reject tampered bodies/nonces/sequences.

**UM-C (web/auth)**: SEC-01..SEC-10, SEC-15 (web half), SEC-18, SEC-26; plus
CSP/HSTS/cookie flag tests, session revocation, password/TOTP/recovery flows,
audit completeness, login DoS bounds.

**UM-D (dashboard/history)**: SEC-10 (endpoint matrix over every route), XSS/
output-encoding, pagination/authz bounds, history purge/retention visibility,
"STALE/UNKNOWN" honesty tests (no fabricated ONLINE/OFFLINE).

**UM-E (platform/deployment)**: SEC-20, SEC-22 route-inventory test, SEC-25
existing-systems no-touch checks, backup theft/restore, disk pressure, center
restart, cloudflare outage, center-offline business-independence proof, agent
spool replay after outage, node reboot, load/soak, install/upgrade/rollback/
uninstall, and an independent security review of the actual deployment.

## 8. Performance budget (targets for UM-E acceptance)

### 8.1 Center (2 vCPU / 4 GiB / 40 GB, 200-node planning ceiling)

| Metric | Target | Measurement |
| --- | --- | --- |
| Idle CPU (web+ingest+workers, no traffic) | <2 % of 2 cores | 30-min average from `/proc` |
| Steady CPU at 200 nodes | <25 % of 2 cores | 30-min average |
| RSS at 200 nodes | <512 MiB | sampled maximum |
| Ingest request p95 (accept + ack) | <100 ms | histogram server-side + client observed |
| Report storage transaction p95 | <20 ms | DB timing histogram |
| Web API p95 (dashboard/history query) | <300 ms | server timing |
| Backup duration | <10 min | job timing |
| Retention job (steady state) | <5 min/hour | job timing |
| DB size at 30 days / 200 nodes | ≤8 GB | measured vs model ±30 % |
| Scaling | 500-node stress run passes or PostgreSQL gate opens | UM-E load harness |

### 8.2 Agent (per event VPS)

| Metric | Target |
| --- | --- |
| CPU (30-min average) | <1 % of one core |
| sampled private working set / RSS | <64 MiB |
| Disk (binary + config + spool max) | ≤150 MiB (spool ≤32 MiB) |
| Network egress | ≤20 MB/day/node at default cadence |
| Startup-to-first-report | <5 s on a healthy node |
| Spool replay after a 1-hour center outage | all retained reports delivered in order, no duplicates on the server |
| Node write surface | only `/var/lib/um-agent`; no service/config write |

### 8.3 Web frontend

| Metric | Target |
| --- | --- |
| Initial JS transfer | ≤300 KiB gzip; no CDN/external fonts |
| First meaningful dashboard render on a 4G profile | ≤1.5 s after API data |
| Bundle/runtime dependency additions | each requires the ADR-UM-007 review |

### 8.4 Measurement plan

- UM-B ships a synthetic agent harness (N nodes, configurable cadence, replay and
  failure injection) and a DB generator for 30-day volume; UM-E runs it on the
  target VPS class.
- Scenarios: S1 idle; S2 200 nodes steady 30 min; S3 500-node stress; S4 10×
  burst for 5 min; S5 agent backlog replay after 1 h outage; S6 retention +
  backup + dashboard concurrent; S7 accelerated 30-day DB then restart/restore;
  S8 process/host restart and Cloudflare-unreachable admin plane.
- Every target above is a **gate**: a miss is reported, not averaged away, and
  the PostgreSQL/sizing decision follows doc 05 §4.
- No performance claim may be made from mocked tests only; UM-E needs the real
  binary on the real target host class (or owner-approved equivalent).

## 9. Residual risks accepted at UM-A (to re-evaluate in UM-E)

1. Single center VPS is a single point of failure for the **admin plane** and for
   newly arriving telemetry (business services are unaffected by design).
   Availability target is best-effort single-host, not HA.
2. The ingest listener is publicly reachable (direct TLS). It must withstand
   unauthenticated traffic; cryptographic auth and rate limits reduce but do not
   eliminate resource-exhaustion risk.
3. Cloudflare Access is an external dependency; misconfiguration could expose the
   login page, but not bypass the local password + TOTP gate.
4. Node-private-key compromise allows forged telemetry for that node until
   revocation; key rotation/revocation and anomaly detection limit duration.
5. Center-host compromise exposes monitoring data and admin sessions; the design
   intentionally contains no VPS root/write capability to keep the blast radius
   out of business systems.
6. Backup confidentiality depends on owner-held encryption key handling.
7. Operators can still make mistakes (wrong purge, over-broad role); audit +
   type-to-confirm + least privilege reduce impact, they do not remove it.

## 10. Out of scope / deferred

- UM-F remote client management (own threat model, operation-level authorization,
  not started).
- Security certification/pen-test beyond the independent review required by UM-E.
- Multi-region/HA design, SIEM/observability SaaS integration, and any change to
  existing per-VPS systems.
