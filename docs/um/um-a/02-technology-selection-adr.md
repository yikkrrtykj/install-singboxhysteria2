# UM-A 02 — Technology selection decisions (ADR set)

Status: proposed by UM-A for independent review. No implementation is
authorized until this ADR set is accepted. The repo currently contains **no Go
code, no frontend framework and no container tooling**; every addition below is
a deliberate new dependency with an explicit justification.

## ADR-UM-001 — Center service language/runtime: **Go**

Decision: implement the center as a single Go binary (`um-center`) using the Go
standard library for HTTP/TLS/JSON/crypto, `database/sql` for storage and the
minimum number of pinned modules (see dependency policy).

Options considered:

| Option | Strengths | Weaknesses | Verdict |
| --- | --- | --- | --- |
| **Go** (chosen) | static single binary, no runtime install, low memory, strong stdlib HTTP/TLS/crypto, `embed` for frontend, easy systemd unit, predictable concurrency | new toolchain in repo/CI; team must review Go code | **ADOPT** |
| Python stdlib (like `monitor-v2`) | existing repo expertise, no new toolchain | GIL/threaded HTTP limits, per-request memory, more moving parts for a long-lived multi-tenant center, no static binary | reject for center |
| Rust | strongest safety/perf | implementation and review cost for a small team; no repo experience | reject |
| Node/TypeScript service | shared language with frontend | runtime + npm supply-chain surface; per-request server footprint; not the repo's operation model | reject |
| Managed service (Cloudflare Workers, hosted DB) | low ops | center must own node identity, storage, history, audit and backup; vendor lock-in and data residency for private monitoring data | reject |

Consequences: UM-B adds a Go module, pinned dependency list and a CI lane. The
center binary must build reproducibly (`-trimpath`, pinned Go version) and ship
with a source/build receipt. The Python `monitor-v2` is **not migrated**.

## ADR-UM-002 — Node agents: **Go, static, unprivileged, read-only** (`linux_vps` + `windows_terminal`)

Decision: one Go codebase with class-specific builds/services for the two
`node_class` values. Both classes are unprivileged, read-only observers; neither
has a listening socket, root/admin capability, `sbox-cm` socket access or a
remote command channel. They write only their own private state/spool directory.

- `linux_vps`: one statically linked binary (`um-agent`) for Linux (amd64 + arm64),
  systemd service, dedicated non-login user. It reads only the reviewed local
  read-only surfaces (sing-box `service.api` on loopback, `/proc`, read-only
  systemd D-Bus unit properties).
- `windows_terminal`: a Windows service/process for a dedicated user; it reads
  only a local loopback Mihomo/Clash Verge Rev data source and emits the six
  route tokens plus aggregate selection/connection samples. It never edits
  Mihomo/Clash Verge Rev configuration, switches nodes, closes connections or
  changes HA-UI/P6/#67 behavior. The R2 truly-read-only source is preferred; R1
  (a write-capable controller credential used by a GET-only client) requires a
  separate later owner risk acceptance and is never auto-enabled.

Provisioning is a **one-time orchestration, never a resident privileged agent**:
the reviewed Linux installer runs `um-agent enroll --token-stdin` as `umagent`
via `runuser`, feeding the root-only token over a pipe; the agent generates its
own key and owns its state directory; the installer deletes the token afterwards.
The Windows installer/service runs the collector unprivileged and stores only its
own protected state/credential material. The admin-issued bootstrap token carries
`{event_id, node_class}`; the agent cannot choose event or class. Existing
Monitor/sing-box/`sbox-cm` file permissions are never loosened; Linux sing-box API
credentials are delivered by systemd `LoadCredential=`, and the Windows source
credential (if R1 is ever accepted) uses DPAPI/private ACL only.

The Linux agent is **no-exec by construction**: `SystemCallFilter` denies
`execve`/`execveat` (plus `NoExecPaths=/` where supported). It therefore does not
call `systemctl`; unit state comes from restricted read-only D-Bus property reads
(`ActiveState`), and is `unknown` when unavailable. The sing-box client implements
only the audited read-only started-service subscription methods; there is no
generic RPC surface and no config-mutation call. UM-B must record the audited
sing-box version, method allowlist and a negative test. The Windows client is
likewise restricted to fixed loopback GET paths and closed token mapping; a
static/runtime test must prove no write method/path exists in the binary.

Alternatives rejected: running the existing Python collector on every VPS
(duplicates runtime/venv, needs per-VPS Python management); root-side journal
reader (privilege and #33 ownership; forbidden in doc 01 §7); a central SSH
polling model (requires centralized credentials — explicitly out of bounds);
running a resident collector/agent as root or executing `systemctl` from a
non-root agent (violates least privilege/no-exec); reusing a write-capable Mihomo
controller as an automatically enabled source or claiming the GET client
allowlist proves read-only authorization.

## ADR-UM-003 — Frontend: **Vue 3 + TypeScript + Vite + uPlot, embedded static assets**

Decision: a static SPA built with Vue 3 + TypeScript + Vite, charting with
uPlot (small, fast, no chart framework), no UI component framework, no CDN, no
external fonts, no SSR. Build output is embedded into the center binary
(`go:embed`); production has no Node runtime.

| Option | Strengths | Weaknesses | Verdict |
| --- | --- | --- | --- |
| **Vue 3 + TS + Vite + uPlot** (chosen) | small bundle, low ceremony, first-class TS, easy CSP `default-src 'self'` | new npm dependency set to pin/audit | **ADOPT** |
| React + TS | mature ecosystem | larger baseline and dependency surface for a small dashboard | reject (no offsetting need) |
| Extend `monitor-v2` vanilla JS/HTML | zero new frontend toolchain | 124 KB hand-written `app.js`; no typed contracts; dashboard scope is larger | reject for UM, keep for existing Monitor |
| Server-rendered HTML only | minimal client | global overview/timeline interactivity and chart UX would be re-implemented ad hoc | reject |

Budget: first-load JS ≤ 300 KiB gzip, no render-blocking external requests, CSP
`default-src 'self'; connect-src 'self'`, all API responses JSON.

## ADR-UM-004 — Database: **SQLite WAL first, PostgreSQL behind an explicit gate**

Decision: SQLite (WAL mode) with a single writer process for v1, `database/sql`
with `modernc.org/sqlite` (pure Go, no CGO) so the center stays a static binary.
All SQL lives behind a small storage interface so a future PostgreSQL backend
does not change handlers/contracts.

Configuration: `journal_mode=WAL`, `synchronous=FULL` (fsync on every commit —
the prior `NORMAL` consideration is rejected because an `accepted` ACK must
survive OS/power loss; see protocol doc 04 §6.2), `foreign_keys=ON`,
`busy_timeout` bounded, `wal_autocheckpoint` tuned, periodic checkpoint,
`VACUUM`/incremental-vacuum policy for retention. Files 0600 in a 0700 data
directory; DB on the local SSD only.

Why not PostgreSQL now: single 2C4G center, <10 events / ~200 nodes planning
ceiling, one writer, modest write rate; SQLite reduces deployment, backup and
maintenance cost. It stays sufficient while it meets the gate in
[doc 05](05-retention-capacity-backup.md). Why not a hosted/remote DB: adds a
network dependency and a second trust boundary for monitoring data.

PostgreSQL decision gate (one of): sustained ingest writes > 50 writes/s for 1 h
at the planning ceiling; DB > 24 GB with the 30-day contract intact; p95 write
transaction > 50 ms; need for concurrent writers (separate web/ingest processes);
or a true HA/read-replica requirement. A migration plan must be reviewed as its
own phase before any switch.

## ADR-UM-005 — Deployment: **systemd on the center VPS; public entries are a deployment choice**

Decision: Debian/Ubuntu LTS center host; center and cloudflared run as systemd
services; no containers, no Kubernetes, no reverse proxy fleet, no message
queue. The center binary has two independent HTTP listeners/handler stacks; the
public exposure of each is a **deployment choice** (owner decision, doc 07):

- **Option A (preferred evaluation): both entries via Cloudflare Tunnel.**
  `monitor.132431.xyz` uses Tunnel + Access; `ingest.132431.xyz` uses a second
  tunnel hostname **without** Access and forwards to a loopback ingest listener.
  No public inbound port; Cloudflare terminates TLS, so the monitoring payload is
  readable by the Cloudflare edge while the node signature still provides
  end-to-end authenticity/integrity. The ingest listener keeps no cookies/HTML/
  session semantics.
- **Option B: direct TLS for the machine entry.** `ingest.132431.xyz` is DNS-only
  and the center exposes `8443/tcp` with TLS 1.3; the payload stays end-to-end
  encrypted to the center, at the cost of a publicly reachable listener that must
  absorb unauthenticated traffic.

Both options use the identical frozen protocol (doc 04); the design does not
depend on which transport is selected. Rejected: Docker/Compose (no isolation need
that systemd sandbox does not cover; extra attack surface and ops); a public
nginx reverse proxy (unnecessary); exposing the web listener on a public port.
Cloudflare's Tunnel/Access is a gateway for the **web** entry, never the sole
authentication.

## ADR-UM-006 — Identity and cryptography

- **Node identity:** Ed25519 keypair generated on the node; private key never
  leaves the node; every request's signature is a **transport header** over a
  frozen signing string that binds protocol version, endpoint, method, path,
  identity fields, time, sequence, nonce, content encoding and the SHA-256 of the
  exact decoded body bytes. No signed body contains a signature field (the
  enrollment circular dependency is removed). The center stores only public keys;
  keys are per node, rotatable and revocable.
- **Transport:** HTTPS over TLS 1.3 with a server certificate for the ingest
  hostname, public-CA validation and hostname checking (no plaintext fallback; the
  chosen public path is Option A or B from ADR-UM-005). An optional SPKI pin is
  recorded at enrollment for strict deployments.
- **Admin credentials:** Argon2id password hashes (Go `x/crypto`), TOTP
  RFC 6238 (6 digits/30 s, one-window skew, single-use counter tracking),
  one-time recovery codes stored hashed, TOTP secrets encrypted at rest with a
  center master key (separate 0600 key file; never in the DB plaintext).
- **Cloudflare Access:** the center verifies the `Cf-Access-Jwt-Assertion`
  JWT cryptographically (signature against the team JWKS, `iss`, `aud`, `exp`,
  `nbf`, algorithm allowlist, bounded cache) as a gateway requirement, then
  enforces its own password + TOTP session gate. A Cloudflare header alone is
  never authentication, and `CF-Connecting-IP`/`X-Forwarded-For` are never used
  for authorization.
- **Sessions:** 256-bit server-side session IDs, `__Host-` Secure HttpOnly
  SameSite=Strict cookie, idle + absolute expiry, per-session CSRF token,
  bound to the user and revoked on password/TOTP/reset changes.

Rejected: public-key-only admin login (owner requires password + TOTP);
JWT-only trust of Cloudflare (explicitly forbidden); server-side client
certificates as the only node auth in v1 (agent key rotation/revocation is
simpler and works behind NAT without a CA lifecycle); storing TOTP secrets in
the database plaintext.

## ADR-UM-007 — Dependency and supply-chain policy

- Runtime dependencies: only what is needed for (a) SQLite driver, (b) Argon2id
  (Go `x/crypto`), (c) optional zstd for compressed backups (decided in UM-E).
  Each module is pinned by version + commit hash in `go.sum` and recorded in a
  dependency register.
- Frontend dependencies: `vue`, `vue-router`, `uplot`, Vite + TypeScript
  toolchain, all lockfile-pinned; no UI framework/CDN/analytics.
- No new service, container, database, message broker, agent framework or
  observability SaaS without a new ADR and owner review.
- Build reproducibility: pinned Go toolchain, `-trimpath`, vendor-free module
  cache with `go.sum`; build receipt (source commit, Go version, binary SHA-256)
  published with each UM build.
- CI additions happen in UM-B (Go test/build lane + frontend build + supply-chain
  pin checks). UM-A changes no workflow.

## ADR-UM-008 — Data format and API conventions

- Machine protocol: JSON (UTF-8), versioned major=1, additive-only minor
  changes; signing over exact body bytes; closed enums where forward
  compatibility is not needed, `unknown` token where it is.
- Web API: JSON, `/api/v1/...`, server-side session + CSRF for mutations,
  read-only GET for dashboards, server-side pagination/time-range bounds,
  closed error codes, no free-text error passthrough.
- Timestamps: epoch seconds (UTC) in wire/DB; rendered in browser time zone.
- No raw JSON blobs in hot storage beyond a bounded per-event detail map
  (≤2 KiB, closed scalar values) — see data model in doc 03.

## Consequences and open items

- UM-B must add (and review) a new toolchain and CI lanes; this is a deliberate
  cost accepted for a long-lived platform.
- Driver choice (`modernc.org/sqlite`) must be benchmarked in UM-B; if write
  latency is unacceptable, CGO `mattn/go-sqlite3` is the fallback, then the
  PostgreSQL gate.
- Frontend and Go versions are pinned in UM-B based on then-current stable
  releases; UM-A does not pin exact versions to avoid stale lock-in.
- The exact Cloudflare Access IdP and `aud` tag are owner-provided inputs (see
  doc 07 open questions).
