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

## ADR-UM-002 — Linux node agent: **Go, static, unprivileged, read-only**

Decision: one statically linked Go binary (`um-agent`) for Linux (amd64 + arm64),
systemd service, dedicated non-login user, no listening socket, no root/sudo, no
`sbox-cm` socket access. It reads only the reviewed local read-only surfaces
(sing-box `service.api` on loopback, optional Mihomo controller loopback GET,
`/proc`, `systemctl is-active` for the two monitored units) and writes only its
own private state/spool directory.

Alternatives rejected: running the existing Python collector on every VPS
(duplicates runtime/venv, needs per-VPS Python management); root-side journal
reader (privilege and #33 ownership; forbidden in doc 01 §7); a central SSH
polling model (requires centralized credentials — explicitly out of bounds).

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

Configuration: `journal_mode=WAL`, `synchronous=NORMAL` (durability target RPO
24 h for backups; per-report durability is not required), `foreign_keys=ON`,
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

## ADR-UM-005 — Deployment: **systemd on the center VPS + Cloudflare Tunnel for web only**

Decision: Debian/Ubuntu LTS center host; center and cloudflared run as systemd
services; no containers, no Kubernetes, no reverse proxy fleet, no message
queue. Web admin listener is bound to loopback and published only through
cloudflared (`monitor.132431.xyz`, Cloudflare Tunnel + Access). Machine ingress
is a separate TLS listener published directly on `ingest.132431.xyz:8443`
(DNS-only, no Cloudflare proxy), so node telemetry is not decrypted by the
Cloudflare edge and the two entries never share routing or auth code.

Rejected: Docker/Compose (no isolation need that systemd sandbox does not cover;
extra attack surface and ops); nginx as a public reverse proxy (unnecessary —
cloudflared terminates the public path); exposing the web port directly.
Cloudflare's Tunnel/Access is chosen for the single public admin entry; it is a
gateway, never the sole authentication (see ADR-UM-006).

## ADR-UM-006 — Identity and cryptography

- **Node identity:** Ed25519 keypair generated on the node; private key never
  leaves the node; each report carries an Ed25519 signature over a frozen
  signing string that includes the SHA-256 of the exact body bytes. The center
  stores only public keys. Keys are per node, rotatable and revocable.
- **Transport:** TLS 1.3 for machine ingress with a public-CA-validated server
  certificate for the ingest hostname (hostname checked; no plaintext fallback).
  An optional SPKI pin is recorded at enrollment for strict deployments; it is
  not required by default so certificate renewal does not lock out agents.
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
