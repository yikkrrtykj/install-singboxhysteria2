# tests/security — Independent Security Review Track

Adversarial regression tests produced by the Monitor v2 security/QA review
track. These suites **never modify production code** and never touch
`/root/sbox`: everything runs against extracted sandbox copies or in-process
loopback servers.

Review baseline: `feature/proxy-monitor-web` at `839d315` (E2 hardening
series included). Re-run against newer heads; KNOWN-ISSUE checks are
designed to fail loudly when their tracked weakness is fixed.

## Suites

| Script | Target | Environment |
| --- | --- | --- |
| `test-monitor-v2-security.sh` | Phase E2 web layer (`monitor-v2/web/*`, `webapp.py`) | Python 3 + real loopback sockets; runs on the dev box and on the Linux testbed |
| `test-phase-c-security.sh` | Phase C transaction core (`install.sh` phase-c block) | Linux testbed (needs `jq` + `flock`, like `tests/test-phase-c.sh`) |

```bash
bash tests/security/test-monitor-v2-security.sh
bash tests/security/test-phase-c-security.sh     # on the Linux testbed
```

Both follow the repo-wide gate discipline: the script exits 0 only when
exactly the expected number of assertions ran **and** passed. A section that
silently fails to run can never fake a green result; skips are printed
explicitly (`SKIP ...`) and never counted as passes.

## What the web suite covers (beyond test-monitor-v2-e2.sh)

- **S0 static checks** — no spoofable identity/override header is ever read;
  no CORS headers; the 500 fallback body is a fixed constant; the Secure
  cookie flag is conditional on TLS/remote.
- **S1 spoofed-header matrix** — `Forwarded`, `X-Forwarded-For`, `X-Real-IP`,
  `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-Host`, `X-Client-IP`,
  `X-Host`, `X-HTTP-Method-Override`: identity comes only from the socket
  peer; override headers are inert.
- **S2 protocol abuse** — chunked bodies (400), oversized Content-Length
  (uniform 413), 20 KB request lines/headers, JSON bombs, non-object JSON,
  binary bodies: the server answers completely and stays functional.
- **S3 URL normalization** — percent-encoded, double-slash, dot-segment,
  NUL and case variants of authenticated paths never authenticate. (`//` is
  collapsed by modern stdlib or 404'd by older urlsplit parsing; the
  whitelist gate is socket-peer-based, so path variants cannot change the
  gate decision either way.)
- **S4 CSRF contract** — session-bound `X-CSRF-Token` required for every
  mutation; missing/wrong tokens 403; correct token 200; foreign-Origin
  POSTs 403; uniform 405 + `Allow` for PUT/DELETE/OPTIONS.
- **S5 lockout semantics** — the correct password after lockout is still
  429; other whitelisted IPs are unaffected; the recovery limiter and the
  login limiter are independent stores.
- **S6 session hardening** — 256-bit tokens, uniqueness, HttpOnly +
  SameSite=Strict always (Secure only over TLS/remote, documented contract),
  session-fixation resistance, logout-with-CSRF server-side invalidation,
  garbage cookie headers.
- **S7 recovery red-team matrix** — 7 injected target-IP/CIDR fields are
  ignored; only the caller's own /32|/128 is added; recovery never mints a
  session or reads the whitelist; the recovery page exemption cannot be
  reached via method/path confusion.
- **S8 KNOWN-ISSUE perimeter switch** — the whitelist API accepts
  `0.0.0.0/0`, which turns the perimeter off (tracked weakness, see the
  security review report).
- **S9 SSE resilience** — abrupt mass disconnects and 60+ churned streams:
  publisher keeps publishing, no handler-thread leak, auth stays healthy.
- **S10 dynamic credential-leakage scan** — every byte returned to the client
  plus the server's stderr across a full login/snapshot/stream/rotate/
  recovery flow: no password, no recovery key, no session token, no
  tracebacks.
- **S11 concurrent whitelist mutation** — 8-thread add/remove race: no
  exceptions (POSIX; Windows `os.replace` WinError 5 quirk tolerated and
  documented), `access.json` stays valid JSON, policy reloads.

## What the Phase C suite covers (beyond test-phase-c.sh)

- **PC-S1 KNOWN-ISSUE traversal delete** — a naming-contract-violating name
  planted by hand in `sbconfig_server.json` is deleted by
  `delete_client`, and `rm -rf` escapes `SB_CLIENTS_DIR` (delete does not
  re-validate `validate_client_name`). The canary directory proves the
  escape; the sandbox keeps the escape contained.
- **PC-S2 KNOWN-ISSUE fail-open lock** — with `with_client_lock` unable to
  create/lock the lock file, the mutation still commits (warning only).
- **PC-S3 ADD A + DELETE A race** — serialized by the lock; the final state
  is all-or-nothing and the audit passes.
- **PC-S4 ADD A + ADD A race** — exactly one client survives (no lost
  update, no duplicate).
- **PC-S5 post-transaction file mode** — the live config is 0600 after the
  `mv` promotion of the mktemp candidate.

## KNOWN-ISSUE protocol

Checks labelled `KNOWN-ISSUE` assert a weakness that exists today so it
cannot be silently forgotten. **When a fix lands, these checks start
failing on purpose** — that is the signal to flip them into permanent
regression assertions (the check output prints the exact instruction).
They must never be deleted silently.
