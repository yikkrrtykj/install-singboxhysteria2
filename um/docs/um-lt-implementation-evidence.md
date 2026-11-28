# UM-LT implementation evidence (Draft PR #136)

Status: **implementation evidence for review; PR #136 remains unmerged**. This
document records only commands/results that were actually observed on this
implementation branch or on its exact-head CI runs. Anything not executed is
marked NOT RUN; no production, Cloudflare, DNS, certificate, VPS, SSH, R1 or paid
resource was touched.

## Contract baseline

- Rev-7 contract PR #135 merged by ordinary merge commit
  `8a3759ba1e9b830dc0cf7f93c25b69b9096fc3e3`; merge parents
  `3bf1fadf32f84aead0433b1534619cb9820d2e44` + `f24cc3d15ce87fa0ca746e199d3a3a5fef34b0ce`;
  merged tree `834d99610b93a1e2a1ba7918debe7420f8731043`.
- Exact-head contract CI: 30/30 SUCCESS, including the rerun quality
  `windows-exe` job. Post-merge main CI at the merge SHA: Unified Monitor Go
  `46178501631`, p6b2 `46178501719`, monitor-packaging `46178501639`, shell
  `46178501781`, quality `46178501663`, HY2 `46178501674` — all SUCCESS.
- Independent contract delta review verdict: **CLEAN (Draft Contract)**.
- Frozen rev-5/rev-6 files remain byte-identical to base.

## Implementation branch / scope

- Branch: `codex/um-linux-traffic-export`; Draft PR #136 (must not be merged by
  this goal).
- Base: `main` after the contract merge.
- No new write-capable credential holder: the monitor keeps its existing
  `service.api` secret; the agent reads only the restricted export file; the
  center does not receive `service.api` access. `singbox_api` remains **DISABLED**
  and P1-10 remains **FAIL**. PRODUCTION HOLD and R1 PRODUCTION HOLD remain.
- The OpenAPI/Web traffic reads are read-only, session + Cloudflare Access + RBAC
  bounded; no raw monitor export or raw report body is returned.
- No UM-D/E/F/G, no sbox-cm/HA-UI, no #48 reopen, no #127 close.

## Real Reality + Hysteria2 protocol lab

Exact implementation HEAD `21f85f7d2b43c982d80760772c1f972e55edd891`, workflow
`UM-LT real-protocol traffic lab` run `46184697467` (also `46184691575`):
**SUCCESS**.

- Pinned real sing-box `1.14.5` linux-amd64, official SHA-256
  `ca57e405be6b7dc79a0efa91823a0cc4d81138cbe4a9aacbfd749c65e6fca3b2`.
- Real Reality VLESS `vless-in`, real Hysteria2 `hy2-in`, synthetic credentials,
  self-signed local TLS, loopback HTTP payload services. No `mixed` inbound
  substitution. The Reality handshake target is a second **real sing-box TLS
  1.3 inbound** on loopback (documented in the lab): the pinned 1.14.5
  client/server pair does not interoperate with the earlier synthetic Python TLS
  target, while it does interoperate with the audited real sing-box target.
- 15/15 stages PASS, 316 assertions, 0 failures; stages:
  `agent-version-gate`, `default-disabled`, `main-path`, `center-query`,
  `monitor-restart`, `singbox-reset`, `export-tamper`, `replay-duplicate`,
  `agent-center-spool`, `config-source`, `allowlist-change`,
  `connection-shapes`, `concurrent-protocols`, `monitor-after-traffic`,
  `final-verification`.
- Independent measured payload (HTTP layer) vs observed **lower-bound** counters
  (e.g. Reality 6 MiB downlink / 1 MiB uplink; Hysteria2 8 MiB downlink / 2 MiB
  uplink with bounded protocol overhead), per-inbound attribution, epoch reset,
  monitor restart, stale/unavailable handling, duplicate/replay, spool drain,
  config source switch, allowlist change, active-connection observation, and
  authenticated center/store reads were exercised.
- Artifacts: redacted monitor export/evidence samples, redacted sing-box configs,
  center/agent logs, summary JSON, and independent payload ledger; summary
  `status=passed`, `assertions=316`.

The final branch HEAD after documentation/CI-only follow-ups must be re-run on
the exact final SHA before the completion claim; an exact-head lab success is
required.

## Go tests / capacity

Local commands on the implementation branch (independently reproducible):

```text
cd um
go vet ./...                                   # PASS
go test ./... -count=1                         # PASS (all packages)
UM_LT_CAPACITY=1 go test ./internal/store \
  -run TestUMTLTrafficCapacityMeasurement -count=1 -v   # PASS
```

Capacity measurement (actual SQLite `dbstat` page bytes, 150 nodes, 30 days,
30 s worst-case cadence; synthetic rows only, no production data):

- 2 inbounds: bounded raw ring 9,600 reports + 1,200 measured buckets in the
  48-minute sample; projected 864,000 bucket rows / **~168 MB** steady-state
  traffic tables.
- 8 inbounds: 28,800 raw observation rows + 3,600 measured buckets; projected
  3,456,000 bucket rows / **~650 MB** steady-state traffic tables.
- This is below the 5 GiB active planning basis with headroom for the 10 GiB
  overlap window. The model is bounded because raw normalized reports are kept
  only as a 64-report-per-node raw ring and older history is represented by
  15-minute monotone **lower-bound** bucket samples (B in the contract's
  `[300,900]` choice); history deduplicates bucket windows still covered by a raw
  row. The test fails if the raw ring is not bounded or projected bytes exceed
  5 GiB.
- This is the implementation's capacity conclusion, not a UM-E production
  capacity acceptance: the full production capacity/backup/degradation program
  remains UM-E.

## Monitor coexistence / export tests

- `monitor-v2` export tests: **57 tests OK (3 skipped)** in the last local run;
  packaging suite: **283 passed, 0 failed**.
- Monitor default remains **no export** (no flag => no directory/file, no write
  path opened). The optional `/run/singbox-monitor-export` path is the only new
  writable exception, is a non-root monitor-owned directory (group read only for
  the agent), and the unit has exactly two reviewed `ReadWritePaths` entries.
- The existing M0.5 privilege-boundary regression was updated to assert exactly
  two contractual writable paths and to preserve "no /root/sbox", "no
  /var/lib/sbox-cm", no capabilities, no world access.

## Existing-project regressions

Exact-head CI on `21f85f7d` (implementation code; before the shell-only M0.5
test fix) was green for: Unified Monitor Go, p6b2 foundations, monitor packaging,
HY2 defaults, UM-B3 isolated service labs, UM-C Web and Browser Lab, and the
UM-LT real lab. The shell lane found the expected old "exactly one writable path"
assertion and was updated in `tests/test-monitor-v2-m05.sh`; the final HEAD must
pass all lanes again. No B1-B4/UM-C production artifact was modified except that
one regression assertion, which is required by the new optional feature and still
enforces least privilege.

## Not run / limitations (honest)

- Full production installation/upgrade on a **live Debian 12** host and on a
  privileged systemd VPS was **NOT RUN** in this environment. The existing
  monitor-packaging and installer test suites ran in CI on Ubuntu, and the real
  lab starts the actual monitor/agent/center processes, but that is not a
  substitute for a Debian 12 systemd installation acceptance. This remains an
  Owner/UM-E installation gate and must not be reported as passed.
- Cloudflare Access authenticated browser E2E for `/web/api/traffic/*` is covered
  by Go web tests; the offline real lab checks the fail-closed route and store
  attribution, not a live Cloudflare tunnel.
- No production capacity run, no R1/Cloudflare/DNS/cert/VPS/SSH authorization, no
  UM-D/E/F/G work, no #127 close, no #48 reopen.
- The implementation PR is Draft and must remain unmerged pending final
  independent review and Owner merge authorization.
