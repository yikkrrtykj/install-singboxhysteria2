# HA-04 real-environment run pack (Shanghai Windows + two test VPSes)

Status: **PREPARATION ONLY — NOT RUN / BLOCKED.** This is the operator run
pack for the HA-04 (#92) real-environment verification. It is not evidence and
it does not authorize production deployment. No row in this pack may be marked
PASS until executed on the authorized Windows PC and both authorized disposable
test VPSes with reviewable, sanitized evidence.

Parents: [fast-probe variants](mihomo-competition-ha4-fastprobe.md),
[LAB evidence](mihomo-competition-ha4-lab-evidence.md),
[acceptance contract](mihomo-competition-ha-acceptance.md),
[Windows runtime runbook](mihomo-competition-ha-windows-verification.md).

## 1. Prerequisites (all must be true before a run starts)

- [ ] Owner authorization for this exact test window; test PC, both test VPSes
      and the load generator/fleet are authorized disposable resources.
- [ ] HA-03 real-environment rows that HA-04 depends on are accepted: exact
      Clash Verge Rev + on-disk Mihomo core identity/provenance, real HY2 TLS
      accept/reject/rotation/rollback on A and B, effective runtime config,
      TUN/DNS/UDP/path, cache/exit/restore.
- [ ] A verified HA-03 competition delivery exists; the HA-03 `--check
      --source-delivery` preflight is GREEN; its manifest hash is recorded.
- [ ] HA-04 fast-probe variants generated for this run from that delivery:
      9 policies (`3/5/10 s` × `1000/2000/5000 ms`) for at least one A-first
      and one B-first terminal; each `--check` GREEN; record every manifest name
      and SHA-256. The shipped 60 s/5000 ms HA-03 artifact stays untouched and is
      the reference measurement.
- [ ] Exact core binary path + SHA-256 + banner recorded on the PC; auto-update
      disabled; no “升级内核”; re-hash before/after each session.
- [ ] Private backup of original profiles/settings/selections + a tested
      rollback/restore path (HA-03 Windows runbook §2); out-of-band management
      channel verified and outside the proxied traffic.
- [ ] Own/approved 204 health origin and upload endpoint; never a third-party
      URL. 30-client probe-load arithmetic predeclared; monitoring for origin.
- [ ] No production VPS, production Clash profile, event PC or customer data in
      scope; no real credentials in tickets/PRs.

If any prerequisite is missing, the run is **BLOCKED**, not partially PASS.

## 2. Environment to record

Run ID (synthetic), operator, authorization reference, date/time UTC, site link
type and expected upload/download capacity, Windows build, Clash Verge Rev
version + installer SHA-256, actual core path/banner/SHA-256, HA-03/HA-04
manifest names/hashes, A/B VPS aliases and providers (sanitized), whether VPS
A/B are with independent providers, client PC count, and the tested policy
(`interval`/`timeout`/`lazy:false`).

## 3. Execution phases

### P0 — Real Windows baseline (once)

Follow the HA-03 Windows runbook: pinned combination, effective config verified
against the imported artifact, actual TCP+UDP binds on loopback only, controller
auth, second-device LAN negatives, TUN/DNS/Fake-IP/Rule-Global-Direct, remote
management, application path attribution. This proves the platform before any
HA-04 policy number is trusted.

### P1 — One-cell sanity on real hardware

Pick `i5/t2000` (or the owner-approved candidate) and run one reality-reference
and one whole-VPS fault in each direction (A-first / B-first). Confirm T0
injector ack + independent effect, T1 evidence, T2 fresh connection with
`/connections` chain attribution. Stop and fix if path attribution is missing
(report UNKNOWN, do not count the attempt).

### P2 — Matrix × faults, phase-covering repetitions

- Policies: `3/5/10 s` × `1000/2000/5000 ms` for both A-first and B-first groups
  (9 cells × 2 groups minimum); `lazy:false`; fixed four-node priority.
- Faults per cell: primary Reality TCP-only; primary HY2 UDP-only; whole-VPS
  outage; backup-only failure (should not disturb the business path).
- Fault phase: cover just-after-success, mid-interval, just-before-next-check;
  at least 5 randomized repetitions per meaningful matrix cell for the real
  run, one 60 s fault-free control window per cell. Do not use the 60 s
  reference as an assumed result — measure it.
- Report T0→T1, T0→T2 and T0→T3 separately; never average a >10 s mandatory
  case away. Include clock offset/uncertainty, sampling cadence and false
  positives/switch-rate denominator.

### P3 — Recovery and re-fault rows

- Kill only HY2, restart it: record fault→usable separately from
  restart→usable; expect ~30 s stale QUIC session but measure the real WAN
  window. A second fault during that window must not leave a dead node selected
  and must not claim false recovery.
- Whole-VPS outage → other VPS carries → restore → measure failback latency and
  switch count in a >=10 min observation window; then fail the actually-current
  path again (second interruption) and measure it separately.
- Both VPSes unavailable: explicit no-route/no-false-recovery row.
- UDP hopping: one blocked port vs whole configured port range/global UDP
  impairment; hopping must not hide global degradation.

### P4 — N02 (204 healthy, upload degraded)

Run the N02 upload workload over the selected path while the 204 health origin
stays green. Record native switches (expected 0), app impact, manual/app
contingency and the automatic quality verdict separately, then hand the run IDs
and disposition to HA-06. Native hard-failure PASS is not a quality PASS;
Quality Failover stays opt-in/off.

### P5 — Application T3 gates (HA-05 evidence)

vMix Call (real host+guest, ICE/STUN/TURN path attribution), TikTok LIVE Studio
(authorized test account/method; BLOCK if unavailable), Google Drive
uploads/downloads (size/SHA-256, resumed/restarted bytes). T3 is usable
application service, not a 204 or an egress-IP change. Real recovery values stay
distinct from T2 and from the >10 s call/transfer gap.

### P6 — 30-client probe load / false positives

Predeclare the 30-PC equivalent workload, allowed switch rate, observation
window and origin capacity; measure requests/bytes/handshakes/CPU/connection
bursts and media impact for the candidate policy. A configured interval is not a
load guarantee. This row needs the fleet/resources and is BLOCKED until then.

## 4. Evidence to keep (sanitized)

Per run: run ID, UTC + monotonic clock offset, exact core/config variant
hashes, A/B roles, T0 ack + independent effect, T1 evidence, T2 fresh success +
`/connections` chain, T3 app-usable time, dead-node selected window, switch
counts, false positives, failback/re-fault timing, N02 disposition, manual
actions, rollback receipt, reviewer and verdict. No real IPs, credentials,
private YAML, certificate bodies, account IDs or full connection tuples in
public tickets. Failed valid trials stay in the accounting.

## 5. Stop conditions

Any P0/P1 finding (identity mismatch, unsafe exposure, missing attribution
treated as success, unaccepted >10 s gate, capacity/integrity/rollback failure,
missing human approval) stops the affected scope. Do not proceed to later
phases or represent partial results as HA-04/HA-05 acceptance. HA-03 #91 and
HA-04 #92 remain OPEN / NOT ACCEPTED until the reviewed real rows exist.

## 6. Resource status

| Resource | Needed for | Status |
| --- | --- | --- |
| Shanghai Windows test PC (Verge + pinned core) | P0/P1/P2/P4 | BLOCKED — operator resource not yet provided to the agent |
| Two independent authorized test VPSes (A/B) | P1/P2/P3/P4 | BLOCKED — operator resource not yet provided |
| 16–30 PC fleet / load generator | P6 | BLOCKED |
| vMix host+guest, TikTok authorized account, Drive test files | P5 | BLOCKED |

The agent will not invent these resources or substitute LAB/loopback results for
them. Once the operator provides authorized access and the HA-03 dependency
rows are accepted, the run pack above is the execution order.
