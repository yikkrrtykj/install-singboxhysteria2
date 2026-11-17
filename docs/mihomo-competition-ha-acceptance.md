# Competition HA — measurement and acceptance gates

Status: **HA-01 review draft. No competition runtime/application/fleet PASS claimed.**
Parent [#48](https://github.com/yikkrrtykj/install-singboxhysteria2/issues/48); owner [HA-01 #89](https://github.com/yikkrrtykj/install-singboxhysteria2/issues/89).
Scope/security/architecture: [contract](mihomo-competition-ha-contract.md).
Dependencies: HA-01 #89 -> HA-02 #90 -> HA-03 #91 -> HA-04 #92 -> HA-05 #93 -> HA-06 #94.

## Verdict and reproducibility rules

Use PASS only for a completed, reproducible gate with reviewed evidence.
Use NOT MET for observed failure, BLOCKED for an unmet prerequisite, UNKNOWN for
missing/stale/ambiguous measurement, and NOT RUN before execution. A documentation
merge, green CI, a 204 response or a green node is not real-application acceptance.
Do not import PR-48B trial results as competition evidence or close #48.

The operator records a synthetic run ID, test resource authorization, exact
Windows/Verge/Mihomo version and core binary SHA-256, configuration version/hash,
A/B preference and actual selected chain, mode, cache/manual state, health
URL/status/interval/timeout and load. Keep real accounts/endpoints and private
profiles out of public receipts. Fault injection uses authorized disposable test
resources only; never production VPSes, daily Clash or production application
sessions. The protection boundary covers production sing-box, Monitor, Windows
Agent, credentials and existing configurations. Linux gateway, srt-cam and
Haivision SRT Tools are outside acceptance.

Before a run, verify a stable application baseline, expected protocol/exit and
usable alternative path. Predeclare timeout, observation duration, recovery
criterion, upload-quality thresholds, allowable false-positive/switch rate and
capacity reserve for review. An unreviewed threshold is an open gate, not a
license to choose it after seeing results.

## T0–T3 measurement (HA-04 / HA-05)

| Marker | Definition and required evidence |
| --- | --- |
| T0 | Fault actually takes effect on the selected test path; record injector acknowledgement plus independent effect check; clicking a button alone is insufficient |
| T1 | First time the client observes the relevant failure/degradation with timestamped detection/selection evidence; absent detection is UNKNOWN, not invented |
| T2 | First fresh connection completes a useful response via the intended surviving candidate, with path attribution; no reused keep-alive/old connection or cached response |
| T3 | Earliest verified return of usable application service, as defined per app below; confirmation may finish later without moving the recovery timestamp |

Record UTC wall timestamps for correlation and monotonic elapsed time on the
measurement host. For remote host/guest/platform observations, measure and
record clock offset and uncertainty; do not subtract unsynchronized clocks.
Record sampling cadence and uncertainty bounds. Keep enough local timestamped
evidence for another reviewer to reproduce the calculation without secrets or
full connection metadata.

Report T0->T1, T0->T2 and T0->T3 independently, with actual failure/timeout/manual
action. If native checks do not detect an upload-only fault, T1 is NOT DETECTED;
a separately measured app stall does not become a native health detection.
T2 does not need to wait for a dashboard refresh, and app reconnection can differ
from T2. Never force event order by fabricating timestamps.

For a <=10s PASS, the measured elapsed time including its uncertainty upper bound
must be <=10s. Record startup, DNS, handshake, retry/backoff and application
renegotiation as part of elapsed recovery, not excluded overhead. Test faults at
different phases of the probe interval, including just after a successful check.
Use real elapsed time: accelerated or simulated clocks are policy/unit evidence
only. A configured 3s/5s/10s interval is not a recovery guarantee.

After T3, observe at least 30s of continued usable service to confirm stability;
T3 stays at the first verified recovery point. If it fails again in that window,
record the interruption and classify the attempt unsuccessful/unstable rather
than selecting a favorable instant. Track failback interruptions separately.

## Symmetric new-connection matrix (HA-04)

Run this table twice: P=A/S=B for A-first and P=B/S=A for B-first. Start each
independent fault trial from a verified healthy baseline unless the row explicitly
requires accumulated faults. Record physical A/B and compatible node names, not
only the ambiguous label Reality. Test timeouts against drop/blackhole as well
as immediate refusal.

| Case | Fault / precondition | Expected new-connection selection or verdict |
| --- | --- | --- |
| M01 | All four healthy, no pins | P Reality |
| M02 | P Reality TCP-only fails, P HY2 usable | P HY2; not whole-VPS DOWN |
| M03 | P HY2 UDP-only fails, P Reality usable | P Reality; no unnecessary move to broken HY2 |
| M04 | P Reality unavailable; selected P HY2 then fails | S Reality; measure same-VPS to cross-VPS transition |
| M05 | P whole VPS/path unavailable; S healthy | S Reality; separate confirmed injected fault from inferred root cause |
| M06 | Both P protocols unavailable; S Reality fails, S HY2 usable | S HY2 |
| M07 | Current S HY2 fails, all other candidates unavailable | No usable route; no false recovery/PASS |
| M08 | Both VPSes unavailable simultaneously | Common outage/no usable route; no protected-recovery claim |
| M09 | P recovers Reality first, then HY2 | Record native failback, any business interruption and review disposition |
| M10 | P recovers HY2 first, then Reality | Same; test different restoration ordering |
| M11 | After P recovery, identify and fail whichever path is actually current | Verify the next usable selection; do not assume native failback left S current |
| M12 | Repeat down/up on P and S in different orders | Measure switch count, false positives and flapping; block unacceptable behavior |

M03 is the idle-HY2 negative control. M04/M06/M07 together cover HY2 actually
selected and subsequently failed, rather than only an idle broken candidate. Record that TCP or UDP fault injection
targets the intended protocol and preserves the other path. With HY2 hopping,
test one blocked port separately from the whole configured port range/broad UDP
impairment; port hopping must not conceal global UDP degradation.

## Attribution and negative-control matrix (HA-03 / HA-04)

Run relevant rows with both preferences; also cover Rule, Global and Direct.

| Case | Condition | Required evidence / non-claim |
| --- | --- | --- |
| N01 | Health URL fails while real business works | Endpoint/check failure is distinct from confirmed tunnel DOWN; record false switching |
| N02 | 204 succeeds while selected path upload collapses | Mark upload DEGRADED/automation gap with bounded/real transfer evidence; no native quality PASS |
| N03 | HY2 UDP/QUIC broadly degraded while Reality works | Per-protocol state; do not assume HY2 always healthy or label VPS dead |
| N04 | Same ISP/site exit/DNS/NAT/firewall affects both VPSes | Common failure domain; two VPSes do not solve it |
| N05 | Terminal network/TUN/DNS fails | Client fault distinct from remote host failure |
| N06 | Application stalls/auth fails while fresh proxy connection works | T2 may pass; T3 remains failed/unknown |
| N07 | Missing/stale/mismatched route or health data | UNKNOWN, not DOWN; no success without attribution |
| N08 | Outer manual pin or historical inner fixed selection | Verify intentional override; explicit controlled automatic-mode migration, no silent cache clearing |
| N09 | Core restart, normal exit, abnormal close or control process stops | Actual effective selection/cache/listener state after restart; no invented continuity |
| N10 | UDP test versus TCP-only check | Verify actual UDP exit and application media path |
| N11 | IPv4/IPv6, TUN/DNS/Fake-IP and LAN/production/management access | No unintended bypass/leak or internal network regression |
| N12 | Controller/proxy/DNS access from untrusted network | Must fail; verify actual listening/auth/firewall scope |

A core/controller outage is not a VPS fault. A manual fixed path does not prove
automatic failover. Direct mode and intentional LAN exceptions must be recorded
as bypasses, never claimed as VPS-protected traffic. Native-only quality gaps
remain explicit; #48's reviewed trial design and open gates are unchanged.

## Timing, failback and probe load study (HA-04 #92)

Compare competition-only intervals 3s/5s/10s with multiple recorded timeouts,
`lazy: false` and all four candidates. Keep A/B priorities fixed and retain the
current general 60s template. Do not use `max-failed-times` as a continuous-failure
threshold. Capture selection history, check results, sanitized connection state,
false-positive denominator and rate, real T0–T3 and recovery ordering.

At 30 PCs, four candidates imply a nominal 120 scheduled checks per interval:
40/s at 3s, 24/s at 5s, 12/s at 10s. These are planning arithmetic, not measured
load or a scheduling guarantee. Measure actual requests/bytes, handshakes,
connection bursts, CPU and media impact, including restart/recovery alignment.
Record probe endpoint effects separately; do not overwhelm a third-party URL.

Native fallback recovery behavior must be observed on the exact validated core.
Approval needs a reviewed switch-rate limit and observation window, no unacceptable
flapping and no recovery-induced second media interruption. Otherwise block,
open a separate sticky-policy design and review its ownership/manual/cache/crash/
rollback behavior. No automatic extra EXE/worker activation is authorized.

## Three real application gates (HA-05 #93)

### vMix Call

Use a real host and remote guest with bidirectional audio/video. Record ICE
candidate class, STUN/TURN usage, UDP/TCP media transport and actual routed
media path using sanitized descriptions. Direct P2P media is excluded from a
claim of VPS protection; route ambiguity blocks that claim.

T3 is usable audio and video restored at both ends with any required media
session re-establishment completed. Measure local and remote gaps separately;
the later successful recovery governs the bidirectional verdict. Test both
preferences, selected Reality failure, selected HY2 failure and whole-VPS loss.
Keep reconnect/renegotiation and manual action visible.

### TikTok LIVE Studio

Use an authorized test account and an authorized non-public test method.
If that method/account is unavailable, BLOCK this gate; do not silently
substitute public production streaming or a synthetic TCP send.

Start actual push and independently observe the platform receiving usable media.
T3 is platform-received playable audio/video after reconnect, not just the
client reporting connected or the egress IP changing. Record detection delay/
clock uncertainty at the platform. Check session/auth/region or other platform
restrictions caused by the public-IP change. Test both preferences and selected
protocol/whole-VPS faults.

### Google Drive

Use authorized non-sensitive large files, long enough to still be transferring
when the fault occurs. Record source size/SHA-256 before upload/download and
effective byte progress. Test uploads and downloads, both priorities, selected
protocol and whole-VPS faults. Record automatic retry, resume offset, restart
from zero and any manual intervention.

T3 is the return of sustained effective file-data progress at the predeclared
usable transfer threshold, not an idle socket, metadata request or HTTPS 204.
After upload, verify remote size and SHA-256 via authoritative available metadata
or a full re-download and local hash; do not assume every API exposes SHA-256.
Verify downloads against the original source size/SHA-256. A quick T3 with bad
integrity still fails. Keep duplicate/partial-file outcomes in the receipt.

### Repetition and reporting

At least 30 valid timestamped real fault experiments total: at least five for
each of the three apps in each direction (A->B and B->A). Distribute selected
Reality, selected HY2 and whole-VPS cases in every app/direction set. For Drive,
cover upload and download in both directions. Add trials if necessary to
complete coverage; do not discard a failed valid trial to reach a green count.

For each app and direction, report sample count, T0->T2 and T0->T3 median/p95/
maximum, failures, no-recovery timeouts, manual actions and unstable recoveries.
State percentile method and small-sample limits; never average away a >10s
mandatory case or remove timeouts from the reported total. Every applicable
mandatory trial must meet <=10s within uncertainty for that scope to PASS.
An app failing the target is NOT MET even when proxy T2 passes.

## Fleet, capacity and rollback gates (HA-06 #94)

| Stage | Required gate before expanding |
| --- | --- |
| 2 PCs | Independent machines, one A-first and one B-first; single-client matrix, routes and rollback verified |
| 4 PCs | Both groups concurrently usable and preference/identity/hash reconciliation correct |
| 8 PCs | Concurrent media/transfers and A/B fault switching measured |
| 16 PCs | Expansion load and per-terminal delivery/rollback records accepted |
| Final 16–30 | Full fleet drill plus each VPS taking 30-client equivalent load independently |

Each stage needs accepted prerequisites, test IDs and review disposition.
Check unique per-PC/per-VPS credentials locally, intended A/B groups against
actual effective profiles, delivery version/SHA-256, previous profile backup
and complete rollback receipt. Never publish credential-bearing manifests.

For A-alone and B-alone tests, define the expected three-app concurrent mix,
peak durations, site uplink constraints, headroom floor and acceptable
latency/loss before measurement. Include steady-state and reconnect bursts,
probe overhead and the failure transition. Record numeric measured throughput,
CPU, UDP/QUIC health, connection count, packet loss, reconnects and latency.
Both endpoints must carry all 30 equivalent clients with accepted measured
reserve; partial normal dual-active load or a link-speed label is insufficient.

Verify critical-business manual switch entry and full restoration of original
Clash profiles/settings/selections, TUN/DNS/LAN access and application behavior.
A rollback receipt includes before/after version/hash, operator action, elapsed
time, result and reviewer, without profile contents or endpoint metadata.
If an app misses recovery requirements, retain a reviewed independent application
backup; this does not automatically waive its failed <=10s gate.

## HA-01 PR boundary and merge gates

- [ ] Remote main rechecked against requested base; changed base explicitly reconciled.
- [ ] Draft PR targets main; diff is exactly the three allowed document paths.
- [ ] Existing #48 design/trial limits and historical TODO entries preserved.
- [ ] Every requirement maps to #89–#94; dependencies, methods and blockers complete.
- [ ] No real IPs, accounts, private YAML, secrets, customer data or full connection metadata.
- [ ] No executable code, deployment, runtime or CI changes.
- [ ] All five existing workflows pass: shell-tests, monitor-packaging, HY2 BBR defaults, p6b2-foundations, quality-receiver; inspect every job and existing required checks on the final revision.
- [ ] Review threads all resolved, P0/P1 findings zero; no absent review represented as approval.
- [ ] Human approval obtained before merge; no automatic merge.
- [ ] After approved merge, main CI revalidated on the merge SHA; failure stops HA-02.

Pending review/CI is not PASS. If main or the PR head moves, recheck affected
diff, review and checks rather than relying on a stale SHA. Green synthetic
CI only validates the repository; it does not certify 10s behavior.

## Final event Go / No-Go

Go requires every prerequisite accepted, all code PRs reviewed, final source
and main CI green, both-VPS 30-client takeover with measured reserve, complete
reviewable app evidence and clear per-app <=10s met/unmet scope, tested manual
takeover and original-profile rollback, company/account/security authorization,
and independent Go-Live approval before the event.

Missing evidence, unresolved unsafe exposure, P0/P1, capacity/integrity/rollback
failure, an unmet required app target or missing approval means No-Go for the
affected scope and blocks blanket fleet acceptance. Do not proceed to later
stage acceptance or downgrade requirements automatically. Any proposed narrower
event scope/exception requires separate explicit review and authorization;
the failed original gate remains visible. Linux stays outside this verdict.

## Sanitized receipt template (not a result)

Keep this as a field checklist, not a credential-bearing sample:

- Run ID; HA Issue; synthetic terminal role; config version/hash; exact core hash.
- Authorization reference; topology diversity summary; test mode; effective candidate;
  outer/inner automatic or manual state; baseline and probe parameters.
- Fault class, injection/effect verification, restoration order; clock/sampling uncertainty.
- T0/T1/T2/T3 and elapsed values; NOT DETECTED/UNKNOWN/timeouts where appropriate.
- Application/remote-platform evidence summary; Drive size/SHA-256 verdict.
- Follow-up stability, switch counts/false positives, actual load and reserve.
- PASS/NOT MET/BLOCKED/UNKNOWN/NOT RUN; reason, manual actions, rollback and reviewer.

Do not attach source/output YAML, raw controller dumps, accounts, secrets,
session IDs or complete connection tuples. Publish only reviewed sanitized
evidence; keep all failed valid experiments in the accounting.
