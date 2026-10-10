# Issue #48 development / acceptance

Original topology work: [PR-48A](mihomo-multi-vps-failover-p48a.md).
Current quality work: [PR-48B](mihomo-protocol-quality-failover-p48b.md).

## PR-48B implementation

- [x] Independent UP / DEGRADED / DOWN / UNKNOWN protocol state.
- [x] Passive churn / upload-baseline suspicion; no low-demand verdict.
- [x] Node-forced, route-attributed, authenticated bounded TLS upload confirmation.
- [x] Per-path configurable fail/recover thresholds, hold and consecutive recovery.
- [x] Single/dual-VPS profile preparation, independent source credentials,
      original names/defaults/manual pins and HY2 hopping preserved.
- [x] Dedicated hidden fallback group; original group selection untouched.
- [x] Native hard-failure fallback without worker intervention.
- [x] Normal exit restore; foreign/cached selection suspends ownership.
- [x] Closed time-stamped state/reason records; no raw metadata or secrets.
- [x] Bounded receiver, byte/cadence/timeout caps and no automatic installation.
- [x] Local hermetic suite: 58 tests, 56 pass and 2 POSIX-only skips on Windows.
- [x] Pinned-core loopback lab: 24 checks pass; actual TLS receipt/body
      measurements and real Mihomo groups/listeners, mock SOCKS node bodies.
- [x] Previous head 45e4028: all 15 GitHub checks passed.
- [x] Unified isolated pilot GUI/CLI; receiver preparation without trust/firewall/service changes.
- [x] 18 pilot contracts pass: byte forwarding, hopping, startup history, cancel/failure cleanup.
- [x] Two-core genuine Reality/HY2 loopback suite: seven stages pass with wall-clock waits (~297s).
- [x] Pilot head 24af6898: all 15 GitHub checks passed.
- [x] Correct proxy/group blank-line boundary to match the actual full server renderer;
      non-hopping and hopping template round trips and malformed boundaries covered.
- [x] Renderer-boundary correction head 8378b27a: all 15 GitHub checks passed.

- [x] Daily opt-in GUI: private preparation, loaded-profile marker, observation first,
      explicit enable, manual precedence and owned stop restoration.
- [x] 34 hermetic daily contracts pass; real pinned-core API identity/selection
      smoke check passes without touching daily Clash.
- [x] Latest-state receipt is atomic/bounded; controller credentials remain in memory.
- [x] Pilot evidence follow-up head 8452b76: all 15 GitHub checks passed.
- [x] Daily-entry head18b8072a: all15 GitHub checks passed.
- [x] Routing-correction head0ce8fb70: all15 CI checks passed.
- [x] Windows early-rejection test framing: exact403/400/429 checks send
      headers with declared body length before reading the immediate rejection;
      previously sending an unread body could reset the socket on Windows.
      Receiver source and fail-closed production behavior are unchanged.
- [x] Retain healthy current at every priority; recovery does not cause failback.
      Two-minute recovery hold only makes a standby eligible for a later failure.
- [x] 63 quality contracts (61 pass, 2 POSIX skips), including sticky decision,
      recovered-primary/current-failure and fresh native-member retention guards.
- [x] Genuine Reality/HY2 daily-global adapter lab: controlled quality switch,
      recovered primary stays standby, current HY2 fails and switches to Reality,
      recovered HY2 stays standby, manual precedence and cleanup all pass.
      Local lab policy clock accelerated; no live Clash mutation.
- [x] New sticky-policy existing-VPS pilot: seven stages pass in 311.1s,
      including recovered-primary retention, current-HY2 failure, recovered-HY2
      retention and completed cleanup. Daily Clash was not controlled.
- [x] Sticky-policy code head2ab51082: all15 CI checks passed.
- [x] Reopened daily window: matching delivered source, sticky-policy receipt,
      global control enabled, exact current Reality pin and continuing fresh
      state records. This verifies normal integration, not an application fault.
- [x] Rule/global effective selection and direct-mode refusal; eight routing
      regressions plus real-core global/manual/restore coverage.
- [x] Read-only operator snapshot reproduced GLOBAL=quality with unused rule=HY2;
      no live mode/selection was changed during diagnosis.

## Operator acceptance

The existing-VPS operator pilot passed all seven controlled stages in 311.3 seconds
using the original export. Owned-process cleanup completed. The result stays local;
no raw result or credential files are committed. The daily Clash core was not controlled.

- [x] Single-VPS genuine Reality/HY2 controlled degradation, hard failure, recovery,
      connection continuity and manual-choice pilot.
- [x] Daily Clash normal integration: loaded-profile identification, global opt-in,
      positive uploads and enabled continuing records. This does not prove a fault.
- [ ] Daily Clash actual-fault/application acceptance of the new sticky policy.

- [ ] Actual Reality/HY2 and both opposite network cases.
- [ ] Site thresholds / payload / probe rate and receiver resource capacity.
- [ ] Independent backup provider/network and a real one-VPS outage.
- [ ] Quiet application uplink and live application session/reconnect behavior.
- [ ] Actual HY2 loss/churn/broad UDP impairment versus single-port hopping.
- [ ] Company-facing package/UX and optional #33 evidence integration contract.

The work is an opt-in trial; do not close #48, deploy unattended or claim real-world
HA acceptance from mock-path tests. Monitor 0.9.1 and its scanner follow-up
remain separate. No new Windows administrator/test step is requested here.
