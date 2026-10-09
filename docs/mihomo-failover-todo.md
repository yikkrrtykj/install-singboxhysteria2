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
- [ ] GitHub CI completion on the renderer-boundary correction commit.

## Operator acceptance deferred

The operator explicitly requested development first and will test later.

- [ ] Actual Reality/HY2 and both opposite network cases.
- [ ] Site thresholds / payload / probe rate and receiver resource capacity.
- [ ] Independent backup provider/network and a real one-VPS outage.
- [ ] Quiet application uplink and live application session/reconnect behavior.
- [ ] Actual HY2 loss/churn/broad UDP impairment versus single-port hopping.
- [ ] Company-facing package/UX and optional #33 evidence integration contract.

The work is an opt-in pilot; do not close #48, deploy it or claim real-world
HA acceptance from mock-path tests. Monitor 0.9.1 and its scanner follow-up
remain separate. No new Windows administrator/test step is requested here.
