# Competition HA — Windows Clash Verge dual-active contract

Status: **HA-01 review draft; NOT ACCEPTED; all new competition features default OFF.**
Parent Epic: [#48](https://github.com/yikkrrtykj/install-singboxhysteria2/issues/48).
Requested and verified starting base: `c207846cd782c2d0b53722a9c9d304ffff53624d`.
This document freezes requirements, not a working configuration or deployment.
Evidence and verdict rules: [acceptance contract](mihomo-competition-ha-acceptance.md).

## Scope and protection

| Item | Contract |
| --- | --- |
| Terminals | 16–30 Windows PCs with Clash Verge Rev and a verified Mihomo core |
| Applications | vMix Call; TikTok LIVE Studio; Google Drive upload/download |
| Endpoints | Independent VPS A and VPS B, each running independent Reality + Hysteria2 |
| Allocation | Some terminals prefer A; the rest prefer B; each can use the other VPS |
| Objective | Fault to new proxy connection <=10s; fault to actual application recovery <=10s, measured separately |
| Linux Mihomo gateway | Deferred; excluded from this delivery and acceptance |
| Other repositories/tools | `srt-cam` and Haivision SRT Tools are Out of Scope |

Preserve existing production VPSes, sing-box, Monitor, Windows Agent, configurations
and credentials. No silent deployment, automatic upgrade or replacement of the
current Clash profile. Import and activation require a controlled operator action;
formal event use additionally requires independent Go-Live approval under HA-06.
No production fault injection. Use only authorized test PCs and test resources.

HA-01 changes exactly these repository paths:

- `docs/mihomo-competition-ha-contract.md`
- `docs/mihomo-competition-ha-acceptance.md`
- `docs/mihomo-failover-todo.md` (additive tracking only)

It must not change executable code, CI logic or production behavior, including
`install.sh`, `lib/client-management.sh`, `tools/mihomo-multi-vps-merge.py`,
`tools/quality_failover/`, `install-linux-gateway.sh`, `monitor-v2/`,
`sbox-cm/`, `windows/`, `.github/workflows/`, server runtime configuration,
keys or deployment scripts. Do not touch the `srt-cam` repository.

## Relationship to existing #48 work

This is a competition-specific workstream under #48, not a replacement for its
original design, checklists or trial limits. Keep #48 open. Existing references:

- [#42 native policy](mihomo-client-failover-policy.md): general template remains
  60s/5000ms, `lazy: false`, strict external HTTPS 204 reachability checking.
- [PR-48A canonical merge](mihomo-multi-vps-failover-p48a.md): operator-local merge,
  independent sources/credentials and primary-compatible names.
- [PR-48B quality trial](mihomo-protocol-quality-failover-p48b.md): explicit opt-in,
  per-protocol quality state, healthy-current retention, dedicated control ownership
  and outstanding real application/provider/capacity acceptance.
- [Existing acceptance ledger](mihomo-failover-todo.md); #33 remains the
  incident-evidence/fault-domain diagnosis workstream.

Competition HA-04 first evaluates native hard-failure behavior without an extra
quality-switch EXE. That narrower test does not complete #48 quality-aware or
symmetric protocol-health acceptance. A passing 204 cannot prove upload quality.
No trial worker, receiver, startup task or new control process is enabled by
this contract. Trial PASS items cannot be copied into competition PASS items.

## Priority, identity and independent lifecycle (HA-02)

| Terminal preference | Ordered physical candidates | Compatible emitted node names, in the same order |
| --- | --- | --- |
| A-first | A Reality -> A HY2 -> B Reality -> B HY2 | Reality; Hysteria2; Backup-Reality; Backup-Hysteria2 |
| B-first | B Reality -> B HY2 -> A Reality -> A HY2 | Reality; Hysteria2; Backup-Reality; Backup-Hysteria2 |

In B-first output B is the merge primary and A is the backup. The local delivery
manifest must identify those roles; a node called Reality alone does not identify
a physical VPS. Priority is fixed per terminal, not latency selection.

Dual-active describes fleet allocation across two independent endpoints. It is
not per-flow balancing, bandwidth aggregation or migration of established sessions.
A group switch directs new connections; applications must reconnect or recover
their own existing sessions. Neither VPS depends on a server-to-server heartbeat,
shared VIP, VRRP, DNS failover, replicated state or shared credential database.

Every PC has a distinct logical name, for example the synthetic `event-ob01`.
Create that same name independently on A and B. Its A UUID/HY2 password and B
UUID/HY2 password are independent, as are other PCs' credentials. Create, rotate
and delete locally on each VPS; no automatic fan-out or credential replication.
VPS installation order is irrelevant. Single-VPS events keep the existing workflow.

HA-02 inputs are canonical exports `A/event-ob01-mihomo.yaml` and
`B/event-ob01-mihomo.yaml`. The filename is a provenance guard, not signed client
identity. Reuse the strict canonical validation of
`tools/mihomo-multi-vps-merge.py`; do not introduce arbitrary YAML concatenation
or change `client.export`. Batch-wide validation must reject mixed A/B source
pairs, duplicate terminal names, reused credentials, missing backup or damaged
inputs. Distinct server fields alone do not prove distinct providers or paths.

Generate new, no-clobber delivery files from a terminal/group manifest. Keep
version, A/B roles, output SHA-256 and rollback receipt locally; validate
1/2/16/30-PC batches, actual pinned-core loading, accepted legacy formats and
single-VPS compatibility. Preserve each source's complete HY2 hopping range and
interval. Single-port impairment and broad UDP/QUIC failure are different cases;
hopping is not proof of protection against protocol-wide blocking.

## Windows effective path and rollback (HA-03)

No Clash Verge Rev/Mihomo combination is declared competition-supported yet.
HA-03 must record exact Windows build, Verge release, core version, binary
SHA-256 and provenance, then validate that exact combination. Historical
repository lab results are candidate evidence only, not fleet certification.
Core upgrades or a different binary reopen affected runtime gates; no auto-upgrade.

The competition profile must enforce minimum required controller/proxy/DNS access:
loopback management with authentication, no untrusted LAN exposure, and explicitly
reviewed scope for any necessary LAN listener. Verify actual binds, authorization
and reachability, not just YAML text. Private Windows directory ACLs matter;
POSIX mode checks alone cannot prove Windows source/output privacy.

Validate TUN, DNS, Fake-IP, IPv4/IPv6 and UDP, retaining required LAN, production
equipment and management-network access. A TCP webpage cannot prove UDP egress.
Inspect actual Rule, Global and Direct paths and intentional bypasses; a group
selection is not enough to attribute an application's traffic.

Handle both outer selector and inner fixed selections under
`profile.store-selected`. Historical pins must not masquerade as automatic
A/B mode. Intentional manual choices remain operator overrides. Explicitly
review/perform any transition to automatic mode; do not clear all caches or
silently release pins. Verify cold start, ordinary exit, abnormal close, core
restart, control-process stop and subsequent restart.

Record vMix ICE/STUN/TURN and actual media transport/path; a direct P2P call is
not protected by VPS failover. Verify TikTok and Drive actual exits separately.
Do not force-install a second switching program. Controlled import/activation
must preserve a complete original profile/settings/selection backup and permit
immediate restoration; HA-03 and HA-06 require actual rollback verification.

### Hysteria2 server identity (HA-03 #91)

The legacy canonical renderer emits `skip-cert-verify: true` and the merge
parser requires that literal. HA-01 and HA-02 preserve this input contract.
Successful use of such an export does not establish the server's TLS identity
or qualify a profile for competition use. HA-03 owns the separate competition
profile design on the exact validated Windows/Verge/Mihomo combination.

For each physical VPS, document the expected peer identity and evaluate
trusted certificate validation (trust chain and expected name) or explicit
certificate pinning with securely provisioned pins. Justify the chosen policy
and validate it independently on VPS A and VPS B, including when each endpoint
is used as a backup. Failed identity verification must reject the affected
candidate. Any subsequent selection must use another eligible candidate under
its own approved policy. Import, failover, renewal, restart, and rollback
within the competition profile must never silently weaken verification.

If verified identity cannot be delivered for an endpoint, an exception needs
explicit security approval before use. Record the affected endpoint and
workloads, residual impersonation risk, compensating controls, owner, expiry,
and revocation or removal plan. Record the endpoint as operating under an
exception and keep its identity verification verdict separate. Unapproved,
expired, or out-of-scope exceptions block the affected competition scope.

The [HY2 acceptance matrix](mihomo-competition-ha-acceptance.md#hysteria2-tls-identity-ha-03-91)
covers expected and unexpected certificates, identity mismatch, expiry, renewal,
recovery, and rollback. Record independent evidence for A and B. Restoring
the old profile is an exit from competition mode. HA-01 specifies only the
gate. Leave canonical rendering/parsing, production certificates, server
configuration, and deployed clients in place.

## Fault model and selection boundaries (HA-04)

Track each of the four candidate paths independently; do not reduce them to one
VPS boolean. A probe failure is an observation, not proof of root cause.

| Class | Required distinction and response |
| --- | --- |
| Single protocol DOWN | Confirm selected Reality TCP or HY2 UDP failure; use another verified usable candidate in priority order |
| Whole VPS DOWN | Both transports fail on that VPS; test other VPS independently; do not infer host death solely from client probes |
| Reachable, upload DEGRADED | 204 may pass while effective upload collapses; native liveness alone cannot detect/prove this; preserve #48 quality gap |
| Common path abnormality | Both VPS paths can fail through shared ISP/site exit/DNS/NAT/firewall; record common dependency and manual/application contingency |
| Client fault | TUN, DNS, local network, core or control-process failure; do not label a remote VPS dead |
| Application fault | Proxy new connections can work while media/auth/file transfer fails; application recovery remains failed/unproven |
| UNKNOWN | Missing, stale, conflicting or unattributed evidence; never relabel as DOWN or PASS |

HA-04 compares competition-only 3s/5s/10s health intervals, multiple explicitly
recorded timeouts and false-positive rates, using real elapsed time and
`lazy: false` on all four candidates. Do not modify the general 60s template.
Do not interpret `max-failed-times` as a consecutive-failure switching threshold.
A configured interval, a mock clock or a node turning green is not a 10s result.

Test health-URL failure with usable business traffic and 204 success with severely
degraded upload. Separate failed checks, endpoint failure, path DOWN and UNKNOWN.
Record selection/detection history and sanitized connection state with timestamps.
Measure all-four-node probe load at 30 clients, including synchronized bursts and
its impact on media, not just one idle PC.

Failback is a separate review gate: observe the exact pinned core's native
fallback behavior when protocols/VPSes recover in different orders. Define the
allowable switch rate and observation window before tests. Any unacceptable
flapping or recovery-triggered second business interruption blocks approval.
Open a separate sticky-policy design/review if needed; do not implicitly reuse
or enable PR-48B or another controller. Preserve intentional manual overrides.
Both-VPS and local-network outages require explicit No-Go/contingency reporting;
they are not promised protection by two VPSes.

### Upload degradation handoff (HA-04 to HA-06)

Record the [N02 disposition](mihomo-competition-ha-acceptance.md#n02-upload-degradation-disposition-ha-04-92)
for a path that continues to return 204 while effective upload falls below the
reviewed usable threshold. Carry the run IDs, observed impact, and separate
automatic quality failover verdict into the HA-06 decision. A native hard
failure PASS applies only to the tested hard failure cases. It gives no
automatic protection claim for the known upload collapse scenario.

If automatic quality recovery is unavailable, failed, or unproven, identify
the affected workloads and routes. HA-06 must record a tested manual or
application contingency for any scope proposed to operate with that residual
risk, or independently approve a narrower scope that excludes the unsupported
cases. With neither disposition, the affected scope is No-Go. Preserve
PR-48B's opt-in trial boundary and open gates. The competition baseline leaves
the quality-switch EXE disabled and requires no additional background controller.

## Time and business success (HA-04 / HA-05)

The [acceptance contract](mihomo-competition-ha-acceptance.md) defines T0 fault,
T1 detection, T2 fresh proxy connection and T3 verified application recovery.
Report T0->T1, T0->T2 and T0->T3 separately. <=10s is the objective for both
new-connection and actual application recovery; success in one is not success
in the other. Do not claim migration of an old long-lived connection.

- vMix: real host/guest, actual bidirectional audio/video, path attribution and
  media re-establishment; distinguish direct P2P from VPS-routed media.
- TikTok: authorized account and non-public authorized test method, real push,
  platform-received media, reconnect/auth/IP-change behavior.
- Drive: large upload/download, effective-byte progress, retry/resume/restart
  behavior, final size and SHA-256 integrity including uploaded content.

At least 30 valid, timestamped real fault experiments must cover three apps,
both A->B and B->A and the protocol/whole-VPS matrix. Report each app's recovery
distribution and failures; mark any app missing <=10s as NOT MET. Missing
evidence is BLOCKED/UNKNOWN. Real failures cannot silently lower the standard.

## Fleet, capacity, roles and final authority (HA-06)

Rollout is 2 test PCs (one per preference), then 4, 8, 16, and final 16–30,
with a gate at every stage. Check logical identity, actual loaded version/hash,
A/B allocation, delivery/rollback records and manual entry for critical traffic.

Both VPSes must separately carry the full 30-terminal equivalent expected mix
after peer failure, with measured spare capacity. Before tests, review workload,
duration, acceptable latency/loss and numeric reserve floor. Record peak
throughput, CPU, UDP/QUIC behavior, connections, loss, reconnects and latency.
Do not infer failover capacity from dual-active normal traffic.

The implementer supplies code/documents and sanitized reproducible evidence.
The authorized test operator owns private profiles/accounts and safe fault setup.
An independent reviewer checks source, runtime evidence, blockers and rollback.
The event owner/company authorizes accounts/resources and gives separate Go-Live
approval after review; implementation completion does not grant that approval.
For any application that misses recovery requirements, preserve a reviewed
independent application backup; no blanket PASS or automatic waiver.

The final Go/No-Go record includes HA-04 N02's evidence, the automatic quality
verdict, the scope covered by a tested contingency or excluded by separate
approval, and the remaining risk. Manual recovery and narrower approval leave
the original automatic quality verdict visible and do not waive the <=10s gates.

## Security and evidence boundary (all stages)

Never store or submit real YAML, UUIDs, passwords, keys, tokens, customer
information or full connection metadata to the repository, Issues, PRs, CI,
Monitor Web, logs or third parties. Keep credential-bearing source/output
profiles only in locally access-controlled operator storage; no secrets in argv,
error text, debug dumps or public artifacts. Public examples use logical A/B
aliases only; no real endpoint addresses or accounts.

Sanitized receipts may contain test ID, role alias, version/hash, elapsed times,
classified observations and verdict. Raw controller dumps, session identifiers,
account details and endpoint tuples are not receipts. Private evidence must
still avoid unnecessary full connection metadata or secret logging. Review
redaction before publication; sanitized summaries must retain failures and
measurement uncertainty.

## Issue ownership and blocking order

| Stage / Issue | Owns | Dependency / stopping condition | Initial status |
| --- | --- | --- | --- |
| HA-01 [#89](https://github.com/yikkrrtykj/install-singboxhysteria2/issues/89) | Architecture, fault/timing contract, mapping and gates | None; docs-only Draft, review/CI/human merge approval required | REVIEW DRAFT |
| HA-02 [#90](https://github.com/yikkrrtykj/install-singboxhysteria2/issues/90) | Canonical batch generation, A/B order, identities, permissions, hashes | HA-01 merged and main CI green; reject missing/mixed/reused/invalid inputs | BLOCKED |
| HA-03 [#91](https://github.com/yikkrrtykj/install-singboxhysteria2/issues/91) | Verified Verge/core, Windows safety, per-VPS HY2 TLS identity, cache/routes and rollback | HA-02 accepted; block unsafe binds, unattributed paths, unverified versions, failed TLS gates without an approved exception, or rollback failure | BLOCKED |
| HA-04 [#92](https://github.com/yikkrrtykj/install-singboxhysteria2/issues/92) | Native timing/false positives, fault matrix, N02 disposition, failback and probe load | HA-03 accepted; block missing/>10s hard-fail data, flapping or unreviewed sticky control | BLOCKED |
| HA-05 [#93](https://github.com/yikkrrtykj/install-singboxhysteria2/issues/93) | Three actual apps, >=30 real trials, recovery distributions, integrity | HA-04 accepted; block missing tests, integrity failure or app target misses | BLOCKED |
| HA-06 [#94](https://github.com/yikkrrtykj/install-singboxhysteria2/issues/94) | Staged fleet, both-VPS capacity, manual fallback, N02 disposition in Go/No-Go | HA-05 accepted; missing capacity, rollback, N02 disposition, authorization or Go-Live approval is No-Go for affected scope | BLOCKED |

Issue bodies and this contract must remain consistent; changes require explicit
review with affected gates reopened. None of the new stage references is PASS.
HA-01 stays Draft, does not auto-merge and does not start HA-02. After human-approved
merge, verify main CI again; any failure stops HA-02.
