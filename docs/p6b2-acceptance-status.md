# P6B2 closeout status

Updated 2026-10-07. Issue #67 section22 and current amendments are authoritative.
The human has authorized merge after remaining conditions and final review.
PR70 remains Draft/unmerged; whole completion/final review/production/P6C/P6D
remain pending. This conditional authorization supersedes historical MERGE=NO,
without waiving acceptance or authorizing production.
Base/merge-base: be7fbc047827a563b52c8e82c1d310446cdd72c1.
Current field runtime source: a07bc85e22e0855ea226d6ce32ef6af88f168f0d.
Later license/route/checklist and administrator signing-tool commits do not
change the field Agent payload; they are not new field runtime builds.

## Latest retained field review — 2026-10-07

Idle/pause and same-process two-profile short resource coverage is now complete.
Independent recomputation matches each saved analysis, with original records
retained. Idle60.88s: CPU0.03793% total-machine, sampled private working set
13.72MiB, unchanged counters and zero Agent network events. Two-profile90.92s:
30 stable-process readings, CPU0.06373%, sampled private maximum15.79MiB,
two confirmations per profile, no pending/retry/storage errors. Agent send/receive
17127/42188 bytes are attested by zero-loss per-process TCP/UDP ETW accounting;
they exclude delegated DNS, Clash and wire framing. Both original services are
restored Stopped/Manual, original enrollment/enabled/controller/startup choices
match, temporary profile removed, cleanup complete. No Agent, trust, Clash/TUN,
firewall or VPS change accompanies this documentation review.

Focused offline/backlog/recovery resource coverage is now complete. Independent
review recalculated CPU from cumulative process time and monotonic elapsed time,
validated all30/29 same-process readings and the >=90s windows, and checked
original/final identities, enrollment/enabled/controller/settings and restoration.
Offline CPU0.04522%, sampled private maximum14.98MiB, unresolved span0->2 with
confirmations unchanged; recovery CPU0.04040%, maximum14.94MiB, span2->0 and
confirmations +4. No drops/corruption/state-save errors. Per-process send/receive
4218/17416 and20023/45869 bytes, ETW zero loss. Exact-image upload isolation,
local-controller/other-image allowance, dynamic-filter cleanup and restoration
of both Stopped/Manual services were verified. The failed predecessor is retained:
BFE added the documented0x40 indexing flag, which the old checker rejected.
The repair accepts only that optimization flag while retaining all policy gates.

The retained one-profile comparison has six completed phases and partial A4.
Independent review uses numeric completion timestamps and valid final metadata,
including ALL six completed phases:18 baseline/18 active observations per role.
Reality p95 77->73ms (-4), HY2 65->67ms (+2); the measured one-profile <=5ms
point target is met. No completed phase is excluded based on its observed value.
Partial A4 remains separately retained; the older saved analysis includes it
and gives -3/+9ms with unbalanced counts. Older sequential failed comparisons
also remain retained. These are observed estimates, not causal/population proof.
The old projection omitted direct controller snapshots, so controller consistency
is limited to the historical worker phase-completion guard, explicitly disclosed.

The completed same-process two-profile resource run collected no delay samples.
Its matched latency comparison remains open: one predeclared A/B/B/A block,
four60s phases plus10s warmup each, with direct controller snapshots and both
profiles recorded. The signed bounded helper does not install a new Agent,
create network filters, change startup preferences or repeat accepted scopes.
The eight-phase format is not an extra product requirement. Do not repeat idle,
offline/recovery, signing, reboot, TUN or30min CPU/memory for this missing item.

Lifecycle assessment accepts existing actual native SCM/HTTPS fixtures for
cross-server isolation, revocation, remove-one/preserve-other, uninstall and
selected purge. Actual repaired-device in-place upgrade plus native signed
upgrade/rollback retention covers update behavior; no destructive repeat on the
active Device is needed. Native fixtures and field actions remain distinguished.

Predecessor source head ea4ed6749ffc8de6d74724dba46fc7974781dfde has15/15 actual
CI successes with exact logs and verified synthetic-merge parents. A later
documentation head requires its own status receipt. PR70 remains Draft pending
the multiple-profile delay result and final exact-head review requested of this
agent. No new external-reviewer approval requirement, merge or rollout is added.

## Current scoped follow-up

The administrator chose Manual service start. The previous native SCM ownership
check required Auto and rejected this legitimate preference. The source now
accepts only Auto/Manual while retaining exact command, LocalSystem, service
kind, dependencies/group and ACL validation; existing start mode is preserved
on reconfiguration, including upgrade and rollback. Default fresh installation
remains Auto. No installed service, signing trust or Clash/TUN was changed.
Local policy4/4 and portable installer13/13 pass. The added native fixture
exercises Manual stop/start, reinstall, upgrade/rollback and Disabled refusal;
its current-head CI result is required before claiming native completion.

The retained resource evidence review accepted the recorded single-profile
30minute cumulative CPU average and private-working-set sampling below their
targets, with query gaps and the original strict verifier refusal preserved.
This does not close missing workload/network/multiple-profile coverage or the
unproven added diagnostic p95<=5ms target; whole resource acceptance is NO.
Agent measurement code is unchanged by this installer SCM fix. Previous
field records retain their scope; a source fix is not an installed update.

## Completed checkpoints

| Item | Evidence and scope |
| --- | --- |
| Foundation, server/helper lifecycle, ingress, Bundle and installer | Earlier human slice reviews; final-head review remains distinct |
| Repaired runtime CI | a07bc85: 15/15 jobs; shell-tests37182322620, foundations37182322564, packaging37182322624 |
| License/company-route documentation CI | 30a1967: all three workflows successful; shell-tests37192254899, foundations37192254826, packaging37192255005; later commits require their own CI |
| Native memory-leak regression | Old layout creates2,000 retained pointer types after1,000 directory checks; shared layouts create zero, with unsafe-DACL refusal preserved |
| Repaired signed LAB delivery | Native export and in-place upgrade receipts; release b0e65304dd0726e4f338b54f4c9bfa9cedee7280397a30bbeae95526160096e4, publisher E98C97A9F64573C0E727E5B6B7657A27F695CDC2; current Device/spool preserved |
| Test VPS | Operator SSH output: a07bc85, Monitor0.7.0-20261004081332, final healthy, identity/Client digests unchanged, exact new distribution readable by Monitor |
| Upload/offline/IPLark | Preserved real-origin receipts and historical ack20→22/unresolved1→0/retry1→0; do not repeat for observer/documentation edits |
| Process restart | Earlier ack93/newseq1 supports a new process run; full OS reboot remains distinct |
| Signing tools CI | e2c6faa:15/15 jobs; foundations37194441609, shell-tests37194441612, packaging37194441649; native Windows internal-publisher suite9/9 including real machine trust/sign reuse/removal. Synthetic-merge checkout, not raw head checkout |
| Short observer field validation | 182.48s,62 valid points,0 failures/retries, stable exact service/PID/release, sampled private maximum9.02MiB, local ack929→932; observer gap only |
| Fixed company identity | Fixed company trust/signatures/timestamps/protected export and test-server publication complete; controlled company-device download/install now verified, native update/rollback24/24 remains distinct from field coverage |
| Company Device | test/company-check uses normal P6RemoteProbe; downloaded program bytes match signed export; actual pause/resume and continuing samples/upload confirmations, active test/my preserved |
| Real OS reboot/autostart | Administrator readonly exact SCM/process readback: OS boot21:35:00.500 +08:00, Auto/LocalSystem service PID5732 starts21:35:13.594,13.094s after boot; subsequent GUI confirms new samples. Window manually opened, readonly opening does not start service |
| Current review packet | d220190:15/15 jobs, synthetic merge39055a3 with base+head parents,92 files,13 protected paths zero diff/two functions unchanged. Evidence packet only; final independent review pending |
| Native lifecycle coverage | Actual Windows fixture reinstall/upgrade/rollback/pending bytes/remove-one/keep-other/zero-profile uninstall/purge24/24; foundation isolation and offline reopen/HTTPS replay passed; not falsely labelled company-device field actions |
| Runtime notices | Controlled download payload/runtime/LICENSE.txt33861 bytes matches the signed archive |

## Finished repaired native resource capture

Original report SHA256:
380ea78cfa724c7d7efe82601aad7073d1967764951add256129c801ef86394e.
Exact repaired LAB service binding, one configured/enabled profile, one stable
PID/creation identity and Running at all119 valid points. Window1803.80s;
two failures at service_query/service_recheck, maximum gap30.17s.

Observed private working set: first12.54MiB, last8.73MiB, sampled maximum12.54MiB.
CPU endpoint estimate0.041% of total machine capacity. Recorded snapshots do not
show the former growing private memory, but cannot attest unseen continuous peaks.
The closed verifier keeps invalid_or_incomplete_resource_report and whole-resource
PASS=false. False acceptance flags from invalid input are not measured target
exceedances. Short network/latency results below are now recorded; full adequacy remains open.

Local observer-only repair now records CIM-provider failures and permits at most
one retry after250ms. Short native tests verify recovered/persistent failure,
foreign/missing identity refusal and exact release binding. No cached state,
weakened identity checks or original-report rewrite. The actual short operator
capture now validates this observer repair with62 valid points/zero failures;
it remains distinct from full resource acceptance and requires no client/VPS reinstall.

## Administrator closeout readback

The repaired administrator entry completed and saved a native state receipt:
four exact old fixtures Stopped/Disabled, current exact service Running/Auto and
fixed internal code-signing trust installed. Independent readonly registry now
confirms old Start=4/current Start=2 and both exact Root/TrustedPublisher entries.
Unprivileged direct SCM queries remain denied; stopped state comes from the
administrator's native readback, not a fabricated unprivileged observation.
Old data/current Device/queue are preserved; no VPS TLS trust/Clash/TUN/VPS change.

Actual fixed-publisher company setup executable, script and payload catalog are
now signed and timestamped. Native exact-publisher/signature/timestamp/catalog
validation passed. Source01586cc has15/15 CI jobs success:37196950313,
37196950312,37196950334; synthetic merge81061673d53b63a5f5170578e93671ba5cc6a81e
has parents base + that head. Field Agent bytes match the already tested repair.
Protected release export completed; operator SSH output now confirms software-only
publication on TEST VPS64.83.37.46: publisher92E0176599764946F7E5AB332A5CEF150355BE9B,
releasee5277d4778630089488a808de83c5da58e384497be2c439117baa062dfb1e008,
archive6b2c30252cbced851a276cbf3a22430f67815aa24a9c166d3b67de49d533520f.
Installed Monitor account validates the normal P6RemoteProbe download; five
identity/config digests unchanged. No service/client reinstall, trust/firewall or
ingress change. Head792d85a CI15/15; root distribution suites37/37 on three Ubuntu
versions. Controlled company Device installation, pause/resume and real Windows
reboot/autostart are now verified. Ordinary update field coverage remains an
assessment item; actual native fixture upgrade/rollback already passes.
Production VPS is not deployed.

## Open conditions — three batches, no new feature stages

1. Resource evidence review is complete for retained30min one-profile CPU and
   sampled private memory, active/idle/offline/recovery and same-process two-profile
   resource/network scopes, with query gaps and the original verifier preserved.
   All six completed one-profile comparison phases meet the observed5ms point
   target, with partial/older failed comparisons and attribution limits disclosed.
   Only the missing matched same-process multiple-profile delay result remains
   open in field coverage. Real reboot/autostart and user-enabled TUN operation
   are complete. Native server isolation, revocation and retirement/lifecycle
   evidence has been assessed; do not repeat destructive active-Device actions.
2. Company identity/trust/timestamped release/export/test-server publication and
   actual normal company-device installation are complete. The signer is fixed,
   not a disposable LAB certificate. Native expiry/revocation/update/recovery tests
   remain valid; assess only additional controlled-device field coverage. SignPath
   was cancelled before submission; public approval is not a company-only blocker.
   Keep native publisher/catalog/hash/timestamp gates with no unsigned fallback;
   signing keys never enter VPS/client and TLS trust stays separate.
3. Final exact-head code/evidence review requested of the agent and satisfaction of
   the human's conditional merge authorization. Merge-commit CI follows merge;
   production rollout remains separately authorized.

Use [p6b2-todo.md](p6b2-todo.md) as the current checklist. Earlier receipts retain
their historical build scope. Completed upload/export/recovery is not reset by
local observer repairs, licensing or checklist updates. A historical generic LAB
launcher diagnostic does not undo independently verified subsequent exports.

## Actual short performance and user-enabled TUN readback

Three sequential120s phases used the same host/nodes, TUN off: no clients,
one normal company client, then two separate service processes with one profile
each. Both initial Running states were restored and acknowledgements continued;
original Device secrets/spools retained. Not one-process multiprofile evidence.

| Scenario | Average CPU, total machine | Sampled private maximum | Observed send/receive bytes | Reality p95 | HY2 p95 |
| --- | --- | --- | --- | --- | --- |
| Baseline | 0% | 0MiB | 0/0 | 340ms | 156ms |
| One company client | 0.0395% | 15.29MiB | 14459/39568 | 373ms | 163ms |
| Two separate clients | 0.0874% | 30.11MiB | 27971/71541 | 389ms | 144ms |

Nearest-rank percentiles use38-40 successful positive delays per role; failure
outcomes retained separately, including one single-client Reality unavailable.
Added p95 point estimates +33/+49ms Reality and +7/-12ms HY2 do not satisfy the
frozen <=5ms target. Baseline Reality already ranges59-572ms, median69ms;
single-client median66ms. Short sequential phases, Internet jitter, observer
active diagnostics/cache updates and service cold starts confound attribution.
Do not conclude Agent-caused regression, non-regression or whole-resource PASS.
Observed network bytes exclude delegated DNS/proxy-core/wire framing; ETW
zero-loss is not attested. This does not replace the retained30min record.
Raw result SHA256: ffac49f7b20feb9e64c8563387cc61fa3d28885c374361ab27a6dfd068a0d8c3.

The user then enabled TUN, reporting working network. Authenticated controller
readback was true before/after120s; both existing service PIDs unchanged and
Running/Enabled. Local upload acknowledgements158->160 and1267->1269, pending/
retry/state-save failures0; Reality/HY2 each38/38 successful actual diagnostics.
No service, settings, trust, firewall or TUN mutations by this readback. Runtime
TUN evidence does not assert packet-level route attribution or whole P6B2 PASS.
No repeat install/reboot/TUN smoke is needed for this documentation change.

## Simple startup preference control

The client manager now contains a single “开机自动运行” checkbox with actual
Auto/Manual readback. Changing it affects the monitoring service's next boot,
leaves its current Running/Stopped state intact, and never changes Clash/TUN.
Refresh is readonly; unavailable or pending-recovery state disables the control
instead of displaying a false successful setting. Upgrade/rollback preserve
the preference. Startup actions accept no profile, Bundle or credential inputs.

Local configuration/startup policy8/8, GUI observation29/29 and the actual
WinForms recording-backend click/refresh/busy/pending checks pass. Isolated
Windows CI additionally verifies native same-PID service control, unchanged
profile/queue bytes, stopped-state preservation and pending recovery refusal;
native suite now has26 tests. Source change is not an installed-device update.
This feature does not close the remaining matched latency/workload evidence or
final review conditions, and does not repeat accepted30min CPU/memory checks.
