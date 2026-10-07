# PR #70 closeout checklist

Issue #67 section 22 and its current company-only distribution amendment are
authoritative. The human has authorized merging after remaining conditions are
resolved and the final version is reviewed. PR70 stays Draft until then; no
production rollout or P6C/P6D authorization. Preserve each receipt scope.

## Current administrator preference and remaining fix

The human requested Manual start for the two controlled monitoring services.
Historical Auto/reboot evidence below remains valid; it is not the current
preference. Do not restore Auto or start services for a documentation review.
SCM checks now accept only Auto or Manual with the same exact image/account/ACL
checks, and reconfiguration preserves the existing start mode. New installations
still default to Auto. This is source work, not a changed installed client.
Local configuration-policy4/4 and portable installer13/13 pass; native Windows
reinstall/upgrade/rollback preservation is a mandatory current-head CI gate.

## Completed — retain these results

- [x] Foundation, provisioning/revocation, ingress, Bundle and installer slice reviews.
- [x] Combined Windows program/device package, adjacent configuration discovery,
      Chinese Client/Device/Location/Network Path UI and single-login/15min idle policy.
- [x] Historical real offline/reconnect recovery and originating-VPS IPLark receipts.
- [x] Native ctypes pointer-cache leak reproduced and repaired; native regression
      tests fail on the old source and pass with shared layouts. Ownership/DACL,
      reparse, hard-link and same-object enforcement remain intact.
- [x] Repaired Agent delivered through native signed LAB gates; actual in-place
      upgrade preserves the current Device, credentials and spool.
- [x] Test VPS source a07bc85 and repaired signed distribution synchronized;
      final health healthy, identity/Client configuration digests unchanged.
- [x] Exact repaired-service binding and native private-working-set collector.
- [x] Finished repaired native capture analyzed without changing its report/verdict.
      1803.80s, 119 valid snapshots, two service-query failures; observed private
      memory 12.54→8.73MiB, sampled maximum 12.54MiB, endpoint CPU estimate 0.041%.
      This is partial evidence, not formal whole-resource PASS or an exceeded target.
- [x] Local observer repair prepared and short native tests passed: one bounded
      retry only for CIM provider exceptions, recorded failures/retries, persistent
      failures and foreign/missing identity still refuse. Actual short operator capture
      completed: 182.48s, 62 valid points, zero failures/retries, stable exact PID/release,
      sampled private maximum9.02MiB, local acknowledgements929→932. This validates
      the observer; it does not manufacture a full-resource/network/latency PASS.
- [x] MIT confirmed and added. SignPath application cancelled before submission;
      public certificate approval is not a company-internal release prerequisite.

## Completed company-device and native lifecycle evidence

- [x] Fixed-company download inventory matches the native signed export. Normal
      P6RemoteProbe Auto/LocalSystem installation uses separately enrolled
      test/company-check; current test/my credentials and queue are preserved.
- [x] Actual company-device GUI pause/resume and continuing acknowledgements.
      Post-reboot fresh sample21:54:19/seq20, acknowledgements43, all displayed
      unresolved/retry/drop/corrupt/save/share-retry counters0.
- [x] Real Windows reboot/autostart independently checked with administrator
      service/process readback: exact service/image, unchanged Running PID5732,
      OS boot21:35:00.500 +08:00, process start21:35:13.594,13.094s after boot.
      The management window was opened manually later; its readonly ui-status
      path does not start the service. This check made no service-control calls.
- [x] Current-head native Windows CI includes reinstall preserving identity/spool,
      actual upgrade/rollback with pending bytes, remove-one/preserve-other,
      zero-profile uninstall and explicit purge. Native installer suite24/24.
      Foundation CI includes two-server profile isolation and real offline
      reopen/HTTPS replay. These are native fixture evidence, not the user's
      company-device field actions; retain that distinction during final review.
- [x] Controlled download includes the bundled Python license/notices:
      payload/runtime/LICENSE.txt,33861 bytes, matches the signed archive exactly.

## 1. Complete only missing field evidence

- [x] Short field validation closes the observer repair gap:62 valid/0 failures.
      Preserve the earlier30min119-point/two-failure report unchanged. Remaining
      full-resource adequacy requires reviewer assessment; do not automatically
      restart30min measurements.
- [x] Retained resource evidence reviewed: the recorded single-profile30min
      cumulative CPU average0.04118% is below2%; sampled private maximum12.54MiB
      is below128MiB. Stable process identity at119 valid points; two observer
      failures/max gap30.166s disclosed, no invented observations. Reuse these
      scoped measurements; do not rerun the whole window solely for query gaps.
      The original strict verifier refusal stays unchanged; workload/network/
      matched-latency coverage and whole resource acceptance remain incomplete.
      The observer's121-point/zero-failure rules are not new product requirements.
- [x] Retained active-phase resource/network evidence reviewed with zero-loss
      ETW attestation; average total-machine CPU0.038-0.046%, sampled private
      working-set maximum15.26MiB. Earlier incomplete phases remain retained.
- [x] Completed idle/pause resource check:60.88s, CPU0.03793% total-machine,
      sampled private working-set maximum13.72MiB, unchanged spool counters
      and zero Agent network events with zero-loss ETW attestation.
- [x] Completed same-process two-profile resource check:90.92s/30 valid points,
      CPU0.06373% total-machine, sampled private working-set maximum15.79MiB.
      Both enabled profiles confirmed two uploads each; pending/retry/storage
      error counters0. Agent TCP/UDP send17127/receive42188 bytes; zero ETW loss.
      Both services restored Stopped/Manual; original profile/controller/startup
      choices preserved and temporary profile removed. No repeat is needed.
- [x] Focused offline/backlog and recovery field check independently verified:
      90.86s/30 readings offline and90.88s/29 recovery, same exact process.
      Total-machine CPU0.04522%/0.04040%, sampled private maxima14.98/14.94MiB;
      unresolved span0->2->0, confirmations274->274->278, no drops/storage errors.
      Per-process send/receive4218/17416 and20023/45869 bytes; ETW loss0.
      Upload-only isolation smoke and dynamic-rule removal verified. Original
      enrollment/controller/settings and both Stopped/Manual services restored.
- [x] Independently recompute all six completed one-profile comparison phases,
      selected by numeric completion timestamp and valid final metadata, never
      by observed delay. All18 baseline/18 active observations per role included:
      Reality p95 77->73ms (-4), HY2 65->67ms (+2), observed <=5ms target met.
      Partial A4 and earlier failed comparisons remain retained. The old export
      omitted direct controller snapshots; consistency has only the worker's
      phase-completion guard. No population/causal noninferiority claim.
- [x] Fixed same-process multiple-profile matched delay check captured and
      independently reviewed: complete A1/B1/B2/A2, four60s windows with10s
      warmup, all48 diagnostics successful,12 baseline/12 active per role.
      Both profiles progressed in the same unchanged process. Controller
      snapshots match in every phase; temporary profile removed and both
      original Stopped/Manual services/enrollment/enabled choices restored.
- [ ] Resolve the observed multiple-profile Reality added-p95 failure before
      merge: baseline74ms -> active87ms (+13ms), exceeding the frozen <=5ms
      target. HY2 71->71ms (+0) meets it. Reality medians62->62.5ms do not
      replace p95. With12 observations/group nearest-rank p95 is the maximum;
      retain all values, no deletion of tails or repeated runs until favorable.
      Attribution remains unproven; investigate existing timestamps/scheduler
      behavior before another field request or any product change.
- [x] User-enabled TUN runtime scenario: authenticated controller readback true
      before/after120s; both exact service PIDs unchanged/Running/Enabled,
      acknowledgements158->160 and1267->1269; pending/retry/write failures0.
      Reality/HY2 each38/38 actual diagnostics successful. No service/config/TUN
      changes by this readback. This is runtime evidence, not packet-route tracing.
      Real OS reboot/autostart is complete; never change Clash/TUN automatically.
- [x] Actual short zero/one/two-client comparison collected, originals retained.
      Single client CPU0.0395% total-machine, sampled private maximum15.29MiB;
      two separate service processes CPU0.0874%, combined30.11MiB. Observed
      process TCP/UDP send/receive14459/39568 and27971/71541 bytes; ETW loss
      not attested. Two processes each one profile is not one-process multiprofile.
      This120s/group evidence does not replace the retained30min capture.
- [x] Review older failed added-delay comparisons and retain attribution limits: nearest-rank Reality p95 baseline
      340ms, single373ms, two389ms (+33/+49); HY2 156/163/144 (+7/-12).
      Those older observed <=5ms targets were not met; one Reality unavailable.
      Baseline Reality59-572ms/median69; single median66. Sequential short
      phases, Internet tails, diagnostic cache updates and cold starts confound
      attribution. Neither causal regression nor non-regression is established.
      The later all-completed-phase estimate above is separate evidence; it does
      not erase these tails or establish causation. The multiple-profile target
      is now measured but Reality did not meet it. Do not manufacture PASS or
      relax the frozen target.
- [x] Assess profile/server and retirement/revoke coverage against the contract:
      same-process two-profile actual field operation is complete. Native fixture
      tests exercise two-server isolation, actual SCM remove-one/preserve-other,
      zero-profile uninstall, selected retired-data purge and server revocation
      refusing the old secret while another Device remains accepted. These are
      real native/HTTPS fixture operations, not actions on the user's Device.
      No new destructive field repetition is required; preserve this distinction.
- [x] Readonly administrator inventory identified four old Running/Auto fixtures
      and the exact current service. Current profile/queue preserved.
- [x] Exact four old fixtures stopped/disabled by the administrator entry;
      native receipt reports completed and readonly registry confirms Start=4.
      Fixed code-signing identity is present in machine Root/TrustedPublisher;
      current service stays Auto and current Device/queue are preserved.
      No old data deletion, VPS TLS trust import, Clash/TUN or VPS change.

Use one consolidated runbook and a stable repaired version. Reuse upload,
download and recovery receipts; retest only evidence affected by a real change.
Missing second environments remain explicit gaps, never fabricated PASS.

## 2. Company-internal release, once

- [x] Fixed internal identity creation/reuse and independently pinned trust tools
      implemented; actual Windows administrator CI passes9/9, including two files
      signed by the same identity, trust reuse and exact removal. Fixture signatures
      do not attest a timestamped company release.
- [x] Actual fixed company publisher created on the build host; nonexportable
      private key retained locally, public certificate only in staging. Never send
      the private key to VPS/client. Initial machine trust is independently read back present.
- [x] Actual fixed-publisher setup executable, script and payload catalog signed;
      native publisher/signature/timestamp/catalog validation passes. Signing
      identity is reused, no private key exported. Source01586cc; Agent bytes match
      the already tested memory repair. This is build evidence, not installed rollout.
- [x] Actual protected production-scope native export completed; exact signed
      software manifest/archive digests confirmed. No credentials or private keys
      included, no service/trust/VPS changes from export.
- [x] Explicit exact-old-LAB to fixed-company publication admission: serialized
      transaction and eight Linux authority/retry/crash/capacity/concurrency cases.
      Head792d85a actual CI15/15; three Ubuntu root distribution suites37/37 each.
- [x] Controlled TEST VPS64.83.37.46 publication completed: fixed publisher
      92E0176599764946F7E5AB332A5CEF150355BE9B, signed releasee5277d47,
      archive6b2c3025. Operator SSH output confirms installed Monitor account
      validates the exact normal P6RemoteProbe download; five identity/config
      digests unchanged. No service reinstall, trust/firewall/ingress change.
      Initial transport quoting error fixed; the same uploaded archive reused.
- [x] Controlled GUI download and separately enrolled company Device installation
      verified above. Normal P6RemoteProbe did not adopt a LAB fixture root.
- [x] Assess controlled-device update coverage: repaired Agent was upgraded in
      place with existing Device/queue retained. Company-device install and
      native signed SCM reinstall/upgrade/rollback with paused profile, secret
      and pending bytes cover lifecycle behavior. No new Agent change in this
      documentation update; do not repeat an installation solely for a new head.
- [x] Retain native exact-publisher/signature/catalog/hash/timestamp gates,
      controlled expiry/revocation and recovery/rollover. No unsigned fallback,
      silent self-trust or globally disabled protection. Private signing keys
      never go to the VPS or client; VPS TLS trust stays profile-local and separate.
- [x] Fixed internal release and accompanying bundled runtime notices verified
      on the controlled company device. Native publisher/catalog/timestamp/hash
      gates use the fixed company authority, not a disposable LAB certificate.

## 3. Final review and release decision

- [x] d220190 and3c5bee4 review packets record head/base/merge-base, all92 changed files,
      synthetic-merge parents,15/15 actual CI jobs and13 protected zero-diff paths;
      both protected functions are unchanged. This is an evidence packet, not
      final independent review. Later heads require their own CI/status receipt.
- [x] Human conditional merge authorization after remaining acceptance/final review.
- [ ] Final exact-head code/evidence review requested of this agent, and
      resolution of the observed multiple-profile Reality delay failure. No new
      outside-reviewer approval gate is introduced.
- [ ] After an authorized merge: merge-commit CI, then separately authorized rollout.
- [ ] P6C/P6D only after P6B2 completion and explicit authorization.

tools/p6-resource-report.py remains fail closed for invalid/incomplete input.
No local observer repair changes its verdict or retroactively repairs old data.
Generic historical LAB launcher failure is retained as a tool diagnostic;
verified later export/publication stands and does not need repetition for it.

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

## Consolidated field check — 2026-10-06

The first consolidated acceptance helper stopped during A1, before active
comparison or idle/offline/recovery/multiple-profile phases. The retained
receipt records 36.27 seconds overall, one successful observation per protocol,
capture_complete=false and whole_p6b2_pass=false. It is incomplete evidence,
not a product-performance failure or acceptance PASS.

Restoration and cleanup readback completed: both exact original services are
Stopped/Manual, both original enrollment hashes and enabled flags match, queue
counters are unchanged, and authenticated controller settings match the initial
snapshot. Do not restore historical Auto/Running preferences.

The old helper suppressed the exception class/code, so its precise exception
cannot be recovered from that receipt. A real Windows temporary-file test
reproduced a failure path in its report persistence: CPython os.replace refuses
an open destination while the GUI reads it, including with delete sharing.
The helper now uses ReplaceFileW, a snapshot reader with read/write/delete
sharing, and two bounded retries only for sharing violations. Other permission
failures remain fatal. Future failures retain phase/class/Windows error code,
without raw exception messages, credentials or sample bodies.

Actual local verification: old locked replacement refused; new delete-sharing
snapshot replacement passed; 200 overlapping atomic writes and 12,867 valid
snapshot reads completed without errors. Ten protocol/restore/analysis tests
pass. Native PS5 parser, ETW layout/foreign-session guard, actual WinForms
recording-backend events and the actual report-reader fixture pass. These tests
do not control installed services, networking, trust or profiles.

A separate repaired helper was signed and timestamped with the existing fixed
company publisher; native payload catalog validation passed. Original package
and receipt remain preserved. No Agent bytes, installed program, identity,
startup choice, Clash/TUN, signing trust or VPS deployment changed.

The repaired helper is prepared, not a completed field run. Remaining field
gates stay open: matched added-Clash-diagnostic p95 <=5ms and the missing short
idle/offline/recovery/same-process multiple-profile resource coverage. Reuse
the previously reviewed 30-minute CPU/private-working-set evidence; do not
restart it. PR remains Draft pending those gates and final review. Source/CI
review packet for head7398693 records 15/15 successful jobs, thirteen protected
zero-diff paths and both unchanged protected functions; this packet alone is
not final review or merge approval.

## Review follow-up — 2026-10-07

A review found one stray `+` in the public-endpoint guard pipeline. The
character was interpreted as a grep input filename; the existing `|| true`
could hide its error and report an empty leak list. The one-character fix
restores the intended check without expanding the two approved exclusions.
An isolated Windows/Git Bash fixture reproduced the old false negative and
proved that the corrected actual pipeline catches an injected unauthorized
endpoint. Shell syntax validation also passed. Fresh CI is required for this
new head; the previous head's 15 successful jobs are not assigned to it.

Readonly field readback confirms the interrupted second attempt restored its
original service settings. Both monitoring services currently remain stopped
with manual startup. Another retained field record was refused by the local
reader because it counted duplicate privileged ACEs as unsafe. Reader source
now checks the bounded privileged principal/right set instead; unauthorized
principals, rights, owners and reparse paths remain refused. No signed client
package or installed service was changed by this helper repair. Review of the
retained record is still pending; no new sampling or field PASS is claimed.
Keep the previously scoped CPU/memory evidence, existing functional acceptance
and original latency/workload requirements. PR remains Draft until the missing
field evidence and final review actually close.