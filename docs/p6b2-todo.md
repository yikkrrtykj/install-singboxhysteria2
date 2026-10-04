# PR #70 closeout checklist

Issue #67 section 22 and its current company-only distribution amendment are
authoritative. The human has authorized merging after remaining conditions are
resolved and the final version is reviewed. PR70 stays Draft until then; no
production rollout or P6C/P6D authorization. Preserve each receipt scope.

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

## 1. Complete only missing field evidence

- [x] Short field validation closes the observer repair gap:62 valid/0 failures.
      Preserve the earlier30min119-point/two-failure report unchanged. Remaining
      full-resource adequacy requires reviewer assessment; do not automatically
      restart30min measurements.
- [ ] Close one-profile CPU <=2% total-machine average over30min and private
      working set <=128MiB acceptance with adequate evidence/reviewer assessment.
      The observer's 121-point/zero-failure rules are not new product requirements.
- [ ] Missing idle/active/offline-backlog network/queue and one/multiple-profile
      resource comparisons. Process IO bytes are not measured network bytes.
- [ ] Matched baseline/Agent-active Clash comparison: added p95 <=5ms;
      displayed active node-test delays are not that comparison.
- [ ] Real OS reboot/autostart and user-controlled TUN scenario. Existing process
      restart records do not prove a Windows reboot; never change Clash/TUN automatically.
- [ ] Multiple-profile/server isolation and retirement/revoke/remove/purge/uninstall
      using dedicated test identities; preserve the active Device and its queue.
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
- [ ] Protected native release export/publication and controlled-device install/update
      verification using the fixed company publisher.
- [x] Retain native exact-publisher/signature/catalog/hash/timestamp gates,
      controlled expiry/revocation and recovery/rollover. No unsigned fallback,
      silent self-trust or globally disabled protection. Private signing keys
      never go to the VPS or client; VPS TLS trust stays profile-local and separate.
- [ ] Verify internal release and accompanying third-party notices on a controlled
      company device. Disposable LAB certificates are not this release authority.

## 3. Final review and release decision

- [ ] Final head/base/merge-base, full changed files, synthetic-merge parents,
      actual CI run/job/test counts, protected-path zero diff and residual issues.
- [x] Human conditional merge authorization after remaining acceptance/final review.
- [ ] Final human independent review and satisfaction of remaining conditions.
- [ ] After an authorized merge: merge-commit CI, then separately authorized rollout.
- [ ] P6C/P6D only after P6B2 completion and explicit authorization.

tools/p6-resource-report.py remains fail closed for invalid/incomplete input.
No local observer repair changes its verdict or retroactively repairs old data.
Generic historical LAB launcher failure is retained as a tool diagnostic;
verified later export/publication stands and does not need repetition for it.
