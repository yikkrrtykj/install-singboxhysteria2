# PR #70 closeout checklist

Issue #67 section 22 and its current company-only distribution amendment are
authoritative. PR70 stays Draft. No merge, production rollout or P6C/P6D is
authorized. Preserve the version and scope of each existing receipt.

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
      failures and foreign/missing identity still refuse. No operator run started.
- [x] MIT confirmed and added. SignPath application cancelled before submission;
      public certificate approval is not a company-internal release prerequisite.

## 1. Complete only missing field evidence

- [ ] Resolve the resource-record completeness gap. Preserve all old reports;
      first validate the observer repair in a short check, then assess whether
      another full capture is necessary. Do not automatically restart 30min tests.
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
- [ ] Readonly inventory of historical test instances before any authorized cleanup.

Use one consolidated runbook and a stable repaired version. Reuse upload,
download and recovery receipts; retest only evidence affected by a real change.
Missing second environments remain explicit gaps, never fabricated PASS.

## 2. Company-internal release, once

- [ ] Administrator-held durable signing identity and independently trusted initial
      provisioning, followed by same-identity signed setup/catalog updates.
- [ ] Retain native exact-publisher/signature/catalog/hash/timestamp gates,
      controlled expiry/revocation and recovery/rollover. No unsigned fallback,
      silent self-trust or globally disabled protection. Private signing keys
      never go to the VPS or client; VPS TLS trust stays profile-local and separate.
- [ ] Verify internal release and accompanying third-party notices on a controlled
      company device. Disposable LAB certificates are not this release authority.

## 3. Final review and release decision

- [ ] Final head/base/merge-base, full changed files, synthetic-merge parents,
      actual CI run/job/test counts, protected-path zero diff and residual issues.
- [ ] Final human independent review and explicit merge authorization.
- [ ] After an authorized merge: merge-commit CI, then separately authorized rollout.
- [ ] P6C/P6D only after P6B2 completion and explicit authorization.

tools/p6-resource-report.py remains fail closed for invalid/incomplete input.
No local observer repair changes its verdict or retroactively repairs old data.
Generic historical LAB launcher failure is retained as a tool diagnostic;
verified later export/publication stands and does not need repetition for it.
