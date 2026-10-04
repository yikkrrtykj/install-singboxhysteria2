# P6B2 closeout status

Updated 2026-10-04. Issue #67 section22 and current amendments are authoritative.
PR70 remains Draft; whole completion/final review/MERGE/production/P6C/P6D are NO.
Base/merge-base: be7fbc047827a563b52c8e82c1d310446cdd72c1.
Current field runtime source: a07bc85e22e0855ea226d6ce32ef6af88f168f0d.
Later license/route/checklist commits are documentation changes, not new field builds.

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
exceedances. Network/matched latency remain unmeasured.

Local observer-only repair now records CIM-provider failures and permits at most
one retry after250ms. Short native tests verify recovered/persistent failure,
foreign/missing identity refusal and exact release binding. No cached state,
weakened identity checks, original-report rewrite or new operator run. This is
tool validation, not new field acceptance; it requires no client/VPS reinstall.

## Open conditions — three batches, no new feature stages

1. Adequate resource coverage/reviewer assessment; missing real network/workload,
   single/multiple-profile and matched added-Clash p95<=5ms evidence. One-profile
   targets remain30min average CPU<=2% total machine and private memory<=128MiB.
   Short-check the observer gap before deciding on any repeated full capture.
   Real OS reboot, user-controlled TUN, multi-server isolation and dedicated
   test-identity retirement records remain pending. Inventory old fixtures before
   cleanup; preserve the current active Device and do not alter Clash automatically.
2. Company-internal durable signing identity, independently trusted first setup,
   ordinary same-identity updates and expiry/revocation/recovery handling. SignPath
   was cancelled before submission; public approval is not a blocker for the
   human's company-only audience. Keep native publisher/catalog/hash/timestamp
   gates, no unsigned fallback. Current disposable LAB signing is not internal
   production authority; signing keys never enter VPS/client and TLS trust stays separate.
3. Final exact-head review packet, human independent review and explicit merge
   authorization. Merge-commit CI and production rollout follow separate approval.

Use [p6b2-todo.md](p6b2-todo.md) as the current checklist. Earlier receipts retain
their historical build scope. Completed upload/export/recovery is not reset by
local observer repairs, licensing or checklist updates. A historical generic LAB
launcher diagnostic does not undo independently verified subsequent exports.
