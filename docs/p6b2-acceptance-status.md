# P6B2 closeout status

Issue #67 section22 and its latest amendments remain authoritative. PR70 stays
Draft. This is a review checkpoint, not whole-implementation or independent PASS.
Implementation base/merge-base: be7fbc047827a563b52c8e82c1d310446cdd72c1.
Current field-deployed source: 9ac74e40f953863621ca179b44723b05ac2a22eb.
This closeout changes UI wording/documentation only; retain prior field evidence.

## Completed checkpoints

| Item | Evidence |
| --- | --- |
| Foundation, server/helper lifecycle, ingress, Bundle and installer slices | Earlier human independent reviews; keep their exact reviewed heads distinct from later source |
| Protocol/store/History/classifier separation | Protected base-to-head paths unchanged; classifier_bundle and _evidence_health_locked byte-identical |
| Current deployed-source integration CI | 15/15 jobs; synthetic merge959af8de4c1a38b38f7978f8acfeb98464a4449a has base+9ac74e4 parents |
| Native signed LAB export | Exact native-Valid entries/catalog and digest-pinned export independently read back; temporary LAB authority, no production signer |
| Real current test VPS update | Operator output: release0.7.0-20261003183326, healthy, identity hashes unchanged, generic source/distribution verified |
| Current IPLark collection/upload | Operator GUI successful sample2026-10-04 02:37:13 +08:00; exact run/seq1 receipt query: max_seq10, receipts10, latest acceptance age9.1s |
| Earlier real offline/reconnect behavior | Operator screenshots: ack20→22, unresolved span1→0, retries1→0. Retain this historical evidence rather than repeat the whole exercise for UI/provider changes |
| Process restart continuity evidence | Earlier screenshot: ack93 and new seq1. This supports a new process run; full Windows reboot is a distinct unproven assertion |
| Native automated lifecycle/resource bounds | Existing Linux/Windows fixtures verify bounded profiles, spool, native SCM, recovery and retirement. They are not real-host performance measurements |

## Open acceptance and release conditions

1. Resource evidence under the frozen protocol: one-profile steady CPU <=2% of
   total machine capacity over30minutes, private working set <=128MiB, matched
   baseline added Clash diagnostic latency p95 <=5ms. Record idle/active/offline
   backlog CPU/memory/network/queue and one/multiple-profile comparisons. The old
   single working-set snapshot is not a private-set or30-minute benchmark.
2. Real Windows reboot/autostart, TUN routing and multiple-profile/retirement
   field records have not been found in the preserved acceptance receipts.
   Do not turn absent records into PASS, nor automatically reset passed tests.
3. Production code-signing publisher and timestamp are unavailable; keep the
   frozen production admission gate closed. Existing temporary LAB signatures
   expire; production publication cannot rely on them.
4. A LAB preparation tool showed a generic failure despite valid signed export.
   Its detailed launcher exception is unknown. Preserve verified output, avoid
   repeating trust/export merely to collect the same result; improve diagnostics
   in a later batched lab-tool build if that workflow remains needed.
5. Final independent review of the final source and explicit merge authorization
   remain required. No merge, production deployment or P6C/P6D is authorized.

Open items above are distinct from already passed collection/upload recovery.
The operator rejected another offline exercise for this narrow repair; retain
historical coverage and note its source/build scope transparently. New source
fixes should invalidate only affected evidence, not restart all field steps.

## Current UI closeout

- Translate NONE as 无错误; successful egress shows existing latency_ms.
- Label direct observation 本机出口检测 / 本机网络出口 IP, with this sample's
  request-route note. Do not display configured VPS IP as a measured result.
- Preserve actual routing, collection/upload cadence, payloads, keys, profiles,
  queues, acceptance counters and server behavior.
- Review source/CI now; batch later signed delivery instead of making the
  operator reinstall solely to confirm these wording changes.
