# PR #70 remaining work

Authoritative contract: Issue #67 section22 and current amendments. Keep PR70
Draft; no merge, production deployment or P6C/P6D until separately authorized.
Use this checklist with p6b2-acceptance-status.md; checked tooling is not checked
physical acceptance. Preserve exact source/build scope of existing receipts.

## Completed evidence to retain

- [x] Foundation, provisioning/revocation, ingress, Bundle and installer slice reviews.
- [x] Combined Windows client package and adjacent Device configuration discovery.
- [x] Chinese Client/Device/Location/Network Path interfaces; single login/15min idle policy.
- [x] Historical offline/reconnect recovery (ack20→22, unresolved1→0, retry1→0).
- [x] Current IPLark sample matched to actual originating-VPS seq1 receipt.
- [x] UI NONE/direct-egress wording source fix; defer signed delivery to a batch.
- [x] Existing readonly native 30min CPU/private-working-set sampler prepared.
- [x] Resource report verifier: recompute units and refuse partial/gapped/restarted reports.

## Blocking repair: Windows native storage memory growth

- [x] Reproduce retained native pointer types on the actual Windows interpreter.
      1,000 directory DACL checks retained2,000 pointer-cache entries and
      12,074,488 traced bytes after collection. An isolated fixture only;
      no installed service/profile, controller or network changes.
- [x] Reuse module-level ACL/ACE/file-information layouts; preserve all native
      owner/DACL/reparse/hard-link checks and handle/descriptor lifetime rules.
- [x] Native regressions cover repeated directory/file/open-fd checks, recurring
      one-profile idle runtime checks, and subsequent unsafe-DACL refusal.
      Both regressions fail on the old source and pass after the repair.
      Repeated1,000 directory checks now add zero pointer types and retain
      1,224 traced bytes. This is not a whole-service working-set benchmark.
- [ ] Publish/test the changed Agent through the signed LAB package gates;
      never patch installed signed bytes or downgrade permission enforcement.
- [ ] Re-measure the repaired exact service's CPU/private working set. Keep the
      running original capture as a pre-repair result; do not mark it PASS.
      Operator reports rising~100→230MiB; independent protected Python process
      snapshots showed~239–242MiB private sets, but exact service PID binding
      must come from the administrator-authorized capture before attribution.

## Next: resource evidence

- [ ] Bind the existing sampler to the actually installed, exact LAB service/profile/release.
      The original prepared sampler names an older fixture; do not reuse that binding blindly.
      No current P6 SCM entry was available in this agent's readonly service inventory;
      this is an evidence/access gap, not proof that the operator's service is absent.
- [ ] Record one-profile steady CPU for30min (<=2% total-machine capacity) and
      sampled private working set (<=128MiB); total working set is a different metric.
- [ ] Record idle/active/offline-backlog CPU, private memory, network/queue and
      one/multiple-profile comparisons. Retain passed recovery; collect only missing metrics.
- [ ] Record matched baseline/Agent-active Clash latency comparison, added p95<=5ms.
      Process IO bytes are not network bytes; active diagnostic delay is not added Clash delay.

## Then: missing lifecycle field records

- [ ] Actual full Windows reboot/autostart, exact installed release and run continuity.
      Existing process-run seq restart is retained but does not prove an OS reboot.
- [ ] TUN off/on routing and collection/upload evidence; no automatic network-mode changes.
- [ ] Multi-profile isolation and project retirement/revocation/purge recovery.
      Perform destructive lifecycle checks on dedicated test identities, preserving the active Device.
- [ ] Close or explicitly assess the generic LAB preparation error; valid native export
      and later publication remain separate verified facts, cause currently unknown.

## Final review and release

- [ ] Batch only necessary signed delivery; exact native package/catalog/hash gates unchanged.
- [ ] Production publisher certificate/timestamp. Human reports no production certificate;
      implement/test gates now, production publication remains closed until authority exists.
- [ ] Final review packet: head/base/merge-base, full changed files, actual synthetic-merge
      parents, run/job/test counts, protected-path zero diff and residual issues.
- [ ] Final human independent review and explicit merge authorization.
- [ ] Merge-commit CI after an authorized merge, then separately authorized production rollout.
- [ ] Only after P6B2 completion and explicit authorization: P6C presentation, then P6D.

## Report analysis boundary

tools/p6-resource-report.py consumes the existing resource_window report using
explicit expected service/probe/profile and an expected report SHA256. It emits
only calculated aggregate metrics and closed status, never input sample bodies
or credentials. Exit0 means the recorded CPU/sampled-memory subchecks pass;
exit1 means a measured subcheck exceeds its target; exit2 means invalid/incomplete
input. Every outcome keeps whole_resource_acceptance_pass=false: recorded-input
validation neither attests real execution nor substitutes for network/latency,
workload comparisons, lifecycle field evidence or independent review.

## 2026-10-04 免费代码签名准备

- [x] 用户确认 MIT 草案，并加入根目录 LICENSE；第三方许可不变。
- [x] 免费签名路线、政策和申请前数据流说明已记录：`docs/p6b2-free-signing.md`。
- [ ] 核对 Windows 首次公开发布资格及随包第三方通知；当前 GitHub Releases 无已发布客户端。
- [ ] 仓库所有者完成真实联系人、MFA 和申请条款确认，取得 SignPath 审核结果。
- [ ] 获批后接入 GitHub-hosted 构建与签名审批，并验证真实时间戳签名包。

以上是文档和授权变更，不修改客户端、采样器、Clash/TUN、VPS 或签名验证门禁；不重置现有通过证据。PR 仍为 Draft，不授权合并/部署。
