# Server service/resource evidence — issue #33, Monitor 0.9.0

Operator authorized this next feature after 0.8.1 deployment on 2026-10-08.

## Contract

- Independent daemon samples every 10 seconds; only fixed /proc files, state-root statvfs and fixed `systemctl show sing-box.service` properties. One-second subprocess timeout. No journal/config/secret/network read, privileged helper or mutation command.
- Store is independent `host-evidence/host.sqlite3`, version 1, owner-only real paths. Exact schema/objects, 7-day/60480-row retention, 16 MiB SQLite page ceiling (rollback journal separately at most another database-sized footprint). Unknown existing schema is refused, never migrated/adopted. API reads are bounded to 1024 plus a truncation witness and do not prune/write.
- History remains v5 and remote store v1. No deploy/rollback backup glob broadening, no classifier/presenter/runtime or Windows change. Rolling back keeps the independent store; 0.8.1 ignores it. New records begin only after deploying 0.9.0.
- Authenticated GET `/api/v1/incidents/<id>/host-evidence`; canonical ID, stored incident analysis bounds only. URL parameters cannot broaden the window. Existing list/detail/remote schemas remain frozen.
- Service ActiveState, MainPID, NRestarts and monotonic start timestamp are stored as closed states/integers. NRestarts means automatic systemd restarts, not all manual lifecycle changes; process identity changes are shown separately and are not added together.
- Counter comparisons require same boot and monitor run, known service states and positive adjacent time delta no more than 25 seconds. A gap, reboot, monitor restart, unavailable state or reset cannot fabricate a service restart. CPU is interval delta, first/gapped samples unknown; memory uses MemAvailable; file-descriptor and conntrack values are system-wide, not sing-box-specific.
- Event screen shows concise sampled facts with collapsed resources. Explicit missing, partial, truncated, unobservable and current-recorder status; never replaces the frozen incident classification. Resource peaks do not establish cause, nor do 10-second sample points exclude shorter incidents.

## Review / validation TODO

- [x] Authorized scope and independent evidence/storage/UI contract recorded.
- [x] Local collector/store lifecycle, missing permission/timeout, restart/reset/reboot/gap and retention/storage refusals tested.
- [x] Actual HTTP session/missing ID/history failure/window constraints and late-response DOM checks.
- [ ] Packaging/compatibility and exact-head CI pass; review and PR.
- [ ] Existing VPS update and one server-health receipt; no client reinstall or old native acceptance repetition.

Local verification: 32 host-evidence tests, 30 passed and 2 Linux-only checks covered by Linux CI;
153 DOM behavior checks; all 23 existing remote-evidence HTTP/SQLite tests;
166 existing incidents checks. The initial Windows packaging attempt exposed the
synthetic 0.9.0 collision (corrected to 98.9.0 / 98.10.0) and three mock-listener
shutdown failures from the local shell/Python adapter; retain that failed run,
use a native test entry and leave full atomic/Linux ownership gates to CI. The first PR head passed all 15 CI checks, including all 30 initial host tests on Linux and the non-root reader/store test on Ubuntu 22.04, 24.04 and 26.04. Final-head CI covers two additional worker-start/storage-full cases and explicit mock-listener waits.

## 0.9.1 host-facts guidance（原 `monitor-v2-host-guidance.md` 合并）

0.9.0 独立保留 host service/resources，但旧全局事件限制仍称不记录此类历史——该说法已过时。presenter 现已说明：存储的 classifier 并未消费这些独立事实；category、summary keys、bitsets 与 classifier/runtime 保持不变。

host facts 旁附带一条简洁运维下一步：observed non-running service 指向检查匹配的 service/errors；automatic restart increments 指向对比 before/after 记录；process changes 指向复核人工更新。Missing、reset、incomparable、partial、truncated 或 single-sample 记录不能排除 service 变化。完整采样对比指向独立网络/设备证据核查，同时承认未采样的短时变化。

任何资源阈值都不虚构原因；资源峰值只是 drill-down facts。本指引不建议 restart/reinstall/protocol switch。旧兼容文案映射到同一准确解释；加载清除旧建议，late responses 不能覆盖 closed/other incidents。

验收：实际 presenter 结果保持冻结 keys 并承认独立历史；DOM 场景区分 stop/restart/manual/reset/gap/single/partial/missing/high-resource 与 late-response isolation。既有 host-store/API、classification、privacy 与 Linux deployment gates 全部适用；storage、collector cadence、systemd、Windows Agent 与凭据不变，无需重复 native 30 分钟检查。
