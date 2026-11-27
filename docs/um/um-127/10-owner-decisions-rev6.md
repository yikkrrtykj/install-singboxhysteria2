# Owner decisions for rev-6 / UM-B3 finalization

- Record date: **2026-11-27** (Europe/Istanbul)
- Decision source: Owner instruction in the UM-B3 Finalization / Rev-6 Contract
  Release goal, referencing Issue #127, amendment Draft PR #132 and B3 Draft
  PR #131.
- Status: **APPROVED within the limited scope below.** This is a technical and
  deployment-architecture decision, not a production deployment authorization.
- Binding baseline: UM-A rev-5 `docs/um/um-a/04-node-protocol-v1.md` (contract
  commit `048fc170685da5b7140bebd9e3347616cb3ec656`) plus the rev-6 normative
  overlay in this package.

## 1. OD-P3 — Windows data source

| Decision | Record |
| --- | --- |
| R2 investigated result | R2 (a truly read-only Windows source with no controller secret) is **INFEASIBLE on the tested Clash Verge Rev 2.5.10 / Mihomo 1.19.33 surfaces**. This is a tested-version finding, **not** a claim that every future/other version is infeasible. |
| R1 architecture | **APPROVED as the first supported Windows terminal source architecture** after isolated-lab verification, **production enablement HOLD**. |
| Residual risk explicitly accepted for the architecture | The Mihomo controller credential is **write-capable** even when the agent is limited to GET. Local credential compromise and agent process compromise therefore retain a write-capability residual risk. |
| Required controls | disabled by default; literal loopback TCP only; fixed `GET /proxies` and `GET /connections`; protected local bundle; DPAPI **CurrentUser**; private ACL; non-admin service account; no environment/center-config/arbitrary-URL bypass; no unauthorized auto-enable; no unauthenticated write-capable named pipe; no Mihomo/Clash Verge Rev/HA configuration changes. |
| Production | R1 production enablement is **NOT approved**. A real tournament terminal requires a separate deployment authorization. |

## 2. OD-P7 — Windows service account

| Decision | Record |
| --- | --- |
| Standard account | **`NT SERVICE\um-agent`** — a non-admin dedicated virtual service account with its own service SID, running in **Session 0**. |
| Secret/state protection | DPAPI **CurrentUser**, private ProgramData/state ACL, ACL limited to SYSTEM, Administrators and the dedicated service account; enrollment, identity, rotation and R1 provisioning run under the correct service-account context. |
| Fallback | A dedicated non-admin local account is allowed **only** as an independently verified fallback. |
| Forbidden | `LocalSystem`; automatic fallback to **DPAPI LocalMachine**. |
| Authorization scope | Technical/deployment architecture approved; **no authorization to operate a real tournament computer**. The final production account/credential policy remains subject to deployment review. |

## 3. Linux sing-box data source

- The current **v1.14.5 P1-10 authorization audit FAIL** is accepted as fact.
- `collect.singbox_api` remains **disabled/unavailable**; it must not be enabled
  by weakening a security gate.
- Linux Agent base capability and protocol-traffic data-source capability may be
  accepted separately.
- Real **Reality/Hysteria2 traffic collection remains an incomplete product
  capability** and must not be marked PASS. It is recorded in Issue #127 as a
  pre-production functional limitation.
- Read-only investigation of whether the existing VPS Monitor exposes a reusable
  local statistics/export interface is allowed. **No monitor-v2 modification, no
  source-permission expansion, and no new process holding write credentials** is
  authorized.

## 4. Power-loss / process-restart contract

The rev-6 amendment direction in PR #132 is **APPROVED**:

- every successful start of an enrolled runtime, including unclean exit and
  power-loss recovery, enters a **new generation**;
- a new random `boot_id`;
- a fresh transport attempt;
- preserve `report_id`, `collected_at` and payload identity;
- a duplicate from the new generation still advances the new-generation
  high-water;
- fsynced data must not be lost;
- same-runtime exact retry and restart replay are distinct;
- `status`/read-only inspection does not mutate generation or boot state.

The amendment must not weaken signature binding, nonce uniqueness, request
fingerprint, report_id dedupe, boot high-water, generation gap bounds, identity
revocation, rotation proof or fsync-before-send.

## 5. Merge authorization and limits

- The Owner conditionally authorizes merging **PR #132 only**, solely as the
  rev-6 contract-release PR, and only after an independent review PASS, exact
  baseline match, no blocking findings, and all required checks green.
- Normal Merge Commit only; no squash/rebase/force-push; no protected-branch
  bypass.
- This authorization does **not** authorize merging PR #131.
- It does not authorize production deployment, a real R1 deployment, an
  unauthorized `singbox_api`, UM-B4/C/D/E/F/G work, paid resources, or changes to
  unrelated modules.
- PRODUCTION HOLD and UM-F DEFERRED remain in force.
