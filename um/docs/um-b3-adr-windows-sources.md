# UM-B3 ADR — Windows terminal data sources: R2-first research and gating (OD-P3)

- Status: **PROPOSED / PENDING OWNER — R2 investigation completed; R2 is
  INFEASIBLE on the tested surfaces.** This is the B3 research record and R1
  proposal for Owner decision **OD-P3** (R2 truly-read-only source preferred;
  R1 write-capable controller credential needs a separate later Owner risk
  acceptance and is never auto-enabled). It is **not** an approval, not an
  authorization to enable any source, and not production evidence.
- Baseline: `docs/um/um-a/04-node-protocol-v1.md` §9.2/§11 (revision 5, frozen),
  `docs/um/um-127/02-dual-platform-contract.md` §4,
  `docs/um/um-a/06-threat-model-security-tests-performance.md` SEC-39/47/50,
  `docs/um/um-127/05-owner-decisions.md` OD-P3/P7.
- R1 status: **not authorized, not enabled by default.** The Windows binary has
  an explicitly gated R1 source path (`UM_AGENT_WINDOWS_SOURCE_AUTHORIZED=1` plus
  operator-local profile/secret files) that remains disabled unless an operator
  performs an Owner-approved setup; no source is enabled by this Draft.
- R2 status: **INFEASIBLE on the tested Clash Verge Rev 2.5.10 / Mihomo Meta
  1.19.33 surfaces (isolated synthetic lab); full target build matrix remains
  UNVERIFIED.** See §6.

## 1. Decision requested

| Item | Requested decision | Status |
| --- | --- | --- |
| OD-P3-R2 | Accept/reject a specific **truly read-only** Windows terminal data source (no controller secret) as the `windows_terminal` telemetry source | **PENDING OWNER** (research completed; R2 INFEASIBLE on tested surfaces; see §6) |
| OD-P3-R1 | Accept/reject the **R1 residual risk**: a write-capable Mihomo/Clash Verge Rev controller credential used by a strictly GET-only client | **NOT AUTHORIZED / BLOCKED** — only after R2 is shown infeasible and a separate risk acceptance is recorded |
| Enablement | Whether the center may set `collect.terminal`/`mihomo_api=true` for a node | **PENDING OWNER**; defaults remain `false` |

No source is enabled by this Draft. The R2 lab used an isolated synthetic Mihomo/Clash Verge Rev instance; no production controller or production configuration was contacted or changed.

## 2. Facts that constrain the decision

1. **The Mihomo/Clash Verge Rev external controller credential is
   write-capable.** The official API exposes configuration-mutating operations
   (`PUT/PATCH /configs`, `POST /restart`, `POST /upgrade`, `PUT/DELETE
   /proxies`, provider writes, `PATCH /rules/disable`, `DELETE /connections`,
   and others). Clash Verge Rev requires the user to enable the external
   controller manually and use is at the user's own risk. Sources:
   <https://wiki.metacubex.one/en/api/>,
   <https://github.com/clash-verge-rev/clash-verge-rev/discussions/6951>.
2. **A GET-only client is an implementation constraint, not an authorization
   proof.** The credential remains write-capable server-side even if the agent
   only calls `GET /proxies` and `GET /connections`. UM must never describe the
   controller credential as "read-only". Any "read-only platform" statement must
   be phrased as "write-capable credential used by a read-only client".
3. **R2** means a genuinely read-only local data source that does **not** hold a
   controller secret (for example a verified local read-only surface/export).
   If proven, it is the preferred source and is reported as
   `source=local_readonly`. Whether such a surface exists on the target Clash
   Verge Rev/Mihomo builds was investigated; no conforming surface was found on
   the tested builds (see §6).
4. **R1** means the write-capable controller credential, used only via fixed
   loopback GET paths. It is a documented residual risk requiring a separate,
   later Owner acceptance and is **never auto-enabled**.
5. The Windows agent must remain read-only with respect to
   Mihomo/Clash Verge Rev and HA behavior: it must not modify configuration,
   switch nodes, close connections or change HA-UI/P6/#67 behavior. Only six
   bounded route tokens, aggregate counts and sampling timestamps may leave the
   host; local proxy names, private YAML, controller secrets, URLs,
   destinations, process names and connection ids never leave the host.

## 3. Exact gating rules (normative for B3; copied from the frozen contract)

Verbatim normative wording from `docs/um/um-a/04-node-protocol-v1.md` rev-5
(referenced by the rules below; do not weaken or paraphrase it in
implementation/PR claims):

> Windows collection is read-only: the agent MUST NOT modify Mihomo/Clash Verge
> Rev configuration, switch nodes, close connections or change HA-UI/P6/#67
> behavior. `mihomo_api` defaults to **false**. The R2 truly-read-only data
> source is the preferred enabler; R1 (a write-capable controller credential
> used by a read-only client) requires a later, separate owner risk acceptance
> and is never auto-enabled. Until an authorized source is proven,
> `terminal.availability` is `unavailable` with
> `reason_code=source_authorization_unproven`; no fabricated data. (04 §9.2)

> The external controller credential is generally read/write; the R2 truly
> read-only source (no controller secret, e.g. a verified local read-only
> surface) is the preferred R2 investigation and must be evaluated in UM-B3. R1
> (a write-capable controller credential used by a strictly GET-only client) is
> a documented residual risk that requires a separate, later owner acceptance;
> it is never auto-enabled and is never described as "read-only". (04 §11)

These are the rules UM-B3 must implement and reviewers must check. They are
quoted/condensed from `04` §9.2 and §11 (revision 5) and `02` §4; where wording
differs, `04` is normative.

- **G1 — default off.** `mihomo_api`/`collect.terminal` default to `false`;
  source switches are enabled only by an authorized center config after the
  Owner data-source authorization is recorded.
- **G2 — R2 first.** The R2 truly-read-only source is the preferred enabler and
  must be evaluated in UM-B3 before any R1 proposal.
- **G3 — R1 never auto-enabled.** R1 requires a later, separate Owner risk
  acceptance; it is never enabled by default, never enabled by a config pull,
  and never described as read-only.
- **G4 — unproven source stays unavailable.** Until an authorized source is
  proven at runtime, `terminal.availability` is `unavailable` with
  `reason_code=source_authorization_unproven`; no fabricated data, no fake
  zeros, no "up" without evidence.
- **G5 — read-only client surface.** Only loopback controller access; fixed
  `GET /proxies` and `GET /connections`; no redirects, no proxy environment, no
  DNS-based indirection, bounded response size/caps, closed local token
  mapping.
- **G6 — no local names leave the host.** Local group/member/proxy names are
  operator-local (a Windows route-binding file, not center config, not
  uploaded); reports carry only the six tokens and aggregate counts; the center
  never receives or resolves local names.
- **G7 — honesty and six tokens.** Exactly six tokens (`a_reality`, `a_hy2`,
  `b_reality`, `b_hy2`, `direct`, `unknown`); `direct` only with an explicit
  owner-local binding, otherwise `unknown`/null; selection and active
  connections are sampled independently with bounded skew; `ok` requires
  non-null values and total = sum of the six counts.
- **G8 — no write / no HA change.** The agent never modifies Mihomo/Clash Verge
  Rev configuration, never switches nodes, never closes connections and never
  changes HA-UI/P6/#67 behavior. UM-E must validate this on the real target
  builds (config hash before/after, unchanged selection, no connection-close
  requests).
- **G9 — no permission changes.** No sing-box/Mihomo/Monitor/`sbox-cm` file
  permission is changed; a credential (if R1 were ever accepted) is delivered
  via DPAPI/private ACL to the unprivileged agent.
- **G10 — owner gate.** Source enablement requires the Owner decision recorded
  in the tracking issue/PR and, for R1, a versioned risk-acceptance record.
  Coding agents must not infer approval.

## 4. R2 research questions and candidate surfaces

R2 must satisfy **all** of: (a) no controller secret is held by the agent;
(b) the source is provably non-mutating server-side (not merely "we only call
GET"); (c) it exists on the target Clash Verge Rev/Mihomo build matrix;
(d) it provides enough information to classify the selected path and active
connections into the six tokens; (e) it works without admin/exec/root and
without changing product configuration; (f) it does not require uploading local
names or raw connection data.

Candidate surfaces tested in the isolated lab (results in §6; none conforms to R2):

| Candidate | What would make it R2 | Main risk |
| --- | --- | --- |
| A verified local read-only export/state file produced by the product | documented read-only contract; no secret; stable on target builds | files are usually user-writable → "read-only" claim weak; format may be unstable |
| A local read-only IPC/API surface with no write methods | product-side API that cannot mutate (server-side proof) | may not exist / may expose only write-capable controller |
| OS-level read-only observation (process/network/connection tables) | no secret, non-mutating by construction | cannot map to route tokens; privacy risk (raw connections) → likely fails G5/G6 |
| Local log/diagnostic export already sanitized by the product | sanitized, aggregate, no secret | needs read-only proof; may not contain current selection/active counts |

R2 findings must include the product/build versions, exact surface, static
capability proof (no write operations in the surface's contract/client), a
dynamic proof attempt (show that a mutation is impossible/absent, not merely
that the agent does not call it), and the mapping coverage for the six tokens.

## 5. R2 lab method (executed; no production)

Preconditions: Owner permission to use a **test** Windows terminal/lab machine;
no production hosts; no real user credentials; no changes to Clash Verge Rev or
Mihomo configuration; snapshots/hashes of the test configuration before and
after.

1. Record build matrix: Windows version/edition, Clash Verge Rev version,
   Mihomo core version/build hash, controller/API documentation revision.
2. Inventory candidate surfaces from product documentation/binaries and the
   local configuration (without extracting secrets). Record whether a secret is
   required and who controls the file/socket.
3. Prove (or disprove) read-only property: static capability audit (methods,
   paths, file modes, IPC verbs) + dynamic negative checks against the lab
   instance; a GET-only client is **not** sufficient proof.
4. Prove data coverage: map the candidate's data to the six tokens, the
   selected route and active connections; verify independent
   `selection`/`active_connections` sampling is possible.
5. Prove privacy boundaries: what the agent would read locally and what would be
   sent; confirm no names/URLs/IPs/connection ids/credentials are transmitted;
   run the sentinel negative tests.
6. Prove failure honesty: source absent/unreachable/malformed → `unavailable`/
   `unknown` with the closed reason codes; never zero/healthy.
7. If no R2 candidate passes, write the R1 infeasibility record and produce the
   separate R1 risk-acceptance proposal. Do not enable R1 by default and do not
   weaken G1–G10.

## 6. R2 investigation results (completed, isolated synthetic lab)

Status: **investigation executed; R2 INFEASIBLE on the tested surfaces; full
target build matrix UNVERIFIED.** This is LAB-REAL evidence for the tested
Mihomo/Clash Verge Rev builds, not a production or tournament-build claim.

Test object and method (no production config/credentials):

- Windows host lab; installed Clash Verge Rev **2.5.10**, Mihomo Meta
  **v1.19.33 windows amd64** (`with_gvisor`); isolated temporary Mihomo config
  and a synthetic controller secret. The installed user configuration was not
  modified; the lab process/temp files were removed after the test.
- TCP controller test (synthetic loopback): no secret -> HTTP 401, wrong secret
  -> 401, correct secret -> 200. The controller API exposes write operations.
- Windows named-pipe test: the official Mihomo docs state named-pipe access
  does not validate the secret. In the isolated lab, `/version`, `/connections`
  and `/proxies` returned 200 with no secret and with a wrong secret;
  `PUT /proxies/<synthetic-group>` returned 204 and `PATCH /configs` returned
  204. The observed pipe DACL was
  `D:P(A;OICI;0x12019f;;;BU)(A;OICI;0x12019f;;;SY)` (BUILTIN\Users + SYSTEM).
  The named pipe is therefore an unauthenticated write-capable controller
  surface, not a read-only source.
- Local config/state files: `clash-verge.yaml`, `config.yaml`, `profiles.yaml`
  and `verge.yaml` contain profile/selection metadata but no authoritative live
  active-connection/route distribution; they are user-owned/writable and
  session-0 service access is not guaranteed. They are not a sufficient R2
  source.
- A separate local read-only bridge that holds the named-pipe/controller
  capability and exposes GET-only would introduce a new process holding a
  write-capable capability and a new trust boundary. It must not be classified
  as R2; it would need a separate R1-style Owner risk acceptance and independent
  security review. It is not implemented in this Draft.

| ID | Candidate surface | Product/build | Secret? | Read-only proof | Six-token/selection/active coverage | Independent sampling | Privacy | Verdict | Evidence refs |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| R2-01 | TCP external controller (`127.0.0.1:9090`) | Clash Verge Rev 2.5.10 / Mihomo 1.19.33 | Yes (required) | **FAIL**: controller is write-capable; no read-only server-side proof | `/proxies` gives group `now`; `/connections` gives chains; no server truth or inbound tag guarantee | caller-controlled | requires secret; no local names in UM body | **INFEASIBLE (R1 only)** | isolated TCP auth test; official API docs |
| R2-02 | Windows named pipe (`external-controller-pipe`) | Clash Verge Rev 2.5.10 / Mihomo 1.19.33 | **No** (official: pipe does not validate secret) | **FAIL**: no auth, full write-capable controller API; `PUT`/`PATCH` returned 204 | same controller data as TCP | caller-controlled | pipe DACL BUILTIN\Users + SYSTEM | **INFEASIBLE (not R2)** | isolated pipe GET/PUT/PATCH test; official Mihomo docs |
| R2-03 | local config/state files | Clash Verge Rev 2.5.10 / Mihomo 1.19.33 | No | **FAIL/INSUFFICIENT**: no authoritative live active-connection/route distribution; user-writable/session access | insufficient | N/A | files contain private config; must not be read broadly | **INFEASIBLE/INSUFFICIENT** | file/schema inspection; no live connection data |
| R2-04 | separate local read-only bridge | proposed only | likely holds pipe/controller capability | not a read-only product surface; new trust boundary | could expose GET-only | N/A | new process/secret risk | **NOT R2 (separate risk acceptance)** | design analysis |

**R2 verdict: INFEASIBLE on the tested current product surfaces.** A fully
qualified R2 result would require a new upstream/product read-only API or a
separately reviewed bridge with an explicit Owner risk decision; neither exists
in this Draft. Because the target Clash Verge Rev/Mihomo build matrix (Q-AGENT-OS)
is not frozen, a different future build with a proven read-only surface must be
re-evaluated, not assumed.

Status of the R2 gate: **INVESTIGATION COMPLETE / R2 INFEASIBLE / OD-P3 PENDING;
no R2 source enabled.**

## 7. R1 write-capability record and exact mitigation list (not approved)

If R2 is shown infeasible, the R1 proposal must document the credential's write
capability (the API operations listed in §2) and the residual risk. The
mitigations required by `04` §11 for the proposal are:

- loopback-only binding of the controller;
- a dedicated secret in DPAPI/private ACL, not shared with other tools;
- an unprivileged agent with no exec and no admin rights;
- fixed `GET /proxies` + `GET /connections` only, no redirect/proxy env/DNS;
- static and runtime method/path allowlist tests proving no write method/path
  exists in the binary and that mutation attempts are impossible/absent;
- per-version controller capability audit on the target Mihomo/Clash Verge Rev
  builds;
- an explicit, auditable Owner risk-acceptance record.

R1 status in this Draft:

- **not enabled**; `mihomo_api`/`collect.terminal` remain `false` by default and
  no center config enables them;
- no R1 credential is created, requested, stored or logged by default; the
  optional R1 observer path requires an explicit operator environment gate and
  owner-approved profile/secret provisioning;
- the Windows install template refuses R1/controller-secret provisioning;
- the agent is never described as having a "read-only credential";
- `terminal.availability` stays `unavailable` with
  `source_authorization_unproven` until an authorized source is proven.

## 8. Evidence-level visibility rules (real vs MOCK/UNIT)

Every B3/UM claim about Windows sources must be labeled with one of these
levels; higher levels are not implied by lower ones.

| Level | Meaning | Allowed claim |
| --- | --- | --- |
| **MOCK/UNIT** | synthetic snapshot bytes or an injected `RouteObserver` fake; no real controller/product | "parsing/mapping/honesty logic passes unit tests"; never "R1/R2 works" |
| **LAB-REAL** | real Clash Verge Rev/Mihomo build on an authorized lab machine, real read-only proof, evidence captured | "candidate passes lab checks"; still not production-enabled |
| **FIELD** | real event terminal under operator supervision, center-authoritative source config, no write/HA regression | only after Owner authorization + UM-E acceptance |
| **PRODUCTION** | actual event production | requires separate production release authorization (HOLD) |

Current state: MOCK/UNIT evidence exists for the Windows collector logic and
LAB-REAL evidence exists for the isolated R2 investigation above (tested builds
only). FIELD/PRODUCTION evidence does not exist in this Draft, and R1 remains
disabled/unaccepted. The gated R1 CLI path is code-complete but not enabled. Test names and docs must use `mock`/`synthetic`
wording where applicable so a green unit test can never be mistaken for a real
source result.

## 9. Gating sequence to close OD-P3

1. R2 research with evidence (§5/§6) — **COMPLETED for the tested builds;
   R2 INFEASIBLE; full target build matrix UNVERIFIED.**
2. Independent review of the R2 evidence and privacy/read-only arguments —
   **PENDING** (this Code/Draft slice is not an approval).
3. Owner decision: either enable the proven R2 source, or accept the R1
   residual risk in a separate written record, or keep the source unavailable.
4. Only then may the center set the source switch for the class and the agent
   prove runtime authorization; the agent still reports `unavailable` on any
   unproven/version-mismatched source.
5. UM-E real-build read-only/HA assertions (`06` SEC-42..47) and independent
   security review.
6. Production release/authorization separately (HOLD).

Any failed step keeps the source disabled and the Windows terminal reports
`terminal.availability=unavailable` with a closed reason code; the existing
snapshot-with-terminal surface remains honest `unavailable`/null.

## 10. Owner decision record (to be completed by the Owner)

| Item | Value |
| --- | --- |
| OD-P3 R2 decision | **PENDING — evidence says INFEASIBLE on tested builds; owner must decide R1 risk acceptance vs no Windows source** |
| OD-P3 R1 decision | **NOT AUTHORIZED (PENDING separate risk acceptance)** |
| Owner answer/reference/date | **PENDING** |
| Enablement authorization | **PENDING** |
| Resulting center/agent change | none until approval |

Record the decision in `docs/um/um-127/05-owner-decisions.md` or a linked
Owner-authored record. This ADR must never be edited to say APPROVED by a
coding agent.
