# UM-B3 R1 isolated-lab risk acceptance record (DRAFT, PRODUCTION HOLD)

- Record version: **1**
- Date: 2026-11-27 (Europe/Istanbul)
- Decision source: Owner instruction in the B3 Final Closure goal, recorded in
  this session and referenced by issue #127 / Draft PR #131.
- Scope: **isolated development, synthetic credentials and disposable lab
  hosts only.**
- Status: **R1 LAB AUTHORIZED / R1 PRODUCTION ENABLEMENT HOLD**
- R2: **INFEASIBLE on the tested Clash Verge Rev 2.5.10 / Mihomo 1.19.33
  surfaces; full target build matrix UNVERIFIED.**

## 1. Accepted technical direction

The Owner accepts R1 as a candidate Windows Terminal Agent source **only for
isolated lab verification**:

- the Mihomo controller credential is **write-capable**; a GET-only agent does
  not make the credential read-only;
- no unauthenticated write-capable named pipe may be used;
- no new bridge process holding a write-capable credential may be introduced
  without a separate Owner decision;
- R1 must remain disabled by default and must not be enabled by a center
  config or an environment variable alone;
- the controller secret must be protected with DPAPI CurrentUser and a private
  ACL, and must never enter logs, CLI arguments, environment values, center
  configuration or telemetry;
- no real business controller secret may be rotated, overwritten or modified;
- this record does **not** authorize production use, a real tournament
  terminal, or changing Mihomo/Clash Verge Rev/HA behavior.

## 2. Local activation design

Activation requires a protected provisioning bundle under the agent state
directory (`<state>/r1/`):

| File | Meaning |
| --- | --- |
| `acceptance.json` | versioned record binding decision, isolated-lab scope, Owner reference, profile hash and protected-secret hash |
| `profile.json` | operator-local controller/group/route binding; literal loopback IP only |
| `controller.secret.dpapi` | controller secret sealed with Windows DPAPI **CurrentUser** |

The provisioning path is `um-agent r1-provision`, intended to run under the
same account as the service. It is the only code path that writes the bundle;
it applies a protected DACL (current user, SYSTEM, Administrators) to the R1
directory/files. There is no `UM_AGENT_WINDOWS_*` environment secret/profile/
authorization switch in the B3 code any more. A missing bundle leaves R1
disabled; a malformed, hash-mismatched, non-isolated-lab or unsealable bundle
fails closed.

The observer keeps the frozen R1 shape: literal loopback HTTP, fixed
`GET /proxies` and `GET /connections`, no redirects, no proxy environment, no
arbitrary URL/path/method, bounded responses, independent selection and active
sampling, six route tokens, and operator-local route bindings.

## 3. Lab acceptance matrix

| Check | Required | Status |
| --- | --- | --- |
| isolated Mihomo controller authentication and selection changes | yes | **LAB PASS** (Windows 2022, run 46038057860) |
| four non-direct paths + direct/unknown | yes | **LAB PASS** for direct + four non-direct selection bindings; unknown is the frozen fallback |
| selection vs active-connection sampling | yes | **LAB PASS** (independent sampling; real direct connection persisted) |
| controller unavailable/malformed/auth failure | yes | **LAB PASS** for controller loss; malformed/auth failure have unit coverage |
| connection close | yes | LAB harness closes the test connection; unit lifecycle coverage exists |
| only allowed GETs from agent; no PUT/PATCH/DELETE/POST | yes | **static/unit PASS**; lab requests are harness-only PUTs plus agent GETs |
| Mihomo config hash unchanged | yes | **LAB PASS** |
| agent never changes selection/closes connections | yes | **LAB PASS** (selection changes made only by harness) |
| privacy sentinel never leaves host | yes | **LAB PASS** (local profile/controller sentinel absent) |
| DPAPI CurrentUser + private ACL for R1 bundle | yes | **LAB PASS** under virtual service account |
| R1 production enablement | forbidden | HOLD |

The machine-readable acceptance is
[`r1-acceptance-record.v1.json`](r1-acceptance-record.v1.json) in this
directory.

## 4. Standing holds

- R1 remains disabled in every production deployment.
- R2 remains unavailable/infeasible on tested builds.
- No real controller secret is used; lab credentials are synthetic.
- Production enablement requires a separate Owner decision, target-build
  capability audit, independent review and UM-E acceptance.
