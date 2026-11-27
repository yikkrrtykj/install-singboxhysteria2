# UM-B3 ADR — agent credentials and Windows runtime account (OD-P7 proposal)

- Status: **PROPOSED / PENDING OWNER.** This is an ADR **proposal** for Owner
  decision **OD-P7** (`docs/um/um-127/05-owner-decisions.md` §C). It must not be
  marked APPROVED, and no coding agent may treat it as approved or as an
  installation authorization.
- Scope: how the UM agent stores its node private key and (if a source that
  needs one is ever authorized) a local data-source credential, and which
  Windows account runs the `windows_terminal` agent service.
- Related: `docs/um/um-a/04-node-protocol-v1.md` §7/§11,
  `docs/um/um-a/03-architecture-and-trust-boundaries.md` §11–§12,
  `docs/um/um-a/06-threat-model-security-tests-performance.md` §4/§8,
  `docs/um/um-127/05-owner-decisions.md` (OD-P3, OD-P7),
  `docs/um/um-a/02-technology-selection-adr.md` ADR-UM-002.
- Not in scope: center credentials, admin/TOTP/session secrets, TLS keys,
  Cloudflare tokens (center is UM-C/UM-E), and **R1 enablement** (separate
  Owner risk acceptance under OD-P3; this ADR does not grant it).

## 1. Decision summary (proposed, not approved)

| ID | Decision | Proposed direction | Status |
| --- | --- | --- | --- |
| D-1 | Linux agent runtime identity and file permissions | non-login `umagent`; `/var/lib/um-agent` 0700 `umagent`; key/state files 0600; root-only bootstrap token; no root resident process | **PROPOSED** (already congruent with frozen contract; no extra Owner decision requested) |
| D-2 | Linux data-source credential delivery | systemd `LoadCredential=` from a root-owned file into the `umagent` process; source permissions unchanged; no plaintext copy in agent state; source off by default | **PROPOSED** |
| D-3 | Windows agent runtime account | session-0 Windows service under a **dedicated non-admin** account: virtual service account `NT SERVICE\um-agent` preferred, dedicated local user fallback; `LocalSystem` rejected; `LocalService` only as legacy placeholder | **PENDING OWNER; virtual-account SCM/DPAPI/R1/session-0 lab PASS (isolated Windows 2022, run 46038057860); production account still PENDING** |
| D-4 | Windows secret storage scope | DPAPI **CurrentUser** scope of the service account (preferred, implemented for agent state); machine scope only with explicit Owner risk acceptance; R2 (no secret) preferred over both | **PENDING OWNER; CurrentUser node-key protection IMPLEMENTED and service-account lab PASS; final account/ACL and machine-scope decision PENDING** |
| D-5 | R1 controller credential (write-capable) | **Owner-authorized for isolated lab only**; protected local bundle + DPAPI CurrentUser + private ACL; production HOLD with the mitigations in `04` §11 | **R1 LAB AUTHORIZED / PRODUCTION HOLD** |
| D-6 | Install/upgrade/uninstall and rotation procedure | account and storage scope fixed before install; no secret in scripts/repo/logs; upgrade preserves state; uninstall requires explicit data-purge confirmation | **PROPOSED** |

No real credential, token, password, private key or DPAPI blob may be created,
requested or stored by UM-B3 work. This ADR contains none.

## 1a. Implementation status at this Draft (not an OD-P7 approval)

- The shared `internal/secretstore` package implements DPAPI CurrentUser with
  synthetic round-trip tests. The agent runtime protects `identity.json` and
  `rotation.json` private-key material at rest with DPAPI CurrentUser, migrates
  legacy plaintext state, and seals the R1 controller secret in the protected
  `<state>/r1` bundle. Machine scope is not used by default and must not be
  selected automatically. The installer creates built-in/virtual accounts with
  correct SCM syntax and verifies them with `sc qc`; the UM lab workflow runs
  enrollment/R1 provisioning under the virtual account.
- This is **current-user** protection, not a service-account validation. The
  Windows SCM/account/ACL provisioning, virtual-service-account profile
  behavior, session-0 source access and enrollment-under-service-account flow
  remain **OD-P7 PENDING**. Enrollment must run under the same Windows account
  that later decrypts the state; changing the account without a rewrap/re-enroll
  plan makes the state fail closed (documented, not silently reset).
- The Windows installer template still defaults to `LocalService` for a safe
  placeholder; it is not the proposed virtual service account and must not be
  treated as final. The installer does not run enrollment, create a DPAPI
  secret, or approve an account.
- The node private key must be protected even if R2 is proven and no controller
  secret exists. `LocalSystem` remains forbidden; `LocalMachine` DPAPI scope is
  not a default.

## 1b. OD-P7 isolated Windows lab result and recommendation

The dedicated isolated `um-b3-lab.yml` workflow ran on the GitHub-hosted
**windows-2022** runner (run `46039366384`, PASS). It created the service
directly under `NT SERVICE\um-agent` with a per-service SID and no password,
enrolled under that account, verified DPAPI CurrentUser protection of the
Ed25519 identity and provisional rotation key, provisioned the R1 bundle under
the same account, ran the real `um-agent service` wrapper in session 0, and
verified stop/start identity recovery. The SCM service account, session and
state ACL were checked; no LocalSystem or machine-scope DPAPI path was used.

**Recommendation:** use `NT SERVICE\um-agent` as the primary OD-P7 account
(virtual service account, per-service SID, DPAPI CurrentUser, private state/R1
ACL). A dedicated non-admin local user remains the fallback if a target build
cannot support the virtual account's DPAPI/profile behavior. `LocalSystem` is
forbidden. This is a **LAB result and recommendation only**; final production
account and production credential policy require a separate Owner record.

Enrollment and R1 provisioning must run under that same account. The lab uses a
SCM helper because a console `enroll`/`r1-provision` process cannot itself be an
SCM service; the production installer does not silently enroll or provision.

## 2. Linux file-permission baseline (proposed; aligns with frozen contract)

The Linux runtime follows `04` §11 and is **not** an OD-P7 policy question; the
table is recorded here so the Windows decision is made against the same baseline.

| Artifact | Path | Owner / mode | Notes |
| --- | --- | --- | --- |
| State directory | `/var/lib/um-agent/` | `umagent:umagent` 0700 | only writable path for the service; symlinks rejected by agent state checks |
| Node private key | inside state dir (`identity.json`, mode 0600) | `umagent` 0600 | generated on node, never sent/backed up centrally/logged |
| Boot/config/rotation state | inside state dir, 0600 | `umagent` 0600 | boot-state loss is fail-closed (REC-17), never reset |
| Spool / quarantine | `/var/lib/um-agent/{spool,quarantine}` 0700 | `umagent` | 32 MiB / 7 d; fsync-before-send; no secrets |
| Bootstrap token | `/etc/um-agent/bootstrap.token` | `root:root` 0600 | **not readable by `umagent`**; read by root installer and piped to `um-agent enroll --token-stdin`; deleted by root after successful enrollment; left 0600 only for operator retry on failure |
| Service unit | `/etc/systemd/system/um-agent.service` (+) noexec drop-in | `root:root` 0644 | installed by reviewed one-shot installer; no agent-controlled unit file |
| Agent binary | `/usr/local/libexec/um-agent` | `root:root` 0755 | only executable path; upgraded only from a verified SHA-256 build receipt |
| sing-box API credential (if ever authorized) | root-owned credential source (not the sing-box config) | `root` 0400 + `LoadCredential=` | agent sees content only in `$CREDENTIALS_DIRECTORY` in its private mount namespace; no permission change to sing-box/Monitor/`sbox-cm` files |

Additional rules: `umagent` is a non-login system user (no home, no shell, no
sudo); no resident root collector; no fork/exec (`NoExecPaths=` standard-tool whitelist where
supported, see `um-b3-scope-and-matrix.md` G2); only outbound HTTPS to the
center; no listening socket. **No DPAPI on Linux** — there is no OS keyring
dependency; "DPAPI scope" below is Windows-only.

## 3. Windows runtime account candidates (decision D-3)

The Windows terminal agent is a service running in **session 0**. Clash Verge
Rev normally runs in the interactive user's session; an R2 read-only local
source should not require controller secrets, while an R1 source would require a
write-capable controller credential (OD-P3, not authorized).

| Candidate | Privilege | Secret/DPAPI implications | Session/desktop access | Overall |
| --- | --- | --- | --- | --- |
| **Virtual service account** `NT SERVICE\um-agent` (`sc.exe sidtype ... unrestricted`) | non-admin by default; per-service SID for ACLs; no password | own profile; DPAPI user scope must be verified on target Windows build | cannot read interactive user's DPAPI; needs explicit ACL/read for any file source | **candidate (proposed preferred if DPAPI user scope is verified)** |
| **Dedicated local user** (e.g. `.\umagent-win`), "Log on as a service", non-admin, non-interactive | non-admin; explicit ACLs | own profile → DPAPI CurrentUser scope straightforward; admin-managed password (store none in scripts) | cannot read interactive user's DPAPI; explicit ACL needed for file sources | **candidate (proposed fallback with password-management burden)** |
| `NT AUTHORITY\LocalService` | built-in least privilege; anonymous network | service SID; DPAPI user scope under LocalService profile; provisioning must run as LocalService | no interactive access | acceptable **minimum** only with Owner acceptance; shared built-in identity |
| `NT AUTHORITY\NetworkService` | network identity | unnecessary machine/network credential exposure | no interactive access | reject |
| `LocalSystem` | full local admin | can read machine DPAPI; violates least privilege; agent compromise = host compromise | full | **reject** (the installer must refuse it) |
| Interactive desktop user (scheduled task/autostart, not a service) | user rights only | DPAPI CurrentUser of that user; secret tied to interactive logon | sees user files/DPAPI | reject for a service, but note: if ever used, it is a different deployment mode and needs its own decision (DPAPI scope is the only "optional DPAPI" variant) |

Proposed decision text for the Owner (not approved): "Run the Windows agent as
an unprivileged session-0 service under a dedicated non-admin account (virtual
service account preferred if DPAPI user scope is proven on the target builds;
otherwise a dedicated local user).`LocalSystem` is prohibited; `LocalService` is
only acceptable with explicit written acceptance."

## 4. Windows secret storage and DPAPI scope (decision D-4)

DPAPI is only relevant if a secret must be stored locally (R1 controller
credential; R2 is defined by *not* needing a controller secret). Options:

| Option | Protects against | Does not protect against | Verdict |
| --- | --- | --- | --- |
| **DPAPI CurrentUser** under the agent service account | other local users, other services, offline file theft without the account profile/master keys | a local administrator who can log on as/serve as that account, process memory after compromise | **proposed preferred if a secret is unavoidable** |
| DPAPI LocalMachine | casual file copying | **any local administrator** can decrypt with machine scope | only with explicit Owner risk acceptance; not proposed |
| Plain ACL-protected file (0600-equivalent, no DPAPI) | other non-admin users (with correct ACL) | admin, backup/disk theft, profile-less service context | reject for R1 |
| **No secret at all (R2 truly read-only source)** | the whole credential-write-path risk | — | **preferred by OD-P3; R2 investigated and INFEASIBLE on tested builds; no approved secretless source** |

DPAPI user scope requires the secret to be encrypted **by the account that runs
the agent**; a user-session secret cannot be decrypted by a session-0 service
under a different account. Provisioning the R1 secret must therefore be an
explicit, Owner-approved step executed as the service account (no admin `runas`
password in scripts, no password on the command line, no secret in the repo).
R2 avoids this entirely by using a source that has no controller secret.

Session isolation facts to record in the decision: session 0 cannot read the
interactive user's DPAPI; UI/IPC cross-session is restricted; the service cannot
inspect the user's process memory by default; files written by the user are not
automatically readable by the service (explicit ACL needed); Clash Verge Rev
config/secret files stay under the user's profile unless a specific read-only
local source is proven and authorized.

## 5. ACL design (Windows, proposed)

| Object | ACL proposal |
| --- | --- |
| Data dir `C:\ProgramData\UM Agent` | `SYSTEM` full, `Administrators` full, service account full, `Users` none; directory not inheritable from a broader public root where avoidable |
| State files (`identity.json`, boot/config/rotation, spool) | service account only read/write; no `Users`/`Everyone`; created 0600-equivalent; inherited ACL restricted |
| Config file (center URL, node class) | service account read; no secrets |
| DPAPI-protected secret blob | service account read; ACL restricted; never backed up centrally |
| Clash Verge Rev config/secret source | **unchanged** by UM; if R2/R1 is later authorized, UM adds a read-only grant for the service account only (no write, no inheritance widening) |
| Service registration | `sc.exe sidtype um-agent unrestricted` (virtual SID), recovery actions, `StartupType=Manual` by default; no automatic start from the installer |

The service must not have write access to Clash Verge Rev, Mihomo or HA-UI
objects; no new public listener; outbound HTTPS to the center only.

## 6. Credential lifecycle

1. **Node Ed25519 key (both platforms)** — generated on the node at enrollment;
   rotation is the frozen protocol state machine (`04` §7): old key stays active
   until proof of new-key use, never revoked on a timer; admin revocation wins;
   private key never uploaded/backed up centrally. Agent state loss = operator
   revoke + re-enroll as a new node id (REC-17/18).
2. **Linux bootstrap token** — one-time, root:root 0600, piped to the
   unprivileged enrollment process, deleted by root after success; orphan path
   on lost response is admin revoke + reissue (REC-24).
3. **Linux sing-box API credential (if authorized)** — delivered only through
   `LoadCredential=`; source permissions unchanged; rotating it is a root
   operator action replacing the credential source and restarting the unit; the
   agent never persists it to its state dir or logs.
4. **Windows source credential (R1, only if ever accepted)** — provisioned
   under the service account into DPAPI CurrentUser (or machine scope only with
   explicit acceptance); rotation = change in Clash Verge Rev/Mihomo, re-run
   the approved provisioning step as the service account, restart service,
   verify an authenticated response; no center-side change; secret never in
   logs/repo/issues/scripts.
5. **Windows node key** — same frozen rotation as Linux. Node identity and
   rotation provisional private keys are now **DPAPI CurrentUser-protected at
   rest** (implemented in `internal/agent` via `internal/secretstore`); this is
   required even if R2 needs no controller secret. The final service-account
   context/enrollment flow and machine-scope use remain Owner decisions.

## 7. Install / upgrade / uninstall (proposed)

- **Install**: account and storage scope are decided/recorded first; the
  installer requires an explicit Owner-confirmation switch and refuses
  `LocalSystem` and any R1/controller-secret provisioning. It creates the data
  dir/ACLs, installs the service as **Manual** (no start, no enable), and prints
  the exact next operator command. Secret provisioning, if any, is a separate
  explicitly-approved step, never part of the install script.
- **Upgrade**: stop service; replace the binary only from a verified build
  receipt (SHA-256); preserve state dir/DPAPI; start; verify a signed report is
  accepted. Node private key and boot state are not re-created (boot generation
  increments normally on restart).
- **Uninstall**: stop/disable and delete the service; remove the data dir only
  after explicit confirmation and after the admin has revoked the node and the
  spool disposition is recorded; never delete `spool`/`quarantine` silently
  (no silent data loss, no orphan identity). Clash Verge Rev/HA-UI are not
  touched by install, upgrade or uninstall.

## 8. Residual risks (for the Owner decision)

| Risk | Mitigation in this proposal | Residual |
| --- | --- | --- |
| Local admin can decrypt/impersonate the agent account | least privilege, service SID DPAPI scope, no admin runtime | accepted at host-admin trust level (out of scope, documented in `06` §8) |
| Service cannot read the user's controller secret | R2 preferred; if R1 is accepted, secret must be re-provisioned under the service account / explicit ACL | R1 risk acceptance (OD-P3) required |
| Machine-scope DPAPI decryptable by any admin | prefer CurrentUser scope; machine scope only with written acceptance | Owner decision |
| Secret leaks via scripts/logs/backups | no secrets in scripts/repo/logs; no central key backup; closed error logging | operator discipline + UM-E test |
| Virtual account DPAPI behavior varies by Windows build | verify on the target OS matrix before the final account decision | research gap (see Windows sources ADR) |
| Agent compromise on a terminal | no config write, no exec, no admin, revocable node identity | host-local tamper is out of scope (`06` §8.11) |

## 9. Decision record (to be completed by the Owner; do not fill in approval)

| Item | Value |
| --- | --- |
| OD-P7 decision owner | project Owner |
| Requested decision | D-3 Windows account, D-4 DPAPI scope, D-5 R1 (separate), D-6 lifecycle |
| Proposed by | UM-B3 Draft (this document) |
| Owner answer | **PENDING** |
| Owner name/date/reference | **PENDING** |
| Resulting implementation change | after approval: installer account/ACL defaults; otherwise no change |

Any approval must be recorded in `docs/um/um-127/05-owner-decisions.md` (or an
Owner-authored record linked there) before code or install assets rely on it.
Until then, the Windows installer remains a template that requires explicit
Owner confirmation and creates no credential, and R1 stays disabled.
