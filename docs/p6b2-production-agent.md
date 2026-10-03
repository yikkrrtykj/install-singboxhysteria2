# P6B2 — production Agent / provisioning

> 当前登录策略：2026-10-03 用户确认的[单次登录与闲置退出](monitor-single-login.md)取代本文中的独立 300 秒密码确认；旧实现与 review 记录仅描述对应历史 head。客户端操作与下载仍保留会话、CSRF、来源、审计及实时管理状态门禁。

Authoritative contract: [Issue #67 §22](https://github.com/yikkrrtykj/install-singboxhysteria2/issues/67).
Recorded and implementation authorized 2026-10-02. This document explains the
reviewable implementation slices; it does not replace the issue body.

## Product direction

Keep P6A collection and P6B machine wire/storage. Add Client may orchestrate
optional device enrollment; Download Client Bundle delivers canonical YAML,
generic versioned Agent, immutable device/server profile, separate HMAC key,
per-VPS public TLS trust and installer. One Windows service manages bounded
independent profiles. IP + configurable high TLS port needs neither domain
nor newly opened public 80/443/9191. Monitor stays loopback/SSH-tunnel only.

Enrollment, download and reinstall must not rotate identity silently. A copied
ZIP is not a new device identity. Server revocation is independent of local
removal. Windows TUN routing and actual current Mihomo node mapping need live
acceptance; successful installation alone proves neither.

## This first slice

- `pinned_transport.py`: HTTPS/IP only, one profile-local public certificate,
  exact SHA-256 of leaf DER, normal certificate validity/IP-SAN checks. Explicit
  TLS connect and pin validation before HTTP headers/body. No environment TLS
  key logging, global trust import, TOFU or redirects. Absolute exchange timer
  bounds slow header/body peers. Caller cannot override framing.
- `profiles.py`: max eight profiles, each identified by SHA-256(server_id +
  newline + probe_id). Strict v1 manifest, no secret/path fields in public
  settings. Separate `ingest.key`, `server.pem`, `control.json` and `spool/`.
  Exclusive mutation lock, staged publication and fsync / Windows
  MoveFileEx(WRITE_THROUGH). Existing identity changes fail closed. Interrupted
  staging cannot become active or bypass capacity.
- `windows_security.py`: native protected DACL, SYSTEM/Administrators authority,
  descriptor/owner/type checks on opened handles and no junction/reparse paths.
  POSIX mode checks are used only on POSIX. Fixture-only SID injection is never
  exposed in production command arguments.
- `production_runtime.py`: explicitly wires the real pinned poster into the
  existing Agent collector and durable spool/disposition. Max two in-flight
  cycles, no per-profile overlap, cadence without catch-up storms, bounded
  replay slices. Local controller credential is read only from the protected
  profile's `mihomo.key`, never inherited from environment or bundled by a VPS.
  Failure is a closed profile status, not a raw exception or Clash control.
- `service_host.py`: stdlib ctypes SCM dispatcher and stop/pause/continue,
  no service desktop UI. `tools/p6-agent.py` is an absolute-path service entry
  without a PYTHONPATH dependency. The existing P6A CLI stays DARK.

On Windows the service authority is SYSTEM/Administrators only. The production
root is created by an elevated installer; root permissions are not silently
repaired on arbitrary existing paths. Credentials and state are never returned
by the status command. Foreground run is an explicit development entry that
can perform real network uploads; tests use loopback only.

## Development input shape

```json
{
  "v": 1,
  "server_id": "0123456789abcdef0123456789abcdef",
  "probe_id": "device-one",
  "ingest_url": "https://192.0.2.10:38443/api/v1/remote-probes/ingest",
  "certificate_sha256": "<64 lowercase hex characters>",
  "agent": {
    "mihomo_url": "http://127.0.0.1:9090",
    "reality_node": "Reality",
    "hy2_node": "Hysteria2",
    "dns_host": "www.cloudflare.com",
    "https_host": "www.cloudflare.com",
    "egress_host": "www.cloudflare.com",
    "vps_host": "192.0.2.10"
  }
}
```

This is a schema example, not a usable provisioned profile. Secret/certificate
input paths are chosen through the trusted future installer; never put their
contents on the command line. Different server certificate/key/endpoint for
the same identity requires explicit replacement, not ordinary reimport.

Pause stops scheduling; an already running bounded cycle finishes before its
spool closes. Explicit purge requires pause and acquisition of the existing
spool single-writer lock; it cannot delete a currently active profile.
Ordinary pause/reinstall preserves unresolved spool. Purge does not revoke
the server identity. Profile operations do not touch other profiles.

## Verification

`python tests/remote-production/test_foundations.py` runs actual TLS, isolated
profile, bounded scheduler and spool-to-P6B integration tests. On Windows it
also runs real DACL/junction/SCM-console refusal tests. Unsupported native
assertions are not counted as passed on Linux.

The dedicated CI workflow additionally runs
`python tests/remote-production/test_service_scm.py` on elevated Windows:
register/start/pause/continue/stop/delete one random `P6B2Fixture*` service.
It does not touch an installed product service, and does not skip missing
Windows/elevation. Fixture TLS certificates/keys, services and vaults are
temporary. Nothing activates public ingress or contacts a real VPS.

P6A's existing POST-boundary gate now enumerates both reviewed transport call
sites and verifies both use POST/self.path and the shared frozen URL validator;
it still excludes every other POST/Mihomo mutation surface.

## Second slice: server lifecycle

The existing privileged socket now accepts `probe.enroll`, `probe.revoke` and
`probe.list`. No browser route, ZIP or credential export is added. The daemon
forwards only bounded non-secret metadata, never returns/caches a probe key,
and bypasses its replay cache for every lifecycle acknowledgement. Enrollment
and Client deletion share the canonical config.lock; the worker obtains the
current Client credential digest internally, so the browser cannot choose a
Client generation or server trust authority.

The root-only `/var/lib/sbox-cm/p6/devices.json` desired-state ledger retains
at most 4096 device records/tombstones and is capped at 4 MiB. It contains the
independent random 256-bit keys needed for recovery and later sensitive export;
it is root:root 0600 inside a real 0700 directory. Keys published for Monitor
are root:sboxweb 0640. Identity slots use Client name + current credential
digest + device. Recreated Client accounts have new generations; old deletion
retries cannot revoke their new profiles. Same enrollment key retries restore
the original identity/key, changed semantics conflict, a second enrollment key
cannot silently replace a device slot, and revoked enrollment retries remain
revoked. Tombstones are never evicted to admit new devices. The existing
64-identity registry limit includes manually configured identities.

Enrollment requires pre-existing root-owned `p6-server.json` (0600) and
`p6-server.pem` (root:sboxweb 0640). The binding JSON has exactly v=1,
server_id, ingest_url and certificate_sha256. Certificate DER pin, IP SAN and
validity are checked; the endpoint must be HTTPS/IP/high-port/exact ingest.
Missing or changed binding fails closed. Creating/rotating that authority is
the later ingress installer slice; this slice generates no TLS private key or
public ingress. Revocation remains available if a binding certificate expires.

Desired intent is durable before any key/config publication. One root worker
lock orders mutations. Monitor takes a shared lock on `remote-probes.json.lock`
and reloads authority for the entire authentication-to-commit operation. The
root writer takes that lock exclusively to drain prior authenticated requests
and publish the new registry. Lock release is the revocation boundary: earlier
ingest may complete; later ingest reloads and refuses the old key. Lock waits
are bounded and filesystem authority errors fail closed. Read/status primitives
also reload mapping authority, preserving retired-history truthfulness.

Publication alone is not success. A fresh HMAC request with the intentionally
invalid evidence body `{}` goes through the shipped loopback Monitor handler:
active-key `400 invalid_body` proves the authentication path succeeded;
retired-key `401 unauthorized` proves it failed. No receipt/run/sample is
created. Timeout/rate-limit/unexpected response keeps `verified=pending` and
reports failure; retry reconciles the same durable intent. No new endpoint,
framing exception or authentication bypass exists. Receipt/sample/run history
is never provisioning cleanup. Manually managed registry rows/keys survive.
`verified_epoch` records the last confirmation; listing stored lifecycle state
does not claim ongoing health. List responses contain at most 64 rows plus an
explicit next cursor, preserving the existing 64-KiB RPC frame limit after
retirement tombstones accumulate. Changed owned registry rows fail closed;
ordinary enrollment cannot silently reactivate an operator-disabled identity.
Retirement confirms at most 64 pending records per attempt and checkpoints the
batch once. Larger accumulated pending sets report E_P6_CONFIRM_PENDING and
resume on retry without resetting already confirmed tombstones. A repeated
fully confirmed retirement checks one representative again; historical
confirmation times for the other immutable tombstones remain explicit.

Delete Client first retires probes of that exact Client generation. A failed
P6 confirmation preserves the proxy account and reports E_P6_REVOKE_PENDING;
the same deletion key may retry. If P6 retirement succeeds and proxy deletion
subsequently fails, probes stay revoked and the existing Client engine recovers
the proxy transaction. This is an explicit sequence of durable operations.

The helper's systemd sandbox additionally allows AF_INET **only to localhost**
for the authentication proof, write access to the existing Monitor config
directory, and CAP_CHOWN to publish root:sboxweb files. Its listener remains
AF_UNIX only; the web process gains no new filesystem authority. Deployment
copies the lifecycle worker but does not create enrollment/binding/ingress or
enable a service. Linux fixtures exercise actual native ownership/flock and
the real Client worker on every supported Ubuntu baseline.
The same suite also publishes and authenticates from a real transient systemd
unit using the shipped sandbox properties, rather than a text-only unit check.

## Third slice: VPS identity and dedicated ingress installer

The human reviewer passed the server/helper slice at `6693dda…`. Identity now
precedes sensitive bundle/UI. The installed root helper includes
`p6_ingress.py`; the explicit entry is
`bash sbox-cm/deploy/install-p6-ingress.sh prepare IP [HIGH_PORT] [nft|none]`.
It requires the installed reviewed helper and native nginx >=1.18.0 with TLS,
OpenSSL, systemd and (for the default nft backend) nftables. It never installs
packages, changes a cloud Security Group or downloads privileged code.

`prepare` generates a root-only durable authority directory, random server_id,
RSA-3072 key and 3650-day self-signed certificate with IP SAN/serverAuth. It
publishes the existing provisioning JSON/public cert shape. Private key remains
root:root 0600 in a 0700 directory. Public cert is root:sboxweb 0640. Complete
authority publication is an atomic directory rename/fsync; interrupted public
copies resume from that authority, not a new identity. Reinstall must retain
the exact identity/key/cert/endpoint. Changed settings, expired/mismatched trust,
operator-provided bindings, unsafe files and edited managed files fail closed.
Explicit certificate/endpoint replacement is a later operator workflow, never
an implicit ordinary reinstall or a bypass of enrolled profiles' binding.

Preparation validates an independent full nginx configuration and dedicated
`sbox-p6-ingress.service`. It opens no listener/firewall and does not enable
anything. `activate` and `deactivate` are separate explicit commands. They
operate only this unit and its journaled firewall table, never `nginx.service`,
global nginx configuration, ports 80/443/9191 or Monitor's loopback bind.
The exact raw POST route requires client HTTP/1.1, explicit CL and no TE before
buffering; wrong methods/paths/queries/encoded aliases stay local. Body bytes
and all five signature headers are forwarded untouched. Fixed bounded peer +
aggregate request/connection limits, TLS/header/body/upstream deadlines, worker,
FD/task/memory/CPU caps contain unauthenticated work. Runtime access/error logs
are suppressed to avoid credential/header disclosure.

Activation journals intent, validates native nginx/systemd, checks the port,
creates only its owned firewall rule, enables/starts its dedicated unit and
proves local pinned TLS + local 404. Interrupted starts reconcile closed;
failures disable/stop this unit and remove only its verified table. Identity,
registry, credentials and remote history remain. A changed table stays intact
and reports failure rather than being deleted. The dedicated nft pre-start
restores the journaled rule after reboot; the privileged root pre-start has
firewall authority, while nginx workers have no CAP_NET_ADMIN. It is separate
from the existing loopback-only Client helper sandbox.

An nft accept in a separate base chain cannot override a drop in another
chain. The response therefore says `external_reachability=unverified`. Existing
UFW/nft policy and cloud Security Groups need actual host/external validation;
this foundation does not claim that a managed accept proves the port open.
`none` is an explicit operator-owned firewall mode. No global flush or automatic
weakening of another firewall is supported.

The main `install.sh` CLI now invokes the same retirement worker under the
canonical Client lock, with the internally derived exact credential generation,
before creating/committing a delete candidate. An unconfirmed live revocation
preserves Client/derived files and permits retry. No-P6 deletion keeps its
original behavior. This closes the previously documented CLI deletion residual.

The new native Linux suite uses temporary loopback TLS, real nginx runtime,
random real systemd services, actual process death and isolated network
namespaces for nft rules. A separate actual Monitor process with 64 configured
identities receives malicious missing-auth/wrong-HMAC burst traffic through
TLS nginx. Native /proc CPU/RSS, outcomes and concurrent session-route latency
are emitted as a reproducible `P6_INGRESS_LOAD_RECEIPT`. This verifies server
fixture containment/responsiveness, not real Windows/Clash/TUN measurements.

## Fourth slice: sensitive Client Bundle and Download UI

The Client page keeps the existing YAML Download intact and adds a separate
Devices / Bundle panel for named Clients. Enroll each device independently;
only an active, live-confirmed enrollment offers Download Client Bundle.
Stored confirmation describes enrollment/revocation, not current probe health.
Browser revocation requires the selected row's probe_id; root checks the
Client/device/identity tuple and retires exactly that record. Old rows cannot
accidentally retire a same-device identity in a rebuilt Client generation.
Existing internal generation-wide Client retirement keeps its original scope.
Revocation requires step-up and a fresh live proof. Pending enrollment offers
Verify again after a page reload: `probe.resume` recovers only the existing
current-generation record/key/labels, never creates or resurrects an identity.
An uncertain in-page enrollment retains its exact key for explicit retry;
the browser stores neither this intent nor credential material persistently.

The five POST-only routes are `/api/v1/clients/probes/{list,enroll,revoke,resume}`
and `/api/v1/clients/bundle`. All require session, same-origin and CSRF checks;
all except the metadata list additionally require the existing password step-up.
They also require the fresh management gate. Browser-selected generation,
endpoint, paths, certificate and keys are refused. Errors and lifecycle JSON
contain only closed metadata; arbitrary helper fields are never forwarded.

`client.bundle` and `probe.resume` bring the fixed RPC surface to twelve ops.
The existing 64-KiB frame limit is unchanged. The root worker holds the canonical
Client lock while deriving the current credential generation and rendering
the canonical Mihomo YAML. Under the provisioning lock it verifies current
binding, owned registry row, original key and live HMAC authentication before
returning bounded typed parts. Export changes no enrollment state, does not
repair missing keys and never rotates them. Both new ops bypass daemon replay;
every delivery requires a durable secret-free audit before parts reach stdout.
The key/YAML travel only through memory and pipes, never argv/env/audit/cache.

Generic source is independently built into a deterministic `.pyz` containing
the reviewed Agent modules and the unchanged Mihomo client/model. The installed
public artifact is `/usr/local/share/sbox-p6-artifact/{p6-agent.pyz,artifact.json}`:
real root-owned ancestors, root:root 0755 directory, no-follow/same-object
root:root 0644 single-link files, maximum 4 MiB, version derived from SHA-256.
Both helper and web revalidate the artifact. A mismatched two-file upgrade
refuses export. The digest authenticates this protected installed build; it
does not claim publisher signing for a Windows executable.

After auth and artifact checks, the web assembles one transient ZIP response
from typed parts plus generic bytes; no large binary crosses RPC and no ZIP is
persisted on the server. YAML is capped at 32 KiB, the full serialized worker
response at 64512 bytes, the ZIP at 5 MiB, active downloads at two, and response
writes at a ten-second socket timeout. Capacity failures refuse rather than
truncate. The root manifest and web generic hash must match during upgrades.
The download has no-store, nosniff and fixed safe filenames. Browser delivery
uses a Blob only, then releases its object URL and temporary anchor.

Each ZIP contains exactly the canonical `<client>-mihomo.yaml`, `profile.json`,
separate `ingest.key`, public `server.pem`, `agent/p6-agent.pyz`,
`agent/artifact.json`, `bundle.json` and `README.txt`. No server private TLS key,
other device key, controller credential or prebuilt credential cache is added.
Repeated download of an unchanged enrollment/build has identical bytes.

**This slice supplies a source foundation, not a Windows one-click installer.**
The generic zipapp requires Python 3.10+. The page and README say Windows setup
is unavailable. They do not imply successful service installation or rollout.
The generated profile uses canonical Reality/Hysteria2 node names and loopback
controller defaults; later Windows installation must validate the actual
controller/credentials/nodes before enabling this profile. Server packaging
remains independent of client-only Mihomo imports. Signed Windows packaging,
installer/uninstaller and real host acceptance remain mandatory before P6B2
completion. No production listener/service activation is performed here.

Acceptance uses eleven portable real-artifact/profile-import cases, twenty-one
native root worker/RPC/HTTP/audit/recovery cases, and fourteen new shipped-JS
UI cases (104 total, including the previous 90). Existing cross-platform and
native provisioning CI entrypoints run the corresponding bundle suite as a
second explicit process and retain separate original test counts.

## Following slices — still required

- actual VPS host/firewall/cloud-policy reachability acceptance and explicit
  replacement/retrusted-bundle operator workflow for IP/expiry/compromise;
- local controller discovery/explicit binding and credential setup, signed
  Windows packaging, autostart/failure-recovery installer and uninstaller;
- real Windows + Clash/TUN + VPS installation/reboot/offline/revocation/purge
  acceptance and measured CPU/RAM/network/Clash-delay thresholds.

Slice tests are not a production resource benchmark, real-user reboot
test or independent review pass. Monitor stays 0.7.0 in this slice. History,
classifier, P5 response shapes and completed P6B storage semantics are unchanged.
P6B2 implementation is incomplete; merge, production deployment, public
activation, real client rollout, P6C and P6D are not authorized.
## Windows installer / uninstaller checkpoint

Bundle / Download UI received human independent PASS at
`4e1ad2a89311f8326165ddf926929a525928cffc`. This slice stays on Draft PR #70;
no release bump, production deployment, public ingress or P6C/P6D is authorized.

The Windows release is a **generic, separate** package, not another per-client
executable or a larger privileged export. The sensitive eight-member Client
Bundle and canonical YAML stay unchanged. Existing source Bundle UI remains
truthful until installer review and real client acceptance are complete.

- Build with `tools/build-p6-windows.py` using the fixed
  [CPython 3.13.16 x64 embeddable archive](https://www.python.org/downloads/release/python-31316/)
  (SHA-256 `97dae5274cc54867065e8d5a3226e48c35017ed332a0fdb0e27d5b5821961297`).
  No pip, system Python, user-site or environment import dependency. The
  explicit `_pth` admits only bundled stdlib/runtime/Agent/installer.
- This builder emits **unsigned staging**, not a publishable release. Supply
  an actual publisher certificate thumbprint, then use `windows/Sign-Package.ps1`
  on the signing host. It requires private key in the certificate store,
  SHA-256 signatures and timestamp verification. The operator currently has no
  production certificate; production signing remains a release blocker.
- Both signed `Setup.ps1` and signed payload catalog must validate under native
  Windows trust and the exact compiled publisher thumbprint. The catalog checks
  all payload files; per-file hashes/size/release digest and ACL checks repeat
  after protected copying. No unsigned mode, downloaded runtime at installation,
  trust-on-first-use or machine-wide server certificate installation.
  [Microsoft catalog validation](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/test-filecatalog)
  and [Authenticode signing](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature)
  are separate checks; SHA-256 alone is not publisher authentication.
- Run the signed setup elevated on Windows 10/11 x64. `install` stages the
  runtime under native ProgramData/P6RemoteProbe, configures LocalSystem SCM
  auto-start with protected service ACL and three delayed failure restarts,
  then NONE until the one-day reset. Service has no interactive UI.
- `install -Bundle <zip>` or subsequent `import -Bundle <zip>` validates the
  exact bounded members without extracting/executing bundle code. It verifies
  actual loopback `/version` and `/proxies`, explicit configured nodes/group,
  and controller authentication before enabling. Import YAML into the existing
  Clash client separately; the installer never changes/restarts Mihomo.
- For authenticated local controller, supply `-ControllerKeyFile` naming an
  already native-protected credential file, or use `-PromptControllerSecret`
  for secure installer-only input and temporary protected credential staging.
  The value is never an argument,
  URL, environment variable or diagnostic. Controller and P6 credentials are
  separate; local credential is published atomically with a new profile.
- `pause/resume/remove/purge -Profile <64-character profile id>` acts on exactly
  that profile. Operations serialize, drain the verified managed service and
  acquire its runtime lease. Resume revalidates the current controller. Remove
  archives disabled config/secret/spool; it does **not** imply server revocation.
  Revoke server probe separately through Monitor. Purge is explicit destruction
  of selected retired state. Live + retained profile capacity is eight.
- Reinstall retains identity, secrets, local credentials, control state and
  pending spool. Durable old/new release intent permits recovery; explicit
  `rollback` recovers the previous signed release after failed startup. A
  mismatched/foreign service or unsafe protected object fails closed.
- `uninstall` requires zero live profiles, deletes only the managed SCM service
  and generic installed binaries, and preserves retired state. Subsequent
  explicit purge can remove a selected retained profile. Cleanup checks every
  owned object and stays within the verified product directory.

Native CI builds and signs a **scoped test package** with a temporary signing
certificate (CurrentUser private key, isolated CI LocalMachine public trust;
both explicitly cleaned) and random fixture service/path. Only the builder's test
constructor can compile this name; no CLI root/service/publisher override or
unsigned operational bypass exists. Fixtures remove their own certificate,
service and state. This evidence is not production signing or real rollout.

Remaining whole-P6B2 requirements: production signing certificate/release,
friendly final bundle/setup distribution integration, actual Windows 10/11 +
Clash/TUN + VPS install/offline replay/reboot/routing/resource acceptance. Draft
installer implementation/CI cannot claim any of these as PASS.

## Test-host Bundle repair and Chinese display

Actual test-VPS download failed because the generic artifact was installed below
`/usr/local/lib/sbox-cm` mode 0700; a root-only fixture could read it while the
Monitor user could not. Generic code now lives at the fixed public read-only
`/usr/local/share/sbox-p6-artifact`, root:root 0755, with the same root:root 0644
single-link, no-follow and digest-verified files. Protected ancestors must also
be world-traversable. The privileged helper and all credentials remain in their
existing protected locations. Updating both helper and Monitor is required;
mixed old/new readers fail closed. This repair does not rotate enrollments,
server identity, trust, secrets or pending evidence. Uninstall removes only the
two known generic files and preserves any foreign file and runtime state.

The shipped Web now displays Chinese navigation, controls, warnings, status and
existing incident explanations. English server display sentences are translated
only at rendering; closed API enums, identity/protocol names, raw evidence tokens,
request bodies and backend judgments remain unchanged. Unknown future display
copy stays verbatim. This is localization of existing P5 UI, not P6C presentation.
The signed Windows release remains unavailable; the page says so explicitly.

Repair verification adds actual unprivileged reads after the actual installer
under a private umask with a 0700 helper, generic uninstall/state preservation,
and root-validator refusal of a private ancestor. Native Bundle tests are now
23; shipped UI checks are 108. Prior independent PASS applies to its reviewed
head only; this repair awaits independent review and actual test-VPS readback.
PR #70 stays Draft; no merge, production deployment or P6C/P6D.

## Graphical Windows manager and scoped controller discovery

The unsigned Windows staging builder now requires the native Windows x64 .NET
compiler and emits `P6Setup.exe` alongside signed `Setup.ps1`, `payload.cat` and
the bounded payload. The executable requests normal administrator consent and
hosts build-embedded authenticated GUI/setup code on an STA runspace and opens
a Chinese graphical manager without a console or script-policy override. It does
not execute downloaded script code; the native Windows PowerShell assembly comes
from the fixed machine GAC. Trusted distribution and
external publisher verification remain entry requirements. All three entry
objects must have native Valid signatures from the compiled publisher; the
production signer requires timestamps for all three. No production signing
certificate is available yet, so this is not a publishable Windows release.

The manager selects a separate sensitive Bundle and exposes explicit install /
update, import, rollback, per-profile pause/resume/removal, retired-data purge,
and zero-live-profile uninstall. Remove retains local credentials/queues and
does not revoke the VPS identity; purge has separate irreversible confirmation.
Closing the manager leaves the background service running. Legacy signed
three-member packages are recognized only with their original closed manifest;
the new gui-v1 manifest requires its signed executable. Upgrade/rollback keeps
the original profile and spool semantics.

Refresh uses a separate read-only snapshot, not the legacy installer status
operation that can recover durable intent. It never creates installation state,
executes recovery, controls the service, opens a spool writer or reads credential
files. Exact native object checks permit read sharing with append/atomic replace.
Display contains selected closed local metrics and counters only; the unresolved
record span is not an exact pending count, and a local sample is not proof of a
particular server receipt. Pending upgrade/uninstall requires explicit recovery.

Automatic discovery supports only the current administrator user's native
RoamingAppData Clash Verge Rev `clash-verge.yaml`. The reader is bounded to
256 KiB with same-object owner/DACL/single-link/reparse checks, using a separate
current-user source policy that never widens the installed vault policy. Only
unambiguous top-level controller/secret scalars are recognized. Address and port
must match the existing immutable Bundle controller; existing real GET-only
authentication and explicit node/group verification still run. No scanning other
users, config edits, API enablement, restarts or implicit profile rewrites.
Unsupported/ambiguous sources get a Chinese explanation and masked one-time
credential fallback. Credential bytes never enter argv/env/output/evidence and
temporary fallback staging keeps SYSTEM/Administrators authority.

Real GUI/operator acceptance, offline/reboot/TUN/multiple-profile/resource
benchmarks, production signing/distribution and independent review remain
pending. Existing running lab service is unchanged while this slice is built.
PR #70 stays Draft; no merge, production deployment, P6C or P6D.

## Signed Windows software distribution (separate from device Bundle)

The ordinary device action is now one Windows client package containing
the unchanged signed software, device-bundle.zip, the canonical Mihomo YAML
and Chinese README-client.txt. Extract it and run P6Setup.exe: a sole valid
adjacent device configuration is preselected for an explicit install action.
Separate software/configuration downloads remain advanced compatible actions. The software
archive contains only signed entry files/catalog and the bounded runtime/Agent/
installer inventory. It contains no device/YAML/profile/P6 secret. Closing the
manager leaves the Agent service running.

The native Windows build host exports an already signed protected package:

```powershell
python tools/export-p6-windows.py --package <protected-signed-package> --publisher <expected-thumbprint> --output <protected-export>
```

Production export requires native Valid signatures for PE/Setup/catalog,
Test-FileCatalog, exact compiled publisher binding and timestamps on all three
signatures. Explicit `--lab` labels a previously signed controlled test package;
it creates/imports no signing key or trust and is not production signing.
The exporter reports the manifest SHA-256, publisher and scope for the operator.
The staging builder alone produces unsigned output and cannot pass this gate.

After securely transferring the two exported files to root-owned regular 0644
files, the root operator publishes with independently expected values:

```bash
python3 -I /usr/local/lib/sbox-cm/publish-p6-windows.py publish --package /root/p6-export/windows-installer.zip --manifest /root/p6-export/release.json --manifest-sha256 <exported-manifest-sha256> --publisher <expected-thumbprint> --scope production
```

Use explicit `--scope lab` only for the controlled acceptance export. Linux
checks operator-provided expected hash/publisher/scope, closed inventory, exact
file hashes and current generic Agent compatibility; it does not perform or
claim native Authenticode validation. The expected manifest is admission
authority, not an untrusted uploaded manifest declaring itself signed. Windows
retains its native signature/catalog/compiled publisher gates on installation.
No implicit signer/scope replacement or unsigned fallback exists.

A disposable lab signer may change between acceptance builds. Root can explicitly
use `replace-lab-publisher` with the new package, independently expected new
manifest digest/publisher, plus `--from-publisher <old-thumbprint>` and
`--from-archive <old-archive-sha256>`. This operation only accepts lab-to-lab.
Under the existing publication flock it validates the exact selected old package
and retained inventory, admits the new package through the unchanged gates and
atomically replaces current.json. It retains the old archive and never clears
the selection, evicts versions, imports trust or restarts services. Retry after
commit requires the exact new selection and the validated old archive still
retained. Stale old selection, a third retained version, tamper or any production
scope fails closed. This is a controlled acceptance tool, not production signer
rotation or automatic release fetching.


The fixed public root `/usr/local/share/sbox-p6-windows` holds immutable version
directories and an atomic `current.json`, all root:root, directories 0755, files
0644, single-link/no-follow/same-object checks. Each archive is <=64 MiB; at most
two retained versions plus one staging copy bound archive bytes to 192 MiB,
with <=97 KiB bounded manifest/pointer metadata and an empty private lock file.
Publication is serialized with flock/fsync, never auto-evicts, and supports
idempotent retry. Explicit `retire --archive <inactive-sha256>` refuses current
and foreign files. An interrupted `.stage-<32hex>` stops new publication until
explicit `discard-stage --stage <32hex>` removes only its checked managed files.
Ordinary helper/Monitor reinstall preserves published packages and identities.

The exact POST `/api/v1/clients/windows` accepts only `{}`, behind existing peer
whitelist/origin/password-verified session/CSRF plus fresh management authorization.
The single-login policy supersedes the old separate step-up grant. It
never calls credential export RPC. Software and device Bundles share two
download slots. The archive is checked before headers and streamed in 64 KiB
chunks from the held root file with socket/total deadlines and no-store headers.
Missing/corrupt/incompatible software returns `E_P6_WINDOWS_UNAVAILABLE`; lab
scope is labeled in the filename, response and Chinese instructions. The public
nginx ingress still exposes only the existing machine ingest route.

Production signer and actual signed GUI delivery/test-VPS publication remain
pending. A server code update does not manufacture a signed EXE. PR #70 remains
Draft; no merge, production deployment, P6C/P6D or whole P6B2 PASS is claimed.


### P6B2 field repair boundary — HTTPS target and local storage diagnostics (2026-10-03)

The human authorized continuing field repairs after the real offline/reconnect
screenshots. This narrow amendment supersedes the earlier blanket P6A source
zero-diff restriction only for the following two compatibility hooks: the base
collector may dispatch its HTTPS slot through an overridable method whose base
behavior remains exactly GET / + HTTP 200; the shared HTTPS primitive may accept
one explicit expected status (200 or 204, never arbitrary 2xx). Existing P6A
defaults/tests, TLS validation, deadlines/response bounds, wire payload/HMAC,
sample meaning, server store/retention/History/classifier remain unchanged.

Production HTTPS for the already generated https_host=www.gstatic.com is fixed
to https://www.gstatic.com/generate_204, exact HTTP 204 success. The hostname
and immutable profile bytes/identity/keys stay unchanged; path/status are
compiled production policy, not user/body input. Other previously supported
HTTPS hosts retain / + 200 semantics. No redirects, proxy fallback, arbitrary
URL/status, certificate weakening or reserialization of queued records.
A bounded normal-TLS foreground request on this PC returned 204 with zero body
bytes; it is not a LocalSystem/TUN acceptance proof. Reference: Chromium's
reviewed generate_204 connectivity endpoint history:
https://chromium.googlesource.com/chromium/src/+/0307e728703a96f6c86b35e705937e85821cde0d

Keep P6A spool.py byte-identical. A production-only Spool subclass may retry
Windows sharing/lock violations (native codes 32/33) at most twice with 20/50ms
delays. No retries for permission, disk, fsync, schema or unknown failure; no
deletion, DACL weakening, cursor reset or acknowledgment before durable retry
accounting. Preserve inherited hard/soft failure and rollback semantics.
Add optional bounded local-only diagnostics to spool state: last closed failure
class and cumulative sharing retry count, no raw errors/paths/keys/bodies.
Persist diagnostics on the next successful state write; permanent storage
failure cannot be claimed durably recorded. Legacy state without diagnostics
remains supported; historical failures retain their count and unknown cause.
This is robustness plus diagnosis, not proof that sharing caused the field
state_save_failures=1. Include actual native Windows held-file/read-sharing tests.

Windows read-only snapshot may expose those closed diagnostics plus existing
egress error_code/latency only; never the egress IP/body. Explain 15-second status
refresh versus configured collection cadence in the UI, and that refreshing
does not initiate sampling/upload. Keep snapshot mutation-free. No endpoint
replacement/proxying to force egress green; exact field egress cause remains
pending. No new enrollment/profile mutation/SCM change/signing trust or test
deployment in this source repair. Batch a new signed lab build only after tests.
PR #70 remains Draft; whole COMPLETE/final review/MERGE/production deploy/P6C/P6D
remain NO. Reboot/TUN/multi-profile/resource/retirement acceptance still pending.


### Field repair native replacement refinement (2026-10-03)

Actual isolated native Windows tests on this PC reproduced os.replace /
MoveFileExW failure (native 5) while a target reader had FILE_SHARE_READ |
FILE_SHARE_WRITE | FILE_SHARE_DELETE. ReplaceFileW with flags=0 succeeded
under the same shared reader, and refused an exclusive reader with native 32.
This establishes a concurrency defect compatible with the GUI workload, not
proof of the one historical field failure's cause.

The production-only state persistence adapter therefore uses the existing
canonical-size/open_restricted/complete-write/fsync-before-publication sequence,
then ReplaceFileW(flags=0, no backup, no IGNORE_ACL/MERGE_ERRORS flags) for an
existing regular non-link target. Initial absent target keeps os.replace.
Validate source/target components and regular objects before publication.
Never delete an existing target or fall back to overwrite on refusal. Only
native 32/33 get the already bounded two retries; native 5 remains a refusal.
Preserve target ACL, inherited hard retry rollback/soft failure counting, exact
queued bodies and the P6A spool source. Do not claim stronger power-loss metadata
durability than the existing Windows fsync/publication contract. Require native
shared-reader success, locked-reader refusal/recovery, transient-lock success,
old/new cursor readability, retained DACL, and permission/fsync refusal tests.
Microsoft API reference:
https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-replacefilew


### User-directed IPLark and current public-IP display amendment (2026-10-04)

Issue #67's user-directed amendment supersedes the earlier no-IP display and
no-provider-replacement field boundaries for this narrow production repair.
Production observes the actual request egress using exactly
https://iplark.com/ipapi/public/ip. A current-PC normal-TLS foreground request
returned HTTP 200 text/plain containing a valid global IP; the response/IP was
not logged. This does not prove LocalSystem/TUN acceptance of the future build.
The homepage and richer IP database route returned 403 and are not scraped.

New exports use egress_host=iplark.com. Production also maps the legacy
api.ipify.org profile token to this compiled endpoint, preserving installed
immutable profile/identity/key bytes and all already queued bodies. Base/DARK
collection and other reviewed hosts retain their original behavior. The shared
egress primitive has an opt-in strict mode requiring the complete bounded answer
to be one canonical global IP. Reject oversized replies, JSON/HTML/multiple tokens,
private/reserved/multicast addresses, non-200/redirects and TLS/timeout failures.
Retain normal TLS, no redirect/proxy fallback, five-second slot, 4096-byte reply,
20-second cycle and 60-second default cadence. No arbitrary provider/UI URL input.

Use a distinct fixed egress.iplark.baseline.json (and bounded .tmp) per profile;
do not delete or compare the untagged legacy provider baseline. First IPLark
observation is change=unknown. Only a durably committed IPLark observation becomes
its next/restarted baseline. The existing protected profile removal/purge handles
this finite additional state under the same lock and object-authority checks.

Read-only Windows snapshot exposes only the validated current sample's egress_ip
on success, not a raw response/geo/risk record. GUI shows the IP with its sample
time. Failure displays not obtained and the existing closed error, never a stale
baseline as a current result. No secret/YAML/credential exposure or P6C UI work.
Real TLS/strict response/deadline, legacy compatibility and provider-baseline
restart/commit tests run on the existing Linux/Windows foundation entry. Local
status tests verify success display, failure clearing and no snapshot mutation.
New signed distribution/native service acceptance remains required before claiming
the installed service uses IPLark. PR remains Draft; whole COMPLETE, independent
final PASS, MERGE, production deploy, P6C/P6D remain NO.
