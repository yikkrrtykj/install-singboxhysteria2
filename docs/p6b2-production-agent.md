# P6B2 — production Agent / provisioning

Authoritative contract: [Issue #67 §22](https://github.com/yikkrrtykj/install-singboxhysteria2/issues/67).
Recorded and implementation authorized 2026-10-02. This document explains the
first reviewable code slice; it does not replace the issue body.

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

## Following slices — still required

- step-up/no-store/audited bundle download, immutable digest-verified generic
  artifacts, credentials excluded from replay/audit/cache/log/DOM;
- nginx/certificate/firewall install integration with port-conflict handling,
  existing config preservation and rollback; no automatic trust change on
  reinstall;
- local controller discovery/explicit binding and credential setup, signed
  Windows packaging, autostart/failure-recovery installer and uninstaller;
- real Windows + Clash/TUN + VPS installation/reboot/offline/revocation/purge
  acceptance and measured CPU/RAM/network/Clash-delay thresholds.

Slice tests are not a production resource benchmark, real-user reboot
test or independent review pass. Monitor stays 0.7.0 in this slice. History,
classifier, P5 response shapes and completed P6B storage semantics are unchanged.
P6B2 implementation is incomplete; merge, production deployment, public
activation, real client rollout, P6C and P6D are not authorized.
