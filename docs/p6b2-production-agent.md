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

## Following slices — still required

- privileged server enrollment/revocation with live-registry effectiveness,
  partial failure recovery and existing Client lifecycle integration;
- step-up/no-store/audited bundle download, immutable digest-verified generic
  artifacts, credentials excluded from replay/audit/cache/log/DOM;
- nginx/certificate/firewall install integration with port-conflict handling,
  existing config preservation and rollback; no automatic trust change on
  reinstall;
- local controller discovery/explicit binding and credential setup, signed
  Windows packaging, autostart/failure-recovery installer and uninstaller;
- real Windows + Clash/TUN + VPS installation/reboot/offline/revocation/purge
  acceptance and measured CPU/RAM/network/Clash-delay thresholds.

First-slice tests are not a production resource benchmark, real-user reboot
test or independent review pass. Monitor stays 0.7.0 in this slice. History,
classifier, P5 response shapes and completed P6B registry/store are unchanged.
P6B2 implementation is incomplete; merge, production deployment, public
activation, real client rollout, P6C and P6D are not authorized.
