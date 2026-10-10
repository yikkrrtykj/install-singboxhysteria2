# Persistent receiver for the explicit quality trial

This replaces the need to keep the seven-day foreground pilot receiver alive.
It is a separate, explicitly installed service for a controlled receiver VPS,
not a Monitor component or acceptance of unattended client failover. #48 stays
open for real application, independent provider and capacity acceptance.

## First installation

Use Python 3.10+, OpenSSL and systemd 249+. Review the pinned source and run as
root on the chosen receiver host:

```sh
bash tools/quality-receiver/install.sh RECEIVER_NUMERIC_IP
```

The installer refuses existing code/state/unit names. It installs only the new
`singbox-quality-receiver.service`, renewal service and daily timer, checks TLS
and token readiness, and enables the new receiver for boot. It reserves port
8449; the old temporary pilot on 8448 is untouched. It does not change Monitor,
sing-box, firewall, Windows startup, Clash, TUN or system code-signing trust.
If activation fails, only the newly started receiver/timer are disabled and
protected files are retained. Do not delete or overwrite an unknown existing
installation to retry. Reachability from outside is verified separately before
migrating the client; local readiness does not prove an open firewall.

## Credentials and renewal

Root-only `/etc/singbox-quality-receiver` stores the authority private key,
server key, token, certificate and installation identity. The receiver runs as
DynamicUser with four read-only systemd credentials: configuration, authority
certificate, leaf certificate and leaf key. It never receives the authority key.
The service is read-only, has no capabilities, and has bounded CPU/tasks/memory.
Its existing sink limits remain two concurrent requests and 4 MiB/min admitted
payload; it stores no uploaded body. These limits are for this small controlled
trial, not a fleet capacity claim.

The private authority is valid for 3650 days. A 90-day server leaf is renewed by
a daily timer with up to one hour jitter when fewer than 20 days remain. Ordinary
renewal preserves the authority bytes, address, token, key and client pair. It
atomically publishes the validated leaf and restarts only this receiver. A durable
restart marker retries failed reloads without repeatedly rotating certificates.
An expired leaf can be renewed; an expired or replaced authority needs an explicit
new client pair. Renewal is serialised and rejects altered installation identity.
No certificate is installed into Windows system trust.

Only copy `receiver-info.json` and `receiver-ca.pem` to the existing private client
workspace. The info contains a token: do not paste or commit it. Never copy either
private key. Certificate validation uses this CA and the exact numeric endpoint.

## Migration of an existing daily bundle

Close the quality window normally first; leave the daily Clash profile loaded.
Run `tools/quality-receiver-update.py --bundle PRIVATE_BUNDLE_JSON --receiver-info
PRIVATE_RECEIVER_INFO_JSON --clash-home EXISTING_VERGE_HOME`. This is an explicit
one-time migration, not an automatic daemon operation.

The per-bundle lock refuses an active worker. The adapter checks the loaded profile
marker and confirms actual authenticated uploads to the new receiver through every
node-forced listener before saving any changes. Unconfirmed/slow uploads, a foreign
profile or an unreachable new port retain the old pair. Successful migration changes
only the private bundle CA, receiver parameters and matching CA digest. Original and
generated YAML, current Clash choices and Windows startup are preserved. A failed
save rolls back completed writes. A power loss during the multi-file update can
leave a rejected bundle; it must be repaired from its known pair, never silently
accepted. Reopen the existing entry; no YAML reimport or client reinstall is needed.

## Verification

`tests/test_quality_persistent.py` exercises actual OpenSSL/TLS issuance, renewal,
expired-leaf recovery, restart retry and stable client identity. The migration suite
covers confirmed-only update, active/foreign refusal and failed-save rollback.
`tests/quality-receiver-systemd-lab.py` is root-only on a disposable CI host: it
loads the actual restricted unit with DynamicUser/LoadCredential, validates TLS,
renews, restarts and validates with the original client pair. Never run that lab
on the deployed receiver. CI also runs the quality contracts on Python 3.10 on
Windows and Linux. Operator activation and external reachability remain separate
from those isolated checks.
