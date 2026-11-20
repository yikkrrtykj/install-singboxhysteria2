# Competition-safe profile transform (HA-03 #91)

Code: `tools/mihomo-competition-ha-profile.py`
Contract suite: `tests/test-mihomo-competition-ha-profile.sh`
Consumes: the HA-02 delivery (`ha-delivery-*.json` + `<name>-ha.yaml`) and a
local pins file. Produces: `<name>-hac.yaml` + `ha-competition-<version>.json`
in a **separate** output directory.
Parents: [competition HA contract](mihomo-competition-ha-contract.md),
[acceptance contract](mihomo-competition-ha-acceptance.md),
[HA-02 batch delivery](mihomo-competition-ha-batch.md).

Status: **implementation + hermetic/core/LAB evidence; NOT runtime acceptance.**
The exact Clash Verge Rev/Mihomo combination, real HY2 TLS accept/reject on both
VPSes, Windows TUN/DNS/UDP/routing/binds, cache/exit/restore and application
attribution still require the operator's Windows test PC and authorized test
VPSes. Those rows are NOT RUN / BLOCKED, not PASS. Default OFF: this tool only
writes files; importing and activating a competition profile in Clash Verge Rev
is an explicit operator action. No daemon, GUI, web service or scheduled task is
added; Quality Failover stays opt-in and disabled.

## Why a second delivery instead of editing HA-02

The HA-02 profile is the canonical, credential-bearing dual-active delivery and
is also the input contract of the PR-48A parser. Rewriting it in place would
break byte identity, hashes and the rollback/audit trail. This tool therefore
reads HA-02 bytes, verifies the manifest hashes, applies exactly five
deterministic edits, and writes a new file per terminal. The HA-02 delivery and
its manifest are never modified or overwritten.

## The five edits (per terminal)

Input is the four-node HA-02 profile. Output differs only in:

1. `allow-lan: true` → `allow-lan: false`;
2. `bind-address: "*"` → `bind-address: "127.0.0.1"`;
3. `  listen: "0.0.0.0:53"` → `  listen: "127.0.0.1:53"`;
4. `Hysteria2`: `    skip-cert-verify: true` → `    skip-cert-verify: false`
   plus `    fingerprint: <SHA-256 DER pin of the terminal's primary VPS>`;
5. `Backup-Hysteria2`: same, with the terminal's **backup** VPS pin.

The physical mapping is read from the HA-02 manifest: for an A-first terminal
`Hysteria2` pins A and `Backup-Hysteria2` pins B; for B-first it is the reverse.
A node called `Reality` alone never decides which physical VPS is pinned.

Everything else — names, group order, probe URL/interval/timeout/`lazy`/
`expected-status`, HY2 hopping `ports`/`hop-interval`, credentials — stays
byte-identical. The competition artifact therefore has no LAN proxy listener,
no wildcard bind, loopback-only DNS and pinned HY2. If LAN proxy sharing is
genuinely needed it is a separate, explicitly approved change; it is not the
default and may not be enabled by editing this artifact.

The transformer refuses any input that does not match the expected shape
(missing/extra HY2 block, existing `fingerprint`, missing security lines, CRLF,
more or fewer than five edit points). `--check` re-derives these security
invariants from the YAML itself, so a modified profile cannot pass merely by
updating the manifest hashes.

## Pins file (trusted input)

A local, access-controlled JSON v2 file:

```json
{
  "schema": "mihomo-competition-ha-pins/2",
  "vps": {
    "A": {"fingerprint_sha256": "<64 lowercase/uppercase hex>",
           "not_before": "2026-05-01T00:00:00Z",
           "not_after": "2027-05-01T00:00:00Z",
           "source": "ssh-jq-hy2-in-2026-11-21"},
    "B": {"fingerprint_sha256": "<64 hex>",
           "not_before": "2026-05-01T00:00:00Z",
           "not_after": "2027-05-01T00:00:00Z",
           "source": "ssh-jq-hy2-in-2026-11-21"}
  }
}
```

- SHA-256 of the **DER** leaf certificate, exactly 64 hex characters; upper case
  is accepted and normalised to lower case in output.
- `not_before`/`not_after` must come from the **same certificate** and be UTC
  (`YYYY-MM-DDTHH:MM:SSZ`). `not_after` must be later than `not_before`;
  `not_before` may not be in the future (5-minute clock skew allowed).
- `source` names the trusted management channel and command used.
- A and B pins must be distinct; unknown keys, a missing VPS or field, a wrong
  schema, duplicate JSON keys, a non-hex/short fingerprint or a non-private file
  are refused.

### Obtaining the pin over the trusted SSH management channel

HY2 uses **UDP/QUIC**; ordinary `openssl s_client -connect` is TCP and cannot
retrieve the QUIC peer certificate. Read the certificate file referenced by the
actual server configuration over a known trusted SSH channel instead. This does
not read the private key and does not modify the server:

```bash
set -o pipefail
CONFIG=/root/sbox/sbconfig_server.json

# 1. Resolve exactly one readable regular certificate path; fail otherwise.
jq -er '.inbounds[] | select(.tag == "hy2-in") | .tls.certificate_path' \
  "$CONFIG" > /tmp/hy2-cert-path || { echo "REFUSE: hy2-in cert path missing" >&2; exit 1; }
[ "$(wc -l < /tmp/hy2-cert-path)" -eq 1 ] || { echo "REFUSE: cert path not unique" >&2; exit 1; }
CERT=$(cat /tmp/hy2-cert-path)
[ -n "$CERT" ] && [ -f "$CERT" ] && [ -r "$CERT" ] \
  || { echo "REFUSE: cert file missing/unreadable" >&2; exit 1; }

# 2. Validate the certificate, then derive pin + dates from the same file.
openssl x509 -in "$CERT" -noout -checkend 0 \
  || { echo "REFUSE: invalid/expired certificate" >&2; exit 1; }
FP=$(openssl x509 -in "$CERT" -outform DER | sha256sum | awk '{print $1}')
printf '%s' "$FP" | grep -Eq '^[0-9a-f]{64}$' \
  || { echo "REFUSE: DER SHA-256 failed" >&2; exit 1; }
NOT_BEFORE=$(openssl x509 -in "$CERT" -noout -startdate | cut -d= -f2)
NOT_AFTER=$(openssl x509 -in "$CERT" -noout -enddate | cut -d= -f2)
ISO_BEFORE=$(date -u -d "$NOT_BEFORE" +%Y-%m-%dT%H:%M:%SZ) \
  || { echo "REFUSE: notBefore parse failed" >&2; exit 1; }
ISO_AFTER=$(date -u -d "$NOT_AFTER" +%Y-%m-%dT%H:%M:%SZ) \
  || { echo "REFUSE: notAfter parse failed" >&2; exit 1; }
printf 'fingerprint=%s not_before=%s not_after=%s\n' "$FP" "$ISO_BEFORE" "$ISO_AFTER"
```

Run the same block on VPS A and VPS B through each trusted SSH channel and record
the three values. Never copy private keys off the server, never change the live
certificate for this step, and do not paste the certificate body or addresses
into the task/PR.

**Reading the on-disk certificate is not live TLS acceptance.** It only supplies
the pin and validity dates. The real acceptance still requires a fresh HY2
connection from the event client to prove the correct pin is accepted and a
wrong pin rejected (and the A/B primary/backup roles), on the authorized test
VPSes. LAB pin-semantics evidence is not a substitute.

## Validity control (because Mihomo leaf pinning does not check expiry)

Mihomo's hysteria2 `fingerprint` compares the leaf DER SHA-256; it does not
enforce the certificate's validity window. The tool therefore enforces the
documented control itself; this is **not** a claim that TLS validity is proven:

- generation refuses a pin whose `not_after` is not strictly later than
  `now + --min-validity-days` (default 7), whose `not_before` is in the future,
  or whose dates are inconsistent;
- `--require-valid-through <UTC time>` additionally requires `not_after` to
  cover the expected event end plus the safety margin; the requirement is
  recorded in the delivery manifest;
- `--check` re-validates the pins against the **recorded floor**: it uses
  `max(--min-validity-days, manifest.validity.min_validity_days)` and enforces
  the recorded `required_valid_through`, so a later check cannot silently lower
  the delivery-time validity requirement;
- a failed generation/check exits non-zero and prints a fixed code; the affected
  competition profile must not be used.

Run `--check` before every event day and after any renewal. If it fails, stop
using the affected competition profile (remove/deactivate it in Verge), fix the
pin/certificate and regenerate; do not bypass the check or enable
`skip-cert-verify: true`.

### Rotation and expiry disposition

1. Renew the certificate on the test VPS (production certificates are out of
   scope for HA-03).
2. Re-run the trusted SSH acquisition block; update the pins file with the new
   fingerprint, `not_before`, `not_after` and a new `source`.
3. Regenerate the competition delivery with the new version and the event-end
   `--require-valid-through`, then run `--check` and load-test with the pinned
   core.
4. Re-import the new `<name>-hac.yaml` manually; verify a fresh HY2 connection
   succeeds with the new pin and fails with the retired pin.
5. Test a failed rotation (wrong/missing new cert): the client must reject the
   affected node and fail over without weakening verification; record the
   observed behaviour, then restore the previous valid pair and re-check.
6. Keep the previous delivery for rollback, but a retired certificate/pin must
   be rejected after rollback unless the rollback target is a still-valid,
   explicitly approved configuration.

If the owner concludes this date/pin control cannot satisfy the frozen
acceptance contract, the alternative to evaluate on a disposable test VPS is a
trusted chain + name verification (no pin, no `skip-cert-verify`). That requires
its own approval; it is not the default, does not modify production
certificates, and an approved security exception is never counted as TLS PASS.

## Commands

```sh
# 0. private pins file (operator-owned, chmod 600 / private Windows ACL)
$EDITOR ~/ha/pins.json
chmod 600 ~/ha/pins.json

# 1. generate the competition delivery next to (NOT inside) the HA-02 delivery;
#    --require-valid-through covers the expected event end + safety margin
python3 tools/mihomo-competition-ha-profile.py \
  --delivery ~/ha/delivery \
  --pins ~/ha/pins.json \
  --output-dir ~/ha/competition \
  --config-version ha-2026-11-24-comp-r1 \
  --min-validity-days 7 \
  --require-valid-through 2026-11-25T00:00:00Z

# 2. preflight before each event day and after renewal (repeat until GREEN)
python3 tools/mihomo-competition-ha-profile.py \
  --delivery ~/ha/competition --pins ~/ha/pins.json --check

# 3. import one <name>-hac.yaml into Clash Verge Rev manually and verify it
#    (see docs/mihomo-competition-ha-windows-verification.md). No automatic
#    activation, upgrade or background process is performed.
```

Success prints:

```
ha-profile: OK
terminals: 30
version: ha-2026-11-24-comp-r1
manifest: ha-competition-ha-2026-11-24-comp-r1.json
```

`--check` prints `ha-profile: OK`, `terminals`, `pins: valid` and
`validity: A=<not_after> B=<not_after>`.

## Output manifest

`ha-competition-<version>.json` records: schema/tool/config version, the HA-02
source manifest name + schema + config version, A/B pins with
`not_before`/`not_after`/`source`, `min_validity_days`,
`required_valid_through`, `checked_utc`, the permission gate, and per terminal:
name, group, `primary_vps`, `backup_vps`, input/output file names and SHA-256
values, output bytes, and the exact primary/backup pins used. It also carries
the rollback file list (competition profiles + manifest). It contains no
addresses, UUIDs, passwords or profile bodies. Protect it like the delivery.

The manifest is a **local trusted record, not a cryptographic authenticity
claim**: anyone who can write it can recompute hashes. That is why `--check`
re-reads the actual YAML and enforces the security invariants and the recorded
validity floor instead of trusting stored hashes alone.

## Failure handling and rollback

Fixed codes on stderr, exit 1 (`E_USAGE` exits 2):

| Code | Meaning |
| --- | --- |
| `E_DELIVERY` | HA-02/competition manifest missing/ambiguous/duplicate-key/invalid names, counts, roles or file set |
| `E_DELIVERY_HASH` | an input or competition output no longer matches its recorded size/SHA-256 |
| `E_PINS` | pins file missing/symlink/reparse/duplicate-key/malformed/unknown keys/identical pins/future notBefore/invalid dates |
| `E_PINS_EXPIRED` | a pin expires inside the effective validity floor or does not reach `--require-valid-through` |
| `E_TRANSFORM` | input profile is not the expected HA-02 shape, or a competition YAML fails the security re-derivation (LAN/wildcard DNS/skip-cert/pin mismatch) |
| `E_OUTPUT_EXISTS` | target profile or manifest already exists (case-insensitive) |
| `E_PATH_CONFLICT` | missing/linked/junction input/output directory, output inside the HA-02 delivery, or unsafe local boundary |
| `E_INSECURE_PERMISSIONS` | POSIX mode/owner, Windows ACL allowlist, or private-boundary/temp-inheritance failure (per-file roles `input-manifest`, `input-profile`, `pins`, `manifest-file`, `output-file`, `delivery-input`, `output-dir`) |
| `E_IO` | write/verify failure |
| `E_USAGE` | bad arguments/version/required-valid-through |

All targets are prevalidated before any write; writes are atomic no-clobber;
every output and the manifest are read back, permission-checked and
hash-verified; on partial failure only files this run created are deleted after
re-checking their file identity and bytes (the same device/file-ID + hash rule
as HA-02). Nothing pre-existing is touched. `ROLLBACK removed=… skipped=…
complete=…` is printed on failure.

## What is verified, and what is not

Verified here (hermetic + pinned core + LAB):

- exact five-edit transform, input bytes unchanged, output/manifest hashes,
  A-first/B-first pin mapping, 1/2/16/30-terminal batches;
- pins v2 schema, notBefore/notAfter/floor/`--require-valid-through` and
  `--check` refusal paths, including attempts to lower the recorded floor;
- input/manifest/pins/output real permission, owner, reparse, size, count,
  canonical-name, casefold-duplicate and role checks in both generation and
  `--check`;
- security re-derivation from YAML: modified `allow-lan`/`bind-address`/DNS/
  `skip-cert-verify`/pin with re-hashed manifest is still refused;
- no-clobber, case collisions, path/permission failures, partial rollback;
- real Linux CI with the pinned Mihomo v1.19.31 core loading all 30 generated
  `-hac.yaml` profiles (`-t`); the Windows core loads the same shape;
- loopback LAB: correct leaf pin accepted (HTTP 200 through HY2), one-hex-digit
  wrong pin rejected. This is pin semantics only, not VPS identity acceptance.

**Not verified here (BLOCKED on operator resources):**

- Clash Verge Rev v2.5.10 + its bundled Mihomo v1.19.33 on the real Windows PC
  (installed version, on-disk core banner + SHA-256, provenance, anti-upgrade);
- real HY2 TLS accept/reject on VPS A and B, primary/backup roles,
  certificate renewal/rotation, failed-renewal recovery, expired/retired pin
  rejection and rollback;
- TUN/DNS/Fake-IP/IPv4/IPv6/UDP, Rule/Global/Direct effective paths, actual
  listener binds/auth, LAN/production/management access, effective-config
  cross-check against the imported YAML;
- selection-cache behaviour, manual-override preservation, abnormal close/
  restart, full profile/settings/selection/network restore;
- actual application path attribution and real application UDP; HA-04 owns the
  full failover/recovery measurements;
- real 10 s/application performance.

These rows stay NOT RUN / BLOCKED until the Windows test PC and both authorized
test VPSes are available; none may be replaced by a LAB or CI result.
