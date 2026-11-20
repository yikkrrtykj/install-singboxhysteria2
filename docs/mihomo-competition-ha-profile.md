# Competition-safe profile transform (HA-03 #91)

Code: `tools/mihomo-competition-ha-profile.py`
Contract suite: `tests/test-mihomo-competition-ha-profile.sh`
Consumes: the HA-02 delivery (`ha-delivery-*.json` + `<name>-ha.yaml`) and a
local pins file; `--check` additionally consumes the same trusted HA-02 delivery
as `--source-delivery` (to re-derive the expected bytes).
Produces: `<name>-hac.yaml` + `ha-competition-<version>.json`
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
Project deadline: the competition configuration delivery is due before
2026-11-26; that is a delivery deadline, not the event end and not Go-Live
approval. Certificate validity must cover the actual event end plus a margin.

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
more or fewer than five edit points). `--check` does not trust the YAML's
literal text: it requires the trusted HA-02 source delivery, verifies the
source-manifest SHA-256 recorded at generation time, re-runs the identical
five-edit transform from the source bytes and compares every competition file
byte-for-byte. A file set with an extra profile, a re-cased suffix
(`FOO-HAC.YAML`) or a casefold-duplicate name is refused before any comparison.
A literal-invariant checker is kept as defense-in-depth, but it only matches
exact lines: it cannot recognise equivalent YAML spellings or extra
listeners/keys, so it is not a YAML semantic proof and the byte comparison is
the authoritative preflight gate.

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
actual server configuration over a known trusted SSH channel instead. The block
below keeps everything in shell variables (no fixed `/tmp` file), stops on the
first failed command or pipeline, and derives the fingerprint and both dates
from the **same public certificate snapshot**. The private key is never opened
or copied, and the server is not modified:

```bash
set -euo pipefail
CONFIG=/root/sbox/sbconfig_server.json
refuse() { echo "REFUSE: $*" >&2; exit 1; }

# 1. Resolve exactly one certificate path string in memory.
CERT=$(jq -er '.inbounds[] | select(.tag == "hy2-in") | .tls.certificate_path' \
  "$CONFIG") || refuse "hy2-in certificate path missing/ambiguous"
case "$CERT" in
  "") refuse "empty certificate path" ;;
  *$'\n'*|*$'\r'*) refuse "certificate path is not a single string" ;;
esac
[ -f "$CERT" ] && [ -r "$CERT" ] \
  || refuse "certificate file missing/unreadable"

# 2. Read the public certificate once. The private key is never touched.
CERT_PEM=$(cat -- "$CERT") || refuse "certificate read failed"
printf '%s\n' "$CERT_PEM" | grep -q -- 'BEGIN CERTIFICATE' \
  || refuse "not a PEM certificate"

# 3. Validate and derive all three values from that same public snapshot.
printf '%s\n' "$CERT_PEM" | openssl x509 -noout -checkend 0 \
  || refuse "certificate invalid or already expired"
FP=$(printf '%s\n' "$CERT_PEM" | openssl x509 -outform DER \
  | sha256sum | awk '{print $1}') || refuse "DER SHA-256 failed"
printf '%s' "$FP" | grep -Eq '^[0-9a-f]{64}$' \
  || refuse "DER SHA-256 is not 64 lowercase hex"
NOT_BEFORE=$(printf '%s\n' "$CERT_PEM" | openssl x509 -noout -startdate \
  | cut -d= -f2) || refuse "notBefore extraction failed"
NOT_AFTER=$(printf '%s\n' "$CERT_PEM" | openssl x509 -noout -enddate \
  | cut -d= -f2) || refuse "notAfter extraction failed"
ISO_BEFORE=$(date -u -d "$NOT_BEFORE" +%Y-%m-%dT%H:%M:%SZ) \
  || refuse "notBefore parse failed"
ISO_AFTER=$(date -u -d "$NOT_AFTER" +%Y-%m-%dT%H:%M:%SZ) \
  || refuse "notAfter parse failed"
[ "$ISO_BEFORE" \< "$ISO_AFTER" ] \
  || refuse "notBefore is not before notAfter"
printf 'fingerprint=%s not_before=%s not_after=%s\n' \
  "$FP" "$ISO_BEFORE" "$ISO_AFTER"
```

Every assignment/pipeline has an explicit fail-stop (plain `pipefail` alone
does not stop `set -e` scripts). If `jq`, `openssl`, GNU `date -d` or
`sha256sum` is unavailable the block refuses; do not replace a derived value by
hand. Never echo `$CERT_PEM`, never read `tls.key_path`, never copy private keys
off the server, never change the live certificate for this step, and do not
paste the certificate body or addresses into the task/PR.

Run the same block on VPS A and VPS B through each trusted SSH channel and record
the three values in the private pins file (`source` can name the channel, host
alias and UTC time; no secrets).

**Reading the on-disk certificate is not live TLS acceptance.** It only supplies
the pin and validity dates. The real acceptance still requires a fresh HY2
connection from the event client to prove the correct pin is accepted and a
wrong pin rejected (and the A/B primary/backup roles), on the authorized test
VPSes. LAB pin-semantics evidence is not a substitute.

## Validity control (because Mihomo leaf pinning does not check expiry)

Mihomo's hysteria2 `fingerprint` compares the leaf DER SHA-256; it does not
enforce the certificate's validity window. A matching-pin certificate that has
expired may therefore still be accepted by the pinned core; the runbook records
that as the actual residual behaviour, never as an expiry rejection. The tool
therefore enforces the documented control itself; this is **not** a claim that
TLS validity is proven:

- generation refuses a pin whose `not_after` is not strictly later than
  `now + --min-validity-days` (default 7), whose `not_before` is in the future,
  or whose dates are inconsistent;
- `--require-valid-through <UTC time>` additionally requires `not_after` to
  cover the **actual competition end plus the safety margin**. It is not the
  network build/delivery date: the delivery deadline (before 2026-11-26) does
  not define the event end, so use the latest confirmed schedule and re-check
  if the schedule moves. The requirement is recorded in the delivery manifest;
- `--check` re-validates the pins against the **recorded floor**: it uses
  `max(--min-validity-days, manifest.validity.min_validity_days)` and enforces
  the recorded `required_valid_through`, so a later check cannot silently lower
  the delivery-time validity requirement; it also re-derives every output from
  the trusted HA-02 source bytes;
- a failed generation/check exits non-zero and prints a fixed code; the affected
  competition profile must not be used.

Run `--check` **before every event day** and after any renewal; if a check
fails, deactivate/remove the affected competition profile in Verge immediately,
fix the pin/certificate and regenerate. That mandatory preflight plus
deactivation is the validity control that covers the core's non-enforcement of
expiry; do not bypass the check or enable `skip-cert-verify: true`.

### Rotation and expiry disposition

1. Renew the certificate on the test VPS (production certificates are out of
   scope for HA-03).
2. Re-run the trusted SSH acquisition block; update the pins file with the new
   fingerprint, `not_before`, `not_after` and a new `source`.
3. Regenerate the competition delivery with the new version and the event-end
   `--require-valid-through`, then run `--check` (with `--source-delivery`) and
   load-test with the pinned core.
4. Re-import the new `<name>-hac.yaml` manually; verify a fresh HY2 connection
   succeeds with the new pin and fails with the retired pin.
5. Test a failed rotation (wrong/missing new cert): the client must reject the
   affected node and fail over without weakening verification; record the
   observed behaviour, then restore the previous valid pair and re-check.
6. Keep the previous delivery for a rollback **within competition mode**: restore
   a still-valid, explicitly approved competition delivery and verify a fresh
   connection; a retired certificate/pin stays rejected unless the rollback
   target itself is still valid. Restoring the legacy HA-02 profile
   (`skip-cert-verify: true`) is **not** a competition rollback: it exits
   competition mode and must be a separate explicit operator decision recorded
   in the runbook (TLS5), never counted as TLS recovery.

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

# 1. generate the competition delivery next to (NOT inside) the HA-02 delivery.
#    --config-version records the build revision, NOT the event end.
#    --require-valid-through must be the ACTUAL competition end (UTC) plus the
#    safety margin. The delivery deadline (before 2026-11-26) is not an event
#    end; take the confirmed schedule and re-check if it moves. Replace the
#    placeholder below - do not use the build date or an assumed Nov 25 value.
REQUIRED_THROUGH='<actual-event-end-UTC-plus-margin>'
python3 tools/mihomo-competition-ha-profile.py \
  --delivery ~/ha/delivery \
  --pins ~/ha/pins.json \
  --output-dir ~/ha/competition \
  --config-version ha-2026-11-21-comp-r1 \
  --min-validity-days 7 \
  --require-valid-through "$REQUIRED_THROUGH"

# 2. preflight before each event day and after renewal (repeat until GREEN).
#    --source-delivery is the trusted HA-02 delivery the competition files were
#    generated from; --check re-derives and compares every byte.
python3 tools/mihomo-competition-ha-profile.py \
  --delivery ~/ha/competition --source-delivery ~/ha/delivery \
  --pins ~/ha/pins.json --check

# 3. import one <name>-hac.yaml into Clash Verge Rev manually and verify it
#    (see docs/mihomo-competition-ha-windows-verification.md). No automatic
#    activation, upgrade or background process is performed.
```

Success prints:

```
ha-profile: OK
terminals: 30
version: ha-2026-11-21-comp-r1
manifest: ha-competition-ha-2026-11-21-comp-r1.json
```

`--check` prints `ha-profile: OK`, `terminals`, `pins: valid` and
`validity: A=<not_after> B=<not_after>`. It requires both the competition
delivery and the trusted HA-02 source delivery; keep both private and available.
If the source delivery changed (or was regenerated), `--check` refuses and the
competition delivery must be regenerated rather than repaired in place.

## Output manifest

`ha-competition-<version>.json` records: schema/tool/config version, the HA-02
source manifest name, its **SHA-256**, schema and config version, A/B pins with
`not_before`/`not_after`/`source`, `min_validity_days`,
`required_valid_through`, `checked_utc`, the permission gate, and per terminal:
name, group, `primary_vps`, `backup_vps`, input/output file names and SHA-256
values, output bytes, and the exact primary/backup pins used. It also carries
the rollback file list (competition profiles + manifest). It contains no
addresses, UUIDs, passwords or profile bodies. Protect it like the delivery.

The manifest is a **local trusted record, not a cryptographic authenticity
claim**: anyone who can write it can recompute hashes. `--check` therefore does
not trust the stored hashes alone: it re-reads the actual YAML files, requires
the recorded source-manifest SHA-256 to match the trusted HA-02 delivery you
pass as `--source-delivery`, re-derives the expected bytes from that source and
enforces the recorded validity floor. Rewriting the original HA-02 delivery,
the competition output and every recorded hash consistently is inside the
local-operator trust boundary and is not defended by this tool.

## Failure handling and rollback

Fixed codes on stderr, exit 1 (`E_USAGE` exits 2):

| Code | Meaning |
| --- | --- |
| `E_DELIVERY` | HA-02/competition manifest missing/ambiguous/duplicate-key/invalid names, counts, roles or file set; a different source delivery/manifest name; an exact-name or casefold duplicate in the delivered file set |
| `E_DELIVERY_HASH` | the HA-02 source manifest/profile or a competition output no longer matches its recorded size/SHA-256 (`role=source-manifest` for a different source manifest) |
| `E_PINS` | pins file missing/symlink/reparse/duplicate-key/malformed/unknown keys/identical pins/future notBefore/invalid dates |
| `E_PINS_EXPIRED` | a pin expires inside the effective validity floor or does not reach `--require-valid-through` |
| `E_TRANSFORM` | input profile is not the expected HA-02 shape, the competition output is not the byte-exact deterministic transform of the trusted source (including a re-hashed extra listener/key or equivalent YAML spelling), or the literal defense-in-depth invariants fail |
| `E_OUTPUT_EXISTS` | target profile or manifest already exists (case-insensitive) |
| `E_PATH_CONFLICT` | missing/linked/junction input/output directory, output inside the HA-02 delivery, unsafe local boundary, or a casefold-duplicate name in the output directory |
| `E_INSECURE_PERMISSIONS` | POSIX mode/owner, Windows ACL allowlist, or private-boundary/temp-inheritance failure (per-file roles `input-manifest`, `input-profile`, `pins`, `manifest-file`, `output-file`, `delivery-input`, `output-dir`) |
| `E_IO` | write/verify failure |
| `E_USAGE` | bad arguments/version/required-valid-through, `--check` without `--source-delivery`, or `--source-delivery` in generation mode |

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
- `--check` source binding: recorded HA-02 manifest SHA-256, terminal
  name/role/input relationship, and byte-for-byte equality with the transform
  re-derived from the trusted source; a tampered/wrong source delivery, an
  injected extra listener/controller key, an equivalent YAML spelling, a role
  swap and a swapped pin with a fully re-hashed manifest are all refused;
- file set: extra profile, re-cased suffix (`FOO-HAC.YAML`) and (POSIX) actual
  casefold-duplicate names are refused;
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
  rejection and rollback; the runbook records the actual matching-pin expired
  behaviour of the core rather than assuming rejection;
- TUN/DNS/Fake-IP/IPv4/IPv6/UDP, Rule/Global/Direct effective paths, actual
  listener binds/auth, LAN/production/management access, effective-config
  cross-check against the imported YAML;
- selection-cache behaviour, manual-override preservation, abnormal close/
  restart, full profile/settings/selection/network restore (the business-app
  recovery verdict belongs to HA-05);
- actual application path attribution and real application UDP; HA-04 owns the
  failover timing and HA-05 the complete business recovery;
- real 10 s/application performance.

These rows stay NOT RUN / BLOCKED until the Windows test PC and both authorized
test VPSes are available; none may be replaced by a LAB or CI result.
