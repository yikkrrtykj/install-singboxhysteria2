# Competition-safe profile transform (HA-03 #91)

Code: `tools/mihomo-competition-ha-profile.py`
Contract suite: `tests/test-mihomo-competition-ha-profile.sh`
Consumes: the HA-02 delivery (`ha-delivery-*.json` + `<name>-ha.yaml`) and a
local pins file. Produces: `<name>-hac.yaml` + `ha-competition-<version>.json`
in a **separate** output directory.
Parents: [competition HA contract](mihomo-competition-ha-contract.md),
[acceptance contract](mihomo-competition-ha-acceptance.md),
[HA-02 batch delivery](mihomo-competition-ha-batch.md).

Status: **implementation + hermetic/core-load evidence; NOT runtime acceptance.**
The exact Clash Verge Rev/Mihomo combination, real HY2 TLS accept/reject, Windows
TUN/DNS/UDP/routing, cache/exit/restore and both real VPSes still require the
operator's Windows test PC and authorized test VPSes. Those rows are NOT RUN /
BLOCKED, not PASS. Default OFF: this tool only writes files; importing and
activating a competition profile in Clash Verge Rev is an explicit operator
action. No daemon, GUI, web service or scheduled task is added; Quality
Failover stays opt-in and disabled.

## Why a second delivery instead of editing HA-02

The HA-02 profile is the canonical, credential-bearing dual-active delivery and
is also the input contract of the PR-48A parser. Rewriting it in place would
break byte identity, hashes and the rollback/audit trail. This tool therefore
reads HA-02 bytes, verifies the manifest hashes, applies exactly three
deterministic edits, and writes a new file per terminal. The HA-02 delivery and
its manifest are never modified or overwritten.

## The three edits (per terminal)

Input is the four-node HA-02 profile. Output differs only in:

1. `  listen: "0.0.0.0:53"` → `  listen: "127.0.0.1:53"` (DNS is loopback-only;
   no LAN DNS listener).
2. `Hysteria2` block: `    skip-cert-verify: true` →
   `    skip-cert-verify: false` plus
   `    fingerprint: <SHA-256 DER pin of the terminal's primary VPS>`.
3. `Backup-Hysteria2` block: same, with the terminal's **backup** VPS pin.

The physical mapping is read from the HA-02 manifest: for an A-first terminal
`Hysteria2` pins A and `Backup-Hysteria2` pins B; for B-first it is the reverse.
A node called `Reality` alone never decides which physical VPS is pinned.

Everything else — names, group order, probe URL/interval/timeout/`lazy`/
`expected-status`, HY2 hopping `ports`/`hop-interval`, credentials — stays
byte-identical. The transformer refuses any input that does not match the
expected shape (missing/extra HY2 block, existing `fingerprint`, missing DNS
line, CRLF, more or fewer than three edit points).

## Pins file (trusted input)

A local, access-controlled JSON file:

```json
{
  "schema": "mihomo-competition-ha-pins/1",
  "vps": {
    "A": {"fingerprint_sha256": "<64 lowercase/uppercase hex>",
           "not_after": "2027-05-01T00:00:00Z",
           "source": "ssh-openssl-2026-11-21"},
    "B": {"fingerprint_sha256": "<64 hex>",
           "not_after": "2027-05-01T00:00:00Z",
           "source": "ssh-openssl-2026-11-21"}
  }
}
```

- SHA-256 of the **DER** certificate, exactly 64 hex characters; upper case is
  accepted and normalised to lower case in output.
- `not_after` must be the certificate expiry in UTC (`YYYY-MM-DDTHH:MM:SSZ`).
- `source` names the trusted management channel used to obtain the fingerprint
  (never paste certificate private keys or full certificates here).
- A and B pins must be distinct; unknown keys, a missing VPS, a wrong schema, a
  non-hex/short fingerprint or non-private file permissions are refused.

Obtain each fingerprint over the trusted management channel (SSH to the VPS,
using the **fixed** HY2 port, not a hopping range):

```sh
openssl s_client -connect <vps-host>:8444 -servername <sni> </dev/null 2>/dev/null \
  | openssl x509 -outform der | sha256sum
```

Record the certificate's `notAfter` (`openssl x509 -noout -enddate`) and rotate
the pins file when the certificate is renewed.

### Expiry control (because Mihomo leaf pinning does not check validity)

Mihomo's hysteria2 `fingerprint` compares the leaf DER SHA-256; it does not
enforce the certificate's validity window. The tool therefore enforces the
documented control itself:

- generation refuses a pin whose `not_after` is not strictly later than
  `now + --min-validity-days` (default 7);
- `--check` re-validates the same rule plus the recorded pins and every output
  hash before event use; run it on each event day and after any renewal;
- a failed check refuses the delivery (exit 1) rather than silently continuing.

This is an explicit validity control, not a claim that pinning verifies expiry.
If a certificate is renewed, update the pins file, regenerate the competition
delivery and re-run `--check` before importing.

## Commands

```sh
# 0. private pins file (operator-owned, chmod 600 / private Windows ACL)
$EDITOR ~/ha/pins.json
chmod 600 ~/ha/pins.json

# 1. generate the competition delivery next to (not inside) the HA-02 delivery
python3 tools/mihomo-competition-ha-profile.py \
  --delivery ~/ha/delivery \
  --pins ~/ha/pins.json \
  --output-dir ~/ha/competition \
  --config-version ha-2026-11-24-comp-r1 \
  --min-validity-days 7

# 2. preflight before each event day / after renewal
python3 tools/mihomo-competition-ha-profile.py \
  --delivery ~/ha/competition --pins ~/ha/pins.json --check

# 3. import one <name>-hac.yaml into Clash Verge Rev manually and verify it
#    (see docs/mihomo-competition-ha-windows-verification.md). No automatic
#    activation or upgrade is performed.
```

Success prints:

```
ha-profile: OK
terminals: 30
version: ha-2026-11-24-comp-r1
manifest: ha-competition-ha-2026-11-24-comp-r1.json
```

`--check` prints `ha-profile: OK`, `terminals`, `pins: valid` and
`validity: A=<date> B=<date>`.

## Output manifest

`ha-competition-<version>.json` records: schema/tool/config version, the HA-02
source manifest name + schema + config version, the A/B pins with `not_after`
and `source`, `min_validity_days`/`checked_utc`, the permission gate, and per
terminal: name, group, `primary_vps`, `backup_vps`, input/output file names and
SHA-256 values, output bytes, and the exact primary/backup pins used. It also
carries the rollback file list (competition profiles + manifest). It contains
no addresses, UUIDs, passwords or profile bodies. Protect it like the delivery.

## Failure handling and rollback

Fixed codes on stderr, exit 1 (`E_USAGE` exits 2):

| Code | Meaning |
| --- | --- |
| `E_DELIVERY` | HA-02 manifest missing/ambiguous/invalid, or a profile/competition manifest name invalid |
| `E_DELIVERY_HASH` | a delivered input or competition output no longer matches its recorded SHA-256 |
| `E_PINS` | pins file missing/symlink/reparse/malformed/unknown keys/identical pins |
| `E_PINS_EXPIRED` | a pin expires inside `--min-validity-days`, or `--check` sees an expired/mismatched pin |
| `E_TRANSFORM` | the input profile is not the expected HA-02 shape (exactly three edits impossible) |
| `E_OUTPUT_EXISTS` | target profile or manifest already exists (case-insensitive) |
| `E_PATH_CONFLICT` | missing/linked/junction output directory, or output inside the HA-02 delivery |
| `E_INSECURE_PERMISSIONS` | POSIX mode/owner, Windows ACL allowlist, private-boundary or temp-inheritance failure |
| `E_IO` | write/verify failure |
| `E_USAGE` | bad arguments/version |

All targets are prevalidated before any write; writes are atomic no-clobber;
every output and the manifest are read back, permission-checked and
hash-verified; on partial failure only files this run created are deleted after
re-checking their file identity and bytes (the same device/file-ID + hash rule
as HA-02). Nothing pre-existing is touched. `ROLLBACK removed=… skipped=…
complete=…` is printed on failure.

## What is verified, and what is not

Verified here (hermetic + pinned core):

- exact three-edit transform, input bytes unchanged, output/manifest hashes,
  A-first/B-first pin mapping, 1/2/16/30-terminal batches;
- pins schema/expiry/normalisation and `--check` refusal paths;
- no-clobber, case collisions, path/permission failures, partial rollback;
- real Linux CI with the pinned Mihomo v1.19.31 core loading all 30 generated
  `-hac.yaml` profiles (`-t`); the Windows core loads the same shape;
- HA-02 ACL/core evidence reused; existing five workflows / 20 checks unchanged.

**Not verified here (BLOCKED on operator resources):**

- Clash Verge Rev v2.5.10 + its bundled Mihomo v1.19.33 on the real Windows PC
  (installed version, on-disk core banner + SHA-256, provenance);
- real HY2 TLS accept/reject against VPS A and B (correct pin accepted, wrong
  pin rejected, primary/backup roles), certificate renewal/rotation and
  rollback — a loopback lab can demonstrate pin semantics but is not a VPS
  identity acceptance;
- TUN/DNS/Fake-IP/IPv4/IPv6/UDP, Rule/Global/Direct effective paths, actual
  listener binds/auth, LAN/production/management access, controller reachability;
- cache/exit/abnormal-close/core-restart/restore behaviour and manual override
  preservation;
- real application/10 s performance.

These rows stay NOT RUN / BLOCKED until the Windows test PC and both authorized
test VPSes are available; none may be replaced by a LAB or CI result.
