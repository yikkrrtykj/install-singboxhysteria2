# Competition HA batch delivery (issue #48, HA-02)

Code: `tools/mihomo-competition-ha-batch.py`
Contract suite: `tests/test-mihomo-competition-ha-batch.sh`
Pinned-core load harness: `tests/mihomo-competition-ha-core-load.py`
Stage: HA-02 [#90](https://github.com/yikkrrtykj/install-singboxhysteria2/issues/90)
Parents: [competition HA contract](mihomo-competition-ha-contract.md),
[acceptance contract](mihomo-competition-ha-acceptance.md).
Canonical parser reused, not reimplemented: `tools/mihomo-multi-vps-merge.py`
([PR-48A](mihomo-multi-vps-failover-p48a.md)).
Probe policy inherited unchanged from [#42](mihomo-client-failover-policy.md).

Status: **implementation + local contract evidence; NOT event acceptance.**
A loaded profile is not a 10 s result, a Windows/Verge certification, an
application result or a Go-Live approval. HA-03/HA-04/HA-05/HA-06 own those.

## What it does

One offline operator command turns a terminal inventory plus two canonical
`client.export` trees into one four-node profile per terminal and a local
SHA-256 delivery manifest:

```
terminals.csv ─┐
exports/A/<name>-mihomo.yaml ─┼─ ha-batch ─→ delivery/<name>-ha.yaml        (per terminal)
exports/B/<name>-mihomo.yaml ─┘              delivery/ha-delivery-<version>.json
```

- Every profile contains exactly `Reality`, `Hysteria2`, `Backup-Reality`,
  `Backup-Hysteria2`, in that order, from the two physical VPSes assigned by
  the terminal's group.
- A-first: A Reality → A Hysteria2 → B Reality → B Hysteria2.
- B-first: B Reality → B Hysteria2 → A Reality → A Hysteria2 (B is the merge
  primary; the manifest records `primary_vps: B`, `backup_vps: A`).
- The four physical candidates are fixed per terminal; nothing here is
  latency-based selection or per-flow balancing.
- Each output is byte-identical to what
  `python3 tools/mihomo-multi-vps-merge.py` produces for the same pair, so the
  four-node priority, the group bodies and every untouched byte keep the
  PR-48A contract.
- The 60 s/5000 ms/`lazy: false`/`expected-status: "204"` probe policy is
  inherited byte-for-byte. This tool never edits the probe policy.
- Complete HY2 hopping is preserved: a source `ports: A-B` + `hop-interval: 30`
  pair survives in both the primary and the backup HY2 block.
- Batch identity is compared by *identity*, not spelling: UUIDs are
  case-insensitive, IPv4/IPv6 literals compare by value, hostnames compare
  case-insensitively (the accepted canonical hostname form has no trailing
  root dot). Nothing is rewritten in the delivered bytes; passwords remain
  case-sensitive.
- Credential-bearing directories and delivered files must satisfy a
  conservative permission gate: POSIX mode **and** owner, or a Windows DACL
  whose allow entries name only the operator, SYSTEM, Administrators or an
  inherit-only owner pseudo-principal. Reparse points/junctions are refused.

There is no daemon, GUI, web service, scheduled task, VPS-to-VPS channel,
shared credential database or third-party runtime dependency. The tool opens
the inventory, the 2×N exports, the output directory and nothing else.

## Inputs

### Exports

```
exports/
  A/<name>-mihomo.yaml     # canonical client.export of the physical VPS A
  B/<name>-mihomo.yaml     # canonical client.export of the physical VPS B
```

Both files must be the exact current output of
`lib/client-management.sh :: cm_render_client_mihomo_yaml`: the same strict
canonical validation the PR-48A merge tool applies (43-line literal prefix,
exact top-level key sequence, exactly two proxy blocks, exact group and rule
bodies, no CR/NUL/tab, no anchors/tags/comments, ≤48 KiB, regular file, no
symlink). Anything else is `E_SOURCE_NOT_CANONICAL` for that role. A damaged,
truncated, reflowed, re-encoded or hand-edited export is not repaired; it is
refused.

The file name is a provenance guard, not authenticated identity. The batch
tool constructs the path from the terminal name, so a mis-named export can
never be picked up for a terminal; what it cannot prove is that the operator
downloaded the *right* VPS's export. That is why the batch-wide source gate
exists (below).

### Inventory (`terminals.csv`)

A local terminal/group manifest. Accepted document:

```
terminal,group
event-ob01,A-first
event-ob02,A-first
# one line per PC; comments and blank lines are ignored
event-ob17,B-first
```

- Optional exact header `terminal,group` as the first content line.
- `#` starts a comment line; blank lines are ignored; CRLF is accepted (the
  file is hand-edited on Windows); a BOM, tab, lone CR, padding or extra column
  is refused.
- Terminal names use the repository's canonical client-name rule: one
  alphanumeric followed by up to 31 of `[A-Za-z0-9._-]`. Names are unique
  case-insensitively, because the delivery targets Windows.
- Group must be exactly `A-first` or `B-first`.
- 1 to 256 terminals; the event uses 16–30.
- Order is preserved into the manifest and into the generated file set.

Synthetic example only — never commit a real inventory, export, delivery or
manifest.

## Commands

### Linux / macOS operator host

```sh
mkdir -p ~/ha/exports/A ~/ha/exports/B ~/ha/delivery
chmod 700 ~/ha ~/ha/exports ~/ha/exports/A ~/ha/exports/B ~/ha/delivery
cp /secure/path/A/*-mihomo.yaml ~/ha/exports/A/
cp /secure/path/B/*-mihomo.yaml ~/ha/exports/B/
chmod 600 ~/ha/exports/A/*-mihomo.yaml ~/ha/exports/B/*-mihomo.yaml
chmod 600 ~/ha/terminals.csv

python3 tools/mihomo-competition-ha-batch.py \
  --inventory ~/ha/terminals.csv \
  --exports ~/ha/exports \
  --output-dir ~/ha/delivery \
  --config-version ha-2026-11-24-r1
```

### Windows operator host (PowerShell)

```powershell
$root = "$env:USERPROFILE\ha"
New-Item -ItemType Directory -Force "$root\exports\A", "$root\exports\B", "$root\delivery" | Out-Null

# Real NTFS ACL: remove inherited ACEs, keep the operator, SYSTEM and Administrators.
$acl = @("$($env:USERNAME):(OI)(CI)F", "SYSTEM:(OI)(CI)F", "Administrators:(OI)(CI)F")
foreach ($dir in @("$root", "$root\exports", "$root\exports\A", "$root\exports\B", "$root\delivery")) {
    icacls $dir /inheritance:r /grant:r $acl
}

python -3 tools\mihomo-competition-ha-batch.py `
  --inventory "$root\terminals.csv" `
  --exports "$root\exports" `
  --output-dir "$root\delivery" `
  --config-version ha-2026-11-24-r1
```

`python -3` requires Python 3.10+ (standard library only; nothing to install).
The tool validates the ACLs it actually finds; it never changes them. If the
check fails it prints the offending role and, on Windows, the offending SID
(`detail=sid=...`), so `icacls <dir>` can be used to fix the directory and the
command re-run. `chmod` in a POSIX shell on Windows proves nothing.

### Success and failure output

Success prints exactly five lines and nothing on stderr:

```
ha-batch: OK
terminals: 30
groups: A-first=16 B-first=14
version: ha-2026-11-24-r1
manifest: ha-delivery-ha-2026-11-24-r1.json
```

A failure prints one fixed line on stderr, no stdout, and exits 1 (usage: 2):

```
ha-batch: FAIL E_SOURCE_MIXED vps=B detail=distinct=2
```

Only the fixed code plus a *logical* terminal name, the `A`/`B` role, a
permission role and a permission/duplicate detail are ever printed. No path, no
server address, no UUID, no password, no public-key, no short-id and no YAML
line appears in any message.

## Delivery files

`<name>-ha.yaml` — one four-node Mihomo profile per terminal, mode 0600 on
POSIX, written by the canonical atomic writer: private temp file in the same
directory, `fsync`, `chmod 0600`, then a hard-link publish that refuses an
existing destination.

`ha-delivery-<version>.json` — the local delivery manifest:

```json
{
  "schema": "mihomo-competition-ha-batch/1",
  "generator": {"tool": "tools/mihomo-competition-ha-batch.py",
                 "version": "1", "config_version": "ha-2026-11-24-r1"},
  "canonical_validator": "tools/mihomo-multi-vps-merge.py",
  "permission_gate": "windows-acl-allowlist",
  "created_utc": "2026-11-20T00:00:00Z",
  "inventory_sha256": "…",
  "terminal_count": 2,
  "groups": {"A-first": 1, "B-first": 1},
  "vps_sources": {"A": {"fingerprint_sha256_16": "…"},
                   "B": {"fingerprint_sha256_16": "…"}},
  "terminals": [
    {"name": "event-ob01", "group": "A-first", "primary_vps": "A",
     "backup_vps": "B", "output": "event-ob01-ha.yaml",
     "output_sha256": "…", "output_bytes": 2464,
     "hy2_hopping": {"primary": false, "backup": true}}
  ],
  "rollback": {"kind": "delete-files-created-by-this-batch",
                "files": ["event-ob01-ha.yaml", "event-ob02-ha.yaml",
                          "ha-delivery-ha-2026-11-24-r1.json"]}
}
```

Values above are synthetic placeholders. The manifest deliberately records:

- the local configuration version and the tool/schema versions;
- the actual A/B role assignment per terminal (a node called `Reality` alone
  does not identify a physical VPS);
- the output SHA-256 and byte count that must match the file actually used;
- whether each terminal's HY2 hopping pair was present (the port range itself
  is not recorded);
- the inventory SHA-256 and the two per-VPS source fingerprints
  (`sha256(server)` truncated to 16 hex), which let an operator prove that every
  A-first terminal really used the same physical A and a different physical B;
- the rollback file list for this batch.

The manifest never contains a server address, UUID, password, SNI, public key,
short-id, port, hopping range or profile body. It is a local record: protect it
like the delivery (0600 / private ACL) and never publish it.

## Validation and refusal matrix

All inputs are validated before the first delivery byte is written: a batch is
all-or-nothing. A failed prevalidation writes nothing at all.

| Code | Meaning |
| --- | --- |
| `E_INVENTORY` | inventory unreadable, empty, BOM/tab/lone-CR, bad row/column/group, bad name, or over the terminal cap |
| `E_INVENTORY_DUPLICATE` | the same terminal name twice (case-insensitive) |
| `E_SOURCE_MISSING` | one of the two expected canonical exports is absent |
| `E_SOURCE_NOT_CANONICAL` | the export is not the current canonical `client.export` (damaged, truncated, CRLF, extra key/proxy/group, symlink, unreadable) |
| `E_NAME_MISMATCH` | a basename does not carry the terminal name (defensive; batch paths are constructed from the name) |
| `E_SOURCE_COLLISION` | the two sources of a terminal are the same physical VPS, or the batch's A and B sets are identical |
| `E_CREDENTIAL_REUSE` | a UUID or HY2 password is shared between A and B of one terminal, or reused by another terminal on either VPS |
| `E_SOURCE_MIXED` | one terminal's A-side (or B-side) export comes from a third physical VPS, so the batch is not one A plus one B |
| `E_PATH_CONFLICT` | missing/!directory/linked source or output directory, output directory inside a source tree, or an output colliding with an input |
| `E_OUTPUT_EXISTS` | any target profile or the manifest already exists (also matched case-insensitively) |
| `E_INSECURE_PERMISSIONS` | a credential-bearing path fails POSIX mode/owner, the Windows ACL allowlist, the local/private boundary, or the temp-file inheritance probe |
| `E_GENERATED_INVALID` | the tool's own structural self-check of a generated profile failed (not expected; it is a fail-closed internal gate) |
| `E_TOOL_MISSING` | the canonical `tools/mihomo-multi-vps-merge.py` is not next to this tool |
| `E_IO` | an output or the manifest could not be written/verified |
| `E_USAGE` | bad arguments or an invalid `--config-version` (exit 2) |

Batch-wide identity gates:

- **Identity, not spelling.** UUIDs are case-insensitive (the canonical parser
  accepts upper and lower hex, and a UUID has no case distinction), so
  `A1B2…` and `a1b2…` are one credential for every same-terminal, cross-terminal
  and cross-VPS comparison. IPv4/IPv6 literals compare by parsed value and
  hostnames case-insensitively, so equivalent spellings cannot split one VPS's
  fingerprint or disguise the same VPS as both sources. The delivered bytes are
  never normalised: the source spelling is what the output carries. HY2
  passwords remain case-sensitive.
- **Distinct providers are not proven, only distinct sources.** Two addresses
  are not two providers; the tool never claims otherwise. The per-VPS source
  fingerprint proves the batch used one A endpoint and one B endpoint, not
  different ASNs, DCs or upstream paths.
- **Mixed-VPS rejection.** If one terminal's A-side export really came from the
  B (or a third) VPS, its server fingerprint differs from the other A-side
  exports and the batch fails `E_SOURCE_MIXED` with the role. A batch of ten
  terminals where one A is a copy of the other VPS is exactly the operator
  mistake this gate exists for.
- **Credential independence.** Normalised UUIDs and raw HY2 passwords must be
  unique across the entire batch (2×N values), which covers same-terminal A/B
  reuse, same-VPS cross-terminal reuse and cross-VPS reuse. The offending value
  is never printed.
- **Case-insensitive paths.** Terminal names, output names, the manifest name
  and input/output collisions are compared case-folded on every host, so a
  batch validated on Linux cannot overwrite on the Windows event PC.

## Windows ACL gate

POSIX filesystems are judged on their real mode bits **and** owner: every
credential-bearing directory must have no group/other bits (0700) and every
source/export/inventory/delivered file none either (0600), and each path must
be owned by the user running the tool. In addition, no ancestor above the
private root may be group/other-writable without the sticky bit (a sticky
directory such as `/tmp` cannot be used to replace the operator's entry). Mode
bits on NTFS are cosmetic, so Windows is judged on the owner and DACL read from
the kernel (`GetNamedSecurityInfoW` → SDDL), never on `chmod`.

Windows is an **allowlist**, not a denylist. A DACL is accepted only when:

- the DACL is present and not NULL (`NO_ACCESS_CONTROL` is refused);
- every ACE is of a recognised type (`A`, `OA`, `D`, `OD`, `AU`, `AL`, `OU`,
  `OL`, `ML`, `ID`, `RA`, `SP`); an unknown or unparsable ACE is refused;
- every allow-ACE names the current operator, `NT AUTHORITY\SYSTEM`
  (`S-1-5-18`) or `BUILTIN\Administrators` (`S-1-5-32-544`), or names
  `CREATOR OWNER` (`S-1-3-0`) / `OWNER RIGHTS` (`S-1-3-4`) **with the
  inherit-only flag**; any other principal is refused and reported by SID;
- the owner is the current operator, `SYSTEM` or `Administrators` (an owner who
  could rewrite the DACL is refused).

The gate runs on the exports root, both source trees, the inventory, the
delivery directory, and the delivered YAML and manifest files **themselves**.
The tool also creates a private probe file in the delivery directory before any
sensitive write and checks its inherited ACL/mode, so temp-file inheritance is
proven rather than assumed; the canonical writer's own temp file is created the
same way. Directory junctions, symlinks and other Windows reparse points are
refused (a junction is `S_ISDIR` and not a symlink to `lstat`, so the reparse
attribute is checked explicitly yet the path is still not followed).

The contract suite proves this against live DACLs on a real Windows host: a
private tree is accepted, the delivered files pass the same check, a real
`BUILTIN\Users` grant on the exports root or on one source file is refused, a
real directory junction is refused, and `C:\Users\Public` is refused without
modifying any ACL outside the suite's own fixtures.

What this does **not** prove: the allowlist is enforced on the declared paths
and their delivered files, not on every ancestor's DACL. A broad ACE on a
distant ancestor, or a different owner of an ancestor that can rename the
private root, is outside the check; the operator must place the exports and
delivery inside a private, operator-owned directory and can confirm it with
`icacls`. `permission_gate` in the manifest records which gate ran
(`windows-acl-allowlist` or `posix-mode-owner`), not that the site is safe.

## Failure, rollback and no-clobber

- **No overwrite.** Any existing target profile or manifest is refused. The
  check is case-insensitive, so `EVENT-OB01-HA.YAML` also blocks
  `event-ob01-ha.yaml` on a case-sensitive host that will later be read by
  Windows.
- **All-or-nothing prevalidation.** Inventory, permissions, every export,
  batch identity, path collisions and every target path are validated before
  the first write. One bad terminal fails the whole batch with nothing written.
- **Atomic publish.** Each file is a private temp file in the same directory,
  `fsync`ed, `chmod 0600`, then hard-linked to the target. A concurrent writer
  cannot be silently replaced.
- **Read-back verification.** Every delivered file is read back and compared
  byte for byte before its hash is recorded in the manifest; the manifest is
  written last, so it can never describe a file that was not delivered.
- **Rollback of this batch only.** On any failure after writing started, the
  files this batch created are deleted in reverse order (manifest first). A
  pre-existing file is never touched, because nothing pre-existing is ever
  opened for writing. Before each deletion the current bytes are re-hashed
  against the bytes this batch wrote; a file that was replaced by another
  process is **not** deleted. After a clean rollback the tool prints
  `ha-batch: ROLLBACK removed=<n> skipped=<m> complete=yes`.
- **Incomplete rollback is visible.** If a created file cannot be removed or no
  longer matches the batch's bytes, the failure line is followed by
  `ha-batch: ROLLBACK removed=<n> skipped=<m> complete=no` and the operator must
  inspect/remove the residual (the manifest lists the intended files when it
  exists). `skipped` counts files deliberately left because they are not this
  batch's bytes any more.
- **This is delivery rollback, not client rollback.** Deleting the delivery
  files does not restore a Clash Verge profile/settings/selection backup; that
  is HA-03's rollback contract and must be verified on the Windows PC.

## Security and evidence boundary

- Exports, deliveries and manifests contain real credentials: keep them only in
  locally access-controlled operator storage. Never commit them, upload them,
  attach them to an issue/PR, paste them into Monitor Web or send them to a
  third party.
- Credentials never appear in argv (the CLI takes paths, a logical version and
  the output directory only), stdout, stderr, an exception, the manifest or a
  CI log. The suite asserts this with synthetic credential sentinels.
- There is no `--force`, no `--overwrite`, no credential/password/server option
  and no `--help` (help/usage text is generated from argv; any misuse prints
  one fixed line and exits 2).
- A published receipt may contain the run ID, the configuration version, the
  tool/schema versions, counts, the A/B role assignment, output SHA-256 values
  and PASS/NOT MET/BLOCKED/UNKNOWN. It must not contain source addresses,
  credentials, private YAML or full connection metadata.

## What this does not prove

- **No 10 s result.** Loading a profile proves the core accepts it; it says
  nothing about T0→T1, T0→T2 or T0→T3.
- **No application result.** vMix Call, TikTok LIVE Studio and Google Drive
  behaviour are HA-05.
- **No TLS identity verdict.** The canonical export carries
  `skip-cert-verify: true`; that is an input-compatibility setting, not a
  verified server identity. HA-03 owns the trusted-chain/pinning policy and
  the per-VPS certificate lifecycle.
- **No provider diversity.** Distinct server addresses are not distinct
  providers, ASNs, data centres or upstream paths.
- **No capacity or Go-Live.** Both-VPS 30-client takeover, reserve and the
  final Go/No-Go are HA-06.
- **Hopping is not protocol-wide protection.** A preserved `ports:` range does
  not prove protection against broad UDP/QUIC impairment; single-port and
  protocol-wide impairment are different HA-04 cases.
- **No silent HA on missing input.** The batch tool refuses a missing backup;
  single-VPS operation remains the merge tool's separate explicit mode.

## Verification

Hermetic contract suite (no network, no core, no root; temporary fixtures with
synthetic credentials only; POSIX mode/owner/boundary gates execute on Linux CI
and skip on Windows; Windows ACL/reparse gates execute on Windows):

```sh
bash tests/test-mihomo-competition-ha-batch.sh
```

Local Windows development host, HA-02 review-revision head:
`pass=250 fail=0 skip=5`; the five skips are exactly the POSIX
permission-bit, unreadable-source, symlink-source and symlinked-root gates that
Linux CI runs for real. Linux CI totals are the authority and are recorded on
the pull request. The existing PR-48A merge suite stays at
`pass=176 fail=0 skip=3` and the renderer contract at `PASS=61 FAIL=0 SKIP=0`.

Pinned-core load gate (operator-local; the core and its hash are supplied, it
downloads nothing):

```sh
python3 tests/mihomo-competition-ha-core-load.py \
  --mihomo <pinned-mihomo-binary> \
  --expect-sha256 <exact-sha256> \
  --delivery <delivery-directory> \
  --workdir <private-scratch-directory> \
  --expect-terminals 30
```

It restricts the manifest to its canonical filename inside the delivery
directory, rejects case-insensitive duplicate terminal/output names, path
separators or `..` escapes, verifies the manifest and every output SHA-256, then
asks that exact core to load every profile. Recorded HA-02 local run
(Windows/amd64, synthetic 30-terminal batch, version `ha-2026-11-24-r1`,
delivery directory and files under a strict three-principal ACL):

- core: `Mihomo Meta v1.19.31 windows amd64 with go1.26.8`
- core SHA-256: `532ed88b3a37d72f6b5ee5d24a45ce5d8799f3ba34931d6a167d4345f7ebca50`
- result: `core-load: OK`, `profiles: 30`, elapsed 17.0 s (warm GeoIP cache;
  a failed profile is retried once, so a transient core-side fetch cannot fail
  an otherwise loadable delivery)

CI runs the same harness against the Linux release `mihomo-linux-amd64-v1.19.31`
(`.gz` SHA-256 `d5e74bbddbdfff49a1aef7775bf5911da59f0d7196ed509a0ac914b3653dd5f1`,
decompressed SHA-256 `08787faafea19c1ab0f83fa5a1b22363b7d03ea78da18091a4c883aecaaa5979`).
The Linux core and the Windows core are different binaries; neither result
certifies the other platform, and HA-03 still owns the exact
Clash Verge Rev/Mihomo combination on the event PCs.

CI placement (five workflows / twenty required checks unchanged):
`bash -n` and `py_compile` in the `shell-tests` fast-checks lane; the contract
suite plus the pinned-core load in the `shell-tests` `core-regression` lane
(Linux real permission gates included); and the same suite in the existing
`quality-receiver` `contracts` Windows job, which supplies the native NTFS ACL,
other-principal, junction and per-file permission evidence. No new workflow or
required check is added.

## Non-goals

No GUI, web service, daemon, scheduled task, auto-download of exports, VPS
provisioning, credential generation/synchronisation, DNS/VRRP/anycast failover,
per-flow balancing, live-connection migration, Clash Verge import automation,
health-interval change, quality-aware switching (PR-48B stays opt-in and
disabled), production deployment or automatic Go-Live.
