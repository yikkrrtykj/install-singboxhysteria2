# Multi-VPS Mihomo profile merge (issue #48, PR-48A)

Code: `tools/mihomo-multi-vps-merge.py`
Contract suite: `tests/test-mihomo-multi-vps-merge.sh`
Opt-in runtime harness: `tests/mihomo-multi-vps-runtime-lab.py`
Canonical source of the input format: `lib/client-management.sh :: cm_render_client_mihomo_yaml`
Prior policy decision (probe semantics this PR inherits, unchanged): `docs/mihomo-client-failover-policy.md` (issue #42)

## What it does

One operator-local, completely offline command that turns two downloaded
`client.export` profiles into one profile with four nodes:

```
primary client.export YAML (VPS A)  ┐
                                    ├─ merge tool ─→ multi-VPS YAML
backup client.export YAML (VPS B)   ┘
```

There is no other moving part. VPS A never contacts VPS B, no server-side
configuration is synchronised, no UUID or password is shared, no central
database exists, the Monitor Web is untouched, `client.export` is untouched,
and no production host is involved. The tool opens exactly three files: the
two inputs for reading and the one output for writing.

## Usage

Dual VPS:

```sh
python3 tools/mihomo-multi-vps-merge.py \
  --name event-vmix01 \
  --primary /path/A/event-vmix01-mihomo.yaml \
  --backup  /path/B/event-vmix01-mihomo.yaml \
  --output  /path/event-vmix01-ha.yaml
```

Single VPS (the existing workflow does not drift — a validated primary is
written out byte-for-byte, it is never re-serialised):

```sh
python3 tools/mihomo-multi-vps-merge.py \
  --name event-vmix01 \
  --primary /path/A/event-vmix01-mihomo.yaml \
  --output  /path/event-vmix01.yaml
```

`--primary` and `--output` are required, `--backup` is optional. Only
Python 3.10 standard library modules are used (`argparse ipaddress os re stat
sys tempfile`): no PyYAML, no `yq`, nothing to install.

Success prints exactly three lines and nothing else:

```
merge: OK
mode: dual
output: written
```

## Why it is a canonical parser, not a YAML merger

The tool does not parse "YAML". It accepts one specific document: the current
output of this repository's renderer. That is deliberate — a general YAML
round-trip would silently requote, reorder and reflow the file, and Mihomo's
compatibility with the result is exactly what we do not want to re-verify on
every merge.

Concretely, an input is accepted only if all of the following hold. Anything
else stops before a single byte is written.

File level, per input:

- regular file, not a symlink (`O_NOFOLLOW` + `fstat`, so the checked object
  is the read object);
- at most 48 KiB;
- strict UTF-8, no NUL, no tab, no CR anywhere;
- the exact top-level key sequence `mixed-port, allow-lan, bind-address, mode,
  log-level, unified-delay, ipv6, profile, dns, tun, proxies, proxy-groups,
  rules` — each key exactly once, in this order. This is also what proves
  there is exactly one `proxies`, one `proxy-groups` and one `rules` section,
  and it rejects an added key (for example an `external-controller`), a
  duplicated section, a comment, an anchor or a tag at column 0.

`proxies` section — exactly two blocks, in this order, with exactly one blank
line between them and two before `proxy-groups`:

- `Reality`: `type: vless`, an IP-or-hostname `server`, a numeric `port`, a
  canonical UUID `uuid`, `network: tcp`, `udp: true`, `tls: true`,
  `flow: xtls-rprx-vision`, a hostname `servername`,
  `client-fingerprint: chrome`, and `reality-opts` with exactly a base64url
  `public-key` and an even-length hex `short-id`;
- `Hysteria2`: `type: hysteria2`, the same `server` field shape, `port`,
  optionally `ports: A-B` + `hop-interval: 30` (a half pair is refused),
  `password` (single token, 8–128 chars), `up: "300 Mbps"`,
  `down: "300 Mbps"`, hostname `sni`, `skip-cert-verify: true`, and
  `alpn:` with the single entry `- h3`.

`proxy-groups` section — byte-identical to the accepted #42 policy (plus its
blank-line cadence): outer `节点选择` `type: select` with
`default-selected: 自动选择` and members `Reality, Hysteria2, 自动选择, DIRECT`;
inner `自动选择` `type: fallback` with members `Reality, Hysteria2` and
`url/interval/timeout/lazy/expected-status` as rendered.

`rules` section — exactly `GEOIP,LAN,DIRECT`, `GEOIP,CN,DIRECT`,
`MATCH,节点选择`, followed by the template's trailing blank line.

Extra proxies, extra groups, extra proxy fields, renamed groups, a `url-test`
group, duplicate keys, anchors/aliases/tags, an empty credential field, or a
lost trailing blank line are all refused. There is no "best effort" mode.

## Gates before any merge happens

1. **Logical name / provenance.** The canonical YAML carries no logical client
   name; the only trusted external hint is the downloaded file name
   `<name>-mihomo.yaml`. The tool therefore requires `--name` and that both
   input basenames equal `<name>-mihomo.yaml`.
   This is a **provenance guard against grabbing the wrong export** — it is not
   a cryptographic identity proof and it does not become one. Adding signed or
   sourced metadata to `client.export` is a separate change, deliberately not
   part of this PR.
2. **Distinct sources.** The renderer writes the same `SERVER_IP` into both
   tunnels, so each input must have `Reality.server == Hysteria2.server`, and
   the two inputs must disagree: `primary.server != backup.server`. Three
   violations, one code: `E_SOURCE_COLLISION` (it catches "I passed the same
   VPS twice", which is the failure this gate exists for).
3. **Independent credentials.** Issue #48 freezes per-VPS credentials, so
   `primary Reality.uuid != backup Reality.uuid` and
   `primary HY2 password != backup HY2 password`. A violation is
   `E_CREDENTIAL_REUSE`; the value is never echoed.
   Check order is canonical shape → name → source → credential, so the same
   file passed as both inputs is reported as `E_SOURCE_COLLISION`.

## Merge algorithm

The primary file is the base. Nothing is re-serialised:

- everything before `proxies:` stays primary bytes;
- both primary proxy blocks stay byte-identical;
- both backup proxy blocks are copied with their original field bytes, and the
  only line that changes is `- name:` (`Reality` → `Backup-Reality`,
  `Hysteria2` → `Backup-Hysteria2`). Server, port, UUID, password, public-key,
  short-id, SNI and hopping parameters keep the backup export's own values;
- the `proxy-groups` block is rebuilt to the contract below;
- everything from `rules:` on stays primary bytes.

Output proxies, in order: `Reality`, `Hysteria2`, `Backup-Reality`,
`Backup-Hysteria2`.

```yaml
proxy-groups:
  - name: 节点选择
    type: select
    default-selected: 自动选择
    proxies:
      - Reality
      - Hysteria2
      - Backup-Reality
      - Backup-Hysteria2
      - 自动选择
      - DIRECT

  - name: 自动选择
    type: fallback
    proxies:
      - Reality
      - Hysteria2
      - Backup-Reality
      - Backup-Hysteria2
    url: "https://www.gstatic.com/generate_204"
    interval: 60
    timeout: 5000
    lazy: false
    expected-status: "204"
```

## Timing decision (issue #48 asks for 30 s vs 60 s)

**This PR keeps `interval: 60`.** It is a topology change only: the #42 probe
policy is carried over byte-semantically unchanged (same URL, same 60 s
interval, same 5000 ms timeout, same `lazy: false`, same `expected-status:
"204"`), and the suite asserts that no `interval: 30` appears.

The trade-off, for the separate review that will decide it:

- 30 s halves the worst-case detection window (`interval + timeout`, ~65 s
  today → ~35 s) for a genuinely dead tunnel, which is the whole point of the
  failover;
- it doubles the probe rate through the tunnel against a third-party endpoint.
  At one client per account that is negligible; at fleet scale it is a
  measurable, self-inflicted outbound pattern, and issue #42 chose this probe
  precisely because it exercises real VPS egress;
- changing health timing while also changing topology would make a single
  review unable to attribute a regression to either.

So: add the second VPS now, argue about 30 s on its own.

## store-selected / upgrade compatibility

All previously deployable names survive: `Reality`, `Hysteria2`, `自动选择`,
`DIRECT`, `节点选择`. A client that upgrades from the single-VPS profile to the
merged profile therefore keeps every cached value resolvable — no dangling
selection, and the tool never touches (or clears) a client cache.

Inherited #42 semantics that this PR does **not** change: a client whose inner
`自动选择` is manually fixed to `Hysteria2` stays fixed on `Hysteria2` after
the upgrade, even though two new nodes appeared. Adding a backup VPS never
releases an existing manual pin. (Both behaviours are asserted live, not just
statically — see the runtime section.)

## Failure handling

Every failure is one fixed code on stderr, exit 1 (`E_USAGE` exits 2):

| code | meaning |
| --- | --- |
| `E_PRIMARY_NOT_CANONICAL` | the primary input is not a current canonical export |
| `E_BACKUP_NOT_CANONICAL` | the backup input is not a current canonical export |
| `E_NAME_MISMATCH` | an input basename is not `<name>-mihomo.yaml` |
| `E_SOURCE_COLLISION` | the exports do not look like two distinct VPSes |
| `E_CREDENTIAL_REUSE` | a UUID or password is shared between the VPSes |
| `E_OUTPUT_EXISTS` | the output path is already taken |
| `E_USAGE` | bad arguments (e.g. an invalid logical name) |
| `E_IO` | the output could not be written (e.g. missing directory) |

No failure message ever contains a server address, a UUID, a password, a
public-key, a short-id, a line number or an excerpt of the YAML. There are no
tracebacks: any unexpected exception is reported as `E_IO`, because a default
traceback can echo source lines — i.e. credentials — into stderr.

## Credential hygiene

Input and output both contain real credentials, so:

- credentials never appear in `argv` (the CLI takes paths, the logical name and
  the output path only), in the environment, on stdout, on stderr, in an
  exception, or in a CI log;
- the output is written through a private temp file created in the **same
  directory** with `mkstemp` (0600), flushed, `fsync`ed, `chmod`ed to 0600, and
  published with `os.link`, which is atomic and refuses to replace an existing
  file. The temp file is unlinked in all paths, including failures;
- v1 has no `--force`: an existing output is refused (`E_OUTPUT_EXISTS`).
  Overwriting is a deliberate non-goal for this PR.

On Windows the 0600 assertion is skipped, because POSIX mode bits there carry
no access semantics; the Linux CI lane asserts the mode, including under a
permissive umask.

## Explicit non-goals of PR-48A

No VPS-to-VPS SSH or API, no shared client database, no shared UUID/password,
no cross-VPS automatic add/delete, no DNS failover, no VRRP/BGP/anycast, no
Monitor UI orchestration, no automatic export download, no 30 s probe change,
no quality-aware failover (the "Reality reachable but upload degraded" case
from the second half of issue #48), no active upload-speed probe, no closing of
live Reality connections, no production deployment.

## What the tool does NOT prove (failure domains)

Producing four nodes does not prove that two VPSes are independent. The tool
proves exactly three things: two different canonical sources, two different
server endpoints, and independent credentials. It cannot prove a different
provider, a different ASN, a different DC/AZ, or a different upstream path, and
it never claims to. Those remain the operator's deployment choice. Nothing in
the output says "HA guaranteed"; the receipt says only `merge: OK`, `mode`,
and `output: written`.

## Verification

CI placement is repo/client-management scope, not Monitor regression:
`shell-tests` `fast-checks` runs `bash -n` on the suite plus
`python3 -m py_compile` on both Python files, and `core-regression` runs the
contract suite as the step "Multi-VPS Mihomo profile merge contract
(issue #48 PR-48A)".

Static contract suite (34 discriminators T1..T34 plus static gates), runs on any
host with Python 3.10+; symlink and mode assertions skip on Windows and execute
for real on Linux CI:

```sh
bash tests/test-mihomo-multi-vps-merge.sh
```

Controlled runtime validation. `tests/mihomo-multi-vps-runtime-lab.py` is
**opt-in and never part of CI**: it refuses to run without an operator-supplied
binary whose SHA-256 matches `--expect-sha256`, and it downloads nothing. It
starts one loopback-only Mihomo against four local mock relays, using the
topology taken from the merged profile produced by the real tool. Node bodies,
the probe endpoint and the probe timing are lab stand-ins (interval 3 s /
timeout 1500 ms instead of 60 s / 5000 ms, purely so the wall clock stays
sane); group names, member order, `default-selected` and fallback semantics are
the merged profile's own.

```sh
python3 tests/mihomo-multi-vps-runtime-lab.py \
  --mihomo <pinned-binary> --expect-sha256 <hash> \
  --merged <merged.yaml> --single <primary-export.yaml> \
  --workdir <scratch> --interval 3 --timeout 1500
```

Result of the controlled run for review (2026-09-26, Windows/amd64 lab):

- build: Mihomo Meta **v1.19.31**, `windows amd64 with go1.26.8`
- SHA-256: `deef9d8d34152e29941840df1d339b72ed71ec0dd460c2f2db572c1db231c8bf`
- 21/21 live assertions passed, in particular:

| scenario | observed |
| --- | --- |
| all four healthy | `自动选择` = `Reality`, `节点选择` = `自动选择`, egress really on the Reality relay |
| A Reality down | → `Hysteria2` |
| A Reality + A Hysteria2 down | → `Backup-Reality` |
| B Reality down too | → `Backup-Hysteria2` |
| A Reality restored | → back to `Reality` (first healthy by order) |
| established session while its node dies | stays chained on `Reality`, runs to completion, **not migrated** |
| new connection after that failover | egresses `Hysteria2` |
| warm cache from the single-VPS profile, outer pin `自动选择`, inner pin `Hysteria2` | after loading the merged profile both pins still resolve; the inner pin is **not** silently released |
| pinned `Hysteria2` then goes down | the group leaves the dead pin and returns to healthy `Reality` |
| then the whole primary pair down | → `Backup-Reality` |

No claim is made about established connections: they never migrate, and this PR
does not try to make them migrate (that would mean closing live Reality
connections, an explicit non-goal).

## Drift coupling

The parser pins the renderer's current shape. `tests/test-mihomo-multi-vps-merge.sh`
greps the renderer template for the markers the parser depends on
(`flow: xtls-rprx-vision`, `skip-cert-verify: true`, `client-fingerprint:
chrome`, `hop-interval: 30`, `expected-status: "204"`, `interval: 60`, …), so a
future change to `cm_render_client_mihomo_yaml` turns this suite red instead of
making every real merge fail closed with no explanation.
