# Competition fast-probe variants (HA-04 #92)

Code: `tools/mihomo-competition-ha4-fastprobe.py`
Contract suite: `tests/test-mihomo-competition-ha4-fastprobe.sh`
Operator LAB harness: `tests/mihomo-competition-ha4-lab.py`
LAB evidence: [fast-probe LAB evidence](mihomo-competition-ha4-lab-evidence.md)
Parents: [competition HA contract](mihomo-competition-ha-contract.md),
[acceptance contract](mihomo-competition-ha-acceptance.md),
[HA-03 competition profile](mihomo-competition-ha-profile.md),
[HA-04 LAB input](mihomo-competition-ha-lab-ha04-input.md).

Status: **offline implementation + hermetic contract + loopback LAB evidence;
NOT runtime acceptance.** Real Windows/Clash Verge/Mihomo bundle, real VPS/WAN,
real UDP hopping and the three business applications still require authorized
operator resources. Every such row is NOT RUN / BLOCKED, not PASS. Default OFF:
this tool only writes files. No profile is imported or activated, no Mihomo
source/core is patched, no client is restarted and no business connections are
cleared. Quality Failover stays opt-in and disabled.

This tool is an **experiment/candidate generator and preflight**, not a new
failover controller. It exists so the #92 probe-policy comparison and the
operator acceptance runs use deterministic, security-preserving artifacts that
cannot drift into a hand-edited YAML.

## Why derive from HA-03 instead of editing it

HA-03 owns the competition-safe profile: LAN proxy listener off, wildcard bind
removed, loopback-only DNS, `skip-cert-verify: false` plus a physical-VPS
leaf-certificate pin per HY2 node. Those invariants must not be weakened by a
probe experiment. The HA-04 artifact is therefore a second file set derived
from the **verified** HA-03 delivery:

    HA-02 delivery  --HA-03 tool-->  <name>-hac.yaml (verified competition delivery)
                                            |
        HA-04 tool, exactly two deterministic edits inside 自动选择:
                                            v
    <name>-ha4f.yaml  +  ha4-fastprobe-<version>-i<I>-t<T>.json

Only these lines change:

- `    interval: 60`  -> `    interval: <3|5|10>`
- `    timeout: 5000` -> `    timeout: <1000|2000|5000>`

Everything else is byte-identical: the four nodes in fixed priority order
(`Reality`, `Hysteria2`, `Backup-Reality`, `Backup-Hysteria2`), the health URL
and `expected-status: "204"`, `lazy: false`, the HY2 pins / `skip-cert-verify:
false`, `allow-lan: false`, the loopback listeners, DNS and HY2 hopping
parameters. The shipped generic 60 s/5000 ms template is never modified: HA-04
only writes new files into a separate output directory, and HA-02/HA-03 files
are read-only inputs.

The overlay refuses any source that is not the expected generic shape (missing
or duplicated `自动选择` group, different node order or extra node, base
interval/timeout not 60/5000, `lazy: true`, missing probe URL or
`expected-status`, CRLF). A non-generic or hand-edited profile cannot be made a
"HA-04 variant" by this tool.

## HA-03 compatibility (cannot be bypassed)

Generation and `--check` both run the **full HA-03 preflight** on the untouched
HA-03 delivery before deriving/verifying anything:

1. HA-02 source delivery manifest/profile hashes, role mapping and A/B pin
   mapping are re-verified by the HA-03 tool;
2. the recorded validity floor and pins file are re-validated;
3. the HA-03 output is re-derived from the HA-02 delivery byte-for-byte;
4. only then is the HA-04 overlay applied/re-derived and compared
   byte-for-byte against the delivered variant.

The HA-04 manifest records the HA-03 manifest name and SHA-256, so a different
or modified HA-03 delivery is refused. `--check` additionally re-runs the HA-03
literal security invariants on every variant (LAN/wildcard DNS/skip-cert/pins).
The HA-03 preflight remains valid for the event profile because HA-03 files are
never modified.

## Commands

```sh
# 0. inputs: HA-02 delivery, private pins file, private HA-03 competition dir

# 1. generate one policy variant (repeat per matrix cell / terminal group)
python3 tools/mihomo-competition-ha4-fastprobe.py \
  --delivery ~/ha/competition \
  --ha02-delivery ~/ha/delivery \
  --pins ~/ha/pins.json \
  --output-dir ~/ha/ha04/i5-t2000 \
  --config-version ha4-2026-11-21-r1 \
  --interval 5 --timeout 2000

# 2. preflight before a LAB/operator run (repeat until GREEN)
python3 tools/mihomo-competition-ha4-fastprobe.py --check \
  --delivery ~/ha/ha04/i5-t2000 \
  --source-delivery ~/ha/competition \
  --ha02-delivery ~/ha/delivery \
  --pins ~/ha/pins.json

# 3. import one <name>-ha4f.yaml into the LAB client or the authorized test PC
#    manually. No automatic activation, upgrade, restart or cache clearing.
```

Success prints `ha4-fastprobe: OK`, `terminals: N`, `policy: interval=I timeout=T`
and the manifest name. `--check` also prints `manifest: ...`. The 60 s/5000 ms
reference is the HA-03 `<name>-hac.yaml` itself (left untouched); do not
generate a 60 s HA-04 variant.

Policy values are exactly `{3,5,10}` s and `{1000,2000,5000}` ms. The matrix is
generated into separate output directories (for example `i3-t1000` … `i10-t5000`);
the manifest name includes the policy so cells cannot be confused.

## Manifest

`ha4-fastprobe-<version>-i<I>-t<T>.json` records: schema/tool/config version,
the HA-03 source manifest name + SHA-256 + schema + config version, the exact
policy (`group`, `interval`, `timeout`, `lazy: false`, `expected_status: "204"`,
`generic_defaults_preserved: true`, node order), the permission gate, per
terminal: name, A/B group, physical primary/backup role, source HA-03 file name
and SHA-256, output file name/SHA-256/bytes, and the rollback file list. It
contains no addresses, UUIDs, passwords or profile bodies. Protect it like the
profile files.

The manifest is a local trusted record, not a cryptographic authenticity claim.
The authoritative preflight is the re-derivation chain above (HA-02 bytes →
HA-03 bytes → HA-04 bytes); a local operator who rewrites every input and every
recorded hash consistently is inside the trust boundary and is not defended
against.

## Matrix and measurement contract (for the #92 operator run)

The full comparison is `interval ∈ {3,5,10}` × `timeout ∈ {1000,2000,5000}`
(9 cells) plus the shipped `60 s/5000 ms` reference, for A-first **and** B-first
groups, with `lazy: false` on all four candidates. Follow the acceptance
contract markers and matrix; in particular:

- **T0** injector acknowledgement **plus an independent effect check** (a
  button/command alone is not T0).
- **T1** first client observation of the failure/degradation (timestamped
  health-check/selection evidence), absent detection is UNKNOWN, not invented.
- **T2** first fresh connection through the intended surviving candidate, with
  path/chain attribution; a reused keep-alive or a cached page is not T2.
- **T3** earliest verified usable application service — the three real apps are
  HA-05 evidence; loopback LAB has **no T3** and must never report one.
- Report T0→T1, T0→T2 and T0→T3 separately; do not mix "fault→new surviving
  route" with "fault→recovered original candidate".
- A configured interval is not a recovery guarantee. For a ≤10 s claim the
  measured elapsed time including its uncertainty bound must be ≤10 s.
- Record false positives, switch counts and a predeclared switch-rate limit and
  observation window; repeated switching is a finding, not a pass.
- `max-failed-times` is not a consecutive-failure switch threshold and must not
  be presented as one.
- Test faults at different phases of the probe interval, including just after a
  successful check, and both "connection refused" and timeout/blackhole.

Required behavior rows include: Reality TCP-only failure; HY2 UDP-only failure
(single port vs whole configured hopping range); whole-VPS outage; other-VPS
takeover; recovery/failback; a second fault during recovery; both VPSes
unavailable; probe-endpoint failure while the business path works; historical
manual pins; and N02 (204 healthy while upload is degraded). A green node or a
204 response is reachability only, never application acceptance.

## Loopback LAB harness (operator tool, not CI)

`tests/mihomo-competition-ha4-lab.py` reproduces the offline mechanics on one
host: it builds a synthetic A/B loopback fixture **through the three repo tools**
(HA-02 batch → HA-03 profile → HA-04 variant), starts four real sing-box
listeners standing in for the two VPSes (REALITY TCP and Hysteria2 UDP per VPS,
plus the A-side HY2 hopping range), a loopback 204/probe/hold origin and REALITY
handshake target, and runs pinned Mihomo clients against the generated variants.
It requires the operator to supply hash-pinned binaries:

```sh
export HA04_MIHOMO=/path/to/mihomo          # pinned Mihomo (v1.19.31)
export HA04_SINGBOX=/path/to/sing-box       # pinned sing-box (v1.14.3)
python3 tests/mihomo-competition-ha4-lab.py --scenario all \
  --lab-dir .scratch/ha04-lab
```

`--scenario` supports `fixture`, `matrix-a`, `matrix-b`, `hy2`, `hopping`,
`outage`, `failback`, `n02`, `all`; `--repeats 1..5` repeats matrix cells. It
binds loopback only, refuses busy ports or a binary hash mismatch, and writes
raw `results.json`/event logs under the lab dir. It is an operator LAB tool, not
a CI test: it needs the real binaries, ~10 minutes and local ports
24000-24293, and it has no application/T3 hook. See the
[LAB evidence](mihomo-competition-ha4-lab-evidence.md) for the measured result
and its explicit limits.

## HY2 recovery and the ~30 s QUIC effect

Mihomo keeps one long-lived Hysteria2 QUIC connection per outbound. When the
HY2 server restarts, the client's stale connection state dominates: the member
can stay unusable for about the QUIC idle timeout (~30 s) after the first
post-fault ack-eliciting send, almost independent of the health `interval` or
`timeout`. Therefore:

- record **fault→recovered-candidate** and **fault→new surviving route**
  separately; the ~30 s window is not automatically a ~30 s business outage;
- the listener being up again is not availability; never claim recovery from
  the server process alone;
- do not patch Mihomo source or restart the whole client automatically as a
  mitigation. A client/core restart is an explicit operator action row only;
- test a second fault during the recovery window (it must not leave a dead
  node selected or claim false recovery).

## Probe-endpoint and false-positive control

Use an owned/approved health origin, never a third-party URL. `unified-delay:
true` issues a second HEAD request on the same keep-alive connection, so the
origin must support repeated HEAD with 204 and keep-alive. Loopback LAB has
~1–7 ms RTT and cannot measure real-WAN false positives or 30-client load; only
the mechanics transfer. Real false-positive/switch-rate and probe-load rows are
BLOCKED until authorized WAN/VPS resources are used.

## N02: 204 healthy while upload is degraded

A successful health GET/HEAD says nothing about per-flow upload quality; a
blackholed upload can leave the native `自动选择` on the affected path with zero
switches. HA-04 does not add a quality controller and does not enable PR-48B.
The tested disposition stays: record N02 as NOT DETECTED by native liveness,
provide the documented manual/application contingency, and hand the measurement
plus any proposed scope exclusion to HA-06. A 204 or a hard-failure PASS gives
no automatic quality verdict.

## Failure handling and rollback

Fixed codes on stderr, exit 1 (`E_USAGE` exits 2):

| Code | Meaning |
| --- | --- |
| `E_DELIVERY` | HA-03/HA-04 manifest missing/ambiguous/duplicate-key/invalid names, counts, roles or file set; different source manifest |
| `E_DELIVERY_HASH` | HA-02/HA-03 source profile or HA-04 output no longer matches its recorded size/SHA-256 (`role=source-manifest` for a different HA-03 manifest) |
| `E_TRANSFORM` | source is not the expected generic shape, the variant is not the byte-exact deterministic overlay of the trusted HA-03 source, or a security invariant fails |
| `E_OUTPUT_EXISTS` | target variant or manifest already exists (case-insensitive) |
| `E_PATH_CONFLICT` | missing/linked/junction directory, output inside an input directory, unsafe boundary, or casefold-duplicate output name |
| `E_INSECURE_PERMISSIONS` | POSIX owner/mode, Windows ACL allowlist, boundary or temp-inheritance failure |
| `E_IO` | write/verify failure |
| `E_TOOL_MISSING` | the HA-03 tool/batch helper could not be loaded (install/clone is incomplete) |
| `E_USAGE` | bad arguments/policy/version, `--check` without `--source-delivery`, or `--source-delivery` in generation mode |

All targets are prevalidated before any write; writes are atomic no-clobber;
outputs and the manifest are read back, permission-checked and hash-verified;
on partial failure only files this run created are deleted after re-checking
identity and bytes. Nothing pre-existing is touched.

## What is verified, and what is not

Verified by the hermetic contract suite: exact two-line overlay and byte identity
of every other line; A-first/B-first mapping preserved; 9-policy matrix; 1/2/30
terminal batches; manifest source binding; HA-03 source tamper/new-source
refusal; re-hashed extra listener/interval/LAN/skip-cert tamper refusal;
casefold/uppercase file-set gates; permission and path gates; overlay shape
refusals; partial-write rollback; pinned-core load of 39 generated variants.

**Not verified here (BLOCKED on operator resources):** the real Windows
PC + Clash Verge Rev + its bundled Mihomo version; real VPS/WAN RTT, ISP/GFW
behaviour and real UDP port hopping; real false-positive/switch-rate/probe load
at 30 clients; TUN/DNS/UDP/effective paths; T3 application recovery; 30-client
capacity. Loopback LAB results are mechanics evidence only and never fleet or
application acceptance.
