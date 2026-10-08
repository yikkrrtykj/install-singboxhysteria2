# Protocol-quality failover (issue #48, PR-48B)

Status: opt-in pilot implementation. No installer, auto-start, live deployment,
Windows-agent change, Monitor-classifier change or firewall change is included.
The existing offline multi-VPS merge remains unchanged. Real Reality/HY2,
two independent providers and production thresholds are operator acceptance
items; loopback relay results below do not prove those items.

## Decision and topology

The built-in 204 probe remains the hard-failure signal. A passing small request
does not measure sustained upstream quality. This tool first reads bounded
connection-counter/churn evidence. Suspected degradation triggers a bounded
upload through a node-specific listener to a controlled HTTPS receiver. Both
protocols use the same model, independently:

- UP: currently reachable (the reason distinguishes reachable-only from
  upload-confirmed-good).
- DEGRADED: consecutive bad upload confirmations, or recovery still pending.
- DOWN: a fresh native reachability failure.
- UNKNOWN: missing/stale/invalid reachability evidence. This never means DOWN.

A switch destination must be UP **with a fresh positive upload confirmation**.
Low application demand alone never marks a path degraded. A drop after a recent
active-upload baseline only requests confirmation; a passing confirmation keeps
the path UP. Disappearing connections alone do not imply churn. Recovery needs
the configured hold-down **and** consecutive passing confirmations. Missing or
middle-band active results break the consecutive series; a cadence tick with no
scheduled test does not.

Priority is the existing order: Reality, Hysteria2, Backup-Reality,
Backup-Hysteria2. Each path has its own thresholds and recovery state. No
permanent "HY2 is safe" assumption and no coarse VPS boolean is introduced.

The prepared opt-in profile adds a hidden `质量自动选择` **fallback** group
with the same 60s/5000ms/lazy:false/204 policy and the same member order.
It also adds that group as an extra outer choice. Original `节点选择`,
`自动选择`, defaults, members, saved selections and rules retain their meaning.
The old default remains `自动选择`: the operator explicitly selects
`质量自动选择` to use the new feature. No existing manual pin is auto-released.
Hopping fields stay exactly as exported.

Only the new hidden group is writable. Quality switching temporarily fixes that
group to a verified alternative; recovery to the preferred path clears only
that group's fixed selection. Native fallback continues handling a fixed
member's **hard** failure even if the worker is absent. Normal worker exit
clears its own fixed selection, preserving the outer choice and both original
groups. Established connections are never closed or migrated.

A dedicated selector was rejected during local review because it would keep a
dead fixed member after worker exit; the new fallback preserves native
hard-failure continuity. Quality decisions require a running worker; a crashed
worker cannot detect a later quality-only failure. On worker restart an
unrecognised cached quality pin suspends control instead of claiming ownership.
The original automatic outer choice remains a reversible escape hatch.

## Operator commands (Python 3.10+, standard library)

Files below contain credentials and must stay in an operator-private folder,
outside the repository. They are never source-controlled.

1. Independently create/export the same logical client on each participating
   VPS. Use the existing canonical export, with independent credentials.
2. Review copies of `docs/examples/quality-client.example.json` and
   `quality-receiver.example.json`. Replace sample tokens and addresses
   locally; set each site's fail/recover thresholds explicitly. The client
   example starts with `control_enabled:false`.
3. Prepare a new file, without modifying the original export:

```sh
python3 tools/mihomo-quality-failover.py prepare --config /private/client.json \
  --name event --primary /private/A/event-mihomo.yaml \
  --backup /private/B/event-mihomo.yaml --output /private/event-quality.yaml
```

Omit `--backup` for two paths. The configuration's paths must match that mode.
The original canonical parser/provenance/source/credential gates are reused.
Output is no-clobber, through the merge tool's private same-directory temporary
file. On POSIX, configuration must be owner-only and output is 0600. Windows
uses directory ACL inheritance: use a private user folder; this tool does not
change machine ACLs or install trust. No source YAML or secret is printed.

4. Explicitly deploy the separate receiver on the controlled VPS, with an
   operator-supplied certificate/key and an **IP SAN** certificate trusted by
   the client's configured CA. No certificate generation, port opening,
   reverse proxy, service installation or deployment is automatic:

```sh
python3 tools/mihomo-quality-failover.py receiver --config /private/receiver.json
```

5. Import the new profile intentionally, retain the existing Clash controller
   configuration, and start in observation mode:

```sh
python3 tools/mihomo-quality-failover.py run --config /private/client.json
```

`--once --confirm` performs one explicitly requested bounded confirmation
cycle. It is observation-only while `control_enabled:false`. Review its closed
JSON state records before setting `control_enabled:true` and selecting the new
outer choice. No production setting is enabled by these instructions alone.

Normal stop is Ctrl+C. Return the outer choice to `自动选择` to use the previous
policy. There is no automatic cross-VPS lifecycle or credential cleanup.

## Probe contract and traffic limits

- Two or four distinct loopback SOCKS listeners are generated, one per node,
  using Mihomo's named inbound `proxy` field. No mutation of global selection
  is used to force a test.
- Before a ready/upload request sends auth or body, the worker matches that
  socket's source port in authenticated `/connections` telemetry: inbound
  name, controlled destination, specialProxy and actual chain must all match
  the requested node. Missing/ambiguous/mismatched attribution is UNKNOWN.
  The local controller/core and prepared profile are trusted.
- Probe URL is HTTPS with a numeric IP, no userinfo, arbitrary path, query or
  redirect. Numeric IP avoids an unbounded DNS-resolution stage. TLS hostname/IP
  verification stays enabled. There is no insecure certificate bypass.
- Ready and upload use a bearer token in headers, a random nonce and an exact
  body-size/SHA-256 receipt. Credentials never occur in argv, stdout, errors,
  audit or request URL. The receiver hashes streaming bytes and discards them.
- Completed uploads use the receiver's body-arrival interval after the first
  chunk, excluding connection setup and acknowledgement RTT. The measured byte
  count/time are closed-validated. Buffer bursts are capped at the configured
  sending rate. This is a small path-quality observation, not a full-bandwidth
  Speedtest or proof of application throughput.
- An upload-phase deadline after a verified ready response is a bad
  confirmation; setup/TLS/route/receipt failures or unavailable receiver yield
  UNKNOWN. Two bad confirmations are required by the example; one failure
  cannot switch quality state.
- Request deadline <=15s; payload <=1MiB; send cap <=100Mbps. The configured cap
  must exceed the recovery threshold by at least 1.5x. Per-path probe spacing
  is >=30s. A sliding, aggregate client payload budget is <=4MiB/minute.
  Even failed attempts reserve their full payload allowance conservatively.
  The example uses 512KiB per attempt and 2MiB/minute aggregate (~0.28Mbps
  payload average at the limit), **only on suspicion/recovery/explicit test**.
  TLS/ready/controller overhead is outside the payload budget.
- The receiver has two admitted connections, a hard per-connection lifetime,
  streaming 8KiB chunks, a per-minute byte ceiling and no request/body/peer
  logs. Unsupported methods, duplicate/framing headers, wrong tokens/nonces
  and over-budget bodies are refused. A busy receiver never becomes a DOWN
  verdict. Fleet capacity and per-device fairness need separate sizing; this
  first receiver is a bounded pilot sink, not an unbounded fleet service.

A controlled VPS may itself be busy. The observation concerns the forced
client-to-receiver path, including its endpoint; it does not prove ISP,
transport, CPU or application root cause. #33 may later join these records
with contemporaneous host evidence. This PR does not alter its classification
contract or ingest schema. Closed stdout JSON records contain state/reason,
suggested node, action and observation time; no connection IDs or raw metadata.

## Control ownership and failure boundaries

Controller access is authenticated, loopback-only, bounded to 1MiB/2s. Original
outer and legacy fallback groups are never written. Before every group
mutation, state is re-read: manual outer choices/legacy fixed selections pause
control; changed dedicated-group shape/foreign fixed selection suspends it.
Normal exit only unfixes an exact owned selection in the dedicated group.
Native clear-on-hard-failure is recognised without taking over a foreign pin.

Mihomo has no compare-and-swap selection operation. The new hidden group has
**one authorised writer**; simultaneous writers to that internal group are
unsupported, and a same-value write cannot be identified as another writer.
This is why original manually selectable groups are not commandeered.
A timed-out mutation may have been accepted: next-read ownership disagreement
suspends control rather than blindly retrying or clearing an unknown pin.

## Verification and remaining acceptance

`python3 -B tests/test_quality_failover.py` is hermetic CI coverage of policy,
budgets, closed receipts, controller ownership, stale telemetry, low-demand
negative controls, canonical profile generation, hopping and receiver framing.

`tests/mihomo-quality-runtime-lab.py` is explicitly opt-in, requires a supplied
SHA-256-pinned Mihomo binary and local OpenSSL, and downloads nothing. It starts
only disposable loopback services. Generated group/listener lines are real;
Reality/HY2 are represented by SOCKS relays and native probe cadence is scaled
to 1s. Policy clocks are supplied deterministically for hold/recovery checks.
The ordinary renderer/merge policy stays 60s.

Local pinned-core lab: v1.19.31, binary digest
`deef9d8d34152e29941840df1d339b72ed71ec0dd460c2f2db572c1db231c8bf`.
It covers passing liveness + upload shaping, symmetric hard failure, forced
route independent of DIRECT/other nodes, ownership, recovery, normal cache
restart, native fallback without worker intervention, and old/new connections.

Remaining real-environment acceptance is deliberately unchecked:
- [ ] Actual Reality/HY2 interoperability and per-site threshold calibration.
- [ ] Receiver deployment/capacity/resource-health review.
- [ ] Two genuinely independent providers/paths and real common-VPS outage.
- [ ] Live application quality incident and quiet-uplink negative control.
- [ ] Real HY2 loss/churn/broad UDP restriction versus single-port hopping.
- [ ] Safe operator UX/package integration after the pilot is accepted.
- [ ] Optional #33 quality-state ingest/UI contract, separate from current schema.

Do not close #48 or claim production failover accepted from loopback tests.
