# #48 isolated operator pilot

This entry tests an existing canonical two-protocol export using a **separate
Mihomo process**. It does not attach to Clash Verge, import a profile into the
user's application, modify its controller, change TUN/system proxy/autostart,
install a service or stop sing-box. Use `tools/mihomo-quality-pilot.py`.

## Explicit receiver preparation

On the controlled receiver VPS, Python 3.10 and OpenSSL must be available.
Copy the source tool directory, then explicitly run:

```sh
python3 tools/mihomo-quality-pilot.py receiver-init \
  --directory /root/p48-pilot-private --ip YOUR_NUMERIC_VPS_IP --port 8448
python3 tools/mihomo-quality-failover.py receiver \
  --config /root/p48-pilot-private/receiver.json
```

The first command refuses an existing directory and creates owner-only files.
It prepares, but does not start/bind, the receiver. The second command starts a
foreground bounded receiver. Stop it with Ctrl+C. Check the chosen port is free
and reachable first; this tool does not open a firewall or create a systemd unit.

The certificate has an IP SAN and is valid for **seven days**. It is trusted
only through the pilot's CA file. This is unrelated to the company's Windows
code-signing certificate and does not change any machine-wide trust store.
For another run after expiry use a fresh private directory and copy the new
connection files together; do not reuse an expired certificate or bypass TLS.

Copy only `receiver-info.json` and `receiver-ca.pem` to a private client folder
over the existing authenticated SSH connection. The info file contains a
receiver token: it is **not public**, must stay owner-only, and must not be
uploaded to GitHub or pasted in chat. Do not copy the receiver's private key.

## Single client entry

Supply an existing, independently SHA-256-verified Mihomo binary. The tool does
not download a binary. Keep the original canonical `NAME-mihomo.yaml` export
unchanged and create a local results directory.

```sh
python3 tools/mihomo-quality-pilot.py gui \
  --mihomo /private/mihomo --expect-sha256 VERIFIED_BINARY_SHA256 \
  --results /private/results
```

The window asks for just the canonical YAML and receiver-info file. Put the CA
beside the latter under the filename `receiver-ca.pem`. Click **开始一轮检查**.
No Clash controller key is needed: the disposable core receives its own random
loopback controller secret. Python tkinter is needed only for the GUI; CLI and
VPS receiver use Python's standard library without tkinter.

For an operator who prefers the CLI:

```sh
python3 tools/mihomo-quality-pilot.py run \
  --mihomo /private/mihomo --expect-sha256 VERIFIED_BINARY_SHA256 \
  --profile /private/event-mihomo.yaml --name event \
  --receiver-info /private/receiver-info.json --ca /private/receiver-ca.pem \
  --result /private/results/new-run.json
```

Results are no-clobber owner-only JSON. Normal stop, cancellation and exceptions
terminate only the owned disposable core, stop its loopback relays, then remove
its secret temporary profile. A cleanup failure never yields PASS. The window
remains open while cancellation is being handled, and shows the result location.
OS-level forced termination/power loss is outside the graceful-cleanup contract;
none of the pilot's state is installed into the normal application or autostart.

## What the whole round does

1. Require fresh **actual** native probe history and positive upload confirmation
   for both protocols. A startup default `alive:true`, stale history or receiver
   failure cannot count as a normal baseline. Insufficient baseline stops early.
2. Limit the disposable Reality TCP wire to 1 Mbps, preserving small-request
   reachability. Require consecutive bad upload confirmations and healthy HY2,
   then verify the dedicated group's effective selection is HY2.
3. Remove that limit. Require hold-down and three consecutive passing upload
   confirmations; verify Reality becomes eligible but the healthy current
   Hysteria2 remains selected and fixed. No automatic failback is allowed.
4. Hold one bounded authenticated upload across a selection change. Verify its
   Reality chain persists, a new flow follows HY2, and the original upload completes.
5. Drop only the disposable HY2 UDP relay. Require fresh native DOWN evidence,
   successful Reality upload and actual fallback to Reality.
6. Restore UDP forwarding and verify HY2 recovery while Reality stays selected
   and fixed. Explicitly choose Reality in
   the disposable outer group and verify the worker reports manual override.
7. Stop the disposable core/relays and save the closed stage report.

The test uses the original Reality UUID/public key/servername and HY2 credentials/
SNI; it forwards actual encrypted protocol bytes to the configured numeric VPS.
No SOCKS proxy is substituted for those protocol nodes in this operator entry.
Only the disposable copy maps their server/port to loopback relays. HY2 hopping
retains the range width, ordering and interval with an equally sized local range;
up to 128 hopping ports are supported by one select loop. Wider ranges are
refused rather than silently disabling hopping. The original export is unchanged.

The disposable profile explicitly disables TUN/DNS listeners/LAN binding and uses
only a MATCH rule. It does not request geo-database downloads. Test sockets use
OS routing, so an already active TUN may still carry their outer connections;
the result is for that current environment, not proof of an independent ISP path.

The round normally takes about **5–8 minutes**. Wall-clock per-path probe spacing
remains >=30s, payload <=512KiB per confirmation, aggregate payload <=4MiB/minute,
request deadline <=15s, and sender cap 20Mbps. The recovery hold is 30s only in
this disposable pilot; the normal example's 120s policy is unchanged. Its native
probe refresh is 5s only in the disposable core, not in exported production groups.

Default thresholds are fail=4Mbps and recover=8Mbps. These are pilot assumptions,
not production calibration. CLI `--fail-mbps` / `--recover-mbps` may be supplied
within the validated bounds. Low real-site bandwidth fails baseline instead of
automatically lowering the acceptance bar. Ordinary low application demand is
not the fault signal: this round explicitly requests bounded confirmations.

## Evidence boundaries

The local wire impairments are deliberate simulations through real protocol
implementations. They prove switching mechanics in the tested environment,
**not** real provider outages, application incidents, root cause, fleet capacity
or two independent VPS routes. Quality-only HY2 impairment/loss/churn and real
hopping under Internet loss remain separate operator acceptance items. #48 stays
open for the agreed real-environment acceptance. The opt-in implementation was
merged in PR #76; that merge does not establish real application/HA acceptance.

`tests/test_quality_pilot.py` covers isolated configuration, private preparation,
byte-preserving TCP/UDP relays, hopping mappings, cancellation, no-clobber output,
startup history and failure cleanup without external services.

`tests/mihomo-quality-pilot-lab.py` accepts supplied SHA-pinned Mihomo/OpenSSL.
It starts two disposable cores with genuine VLESS Reality and genuine Hysteria2
loopback endpoints, a TLS sink and a 204 origin. No external traffic is requested.
`--quick` advances only lab policy pauses; the operator tool has no such switch.
Run without it to verify real waiting intervals and budgets:

```sh
python3 tests/mihomo-quality-pilot-lab.py --mihomo /private/mihomo \
  --expect-sha256 VERIFIED_BINARY_SHA256 --openssl /usr/bin/openssl
```

This supplements, and does not replace, the earlier SOCKS-mock kernel lab.

The sticky policy is `retain_healthy_current`. The local two-core lab can also
exercise the daily identified-controller and ownership adapter with
`--daily-mode global` or `--daily-mode rule`; it never attaches to live Clash.
`--quick` advances only the local lab policy clock, not operator pilot waits.
