# Daily Clash quality window (issue #48, opt-in trial)

This entry follows the successful seven-stage single-VPS isolated operator
pilot. It adds deliberate integration with the operator's existing Clash Verge
core. It is not installed, started automatically or enabled by default.
The isolated pilot does not substitute for daily-core/application acceptance.

## Three actions

1. Keep the existing controlled receiver running. The pilot receiver is a
   foreground process with a seven-day IP-SAN certificate; it is temporary.
   Resume that receiver using the already paired local files. No new certificate,
   trust installation, firewall or Windows administrator operation is needed.
2. Open the quality window, generate a private profile from the original
   server-download `NAME-mihomo.yaml` and paired `receiver-info.json`/CA.
   An independent second VPS export is optional. Copy the displayed profile path,
   then **import and activate it in Clash**. Keep the original profile for return.
   Existing source files, manual/default group meanings and HY2 hopping survive.
3. Click **Start observation**. This only observes and requests a bounded initial
   upload confirmation. When both paths show a positive upload confirmation,
   manually choose `质量自动选择` in Clash: under `节点选择` for rule
   mode, or directly in the global proxy selection for global mode. Then click
   **Enable quality switching**. Confirmation expires; stale or missing facts
   refuse enable. `Check upload` requests another bounded confirmation window.

The GUI command (Python 3.10+, Tk, standard library) is:

```sh
python3 -B tools/mihomo-quality-client.py --workspace /private/quality-workspace
```

On Windows, the default Clash home is the official APPDATA Clash Verge directory.
`--clash-home`, `--primary`, and `--receiver-info` can be supplied explicitly.
Prepared files are reused when reopening; there is no need to generate again.
The workspace must be new or marked as this tool's workspace. Windows creation
sets only that new directory's ACL to the current user and SYSTEM. No machine
trust, service, TUN, startup setting or original configuration is modified.
Never upload the private workspace or generated YAML: they contain credentials.

## Scope and limits

- A unique hidden DIRECT-only profile marker and exact expected group/node types
  identify the generated loaded profile. Another profile is refused before
  control, including on fresh reads before selection and restoration.
- The existing authenticated numeric-loopback controller settings are read afresh
  on each start, used only in memory, and not copied into the saved client bundle.
  Verge's existing nonempty short secret is supported; authentication is neither
  disabled nor rewritten. Empty/unsafe secrets and nonloopback addresses fail.
- Current routing mode is read around the proxy snapshot and checked again
  before mutations. Rule mode uses `节点选择`; global mode uses `GLOBAL`.
  An unused remembered choice in the other mode cannot override active opt-in.
  Direct/unknown mode or an observed mode change refuses control; mode changes
  and global/manual selections are never written by the window.
- Only the added hidden quality group is writable. The outer/legacy groups are
  read-only. Manually choosing another outer node pauses quality decisions.
  Reloading another profile or changing ownership prevents clearing its choice.
  A per-bundle lock refuses duplicate windows. Concurrent external writers or
  copied duplicate bundles are unsupported: one writer owns the internal group.
- Initial or explicit confirmation is bounded to 90 seconds and stops early
  once all participating paths have fresh positive confirmations. It is not a
  permanent background speed test. Passive suspicion/recovery still follows
  the existing runtime contract. Defaults: fail below 4Mbps, recover at least
  8Mbps, two-minute hold, 512KiB/request, 30s/path spacing, 2MiB/min aggregate
  payload, 20Mbps send cap and 6s request deadline. Site thresholds need review.
- Stop waits for the current bounded request and clears only an exact owned
  temporary quality choice. It never closes existing application connections.
  The GUI reports when restoration could not be confirmed; select the original
  `自动选择` policy or activate the original profile to return manually.
- One atomic bounded `state.json` records the latest session/progress; it does
  not append history, raw connections, controller secrets or receiver tokens.
  Failure to save state requests stop and still attempts owned restoration.
- Normal-core quality/application behavior has not yet been accepted. The
  temporary receiver's availability/resources are part of the measured path;
  a result cannot establish provider/ISP/application root cause. Independent
  providers, real outages, fleet sizing and long-lived deployment remain separate.

## Verification

`tests/test_quality_daily.py`: 34 hermetic contracts covering preparation,
source preservation, credential handling, profile identity, observe-first enable,
rule/global routing and manual precedence, direct/unknown refusal, stop/failure restoration, locking and bounded receipts.
Existing quality/pilot suites remain required. Python 3.10 syntax is retained.

`tests/mihomo-quality-daily-lab.py` is an explicit supplied-digest real-Mihomo
API smoke check. It uses a disposable loopback-only core and synthetic fixtures;
it downloads nothing and never touches live Clash. The CA is mocked solely for
offline preparation, so this is not TLS/throughput acceptance. It checks real
profile marker/type shape, refusal of a foreign marker, dedicated selection and
restoration. The seven-stage operator pilot separately exercised real TLS and
both actual protocols through the existing VPS.

## Retain the current healthy protocol

The running enabled worker holds the current protocol while it remains healthy.
It switches only after that current protocol is confirmed degraded or down, to
a freshly verified alternative. Recovery of a former protocol does not switch
back. The two-minute hold confirms standby recovery for a later failure, not
a scheduled return. Native fallback selections are latched in the dedicated
group to prevent priority-based failback while the worker runs.

Explicit stop still clears only the worker's exact owned pin and returns the
group to native fallback policy. Manual outer/global selections remain prior
to automatic control. A stopped/crashed worker cannot promise sticky quality
control; native hard-failure fallback remains available.

The normal daily session proves profile identification, explicit enable and
normal upload confirmation only. Actual switching is verified separately in
disposable cores; no natural daily/application fault is inferred from uptime.

## Idle traffic and upload status

The 4 Mbps failure threshold compares a bounded active test upload, not the
application traffic counter. Zero demand is never a quality fault. Passive traffic
changes can request confirmation, but cannot directly degrade a protocol. Two
consecutive authenticated bad uploads are needed for a quality fault, and a switch
requires a freshly upload-confirmed usable alternative. Missing receiver evidence
is unknown; a failed native connection probe can independently mark a path down.

The window reports recent confirmed test quality, consecutive slow tests, hard
connection failure or an unconfirmed upload. After the last positive upload ages
out, it reports connection reachability without claiming current upload quality.
No scheduled upload on an idle tick is a missing observation, not a failed test.
A healthy current protocol is retained; standby recovery is not a switch-back timer.

For an explicitly installed receiver that survives VPS reboot and renews its leaf
certificate, see [persistent receiver](mihomo-quality-receiver-service.md).
