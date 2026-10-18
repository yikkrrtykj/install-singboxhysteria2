# Quality app distribution: two-device pilot

The Monitor device panel offers a separate **下载质量切换 EXE 包** action. The existing monitoring-agent installer remains separate. Quality control requires Clash and the app window to remain open; it installs no client service or startup entry.

The user unpacks the complete ZIP, opens the signed app and clicks **开启质量切换**. On first use they import the newly generated profile, choose **质量自动选择** in Clash global mode and click start again. Profiles expose only Reality, Hysteria2 and the quality group (plus Clash's built-in DIRECT/REJECT). A unique `global-ua` identifies the loaded profile; both configuration reads must match before the quality group can be written. Rule-mode use validates the generated rule list and routes directly to that group. The app never selects GLOBAL, changes mode, rewrites DNS/TUN or closes existing connections.

## Administrator flow

1. Build the generic EXE with `tools/build-quality-windows.py` and sign using `windows/Sign-Quality.ps1`.
2. On Windows run `tools/build-quality-publication.py --exe <signed executable> --output <new directory>`. This verifies the fixed company publisher and timestamp. Input contains software and third-party licenses, no client secrets.
3. Transfer that input to the existing VPS and verify its exact transfer digest. Install the reviewed receiver source including `fleet.py`; do not replace TLS keys, service identities or firewall settings.
4. Prepare a root-private bindings file: a JSON list of one or two `{name, device}` objects already registered and confirmed active in Monitor. Keep the existing operator device first on first publication. Then run the exact merged `tools/publish-quality-windows.py --input <verified input directory> --bindings <root-private file>` as root.
5. The publisher validates the live device registry, creates independent tokens, restarts only the quality receiver, checks TLS/authentication and activates the root-owned publication. Retry preserves the exact per-device tokens. It restores the old receiver configuration and publication pointer if validation fails.
6. In Monitor, download the complete quality ZIP from that device's row. Send only its own ZIP privately to the recipient. The ZIP includes the generic unchanged EXE, its own canonical proxy YAML, receiver connection pair, checksummed adjacent-file descriptor and licenses. Never upload recipient ZIPs to GitHub.

Unprepared devices fail closed before private YAML export. Downloads use the existing login, CSRF, origin, step-up and fresh management gates. Revoked monitoring devices cannot download a package. Software and private pairs are held and checked against the root publication before export; package generation uses an unlinked temporary file, bounded size and no-store headers.

## Capacity and separate permissions

This is **two prepared devices maximum**, not a fleet deployment. Each has 2 MiB/min of admitted test payload and one simultaneous upload; the receiver retains a 4 MiB/min aggregate and two TLS connections. Different tokens share no extra device quota. Its rate tests are capped at 20 Mbps and only occur on initial confirmation, suspected trouble or explicit upload check. Idle usage does not trigger failure.

The old operator token remains a compatibility alias of the first operator device and shares that device's quota. It is not distributed to coworkers. To cancel a coworker's quality-test access, republish with that coworker removed; the receiver reload drops their token. Canceling the Monitor evidence-upload permission alone does not revoke a previously downloaded quality-test token: these are distinct services. Removing the legacy operator requires an explicit compatibility-token migration, so this publisher refuses that operation.

The two-device quota is admission isolation, not a promise that this VPS always has enough bandwidth. Receiver overload, 429 responses and missing receipts are UNKNOWN, never direct throughput-failure evidence. Real application usage by one additional person and the VPS's measured capacity remain deployment acceptance steps. More users need a separate capacity increase and validation. Multi-VPS failover under issue #48 still requires an independently hosted backup VPS.

## BBR-compatible Windows release (manual approval required)

The compatibility build depends on PR #84, starting at
`efa4440bb0cc6da453d245c2cc20037315faf015`. Do not build this release from the
older main branch. Review the dependent EXE PR and #84 together; merge order is
#84 first, then the EXE PR after retargeting/rechecking its base. Neither a branch
push nor a CI run changes the existing Monitor download or a deployed HY2 config.

The existing strict canonical-export parser is reused, not replaced with a
general YAML loader. Complete administrator exports may omit HY2 bandwidth or
contain the exact historical paired `up/down: "300 Mbps"` lines. Both support
port hopping. Partial, custom, duplicate or malformed declarations remain errors.
Newly generated quality profiles always omit both bandwidth declarations, while
the input export, Reality credentials, HY2 password/SNI, hopping and routing rules
are preserved. Arbitrary hand-written YAML fragments are not complete packages.

### Build and accept before transferring anything

On the authorized Windows build machine, with the existing pinned PyInstaller
6.22.3, use a clean committed checkout and a new output directory:

```powershell
python -B tools/build-quality-windows.py --output <new-build-directory>
python -B tests/quality-windows-exe-lab.py --exe <new-build-directory>/software/质量切换.exe --build-receipt <new-build-directory>/build.json --report <new-unsigned-test-report.json>
powershell.exe -NoProfile -File windows/Sign-Quality.ps1 -Executable <new-build-directory>/software/质量切换.exe
python -B tests/quality-windows-exe-lab.py --exe <new-build-directory>/software/质量切换.exe --build-receipt <new-build-directory>/build.json --report <new-signed-test-report.json>
python -B tools/build-quality-publication.py --exe <new-build-directory>/software/质量切换.exe --output <new-publication-input>
```

`build.json` records the exact commit and dynamically bundled module digests. The
frozen diagnostic reads its embedded receipt and hashes the modules actually
extracted by PyInstaller; acceptance compares them with the checkout.
Acceptance also requires the receipt commit to equal the current clean tracked
checkout, and rechecks it before emitting success; matching parser hashes alone
cannot accept an older EXE containing different compiled modules. The external
Windows lab observes controller mutations and actual authenticated upload replies
instead of polling the app's mutable state file, so the test observer cannot
lock its atomic status replacement. Signing
changes the EXE's SHA256: retain both unsigned build and final signed acceptance
receipts. The build receipt deliberately remains `signed:false, publishable:false`;
only the unchanged Windows signature gate can create publication input.

Acceptance uses four complete synthetic packages (new/legacy × hopping/plain),
ZIP extraction to Chinese paths, Windows-only PATH and isolated APPDATA and
LOCALAPPDATA. It drives the actual child EXE's GUI buttons with targeted window
navigation keys; no global mouse/keyboard input or real Clash home is used. Real
authenticated TLS uploads go through loopback SOCKS relays to a disposable
receiver. A simulated local controller supplies liveness/route records and checks
that only the dedicated quality group is written. Tests cover switching on a
confirmed hard failure, retaining the healthy alternative after a full recovery
hold, and stop/restore. This does not claim to be a real Internet HY2 connection,
a physical Python-uninstalled machine, or production traffic/capacity acceptance.
It proves the packaged program needs no Python installed on its search path.
PR #84's separate real-core lab covers the HY2/Reality protocol change.

BBR is the new-deployment default, not a guarantee of equal or higher throughput
on every public network path. Neither lab proves the performance limit of a
specific Internet route or establishes that prior abnormal outbound traffic is
fixed. Treat any reported production-path slowdown as a separate measured
observation with its client/core versions, workload, duration and counters; do
not infer causality from TX/RX ratios or compatibility test success alone.

The fixed signer remains `92E0176599764946F7E5AB332A5CEF150355BE9B` with a
valid Authenticode signature and timestamp. If that certificate is unavailable,
stop at the explicitly unsigned test EXE. Do not create substitute certificates,
change trust stores, skip the signature gate, or publish a CI-built unsigned EXE.
No receipt or public CI artifact may contain recipient inputs or private keys.

### Maintenance-window publication and acceptance

1. Obtain explicit human approval for the exact signed EXE hash, merged source
   commit, maintenance window and devices. Retain the old signed EXE/software
   input and each old complete recipient ZIP privately.
2. Before publication, as root create a **root-only** backup of the existing
   publication `/var/lib/singbox-quality-distribution/current.json` and
   `/etc/singbox-quality-receiver/receiver.json`.
   Preserve the old immutable release directory and record its release ID.
   Confirm these configured paths in the reviewed source for this deployment;
   do not copy private receiver keys into the software input.
3. Transfer only `quality.exe`, `software.json`, `notices.txt` from the Windows
   signature-gated builder, checking every SHA256 after transfer. Use the exact
   approved merged publisher and the existing active device bindings. Do not
   rotate TLS/receiver keys or tokens as part of this software update.
4. Run the existing root publisher from the administrator flow above. **It
   restarts Quality Receiver even on a software update**; schedule that explicitly.
   No Monitor restart, HY2 reinstall, live proxy edit or production deployment is
   performed by the Windows build/acceptance process.
5. Log in to Monitor and download the device's complete **质量切换 EXE 包** again.
   Verify the extracted EXE's final SHA256, signer and timestamp on Windows.
   Check the three adjacent-file digests and receiver pairing with `--self-check`.
   Never replace just the EXE inside an old private ZIP as a substitute for
   generating a verified complete package.
6. On one approved non-streaming test client, keep its old export/profile and ZIP
   for rollback, import the new generated profile, explicitly select the quality
   group and enable it. Check both uploads, start/stop, and authorized controlled
   failure handling before distributing more device-specific ZIPs privately.

### Rollback

The root publisher automatically restores its previous receiver configuration
and publication pointer if its own activation checks fail. If later acceptance
fails, stop the new quality app on test clients; retain their original Clash
profile and switch back to it manually if necessary. Restore the old **complete**
recipient ZIP for clients that need the old app; do not feed a new BBR-only export
to the old parser.

During the approved maintenance window, use the saved root-private backup and
the publisher lock `/var/lib/singbox-quality-distribution/.publish.lock` to restore `current.json` atomically
to the retained old release. If `receiver.json` changed, restore its exact backup
with its original owner/mode and restart **only Quality Receiver**, then verify
TLS, existing device-token authentication and the old Monitor download hash.
Do not delete old immutable releases or change keys/certificates. A failure to
verify the old pair or receiver means stop and investigate, not regenerate tokens
or reinstall Monitor/sing-box. None of these rollback actions run automatically
from this PR or the local acceptance lab.
