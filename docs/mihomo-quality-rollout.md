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
