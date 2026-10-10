# Windows quality switching EXE

This is a separate portable quality-switching app, not the P6 monitoring service.
It runs as the logged-in user without installing services or changing TUN,
startup settings, profiles, the outer selection or system certificate trust.
It supports the single-VPS Reality/Hysteria2 recipient package. Multi-VPS quality
switching remains a separate acceptance scope.

## Recipient workflow

1. Fully extract the administrator-provided ZIP and open `质量切换.exe`.
2. Keep Clash Verge running and click **开启质量切换**.
3. On first use the app prepares a profile in the user's private local app-data
   directory. Click **打开 Clash 配置文件夹**, import the `NAME-quality.yaml`
   file in Clash, activate it and select `质量自动选择` in the active routing mode.
4. Click **开启质量切换** again. The explicit request starts bounded initial
   upload checks and enables control only after both fresh positive confirmations
   and the existing identified-profile/selection checks pass.

Later starts reuse the local prepared profile and need one start click. There are
no path pickers, secret fields or threshold fields. No switching starts on launch.
Keep the window open or minimized while using quality control. Stop or close
waits for the worker's bounded request and ownership-aware restoration.

Idle traffic is not a slow upload. Healthy current protocols are retained;
recovery of the former protocol never schedules failback. Manual choices remain
prior. Unconfirmed initial uploads do not enable control and show a retry hint
after the bounded confirmation period. A stopped/crashed app cannot promise
sticky quality control; Clash native fallback remains available.

## Build and company signing

Use native Windows x64 Python with Tk and install the pinned
`tools/quality-windows-build-requirements.txt`. Run:

```
python -B tools/build-quality-windows.py --output <new-build-directory>
```

The result is `software/质量切换.exe`, containing Python, Tk and application
code, with no receiver token, YAML, local controller secret or operator paths.
The unsigned build is not a release. Sign it using the existing fixed company
certificate with `windows/Sign-Quality.ps1 -Executable <exe>`; signing requires
no certificate export or trust-store mutation. The publisher certificate stays
in the administrator's certificate store. Company signing does not guarantee
that an unprepared employee computer has no Windows trust/SmartScreen prompt.

## Administrator-local recipient packaging

```
python -B tools/package-quality-windows.py --exe <signed-exe> --yaml <NAME-mihomo.yaml> --receiver-info <receiver-info.json> --output <new-recipient.zip>
```

The CA must be adjacent to the receiver-info file. The builder requires a valid
timestamped signature from the fixed company publisher, canonical server-export
YAML and an exactly paired receiver token/CA. It emits an EXE, that recipient's
original YAML, receiver-info/CA, a bounded hash descriptor and plain instructions.
The ZIP contains credentials and must be delivered privately. Software can be
identical for all users; configuration packages must be prepared for each user.
Never distribute the administrator's prepared workspace or account to colleagues.

The app resolves inputs relative to its EXE, not current directory or the build
computer. Its private per-user state identity binds the input hashes; moving the
extracted directory does not change it, while new recipient/receiver inputs use
independent state. File names, digests, canonical exports and CA pairing are
validated before any controller contact. A lone EXE gives a visible extraction
hint. It cannot request secrets or SSH credentials from the recipient.

## Acceptance and delivery boundary

Native Windows build acceptance runs the actual frozen EXE with a relocated
synthetic recipient bundle, Windows-only PATH and no PYTHONPATH/PYTHONHOME.
`--self-check <new-report.json>` is a closed build diagnostic: it checks adjacent
pairing, dynamically bundled code and Tk, without a workspace, sampling or any
controller request. It never writes raw configuration into the report.

The existing 9191 P6 Windows download is unchanged by this EXE builder. Uploading
and adding a new authenticated quality-package download remain a server release
step; no employee should be told the old download already includes this tool.
The current receiver's shared admission/byte budget was accepted for one pilot
computer. A multi-user rollout requires separate concurrent-capacity acceptance
and per-user receiver credential management; packaging alone does not prove it.
