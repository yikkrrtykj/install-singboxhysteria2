# Company-internal Windows release

Issue67 section22's company-only amendment is authoritative. No public CA,
SignPath application or commercial signing certificate is required for the
controlled company audience. Keep the existing production native signature,
exact publisher/catalog/file hash and timestamp gates.

## Once, on the administrator-controlled Windows build host

Use a reviewed checkout. Create a fixed code-signing identity with
`windows/New-InternalPublisher.ps1 -Output <new-directory> -Subject 'CN=Monitor Internal Client'`.
The two-year RSA3072 private key stays nonexportable in that administrator's
CurrentUser/My store. Output contains only publisher.cer and publisher.json.
Existing output is refused; ordinary updates use the recorded publisher, never
create a new certificate. An explicit ExistingThumbprint can recover public
material from that same still-present identity into a new directory.

The public SHA256 and publisher thumbprint must be conveyed through an independent
trusted administrator channel. Do not trust fingerprints obtained solely from
an untrusted download. The trust script itself also comes through that channel;
it is an administrator tool and is not included or auto-run by Setup.

On a controlled build/client device, run `windows/Trust-InternalPublisher.ps1`
with Operation=Install, Certificate=<publisher.cer>, ExpectedSha256=<independent
DER SHA256>, ExpectedPublisher=<independent thumbprint>. This needs normal
administrator authority and installs only the pinned code-only public leaf in
LocalMachine/Root and TrustedPublisher. Repeated install is idempotent. Check is
readonly; Remove removes only that exact identity and also accepts its expired
certificate for incident response. A TLS certificate/PFX, wrong pin/publisher,
CA certificate, unexpected EKU or invalid-time certificate is refused.

No execution-policy changes, signing private-key export, TLS-root installation,
client service update, Clash/TUN change or VPS publication occurs in these tools.

## Ordinary update

1. Build via tools/build-p6-windows.py using the same publisher thumbprint and the
   fixed runtime archive. Builder output is unsigned staging, not a release.
2. Sign via windows/Sign-Package.ps1 with that thumbprint and the administrator's
   approved Authenticode timestamp service. Windows PowerShell's legacy interface
   supports HTTP timestamp endpoints; HTTPS-only validation previously prevented
   this. The script now accepts HTTP/HTTPS URIs without embedded credentials or
   fragments, but successful native signature AND timestamp verification are
   still mandatory. A server failure or unsupported endpoint refuses publication;
   it never silently exports an un-timestamped production package.
3. Native export via tools/export-p6-windows.py without --lab. Publish on the VPS
   via the existing digest/publisher/scope-pinned CLI with scope=production.
4. Employees download the combined Windows client package and use the existing
   GUI. First trust is already prepared by their administrator; subsequent
   releases reuse the identity. Installation still requires ordinary Windows
   administrator authority and remains subject to local security policy.

## Expiry, loss or compromise

Nonexportable signing keys are not backed up in a PFX. Preserve administrator
access to the build host; losing that key requires an explicit new identity,
not an automatic regeneration. Preserve prior signed installers and their
exact release receipts for controlled recovery. Before expiry, plan re-enrollment
under a new independently trusted identity; same-identity update is the ordinary
path, not an unreviewed cross-publisher rotation.

For compromise, suspend distribution, revoke affected device upload access,
use the previously reviewed installer/admin lifecycle to retire affected clients,
remove the exact old publisher trust, then prepare the new identity and freshly
enrolled bundles. Never bypass the hard-coded old publisher gate to force an
update. Removing self-signed trust is the controlled-device revocation mechanism;
these leaf certificates do not provide public CA revocation services. Replacing
the signer does not migrate or import VPS TLS identities.

## Validation scope

Native tests cover public-only/nonexportable identity, explicit reuse, duplicate
creation refusal, wrong pins, trailing DER, TLS/expired-certificate refusal,
idempotent machine trust, native signatures on two versions with one identity,
and exact removal. Machine-trust tests require administrator Windows CI; local
unprivileged tests explicitly skip that part. Test signatures are not a completed
timestamped company release or employee rollout. Actual company identity/trust
provisioning and production export remain separately recorded field steps.

Sources: [Microsoft certificate cmdlet](https://learn.microsoft.com/en-us/powershell/module/pki/new-selfsignedcertificate),
[Microsoft signing cmdlet](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature?view=powershell-5.1),
[HTTPS timestamp limitation](https://github.com/MicrosoftDocs/PowerShell-Docs/issues/11875).
