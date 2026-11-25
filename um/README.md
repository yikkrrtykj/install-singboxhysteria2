# Unified Monitor Go development

This branch starts Windows terminal observation in a separate Go module. The
command takes one local snapshot for an explicitly configured Mihomo group.

## Windows snapshot

Build from this directory with `go build ./cmd/um-windows-observe`. Run the EXE
as the current user with `-profile <json>` and, if the loopback controller
requires authentication, `-secret-file <local-file>`. Store both files in
the current user's private directory. Put only the controller secret on the
first line of the secret file.

Example local profile with synthetic node names:

```json
{
  "controller": "http://127.0.0.1:9090",
  "group": "EVENT",
  "routes": {
    "a_reality": "vps-a-reality",
    "a_hy2": "vps-a-hy2",
    "b_reality": "vps-b-reality",
    "b_hy2": "vps-b-hy2"
  }
}
```

- `selection` records the mapped leaf selected by the named group, including
  nested groups.
- `active_connections` counts currently open connections whose chain includes
  the named group. Active connections can remain on the prior route after a
  selection changes. Chains with absent or ambiguous configured roles count as
  unknown. The command treats Mihomo's empty list and null as observed zero and
  reports a missing or malformed response as unknown. The two views are
  sampled in separate requests.
- The command reads only `GET /proxies` and `GET /connections` at a literal
  loopback IP. Output contains timestamps, states and configured role codes.
  Local proxy names, destinations, connection IDs and the controller secret
  are excluded from the JSON output.

The local JSON is for development. A later Windows enrollment and reporting
slice will bind a pseudonymous terminal to an event and map its local route
roles to approved VPS identities. An outage or stale sample should remain
visible in that contract. The Windows telemetry will be read-only and run
independently of the existing HA-UI, P6 Remote Probe and Mihomo policy.

## Migration order

Build the unified center and Linux and Windows agents in Go. Continue to use
Shell for installation and systemd orchestration. Version Windows telemetry
before connecting it to the center and validate its privacy, freshness and
delivery behavior with two synthetic events. Validate Windows collection on
the target Clash Verge Rev and Mihomo builds before packaging it as a service.

For future installer changes, start with read-only configuration validation,
generation and preview that can be compared against historical exports.
Replace configuration writes only after the replacement demonstrates the same
lock, recovery, reload and rollback behavior through all existing entry points.

Web management is a planned phase. Begin with a typed client-create operation
with explicit event and node scope, node-side authorization, an operation
receipt and retry and failure semantics. Reuse the existing configuration
transaction boundary for committing writes. Device disable and configuration
apply each need their own permissions and post-apply checks.
