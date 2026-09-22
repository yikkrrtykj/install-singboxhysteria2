# Mihomo client failover policy (issue #42)

Canonical source: `lib/client-management.sh :: cm_render_client_mihomo_yaml`
(the single Mihomo/Clash Meta client template; install.sh, the shared-account
display path and the sbox-cm `client.export` op all render through it).
Design decision and review history: issue #42 (policy C accepted); the
client-side forensic capability that confirms per-incident group state is
issue #41.

## Policy

```yaml
proxy-groups:
  - name: 节点选择
    type: select
    default-selected: 自动选择
    proxies:
      - Reality
      - Hysteria2
      - 自动选择
      - DIRECT

  - name: 自动选择
    type: fallback
    proxies:
      - Reality          # primary
      - Hysteria2        # secondary
    url: "https://www.gstatic.com/generate_204"
    interval: 60
    timeout: 5000
    lazy: false
    expected-status: "204"
```

- Reality is preferred while healthy; fallback selects the FIRST healthily
  probed member by list order — never by latency.
- A genuinely dead Reality (one failed HTTPS probe through that tunnel) moves
  NEW connections to HY2 within at most `interval + timeout` (~65 s); the
  first passing Reality probe returns new connections to it.
- The probe leaves through the tunnel and hits an external third party: it
  exercises TCP + tunnel handshake + TLS + HTTP + real VPS egress, and cannot
  be satisfied by the VPS itself (a VPS-local probe would miss
  outbound-wide failures like 2026-09-22). `expected-status: "204"` rejects
  captive/hijacked 200 responses.
- `lazy: false` is REQUIRED: an automatic group nested behind the Selector
  would otherwise stop being probed while not currently selected (upstream
  `healthcheck.go` skips ticks when `lazy` and no traffic touched the group
  within one interval) — the group must be hot before it is ever needed.
- `max-failed-times` is intentionally NOT set (default 5). It is not a
  switch threshold: it only forces a re-probe after repeated dial failures
  within the timeout window (`connection refused` immediately). Detection is
  never guaranteed faster than the interval by this field.

## What this does NOT do

- Established connections never migrate on a group switch; only new
  connections follow the new selection. An app holding a dead Reality
  connection can keep erroring until it reconnects.
- `节点选择` remains a manual pin: a user-selected Reality (or Hysteria2, or
  DIRECT) is an intentional override and is NEVER auto-released — that is
  the operator escape hatch, not a bug.

## Upgrade / migration matrix (`profile.store-selected: true` unchanged)

The group name `自动选择` was kept and its type changed IN PLACE
(url-test -> fallback), so no persisted selection can dangle:

| Persisted 节点选择 selection | After reload |
|---|---|
| none (fresh install) | `default-selected` routes into 自动选择 -> Reality while healthy |
| Reality | stays Reality (manual override preserved) |
| Hysteria2 | stays Hysteria2 |
| 自动选择 | name valid; gains priority-failover semantics immediately |
| DIRECT | stays DIRECT |

Cache precedence (verified against upstream `hub/executor/executor.go`):
the persisted selection is restored ONLY when a cache entry exists;
otherwise `default-selected` applies; otherwise the first member (Reality).
Rollout note: existing installs that had manually pinned Reality keep that
pin after this change; they adopt automatic failover by selecting
`自动选择` once in the panel (or by clearing the kernel selection cache).
