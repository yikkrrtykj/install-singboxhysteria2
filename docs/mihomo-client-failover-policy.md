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

There are TWO independent cache layers to account for:

1. the outer Selector cache for `节点选择`; and
2. the cached fixed selection of the inner group named `自动选择`.

The group name `自动选择` is deliberately kept while its type changes in
place from `url-test` to `fallback`. Mihomo restores cached SelectAble
group selections by group name, so a legacy inner `自动选择=Hysteria2`
selection can survive this type change and fix the new fallback to Hysteria2.
That is valid persisted state, but it is NOT the unpinned
Reality-primary behavior.

### Outer Selector cache

| Persisted `节点选择` selection | After reload |
|---|---|
| none (fresh/no cache) | `default-selected` routes into `自动选择`; unpinned fallback chooses Reality while healthy |
| Reality | stays Reality (manual outer override preserved) |
| Hysteria2 | stays Hysteria2 |
| 自动选择 | stays 自动选择; traffic follows the inner fallback/fixed state described below |
| DIRECT | stays DIRECT |

### Inner `自动选择` cache

| Persisted inner `自动选择` state | After url-test -> fallback reload |
|---|---|
| none | fallback is unpinned and prefers Reality while Reality is healthy |
| Reality | fallback starts fixed to Reality |
| Hysteria2 | fallback starts fixed to Hysteria2, even if Reality is healthy |
| fixed state cleared/unfixed | fallback returns to automatic priority order: Reality first, then Hysteria2 |

The two layers can coexist. For example an upgraded client may have both
`节点选择=自动选择` AND inner `自动选择=Hysteria2`; in that state the outer
Selector correctly points at the automatic group, but the automatic group is
still fixed to HY2 until explicitly unfixed.

**Preferred recovery/migration path:** clear/unfix ONLY the inner
`自动选择` fixed selection in the client UI/API. On the pre-merge validation
build below, `DELETE /proxies/自动选择` returned HTTP 204, cleared the fixed
selection, immediately restored `now=Reality` while Reality was healthy, and
the cleared state remained automatic after restart. Deleting the entire
selection cache is a broader reset and is NOT the primary migration
instruction.

Cache precedence remains: a persisted selection wins when present;
otherwise `default-selected` applies for the outer Selector; an unpinned
fallback then follows member priority. Existing installs that deliberately
pinned outer Reality/Hysteria2/DIRECT retain that operator intent.

## Pre-merge runtime validation

The rendered YAML assertions are necessary but do not prove Mihomo kernel
cache/fallback behavior. Before merge, the S1-S8 matrix was therefore run once
continuously in a controlled client lab.

### Tested build and substitutions

- Kernel: **Mihomo Meta v1.19.31**, Windows amd64, Go 1.26.8, locally built
  binary sha256 `deef9d8d…31c8bf`.
- Members were modeled as SOCKS5 relays. This exercises Mihomo group/cache/
  fallback selection semantics, but it is not a Reality/Hysteria2 protocol
  interoperability test.
- Health URL was lab-only `http://127.0.0.1:18080/hc`; the production
  template remains `https://www.gstatic.com/generate_204`.
- Health timing was scaled to `interval=3s`, `timeout=1500ms` only to make
  transitions observable quickly. The production template remains 60s/5000ms.
- Long-lived-connection evidence used SOCKS5 through the mixed port as a pure
  TCP tunnel. The HTTP-proxy path was deliberately excluded because its
  absolute-URI/keep-alive behavior introduced unrelated lab interference.
- These results verify the exact build above. They do NOT claim behavior for
  older/frozen Mihomo cores that were not tested.

### S1-S8 results

| Scenario | Observed result |
|---|---|
| S1 fresh/no cache | outer `节点选择.now=自动选择`; inner chooses Reality |
| S2 cached outer Reality | outer Reality survives restart |
| S3 cached outer Hysteria2 | outer Hysteria2 survives restart |
| S4 cached outer 自动选择 | outer 自动选择 survives; inner fallback remains active |
| S5 cached outer DIRECT | outer DIRECT survives restart |
| S6 legacy inner fixed Hysteria2 | fixed Hysteria2 survives url-test -> fallback reload; new connections use `[Hysteria2, 自动选择, 节点选择]`; unfix via `DELETE /proxies/自动选择` -> 204 clears fixed state, `now=Reality`, and restart stays automatic |
| S7 unpinned failover/failback | Reality failure -> HY2 in **1198 ms**; Reality recovery -> Reality in **2931 ms**; both within the scaled `interval+timeout=4.5s` window |
| S8 established connection | connection established on Reality remained on its Reality chain after the group switched to Hysteria2 and was still present +3s later; a concurrent new connection used HY2 |

S8 is evidence for the documented limit above: selection changes affect new
dials; they do not migrate an already-established connection.

