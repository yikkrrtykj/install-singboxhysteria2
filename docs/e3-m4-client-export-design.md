# E3 M4 — Client config export (`client.export`) — design

Status: APPROVED FOR IMPLEMENTATION (this PR only; production rollout is out
of scope). Branch: `codex/client-config-export`. Baseline main:
`3b50550b6cb2733e38009af4054eb082307bf2e7`.

Goal: close the client lifecycle. A user who can Add a client from the
Monitor web UI must be able to Download its canonical Mihomo/Clash Meta YAML
(Reality + Hysteria2) without ever touching the server shell. This PR adds
exactly that: one read-only helper op, one Web route, one UI button.

Explicitly NOT in scope: QR codes, share URIs, sing-box client JSON,
`client.rotate`, `client.get`, traffic graphs, search/filter, `no_op`
evidence cleanup, unrelated UI redesign, any production deployment.

---

## 1. Security contract (NON-NEGOTIABLE)

Credential material = the client's Reality UUID and Hysteria2 password, and
the rendered YAML that embeds them.

Credentials MUST NOT appear in:

1. argv of any external process (including `jq --arg`/`--argjson`);
2. environment variables (worker env is already pinned by
   `w_enforce_environment`, sbox-cm-ops);
3. journald / daemon or worker stdout/stderr diagnostics;
4. sbox-cm audit records (`/var/lib/sbox-cm/audit/cm.jsonl`) — metadata only;
5. request-audit `detail`, the ledger, the transaction journal;
6. the daemon replay cache (response bypasses `replay_put`);
7. browser console, localStorage, sessionStorage;
8. URL / query string (export is POST-only);
9. HTML DOM text (the YAML goes straight to a Blob download);
10. generic error detail bodies.

Credentials MAY exist only transiently along:
`sbconfig_server.json → root worker memory/anonymous pipe → private
root:sboxweb AF_UNIX socket RPC → Monitor process memory → HTTP response over
the existing loopback/SSH-tunnel → browser Blob → the user's downloaded file.`

Forbidden shortcuts (STOP and report instead of implementing): credential in
argv/env; a persistent web-readable credential file; sudoers for sboxweb; a
public/list API returning credentials; replay-cache retention of the YAML;
credential-bearing logs or audit. `client.export` introduces the FIRST and
ONLY exception to "the Python RPC core never sees credential material"
(sbox-cm:12): it transports an already-rendered YAML response body. The
daemon's module docstring is updated to say exactly that (§5.3).

## 2. Current-state evidence (why each change is where it is)

* Canonical transaction library: `lib/client-management.sh`
  (SHA-256-pinned at install.sh:708 and
  tests/e3/test-m0-static-contract.sh:35 — both pins are recomputed in the
  same commit that edits the lib; tests/e3/test-m0-shared-lib.sh recomputes
  and compares dynamically).
* Renderer today: `install.sh` `write_mihomo_template()` (install.sh:980) —
  heredoc expanding caller-scope vars; TWO consumers: the installer's
  shared-account display path (install.sh:310) and
  `generate_client_configuration()` (install.sh:1085, vars prepared at
  :1103, mode 0700 dir / 0600 file, CLI credential logging preserved).
* Credential reader: `get_client_credentials <name>` in
  lib/client-management.sh:494 → `uuid\npassword` on stdout.
* Ops allowlists (3 places): daemon `OPS` dict (sbox-cm), worker dispatch
  case (sbox-cm-ops ~:887), static contract
  tests/e3/test-m1-static.sh:63-74 (currently asserts SIX ops and lists
  `client.export` among banned ops).
* Reserved-name wall (2 places +1): daemon `validate_request` rejects
  `name == "legacy"` for any name-carrying op; worker `_add_locked`/delete
  re-check; Web `_handle_e3_mutation` rejects `E3_RESERVED_NAME` for
  add/delete (server.py:1018).
* Replay: `handle_connection` unconditionally `replay_put(request_id, resp)`
  (sbox-cm:526) — must become op-aware.
* Worker result channel: `emit_ok` builds JSON with `jq --argjson d "$1"`
  (sbox-cm-ops:62) — data arrives via argv here; for export we need a
  serializer that takes the YAML via stdin instead.
* Broker: `E3Broker.mutate()` (e3_broker.py:288) refuses unless breaker
  closed; `E3RpcClient` budgets at e3rpc.py:51; wiring is a single
  `E3Broker(E3RpcClient())` (webapp.py:270).
* Web gates: `_route_post` (server.py:445) → `MUTATION_ROUTES` (:54) →
  `_require_step_up` freezes actor (:480); `E3_ERROR_HTTP` (:72);
  deny-by-default `E3_DATA_WHITELIST` (:85); `SECURITY_HEADERS` (:114);
  `MAX_BODY_BYTES = 65536` (:47); `log_message` logs request line + status
  only.
* Transport frame cap: `MAX_FRAME = 65536` on BOTH ends (daemon, e3rpc).
* UI: `e3Writable()`, `renderE3Clients()` 3-column table, `apiWithStepUp`
  401-replay, Add-success copy at app.js:668-669, redundant
  `e3-changes` kv row (index.html:139 / renderE3Controls).
* Version chain: monitor-v2/VERSION == `MONITOR_WEB_VERSION`
  (server.py:45) asserted by tests/test-monitor-v2-ui.cjs:209-213.
* Packaging upgrade regression (tests/test-monitor-packaging.sh T03, :493)
  is already version-dynamic: baseline 0.1.0 → repo VERSION, asserts the
  previous release tree byte-identical and exactly one
  `systemctl restart singbox-monitor`, no sing-box restart. After the bump
  it exercises 0.1.0→0.1.2 with unchanged invariants.

## 3. Layer 0 — canonical pure renderer (lib/client-management.sh)

New function, single source of the YAML:

```
cm_render_client_mihomo_yaml <name> [config-path]   # YAML on stdout ONLY
```

* Reads `<config-path>` (default `sbconfig_server.json` via `SB_SERVER_CONFIG`)
  and `SB_STATE_FILE` for `SERVER_IP` / `PUBLIC_KEY` / `HY_SERVER_NAME` /
  hopping vars; calls `get_client_credentials` for the pair.
* Prints the byte-exact current template to stdout. NO writes, NO logs, NO
  credential on stderr, NO temp files. Everything stays in shell memory +
  command substitution.
* `install.sh::generate_client_configuration` is refactored to call it and
  redirect stdout into `$outfile` (chmod 0600, parent dir 0700 — file modes
  remain install.sh's job, so CLI behavior is byte-identical). The installer
  shared-account display path (install.sh:310) keeps its caller-scope-var
  call to `write_mihomo_template`; BOTH paths are proven equal by the
  byte-identical regression (§12 group A): renderer output == legacy
  template output for the fixture set, and the two installer consumers
  produce identical bytes before/after the refactor.
* `write_mihomo_template` itself moves its body to a
  `cm_render_client_mihomo_yaml` invocation internally (thin shim that maps
  caller-scope vars → positional/env contract) OR is kept as the fallback
  only if the shim proves awkward; the deciding rule: `generate_client_configuration`
  MUST go through the lib copy, because that is the copy the worker uses.
* After editing the lib: recompute `SB_CLIENT_MANAGEMENT_SHA256` in
  install.sh:708 AND the hardcoded digest in
  tests/e3/test-m0-static-contract.sh:35 in the same commit
  (test-m0-shared-lib.sh validates dynamically and needs no edit).

## 4. Layer 1 — root helper op `client.export` (sbox-cm-ops)

Op contract:

* READ-only. Takes `{request_id, name, actor?}`. NO `idempotency_key`
  (nothing to deduplicate), no ledger intent/result, no transaction journal
  enter/clear, no candidate, no commit, no reload, no restart, no backups.
* Runs under the SAME config lock (`with_client_lock`) as everything else,
  so an export can never interleave with add/delete (a deleted-while-exporting
  race is impossible, and a client list never shifts mid-render).
* In-lock preconditions, checked in this order, all fail-closed:
  1. config parses (`jq empty`) — else `E_CONFIG_INCONSISTENT`;
  2. `audit_client_consistency` + `candidate_problems` clean — else
     `E_CONFIG_INCONSISTENT`;
  3. management state active (`cm_management_state`) — else
     `E_ACTIVATION_STATE`;
  4. not degraded (`cm_degraded_marker_present`) — else
     `E_MANUAL_INTERVENTION`;
  5. name valid + client exists in BOTH Reality and HY2 sets with both
     credentials non-empty — else `E_NOT_FOUND` (missing) /
     `E_CONFIG_INCONSISTENT` (half-registered).
* `legacy` IS exportable (§5.2 narrows the reserved-name wall);
  `mutable:false` stays unchanged elsewhere.
* Errors: fixed `err_exit` codes only; detail strings are static and never
  interpolate the name's credential material.

Sensitive serialization (the ONLY new serialization path):

* New `w_export_locked` renders via
  `cm_render_client_mihomo_yaml "$name" "$SB_SERVER_CONFIG"` into a shell
  variable, then pipes it to the response builder over stdin:
  `jq -cn --arg op ... --arg format "mihomo-yaml" --arg filename ...
  '{ok:true, code:"OK", ..., data:{format:$format, filename:$filename,
  content:.}}'` — the YAML enters jq via stdin (`--rawfile` or `.`), NEVER
  via `--arg`/`--argjson`. `emit_ok` (argv `--argjson d`) is NOT used for
  this op.
* Size bound: raw YAML must be ≤ 48 KiB before serialization and the
  finished JSON line must be < 65536 bytes (JSON escaping inflates; the 48
  KiB raw cap leaves headroom). Over cap → `err_exit E_INTERNAL
  "export payload too large"` — fail closed, NEVER truncate. (Legitimate
  YAML is ~3 KiB; the bound is a defence against pathological state.)
* Static hygiene: `export` code path introduces no `password=`-shaped
  assignment that trips the existing `wantnt "$WORKER" 'password='`
  contract — the renderer result variable is named `w_yaml` and credentials
  never land in worker variables at all (the pipeline streams stdout→stdin);
  if a variable is unavoidable it is named to avoid the literal token
  (checked against tests/e3/test-m1-static.sh credential greps).

Audit (metadata ONLY), fail-closed:

* Fields: `op`, `name`, `request_id`, `actor.session_fp/stepup_fp`,
  `outcome` (`ok` / error code), timestamp. FORBIDDEN in the record:
  UUID, password, YAML, share URI, token, digest, filename content beyond
  `<name>-mihomo.yaml`.
* Written via the existing `cm_audit_append` stdin channel (no argv).
* If the audit append FAILS, the response is an error (NOT the YAML):
  unlike `ok_exit`'s deferred-warning behavior for mutations, export has no
  safe partial state — unexported-with-no-record is the required outcome,
  so a failed audit → `err_exit E_INTERNAL` and the YAML is dropped.

## 5. Layer 2 — RPC core (sbox-cm daemon)

5.1 Ops surface: `OPS` dict gains `"client.export"` (schema: required
`name`, optional `actor` exactly like `management.deactivate`). Total ops
becomes SEVEN; tests/e3/test-m1-static.sh:63-74 is updated: count 7,
`client.export` removed from the banned list, `client.rotate`/`client.get`/
`run`/`exec`/`shell`/`argv` stay banned.

5.2 Reserved-name narrowing: `validate_request` currently rejects
`name == RESERVED_NAME` for any name-carrying op. Change: reject `legacy`
for add/delete only; permit for `client.export`. Regression in
m1-rpc-probe.py schema_tests: add/delete legacy → `E_RESERVED_NAME`;
export legacy → accepted.

5.3 Replay bypass: new module constant

```
SENSITIVE_RESPONSE_OPS = {"client.export"}
```

In `handle_connection`, `replay_put(request_id, resp)` is skipped when
`op in SENSITIVE_RESPONSE_OPS` — the YAML never enters the in-memory replay
cache, so a duplicate `request_id` re-dispatches (fresh render, fresh audit)
instead of replaying a cached secret. Module docstring (sbox-cm:11-14) is
updated: the daemon STILL never constructs or parses credentials; the only
exception is that a `client.export` RESPONSE (opaque bytes it forwards
without logging) may contain them in flight.

## 6. Layer 3 — E3RpcClient + broker

* `DEFAULT_OP_BUDGETS["client.export"] = 20.0` (e3rpc.py:51). Budget only;
  transport already never retries.
* `E3Broker.export_client(name, actor)`:
  1. refuse unless breaker `closed` (mirror `mutate`, e3_broker.py:288);
  2. FRESH management gate before dispatch, fail-closed, each check on a
     `status(force=True)`-style fresh read: `management_active` true AND
     `transport == "fresh"` AND `helper.degraded == false` AND
     `helper.reconcile == "clean"` AND `lock.acquirable == true`; any other
     combination → raise (never dispatch);
  3. `self.client.call("client.export", payload={"name": name},
     actor=actor)`;
  4. the RESULT IS NEVER CACHED — no `_status_cache`/`_list_cache` entry,
     no memoization; it is returned to the single caller for immediate
     streaming and then dropped.
* Semantic verdicts (`ok:false`) propagate like other broker calls; the
  export RPC is one-shot: no retry on `result_unknown` either (a read is
  safe to retry in principle, but the frozen contract is single-dispatch,
  audit-per-dispatch).

## 7. Layer 4 — Web API `POST /api/v1/clients/export`

Gate order (identical spine to other mutations, server.py `_route_post`):
whitelist/body-framing → session → CSRF → step-up (freezes actor) →
validated body shape (free, no RPC) → broker FRESH management gate
enforced atomically before the only dispatch → RPC. The externally
observable contract is unchanged: zero export RPCs unless the fresh gate
holds at dispatch time.
(`MUTATION_ROUTES` is for mutate-style ops; export gets its own route entry
so `_handle_e3_export` runs the export broker path — no Idempotency-Key
required or accepted: a body/header key is rejected with 400.)

Body: `{"name": "<E3_NAME_RE>"}`. `legacy` passes (exportable by design);
any other invalid name → 400 `invalid_name` (403 only via helper verdict
passthrough).

Success response is a FILE, not JSON, bypassing `E3_DATA_WHITELIST`
entirely (the whitelist governs JSON `data` objects; the YAML is streamed
from the already-validated broker result):

```
HTTP/1.1 200 OK
Content-Type: application/x-yaml; charset=utf-8
Content-Disposition: attachment; filename="<validated-safe-name>-mihomo.yaml"
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Expires: 0
X-Content-Type-Options: nosniff
(+ existing SECURITY_HEADERS)
```

`<validated-safe-name>` = the regex-validated `name` (charset
`^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$` already excludes anything
filename-hostile; `legacy` → `legacy-mihomo.yaml`). Response length is
Content-Length framed, connection not keep-alive-reused across it is fine
(existing server behavior).

Errors: JSON via the existing non-secret mapping (`E3_ERROR_HTTP` passthrough
for helper verdicts; gate failures reuse existing 401/403 shapes). Never
log the body (`log_message` already logs only request line + status; export
adds no logging). No redirects anywhere. No credential in any error detail
(the worker's details are static strings; the whitelist of allowed
`data.content` never appears in an error).

## 8. Layer 5 — Web UI

* Table becomes CLIENT | PROTOCOLS | ACTION with a **Download** button for
  every listed client when `e3Writable()` is true — including `Default`
  (legacy). **Delete** stays exactly as today: never for `legacy`, only for
  `mutable` clients. Download renders only when Available.
* `downloadConfig(name)`: POST `/api/v1/clients/export` via
  `apiWithStepUp` WITHOUT `idempotencyKey`; on 401 the step-up panel
  appears and the SAME export replays (no key); on success takes
  `response.body` → Blob → `URL.createObjectURL` → anchor click →
  `URL.revokeObjectURL`. The YAML text is NEVER put into the DOM, console,
  or any storage. Failure paths show existing generic product copy only.
* The handler re-checks `e3Writable()` independently before dispatch
  (defense in depth, mirroring add/delete).
* Add-success copy change (app.js:668-669): "Client created. Credentials
  are not displayed here. Generate the client configuration on the server."
  → **"Client created. Download its configuration below."** — no
  auto-download.
* Remove the redundant `Client changes / Available` kv row
  (`e3-changes`, index.html:139 + app.js renderE3Controls): the header
  badge `e3-availability` is the single source. Update
  tests/test-monitor-v2-ui.cjs accordingly (closed() drops the e3-changes
  assertion; line-190 copy assertion updated; `assert.equal(count, 35)`
  re-counted after new checks are added — the export click-flow tests, §12
  group E).

## 9. Size / framing budget chain (cross-layer invariant)

`raw YAML ≤ 48 KiB` → JSON line `< 65536` (worker fail-closed) → daemon
frame cap 65536 (unchanged) → E3RpcClient frame read (unchanged) → HTTP
response unbounded (loopback) → browser Blob. Deterministic fixture YAML is
~3 KiB; a >48 KiB pathological config is proven to fail closed at the
worker AND to be rejected by a synthetic over-cap frame test.

## 10. Legacy/Default policy table (final)

| op | legacy | normal client |
|---|---|---|
| client.add | E_RESERVED_NAME | ok |
| client.delete | E_RESERVED_NAME | ok (fresh-list preflight) |
| client.export | **ok** | ok |
| mutable flag in list | false | true |
| UI Delete | hidden | shown when Available |
| UI Download | shown when Available | shown when Available |

## 11. No-mutation invariants (proven, not assumed)

An export must leave: `sbconfig_server.json` byte-identical (hash),
`SB_STATE_FILE` untouched, systemd `NRestarts` unchanged, client inventory
identical, NO new journal/ledger entry, NO derived file under
`/root/sbox/clients`, no config.lock leaked fd beyond normal release.
Proved dynamically (§12 group C) and statically (export op body must not
call `commit_server_config`, `cm_ledger_*`, `cm_journal_*`, reload/restart;
grep contract in the static test).

## 12. Test plan (deterministic fixtures)

Fixed fixture credentials — UUID `11111111-2222-3333-4444-555555555555`,
HY2 password `super-secret-hy2-fixture` — scanned for in EVERY artifact by
executable leak-scan regressions.

* **A. Renderer (lib)**: `test-client-export-lib.sh` (new, add to CI list):
  byte-identical vs legacy `write_mihomo_template` output; modes preserved
  via `generate_client_configuration`; digest pins recomputed
  (test-m0-shared-lib.sh / test-m0-static-contract.sh must pass with the
  new pins).
* **B. Worker/RPC**: test-m1-worker.sh gains `wout client.export` cases:
  success shape `{format, filename, content}`; legacy exportable;
  missing client → E_NOT_FOUND; degraded → E_MANUAL_INTERVENTION;
  inactive → E_ACTIVATION_STATE; inconsistent sets → E_CONFIG_INCONSISTENT;
  over-cap YAML → fail closed; NO ledger/journal entries created; audit
  line is metadata-only and contains neither fixture value; audit-failure →
  no YAML. m1-rpc-probe.py: schema (export name+actor optional, no key
  field), legacy-for-export vs reserved-for-add, `SENSITIVE_RESPONSE_OPS`
  bypass (same request_id twice → two dispatches, no replay), frame cap,
  and the MOCK_WORKER_LOG-based **argv/env leak scan** (fixture values must
  appear in NO logged argv, and `client.export` args on stdin are
  name-only). Static test updated to 7 ops + banned-list edit.
* **C. No-mutation dynamic**: before/after hashes of config+state,
  inventory, journal/ledger absence, NRestarts mock count.
* **D. Web adapter**: test-monitor-v2-m2.sh harness gains group
  `export`: broker gate matrix — **9 "no export RPC" cases** (breaker open,
  transport stale, transport unavailable, management inactive, degraded,
  reconcile conflict, lock not acquirable, missing helper field,
  pending-retry-style not-fresh) each asserting ZERO client.call; success
  passthrough with fresh actor fps; export result never cached (two
  successes = two RPCs); HTTP contract via M2Stack: POST-only, 401 step-up
  → replay, 400 on Idempotency-Key present, 404/400 name errors, the five
  download headers + nosniff, error bodies JSON non-secret.
* **E. UI**: test-monitor-v2-ui.cjs: Download cell rendering (Available vs
  each closed case), Default row has Download but never Delete, click
  issues POST with no Idempotency-Key header, 401 replay path, Blob path
  never writes fixture text into the fake DOM/console, copy change,
  e3-changes removal, updated assertion count.
* **F. Leak sweep**: every artifact file produced by B/C runs (worker
  stderr capture, daemon log, audit JSONL, ledger, journal, HTTP error
  bodies, replay cache state dump, argv/env recordings from the mock
  worker) is grep-scanned for both fixture values — executable regression,
  all fail-closed.

All existing suites stay green on the ubuntu-22.04/24.04/26.04 CI matrix;
new shell files are appended to the `bash -n` list and given run steps in
.github/workflows/tests.yml.

## 13. Versioning + packaging

* monitor-v2/VERSION: `0.1.1` → `0.1.2`; server.py:45 `MONITOR_WEB_VERSION`
  to match (ui test cross-check). No other literal 0.1.1 references exist
  in the tree (deploy scripts read VERSION dynamically; the earlier grep
  hits in test-legacy-config-transactions.sh are IP addresses).
* Packaging suite: T03 upgrade regression already asserts baseline→repo
  VERSION with old release byte-identical and exactly one monitor restart
  (sing-box untouched) — it thereby covers 0.1.0→0.1.2 with zero edits;
  an explicit `assert_eq '0.1.2'`-style guard is NOT added (the suite
  deliberately reads the repo VERSION so it survives every future bump).
* Production rollout sequence (install/upgrade on the VPS) is explicitly
  OUT of this PR.

## 14. Change boundary

Allowed files: `lib/client-management.sh`, `install.sh` (renderer reuse +
digest pin), `sbox-cm/sbox-cm`, `sbox-cm/sbox-cm-ops`, `sbox-cm/README.md`,
`monitor-v2/web/{e3rpc.py,e3_broker.py,server.py,static/app.js,static/index.html}`,
`monitor-v2/VERSION`, tests (enumerated above), docs.
NOT touched: Phase 1/2/3 evidence/activation code, production files, the
Mihomo read-only adapter under monitor-v2/mihomo, network/firewall config,
the Phase3 `no_op` null-evidence issue.

## 15. Rollout / rollback (repo only)

Draft PR against main; CI green; human review; merge is out of scope.
Rollback = revert the merge commit: the digest pins revert atomically with
the lib, the ops allowlists are additive, and the Web route 404s without
the daemon op, so no data or state migration exists to unwind.
