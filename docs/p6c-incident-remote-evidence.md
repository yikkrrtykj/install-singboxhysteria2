# Monitor 0.8.0 candidate: event-time device evidence

Open **事件**, select an incident, then read **设备监测 · 事件时段**. The existing event judgment stays unchanged. The panel separately shows current reporting status and retained samples inside the stored event analysis window. **刷新设备记录** reloads those records; it neither starts a probe nor changes a device, service, Clash or TUN.

Current reporting means a recently retained sample exists, not that a Windows service has been queried. A silent device is unavailable evidence, never proof of path failure. Slot failures describe that specific DNS, HTTPS, TCP, egress or node test. TCP success is only transport reachability. Active delay tests describe the dedicated destination; cached observations may echo those tests and are not an independent second source. Public IP is the client's observed request egress, not necessarily its registered VPS or carrier identity.

Position and network-path labels come only from the current server registry. A retired/disabled/unavailable mapping has no reconstructed labels. Device identifiers are available under technical details. This phase does not read privileged enrollment credentials or join them into the incident response; registered Client/Device download management stays on its existing page.

## HTTP contract

`GET /api/v1/incidents/<incident_id>/remote-probes` passes the existing source whitelist and browser-session gate. It is GET-only; POST is refused. IDs are canonical ASCII positive integers bounded by the existing parser. A malformed/missing ID yields `incident_not_found`; unavailable core incident history yields 503. The server derives both bounds from `analysis_start_epoch` and `last_classified_end_epoch`. Query parameters cannot change the window, identity filter or record limit.

The exact response keys are `v`, `incident_id`, `window`, `retention`, `current_status`, `rows`, `truncated`, `limit`.

- `window`: `start_epoch`, `end_epoch` — the original incident analysis window.
- `retention`: `max_age_seconds`, `retention_cutoff_epoch`, `retained_since_epoch`, `budget_pruned`. Earliest retained time is global to the remote store, not a guarantee for every device or uninterrupted coverage.
- `current_status`: `observed_epoch`, `status`, `subcode`, `probes`. These are **current**, not incident-time status. Each probe has `probe_id`, `status`, `subcode`, `last_sample_epoch`, `site_label`, `path_label`.
- Each row: `sample_epoch`, `probe_id`, `mapping_retired`, `site_label`, `path_label`, `dns`, `https`, `vps_tcp`, `egress`, `mihomo_api`, `flags`, `active`. Slot and flags shapes reuse the accepted closed payload schema. Each active item exposes only `role`, `source`, `outcome`, `delay_ms`, `independent`.

Reads intersect the incident window with the existing up-to-seven-day evidence horizon and the capture time, enforcing existing store retention. At most 255 samples are returned, oldest first in stable store ordering; a 256th row proves truncation. A truncated response is not a census of all paths. Missing history may mean no upload, expiry, capacity pruning or unavailable storage; it is never presented as healthy. Durable receipts cannot resurrect pruned sample evidence. The route performs no admission or History write; the existing remote-only age/budget maintenance still runs under its original serialization boundary.

The registry lifecycle fence keeps labels coherent during a request. Storage/config failures produce a closed remote-only degradation state with no exception text; core incident history and classifier health remain independent.

## Compatibility and rollout

Only the server/UI release changes. VERSION and MONITOR_WEB_VERSION move together to candidate 0.8.0, and executable release pins are restated. The Windows Agent, signed installer, sample/HMAC schemas, ingest/store/registry implementations, History v5, classifier, presenter and runtime stay unchanged. No credential rotation, Windows signing or long native resource test is required by this presentation change.

CI runs the new real SQLite/HTTP tests plus the existing P5 exact-key, DOM, P6A/P6B, packaging and isolation suites. Existing VPS deployment follows review/merge through the established update flow; it is not performed by opening the panel. P6D and any standalone live device dashboard require separate scope.
