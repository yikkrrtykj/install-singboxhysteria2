"""Monitor v2 Phase E4 -- Mihomo local API enrichment data model.

E4 is OPTIONAL client-side enrichment. It is NOT an identity data source:

    Server truth (Phase E1, api_bridge + collector):
        Device      = sing-box service.api USER
        Protocol    = sing-box service.api INBOUND
        Lifecycle   = sing-box service.api connection ID

    Mihomo API (this module):
        optional client-side enrichment, display only

The enrichment object therefore has a FIXED key whitelist (``ENRICHMENT_KEYS``)
that contains no identity field at all -- no device name, no service.api
identity. Node display names coming from Mihomo (e.g. "vmix-01-HY2",
"香港-01") are echoed verbatim as ``selected_proxy`` for DISPLAY ONLY; they are
never parsed, never matched against server-side devices and never used to
derive, rename or confirm any identity. ``finish_enrichment`` rebuilds the
final object strictly from the whitelist, so a field that is not declared here
can never reach the output even if a future code path tried to add one.

Contract notes below were verified against the real Mihomo REST API source
(MetaCubeX/mihomo, hub/route/*.go + tunnel/statistic/*.go + adapter/*.go) --
not guessed; see monitor-v2/mihomo/README.md for the full table:

* GET /version        -> {"meta": <bool>, "version": "<str>"}        (stable)
* GET /configs        -> {..., "mode": "rule"|"global"|"direct", ...} (stable)
* GET /proxies        -> {"proxies": {name: {"type","now","all","history",
                          "alive", ...}}}                            (stable)
                          - "now" exists on GROUP types only (Selector /
                            URLTest / Fallback / LoadBalance / Relay);
                          - history entries are {"time", "delay"} and a delay
                            of 0 means the last probe FAILED (never a real
                            latency);
                          - "extra" (per-test-URL histories) is newer-build
                            and version-dependent -- not used here;
                          - GET /proxies/{name}/delay performs an ACTIVE
                            probe and is FORBIDDEN in this read-only adapter.
* GET /connections    -> {"downloadTotal", "uploadTotal", "connections":
                          [ ... ] | null, "memory"}                  (stable)
                          - "connections" is null when idle (nil slice,
                            no omitempty) -- normalized to 0 here;
                          - per-connection counters are "upload"/"download"
                            while the totals are "uploadTotal"/
                            "downloadTotal" (deliberately mirrored names,
                            easy to swap by accident);
                          - "memory" is mihomo-specific, optional.
* GET /traffic        -> infinite chunked stream, one JSON line per second:
                          {"up", "down", "upTotal", "downTotal"}; the first
                          line arrives after ~1s. OPTIONAL: read exactly one
                          sample, then close. Failure never affects anything
                          else.
"""

from __future__ import annotations

import datetime
import json

# The complete, closed set of keys an enrichment object may ever carry.
# Deliberately NOT included: any server identity field (no device name, no
# service.api identity), connection ids, rules, provider details, secrets.
ENRICHMENT_KEYS = (
    "reachable",
    "version",
    "mode",
    "selected_group",
    "selected_proxy",
    "delay_ms",
    "active_connections",
    "traffic_up_bps",
    "traffic_down_bps",
    "updated_at",
    "stale",
    "error",
)

# Mihomo tunnels the whole machine; its own cumulative totals are client-local
# and redundant with the server's authoritative counters, so only the
# instantaneous rate (up/down bytes per second) is enrichment-grade.
DEFAULT_MAX_AGE = 30.0  # seconds after updated_at before a stored sample is stale


def new_enrichment():
    """An empty enrichment object: nothing observed, nothing reachable."""
    return {
        "reachable": False,
        "version": None,
        "mode": None,
        "selected_group": None,
        "selected_proxy": None,
        "delay_ms": None,
        "active_connections": None,
        "traffic_up_bps": None,
        "traffic_down_bps": None,
        "updated_at": None,
        "stale": False,
        "error": None,
    }


def finish_enrichment(snapshot, updated_at_iso, error=None):
    """Seal a snapshot: whitelist only, attach updated_at and the joined error.

    This is the single exit point for enrichment objects. It rebuilds the dict
    from ENRICHMENT_KEYS, so anything an intermediate step squirreled away that
    is not part of the contract (identity fields, raw payloads, credentials)
    is structurally dropped, not merely hidden.
    """
    out = new_enrichment()
    for key in ENRICHMENT_KEYS:
        if key in ("reachable", "updated_at", "error", "stale"):
            continue
        out[key] = snapshot.get(key)
    out["reachable"] = bool(snapshot.get("reachable"))
    out["updated_at"] = updated_at_iso
    out["stale"] = False
    out["error"] = error
    return out


def is_identity_safe(enrichment):
    """True when the object carries enrichment keys ONLY (no identity field)."""
    if not isinstance(enrichment, dict):
        return False
    return set(enrichment) == set(ENRICHMENT_KEYS)


def parse_version(payload):
    """GET /version -> version string, or None (stable endpoint, optional field)."""
    if not isinstance(payload, dict):
        return None
    version = payload.get("version")
    if isinstance(version, str) and version.strip():
        return version.strip()
    return None


def parse_mode(payload):
    """GET /configs -> tunnel mode ("rule"/"global"/"direct"), or None.

    Unknown values are kept (lower-cased) for display: the mode is never a
    security decision, but a renamed mode in a future build must not crash
    the adapter either.
    """
    if not isinstance(payload, dict):
        return None
    mode = payload.get("mode")
    if isinstance(mode, str) and mode.strip():
        mode = mode.strip().lower()
        return mode
    return None


def parse_selected_delay(history):
    """Last delay-test result of the selected node, or None.

    Contract: history is a list of {"time": ..., "delay": <uint16>}; a delay
    of 0 encodes a FAILED probe. Only a positive delay is a real latency.
    No probe is ever TRIGGERED here -- cached history only.
    """
    if not isinstance(history, list) or not history:
        return None
    last = history[-1]
    if not isinstance(last, dict):
        return None
    try:
        delay = int(last.get("delay"))
    except (TypeError, ValueError):
        return None
    return delay if delay > 0 else None


def parse_proxies(payload, group):
    """GET /proxies -> (selected_proxy, delay_ms) for ONE named group.

    ``group`` is an explicit caller-provided group name (E4 never guesses
    which group matters and never infers anything from names). "now" exists
    only on group-type entries; the delay history lives on the SELECTED
    NODE's own entry, not on the group (a Selector carries "history": []).
    A missing group, a missing/empty "now" or an unknown selected node all
    yield (None, None) or a partial result -- a missing optional field, not
    an error.
    """
    if not isinstance(payload, dict) or not isinstance(payload.get("proxies"), dict):
        return None, None
    proxies = payload["proxies"]
    entry = proxies.get(group)
    if not isinstance(entry, dict):
        return None, None
    selected = entry.get("now")
    if not isinstance(selected, str) or not selected.strip():
        return None, None
    selected = selected.strip()
    node = proxies.get(selected)
    delay = parse_selected_delay(node.get("history")) if isinstance(node, dict) else None
    return selected, delay


def parse_connections(payload):
    """GET /connections -> number of locally active connections (0 when idle).

    Verified quirk: the official snapshot marshals the connections slice
    without omitempty, so an idle core returns {"connections": null}; some
    builds/paths may omit the key entirely. Both normalize to 0 -- an empty
    snapshot is data, not an error.
    """
    if not isinstance(payload, dict):
        return None
    connections = payload.get("connections")
    if not isinstance(connections, list):
        return 0
    return len(connections)


def parse_traffic_line(line):
    """One JSON line of the /traffic stream -> {"up": int, "down": int} or None.

    Stream shape (verified): one {"up","down","upTotal","downTotal"} JSON per
    second, first sample ~1s after connect. Only the instantaneous up/down
    pair is kept; the totals are redundant with server truth.
    """
    if isinstance(line, bytes):
        try:
            line = line.decode("utf-8")
        except UnicodeDecodeError:
            return None
    if not isinstance(line, str) or not line.strip():
        return None
    try:
        payload = json.loads(line)
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    try:
        up = int(payload.get("up"))
        down = int(payload.get("down"))
    except (TypeError, ValueError):
        return None
    if up < 0 or down < 0:
        return None
    return {"up": up, "down": down}


def parse_updated_at(text):
    """Parse our own ISO-8601 updated_at (with offset); None when unusable."""
    if not isinstance(text, str) or not text.strip():
        return None
    try:
        parsed = datetime.datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed


def apply_freshness(enrichment, now, max_age=DEFAULT_MAX_AGE):
    """Set ``stale`` from updated_at age. ENRICHMENT freshness ONLY.

    This is completely independent of the server Monitor's own stale flag
    (Phase E1 stream health): a client API sample can be stale while the
    server snapshot is healthy, and vice versa. An object without a usable
    updated_at is stale by definition (never treat unknown age as fresh).
    """
    updated = parse_updated_at(enrichment.get("updated_at")) if isinstance(enrichment, dict) else None
    if updated is None:
        enrichment["stale"] = True
        return enrichment
    if isinstance(now, datetime.datetime):
        now_dt = now if now.tzinfo else now.replace(tzinfo=datetime.timezone.utc)
    else:
        now_dt = datetime.datetime.fromtimestamp(float(now), datetime.timezone.utc)
    enrichment["stale"] = (now_dt - updated).total_seconds() > max_age
    return enrichment
