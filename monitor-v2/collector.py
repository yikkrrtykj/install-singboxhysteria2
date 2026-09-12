#!/usr/bin/env python3
"""Monitor v2 E1 collector -- API-first, identity-first.

Identity model (confirmed by the 1.14.0 production canary):

    Device      = API USER      (e.g. "vmix-01")
    Protocol    = API INBOUND   (e.g. "vless-in" / "hy2-in")
    Lifecycle   = API ID        (connection row id)
    Source IP   = metadata, display only -- NEVER an identity key

The collector polls the sing-box service.api (127.0.0.1:9091 only), keeps an
in-memory lifecycle accumulator and emits debug JSON. No database, no public
HTTP UI, no conntrack, no ss -- those are later phases.

Connection lifecycle state machine:

    first seen id            -> active
    same id on next poll     -> update rate/total (monotonic)
    id disappears            -> finalize: bank its last total into the device/
                                protocol cumulative counter, move the row to the
                                recent-closed cache (kept ~10 min)
    id comes back            -> reactivate the same lifecycle (never double count)

Device/protocol cumulative totals therefore never decrease when rows disappear,
and totals are never counted twice (banked once at finalize, un-banked on
reactivation).

Status semantics: the API exposes logical routed connections, not transport
heartbeats. The only honest statuses are ACTIVE / RECENT ACTIVITY / IDLE.
There is deliberately no ONLINE / OFFLINE / "Tunnel Down".
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
import time
import urllib.error
import urllib.request
from collections import OrderedDict

DEFAULT_URL = "http://127.0.0.1:9091"
DEFAULT_CONNECTIONS_PATH = "/connections"
DEFAULT_TIMEOUT = 3.0
DEFAULT_INTERVAL = 3.0
DEFAULT_CLOSED_TTL = 600.0  # keep finalized ids ~10 minutes
RECENT_SOURCES_MAX = 10
RECENT_CONNECTIONS_MAX = 20

STATUS_ACTIVE = "ACTIVE"
STATUS_RECENT = "RECENT ACTIVITY"
STATUS_IDLE = "IDLE"


def _num(value, default=0.0):
    """Tolerant numeric parse: int/float pass through, numeric strings ok."""
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return default
    return default


def _str(value):
    return value if isinstance(value, str) else ""


def normalize_row(row):
    """Extract the identity/traffic fields from one API row.

    Returns None for anything that cannot be safely attributed (fail-safe:
    a malformed row is skipped, never allowed to pollute the aggregate state).
    """
    if not isinstance(row, dict):
        return None
    cid = row.get("id")
    user = row.get("user")
    inbound = row.get("inbound")
    if not isinstance(cid, str) or not cid:
        return None
    if not isinstance(user, str) or not user:
        return None
    if not isinstance(inbound, str) or not inbound:
        return None
    return {
        "id": cid,
        "user": user,
        "inbound": inbound,
        "network": _str(row.get("network")),
        "source": _str(row.get("source")),
        "destination": _str(row.get("destination")),
        "created": _str(row.get("created")),
        "rate": max(0.0, _num(row.get("rate"))),
        "total": max(0.0, _num(row.get("total"))),
    }


def fetch_connections(url, connections_path=DEFAULT_CONNECTIONS_PATH,
                      timeout=DEFAULT_TIMEOUT, secret=None):
    """API adapter: GET {url}{connections_path}, return the raw rows list."""
    request = urllib.request.Request(url.rstrip("/") + connections_path)
    if secret:
        request.add_header("Authorization", "Bearer " + secret)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = json.loads(response.read().decode("utf-8"))
    if isinstance(data, dict):
        rows = data.get("connections")
    elif isinstance(data, list):
        rows = data
    else:
        rows = []
    return rows if isinstance(rows, list) else []


class Tracker:
    """In-memory lifecycle accumulator (first version: no database)."""

    def __init__(self, closed_ttl=DEFAULT_CLOSED_TTL):
        self.closed_ttl = closed_ttl
        self.active = {}            # id -> connection dict (+ last_seen)
        self.closed = OrderedDict() # id -> connection dict (+ closed_at), oldest first
        self.finalized = {}         # (user, inbound) -> banked cumulative total
        self.devices = set()        # every device name ever observed
        self.poll_count = 0
        self.skipped_rows = 0
        self.duplicate_rows = 0

    def poll(self, rows, now):
        """Feed one API poll (rows list) at timestamp `now`."""
        rows = rows if isinstance(rows, list) else []
        self.poll_count += 1
        seen = set()
        normalized = []
        for row in rows:
            item = normalize_row(row)
            if item is None:
                self.skipped_rows += 1
                continue
            if item["id"] in seen:
                self.duplicate_rows += 1  # same id twice in one poll: keep first
                continue
            seen.add(item["id"])
            normalized.append(item)

        for item in normalized:
            cid = item["id"]
            existing = self.active.get(cid)
            if existing is not None:
                # same lifecycle: totals are monotonic
                item["total"] = max(existing["total"], item["total"])
                item["created"] = existing["created"] or item["created"]
            else:
                closed_conn = self.closed.pop(cid, None)
                if closed_conn is not None:
                    # reactivation of a recently finalized id: continue the same
                    # lifecycle and un-bank its total (no double counting)
                    key = (closed_conn["user"], closed_conn["inbound"])
                    self.finalized[key] = max(
                        0.0, self.finalized.get(key, 0.0) - closed_conn["total"])
                    item["total"] = max(closed_conn["total"], item["total"])
                    item["created"] = closed_conn["created"] or item["created"]
            item["last_seen"] = now
            self.active[cid] = item
            self.devices.add(item["user"])

        # finalize ids that disappeared from this poll
        for cid in list(self.active.keys()):
            if cid in seen:
                continue
            conn = self.active.pop(cid)
            conn["closed_at"] = now
            key = (conn["user"], conn["inbound"])
            # bank the final total once: device totals keep it after the row is
            # gone, and the closed cache below is display-only
            self.finalized[key] = self.finalized.get(key, 0.0) + conn["total"]
            self.closed[cid] = conn

        # prune the recent-closed cache (totals stay banked, nothing drops)
        expired = [cid for cid, c in self.closed.items()
                   if now - c["closed_at"] > self.closed_ttl]
        for cid in expired:
            del self.closed[cid]

    def snapshot(self, now):
        """Aggregate the current state into the debug JSON model."""
        per_device_active = {}
        per_device_closed = {}
        for conn in self.active.values():
            per_device_active.setdefault(conn["user"], []).append(conn)
        for conn in self.closed.values():
            per_device_closed.setdefault(conn["user"], []).append(conn)

        devices = {}
        for name in sorted(self.devices | set(per_device_active) | set(per_device_closed)):
            active = per_device_active.get(name, [])
            closed = per_device_closed.get(name, [])
            proto_names = sorted(
                {c["inbound"] for c in active}
                | {c["inbound"] for c in closed}
                | {inbound for (user, inbound) in self.finalized if user == name})
            protocols = {}
            for inbound in proto_names:
                proto_active = [c for c in active if c["inbound"] == inbound]
                banked = self.finalized.get((name, inbound), 0.0)
                protocols[inbound] = {
                    "active_connections": len(proto_active),
                    "rate": round(sum(c["rate"] for c in proto_active), 3),
                    "total": round(sum(c["total"] for c in proto_active) + banked, 3),
                }
            device_total = sum(c["total"] for c in active) + sum(
                self.finalized.get((name, inbound), 0.0) for inbound in proto_names)
            last_seen_list = [c["last_seen"] for c in active + closed]
            if active:
                status = STATUS_ACTIVE
            elif closed:
                status = STATUS_RECENT
            else:
                status = STATUS_IDLE
            recent_conns = sorted(closed, key=lambda c: c["closed_at"],
                                  reverse=True)[:RECENT_CONNECTIONS_MAX]
            devices[name] = {
                "status": status,
                "protocols": protocols,
                "active_connections": len(active),
                "recent_sources": sorted(
                    {c["source"] for c in active + closed if c["source"]}
                )[:RECENT_SOURCES_MAX],
                "rate": round(sum(c["rate"] for c in active), 3),
                "total": round(device_total, 3),
                "last_activity": max(last_seen_list) if last_seen_list else None,
                "recent_connections": [
                    {"id": c["id"], "inbound": c["inbound"], "source": c["source"],
                     "destination": c["destination"], "total": round(c["total"], 3),
                     "closed_at": c["closed_at"]}
                    for c in recent_conns
                ],
            }

        return {
            "poll_count": self.poll_count,
            "skipped_rows": self.skipped_rows,
            "duplicate_rows": self.duplicate_rows,
            "active_connections": len(self.active),
            "recently_closed": len(self.closed),
            "devices": devices,
        }


class Collector:
    """API adapter + tracker: poll_once() never raises and marks staleness."""

    def __init__(self, url=DEFAULT_URL, connections_path=DEFAULT_CONNECTIONS_PATH,
                 timeout=DEFAULT_TIMEOUT, secret=None, closed_ttl=DEFAULT_CLOSED_TTL):
        self.url = url
        self.connections_path = connections_path
        self.timeout = timeout
        self.secret = secret
        self.tracker = Tracker(closed_ttl=closed_ttl)
        self.stale = False
        self.last_error = None

    def poll_once(self, now=None):
        now = time.time() if now is None else now
        try:
            rows = fetch_connections(self.url, self.connections_path,
                                     self.timeout, self.secret)
            self.tracker.poll(rows, now)
            self.stale = False
            self.last_error = None
        except Exception as exc:  # noqa: BLE001 -- any API failure keeps state
            self.stale = True
            self.last_error = str(exc)
        return self.snapshot(now)

    def snapshot(self, now):
        snap = self.tracker.snapshot(now)
        snap["stale"] = self.stale
        snap["last_error"] = self.last_error
        snap["generated_at"] = datetime.datetime.fromtimestamp(
            now, datetime.timezone.utc).isoformat()
        return snap


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Monitor v2 E1 collector (API-first, identity = API USER)")
    parser.add_argument("--url", default=DEFAULT_URL,
                        help="service.api base URL (default: %(default)s, loopback only)")
    parser.add_argument("--connections-path", default=DEFAULT_CONNECTIONS_PATH,
                        help="API path (default: %(default)s)")
    parser.add_argument("--secret-file", default=None,
                        help="optional file containing the API bearer token")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--closed-ttl", type=float, default=DEFAULT_CLOSED_TTL,
                        help="how long finalized ids stay in the recent cache")
    parser.add_argument("--once", action="store_true",
                        help="poll once, print the JSON state, exit")
    parser.add_argument("--loop", action="store_true",
                        help="poll continuously and print one JSON state per poll")
    parser.add_argument("--interval", type=float, default=DEFAULT_INTERVAL,
                        help="loop polling interval in seconds (default: %(default)s)")
    parser.add_argument("--pretty", action="store_true", help="indent the JSON output")
    args = parser.parse_args(argv)

    secret = None
    if args.secret_file:
        with open(args.secret_file, encoding="utf-8") as handle:
            secret = handle.read().strip()

    collector = Collector(url=args.url, connections_path=args.connections_path,
                          timeout=args.timeout, secret=secret,
                          closed_ttl=args.closed_ttl)
    if args.loop:
        try:
            while True:
                print(json.dumps(collector.poll_once(), sort_keys=True), flush=True)
                time.sleep(args.interval)
        except KeyboardInterrupt:
            return 0
    snap = collector.poll_once()
    print(json.dumps(snap, indent=2 if args.pretty else None, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
