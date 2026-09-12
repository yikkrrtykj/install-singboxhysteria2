#!/usr/bin/env python3
"""Monitor v2 E1 collector -- API-first, identity-first, event-driven.

Identity model (confirmed by the 1.14.0 production canary):

    Device      = API USER      (e.g. "vmix-01")
    Protocol    = API INBOUND TAG (e.g. "vless-in" / "hy2-in"; inbound_type is
                  stored separately and is NOT part of the identity)
    Lifecycle   = API connection ID (immutable identity for its whole life)
    Source IP   = metadata, display only -- NEVER an identity key

The collector consumes the OFFICIAL service.api event stream
(``daemon.StartedService/SubscribeConnections`` over gRPC-Web on the loopback
listener -- see monitor-v2/api_bridge/) and maintains an in-memory lifecycle
accumulator. No database, no public UI, no conntrack, no ss.

Official stream contract (verified against the v1.14.0 source,
``daemon/started_service.go`` -- do NOT guess):

* the FIRST message of a subscription carries ``reset=true`` with NEW events
  for ALL active connections plus NEW events (with ``closedAt``) for recently
  closed ones;
* UPDATE carries only id + uplinkDelta + downlinkDelta (no Connection object);
  UPDATE(0,0) means "traffic stopped";
* CLOSED carries id + closedAt and finalizes exactly once;
* neither the server nor this collector relies on ids disappearing from a
  later poll.

Traffic model: ``uplink`` / ``downlink`` are the OFFICIAL API direction names
and are kept separate everywhere (connection, protocol, device). They are NOT
relabelled upload/download -- the client-perspective mapping is a later,
explicit step. Authoritative totals rule:

* NEW carries authoritative uplinkTotal/downlinkTotal (lifecycle start);
* UPDATE without a Connection object ADDS the deltas;
* UPDATE WITH a Connection object REPLACES the totals (authoritative);
* CLOSED banks the final lifecycle totals exactly once into the device/protocol
  cumulative counters: totals never decrease, never double count.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
import time

from api_bridge.singbox_stream import (ConfigurationError, SingboxEventStream,
                                       parse_api_url)

DEFAULT_URL = "http://127.0.0.1:9091"
DEFAULT_INTERVAL = 2.0
DEFAULT_CLOSED_TTL = 600.0  # keep finalized ids ~10 minutes
RECENT_SOURCES_MAX = 10
RECENT_CONNECTIONS_MAX = 20
SECRET_ENV = "BOX_API_SECRET"

STATUS_ACTIVE = "ACTIVE"
STATUS_RECENT = "RECENT ACTIVITY"
STATUS_IDLE = "IDLE"


def _iso(timestamp):
    if timestamp is None:
        return None
    return datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc).isoformat()


def _to_seconds(timestamp):
    """Normalize proto epoch timestamps to seconds.

    The official proto carries createdAt/closedAt as UnixMilli; the collector
    clock runs in seconds. Epoch milliseconds are ~1.7e12, seconds ~1.7e9, so
    the threshold is unambiguous for any plausible clock.
    """
    if not timestamp:
        return 0
    value = float(timestamp)
    return value / 1000.0 if value > 1e11 else value


def redact(text, secrets):
    if not text:
        return text
    for secret in secrets:
        if secret:
            text = text.replace(secret, "[redacted]")
    return text


def _row_identity(fields):
    return fields.get("user"), fields.get("inbound")


def _new_connection(fields, now):
    return {
        "id": fields["id"],
        "user": fields["user"],
        "inbound": fields["inbound"],
        "inbound_type": fields.get("inbound_type", ""),
        "network": fields.get("network", ""),
        "source": fields.get("source", ""),
        "destination": fields.get("destination", ""),
        "created_at": _to_seconds(fields.get("created_at")) or now,
        "closed_at": 0,
        "uplink_rate": 0.0,
        "downlink_rate": 0.0,
        "uplink_total": float(fields.get("uplink_total", 0)),
        "downlink_total": float(fields.get("downlink_total", 0)),
        "last_seen": now,
    }


class Tracker:
    """In-memory event-driven lifecycle accumulator (no database)."""

    def __init__(self, closed_ttl=DEFAULT_CLOSED_TTL, interval=DEFAULT_INTERVAL):
        self.closed_ttl = closed_ttl
        self.interval = interval
        self.active = {}    # id -> connection dict
        self.closed = {}    # id -> connection dict (+ closed_at), recent only
        self.finalized = {}  # (user, inbound) -> {"uplink": x, "downlink": y}
        self.devices = set()  # every device name ever observed
        self.batch_count = 0
        self.skipped_events = 0      # malformed / unknown-id events (fail-safe)
        self.duplicate_events = 0    # CLOSED for an already-finalized id
        self.identity_conflicts = 0  # id tried to change user/inbound (HIGH guard)
        self.abandoned_on_reset = 0  # active ids dropped by reset without CLOSED

    def _bank(self, key, uplink, downlink):
        slot = self.finalized.setdefault(key, {"uplink": 0.0, "downlink": 0.0})
        slot["uplink"] += uplink
        slot["downlink"] += downlink

    def _unbank(self, key, uplink, downlink):
        slot = self.finalized.setdefault(key, {"uplink": 0.0, "downlink": 0.0})
        slot["uplink"] = max(0.0, slot["uplink"] - uplink)
        slot["downlink"] = max(0.0, slot["downlink"] - downlink)

    def _identity_conflict(self, conn, fields, now):
        """HIGH guard: an id keeps its (user, inbound) identity forever.

        A conflicting event never moves accumulated traffic to another device,
        never overwrites the lifecycle identity and is counted. Returns True
        when the event may proceed (identity matches or carries none).
        """
        incoming = _row_identity(fields)
        if None in incoming or not all(incoming):
            return True  # event carries no identity fields to compare
        current = (conn["user"], conn["inbound"])
        if incoming == current:
            return True
        self.identity_conflicts += 1
        conn["last_seen"] = now
        return False

    def _finalize(self, conn, now, closed_at=None):
        conn["closed_at"] = _to_seconds(closed_at) or conn["closed_at"] or now
        conn["last_seen"] = now
        conn["uplink_rate"] = 0.0
        conn["downlink_rate"] = 0.0
        key = (conn["user"], conn["inbound"])
        # bank exactly once, at finalize time
        self._bank(key, conn["uplink_total"], conn["downlink_total"])
        self.closed[conn["id"]] = conn

    # -- batch / event application ----------------------------------------------

    def apply_batch(self, batch, now):
        if not isinstance(batch, dict):
            self.skipped_events += 1
            return
        self.batch_count += 1
        events = batch.get("events") or []
        if batch.get("reset"):
            self._apply_reset(events, now)
            return
        for event in events:
            self._apply_event(event, now)

    def _apply_reset(self, events, now):
        """reset=true: rebuild the snapshot from the official batch.

        Per the official server implementation the reset batch contains NEW
        events for all currently ACTIVE connections plus NEW events (with
        closedAt) for recently CLOSED ones. Active lifecycles present in the
        batch are refreshed with the authoritative totals (same lifecycle, no
        double counting). Active ids NOT present in the batch are dropped
        WITHOUT banking -- the server never confirmed them closed, so banking
        would be guessing.
        """
        seen = set()
        for event in events:
            if not isinstance(event, dict):
                self.skipped_events += 1
                continue
            fields = event.get("connection")
            fields = fields if isinstance(fields, dict) else {}
            cid = event.get("id") or fields.get("id")
            user, inbound = _row_identity(fields)
            if not cid or not user or not inbound:
                self.skipped_events += 1
                continue
            seen.add(cid)
            closed_at = _to_seconds(fields.get("closed_at"))
            if closed_at:
                self._record_closed_row(cid, fields, now, closed_at)
            else:
                self._upsert_active(cid, fields, now)
        for cid in [c for c in list(self.active) if c not in seen]:
            self.active.pop(cid)
            self.abandoned_on_reset += 1

    def _upsert_active(self, cid, fields, now):
        existing = self.active.get(cid)
        if existing is not None:
            if not self._identity_conflict(existing, fields, now):
                return
            # authoritative totals: same lifecycle, values replaced not added
            existing["uplink_total"] = max(existing["uplink_total"],
                                           float(fields.get("uplink_total", 0)))
            existing["downlink_total"] = max(existing["downlink_total"],
                                             float(fields.get("downlink_total", 0)))
            existing["last_seen"] = now
            return
        closed_conn = self.closed.pop(cid, None)
        if closed_conn is not None and \
                (closed_conn["user"], closed_conn["inbound"]) != (fields.get("user"),
                                                                  fields.get("inbound")):
            # reactivation with a different identity is a conflict too
            self.closed[cid] = closed_conn
            self.identity_conflicts += 1
            return
        conn = _new_connection({"id": cid, "user": fields["user"],
                                "inbound": fields["inbound"],
                                "inbound_type": fields.get("inbound_type", ""),
                                "network": fields.get("network", ""),
                                "source": fields.get("source", ""),
                                "destination": fields.get("destination", ""),
                                "created_at": fields.get("created_at"),
                                "uplink_total": fields.get("uplink_total", 0),
                                "downlink_total": fields.get("downlink_total", 0)}, now)
        if closed_conn is not None:
            # reactivation: continue the same lifecycle, un-bank its totals
            key = (closed_conn["user"], closed_conn["inbound"])
            self._unbank(key, closed_conn["uplink_total"], closed_conn["downlink_total"])
            conn["uplink_total"] = max(closed_conn["uplink_total"], conn["uplink_total"])
            conn["downlink_total"] = max(closed_conn["downlink_total"], conn["downlink_total"])
            conn["created_at"] = closed_conn["created_at"] or conn["created_at"]
        self.active[cid] = conn
        self.devices.add(conn["user"])

    def _record_closed_row(self, cid, fields, now, closed_at):
        """A closed connection announced as NEW (reset batches / initial state)."""
        user, inbound = _row_identity(fields)
        self.devices.add(user)
        if cid in self.closed:
            self.duplicate_events += 1  # already banked once
            return
        if cid in self.active:
            # the active lifecycle received its authoritative closure
            conn = self.active.pop(cid)
            conn["uplink_total"] = max(conn["uplink_total"],
                                       float(fields.get("uplink_total", 0)))
            conn["downlink_total"] = max(conn["downlink_total"],
                                         float(fields.get("downlink_total", 0)))
            self._finalize(conn, now, closed_at=closed_at)
            return
        conn = _new_connection({"id": cid, "user": user, "inbound": inbound,
                                "inbound_type": fields.get("inbound_type", ""),
                                "network": fields.get("network", ""),
                                "source": fields.get("source", ""),
                                "destination": fields.get("destination", ""),
                                "created_at": fields.get("created_at"),
                                "uplink_total": fields.get("uplink_total", 0),
                                "downlink_total": fields.get("downlink_total", 0)}, now)
        conn["closed_at"] = closed_at or now
        self._finalize(conn, now, closed_at=conn["closed_at"])

    def _apply_event(self, event, now):
        if not isinstance(event, dict):
            self.skipped_events += 1
            return
        etype = event.get("type")
        cid = event.get("id")
        fields = event.get("connection") if isinstance(event.get("connection"), dict) else {}

        if etype == "NEW":
            closed_at = _to_seconds(fields.get("closed_at"))
            if closed_at:
                self._record_closed_row(cid or "", fields, now, closed_at)
                return
            if not cid:
                self.skipped_events += 1
                return
            user, inbound = _row_identity(fields)
            if not user or not inbound:
                self.skipped_events += 1
                return
            self._upsert_active(cid, fields, now)
            return

        if etype == "UPDATE":
            conn = self.active.get(cid)
            if conn is None:
                # UPDATE for an unknown id: fail-safe, never a phantom device
                self.skipped_events += 1
                return
            if fields and not self._identity_conflict(conn, fields, now):
                return  # identity drift: traffic must not migrate
            elapsed = max(now - conn["last_seen"], 1e-6)
            uplink_delta = float(event.get("uplink_delta", 0))
            downlink_delta = float(event.get("downlink_delta", 0))
            if "uplink_total" in fields or "downlink_total" in fields:
                # authoritative totals inside the UPDATE: replace, never add
                if "uplink_total" in fields:
                    conn["uplink_total"] = max(conn["uplink_total"],
                                               float(fields.get("uplink_total", 0)))
                if "downlink_total" in fields:
                    conn["downlink_total"] = max(conn["downlink_total"],
                                                 float(fields.get("downlink_total", 0)))
            else:
                conn["uplink_total"] += uplink_delta
                conn["downlink_total"] += downlink_delta
            conn["uplink_rate"] = uplink_delta / elapsed
            conn["downlink_rate"] = downlink_delta / elapsed
            conn["last_seen"] = now
            return

        if etype == "CLOSED":
            conn = self.active.pop(cid, None)
            if conn is not None:
                self._finalize(conn, now, closed_at=event.get("closed_at"))
                return
            if cid in self.closed:
                self.duplicate_events += 1  # finalize exactly once
                return
            self.skipped_events += 1  # unknown id: no invented traffic
            return

        self.skipped_events += 1  # unknown event type

    def snapshot(self, now):
        # prune the recent-closed cache by TTL; banked totals are unaffected
        # (they live in self.finalized and never decrease)
        expired = [cid for cid, c in self.closed.items()
                   if now - c["last_seen"] > self.closed_ttl]
        for cid in expired:
            del self.closed[cid]
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
                banked = self.finalized.get((name, inbound),
                                            {"uplink": 0.0, "downlink": 0.0})
                protocols[inbound] = {
                    "device_name": name,
                    "inbound": inbound,
                    "active_connections": len(proto_active),
                    "uplink_rate": round(sum((c["uplink_rate"] for c in proto_active), 0.0), 3),
                    "downlink_rate": round(sum((c["downlink_rate"] for c in proto_active), 0.0), 3),
                    "uplink_total": round(sum((c["uplink_total"] for c in proto_active), 0.0)
                                          + banked["uplink"], 3),
                    "downlink_total": round(sum((c["downlink_total"] for c in proto_active), 0.0)
                                            + banked["downlink"], 3),
                }
            banked_all = [self.finalized.get((name, inbound),
                                             {"uplink": 0.0, "downlink": 0.0})
                          for inbound in proto_names]
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
                "name": name,
                "status": status,
                "protocols": protocols,
                "active_connections": len(active),
                "uplink_rate": round(sum((c["uplink_rate"] for c in active), 0.0), 3),
                "downlink_rate": round(sum((c["downlink_rate"] for c in active), 0.0), 3),
                "uplink_total": round(sum((c["uplink_total"] for c in active), 0.0)
                                      + sum((b["uplink"] for b in banked_all), 0.0), 3),
                "downlink_total": round(sum((c["downlink_total"] for c in active), 0.0)
                                        + sum((b["downlink"] for b in banked_all), 0.0), 3),
                "recent_sources": sorted(
                    {c["source"] for c in active + closed if c["source"]}
                )[:RECENT_SOURCES_MAX],
                "last_activity": _iso(max(last_seen_list)) if last_seen_list else None,
                "recent_connections": [
                    {"id": c["id"], "inbound": c["inbound"], "source": c["source"],
                     "destination": c["destination"],
                     "uplink_total": round(c["uplink_total"], 3),
                     "downlink_total": round(c["downlink_total"], 3),
                     "closed_at": _iso(c["closed_at"])}
                    for c in recent_conns
                ],
            }

        return {
            "batch_count": self.batch_count,
            "skipped_events": self.skipped_events,
            "duplicate_events": self.duplicate_events,
            "identity_conflicts": self.identity_conflicts,
            "abandoned_on_reset": self.abandoned_on_reset,
            "active_connections": len(self.active),
            "recently_closed": len(self.closed),
            "devices": devices,
        }

class Collector:
    """Stream consumer + tracker: consume() never raises and marks staleness.

    Stream failures (connection refused, timeout, EOF, decode error, bad gRPC
    status) keep the last known state, never finalize anything, never zero any
    counter, and set ``stale=True`` until a subsequent batch succeeds.
    """

    def __init__(self, url=DEFAULT_URL, interval=DEFAULT_INTERVAL, secret=None,
                 closed_ttl=DEFAULT_CLOSED_TTL, stream_factory=None,
                 clock=time.time):
        # parse_api_url is fail-closed: non-loopback targets are a fatal
        # configuration error (credentials must never leave the machine).
        self.url = url
        self.host, self.port = parse_api_url(url)
        self.interval = interval
        self.secret = secret
        self.clock = clock
        self.tracker = Tracker(closed_ttl=closed_ttl, interval=interval)
        self.stream_factory = stream_factory or (
            lambda: SingboxEventStream(url, interval_seconds=interval,
                                       secret=secret))
        self.stale = False
        self.last_error = None
        self.last_success_at = None
        self.consecutive_failures = 0

    def _secrets(self):
        secrets = [self.secret, os.environ.get(SECRET_ENV, "")]
        return [s for s in secrets if s]

    def consume(self, duration=None, max_batches=None):
        """Consume the event stream. Exactly one of duration/max_batches is set.

        Reconnects with capped backoff on stream failure until the duration (or
        the batch budget) is exhausted. Never raises.
        """
        if (duration is None) == (max_batches is None):
            raise ValueError("consume() needs exactly one of duration/max_batches")
        start = self.clock()
        deadline = start + duration if duration is not None else None
        applied = 0
        backoff = 0.2
        secrets = self._secrets()
        while True:
            try:
                for batch in self.stream_factory():
                    now = self.clock()
                    self.tracker.apply_batch(batch, now)
                    applied += 1
                    self.stale = False
                    self.consecutive_failures = 0
                    self.last_success_at = now
                    self.last_error = None
                    if max_batches is not None and applied >= max_batches:
                        return applied
                    if deadline is not None and self.clock() >= deadline:
                        return applied
                raise RuntimeError("event stream ended by the server")
            except Exception as exc:  # noqa: BLE001 -- stale semantics
                self.stale = True
                self.consecutive_failures += 1
                self.last_error = redact("%s: %s" % (type(exc).__name__, exc),
                                         secrets)
                if max_batches is not None and applied >= max_batches:
                    return applied
                if deadline is not None:
                    if self.clock() >= deadline:
                        return applied
                    time.sleep(min(backoff, max(0.0, deadline - self.clock())))
                    backoff = min(backoff * 2, 2.0)
                else:
                    return applied  # batch-budget mode: one failure ends it

    def snapshot(self):
        now = self.clock()
        snap = self.tracker.snapshot(now)
        snap["stale"] = self.stale
        snap["last_error"] = redact(self.last_error, self._secrets())
        snap["last_success_at"] = _iso(self.last_success_at)
        snap["generated_at"] = _iso(now)
        return snap


def resolve_secret(secret_file):
    """BOX_API_SECRET environment wins; otherwise read --secret-file (0600)."""
    env_secret = os.environ.get(SECRET_ENV, "")
    if env_secret:
        return env_secret
    if secret_file:
        with open(secret_file, encoding="utf-8") as handle:
            return handle.read().strip()
    return ""


def build_arg_parser():
    parser = argparse.ArgumentParser(
        description="Monitor v2 E1 collector "
                    "(API-first, identity = API USER, loopback-only service.api)")
    parser.add_argument("--url", default=DEFAULT_URL,
                        help="service.api URL; MUST be loopback (default: %(default)s)")
    parser.add_argument("--interval", type=float, default=DEFAULT_INTERVAL,
                        help="stream UPDATE pacing in seconds (default: %(default)s)")
    parser.add_argument("--secret-file", default=None,
                        help="file holding the API bearer token (mode 0600); "
                             "%s takes precedence" % SECRET_ENV)
    parser.add_argument("--closed-ttl", type=float, default=DEFAULT_CLOSED_TTL,
                        help="how long finalized ids stay in the recent cache")
    parser.add_argument("--timeout", type=float, default=5.0,
                        help="per-read stream timeout in seconds")
    parser.add_argument("--once", action="store_true",
                        help="consume the first (reset) batch, print JSON, exit")
    parser.add_argument("--duration", type=float, default=None,
                        help="consume the stream for this many seconds, then "
                             "print the JSON state and exit")
    parser.add_argument("--pretty", action="store_true", help="indent JSON output")
    return parser


def main(argv=None):
    args = build_arg_parser().parse_args(argv)
    secret = resolve_secret(args.secret_file)

    def factory():
        return SingboxEventStream(args.url, interval_seconds=args.interval,
                                  secret=secret, timeout=args.timeout)

    try:
        collector = Collector(url=args.url, interval=args.interval,
                              secret=secret, closed_ttl=args.closed_ttl,
                              stream_factory=factory)
    except ConfigurationError as exc:
        print("fatal configuration error: %s" % exc, file=sys.stderr)
        return 2

    if args.once:
        collector.consume(max_batches=1)
    elif args.duration is not None:
        collector.consume(duration=args.duration)
    else:
        print("nothing to do: pass --once or --duration SECONDS", file=sys.stderr)
        return 2
    print(json.dumps(collector.snapshot(), indent=2 if args.pretty else None,
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
