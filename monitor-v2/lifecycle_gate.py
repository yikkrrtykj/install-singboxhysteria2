#!/usr/bin/env python3
"""Monitor v2 phase-2 lifecycle gate -- pure verdict logic, no I/O beyond inputs.

The Linux integration canary (tests/monitor-v2-integration-e1.sh) feeds this
evaluator a BASELINE snapshot (collector ``--once``, taken BEFORE the traffic
window) and a FINAL snapshot (after ``LIFECYCLE_WINDOW`` seconds), plus the
canary configuration. The service.api initial reset replays ~1000 historically
closed connections and cumulative totals never reset, so neither
``recently_closed > 0`` nor ``uplink_total > 0`` proves anything about the
test window. Every gate here is therefore a baseline -> final DELTA:

* traffic delta   : final per-scope uplink/downlink totals must EXCEED the
                    baseline ones -- historical replay alone cannot move them;
* closed-id delta : ``recent_connections`` IDs seen at final but not at
                    baseline prove a NEW CLOSED/finalize inside this window.
                    This is the ONLY thing REQUIRE_CLOSED=1 accepts;
                    ``active_connections > 0`` is never a substitute;
* EXPECT_USER     : hard gate -- when set, the USER must appear in devices,
                    else FAIL. An empty devices dict with a named USER is a
                    FAIL, never INCONCLUSIVE: the operator named the USER;
* EXPECT_INBOUND  : optional hard gate -- vless-in (Reality) / hy2-in (HY2)
                    must be observed for the gate scope, else FAIL;
* REQUIRE_CLOSED  : 0/1 only, anything else is a configuration error;
* stale           : baseline AND final must both be non-stale.

Verdicts mirror the integration script's three-state contract:

    PASS          exit 0   every gate green
    FAIL          exit 1   a hard gate failed (or a configuration error)
    INCONCLUSIVE  exit 2   phase 1 healthy but NO real client lifecycle was
                          observed in this window (never counted as PASS)

INCONCLUSIVE is reserved for the no-EXPECT_USER run: no devices at all, or
devices that are pure historical replay (no traffic delta AND no new closed
ids). With EXPECT_USER set the verdict is always PASS or FAIL.

The unit suite (tests/test-monitor-v2-e1.sh) drives evaluate() directly with
synthetic baseline/final snapshots, so the gate logic is verified locally
without waiting for a VPS.
"""

from __future__ import annotations

import argparse
import json
import sys

ALLOWED_INBOUNDS = ("vless-in", "hy2-in")

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_INCONCLUSIVE = 2

VERDICT_PASS = "PASS"
VERDICT_FAIL = "FAIL"
VERDICT_INCONCLUSIVE = "INCONCLUSIVE"


class ConfigurationError(ValueError):
    """Gate configuration that must never look like a green run."""


def parse_require_closed(value):
    if isinstance(value, bool):
        return value
    if value in (0, 1, "0", "1"):
        return value in (1, "1")
    raise ConfigurationError(
        "REQUIRE_CLOSED must be 0 or 1 (got %r)" % (value,))


def parse_expect_inbound(value):
    if value in ("", None):
        return ""
    if value in ALLOWED_INBOUNDS:
        return value
    raise ConfigurationError(
        "EXPECT_INBOUND must be empty, vless-in or hy2-in (got %r)" % (value,))


def _fmt(value):
    text = ("%.3f" % float(value or 0)).rstrip("0").rstrip(".")
    return text or "0"


def _totals(entry):
    return (float((entry or {}).get("uplink_total") or 0),
            float((entry or {}).get("downlink_total") or 0))


def _scope_entries(snap, expect_user):
    """Device entries for the gate scope: one named USER or every device."""
    devices = snap.get("devices") or {}
    if expect_user:
        entry = devices.get(expect_user)
        return [entry] if entry else []
    return list(devices.values())


def scope_totals(snap, expect_user):
    """(uplink, downlink) summed over the gate scope."""
    up = down = 0.0
    for entry in _scope_entries(snap, expect_user):
        u, d = _totals(entry)
        up += u
        down += d
    return (up, down)


def scope_recent_ids(snap, expect_user):
    """Recent-CLOSED connection IDs for the gate scope (display cache only)."""
    ids = set()
    for entry in _scope_entries(snap, expect_user):
        for conn in entry.get("recent_connections") or []:
            cid = conn.get("id")
            if cid:
                ids.add(str(cid))
    return ids


def _scope_protocols(snap, expect_user):
    protos = set()
    for entry in _scope_entries(snap, expect_user):
        protos |= set((entry.get("protocols") or {}).keys())
    return protos


def _finish(lines, verdict, exit_code, reason):
    return {"verdict": verdict, "exit": exit_code, "reason": reason,
            "lines": lines}


def evaluate(baseline, final, expect_user="", expect_inbound="",
             require_closed=False):
    """Pure gate logic over two collector snapshots. Never raises for data."""
    lines = []

    def ok(text):
        lines.append(("PASS", text))

    def bad(text):
        lines.append(("FAIL", text))

    def info(text):
        lines.append(("INFO", text))

    expect_user = expect_user or ""
    expect_inbound = expect_inbound or ""

    # Baseline sanity: deltas are only meaningful from a healthy stream.
    if baseline.get("stale") is not False:
        bad("baseline snapshot is stale; baseline->final deltas are not "
            "trustworthy")
        return _finish(lines, VERDICT_FAIL, EXIT_FAIL,
                       "baseline snapshot is stale")

    devices = final.get("devices") or {}
    b_up, b_down = scope_totals(baseline, expect_user)
    f_up, f_down = scope_totals(final, expect_user)
    traffic_delta = f_up > b_up or f_down > b_down
    new_closed_ids = scope_recent_ids(final, expect_user) \
        - scope_recent_ids(baseline, expect_user)

    # INCONCLUSIVE escape (only WITHOUT EXPECT_USER): nothing observable
    # happened in this window. Devices seen with zero delta are historical
    # reset replay, not a real client lifecycle.
    if not expect_user:
        if not devices and (final.get("recently_closed") or 0) == 0:
            info("INCONCLUSIVE: no client traffic observed in this window; "
                 "drive a Reality/HY2 connection (stable client) and re-run")
            return _finish(lines, VERDICT_INCONCLUSIVE, EXIT_INCONCLUSIVE,
                           "no client lifecycle observed")
        if not traffic_delta and not new_closed_ids:
            info("INCONCLUSIVE: devices present are historical replay (no "
                 "traffic delta and no new closed ids in this window)")
            return _finish(lines, VERDICT_INCONCLUSIVE, EXIT_INCONCLUSIVE,
                           "no client lifecycle observed in window")

    # USER/Device observed. EXPECT_USER is a HARD gate: missing USER (even
    # with an empty devices dict) is a FAIL, never an INCONCLUSIVE.
    if expect_user:
        if expect_user in devices:
            ok("USER=%s observed" % expect_user)
        else:
            bad("expected USER was not observed (EXPECT_USER=%s; devices: %s)"
                % (expect_user, ", ".join(sorted(devices)) or "none"))
            return _finish(lines, VERDICT_FAIL, EXIT_FAIL,
                           "EXPECT_USER %s not observed" % expect_user)
    else:
        ok("device observed: %s" % ", ".join(sorted(devices)))

    # INBOUND gates: the requested production path, then the allowlist.
    if expect_inbound:
        seen = _scope_protocols(final, expect_user)
        if expect_inbound in seen:
            ok("INBOUND=%s observed" % expect_inbound)
        else:
            bad("expected INBOUND was not observed (EXPECT_INBOUND=%s; "
                "seen: %s)" % (expect_inbound, ", ".join(sorted(seen)) or "none"))
    unexpected = _scope_protocols(final, expect_user) - set(ALLOWED_INBOUNDS)
    if unexpected:
        bad("INBOUND values stay within vless-in / hy2-in (unexpected: %s)"
            % ", ".join(sorted(unexpected)))
    else:
        ok("INBOUND values stay within vless-in / hy2-in")

    # Traffic delta: cumulative totals are never a pass; the window must add
    # bytes beyond the baseline (either direction suffices).
    if traffic_delta:
        ok("traffic delta observed (uplink %s->%s, downlink %s->%s)"
           % (_fmt(b_up), _fmt(f_up), _fmt(b_down), _fmt(f_down)))
    else:
        bad("no traffic delta beyond baseline (uplink %s->%s, downlink "
            "%s->%s)" % (_fmt(b_up), _fmt(f_up), _fmt(b_down), _fmt(f_down)))

    # Source presence is metadata only -- reported as a boolean, never raw.
    source_present = any(
        conn.get("source")
        for entry in _scope_entries(final, expect_user)
        for conn in entry.get("recent_connections") or []) or any(
        entry.get("recent_sources")
        for entry in _scope_entries(final, expect_user))
    info("SOURCE_PRESENT=%s (raw source is never printed)"
         % ("true" if source_present else "false"))

    # Lifecycle evidence: a new closed id, a live connection or a device the
    # window left ACTIVE / RECENT ACTIVITY. Never a CLOSED verdict by itself.
    lifecycle = bool(new_closed_ids) or any(
        (entry.get("active_connections") or 0) > 0
        or entry.get("status") in ("ACTIVE", "RECENT ACTIVITY")
        for entry in _scope_entries(final, expect_user))
    if lifecycle:
        ok("new lifecycle observed")
    else:
        bad("no lifecycle evidence observed")

    # CLOSED/finalize gate: ONLY a recent-closed ID beyond the baseline
    # counts -- the reset replay of historical closures is not evidence.
    if require_closed:
        if new_closed_ids:
            ok("new CLOSED/finalize observed (%d new id(s) beyond baseline)"
               % len(new_closed_ids))
        else:
            bad("no CLOSED/finalize evidence observed (no new recent-closed "
                "ids beyond baseline)")
    elif new_closed_ids:
        info("new CLOSED/finalize observed (%d new id(s) beyond baseline)"
             % len(new_closed_ids))
    else:
        info("no new CLOSED in this window (REQUIRE_CLOSED=0; close the "
             "client and/or set REQUIRE_CLOSED=1 to enforce)")

    if final.get("stale") is False:
        ok("stale=false")
    else:
        bad("stale=false (final snapshot stale: %s)"
            % (final.get("last_error") or "unknown"))

    failed = [text for status, text in lines if status == "FAIL"]
    if failed:
        return _finish(lines, VERDICT_FAIL, EXIT_FAIL, failed[0])
    return _finish(lines, VERDICT_PASS, EXIT_PASS, "")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Monitor v2 phase-2 lifecycle gate evaluator "
                    "(baseline->final delta verdicts; three-state exit)")
    parser.add_argument("--baseline", required=True,
                        help="baseline snapshot JSON (collector --once)")
    parser.add_argument("--final", required=True,
                        help="final snapshot JSON (collector --duration)")
    parser.add_argument("--expect-user", default="",
                        help="hard gate: this API USER must be in devices")
    parser.add_argument("--expect-inbound", default="",
                        help="hard gate: this inbound tag must be observed")
    parser.add_argument("--require-closed", default="0",
                        help="1 = a NEW CLOSED beyond baseline is required")
    args = parser.parse_args(argv)

    try:
        require_closed = parse_require_closed(args.require_closed)
        expect_inbound = parse_expect_inbound(args.expect_inbound)
        with open(args.baseline, encoding="utf-8") as handle:
            baseline = json.load(handle)
        with open(args.final, encoding="utf-8") as handle:
            final = json.load(handle)
    except ConfigurationError as exc:
        print("FAIL\tconfiguration error: %s" % exc)
        print("RESULT\t%s" % VERDICT_FAIL)
        return EXIT_FAIL
    except (OSError, ValueError) as exc:
        print("FAIL\tcannot read gate input: %s" % exc)
        print("RESULT\t%s" % VERDICT_FAIL)
        return EXIT_FAIL

    outcome = evaluate(baseline, final, expect_user=args.expect_user,
                       expect_inbound=expect_inbound,
                       require_closed=require_closed)
    for status, text in outcome["lines"]:
        print("%s\t%s" % (status, text))
    print("RESULT\t%s" % outcome["verdict"])
    if outcome["reason"]:
        print("REASON\t%s" % outcome["reason"])
    return outcome["exit"]


if __name__ == "__main__":
    sys.exit(main())
