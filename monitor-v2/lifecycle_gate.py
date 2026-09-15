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
                    must be observed for the gate scope, else FAIL. It is
                    NOT just a presence check: it binds BOTH deltas above to
                    the USER + INBOUND scope (traffic reads ONLY
                    ``devices[USER]["protocols"][INBOUND]``, closures only
                    ``recent_connections`` rows carried by that inbound), so
                    a sibling protocol's growth or closures can never make
                    the canary pass;
* REQUIRE_CLOSED  : 0/1 only, anything else is a configuration error;
* stale           : baseline AND final must both be non-stale.

Verdicts mirror the integration script's three-state contract:

    PASS          exit 0   every gate green
    FAIL          exit 1   a hard gate failed (or a configuration error)
    INCONCLUSIVE  exit 2   the fully observational run (NO gate set) saw no
                          real client lifecycle in this window (never
                          counted as PASS)

CLOSE_GRACE_WINDOW (REQUIRE_CLOSED=1 only): when the primary window fails
with the CLOSED gate as the ONLY failure (all other gates green -- USER,
INBOUND, traffic delta, lifecycle, stale), the integration script may run an
additional grace window and feed the resulting snapshot as ``grace_final``.
Grace semantics (enforced here):

* the ORIGINAL baseline stays authoritative -- no recapture, same
  USER/INBOUND scope;
* a sibling protocol's closure can never satisfy the gate (scoping is
  unchanged);
* an active connection is NEVER a substitute for a CLOSED/finalize;
* the snapshot must be non-stale and identity-conflict-free for the whole
  grace window, else FAIL;
* a new recent-closed id beyond the original baseline inside the window ->
  PASS; timeout without one -> FAIL;
* grace can NEVER rescue a primary-window failure of any other gate
  (traffic / USER / INBOUND / lifecycle): those go straight to FAIL.

Sticky scoped CLOSED evidence: the final/grace snapshot is NOT judged from
``recent_connections`` alone -- that is a bounded 20-row display cache, so a
busy device closing >20 newer connections can evict the wanted closure AFTER
it was observed. The gate therefore reads the UNION of recent_connections and
the collector's evidence-grade ``closed_ids`` projection (every closed
lifecycle within the collector's TTL bank, which outlives the whole grace
interval), always under the ORIGINAL baseline subtraction and the USER×
INBOUND scope. Display-cache eviction after observation can therefore never
cause a false FAIL (and the baseline subtraction keeps replayed ids dead, so
it can never cause a false PASS either). The dashboard cache itself is NOT
enlarged as the fix.

When the gate is called WITHOUT ``grace_final`` and reports
``grace_eligible`` (also printed as a GRACE_ELIGIBLE line by the CLI), the
caller MAY enter the grace window; it is never mandatory.

INCONCLUSIVE is reserved for gate-free runs: no devices at all, or devices
that are pure historical replay (no traffic delta AND no new closed ids).
Any strict gate (EXPECT_USER / EXPECT_INBOUND / REQUIRE_CLOSED=1) asserts
evidence and must FAIL, never downgrade to INCONCLUSIVE.

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

# The REQUIRE_CLOSED gate failure line starts with this prefix. It is the
# ONLY failure the CLOSE_GRACE window is allowed to resolve.
CLOSED_FAIL_REASON = "no CLOSED/finalize evidence observed"


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


def _scoped_devices(snap, expect_user):
    """Device entries for the gate scope: one named USER or every device."""
    devices = snap.get("devices") or {}
    if expect_user:
        entry = devices.get(expect_user)
        return [entry] if entry else []
    return list(devices.values())


def scope_totals(snap, expect_user, expect_inbound=""):
    """(uplink, downlink) over the gate scope.

    With expect_inbound the gate reads ONLY devices[..]["protocols"][inbound]:
    a USER's sibling protocol must never make the traffic delta pass. Without
    it, device-level totals (USER scope / all-device scope) are used, exactly
    like before the inbound scoping existed.
    """
    up = down = 0.0
    for dev in _scoped_devices(snap, expect_user):
        if expect_inbound:
            proto = (dev.get("protocols") or {}).get(expect_inbound) or {}
            up += float(proto.get("uplink_total") or 0)
            down += float(proto.get("downlink_total") or 0)
        else:
            up += float(dev.get("uplink_total") or 0)
            down += float(dev.get("downlink_total") or 0)
    return (up, down)


def scope_recent_ids(snap, expect_user, expect_inbound=""):
    """Closed-connection IDs for the gate scope (baseline-delta evidence).

    Reads the union of:
    * ``recent_connections`` -- the 20-row RECENT display cache (all older
      snapshots keep working exactly as before); and
    * ``closed_ids`` -- the collector's evidence-grade projection that covers
      every closed lifecycle within the TTL, so a busy device evicting rows
      from the display cache during a long CLOSE_GRACE_WINDOW can never hide
      an in-window CLOSED (eviction can only cause a false FAIL, never a
      false PASS: the baseline subtraction blocks reset replay).

    With expect_inbound only closures CARRIED by that inbound count: a
    vless-in CLOSED must never satisfy a hy2-in REQUIRE_CLOSED gate.
    """
    ids = set()
    for dev in _scoped_devices(snap, expect_user):
        for source in (dev.get("recent_connections") or [],
                       dev.get("closed_ids") or []):
            for conn in source:
                if isinstance(conn, dict):
                    cid, inbound = conn.get("id"), conn.get("inbound")
                else:
                    cid, inbound = conn, None  # bare id: no scoping info
                if not cid:
                    continue
                if expect_inbound and inbound != expect_inbound:
                    continue
                ids.add(str(cid))
    return ids


def _scope_active(snap, expect_user, expect_inbound=""):
    """True when the gate scope currently holds a live connection."""
    for dev in _scoped_devices(snap, expect_user):
        if expect_inbound:
            proto = (dev.get("protocols") or {}).get(expect_inbound) or {}
            if (proto.get("active_connections") or 0) > 0:
                return True
        elif (dev.get("active_connections") or 0) > 0:
            return True
    return False


def _scope_protocols(snap, expect_user):
    """ALL inbound tags seen for the gate scope (allowlist check only)."""
    protos = set()
    for dev in _scoped_devices(snap, expect_user):
        protos |= set((dev.get("protocols") or {}).keys())
    return protos


def _finish(lines, verdict, exit_code, reason, grace_eligible=False):
    return {"verdict": verdict, "exit": exit_code, "reason": reason,
            "lines": lines, "grace_eligible": grace_eligible}


def evaluate(baseline, final, expect_user="", expect_inbound="",
             require_closed=False, grace_final=None):
    """Pure gate logic over two collector snapshots. Never raises for data.

    ``grace_final`` (optional) is the CLOSE_GRACE_WINDOW snapshot, evaluated
    ONLY when the primary window's sole failure is the CLOSED gate; see the
    module docstring for the exact grace contract.
    """
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
    b_up, b_down = scope_totals(baseline, expect_user, expect_inbound)
    f_up, f_down = scope_totals(final, expect_user, expect_inbound)
    traffic_delta = f_up > b_up or f_down > b_down
    baseline_ids = scope_recent_ids(baseline, expect_user, expect_inbound)
    new_closed_ids = scope_recent_ids(final, expect_user, expect_inbound) \
        - baseline_ids

    # INCONCLUSIVE escape: ONLY the fully observational run (no gate set)
    # may report "nothing observed" as INCONCLUSIVE. A strict canary
    # (EXPECT_USER / EXPECT_INBOUND / REQUIRE_CLOSED) asserts evidence and
    # must FAIL, never downgrade to INCONCLUSIVE.
    if not expect_user and not expect_inbound and not require_closed:
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
    elif devices:
        ok("device observed: %s" % ", ".join(sorted(devices)))
    else:
        bad("no device observed in this window (strict gates cannot be "
            "verified without any device)")

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
    # With expect_inbound only that inbound's closures are inspected; source
    # never participates in identity, accounting or CLOSED matching.
    scoped_conns = [
        conn
        for dev in _scoped_devices(final, expect_user)
        for conn in dev.get("recent_connections") or []
        if not expect_inbound or conn.get("inbound") == expect_inbound]
    source_present = any(conn.get("source") for conn in scoped_conns) or (
        not expect_inbound and any(
            dev.get("recent_sources")
            for dev in _scoped_devices(final, expect_user)))
    info("SOURCE_PRESENT=%s (raw source is never printed)"
         % ("true" if source_present else "false"))

    # Lifecycle evidence: a new closed id or a live connection inside the
    # gate scope. Never a CLOSED verdict by itself.
    lifecycle = bool(new_closed_ids) \
        or _scope_active(final, expect_user, expect_inbound) \
        or (not expect_inbound and any(
            dev.get("status") in ("ACTIVE", "RECENT ACTIVITY")
            for dev in _scoped_devices(final, expect_user)))
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
            bad("%s (no new recent-closed ids beyond baseline)"
                % CLOSED_FAIL_REASON)
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
    closed_failed = any(
        status == "FAIL" and text.startswith(CLOSED_FAIL_REASON)
        for status, text in lines)
    # Grace eligibility: REQUIRE_CLOSED set, verdict FAIL, and the CLOSED
    # gate is the ONLY failure. Anything else (traffic / USER / INBOUND /
    # lifecycle / allowlist) goes straight to FAIL -- grace never rescues.
    eligible = bool(require_closed and failed and closed_failed
                    and len(failed) == 1 and grace_final is None)

    if grace_final is None:
        if failed:
            return _finish(lines, VERDICT_FAIL, EXIT_FAIL, failed[0],
                           grace_eligible=eligible)
        return _finish(lines, VERDICT_PASS, EXIT_PASS, "")

    # ---- CLOSE_GRACE_WINDOW evaluation ----
    if not failed:
        info("CLOSE_GRACE window not needed (primary window already PASS)")
        return _finish(lines, VERDICT_PASS, EXIT_PASS, "")
    if len(failed) > 1 or not closed_failed:
        info("CLOSE_GRACE window NOT entered: the primary window has "
             "failure(s) other than the CLOSED gate; grace never rescues "
             "traffic/USER/INBOUND/lifecycle failures")
        return _finish(lines, VERDICT_FAIL, EXIT_FAIL, failed[0])

    # The CLOSED gate is the sole primary failure. The grace snapshot must
    # itself be healthy for its whole duration: stale or identity conflicts
    # during grace are a FAIL, never a pass-through.
    if grace_final.get("stale") is not False:
        bad("grace window snapshot is stale; closure evidence is not "
            "trustworthy (CLOSE_GRACE)")
        return _finish(lines, VERDICT_FAIL, EXIT_FAIL,
                       "grace window snapshot is stale")
    if (grace_final.get("identity_conflicts") or 0) != 0:
        bad("identity gate failure during the grace window "
            "(identity_conflicts=%s)" % grace_final.get("identity_conflicts"))
        return _finish(lines, VERDICT_FAIL, EXIT_FAIL,
                       "identity gate failure during grace window")

    # Same ORIGINAL baseline, same USER/INBOUND scope: a sibling protocol's
    # closure or an active connection can never satisfy the gate here.
    grace_ids = scope_recent_ids(grace_final, expect_user, expect_inbound) \
        - baseline_ids
    for idx, (status, text) in enumerate(lines):
        if status == "FAIL" and text.startswith(CLOSED_FAIL_REASON):
            if grace_ids:
                lines[idx] = (
                    "PASS",
                    "new CLOSED/finalize observed during the CLOSE_GRACE "
                    "window (%d new id(s) beyond the ORIGINAL baseline)"
                    % len(grace_ids))
            else:
                lines[idx] = (
                    "FAIL",
                    "CLOSE_GRACE window timed out without a new "
                    "CLOSED/finalize (no new recent-closed ids beyond the "
                    "ORIGINAL baseline)")
            break
    if grace_ids:
        return _finish(lines, VERDICT_PASS, EXIT_PASS, "")
    return _finish(lines, VERDICT_FAIL, EXIT_FAIL,
                   "CLOSE_GRACE window timed out without a new "
                   "CLOSED/finalize")


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
    parser.add_argument("--grace-final", default="",
                        help="optional CLOSE_GRACE_WINDOW snapshot; judged "
                             "only when the CLOSED gate is the sole primary "
                             "failure")
    args = parser.parse_args(argv)

    try:
        require_closed = parse_require_closed(args.require_closed)
        expect_inbound = parse_expect_inbound(args.expect_inbound)
        with open(args.baseline, encoding="utf-8") as handle:
            baseline = json.load(handle)
        with open(args.final, encoding="utf-8") as handle:
            final = json.load(handle)
        grace_final = None
        if args.grace_final:
            with open(args.grace_final, encoding="utf-8") as handle:
                grace_final = json.load(handle)
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
                       require_closed=require_closed,
                       grace_final=grace_final)
    for status, text in outcome["lines"]:
        print("%s\t%s" % (status, text))
    if outcome.get("grace_eligible"):
        print("GRACE_ELIGIBLE\t1")
    print("RESULT\t%s" % outcome["verdict"])
    if outcome["reason"]:
        print("REASON\t%s" % outcome["reason"])
    return outcome["exit"]


if __name__ == "__main__":
    sys.exit(main())
