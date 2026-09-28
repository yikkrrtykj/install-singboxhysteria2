"""Probe scheduler -- activation of the PR-3A engine (issue #33 PR-3B).

A DEDICATED daemon thread, deliberately NOT the publisher loop: probe
cadence, a hung worker or a broken persistence boundary can never delay,
starve or kill a snapshot publication. The scheduler owns exactly one
thread and calls the PR-3A engine's ``run_probe_cycle`` (which already
never raises, bounds every worker by an absolute deadline and holds at
most one outstanding worker per slot) once per cadence window, then
hands the CLOSED result to the history store.

Activation contract (all enforced, all tested):

* The reviewed production target set and cadence are frozen compiled
  constants here -- the engine ships no default endpoint at all; this
  module is the reviewed place that does. Cadence and the production
  endpoint grammar are NOT expressible through ``monitor.conf`` (the
  conf loader only maps ``SBMON_*`` keys into ``SBMON_ENV_*``, so no
  conf line can name this surface): changing them is a code review.
* Probing is EXPLICITLY OPT-IN, and the opt-in is one thing: a valid
  JSON target document at the frozen path the packaged systemd unit
  always names through ``SINGBOX_MONITOR_PROBE_TARGETS_FILE``
  (``$SBMON_CONF_DIR/probe-targets.json``). The UNIT supplies the path,
  the OPERATOR supplies the file: while the file does not exist the
  scheduler is DARK -- zero cycles, zero outbound traffic -- even though
  the
  production endpoint set is compiled in, and no release tree, unit,
  drop-in or installer ever creates that file. Reason: the same process
  image must be provably silent in CI and on every default host (the
  PR-3A §12 reservation) while a reviewer-approved host can turn real
  probing on persistently, across restarts and redeploys, with one
  auditable file and no code change and no new knob. A CI lane
  therefore cannot leak into public traffic by forgetting a flag.
* The file names the target set in exactly one of two closed shapes:
  per-slot endpoint objects (CI/loopback injection, ``target_source``
  ``injected``), or the single token ``{"v": 1, "source": "production"}``
  (a deliberate, auditable act that selects the frozen compiled set,
  ``target_source`` ``production``). Naming the production set is thus
  something a file must SAY -- nothing selects it by omission.
* A variable that names a missing file is the documented DARK state of a
  non-opted-in host (``target_file_absent``); a variable that names a
  malformed or non-exact document, or a path that is not a regular file,
  fails closed into the same DARK scheduler with its own sanitized
  startup code (``target_injection_invalid``). Neither ever yields a
  partial target set and NEVER a silent fallback to the production
  endpoints, because that would turn a test misconfiguration into real
  public traffic.
* egress-change semantics are DERIVED DURABLY from the last SUCCESSFUL
  PERSISTED public egress IP (via the history store's own read of its
  v3 table) through the engine's pure ``classify_egress_change``: a
  Monitor restart never fakes a ``changed`` event, and a cycle whose
  egress probe failed never produces one.
* Probe-RUNTIME failures (scheduler defects, persistence refusals)
  are counted here as closed integers only; probe OUTCOMES (network
  failures) are data, never runtime degradation. The two evidence
  planes never merge.
* stdlib only, no listeners, no filesystem writes, results are passed
  to the persistence boundary unmodified (the DB-side revalidation
  lives in ``web/incident_history.py``).
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass

from diagnostics import network_probes as engine

# Frozen cadence (docs/monitor-v2-network-probes-p3a.md §9 review track:
# the 60 s medium lane -- 4 requests per minute at most, invisible on
# VPS bandwidth, low-frequency anonymous traffic for the endpoints).
CADENCE_SECONDS = 60.0
# First cycle runs this long after start(), so a Monitor restart does not
# race its own startup path with an immediate outbound burst.
STARTUP_DELAY_SECONDS = 5.0
# Passed to the engine as the cycle-wide absolute deadline.
TOTAL_DEADLINE_SECONDS = engine.CYCLE_DEADLINE_SECONDS  # 12.0

TARGET_SET_CADENCE = "FROZEN-PR3B"

# The single opt-in switch for probing: a valid target document at the
# frozen path the PACKAGED UNIT always names. The unit supplies the path,
# the operator supplies the file -- while the file is absent the scheduler
# is DARK (zero cycles, zero outbound traffic) even though the production
# endpoint set is compiled in. This is NOT an SBMON_* key, so
# monitor.conf can never
# express it, and nothing in the release tree ships a document at the path:
# a CI lane cannot leak into public traffic by forgetting a flag, and an
# operator turns real probing on by placing one reviewed, auditable file.
TARGETS_ENV_VAR = "SINGBOX_MONITOR_PROBE_TARGETS_FILE"

SOURCE_PRODUCTION = "production"
SOURCE_INJECTED = "injected"
SOURCE_DARK = "dark"

STARTUP_NONE = None
# The variable is unset: a scheduler started outside the packaged
# deployment (a harness, a hand-run process). The documented dark state.
STARTUP_NOT_CONFIGURED = "target_file_not_configured"
# The packaged unit named its frozen path and no file sits there yet: the
# ORDINARY dark state of a host that has not opted in. Absence is a fact,
# not a defect, and it must stay distinguishable from one.
STARTUP_FILE_ABSENT = "target_file_absent"
# The path holds something that cannot be resolved into a complete,
# exact-shape target set.
STARTUP_INJECTION_INVALID = "target_injection_invalid"

# The reviewed production endpoint set (PR-3B functional R1 B1 re-review).
# Every slot is a TARGET/STATUS PAIR that can actually produce positive
# evidence, measured 2026-09-29 against the live endpoints:
#
#   * DNS   -- ``one.one.one.one`` through the system resolver.
#   * HTTPS -- ``https://1.1.1.1/cdn-cgi/trace``, which answers 200. The
#     bare root (``https://1.1.1.1/``) answers 301, and the engine's
#     reviewed contract is 200-only, so the ROOT PATH COULD NEVER PRODUCE
#     EVIDENCE: it failed every cycle with ``bad_response`` no matter how
#     healthy the network was. The host stays a numeric literal so this
#     slot never re-tests the resolver (the DNS slot owns that), and the
#     Cloudflare leaf carries ``IP Address:1.1.1.1`` in its SAN list, so
#     TLS verification -- structurally on, no bypass knob -- passes
#     against the literal.
#   * UDP   -- one A/IN query for ``example.com`` to 1.1.1.1:53. The
#     engine evidences the round trip ONLY on NOERROR, and RFC 6761
#     requires ``.invalid`` to be NXDOMAIN, so the previous query name was
#     deterministically WRONG: a correct resolver could only ever fail the
#     slot, and a resolver that answered it was lying (an NXDOMAIN-shim
#     was measured on the review host, turning the defect into a false
#     positive). ``example.com`` is the RFC 819 documentation name and
#     DOES resolve; the answer bytes are still discarded by the engine.
#   * Egress-- ``https://api.ipify.org/`` -- 200, one plain-text global
#     unicast address, 64-byte body cap.
#
# The DNS probe only ever proves resolution, and the UDP slot sends one
# public documentation query name; both discard every answer byte.


@dataclass(frozen=True)
class ProductionEndpointSet:
    dns_hostname: str = "one.one.one.one"
    https_host: str = "1.1.1.1"
    https_port: int = 443
    https_path: str = "/cdn-cgi/trace"
    udp_resolver_ip: str = "1.1.1.1"
    udp_resolver_port: int = 53
    udp_query_hostname: str = "example.com"
    egress_host: str = "api.ipify.org"
    egress_port: int = 443
    egress_path: str = "/"


def production_targets(endpoints=None):
    """Build the frozen ``ProbeTargets`` from the reviewed endpoint set.

    Every spec keeps the engine's own per-slot budget constants; this
    function adds NO timeout policy of its own.
    """
    ep = endpoints or ProductionEndpointSet()
    return engine.ProbeTargets(
        dns=engine.DnsProbeSpec(hostname=ep.dns_hostname),
        https=engine.HttpsProbeSpec(host=ep.https_host, port=ep.https_port,
                                    path=ep.https_path),
        udp=engine.UdpProbeSpec(resolver_host=ep.udp_resolver_ip,
                                query_hostname=ep.udp_query_hostname,
                                resolver_port=ep.udp_resolver_port),
        egress=engine.EgressProbeSpec(host=ep.egress_host,
                                      port=ep.egress_port,
                                      path=ep.egress_path),
    )


# Module-level alias used by the static gates: the one reviewed instance.
PRODUCTION_ENDPOINTS = ProductionEndpointSet()


def _startup_targets():
    """Resolve the opt-in target file into a target set, or fail closed.

    Probing exists ONLY through this file; it NEVER falls back to the
    compiled production endpoints, because a silent fallback would turn
    a test misconfiguration (or an unreviewed host) into real public
    traffic. Valid documents are built through the engine's own spec
    constructors, so endpoint validation lives in exactly one place.
    """
    path = os.environ.get(TARGETS_ENV_VAR)
    if not path:
        return None, SOURCE_DARK, STARTUP_NOT_CONFIGURED
    try:
        if not os.path.exists(path):
            # The packaged unit always names its frozen path, so a host
            # that has not opted in lands HERE -- dark by absence, which
            # is the ordinary state, not a defect and not an error.
            return None, SOURCE_DARK, STARTUP_FILE_ABSENT
        if not os.path.isfile(path):
            raise ValueError("not a regular file")
        with open(path, "r", encoding="utf-8") as handle:
            doc = json.load(handle)
    except Exception:  # noqa: BLE001 -- closed: no text ever escapes
        return None, SOURCE_DARK, STARTUP_INJECTION_INVALID
    if not isinstance(doc, dict) or doc.get("v") != 1:
        return None, SOURCE_DARK, STARTUP_INJECTION_INVALID
    if "source" in doc:
        # The only shape that may name the frozen production set, and it
        # must be EXACTLY that: an extra or missing key is a defect, not
        # a hint to guess.
        if (doc.get("source") != "production"
                or set(doc) != {"v", "source"}):
            return None, SOURCE_DARK, STARTUP_INJECTION_INVALID
        return production_targets(), SOURCE_PRODUCTION, STARTUP_NONE
    try:
        if not set(doc) <= {"v", "dns", "https", "udp", "egress"}:
            raise ValueError("non-exact injection shape")
        dns_doc = doc.get("dns")
        https_doc = doc.get("https")
        udp_doc = doc.get("udp")
        egress_doc = doc.get("egress")
        dns = engine.DnsProbeSpec(**dns_doc) if dns_doc else None
        https = engine.HttpsProbeSpec(**https_doc) if https_doc else None
        udp = engine.UdpProbeSpec(**udp_doc) if udp_doc else None
        egress = engine.EgressProbeSpec(**egress_doc) if egress_doc else None
        if dns is None and https is None and udp is None and egress is None:
            raise ValueError("empty injection")
        targets = engine.ProbeTargets(dns=dns, https=https, udp=udp,
                                      egress=egress)
    except Exception:  # noqa: BLE001 -- SpecError/TypeError both closed
        return None, SOURCE_DARK, STARTUP_INJECTION_INVALID
    return targets, SOURCE_INJECTED, STARTUP_NONE


class ProbeScheduler:
    """One dedicated daemon thread driving bounded probe cycles.

    Every public method never raises. The scheduler holds no network
    state itself (the engine is stateless) and persists nothing directly
    -- ``history`` is the single sink, and the scheduler thread is the
    ONLY writer of probe rows, so no cross-thread write ordering exists
    to defend against.
    """

    def __init__(self, history, targets=None, cadence_seconds=CADENCE_SECONDS,
                 startup_delay_seconds=STARTUP_DELAY_SECONDS,
                 clock=time.time):
        self._history = history
        self._clock = clock
        self._cadence = (float(cadence_seconds)
                         if isinstance(cadence_seconds, (int, float))
                         and not isinstance(cadence_seconds, bool)
                         and float(cadence_seconds) > 0
                         else CADENCE_SECONDS)
        self._startup_delay = (float(startup_delay_seconds)
                               if isinstance(startup_delay_seconds,
                                             (int, float))
                               and not isinstance(startup_delay_seconds, bool)
                               and float(startup_delay_seconds) >= 0
                               else STARTUP_DELAY_SECONDS)
        if targets is not None and type(targets) is engine.ProbeTargets:
            self._targets = targets
            # equality is structural (frozen dataclass), so an explicitly
            # passed PRODUCTION-shaped set is labelled honestly instead of
            # as an injection; the file opt-in can never reach this branch
            # with the production endpoints unless a reviewer passes them.
            self._source = (SOURCE_PRODUCTION
                            if targets == production_targets()
                            else SOURCE_INJECTED)
            self._startup_error = STARTUP_NONE
        else:
            self._targets, self._source, self._startup_error = \
                _startup_targets()
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._thread = None
        self._cycles_completed = 0
        self._cycles_rejected = 0
        self._runtime_failures = 0
        self._last_cycle_epoch = None
        self._last_store_epoch = None

    # -- lifecycle -----------------------------------------------------------

    def start(self):
        """Spawn the scheduler thread; idempotent. Never raises.

        A dark scheduler (failed injection) starts NO thread at all:
        zero cycles, zero I/O, with the closed startup code visible in
        ``status()``.
        """
        with self._lock:
            if self._thread is not None or self._stop.is_set():
                return
            if self._targets is None:
                return
            self._thread = threading.Thread(target=self._guarded_loop,
                                            name="monitor-probes",
                                            daemon=True)
            self._thread.start()

    def stop(self, join_timeout=TOTAL_DEADLINE_SECONDS + 3.0):
        self._stop.set()
        with self._lock:
            thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=max(0.5, float(join_timeout)))

    # -- cycle loop ----------------------------------------------------------

    def _guarded_loop(self):
        # Absolute containment line, mirroring the broker's
        # write-alongside discipline: nothing from a probe cycle may
        # travel outward on the thread's stack toward anything else in
        # the process. Runtime defects become closed counters only.
        delay = self._startup_delay
        while not self._stop.is_set():
            if self._stop.wait(delay):
                return
            delay = self._cadence
            try:
                self._run_one_cycle()
            except Exception:  # noqa: BLE001 -- runtime plane, counter only
                with self._lock:
                    self._runtime_failures += 1

    def _run_one_cycle(self):
        result = engine.run_probe_cycle(
            self._targets,
            total_deadline_seconds=TOTAL_DEADLINE_SECONDS)
        current_ip = None
        egress = result.get("egress")
        if isinstance(egress, dict) and egress.get("status") == engine.STATUS_OK:
            current_ip = egress.get("ip")
        previous_ip = None
        getter = getattr(self._history, "last_persisted_egress_ip", None)
        if callable(getter):
            previous_ip = getter()
        change = engine.classify_egress_change(previous_ip, current_ip)
        store = getattr(self._history, "record_probe_result", None)
        accepted = False
        if callable(store):
            accepted = bool(store(result, egress_change=change))
        with self._lock:
            self._last_cycle_epoch = self._clock()
            if accepted:
                self._cycles_completed += 1
                self._last_store_epoch = self._clock()
            else:
                self._cycles_rejected += 1

    # -- read surface --------------------------------------------------------

    def status(self):
        """Closed, sanitized status object (never raises, never free
        text, no paths, no endpoints, no probe results)."""
        with self._lock:
            running = (self._thread is not None
                       and self._thread.is_alive()
                       and not self._stop.is_set())
            return {
                "enabled": self._targets is not None,
                "running": running,
                "target_source": self._source if self._targets is not None
                else SOURCE_DARK,
                "startup_error": self._startup_error,
                "cadence_seconds": self._cadence,
                "cycles_completed": int(self._cycles_completed),
                "cycles_rejected": int(self._cycles_rejected),
                "runtime_failures": int(self._runtime_failures),
                "last_cycle_epoch": self._last_cycle_epoch,
                "last_store_epoch": self._last_store_epoch,
            }
