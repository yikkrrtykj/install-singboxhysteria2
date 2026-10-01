"""The dark office agent: config, cycle orchestration, run/seq lifecycle.

One cycle is bounded three ways: every slot has its own budget, the whole
cycle has an absolute deadline (<= 20 s), and cycles never overlap. Sampling
cadence is separate from delivery rate (the server owns the token buckets).

Evidence rules enforced here, not merely documented:

* a configured-but-missing node is ``invalid`` -- configuration, NEVER path
  failure;
* a node display name is never parsed to infer a protocol role;
* a cache echo of our own active test is never counted as a second source;
* the sample is spooled DURABLY before any upload is attempted, and a spool
  failure means no upload at all (no evidence is ever transmitted that is not
  first durable locally).
"""

from __future__ import annotations

import json
import os
import stat as stat_module
import threading
import time

from . import (CADENCE_DEFAULT_SECONDS, CADENCE_MIN_SECONDS,
               CYCLE_DEADLINE_SECONDS, DELAY_TIMEOUT_SECONDS,
               OUTCOME_INVALID, OUTCOME_OK, OUTCOME_TIMEOUT,
               OUTCOME_UNAVAILABLE, ROLES, ROLE_HY2, ROLE_REALITY, SEQ_MIN)
from . import direct_probe as dp
from . import mihomo_probe as mp
from .delivery import (deliver_pending, next_retry_delay)
from .evidence import active_entry, merge_evidence, passive_entry
from .payload import encode_sample, valid_probe_id
from .spool import Spool, SpoolError

BASELINE_FILE = "egress.baseline.json"
STATUS_NOT_CONFIGURED = "not_configured"
STATUS_FRESH = "fresh"
STATUS_SOURCE_UNAVAILABLE = "source_unavailable"
STATUS_DEGRADED = "degraded"


class ConfigError(Exception):
    """Fatal agent configuration problem (fail-closed, never a traceback)."""


def load_probe_secret(path):
    """Read the per-probe ingest secret: FILE ONLY.

    The probe secret is deliberately NOT resolvable from the environment or
    argv (issue #67 §5): argv is world-readable through ``ps``, and the
    environment leaks into journald/core dumps. The audited E4 permission
    discipline is reused verbatim (regular file, no-follow, fstat-same-object,
    0600/0400 on POSIX)."""
    from client import SecretFileError, _read_secret_file
    try:
        value = _read_secret_file(path)
    except SecretFileError as exc:
        raise ConfigError("probe secret unusable: %s" % exc) from None
    if not value:
        raise ConfigError("probe secret is empty")
    return value.encode("utf-8")


class AgentConfig:
    """Validated agent configuration. Nothing here is secret material; the
    secret is loaded separately by file path."""

    def __init__(self, probe_id, ingest_url, spool_dir, ingest_secret_file,
                 mihomo_url, reality_node, hy2_node, dns_host, https_host,
                 egress_host, vps_host, vps_port=443,
                 mihomo_secret_file=None, watched_group=None,
                 cadence=CADENCE_DEFAULT_SECONDS,
                 cycle_deadline=CYCLE_DEADLINE_SECONDS,
                 diagnostic_timeout=DELAY_TIMEOUT_SECONDS):
        if not valid_probe_id(probe_id):
            raise ConfigError("probe_id grammar [a-z0-9-]{1,64}")
        self.probe_id = probe_id
        self.ingest_url = ingest_url
        self.spool_dir = spool_dir
        self.ingest_secret_file = ingest_secret_file
        self.mihomo_url = mihomo_url
        self.mihomo_secret_file = mihomo_secret_file
        self.watched_group = watched_group
        for label, node in (("reality_node", reality_node),
                            ("hy2_node", hy2_node)):
            if type(node) is not str or not node.strip() or len(node) > 128:
                raise ConfigError("%s must be a bounded configured identity"
                                  % label)
        if reality_node == hy2_node:
            # One identity cannot carry two protocol roles: refusing here is
            # what stops a single path from masquerading as two.
            raise ConfigError("reality_node and hy2_node must be distinct")
        self.reality_node = reality_node
        self.hy2_node = hy2_node
        for label, host in (("dns_host", dns_host), ("https_host", https_host),
                            ("egress_host", egress_host),
                            ("vps_host", vps_host)):
            if type(host) is not str or not host.strip() or len(host) > 253:
                raise ConfigError("%s must be a bounded host name" % label)
        self.dns_host = dns_host.strip()
        self.https_host = https_host.strip()
        self.egress_host = egress_host.strip()
        self.vps_host = vps_host.strip()
        if type(vps_port) is not int or isinstance(vps_port, bool) \
                or not 0 < vps_port < 65536:
            raise ConfigError("vps_port out of range")
        self.vps_port = vps_port
        try:
            cadence = float(cadence)
        except (TypeError, ValueError):
            raise ConfigError("cadence must be numeric") from None
        if cadence < CADENCE_MIN_SECONDS:
            raise ConfigError("cadence must be >= %g s"
                              % CADENCE_MIN_SECONDS)
        self.cadence = cadence
        try:
            deadline = float(cycle_deadline)
        except (TypeError, ValueError):
            raise ConfigError("cycle deadline must be numeric") from None
        if not 0 < deadline <= CYCLE_DEADLINE_SECONDS:
            raise ConfigError("cycle deadline must be <= %g s"
                              % CYCLE_DEADLINE_SECONDS)
        self.cycle_deadline = deadline
        try:
            dtimeout = float(diagnostic_timeout)
        except (TypeError, ValueError):
            raise ConfigError("diagnostic timeout must be numeric") from None
        if not 0 < dtimeout <= DELAY_TIMEOUT_SECONDS:
            raise ConfigError("per-role delay timeout must be <= %g s"
                              % DELAY_TIMEOUT_SECONDS)
        self.diagnostic_timeout = dtimeout

    @classmethod
    def from_mapping(cls, raw):
        if not isinstance(raw, dict):
            raise ConfigError("config must be a JSON object")
        allowed = {"probe_id", "ingest_url", "spool_dir",
                   "ingest_secret_file", "mihomo_url", "mihomo_secret_file",
                   "watched_group", "reality_node", "hy2_node", "dns_host",
                   "https_host", "egress_host", "vps_host", "vps_port",
                   "cadence", "cycle_deadline", "diagnostic_timeout"}
        unknown = set(raw) - allowed
        if unknown:
            # Unknown config keys are a schema error: a typo must never be
            # silently ignored into a weaker configuration.
            raise ConfigError("unknown config keys: %s"
                              % ",".join(sorted(unknown)))
        return cls(**raw)


class RemoteProbeAgent:
    """One dark office agent instance."""

    def __init__(self, config, spool=None, mihomo=None, clock=None,
                 poster=None, jitter=None, random_bytes=None,
                 secret_loader=None):
        self.config = config
        self.clock = clock or time.time
        self.monotonic = time.monotonic
        self._random_bytes = random_bytes or os.urandom
        self._jitter = jitter
        self._poster = poster
        self._cycle_lock = threading.Lock()
        self.spool = spool or Spool(config.spool_dir, clock=self.clock)
        self.mihomo = mihomo or mp.P6Mihomo(
            config.mihomo_url, watched_group=config.watched_group,
            secret=(self._secret_from_env(config.mihomo_secret_file)),
            timeout=config.diagnostic_timeout,
            diagnostic_timeout_ms=int(config.diagnostic_timeout * 1000))
        self._secret_loader = secret_loader or load_probe_secret
        self._ingest_secret = None
        self.run = None
        self.seq = 0
        self._last_sample_epoch = None
        self.cycles = 0
        self.cycle_failures = 0
        self.clock_rollbacks = 0
        self.last_active = {}
        self.last_status = STATUS_NOT_CONFIGURED
        self.overlap_refusals = 0
        self.spool_failures = 0
        self._baseline = None

    @staticmethod
    def _secret_from_env(secret_file):
        """The MIHOMO secret keeps the existing E4 discipline (env wins, else
        the 0600 file). Only the PROBE secret is file-only."""
        from client import SecretFileError, resolve_secret
        try:
            return resolve_secret(secret_file)
        except SecretFileError:
            return ""

    # -- lifecycle ----------------------------------------------------------

    def open(self):
        self.spool.open()
        self._read_baseline()
        self._ingest_secret = self._secret_loader(
            self.config.ingest_secret_file)
        self._start_run()
        return self

    def _start_run(self):
        """One fresh random 128-bit run per process (and per rollback)."""
        self.run = self._random_bytes(16).hex()
        self.seq = 0

    def next_seq(self):
        self.seq += 1
        if self.seq < SEQ_MIN:
            raise RuntimeError("seq invariant")
        return self.seq

    # -- sample generation --------------------------------------------------

    def _sample_epoch(self, now):
        """Strictly increasing sample time. A wall clock that moved backwards
        far enough to break monotonicity starts a NEW run; an already-spooled
        timestamp is never rewritten."""
        if self._last_sample_epoch is not None \
                and now <= self._last_sample_epoch:
            self.clock_rollbacks += 1
            self._start_run()
        self._last_sample_epoch = now
        return now

    def _node_roles(self):
        return {ROLE_REALITY: self.config.reality_node,
                ROLE_HY2: self.config.hy2_node}

    def collect_sample(self, now=None):
        """Run one bounded evidence cycle and return the closed sample dict."""
        now = self.clock() if now is None else now
        deadline = self.monotonic() + self.config.cycle_deadline
        unavailable = []

        def remaining():
            return deadline - self.monotonic()

        # 1. Mihomo reachability + the audited /proxies payload. BOTH reads are
        #    bounded by the cycle deadline: an unresponsive controller must not
        #    hold the cycle open past its budget.
        def read(call):
            if remaining() <= 0:
                return OUTCOME_UNAVAILABLE, None, "deadline"
            completed, value = dp.run_bounded(call, max(remaining(), 0.1))
            if not completed:
                return OUTCOME_TIMEOUT, None, "deadline"
            return value

        version_outcome, _version_payload, _vnote = read(self.mihomo.version)
        proxies_outcome, proxies_payload, _pnote = read(self.mihomo.proxies)
        if version_outcome != OUTCOME_OK or proxies_outcome != OUTCOME_OK:
            mihomo_api = "unavailable"
            proxies_payload = None
        else:
            mihomo_api = "ok"

        # 2. Active diagnostics: exactly one bounded request per role.
        active = []
        passive = []
        roles = self._node_roles()
        for role in ROLES:
            node = roles[role]
            if mihomo_api != "ok" or proxies_payload is None:
                active.append(active_entry(role, OUTCOME_UNAVAILABLE))
                continue
            if not self.mihomo.node_present(proxies_payload, node):
                # Configured node missing: configuration, not path failure.
                active.append(active_entry(role, OUTCOME_INVALID))
                continue
            if remaining() <= 0:
                active.append(active_entry(role, OUTCOME_UNAVAILABLE))
                unavailable.append("active_delay")
                continue
            budget = min(self.config.diagnostic_timeout, max(remaining(), 0.1))
            completed, value = dp.run_bounded(
                lambda r=role, n=node: self.mihomo.delay(r, n), budget)
            if not completed:
                active.append(active_entry(role, "timeout"))
                continue
            outcome, delay_ms, _note = value
            active.append(active_entry(role, outcome, delay_ms))
        # 3. Passive correlation (display only) with the echo rule applied.
        selected, cached_delay = self.mihomo.selected_node(proxies_payload)
        if selected is None and self.config.watched_group is not None:
            unavailable.append("passive_cache")
        elif selected is not None:
            # Mihomo encodes a FAILED cached test as delay 0 and omits the
            # field when there is no history: neither is a latency.
            cached_ok = (isinstance(cached_delay, int)
                         and not isinstance(cached_delay, bool)
                         and cached_delay > 0)
            for role in ROLES:
                if selected == roles[role]:
                    if cached_ok:
                        passive.append(passive_entry(role, OUTCOME_OK,
                                                     cached_delay))
                    else:
                        passive.append(passive_entry(role,
                                                     OUTCOME_UNAVAILABLE))
        entries, _corroboration, _dropped = merge_evidence(active, passive)

        # 4. Direct slots, each bounded and skipped once the deadline is gone.
        def slot(fn):
            if remaining() <= 0:
                unavailable.append("direct")
                return dp.failed_slot(dp.ERR_TIMEOUT)
            budget = max(remaining(), 0.1)
            completed, value = dp.run_bounded(fn, budget)
            if not completed:
                return dp.failed_slot(dp.ERR_TIMEOUT)
            return value

        dns_slot = slot(lambda: dp.probe_dns(self.config.dns_host))
        https_slot = slot(lambda: dp.probe_https(self.config.https_host))
        tcp_slot = slot(lambda: dp.probe_tcp(self.config.vps_host,
                                             self.config.vps_port))
        egress_slot = slot(lambda: dp.probe_egress(
            self.config.egress_host, previous=self._baseline))
        if egress_slot["status"] == dp.STATUS_OK:
            self._baseline = egress_slot["ip"]
            self._write_baseline(egress_slot["ip"])
        elif self._baseline is None:
            unavailable.append("egress")

        sample_epoch = self._sample_epoch(now)
        sample = {
            "v": 1,
            "probe_id": self.config.probe_id,
            "run": self.run,
            "seq": self.next_seq(),
            "sample_epoch": sample_epoch,
            "dns": dns_slot,
            "https": https_slot,
            "vps_tcp": tcp_slot,
            "egress": egress_slot,
            "mihomo_api": {"status": mihomo_api},
            "active": entries,
            "flags": {"truncated": False,
                      "source_unavailable": sorted(set(unavailable))},
        }
        self.last_active = {entry["role"]: entry["outcome"]
                            for entry in entries
                            if entry["source"] == "active_delay"}
        return sample

    def run_cycle(self, now=None):
        """One cycle: collect -> encode -> SPOOL DURABLY -> then deliver.

        Cycles never overlap: a cycle that arrives while one is running is
        refused (counted), never queued into a second concurrent pass.
        """
        if not self._cycle_lock.acquire(blocking=False):
            self.overlap_refusals += 1
            return {"outcome": "overlap_refused"}
        try:
            self.cycles += 1
            try:
                sample = self.collect_sample(now=now)
                body = encode_sample(sample)
            except (ValueError, RuntimeError):
                self.cycle_failures += 1
                self.last_status = STATUS_DEGRADED
                return {"outcome": "sample_invalid"}
            try:
                record_id = self.spool.append(
                    sample["probe_id"], sample["run"], sample["seq"], body,
                    queued_epoch=sample["sample_epoch"])
            except (SpoolError, OSError):
                # No durable local copy means NO upload: evidence is never
                # transmitted that could not survive a crash first.
                self.spool_failures += 1
                self.cycle_failures += 1
                self.last_status = STATUS_DEGRADED
                return {"outcome": "spool_unavailable"}
            summary = {"outcome": "spooled", "record_id": record_id}
            self.last_status = STATUS_FRESH
            if self._poster is not None:
                summary["delivery"] = self.deliver()
            return summary
        finally:
            self._cycle_lock.release()

    def deliver(self):
        """Drain the spool against the injected poster (fixtures in PR-6A)."""
        if self._ingest_secret is None or self._poster is None:
            return {"acked": 0, "quarantined": 0, "retries": 0,
                    "attempts": 0, "stopped": "no_transport"}
        sent_epoch = int(self.clock())
        return deliver_pending(self.spool, self._ingest_secret,
                               self.config.probe_id, self._poster,
                               sent_epoch, jitter=self._jitter)

    def run_forever(self, cycles=None, sleep=None):
        """Cadence loop with no overlap by construction."""
        sleeper = sleep or time.sleep
        done = 0
        next_due = self.monotonic()
        while cycles is None or done < cycles:
            self.run_cycle()
            done += 1
            next_due += self.config.cadence
            pause = next_due - self.monotonic()
            if pause > 0:
                sleeper(pause)
        return done

    # -- egress baseline ----------------------------------------------------

    def _baseline_path(self):
        return os.path.join(self.config.spool_dir, BASELINE_FILE)

    def _read_baseline(self):
        path = self._baseline_path()
        if not os.path.exists(path) or os.path.islink(path):
            return
        try:
            with open(path, "rb") as handle:
                payload = json.loads(handle.read(4096).decode("utf-8"))
        except (OSError, ValueError, UnicodeDecodeError):
            return
        if isinstance(payload, dict):
            self._baseline = dp.canonical_global_ip(payload.get("ip"))

    def _write_baseline(self, ip):
        path = self._baseline_path()
        tmp = path + ".tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC \
            | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(tmp, flags, 0o600)
        try:
            os.write(fd, json.dumps({"v": 1, "ip": ip},
                                    sort_keys=True).encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)

    # -- status -------------------------------------------------------------

    def status(self):
        """Closed, sanitized agent status: no secrets, no bodies, no labels."""
        try:
            spool_status = self.spool.status()
        except (SpoolError, OSError):
            spool_status = None
        return {
            "probe_id": self.config.probe_id,
            "run": self.run,
            "seq": self.seq,
            "cycles": self.cycles,
            "cycle_failures": self.cycle_failures,
            "clock_rollbacks": self.clock_rollbacks,
            "overlap_refusals": self.overlap_refusals,
            "spool_failures": self.spool_failures,
            "state": self.last_status,
            "active": dict(self.last_active),
            "spool": spool_status,
        }


class SpoolSlotError(Exception):
    """Reserved for slot-level storage faults (kept closed and sanitized)."""


def read_config_file(path):
    """Load a JSON config file (mode-checked like every other agent input)."""
    if os.path.islink(path):
        raise ConfigError("config must not be a symlink")
    try:
        st = os.lstat(path)
    except OSError:
        raise ConfigError("config not readable") from None
    if not stat_module.S_ISREG(st.st_mode):
        raise ConfigError("config must be a regular file")
    try:
        with open(path, "rb") as handle:
            raw = json.loads(handle.read(64 * 1024).decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        raise ConfigError("config is not valid JSON") from None
    return AgentConfig.from_mapping(raw)
