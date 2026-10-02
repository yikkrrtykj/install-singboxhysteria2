"""Production wiring over the existing P6A collector/spool/disposition.

Two bounded workers, max eight immutable profiles, no overlapping profile
cycles or catch-up storms. Controller credentials are read from a local
protected file; never imported from the VPS or inherited from an environment.
No server/UI/installer activation is performed by this module.
"""
from __future__ import annotations

import concurrent.futures
import os
import threading
import time

from . import delivery as dl
from .agent import ConfigError, RemoteProbeAgent
from .mihomo_probe import P6Mihomo
from .pinned_transport import PinnedHttpsIngest
from .spool import SpoolError, _InstanceLock
from .windows_security import StorageSecurityError

DELIVERY_RECORD_LIMIT = 8
DELIVERY_SECONDS = 10.0


class ProductionAgent(RemoteProbeAgent):
    """Only delivery scheduling changes; payload and evidence rules are reused."""
    def deliver(self):
        now = self.monotonic()
        if now < self._delivery_resume_at:
            self.delivery_deferrals += 1
            return {"stopped": "backoff", "attempts": 0}
        deadline = now + DELIVERY_SECONDS
        transport = self._poster

        def bounded_post(body, headers):
            remaining = deadline - self.monotonic()
            if remaining <= 0:
                raise TimeoutError("delivery deadline")
            transport.timeout = min(2.0, remaining)
            return transport.post(body, headers)

        summary = dl.deliver_pending(self.spool, self._ingest_secret,
                                     self.config.probe_id, bounded_post,
                                     limit=DELIVERY_RECORD_LIMIT, clock=self.clock,
                                     jitter=self._jitter)
        if summary.get("stopped") in (dl.RETRY_STATE_NOT_DURABLE, dl.QUEUE_BLOCKED):
            self.cycle_failures += 1
            self.last_status = "degraded"
        retry = float(summary.get("retry_after") or 0)
        self.last_backoff_seconds = retry
        self._delivery_resume_at = self.monotonic() + retry if retry > 0 else 0
        return summary


def make_agent(vault, key, manifest):
    config = vault.agent_config(key, manifest)
    # P6A writers inherit this protected vault's ACL. Refuse pre-existing
    # reparse/special/unsafe-ACL objects before the reusable writers open them.
    objects = 0
    for current, directories, files in os.walk(vault._path(key), followlinks=False):
        vault.security.validate(current, True)
        objects += len(directories) + len(files)
        if objects > 1024:
            raise ConfigError("profile working directory oversized")
        for name in directories:
            vault.security.validate(os.path.join(current, name), True)
        for name in files:
            vault.security.validate(os.path.join(current, name))
    # The controller secret belongs to this Windows installation, not the VPS.
    controller_path = os.path.join(vault._path(key), "mihomo.key")
    if os.path.lexists(controller_path):
        secret = vault.security.read(controller_path, 4096).decode("utf-8").strip()
        if not secret or "\n" in secret or "\r" in secret:
            raise ConfigError("invalid local controller credential")
    else:
        secret = ""  # controller without auth can still be observed
    mihomo = P6Mihomo(config.mihomo_url, watched_group=config.watched_group,
                      secret=secret, timeout=config.diagnostic_timeout,
                      diagnostic_timeout_ms=int(config.diagnostic_timeout * 1000))
    poster = PinnedHttpsIngest(config.ingest_url, vault.read_certificate(key),
                               manifest["certificate_sha256"])
    agent = ProductionAgent(config, mihomo=mihomo, poster=poster,
                             secret_loader=lambda _path: vault.read_secret(key))
    return agent.open()


class ProductionRuntime:
    def __init__(self, vault, agent_factory=make_agent, monotonic=time.monotonic):
        self.vault = vault
        self.factory = agent_factory
        self.monotonic = monotonic
        self.stop = threading.Event()
        self.pause = threading.Event()
        self._agents = {}
        self._futures = {}
        self._due = {}
        self._states = {}
        self._pool = concurrent.futures.ThreadPoolExecutor(max_workers=2)
        self._lease = None

    def open(self):
        self.vault.open()
        self._lease = _InstanceLock(os.path.join(self.vault.root, "service.lock"))
        try:
            self.vault.security.check_components(self._lease.path)
            self._lease.acquire()
            self.vault.security.validate_fd(self._lease.fd)
        except BaseException:
            self._lease.release()
            self._lease = None
            raise
        return self

    def tick(self):
        if self._lease is None:
            raise ConfigError("runtime is not open")
        now = self.monotonic()
        for key, future in list(self._futures.items()):
            if future.done():
                try:
                    future.result()
                    self._states[key] = "running"
                except Exception:
                    # No raw controller/network/config exception in status/logs.
                    self._states[key] = "cycle_unavailable"
                del self._futures[key]
        keys = self.vault.keys()
        keep = set(keys) | set(self._agents) | set(self._futures)
        self._states = {key: value for key, value in self._states.items() if key in keep}
        self._due = {key: value for key, value in self._due.items() if key in keep}
        # Admin-controlled enrollment/control/purge uses the same vault lock.
        lock = self.vault._lock()
        try:
            enabled = set()
            for key in keys:
                try:
                    if self.vault.enabled(key):
                        enabled.add(key)
                except (ConfigError, StorageSecurityError, OSError):
                    self._states[key] = "profile_unavailable"
            for key in list(self._agents):
                if (key not in enabled or self.pause.is_set() or self.stop.is_set()) and key not in self._futures:
                    self._agents.pop(key).close()
                    self._states[key] = "paused"
            if self.pause.is_set() or self.stop.is_set():
                return
            # No queued jobs: at most two running cycles globally. Rotate by
            # due time so a third profile cannot starve behind the first two.
            available = 2 - len(self._futures)
            for key in sorted(enabled, key=lambda k: (self._due.get(k, 0), k)):
                if available <= 0:
                    break
                if key in self._futures or now < self._due.get(key, 0):
                    continue
                try:
                    if key not in self._agents:
                        manifest = self.vault.load(key)
                        self.vault.security.validate(os.path.join(self.vault._path(key), "spool"), True)
                        self._agents[key] = self.factory(self.vault, key, manifest)
                    agent = self._agents[key]
                    self._due[key] = now + agent.config.cadence
                    self._futures[key] = self._pool.submit(agent.run_cycle)
                    available -= 1
                except Exception:
                    self._states[key] = "profile_unavailable"
                    self._due[key] = now + 60
        finally:
            lock.release()

    def status(self):
        return {"v": 1, "paused": self.pause.is_set(),
                "active_cycles": len(self._futures),
                "profiles": dict(self._states)}

    def run(self):
        try:
            while not self.stop.is_set():
                self.tick()
                self.stop.wait(0.5)
        finally:
            self.close()

    def close(self):
        self.stop.set()
        self._pool.shutdown(wait=True, cancel_futures=True)
        for agent in self._agents.values():
            agent.close()
        self._agents.clear()
        if self._lease is not None:
            self._lease.release()
            self._lease = None
