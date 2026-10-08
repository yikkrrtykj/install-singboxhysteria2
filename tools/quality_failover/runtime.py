"""Opt-in runner. No service installation, config reload, autostart or TUN writes."""
from collections import deque
import http.client
import json
import time
from .controller import Passive, alive
from .policy import AUTO, GROUP, Ownership
from .config import client


class Budget:
    def __init__(self, byte_limit, interval):
        self.limit, self.interval, self.records, self.last = byte_limit, interval, deque(), {}

    def reserve(self, node, size, now):
        while self.records and now - self.records[0][0] >= 60:
            self.records.popleft()
        if (now - self.last.get(node, -1e15) < self.interval
                or sum(item[1] for item in self.records) + size > self.limit):
            return False
        self.records.append((now, size))
        self.last[node] = now
        return True


class Runner:
    def __init__(self, config):
        self.engine, self.probes, self.ports, self.controller = client(config)
        self.config = config
        self.owner = Ownership(self.engine.paths)
        self.passive = Passive(self.engine.paths, config["churn_connections"],
                               {name: policy.fail_mbps for name, policy in self.engine.policies.items()})
        self.budget = Budget(config["probe_bytes_per_minute"], config["probe_interval_seconds"])
        self.offset = 0

    def cycle(self, confirm=False):
        proxies = self.controller.proxies()
        suspect = self.passive.suspicion(self.controller.request("GET", "/connections"), time.monotonic())
        observed = {}
        effective = self.owner.effective(proxies)
        current_bad = (effective in self.engine.paths
                       and self.engine.paths[effective].state in ("DEGRADED", "DOWN"))
        names = list(self.engine.paths)
        # Rotate bounded active probes so a constantly bad first path cannot
        # starve confirmation of the alternative under a fleet traffic budget.
        ordered = names[self.offset:] + names[:self.offset]
        self.offset = (self.offset + 1) % len(names)
        for name in ordered:
            path, policy = self.engine.paths[name], self.engine.policies[name]
            reachability = alive(proxies.get(name), time.time(), policy.freshness_seconds)
            confirmation = None
            testing = (confirm or name in suspect or path.bad > 0 or path.needs_recovery
                       or current_bad)
            probe = self.probes[name]
            if reachability is True and testing and self.budget.reserve(name, probe.size, time.monotonic()):
                def verify(source_port, path_name=name, index=names.index(name), target=probe):
                    return self.controller.confirm_route(path_name, "quality-probe-%d" % index,
                                                         source_port, target.host, target.port)
                confirmation = probe.measure(self.ports[name], verifier=verify)
            observed[name] = (reachability, confirmation)
        # Liveness may have expired during a serial probe batch. Re-check the
        # controller history against the ending clock, never extend its lifetime.
        for name, (reachable, confirmation) in observed.items():
            if alive(proxies.get(name), time.time(), self.engine.policies[name].freshness_seconds) is None:
                observed[name] = (None, None)
        self.engine.update(time.monotonic(), observed)
        current = self.owner.effective(proxies)
        desired = self.engine.target(time.monotonic(), current)
        action = "observe"
        if self.config["control_enabled"]:
            if not self.owner.permitted(proxies):
                action = "control_suspended" if self.owner.suspended else "manual_override"
            elif desired is not None:
                # select() does a fresh ownership/manual-override check.
                selected = AUTO if desired == next(iter(self.engine.paths)) else desired
                action = "selected" if self.controller.select(selected, self.owner) else "control_suspended"
        return {"v": 1, "observed_epoch": round(time.time(), 3), "mode": "control" if self.config["control_enabled"] else "observe",
                "paths": self.engine.summary(), "action": action,
                "suggested": desired, "owned_selection": self.owner.expected}

    def close(self):
        if self.config["control_enabled"] and self.owner.expected != AUTO and not self.owner.suspended:
            self.controller.restore(self.owner)


def run(config, once=False, confirm=False):
    runner = Runner(config)
    try:
        while True:
            started = time.monotonic()
            try:
                print(json.dumps(runner.cycle(confirm), ensure_ascii=False), flush=True)
            except (OSError, ValueError, http.client.HTTPException):
                # A control/telemetry failure is not invented as a bad path.
                runner.engine.update(time.monotonic(), {})
                print('{"v":1,"action":"telemetry_or_control_unavailable"}', flush=True)
            if once:
                break
            time.sleep(max(.01, config["cycle_seconds"] - (time.monotonic() - started)))
    finally:
        try:
            runner.close()
        except (OSError, ValueError, http.client.HTTPException):
            print('{"v":1,"action":"owned_group_restore_unconfirmed"}', flush=True)
