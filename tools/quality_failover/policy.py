"""Pure, bounded protocol state machine. Missing evidence is UNKNOWN, never DOWN."""
from dataclasses import dataclass
import math

NODES = ("Reality", "Hysteria2", "Backup-Reality", "Backup-Hysteria2")
AUTO = "自动选择"
GROUP = "质量自动选择"
OUTER = "节点选择"


def number(value, low, high):
    return type(value) in (int, float) and math.isfinite(value) and low <= value <= high


@dataclass(frozen=True)
class Policy:
    fail_mbps: float
    recover_mbps: float
    fail_samples: int = 2
    recover_samples: int = 3
    hold_seconds: float = 120
    freshness_seconds: float = 90

    def __post_init__(self):
        if not (number(self.fail_mbps, .01, 1000)
                and number(self.recover_mbps, .01, 1000)
                and self.fail_mbps < self.recover_mbps
                and type(self.fail_samples) is int and 2 <= self.fail_samples <= 10
                and type(self.recover_samples) is int and 2 <= self.recover_samples <= 10
                and number(self.hold_seconds, 30, 3600)
                and number(self.freshness_seconds, 15, 300)):
            raise ValueError("policy")


@dataclass(frozen=True)
class Confirmation:
    # Only a completed, authenticated upload is a throughput observation.
    mbps: float | None = None
    timed_out: bool = False
    endpoint_ready: bool = False

    def valid(self):
        return (type(self.timed_out) is bool and type(self.endpoint_ready) is bool
                and (self.mbps is None or number(self.mbps, 0, 10000))
                and not (self.timed_out and self.mbps is not None))

    def verdict(self, policy):
        if not self.valid() or not self.endpoint_ready:
            return "unknown"
        if self.timed_out:
            return "bad"
        if self.mbps is None:
            return "unknown"
        if self.mbps < policy.fail_mbps:
            return "bad"
        if self.mbps >= policy.recover_mbps:
            return "good"
        return "middle"


@dataclass
class Path:
    state: str = "UNKNOWN"
    reason: str = "no_evidence"
    bad: int = 0
    good: int = 0
    hold_until: float = 0
    quality_verified_at: float | None = None
    observed_at: float | None = None
    needs_recovery: bool = False

    def observe(self, now, reachable, confirmation, policy):
        self.observed_at = now
        if reachable is False:
            self.needs_recovery = True
            self.state, self.reason = "DOWN", "hard_probe_failed"
            self.bad = self.good = 0
            self.quality_verified_at = None
            self.hold_until = max(self.hold_until, now + policy.hold_seconds)
            return
        if reachable is not True:
            self.state, self.reason = "UNKNOWN", "missing_reachability"
            self.bad = self.good = 0
            self.quality_verified_at = None
            return
        if self.state == "UNKNOWN":
            self.state, self.reason = (("DEGRADED", "recovery_pending")
                                       if self.needs_recovery else ("UP", "reachable_only"))
        if confirmation is None:
            # A cadence tick without a scheduled probe is not a failed or
            # inconclusive probe; don't reset consecutive confirmation counts.
            if self.quality_verified_at is not None and now - self.quality_verified_at > policy.freshness_seconds:
                self.quality_verified_at = None
                if self.state == "UP":
                    self.reason = "reachable_only"
            return
        result = confirmation.verdict(policy)
        if result == "bad":
            self.good = 0
            self.bad = min(policy.fail_samples, self.bad + 1)
            self.quality_verified_at = None
            if self.bad >= policy.fail_samples:
                self.needs_recovery = True
                self.state, self.reason = "DEGRADED", "upload_confirmed_bad"
                self.hold_until = max(self.hold_until, now + policy.hold_seconds)
        elif result == "good":
            self.bad = 0
            self.good = min(policy.recover_samples, self.good + 1)
            if self.needs_recovery:
                if now >= self.hold_until and self.good >= policy.recover_samples:
                    self.needs_recovery = False
                    self.state, self.reason = "UP", "quality_recovered"
                    self.quality_verified_at = now
            else:
                self.state, self.reason = "UP", "upload_confirmed_good"
                self.quality_verified_at = now
        else:
            # Missing or middle-band samples break "consecutive" evidence.
            self.bad = self.good = 0
            if self.state == "UP" and (self.quality_verified_at is None
                    or now - self.quality_verified_at > policy.freshness_seconds):
                self.quality_verified_at = None
                self.reason = "reachable_only"
            if self.state == "UP" and result == "unknown":
                self.reason = "upload_unconfirmed"

    def usable(self, now, policy):
        return (self.state == "UP" and not self.needs_recovery
                and self.quality_verified_at is not None
                and 0 <= now - self.quality_verified_at <= policy.freshness_seconds)


class Engine:
    def __init__(self, policies):
        if tuple(policies) not in (NODES[:2], NODES):
            raise ValueError("nodes")
        self.policies = policies
        self.paths = {name: Path() for name in policies}
        self.last_time = None

    def update(self, now, observations):
        if not number(now, 0, 1e15) or (self.last_time is not None and now < self.last_time):
            raise ValueError("clock")
        self.last_time = now
        for name, path in self.paths.items():
            alive, confirmation = observations.get(name, (None, None))
            if alive is not None and type(alive) is not bool:
                alive = None
            if confirmation is not None and not isinstance(confirmation, Confirmation):
                confirmation = None
            path.observe(now, alive, confirmation, self.policies[name])
        return self.summary()

    def target(self, now, current):
        if current not in self.paths:
            return None
        path = self.paths[current]
        # Retain a healthy current path at every priority. Recovery of another
        # path only makes it eligible for a future failure, never a failback.
        # UNKNOWN is not a failure and cannot authorize a preference switch.
        if path.state not in ("DEGRADED", "DOWN"):
            return None
        candidates = [name for name, item in self.paths.items()
                      if item.usable(now, self.policies[name])]
        if not candidates:
            return None
        best = candidates[0]
        if best == current:
            return None
        return best

    def summary(self):
        return {name: {"state": path.state, "reason": path.reason}
                for name, path in self.paths.items()}


class Ownership:
    """Own only the dedicated hidden group, never either original group.

    A changed selection or group shape suspends control for this process.
    Controller APIs have no compare-and-swap; this is NOT ownership of a
    user's original fallback. The dedicated group must not have another writer.
    """
    def __init__(self, nodes):
        self.members = [AUTO, *nodes]
        self.expected = AUTO
        self.suspended = False

    def permitted(self, proxies, require_outer=True):
        outer = proxies.get(OUTER, {})
        group = proxies.get(GROUP, {})
        fallback = proxies.get(AUTO, {})
        if any(type(item) is not dict for item in (outer, group, fallback)):
            self.suspended = True
            return False
        expected_fixed = "" if self.expected == AUTO else self.expected
        # Native fallback may clear our fixed member after a hard failure.
        # Accept that only with explicit DOWN evidence for our prior member.
        if (self.expected != AUTO and group.get("fixed") == ""
                and type(proxies.get(self.expected)) is dict
                and proxies[self.expected].get("alive") is False):
            self.expected, expected_fixed = AUTO, ""
        if (group.get("type") != "Fallback" or group.get("all") != self.members[1:]
                or group.get("hidden") is not True or group.get("fixed") != expected_fixed
                or fallback.get("type") != "Fallback" or fallback.get("all") != self.members[1:]
                or type(fallback.get("fixed")) is not str):
            self.suspended = True
        return (not self.suspended and (not require_outer or
                (outer.get("type") == "Selector" and outer.get("now") == GROUP
                 and fallback.get("fixed") == "")))

    def effective(self, proxies):
        if self.expected == AUTO:
            group = proxies.get(GROUP)
            return group.get("now") if type(group) is dict else None
        return self.expected

    def committed(self, selected):
        if selected not in self.members:
            raise ValueError("selection")
        self.expected = selected
