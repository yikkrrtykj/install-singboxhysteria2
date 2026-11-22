#!/usr/bin/env python3
"""Minimal HA-04 Sticky Failover prototype (LOCAL, DEFAULT OFF).

This is a prototype for issue #92. It does not modify Mihomo or the HA-UI.
It uses the loopback Mihomo controller API only:

- the existing fallback group (`自动选择`) remains the health detector;
- the existing selector group (`节点选择`) is the traffic-selecting group;
- after a node fails, the controller explicitly sets the outer selector to the
  next healthy candidate in the configured sticky order;
- a higher-priority node recovering later does NOT change the outer selector;
- only an explicit admin reset restores PREFERRED.

The design deliberately does not use fallback `fixed`: the outer selector's
manual selection is the persistent traffic lock. This removes the traffic
failback race in the fallback group. It does not create extra health probes,
does not call /group/*/delay, does not restart core, and does not modify TUN.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

CONFIG_SCHEMA = "mihomo-competition-ha4-sticky-config/1"
STATE_SCHEMA = "mihomo-competition-ha4-sticky-state/1"
HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")
STATES = (
    "PREFERRED", "TAKEOVER_PENDING", "TAKEOVER_LOCKED", "RECONFIRMING",
    "UNKNOWN", "DUAL_DOWN", "MANUAL_RESET",
)


class StickyError(Exception):
    pass


class ConfigError(StickyError):
    pass


class ApiError(StickyError):
    pass


class StateError(StickyError):
    pass


class InstanceLock:
    """One controller per state path; fails closed instead of double-writing."""

    def __init__(self, path: Path):
        self.path = path
        self.handle = None

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = open(self.path, "a+b")
        try:
            if os.name == "nt":
                import msvcrt
                self.handle.seek(0)
                msvcrt.locking(self.handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self.handle.close()
            self.handle = None
            raise StateError("controller already running (instance lock)") from exc

    def release(self) -> None:
        if self.handle is None:
            return
        try:
            if os.name == "nt":
                import msvcrt
                self.handle.seek(0)
                msvcrt.locking(self.handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
        finally:
            self.handle.close()
            self.handle = None


@dataclass
class Config:
    controller_url: str
    secret: str
    outer_group: str
    health_group: str
    order: list[str]
    profile_sha256: str
    config_version: str
    state_path: Path
    poll_interval: float = 0.05
    api_timeout: float = 1.0
    error_threshold: int = 3

    @property
    def preferred(self) -> str:
        return self.order[0]

    @classmethod
    def load(cls, path: Path) -> "Config":
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ConfigError("cannot read config") from exc
        if raw.get("schema") != CONFIG_SCHEMA:
            raise ConfigError("bad config schema")
        url = str(raw.get("controller_url", ""))
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "http" or parsed.hostname not in ("127.0.0.1", "localhost"):
            raise ConfigError("controller_url must be http loopback")
        secret = raw.get("secret")
        if not isinstance(secret, str) or not secret:
            raise ConfigError("missing controller secret")
        outer = raw.get("outer_group")
        health = raw.get("health_group")
        if not isinstance(outer, str) or not isinstance(health, str) or outer == health:
            raise ConfigError("group names must be distinct strings")
        order = raw.get("order")
        if (not isinstance(order, list) or len(order) < 2
                or any(not isinstance(n, str) or not n for n in order)
                or len(set(order)) != len(order)):
            raise ConfigError("order must be a distinct node list")
        profile = str(raw.get("profile_sha256", ""))
        if not HEX64.fullmatch(profile):
            raise ConfigError("profile_sha256 must be 64 hex")
        version = raw.get("config_version")
        if not isinstance(version, str) or not version:
            raise ConfigError("missing config_version")
        state = Path(str(raw.get("state_path", "")))
        if not str(state) or not state.is_absolute():
            raise ConfigError("state_path must be absolute")
        poll = raw.get("poll_interval_ms", 50)
        timeout = raw.get("api_timeout_ms", 1000)
        threshold = raw.get("error_threshold", 3)
        try:
            poll_s = max(0.005, min(float(poll) / 1000.0, 5.0))
            timeout_s = max(0.1, min(float(timeout) / 1000.0, 10.0))
            threshold_i = max(1, min(int(threshold), 20))
        except (TypeError, ValueError) as exc:
            raise ConfigError("bad interval/timeout/threshold") from exc
        return cls(url, secret, outer, health, list(order), profile, version,
                   state, poll_s, timeout_s, threshold_i)


class MihomoApi:
    def __init__(self, config: Config):
        self.base = config.controller_url.rstrip("/")
        self.secret = config.secret
        self.timeout = config.api_timeout
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def _request(self, method: str, path: str, body: dict | None = None):
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(
            self.base + path, data=data, method=method,
            headers={"Authorization": "Bearer " + self.secret,
                     "Content-Type": "application/json"})
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                raw = response.read()
                payload = json.loads(raw) if raw else None
                return response.status, payload
        except urllib.error.HTTPError as exc:
            raise ApiError("HTTP %s" % exc.code) from exc
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            raise ApiError("controller unavailable") from exc

    def proxies(self) -> dict[str, Any]:
        status, payload = self._request("GET", "/proxies")
        if status != 200 or not isinstance(payload, dict):
            raise ApiError("bad /proxies response")
        proxies = payload.get("proxies")
        if not isinstance(proxies, dict):
            raise ApiError("bad /proxies payload")
        return proxies

    def select(self, group: str, name: str) -> None:
        status, _ = self._request(
            "PUT", "/proxies/" + urllib.parse.quote(group, safe=""),
            {"name": name})
        if status not in (200, 204):
            raise ApiError("selection rejected")


@dataclass
class Snapshot:
    nodes_alive: dict[str, bool]
    outer_now: str | None
    health_now: str | None
    outer_all: list[str]
    health_all: list[str]


class StickyController:
    def __init__(self, config: Config, api: MihomoApi | None = None,
                 state_path: Path | None = None):
        self.config = config
        self.api = api or MihomoApi(config)
        self.state_path = state_path or config.state_path
        self.state: dict[str, Any] = {}
        self.events: list[dict[str, Any]] = []
        self.api_errors = 0
        self.initialized = False
        self.state_exists = False
        self.last_outer_now: str | None = None
        self.reset_request = self.state_path.with_suffix(".reset-request")
        self.binding = {
            "profile_sha256": config.profile_sha256,
            "config_version": config.config_version,
            "order": list(config.order),
            "outer_group": config.outer_group,
            "health_group": config.health_group,
        }

    # ---------- persistence ----------
    def _new_state(self) -> dict[str, Any]:
        return {
            "schema": STATE_SCHEMA,
            "binding": dict(self.binding),
            "state": "PREFERRED",
            "locked_node": self.config.preferred,
            "last_outer_now": None,
            "updated_utc": _utc(),
        }

    def load_state(self) -> None:
        if not self.state_path.exists():
            self.state = self._new_state()
            self.state_exists = False
            return
        try:
            doc = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise StateError("cannot read state") from exc
        if doc.get("schema") != STATE_SCHEMA:
            raise StateError("bad state schema")
        if doc.get("binding") != self.binding:
            raise StateError("state binding does not match profile/order/version")
        if doc.get("state") not in STATES:
            raise StateError("bad persisted state")
        locked = doc.get("locked_node")
        if locked is not None and locked not in self.config.order:
            raise StateError("bad persisted locked_node")
        self.state = doc
        self.state_exists = True

    def save_state(self) -> None:
        if self.state.get("state") not in STATES:
            raise StateError("refusing to persist unknown state")
        self.state["binding"] = dict(self.binding)
        self.state["updated_utc"] = _utc()
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.state_path.with_name(self.state_path.name + ".tmp-%d" % os.getpid())
        payload = json.dumps(self.state, ensure_ascii=False, indent=2, sort_keys=True)
        with open(temp, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        # Verify the temp bytes and JSON before replacing the live state.
        if json.loads(temp.read_text(encoding="utf-8")) != self.state:
            temp.unlink(missing_ok=True)
            raise StateError("state write verification failed")
        os.replace(temp, self.state_path)

    def _set_state(self, state: str, node: str | None, reason: str) -> None:
        if state not in STATES:
            raise StateError("invalid state " + state)
        self.state["state"] = state
        self.state["locked_node"] = node
        self.state["last_outer_now"] = self.last_outer_now
        self.events.append({"utc": _utc(), "state": state, "node": node,
                            "reason": reason})
        self.save_state()
        print(json.dumps({"event": "state", "state": state, "node": node,
                          "reason": reason}, ensure_ascii=False), flush=True)

    # ---------- observation ----------
    def snapshot(self) -> Snapshot:
        proxies = self.api.proxies()
        outer = proxies.get(self.config.outer_group) or {}
        health = proxies.get(self.config.health_group) or {}
        nodes = {name: bool((proxies.get(name) or {}).get("alive"))
                 for name in self.config.order}
        return Snapshot(nodes, outer.get("now"), health.get("now"),
                        list(outer.get("all") or []), list(health.get("all") or []))

    def validate_snapshot(self, snap: Snapshot) -> None:
        if snap.health_all != self.config.order:
            raise StateError("health group order changed; refusing to control")
        if not _is_subsequence(self.config.order, snap.outer_all):
            raise StateError("outer group order changed; refusing to control")

    def fetch(self) -> Snapshot:
        snap = self.snapshot()
        self.validate_snapshot(snap)
        self.last_outer_now = snap.outer_now
        return snap

    # ---------- state helpers ----------
    def _next_after(self, node: str, alive: dict[str, bool]) -> str | None:
        index = self.config.order.index(node)
        for candidate in self.config.order[index + 1:]:
            if alive.get(candidate):
                return candidate
        return None

    def _write_lock(self, node: str, reason: str) -> bool:
        self._set_state("TAKEOVER_PENDING", node, reason)
        try:
            self.api.select(self.config.outer_group, node)
            time.sleep(min(self.config.poll_interval, 0.05))
            snap = self.fetch()
        except (ApiError, StateError):
            self._set_state("UNKNOWN", self.state.get("locked_node"), "api-write-failed")
            return False
        if snap.outer_now != node:
            self._set_state("UNKNOWN", node, "selection-not-verified")
            return False
        self._set_state("TAKEOVER_LOCKED", node, reason + ":verified")
        return True

    def _reset_requested(self) -> bool:
        return self.reset_request.exists()

    def _consume_reset(self) -> None:
        try:
            self.reset_request.unlink()
        except OSError:
            pass

    def _admin_reset(self) -> None:
        self._consume_reset()
        try:
            snap = self.fetch()
        except (ApiError, StateError):
            self._set_state("UNKNOWN", self.state.get("locked_node"), "reset-api-unavailable")
            return
        self.api.select(self.config.outer_group, self.config.preferred)
        time.sleep(min(self.config.poll_interval, 0.05))
        snap = self.fetch()
        if snap.outer_now == self.config.preferred:
            self._set_state("PREFERRED", self.config.preferred, "admin-reset")
        else:
            self._set_state("UNKNOWN", self.config.preferred, "admin-reset-unverified")

    # ---------- lifecycle ----------
    def initialize(self) -> None:
        self.load_state()
        snap = self.fetch()
        state = self.state["state"]
        outer = snap.outer_now
        if state == "PREFERRED":
            if outer != self.config.preferred:
                if self.state_exists:
                    # A previous controller state existed and the operator (or
                    # core restart) changed the outer selection outside this
                    # controller. Never silently overwrite that choice.
                    self._set_state("UNKNOWN", None,
                                    "startup-outer-mismatch")
                    return
                # First explicit activation: set the preferred outer selector.
                self.api.select(self.config.outer_group, self.config.preferred)
                time.sleep(min(self.config.poll_interval, 0.05))
                snap = self.fetch()
                outer = snap.outer_now
            if outer != self.config.preferred:
                self._set_state("UNKNOWN", None, "initial-selection-not-preferred")
            else:
                self.state["locked_node"] = self.config.preferred
                self._set_state("PREFERRED", self.config.preferred, "startup")
        elif state in ("TAKEOVER_LOCKED", "RECONFIRMING"):
            locked = self.state.get("locked_node")
            if locked in self.config.order and outer == locked:
                if snap.nodes_alive.get(locked):
                    self._set_state("TAKEOVER_LOCKED", locked, "startup-resume")
                else:
                    self._set_state("RECONFIRMING", locked, "startup-locked-dead")
            else:
                self._set_state("UNKNOWN", locked, "startup-outer-mismatch")
        elif state == "TAKEOVER_PENDING":
            target = self.state.get("locked_node")
            if target in self.config.order and outer == target:
                self._set_state("TAKEOVER_LOCKED", target, "startup-finish-pending")
            else:
                self._set_state("UNKNOWN", target, "startup-pending-mismatch")
        # UNKNOWN/MANUAL_RESET/DUAL_DOWN stay unavailable until admin reset or
        # a safe observation; no automatic writes at startup.
        self.initialized = True

    def poll_once(self) -> None:
        if self._reset_requested():
            self._admin_reset()
            return
        try:
            snap = self.fetch()
            self.api_errors = 0
        except (ApiError, StateError):
            self.api_errors += 1
            if self.api_errors >= self.config.error_threshold and self.state.get("state") != "UNKNOWN":
                self._set_state("UNKNOWN", self.state.get("locked_node"),
                                "api-errors")
            return

        state = self.state["state"]
        alive = snap.nodes_alive
        outer = snap.outer_now

        if state == "PREFERRED":
            if outer != self.config.preferred:
                self._set_state("MANUAL_RESET", self.config.preferred,
                                "outer-selection-changed-externally")
                return
            if not alive.get(self.config.preferred):
                nxt = self._next_after(self.config.preferred, alive)
                if nxt:
                    self._write_lock(nxt, "preferred-unhealthy")
                else:
                    self._set_state("DUAL_DOWN", self.config.preferred,
                                    "no-lower-healthy-candidate")
            return

        if state in ("TAKEOVER_LOCKED", "RECONFIRMING"):
            locked = self.state.get("locked_node")
            if not locked or locked not in self.config.order:
                self._set_state("UNKNOWN", None, "missing-locked-node")
                return
            if outer != locked:
                self._set_state("MANUAL_RESET", locked,
                                "outer-selection-changed-externally")
                return
            if not alive.get(locked):
                nxt = self._next_after(locked, alive)
                if nxt:
                    self._write_lock(nxt, "locked-unhealthy")
                else:
                    self._set_state("DUAL_DOWN", locked,
                                    "no-lower-healthy-candidate")
            return

        if state == "DUAL_DOWN":
            locked = self.state.get("locked_node")
            if locked and locked in self.config.order:
                if alive.get(locked):
                    self._write_lock(locked, "dual-down-locked-recovered")
                    return
                nxt = self._next_after(locked, alive)
                if nxt:
                    self._write_lock(nxt, "dual-down-lower-recovered")
            return

        # UNKNOWN / MANUAL_RESET wait for an explicit admin reset request.
        return

    def run_forever(self, stop: "threading.Event | None" = None) -> None:
        try:
            self.initialize()
            self.initialized = True
        except (ApiError, StateError) as exc:
            # A controller that cannot establish a verified state must not
            # pretend to protect anything. Persist UNKNOWN and stop.
            try:
                self._set_state("UNKNOWN", self.state.get("locked_node"),
                                "initialize-failed")
            except StickyError:
                pass
            print("sticky: FAIL initialize %s" % exc, file=sys.stderr, flush=True)
            return
        while stop is None or not stop.is_set():
            self.poll_once()
            if stop is not None:
                stop.wait(self.config.poll_interval)
            else:
                time.sleep(self.config.poll_interval)


def _is_subsequence(needle: list[str], haystack: list[str]) -> bool:
    iterator = iter(haystack)
    return all(any(item == candidate for candidate in iterator) for item in needle)


def _utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _write_reset_request(state_path: Path) -> None:
    reset = state_path.with_suffix(".reset-request")
    reset.parent.mkdir(parents=True, exist_ok=True)
    payload = {"requested_utc": _utc(), "pid": os.getpid()}
    reset.write_text(json.dumps(payload) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("run", "status", "reset"))
    parser.add_argument("--config", required=True)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args(argv)
    try:
        config = Config.load(Path(args.config))
    except ConfigError as exc:
        print("sticky: FAIL config %s" % exc, file=sys.stderr)
        return 2
    if args.command == "reset":
        _write_reset_request(config.state_path)
        print("sticky: reset requested (admin operation; controller must be running)")
        return 0
    if args.command == "status":
        try:
            state = json.loads(config.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            print("sticky: no valid state")
            return 1
        print(json.dumps({"state": state.get("state"),
                          "locked_node": state.get("locked_node"),
                          "updated_utc": state.get("updated_utc")},
                         ensure_ascii=False))
        return 0
    lock = InstanceLock(config.state_path.with_suffix(".lock"))
    try:
        lock.acquire()
    except StateError as exc:
        print("sticky: FAIL %s" % exc, file=sys.stderr)
        return 1
    controller = StickyController(config)
    try:
        controller.initialize()
        if args.once:
            controller.poll_once()
            return 0
        controller.run_forever()
    except KeyboardInterrupt:
        return 0
    except StickyError as exc:
        print("sticky: FAIL %s" % exc, file=sys.stderr)
        return 1
    finally:
        lock.release()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
