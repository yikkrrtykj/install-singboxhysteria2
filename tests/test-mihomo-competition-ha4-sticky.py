#!/usr/bin/env python3
"""Hermetic unit tests for the HA-04 sticky controller prototype.

No Mihomo core, network listener, TUN or real profile is used. A fake
loopback-controller API exercises the state machine, persistence, profile
binding, health completeness, transient/fatal API handling and fail-closed
behavior. Real-core loopback LAB evidence is separate.
"""

from __future__ import annotations

import importlib.util
import json
import os
import socket
import sys
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "mihomo-competition-ha4-sticky.py"
ORDER = ["Reality", "Hysteria2", "Backup-Reality", "Backup-Hysteria2"]
PROFILE = "a" * 64


def load_tool():
    name = "ha04_sticky"
    spec = importlib.util.spec_from_file_location(name, TOOL)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


SC = load_tool()


class FakeApi:
    def __init__(self, outer="Reality", health="Reality", alive=None):
        self.outer = outer
        self.health = health
        self.alive = {name: True for name in ORDER}
        if alive:
            self.alive.update(alive)
        self.history_age = {name: 0.0 for name in ORDER}
        self.no_history = set()
        self.missing = set()
        self.outer_type = "Selector"
        self.health_type = "Fallback"
        self.fail_mode = None  # transient | auth | invalid
        self.calls = []

    def _fail(self):
        if self.fail_mode == "transient":
            raise SC.ApiTransientError("fake transient")
        if self.fail_mode == "auth":
            raise SC.ApiAuthError("fake auth")
        if self.fail_mode == "invalid":
            raise SC.ApiResponseError("fake invalid")

    def proxies(self):
        self._fail()
        now = time.time()
        proxies = {
            "节点选择": {"now": self.outer, "all": ["自动选择"] + ORDER + ["DIRECT"],
                         "type": self.outer_type},
            "自动选择": {"now": self.health, "all": list(ORDER),
                         "type": self.health_type},
        }
        for name in ORDER:
            if name in self.missing:
                continue
            entry = {"alive": self.alive[name]}
            if name not in self.no_history:
                ts = datetime.fromtimestamp(now - self.history_age[name],
                                            timezone.utc)
                entry["history"] = [{"time": ts.isoformat(), "delay": 1}]
            proxies[name] = entry
        return proxies

    def select(self, group, name):
        self._fail()
        self.calls.append((group, name))
        self.outer = name


def make(tmp: Path, poll=0.001, threshold=2, health_age=20.0):
    cfg = SC.Config(
        controller_url="http://127.0.0.1:19097",
        secret="unit-secret",
        outer_group="节点选择",
        health_group="自动选择",
        order=list(ORDER),
        profile_sha256=PROFILE,
        config_version="unit-r1",
        state_path=tmp / "state.json",
        poll_interval=poll,
        api_timeout=0.2,
        error_threshold=threshold,
        health_max_age=health_age)
    api = FakeApi()
    ctrl = SC.StickyController(cfg, api=api)
    return cfg, api, ctrl


class ConfigTests(unittest.TestCase):
    def test_config_validation_and_loopback(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "config.json"
            base = {
                "schema": SC.CONFIG_SCHEMA,
                "controller_url": "http://127.0.0.1:9097",
                "secret": "s",
                "outer_group": "节点选择",
                "health_group": "自动选择",
                "order": ORDER,
                "profile_sha256": PROFILE,
                "config_version": "v1",
                "state_path": str(Path(d) / "state.json"),
                "health_max_age_ms": 20000,
            }
            path.write_text(json.dumps(base), encoding="utf-8")
            self.assertEqual(SC.Config.load(path).preferred, "Reality")
            base["controller_url"] = "http://192.0.2.10:9097"
            path.write_text(json.dumps(base), encoding="utf-8")
            with self.assertRaises(SC.ConfigError):
                SC.Config.load(path)
            base["controller_url"] = "http://127.0.0.1:9097"
            base["profile_sha256"] = "bad"
            path.write_text(json.dumps(base), encoding="utf-8")
            with self.assertRaises(SC.ConfigError):
                SC.Config.load(path)
            base["profile_sha256"] = PROFILE
            base["health_max_age_ms"] = -1
            path.write_text(json.dumps(base), encoding="utf-8")
            with self.assertRaises(SC.ConfigError):
                SC.Config.load(path)

    def test_instance_lock_and_release(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "state.lock"
            first = SC.InstanceLock(path)
            first.acquire()
            try:
                second = SC.InstanceLock(path)
                if os.name == "nt":
                    # Windows msvcrt locks are process-scoped for the same
                    # process; cross-process exclusion is covered by the CLI.
                    first.release()
                    first = None
                    second.acquire()
                    second.release()
                else:
                    with self.assertRaises(SC.StateError):
                        second.acquire()
            finally:
                if first is not None:
                    first.release()


class StateTests(unittest.TestCase):
    def test_preferred_takeover_and_no_failback(self):
        with tempfile.TemporaryDirectory() as d:
            cfg, api, ctrl = make(Path(d))
            ctrl.initialize()
            self.assertEqual(ctrl.state["state"], "PREFERRED")
            api.alive["Reality"] = False
            ctrl.poll_once()
            self.assertEqual(ctrl.state["state"], "TAKEOVER_LOCKED")
            self.assertEqual(ctrl.state["locked_node"], "Hysteria2")
            self.assertEqual(api.calls, [("节点选择", "Hysteria2")])
            calls_before = list(api.calls)
            api.alive["Reality"] = True
            for _ in range(5):
                ctrl.poll_once()
            self.assertEqual(ctrl.state["state"], "TAKEOVER_LOCKED")
            self.assertEqual(api.calls, calls_before)

    def test_second_failure_uses_lower_candidate(self):
        with tempfile.TemporaryDirectory() as d:
            cfg, api, ctrl = make(Path(d))
            ctrl.initialize()
            api.alive["Reality"] = False
            ctrl.poll_once()
            self.assertEqual(ctrl.state["locked_node"], "Hysteria2")
            api.alive["Hysteria2"] = False
            ctrl.poll_once()
            self.assertEqual(ctrl.state["state"], "TAKEOVER_LOCKED")
            self.assertEqual(ctrl.state["locked_node"], "Backup-Reality")

    def test_current_failure_uses_recovered_higher_priority(self):
        with tempfile.TemporaryDirectory() as d:
            cfg, api, ctrl = make(Path(d))
            ctrl.initialize()
            api.alive["Reality"] = False
            ctrl.poll_once()
            self.assertEqual(ctrl.state["locked_node"], "Hysteria2")
            # Current Hysteria2 fails; lower candidates are down; Reality has
            # recovered. A failure-driven takeover may now use Reality.
            api.alive["Hysteria2"] = False
            api.alive["Backup-Reality"] = False
            api.alive["Backup-Hysteria2"] = False
            api.alive["Reality"] = True
            ctrl.poll_once()
            self.assertEqual(ctrl.state["state"], "TAKEOVER_LOCKED")
            self.assertEqual(ctrl.state["locked_node"], "Reality")

    def test_current_healthy_higher_priority_recovered_is_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            cfg, api, ctrl = make(Path(d))
            ctrl.initialize()
            api.alive["Reality"] = False
            ctrl.poll_once()
            calls = list(api.calls)
            api.alive["Reality"] = True
            for _ in range(5):
                ctrl.poll_once()
            self.assertEqual(ctrl.state["locked_node"], "Hysteria2")
            self.assertEqual(api.calls, calls)

    def test_all_down_then_recovery(self):
        with tempfile.TemporaryDirectory() as d:
            cfg, api, ctrl = make(Path(d))
            ctrl.initialize()
            for name in ORDER:
                api.alive[name] = False
            ctrl.poll_once()
            self.assertEqual(ctrl.state["state"], "DUAL_DOWN")
            self.assertEqual(api.calls, [])
            api.alive["Backup-Hysteria2"] = True
            ctrl.poll_once()
            self.assertEqual(ctrl.state["state"], "TAKEOVER_LOCKED")
            self.assertEqual(ctrl.state["locked_node"], "Backup-Hysteria2")

    def test_health_incomplete_is_unknown_not_down(self):
        with tempfile.TemporaryDirectory() as d:
            cfg, api, ctrl = make(Path(d))
            ctrl.initialize()
            calls = list(api.calls)
            api.alive["Reality"] = None
            ctrl.poll_once()
            self.assertEqual(ctrl.state["state"], "UNKNOWN")
            self.assertEqual(ctrl.state["unknown_reason"], "health-unknown")
            self.assertEqual(api.calls, calls)
            api.alive["Reality"] = True
            ctrl.poll_once()
            self.assertEqual(ctrl.state["state"], "PREFERRED")

    def test_stale_health_is_unknown(self):
        with tempfile.TemporaryDirectory() as d:
            cfg, api, ctrl = make(Path(d), health_age=20.0)
            ctrl.initialize()
            api.history_age["Backup-Reality"] = 3600.0
            ctrl.poll_once()
            self.assertEqual(ctrl.state["state"], "UNKNOWN")
            self.assertEqual(ctrl.state["unknown_reason"], "health-unknown")
            api.history_age["Backup-Reality"] = 0.0
            ctrl.poll_once()
            self.assertEqual(ctrl.state["state"], "PREFERRED")

    def test_missing_node_is_unknown(self):
        with tempfile.TemporaryDirectory() as d:
            cfg, api, ctrl = make(Path(d))
            ctrl.initialize()
            api.missing.add("Backup-Hysteria2")
            ctrl.poll_once()
            self.assertEqual(ctrl.state["state"], "UNKNOWN")
            self.assertEqual(ctrl.state["unknown_reason"], "health-unknown")

    def test_group_type_mismatch_is_binding_unknown(self):
        with tempfile.TemporaryDirectory() as d:
            cfg, api, ctrl = make(Path(d))
            ctrl.initialize()
            api.health_type = "Selector"
            ctrl.poll_once()
            self.assertEqual(ctrl.state["state"], "UNKNOWN")
            self.assertEqual(ctrl.state["unknown_reason"], "binding")

    def test_alive_type_and_missing_history_are_unknown(self):
        with tempfile.TemporaryDirectory() as d:
            cfg, api, ctrl = make(Path(d))
            ctrl.initialize()
            api.alive["Reality"] = "yes"
            ctrl.poll_once()
            self.assertEqual(ctrl.state["state"], "UNKNOWN")
            api.alive["Reality"] = True
            ctrl.poll_once()
            self.assertEqual(ctrl.state["state"], "PREFERRED")
            api.no_history.add("Hysteria2")
            ctrl.poll_once()
            self.assertEqual(ctrl.state["state"], "UNKNOWN")

    def test_transient_api_with_concurrent_fault_reconciles_into_takeover(self):
        with tempfile.TemporaryDirectory() as d:
            cfg, api, ctrl = make(Path(d), threshold=2)
            ctrl.initialize()
            api.fail_mode = "transient"
            ctrl.poll_once()
            ctrl.poll_once()
            self.assertEqual(ctrl.state["state"], "UNKNOWN")
            # The preferred node fails while the API is unavailable.
            api.alive["Reality"] = False
            api.fail_mode = None
            ctrl.poll_once()
            self.assertEqual(ctrl.state["state"], "RECONFIRMING")
            ctrl.poll_once()
            self.assertEqual(ctrl.state["state"], "TAKEOVER_LOCKED")
            self.assertEqual(ctrl.state["locked_node"], "Hysteria2")

    def test_repeated_transient_loss_and_recovery(self):
        with tempfile.TemporaryDirectory() as d:
            cfg, api, ctrl = make(Path(d), threshold=2)
            ctrl.initialize()
            for _ in range(2):
                api.fail_mode = "transient"
                ctrl.poll_once()
                ctrl.poll_once()
                self.assertEqual(ctrl.state["state"], "UNKNOWN")
                api.fail_mode = None
                ctrl.poll_once()
                self.assertEqual(ctrl.state["state"], "PREFERRED")

    def test_third_failure_uses_backup_hysteria2(self):
        with tempfile.TemporaryDirectory() as d:
            cfg, api, ctrl = make(Path(d))
            ctrl.initialize()
            api.alive["Reality"] = False
            ctrl.poll_once()
            api.alive["Hysteria2"] = False
            ctrl.poll_once()
            self.assertEqual(ctrl.state["locked_node"], "Backup-Reality")
            api.alive["Backup-Reality"] = False
            ctrl.poll_once()
            self.assertEqual(ctrl.state["state"], "TAKEOVER_LOCKED")
            self.assertEqual(ctrl.state["locked_node"], "Backup-Hysteria2")

    def test_api_transient_reconciles_after_recovery(self):
        with tempfile.TemporaryDirectory() as d:
            cfg, api, ctrl = make(Path(d), threshold=2)
            ctrl.initialize()
            calls = list(api.calls)
            api.fail_mode = "transient"
            ctrl.poll_once()
            ctrl.poll_once()
            self.assertEqual(ctrl.state["state"], "UNKNOWN")
            self.assertEqual(ctrl.state["unknown_reason"], "api-transient")
            self.assertEqual(api.calls, calls)
            api.fail_mode = None
            ctrl.poll_once()
            self.assertEqual(ctrl.state["state"], "PREFERRED")
            self.assertEqual(api.calls, calls)

    def test_auth_and_invalid_response_stay_unknown(self):
        for mode, reason in (("auth", "api-auth"), ("invalid", "api-invalid")):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as d:
                cfg, api, ctrl = make(Path(d))
                ctrl.initialize()
                api.fail_mode = mode
                ctrl.poll_once()
                self.assertEqual(ctrl.state["state"], "UNKNOWN")
                self.assertEqual(ctrl.state["unknown_reason"], reason)
                api.fail_mode = None
                ctrl.poll_once()
                self.assertEqual(ctrl.state["state"], "UNKNOWN")
                self.assertEqual(ctrl.state["unknown_reason"], reason)

    def test_reset_request_preserved_on_transient_api(self):
        with tempfile.TemporaryDirectory() as d:
            cfg, api, ctrl = make(Path(d))
            ctrl.initialize()
            api.alive["Reality"] = False
            ctrl.poll_once()
            self.assertEqual(ctrl.state["state"], "TAKEOVER_LOCKED")
            reset = cfg.state_path.with_suffix(".reset-request")
            reset.write_text("{}", encoding="utf-8")
            api.fail_mode = "transient"
            ctrl.poll_once()
            self.assertTrue(reset.exists())
            self.assertEqual(ctrl.state["state"], "UNKNOWN")
            api.fail_mode = None
            ctrl.poll_once()
            self.assertEqual(ctrl.state["state"], "PREFERRED")
            self.assertFalse(reset.exists())

    def test_manual_conflict_and_admin_reset(self):
        with tempfile.TemporaryDirectory() as d:
            cfg, api, ctrl = make(Path(d))
            ctrl.initialize()
            api.alive["Reality"] = False
            ctrl.poll_once()
            self.assertEqual(ctrl.state["state"], "TAKEOVER_LOCKED")
            api.outer = "Reality"
            ctrl.poll_once()
            self.assertEqual(ctrl.state["state"], "MANUAL_RESET")
            calls = list(api.calls)
            ctrl.poll_once()
            self.assertEqual(api.calls, calls)
            reset = cfg.state_path.with_suffix(".reset-request")
            reset.write_text("{}", encoding="utf-8")
            api.alive["Reality"] = True
            ctrl.poll_once()
            self.assertEqual(ctrl.state["state"], "PREFERRED")
            self.assertEqual(api.outer, "Reality")
            self.assertFalse(reset.exists())

    def test_fast_recovery_before_detection(self):
        with tempfile.TemporaryDirectory() as d:
            cfg, api, ctrl = make(Path(d))
            ctrl.initialize()
            calls = list(api.calls)
            api.alive["Reality"] = False
            api.alive["Reality"] = True
            ctrl.poll_once()
            self.assertEqual(ctrl.state["state"], "PREFERRED")
            self.assertEqual(api.calls, calls)

    def test_startup_resume_and_mismatch(self):
        with tempfile.TemporaryDirectory() as d:
            cfg, api, ctrl = make(Path(d))
            ctrl.initialize()
            ctrl.state["state"] = "TAKEOVER_LOCKED"
            ctrl.state["locked_node"] = "Hysteria2"
            ctrl.save_state()
            api.outer = "Hysteria2"
            ctrl2 = SC.StickyController(cfg, api=api)
            ctrl2.initialize()
            self.assertEqual(ctrl2.state["state"], "TAKEOVER_LOCKED")
            # Locked node dead on restart -> RECONFIRMING then next candidate.
            api.alive["Hysteria2"] = False
            api.alive["Backup-Reality"] = True
            ctrl3 = SC.StickyController(cfg, api=api)
            ctrl3.initialize()
            self.assertEqual(ctrl3.state["state"], "RECONFIRMING")
            ctrl3.poll_once()
            self.assertEqual(ctrl3.state["state"], "TAKEOVER_LOCKED")
            self.assertEqual(ctrl3.state["locked_node"], "Backup-Reality")
            # Outer mismatch is explicit UNKNOWN, not a guessed state.
            ctrl4 = SC.StickyController(cfg, api=api)
            api.outer = "Reality"
            ctrl4.initialize()
            self.assertEqual(ctrl4.state["state"], "UNKNOWN")

    def test_existing_preferred_state_does_not_overwrite_manual_selection(self):
        with tempfile.TemporaryDirectory() as d:
            cfg, api, ctrl = make(Path(d))
            ctrl.initialize()
            ctrl.save_state()
            api.outer = "自动选择"
            api.calls.clear()
            ctrl2 = SC.StickyController(cfg, api=api)
            ctrl2.initialize()
            self.assertEqual(ctrl2.state["state"], "UNKNOWN")
            self.assertEqual(api.calls, [])
            self.assertEqual(api.outer, "自动选择")

    def test_repeated_initialize_is_idempotent(self):
        with tempfile.TemporaryDirectory() as d:
            cfg, api, ctrl = make(Path(d))
            ctrl.initialize()
            calls = list(api.calls)
            ctrl.initialize()
            self.assertEqual(api.calls, calls)

    def test_state_binding_rejects_other_profile(self):
        with tempfile.TemporaryDirectory() as d:
            cfg, api, ctrl = make(Path(d))
            ctrl.initialize()
            raw = json.loads(cfg.state_path.read_text(encoding="utf-8"))
            raw["binding"]["profile_sha256"] = "b" * 64
            cfg.state_path.write_text(json.dumps(raw), encoding="utf-8")
            with self.assertRaises(SC.StateError):
                SC.StickyController(cfg, api=api).load_state()

    def test_cli_initialize_failure_is_nonzero(self):
        with tempfile.TemporaryDirectory() as d:
            sock = socket.socket()
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
            sock.close()
            cfg_path = Path(d) / "config.json"
            cfg_path.write_text(json.dumps({
                "schema": SC.CONFIG_SCHEMA,
                "controller_url": "http://127.0.0.1:%d" % port,
                "secret": "s",
                "outer_group": "节点选择",
                "health_group": "自动选择",
                "order": ORDER,
                "profile_sha256": PROFILE,
                "config_version": "v1",
                "state_path": str(Path(d) / "state.json"),
                "api_timeout_ms": 100,
                "poll_interval_ms": 10,
                "health_max_age_ms": 20000,
            }), encoding="utf-8")
            self.assertNotEqual(SC.main(["run", "--config", str(cfg_path)]), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
