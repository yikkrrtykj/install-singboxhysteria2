#!/usr/bin/env python3
"""Hermetic unit tests for the HA-04 sticky controller prototype.

No Mihomo core, network listener, TUN or real profile is used. A fake
loopback-controller API exercises the state machine, persistence, profile
binding and fail-closed behavior. Real-core loopback LAB evidence is separate.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
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
        self.calls = []
        self.fail = False

    def proxies(self):
        if self.fail:
            raise SC.ApiError("fake unavailable")
        proxies = {
            "节点选择": {"now": self.outer, "all": ["自动选择"] + ORDER + ["DIRECT"]},
            "自动选择": {"now": self.health, "all": list(ORDER)},
        }
        for name in ORDER:
            proxies[name] = {"alive": self.alive[name], "history": []}
        return proxies

    def select(self, group, name):
        if self.fail:
            raise SC.ApiError("fake unavailable")
        self.calls.append((group, name))
        self.outer = name


def make(tmp: Path, poll=0.001, threshold=2):
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
        error_threshold=threshold)
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

    def test_instance_lock_and_release(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "state.lock"
            first = SC.InstanceLock(path)
            first.acquire()
            try:
                second = SC.InstanceLock(path)
                if os.name == "nt":
                    # Windows msvcrt locks are process-scoped for the same
                    # process; cross-process exclusion is covered by the
                    # controller CLI check. At minimum a release must unlock.
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
            self.assertEqual(api.outer, "Hysteria2")
            calls_before = list(api.calls)
            api.alive["Reality"] = True
            for _ in range(5):
                ctrl.poll_once()
            self.assertEqual(ctrl.state["state"], "TAKEOVER_LOCKED")
            self.assertEqual(api.calls, calls_before)

    def test_second_failure_and_lower_only_policy(self):
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
            # All lower candidates dead, higher-priority Reality alive:
            # strict sticky order must not auto-restore the preferred path.
            api.alive["Backup-Reality"] = False
            api.alive["Backup-Hysteria2"] = False
            ctrl.poll_once()
            self.assertEqual(ctrl.state["state"], "DUAL_DOWN")
            api.alive["Reality"] = True
            ctrl.poll_once()
            self.assertEqual(ctrl.state["state"], "DUAL_DOWN")

    def test_all_down_and_lower_recovery(self):
        with tempfile.TemporaryDirectory() as d:
            cfg, api, ctrl = make(Path(d))
            ctrl.initialize()
            api.alive["Reality"] = False
            ctrl.poll_once()
            api.alive["Hysteria2"] = False
            ctrl.poll_once()
            self.assertEqual(ctrl.state["state"], "TAKEOVER_LOCKED")
            self.assertEqual(ctrl.state["locked_node"], "Backup-Reality")
            api.alive["Backup-Reality"] = False
            api.alive["Backup-Hysteria2"] = False
            ctrl.poll_once()
            self.assertEqual(ctrl.state["state"], "DUAL_DOWN")
            api.alive["Backup-Reality"] = True
            ctrl.poll_once()
            self.assertEqual(ctrl.state["state"], "TAKEOVER_LOCKED")
            self.assertEqual(ctrl.state["locked_node"], "Backup-Reality")

    def test_third_failure_continues_to_backup_hysteria2(self):
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
            self.assertEqual(ctrl.state["state"], "MANUAL_RESET")
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
            # Node recovers before the controller's next poll sees the fault.
            api.alive["Reality"] = True
            ctrl.poll_once()
            self.assertEqual(ctrl.state["state"], "PREFERRED")
            self.assertEqual(api.calls, calls)

    def test_api_failure_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            cfg, api, ctrl = make(Path(d), threshold=2)
            ctrl.initialize()
            calls = list(api.calls)
            api.fail = True
            ctrl.poll_once()
            ctrl.poll_once()
            self.assertEqual(ctrl.state["state"], "UNKNOWN")
            self.assertEqual(api.calls, calls)
            api.fail = False
            ctrl.poll_once()
            self.assertEqual(ctrl.state["state"], "UNKNOWN")

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
            # Locked node dead on restart -> RECONFIRMING then next lower.
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

    def test_state_binding_rejects_other_profile(self):
        with tempfile.TemporaryDirectory() as d:
            cfg, api, ctrl = make(Path(d))
            ctrl.initialize()
            raw = json.loads(cfg.state_path.read_text(encoding="utf-8"))
            raw["binding"]["profile_sha256"] = "b" * 64
            cfg.state_path.write_text(json.dumps(raw), encoding="utf-8")
            with self.assertRaises(SC.StateError):
                SC.StickyController(cfg, api=api).load_state()


if __name__ == "__main__":
    unittest.main(verbosity=2)
