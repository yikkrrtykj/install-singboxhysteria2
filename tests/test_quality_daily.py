"""Daily opt-in contracts; synthetic files/controllers, no live Clash or VPS writes."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from quality_failover import daily
from quality_failover.controller import Controller
from quality_failover.policy import AUTO, GROUP, OUTER, NODES, Ownership, Engine, Policy, Confirmation

spec = importlib.util.spec_from_file_location("daily_fixtures", ROOT / "tests/test_quality_failover.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
MARKER = "quality-profile-" + "a" * 32


def topology(nodes=NODES[:2], outer=GROUP):
    values = fixture.snapshot(nodes)
    values[OUTER]["all"] = [*nodes, AUTO, GROUP, "DIRECT"]
    values[OUTER]["now"] = outer
    values[MARKER] = {"type": "Selector", "all": ["DIRECT"], "hidden": True, "now": "DIRECT"}
    for index, node in enumerate(nodes):
        values[node]["type"] = "Vless" if index % 2 == 0 else "Hysteria2"
    values["GLOBAL"] = {"type": "Selector", "all": [GROUP, "Reality", "Hysteria2", "DIRECT"], "now": GROUP}
    return daily.RoutingSnapshot(values, "rule")


def api(values, mode="rule"):
    def request(method, path, payload=None):
        if path == "/configs": return {"mode": mode}
        if path == "/proxies": return {"proxies": dict(values)}
        return {}
    return request


def settings(path, address="127.0.0.1:19091", secret="verge-test-only"):
    path.mkdir()
    (path / "clash-verge.yaml").write_text("external-controller: " + address + "\nsecret: '" + secret + "'\n", "utf-8")


class CredentialsTests(unittest.TestCase):
    def test_existing_fifteen_character_authenticated_loopback_secret_works(self):
        controller = Controller("http://127.0.0.1:19091", "synthetic-only1")
        self.assertEqual(controller.secret, "synthetic-only1")
        for secret in ("", "x" * 257, "a\nb", "white space", "非ASCII"):
            with self.subTest(secret=secret), self.assertRaises(ValueError):
                Controller("http://127.0.0.1:19091", secret)

    def test_read_active_scalars_leaves_clash_settings_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "clash"
            settings(home)
            source = home / "clash-verge.yaml"
            before = source.read_bytes()
            url, secret = daily.clash_credentials(home)
            self.assertEqual(url, "http://127.0.0.1:19091")
            self.assertEqual(secret, "verge-test-only")
            self.assertEqual(source.read_bytes(), before)

    def test_utf8_bom_crlf_and_ipv6_loopback_scalars(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            (home / "clash-verge.yaml").write_bytes(b'\xef\xbb\xbfexternal-controller: "[::1]:19091"\r\nsecret: "synthetic-only"\r\n')
            self.assertEqual(daily.clash_credentials(home)[0], "http://[::1]:19091")

    def test_duplicate_wildcard_hostname_and_unsupported_scalar_refused(self):
        for text in ("external-controller: 0.0.0.0:19091\nsecret: xxx\n",
                     "external-controller: localhost:19091\nsecret: xxx\n",
                     "external-controller: 127.0.0.1:19091\nsecret: a\nsecret: b\n",
                     "external-controller: 127.0.0.1:19091\nsecret: &anchor\n"):
            with self.subTest(text=text), tempfile.TemporaryDirectory() as directory:
                (Path(directory) / "clash-verge.yaml").write_text(text, "utf-8")
                with self.assertRaises(ValueError):
                    daily.clash_credentials(directory)

    def test_scalar_escapes_only_supported_literal_forms(self):
        self.assertEqual(daily.scalar("'a''b'"), "a'b")
        self.assertEqual(daily.scalar('"a\\u0031b"'), "a1b")
        for value in ("'open", '"with\\nnewline"', "[]", "", "abc # comment"):
            with self.subTest(value=value), self.assertRaises((ValueError, json.JSONDecodeError)):
                daily.scalar(value)


class BundleTests(unittest.TestCase):
    def create(self, root, dual=False):
        home, inputs = root / "clash", root / "inputs"
        settings(home)
        inputs.mkdir()
        a = inputs / "event-mihomo.yaml"
        fixture.export(a, hopping=True)
        b = None
        if dual:
            (inputs / "B").mkdir()
            b = inputs / "B/event-mihomo.yaml"
            fixture.export(b, backup=True, hopping=True)
        info, ca = inputs / "receiver-info.json", inputs / "receiver-ca.pem"
        ca.write_bytes(b"synthetic-ca-never-used-on-network")
        value = {"v": 1, "endpoint": "https://127.0.0.1:19443", "token": "z" * 32,
                 "certificate_sha256": hashlib.sha256(ca.read_bytes()).hexdigest()}
        info.write_text(json.dumps(value), "utf-8")
        info.chmod(0o600)
        return home, a, b, info

    def build(self, root, dual=False):
        home, a, b, info = self.create(root, dual)
        with patch("quality_failover.transport.ssl.create_default_context"):
            path = daily.prepare_bundle(root / "private", a, "event", info, home, b)
        return path, home, a, b, info

    def test_private_bundle_generation_source_and_manual_defaults_preserved(self):
        for dual in (False, True):
            with self.subTest(dual=dual), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                home, a, b, info = self.create(root, dual)
                before = {path: path.read_bytes() for path in (a, b, home / "clash-verge.yaml") if path}
                with patch("quality_failover.transport.ssl.create_default_context"):
                    path = daily.prepare_bundle(root / "private", a, "event", info, home, b)
                    meta, config = daily.load_bundle(path, home)
                text = (path.parent / meta["profile"]).read_text("utf-8")
                self.assertIn("    default-selected: 自动选择", text)
                self.assertIn("    interval: 60", text)
                self.assertIn(meta["marker"], text)
                self.assertEqual(text.count("    hop-interval: 30"), 2 if dual else 1)
                self.assertFalse(config["control_enabled"])
                saved = (path.parent / "client.json").read_text("utf-8")
                self.assertNotIn("controller_secret", saved)
                self.assertNotIn("verge-test-only", saved)
                self.assertEqual(meta["nodes"], list(NODES if dual else NODES[:2]))
                for source, raw in before.items():
                    self.assertEqual(source.read_bytes(), raw)

    def test_unknown_existing_working_directory_never_adopted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "important").write_text("keep", "utf-8")
            with self.assertRaises((ValueError, FileNotFoundError)):
                daily.working_directory(root)
            self.assertEqual((root / "important").read_text(), "keep")

    def test_bundle_profile_or_certificate_edit_refused(self):
        for target in ("event-quality.yaml", "receiver-ca.pem"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                path, home, *_ = self.build(Path(directory))
                (path.parent / target).write_bytes(b"changed")
                with patch("quality_failover.transport.ssl.create_default_context"), self.assertRaises(ValueError):
                    daily.load_bundle(path, home)

    def test_bundle_controller_secret_injection_or_enabled_flag_refused(self):
        for field, value in (("controller_secret", "attacker-value"), ("control_enabled", True)):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                path, home, *_ = self.build(Path(directory))
                file = path.parent / "client.json"
                config = json.loads(file.read_bytes()); config[field] = value
                file.write_bytes(json.dumps(config).encode())
                with self.assertRaises(ValueError):
                    daily.load_bundle(path, home)

    def test_bundle_path_escape_and_wrong_member_order_refused(self):
        for field, value in (("profile", "../outside"), ("nodes", ["Hysteria2", "Reality"]), ("v", True)):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                path, home, *_ = self.build(Path(directory))
                meta = json.loads(path.read_bytes()); meta[field] = value
                path.write_bytes(json.dumps(meta).encode())
                with self.assertRaises(ValueError):
                    daily.load_bundle(path, home)

    def test_live_secret_is_read_fresh_without_rewriting_saved_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            path, home, *_ = self.build(Path(directory))
            before = (path.parent / "client.json").read_bytes()
            (home / "clash-verge.yaml").write_text("external-controller: 127.0.0.1:19092\nsecret: 'rotated-secret'\n", "utf-8")
            with patch("quality_failover.transport.ssl.create_default_context"):
                _, config = daily.load_bundle(path, home)
            self.assertEqual(config["controller_secret"], "rotated-secret")
            self.assertEqual(config["controller"], "http://127.0.0.1:19092")
            self.assertEqual((path.parent / "client.json").read_bytes(), before)

    def test_regeneration_is_no_clobber_and_old_marker_stays(self):
        with tempfile.TemporaryDirectory() as directory:
            path, home, a, b, info = self.build(Path(directory))
            before = path.read_bytes()
            with patch("quality_failover.transport.ssl.create_default_context"):
                second = daily.prepare_bundle(Path(directory) / "private", a, "event", info, home)
            self.assertNotEqual(path.parent, second.parent)
            self.assertEqual(path.read_bytes(), before)
            self.assertNotEqual(json.loads(path.read_bytes())["marker"], json.loads(second.read_bytes())["marker"])

    def test_error_text_never_echoes_sensitive_exception_payload(self):
        self.assertEqual(daily.error_code(ValueError("synthetic-private-token")), "operation_unavailable")
        self.assertEqual(daily.error_code(OSError("synthetic-private-token")), "operation_unavailable")


class IdentityTests(unittest.TestCase):
    def controller(self):
        return daily.IdentifiedController("http://127.0.0.1:19091", "test-only-secret", MARKER, NODES[:2])

    def test_marker_missing_or_different_never_permits_mutation(self):
        for kind in ("missing", "foreign", "shape", "wrong-type"):
            with self.subTest(kind=kind):
                values = topology()
                if kind == "missing": values.pop(MARKER)
                elif kind == "foreign": values["quality-profile-" + "b" * 32] = values.pop(MARKER)
                elif kind == "shape": values[GROUP]["all"].reverse()
                else: values["Reality"]["type"] = "Direct"
                controller = self.controller()
                with patch.object(controller, "request", side_effect=api(values)) as request:
                    with self.assertRaises(ValueError):
                        controller.select("Hysteria2", daily.DailyOwnership(NODES[:2]))
                    self.assertTrue(all(call.args[0] == "GET" for call in request.call_args_list))

    def test_own_group_only_written_with_matching_loaded_profile(self):
        controller = self.controller(); owner = daily.DailyOwnership(NODES[:2])
        with patch.object(controller, "request", side_effect=api(topology())) as request:
            self.assertTrue(controller.select("Hysteria2", owner))
        self.assertEqual(request.call_args_list[3].args[:2], ("PUT", "/proxies/" + __import__("urllib.parse", fromlist=["quote"]).quote(GROUP, safe="")))
        self.assertEqual(owner.expected, "Hysteria2")

    def test_stop_does_not_clear_another_loaded_profile(self):
        values = topology(); values.pop(MARKER)
        controller = self.controller(); owner = daily.DailyOwnership(NODES[:2]); owner.committed("Hysteria2")
        with patch.object(controller, "request", side_effect=api(values)) as request:
            with self.assertRaises(ValueError):
                controller.restore(owner)
            self.assertTrue(all(call.args[0] == "GET" for call in request.call_args_list))

    def test_manual_outer_choice_kept_even_with_matching_identity(self):
        controller = self.controller()
        values = topology(outer="Reality")
        with patch.object(controller, "request", side_effect=api(values)) as request:
            self.assertFalse(controller.select("Hysteria2", daily.DailyOwnership(NODES[:2])))
            self.assertEqual(request.call_count, 3)


class SessionTests(unittest.TestCase):
    def setup_session(self, root, good=False, outer=GROUP):
        session = daily.Session(root / "bundle.json", "not-read")
        session.runner = Mock()
        runner = session.runner
        runner.config = {"control_enabled": False, "cycle_seconds": .01}
        runner.engine = Engine({name: Policy(4, 8) for name in NODES[:2]})
        runner.owner = daily.DailyOwnership(NODES[:2])
        runner.controller.proxies.return_value = topology(outer=outer)
        if good:
            runner.engine.update(time.monotonic(), {node: (True, Confirmation(12, endpoint_ready=True)) for node in NODES[:2]})
        runner.cycle.side_effect = lambda **kwargs: (session.stop(), {"v": 1, "action": "observe", "paths": runner.engine.summary()})[1]
        return session

    def test_observation_first_never_turns_control_on(self):
        with tempfile.TemporaryDirectory() as directory:
            session = self.setup_session(Path(directory), good=True)
            messages = []; session.loop(messages.append)
            self.assertFalse(session.runner.config["control_enabled"])
            self.assertTrue(session.finished)
            session.runner.controller.select.assert_not_called()

    def test_explicit_enable_requires_fresh_positive_quality_and_outer_optin(self):
        for good, outer, enabled in ((False, GROUP, False), (True, "Reality", False), (True, GROUP, True)):
            with self.subTest(good=good, outer=outer), tempfile.TemporaryDirectory() as directory:
                session = self.setup_session(Path(directory), good=good, outer=outer)
                session.enable(); messages = []; session.loop(messages.append)
                self.assertEqual(session.runner.config["control_enabled"], enabled)
                if not enabled:
                    self.assertIn("control_not_ready" if not good else "manual_choice", [item["action"] for item in messages])

    def test_bounded_initial_confirmation_not_permanent_background_speedtest(self):
        with tempfile.TemporaryDirectory() as directory:
            session = self.setup_session(Path(directory))
            calls = [0]
            def clock():
                calls[0] += 1
                return 0 if calls[0] == 1 else 91
            with patch.object(daily.time, "monotonic", side_effect=clock):
                session.loop(lambda value: None)
            self.assertFalse(session.runner.cycle.call_args.kwargs["confirm"])

    def test_stop_releases_lock_and_reports_restore_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            session = self.setup_session(Path(directory), good=True)
            session.lock.acquire()
            session.runner.close.side_effect = ValueError("restore_unconfirmed")
            messages = []; session.loop(messages.append)
            self.assertFalse(messages[-1]["restore_confirmed"])
            other = daily.WorkerLock(session.lock.path); other.acquire(); other.close()

    def test_suspended_ownership_cannot_report_confirmed_restore(self):
        with tempfile.TemporaryDirectory() as directory:
            session = self.setup_session(Path(directory))
            session.runner.config["control_enabled"] = True
            session.runner.owner.suspended = True
            messages = []; session.loop(messages.append)
            self.assertFalse(messages[-1]["restore_confirmed"])

    def test_failed_start_releases_worker_lock_and_never_controls(self):
        with tempfile.TemporaryDirectory() as directory:
            session = daily.Session(Path(directory) / "bundle.json", "not-read")
            with patch.object(daily, "load_bundle", side_effect=ValueError("live_profile_not_loaded")):
                with self.assertRaises(ValueError): session.start()
            other = daily.WorkerLock(session.lock.path); other.acquire(); other.close()

    def test_concurrent_window_is_refused_and_stop_allows_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "worker.lock"
            one, two = daily.WorkerLock(path), daily.WorkerLock(path)
            one.acquire()
            with self.assertRaises(ValueError): two.acquire()
            one.close(); two.acquire(); two.close()

    def test_last_state_records_only_closed_progress_without_controller_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            session = self.setup_session(root, good=True)
            session.enable(); session.loop(lambda value: None)
            state = json.loads((root / "state.json").read_bytes())
            self.assertTrue(state["quality_confirmed_both"])
            self.assertTrue(state["control_enabled_once"])
            self.assertTrue(state["stopped"])
            self.assertTrue(state["last"]["restore_confirmed"])
            self.assertNotIn("controller_secret", (root / "state.json").read_text())
            self.assertEqual(list(root.glob(".quality-state-*")), [])

    def test_receipt_failure_stops_session_and_still_restores(self):
        with tempfile.TemporaryDirectory() as directory:
            session = self.setup_session(Path(directory), good=True)
            messages = []
            with patch.object(daily, "write_state", side_effect=OSError("private-token-never-echoed")):
                session.loop(messages.append)
            self.assertTrue(session.stop_event.is_set())
            session.runner.close.assert_called_once()
            self.assertIn("record_unavailable", [row["action"] for row in messages])
            self.assertNotIn("private-token-never-echoed", json.dumps(messages))


class RoutingTests(unittest.TestCase):
    def controller(self):
        return daily.IdentifiedController("http://127.0.0.1:19091", "test-only-secret", MARKER, NODES[:2])

    def test_global_quality_selection_ignores_unused_rule_pin_and_only_writes_quality(self):
        values = topology(outer="Hysteria2")
        before = copy.deepcopy(values)
        controller = self.controller()
        with patch.object(controller, "request", side_effect=api(values, "global")) as request:
            self.assertTrue(controller.select("Hysteria2", daily.DailyOwnership(NODES[:2])))
            writes = [call for call in request.call_args_list if call.args[0] != "GET"]
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0].args[0], "PUT")
        self.assertNotIn("GLOBAL", writes[0].args[1])
        self.assertEqual(values, before)

    def test_global_manual_pin_blocks_even_if_rule_outer_still_quality(self):
        values = topology(); values["GLOBAL"]["now"] = "Hysteria2"
        controller = self.controller()
        with patch.object(controller, "request", side_effect=api(values, "global")) as request:
            self.assertFalse(controller.select("Reality", daily.DailyOwnership(NODES[:2])))
            self.assertTrue(all(call.args[0] == "GET" for call in request.call_args_list))

    def test_direct_and_unknown_modes_never_inherit_remembered_quality_selection(self):
        for mode in ("direct", "unknown", None, True):
            with self.subTest(mode=mode):
                controller = self.controller()
                with patch.object(controller, "request", side_effect=api(topology(), mode)) as request:
                    if mode == "direct":
                        self.assertFalse(controller.select("Reality", daily.DailyOwnership(NODES[:2])))
                    else:
                        with self.assertRaises(ValueError): controller.select("Reality", daily.DailyOwnership(NODES[:2]))
                    self.assertTrue(all(call.args[0] == "GET" for call in request.call_args_list))

    def test_rule_mode_uses_outer_not_global(self):
        values = topology(outer="Reality")
        controller = self.controller()
        with patch.object(controller, "request", side_effect=api(values)) as request:
            self.assertFalse(controller.select("Hysteria2", daily.DailyOwnership(NODES[:2])))
            self.assertTrue(all(call.args[0] == "GET" for call in request.call_args_list))

    def test_mode_change_during_snapshot_refuses_mutation(self):
        controller = self.controller()
        with patch.object(controller, "request", side_effect=[{"mode":"global"}, {"proxies":dict(topology())}, {"mode":"rule"}]) as request:
            with self.assertRaisesRegex(ValueError, "routing_mode_changed"):
                controller.select("Hysteria2", daily.DailyOwnership(NODES[:2]))
            self.assertTrue(all(call.args[0] == "GET" for call in request.call_args_list))

    def test_missing_routing_context_is_not_optin(self):
        owner = daily.DailyOwnership(NODES[:2])
        self.assertFalse(owner.permitted(dict(topology())))
        self.assertFalse(owner.suspended)

    def test_global_manual_override_still_restores_only_owned_quality_pin(self):
        values = topology(outer="Reality")
        values["GLOBAL"]["now"] = "Reality"
        values[GROUP]["fixed"] = "Hysteria2"
        controller = self.controller(); owner = daily.DailyOwnership(NODES[:2]); owner.committed("Hysteria2")
        with patch.object(controller, "request", side_effect=api(values, "global")) as request:
            controller.restore(owner)
            writes = [call for call in request.call_args_list if call.args[0] != "GET"]
        self.assertEqual([call.args[0] for call in writes], ["DELETE"])
        self.assertNotIn("GLOBAL", writes[0].args[1])

    def test_session_enable_uses_global_quality_choice_with_unused_rule_pin(self):
        with tempfile.TemporaryDirectory() as directory:
            session = SessionTests().setup_session(Path(directory), good=True, outer="Hysteria2")
            values = topology(outer="Hysteria2"); values.routing_mode = "global"
            session.runner.controller.proxies.return_value = values
            session.runner.controller.last_routing_mode = "global"
            session.enable(); messages = []; session.loop(messages.append)
            self.assertTrue(session.runner.config["control_enabled"])
            self.assertEqual(messages[-1]["routing_mode"], "global")
            self.assertEqual(json.loads((Path(directory) / "state.json").read_bytes())["last"]["routing_mode"], "global")


if __name__ == "__main__":
    unittest.main(verbosity=2)
