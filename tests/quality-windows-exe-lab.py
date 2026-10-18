"""Accept the final frozen EXE, not source mocks, using disposable loopback fixtures."""
import argparse
from contextlib import ExitStack
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from quality_failover.pilot import receiver_init
from quality_windows_lab import ChildWindow, LoopbackController, SocksServer, TrackedReceiver, serve, until

spec = importlib.util.spec_from_file_location("exe_export_fixture", ROOT / "tests/test_quality_failover.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def verify_checkout(expected_commit):
    """Reject old receipts even when their two dynamic scripts are unchanged."""
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if expected_commit != head:
        raise ValueError("build receipt source_commit does not match checkout HEAD")
    dirty = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"],
                                    cwd=ROOT, text=True)
    if dirty:
        raise ValueError("acceptance requires a clean tracked checkout")


def manifest(recipient):
    files = ("synthetic-mihomo.yaml", "receiver-info.json", "receiver-ca.pem")
    value = {"v": 1, "client": "synthetic", "files": {name: digest(recipient / name) for name in files}}
    (recipient / "quality-package.json").write_text(json.dumps(value), encoding="utf-8")


def isolated_environment(root):
    environment = {key: value for key, value in os.environ.items()
                   if key.upper() not in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV", "PATH", "APPDATA", "LOCALAPPDATA")}
    environment["PATH"] = str(Path(os.environ["SystemRoot"]) / "System32")
    for variable in ("APPDATA", "LOCALAPPDATA"):
        path = root / variable
        path.mkdir()
        environment[variable] = str(path)
    return environment


def check(app, root, environment, expected_source, label, valid=True):
    report = root / (label + ".json")
    result = subprocess.run([str(app), "--self-check", str(report)], env=environment,
                            cwd=root, timeout=45, creationflags=0x08000000)
    observed = json.loads(report.read_text(encoding="utf-8"))
    if valid:
        assert result.returncode == 0, observed
        assert observed == {"v": 1, "portable_package_valid": True, "tk_available": True,
                            "frozen": True, "controller_contacted": False,
                            "source_commit": expected_source["source_commit"],
                            "bundled_data_sha256": expected_source["bundled_data_sha256"]}, observed
    else:
        assert result.returncode == 2, observed
        assert observed == {"v": 1, "portable_package_valid": False, "controller_contacted": False,
                            "phase": "adjacent_inputs", "failure_class": "ValueError"}, observed


def end_summary(path):
    """Whitelist before including a private worker receipt in public test results."""
    value = json.loads(Path(path).read_bytes())
    assert set(value) == {"v", "session_id", "started_epoch", "ended_epoch", "reason",
                          "record_failed", "record_error", "restore_confirmed"}
    assert value["v"] == 1 and re.fullmatch(r"[0-9a-f]{32}", value["session_id"])
    assert value["reason"] in ("requested", "record_unavailable", "loop_exception", "stop_signal")
    assert type(value["record_failed"]) is bool and type(value["restore_confirmed"]) is bool
    assert all(type(value[key]) in (int, float) for key in ("started_epoch", "ended_epoch"))
    error = value["record_error"]
    if error is not None:
        assert type(error) is dict and set(error) <= {"kind", "errno", "winerror"}
        assert error["kind"] in ("PermissionError", "OSError", "state_write_failed")
        assert all(type(item) is int and 0 <= item <= 65535 for key, item in error.items() if key != "kind")
    return value


def lifecycle_failure(timeline, process_exit_before_cleanup):
    """Distinguish protocol failback, worker restore and GUI process exit."""
    switched, stop_requested, close_requested, fault = False, False, False, False
    for event in timeline:
        kind = event["kind"]
        if kind == "alternate_selected": switched = True
        elif kind == "stop_requested": stop_requested = True
        elif kind == "close_requested": close_requested = True
        elif kind == "state_write_fault_injected": fault = True
        elif kind == "controller_write" and switched and not stop_requested:
            if event["method"] == "PUT" and event["name"] == "Reality":
                return "protocol_failback_before_stop"
            if event["method"] == "DELETE" and not fault:
                return "worker_restored_before_stop"
    if process_exit_before_cleanup is not None and not close_requested:
        return "gui_exited_before_close"
    return None


def gui(app, root, environment, controller, sink, hopping, full_recovery, record_fault=False):
    home = Path(environment["APPDATA"]) / "io.github.clash-verge-rev.clash-verge-rev"
    home.mkdir()
    settings = home / "clash-verge.yaml"
    settings.write_text('external-controller: "127.0.0.1:%d"\nsecret: "%s"\n' % (
        controller.server_port, controller.secret), encoding="utf-8")
    settings_digest = digest(settings)
    source_digest = digest(app.parent / "synthetic-mihomo.yaml")
    process = subprocess.Popen([str(app)], env=environment, cwd=root, creationflags=0x08000000)
    controller.event("process_started")
    window = ChildWindow(process)
    bundle, failed = None, False
    with ExitStack() as stack:
        try:
            until(lambda: len(window.children()) > 10, label="actual GUI opens")
            work = Path(environment["LOCALAPPDATA"]) / "ClashQualitySwitch"
            assert not list(work.glob("*/bundle-*/bundle.json"))
            assert controller.writes == []
            controller.event("prepare_requested")
            window.click("start")
            bundle = until(lambda: next(work.glob("*/bundle-*/bundle.json"), None), label="EXE generates bundle")
            meta = json.loads(bundle.read_text(encoding="utf-8"))
            generated = bundle.parent / meta["profile"]
            text = generated.read_text(encoding="utf-8")
            assert not re.search(r"^\s+(?:up|down|up_mbps|down_mbps):", text, re.M)
            assert ('    ports: 40000-40100' in text) == hopping
            assert ('    hop-interval: 30' in text) == hopping
            assert 'uuid: 11111111-1111-4111-8111-111111111111' in text
            assert 'password: synthetic-primary-password' in text
            assert 'sni: www.example.com' in text
            assert 'MATCH,质量自动选择' in text
            assert digest(generated) == meta["profile_sha256"]
            controller.marker = meta["marker"]
            config = json.loads((bundle.parent / "client.json").read_text(encoding="utf-8"))
            servers = []
            for entry in config["paths"]:
                server = serve(SocksServer(entry["listener_port"], entry["name"], controller, sink))
                servers.append(server)
                stack.callback(server.server_close)
                stack.callback(server.shutdown)
            time.sleep(.5)
            assert controller.writes == []
            controller.event("control_requested")
            window.click("start")
            until(lambda: controller.fixed == "Reality", seconds=40, label="confirmed uploads enable control")
            assert all(sink.confirmed(node, controller.started) for node in ("Reality", "Hysteria2"))
            assert all(server.upload_connections >= 2 for server in servers)
            assert sink.minute_used >= 2 * 524288
            controller.event("primary_failure_injected")
            controller.reachable["Reality"] = False
            # A transient telemetry failure invalidates quality evidence. Allow
            # the normal 30-second probe budget/cadence to reconfirm the alternate
            # instead of imposing a shorter, unsupported 15-second test SLA.
            switch_wait = config["probe_interval_seconds"] + 3 * config["cycle_seconds"]
            until(lambda: controller.fixed == "Hysteria2", seconds=switch_wait, label="actual EXE switches protocol")
            selected_at = time.monotonic()
            controller.event("alternate_selected")
            controller.reachable["Reality"] = True
            recovered_at = time.monotonic()
            controller.event("primary_reachability_restored")
            def retained():
                assert process.poll() is None, "GUI process exited before close request"
                assert controller.fixed == "Hysteria2", "healthy alternate displaced before stop request"
            if full_recovery:
                policy = config["paths"][0]["policy"]
                def recovery_confirmed():
                    retained()
                    rows = sink.uploads("Reality", recovered_at)
                    return (sink.confirmed("Reality", recovered_at, policy["recover_mbps"], policy["recover_samples"])
                            and rows[-1]["at"] >= selected_at + policy["hold_seconds"])
                until(recovery_confirmed, seconds=155, label="real 120-second hold and confirmed recovery uploads")
                controller.event("recovery_hold_complete")
            elif not record_fault:
                observations = controller.observations
                def steady():
                    retained()
                    return controller.observations >= observations + 2 and time.monotonic() >= recovered_at + 10
                until(steady,
                      seconds=20, label="healthy choice remains sticky across observation cycles")
            assert controller.fixed == "Hysteria2"
            if record_fault:
                # Intentional negative test only: a normal Python reader on
                # Windows denies replacement. Never used by healthy observers.
                def lock_state():
                    try:
                        return (bundle.parent / "state.json").open("rb")
                    except (FileNotFoundError, PermissionError):
                        return None
                with until(lock_state, seconds=5, label="inject status replacement lock"):
                    controller.event("state_write_fault_injected")
                    until(lambda: controller.fixed == "", seconds=15, label="failed state write safely restores group")
                    until(lambda: (bundle.parent / "session-end.json").is_file(), label="independent termination receipt")
                assert process.poll() is None, "worker failure must not be reported as GUI process exit"
                controller.event("worker_restored_with_gui_alive")
            else:
                controller.event("stop_requested")
                window.click("stop")
                until(lambda: controller.fixed == "" and controller.writes[-1:] == [("DELETE", "")], label="GUI stop restores group")
            assert controller.fixed == ""
            assert controller.writes == [("PUT", "Reality"), ("PUT", "Hysteria2"), ("DELETE", "")], controller.writes
            assert not controller.unexpected, controller.unexpected
            assert digest(settings) == settings_digest
            assert digest(app.parent / "synthetic-mihomo.yaml") == source_digest
            controller.event("close_requested")
            window.click("close")
            assert process.wait(timeout=15) == 0
            controller.event("process_exited", exit_code=process.returncode)
            # The writer has exited; reading its final receipt cannot interfere.
            final_state = json.loads((bundle.parent / "state.json").read_text(encoding="utf-8"))
            end = end_summary(bundle.parent / "session-end.json")
            assert end["session_id"] == final_state["session_id"] and end["restore_confirmed"] is True
            if record_fault:
                assert end["reason"] == "record_unavailable" and end["record_failed"] is True
                assert end["record_error"]["kind"] == "PermissionError"
                assert end["record_error"].get("winerror") in (5, 32)
                assert not any(event["kind"] == "stop_requested" for event in controller.timeline)
            else:
                assert final_state["stopped"] and final_state["last"]["restore_confirmed"] is True
                assert end["reason"] == "requested" and end["record_failed"] is False and end["record_error"] is None
            assert lifecycle_failure(controller.timeline, process.returncode) is None
        except Exception as error:
            failed = True
            # Do not poll state.json: a Windows observer can block its writer.
            # Observe actual API mutations/authenticated receipts, never credentials.
            diagnostic = {"lab_failure": True, "process_exit_before_cleanup": process.poll(),
                "observations": controller.observations,
                "confirmed_receipts": {node: len(sink.uploads(node, controller.started)) for node in ("Reality", "Hysteria2")},
                "mock_fixed": controller.fixed, "mock_writes": controller.writes,
                "mock_reachable": controller.reachable, "unexpected_requests": controller.unexpected,
                "timeline": controller.timeline}
            error.lab_diagnostics = diagnostic
            raise
        finally:
            if process.poll() is None:
                controller.event("test_cleanup_forced_kill")
                subprocess.run(["taskkill.exe", "/PID", str(process.pid), "/T", "/F"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=0x08000000)
                process.wait(timeout=15)
            if failed and bundle is not None:
                # Post-exit only. Never dump inputs, connection files or tokens.
                try:
                    state = json.loads((bundle.parent / "state.json").read_text(encoding="utf-8"))
                    last = state.get("last", {})
                    diagnostic["post_exit_state"] = {"cycles": state.get("cycles"),
                        "stopped": state.get("stopped"), "last": {key: last[key] for key in (
                            "action", "mode", "paths", "restore_confirmed", "owned_selection") if key in last}}
                except (OSError, ValueError) as error:
                    diagnostic["post_exit_state_unavailable"] = type(error).__name__
                try:
                    diagnostic["worker_end"] = end_summary(bundle.parent / "session-end.json")
                except (OSError, ValueError, AssertionError):
                    diagnostic["worker_end_unavailable"] = True
            if failed:
                diagnostic["process_exit_after_cleanup"] = process.returncode
                diagnostic["lifecycle_failure"] = lifecycle_failure(controller.timeline, diagnostic["process_exit_before_cleanup"])
                print(json.dumps(diagnostic), flush=True)
    return {"generated_without_bandwidth": True, "gui_start_stop": True, "real_tls_upload": True,
            "protocol_switch": True, "healthy_current_retained": not record_fault, "full_recovery_hold": full_recovery,
            "intentional_state_write_fault": record_fault, "worker_end": end, "process_exit": process.returncode,
            "timeline": controller.timeline}


def accept(exe, build_receipt, recovery_repetitions=1):
    if type(recovery_repetitions) is not int or not 1 <= recovery_repetitions <= 3:
        raise ValueError("recovery repetitions must be bounded to 1..3")
    exe = Path(exe).resolve()
    expected_source = json.loads(Path(build_receipt).read_text(encoding="utf-8"))
    verify_checkout(expected_source["source_commit"])
    assert expected_source["configuration_embedded"] is False
    for name, value in expected_source["bundled_data_sha256"].items():
        assert digest(ROOT / "tools" / name) == value, "receipt does not match test checkout"
    results = []
    with tempfile.TemporaryDirectory(prefix="quality-exe-acceptance-") as temporary, ExitStack() as stack:
        root = Path(temporary)
        sink = TrackedReceiver()
        stack.callback(sink.server_close)
        receiver_init(root / "sink", "127.0.0.1", sink.server_port, os.environ.get("P48_TEST_OPENSSL", "openssl"))
        info_file = root / "sink/receiver-info.json"
        sink.token = json.loads(info_file.read_text())["token"]
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(root / "sink/receiver-ca.pem", root / "sink/receiver-key.pem")
        sink.context = context
        serve(sink)
        stack.callback(sink.shutdown)
        cases = [(legacy, hopping, legacy and hopping, False,
                  ("legacy" if legacy else "bbr") + ("-hopping" if hopping else "-single"))
                 for legacy in (False, True) for hopping in (False, True)]
        cases += [(True, True, True, False, "recovery-repeat-%d" % index)
                  for index in range(2, recovery_repetitions + 1)]
        cases += [(True, True, False, True, "intentional-state-write-failure")]
        for legacy, hopping, full_recovery, record_fault, name in cases:
            case = root / name
            case.mkdir()
            environment = isolated_environment(case)
            staged = case / "staging"
            staged.mkdir()
            shutil.copyfile(exe, staged / "质量切换.exe")
            fixture.export(staged / "synthetic-mihomo.yaml", hopping=hopping, legacy_bandwidth=legacy)
            for filename in ("receiver-info.json", "receiver-ca.pem"):
                shutil.copyfile(root / "sink" / filename, staged / filename)
            manifest(staged)
            archive = case / "synthetic-only.zip"
            with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zipped:
                for path in staged.iterdir():
                    zipped.write(path, path.name)
            recipient = case / "同事电脑 完整解压包"
            with zipfile.ZipFile(archive) as zipped:
                zipped.extractall(recipient)
            app = recipient / "质量切换.exe"
            check(app, case, environment, expected_source, "valid")
            controller = serve(LoopbackController(sink))
            try:
                facts = gui(app, case, environment, controller, sink, hopping,
                            full_recovery=full_recovery, record_fault=record_fault)
            finally:
                controller.shutdown()
                controller.server_close()
            results.append(dict(case=name, portable_package_valid=True, **facts))
            print("[PASS] frozen EXE: " + name + " import, upload, switch, worker/process lifecycle verified", flush=True)
            assert not (recipient / "receiver-key.pem").exists()
        yaml = recipient / "synthetic-mihomo.yaml"
        fixture.export(yaml, legacy_bandwidth=True)
        original = yaml.read_text(encoding="utf-8")
        pair = '    up: "300 Mbps"\n    down: "300 Mbps"\n'
        # Windows write_text would introduce CRLF. The strict parser rejects
        # CR before it examines any bandwidth fields, masking every case below.
        # Prove the same LF-only write/manifest pipeline accepts an unmodified
        # canonical export before relying on its malformed-field refusals.
        yaml.write_bytes(original.encode("utf-8"))
        manifest(recipient)
        check(app, root, environment, expected_source, "negative-control-valid")
        invalid = {
            "partial-up": original.replace('    down: "300 Mbps"\n', ''),
            "partial-down": original.replace('    up: "300 Mbps"\n', ''),
            "custom": original.replace('300 Mbps', '200 Mbps'),
            "numeric": original.replace('"300 Mbps"', '300'),
            "zero": original.replace('"300 Mbps"', '0'),
            "null": original.replace('"300 Mbps"', 'null'),
            "duplicate-up": original.replace(pair, '    up: "300 Mbps"\n' + pair),
            "duplicate-down": original.replace(pair, pair + '    down: "300 Mbps"\n'),
            "malformed-yaml": original.replace('    sni: www.example.com', '    sni: [unterminated'),
            "duplicate-password": original.replace('    password: synthetic-primary-password',
                '    password: synthetic-primary-password\n    password: second-password'),
            "wrong-provenance": original.replace('  - name: Hysteria2', '  - name: Renamed'),
        }
        for label, raw in invalid.items():
            yaml.write_bytes(raw.encode("utf-8"))
            assert b"\r" not in yaml.read_bytes(), "field test masked by noncanonical line endings"
            manifest(recipient)
            check(app, root, environment, expected_source, label, valid=False)
        yaml.write_bytes(original.encode("utf-8"))
        manifest(recipient)
        yaml.write_bytes(yaml.read_bytes() + b"# changed without a new manifest\n")
        check(app, root, environment, expected_source, "stale-digest", valid=False)
        print("[PASS] frozen EXE: 11 malformed/provenance cases and stale package digest refused", flush=True)
    verify_checkout(expected_source["source_commit"])
    return {"v": 1, "acceptance_passed": True, "exe_sha256": digest(exe), "source_commit": expected_source["source_commit"],
            "bundled_data_sha256": expected_source["bundled_data_sha256"], "cases": results,
            "negative_cases": len(invalid) + 1, "negative_control_valid": True, "checkout_verified": True,
            "observation": "controller_mutations_and_authenticated_upload_receipts",
            "full_recovery_repetitions": recovery_repetitions,
            "windows_only_path": True, "production_contacted": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", required=True)
    parser.add_argument("--build-receipt", required=True)
    parser.add_argument("--report")
    parser.add_argument("--recovery-repetitions", type=int, choices=(1, 2, 3), default=1)
    args = parser.parse_args()
    try:
        result = accept(args.exe, args.build_receipt, args.recovery_repetitions)
    except Exception as error:
        if args.report:
            with Path(args.report).open("x", encoding="utf-8") as stream:
                json.dump({"v": 1, "acceptance_passed": False, "failure_class": type(error).__name__,
                           "diagnostic": getattr(error, "lab_diagnostics", None), "production_contacted": False}, stream, indent=2)
        raise
    if args.report:
        with Path(args.report).open("x", encoding="utf-8") as stream:
            json.dump(result, stream, indent=2)
    print(json.dumps(result))
