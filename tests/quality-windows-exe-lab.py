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


def gui(app, root, environment, controller, sink, hopping, full_recovery):
    home = Path(environment["APPDATA"]) / "io.github.clash-verge-rev.clash-verge-rev"
    home.mkdir()
    settings = home / "clash-verge.yaml"
    settings.write_text('external-controller: "127.0.0.1:%d"\nsecret: "%s"\n' % (
        controller.server_port, controller.secret), encoding="utf-8")
    settings_digest = digest(settings)
    source_digest = digest(app.parent / "synthetic-mihomo.yaml")
    process = subprocess.Popen([str(app)], env=environment, cwd=root, creationflags=0x08000000)
    window = ChildWindow(process)
    bundle = None
    with ExitStack() as stack:
        try:
            until(lambda: len(window.children()) > 10, label="actual GUI opens")
            work = Path(environment["LOCALAPPDATA"]) / "ClashQualitySwitch"
            assert not list(work.glob("*/bundle-*/bundle.json"))
            assert controller.writes == []
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
            window.click("start")
            until(lambda: controller.fixed == "Reality", seconds=40, label="confirmed uploads enable control")
            assert all(sink.confirmed(node, controller.started) for node in ("Reality", "Hysteria2"))
            assert all(server.upload_connections >= 2 for server in servers)
            assert sink.minute_used >= 2 * 524288
            controller.reachable["Reality"] = False
            # A transient telemetry failure invalidates quality evidence. Allow
            # the normal 30-second probe budget/cadence to reconfirm the alternate
            # instead of imposing a shorter, unsupported 15-second test SLA.
            switch_wait = config["probe_interval_seconds"] + 3 * config["cycle_seconds"]
            until(lambda: controller.fixed == "Hysteria2", seconds=switch_wait, label="actual EXE switches protocol")
            selected_at = time.monotonic()
            controller.reachable["Reality"] = True
            recovered_at = time.monotonic()
            if full_recovery:
                policy = config["paths"][0]["policy"]
                def recovery_confirmed():
                    assert controller.fixed == "Hysteria2", "healthy alternate displaced during recovery"
                    rows = sink.uploads("Reality", recovered_at)
                    return (sink.confirmed("Reality", recovered_at, policy["recover_mbps"], policy["recover_samples"])
                            and rows[-1]["at"] >= selected_at + policy["hold_seconds"])
                until(recovery_confirmed, seconds=155, label="real 120-second hold and confirmed recovery uploads")
            else:
                observations = controller.observations
                until(lambda: controller.observations >= observations + 2 and time.monotonic() >= recovered_at + 10,
                      seconds=20, label="healthy choice remains sticky across observation cycles")
            assert controller.fixed == "Hysteria2"
            window.click("stop")
            until(lambda: controller.fixed == "" and controller.writes[-1:] == [("DELETE", "")], label="GUI stop restores group")
            assert controller.fixed == ""
            assert controller.writes == [("PUT", "Reality"), ("PUT", "Hysteria2"), ("DELETE", "")], controller.writes
            assert not controller.unexpected, controller.unexpected
            assert digest(settings) == settings_digest
            assert digest(app.parent / "synthetic-mihomo.yaml") == source_digest
            window.click("close")
            assert process.wait(timeout=15) == 0
        except Exception:
            # Do not poll state.json: a Windows observer can block its writer.
            # Observe actual API mutations/authenticated receipts, never credentials.
            print(json.dumps({"lab_failure": True, "process_exit": process.poll(),
                "observations": controller.observations,
                "confirmed_receipts": {node: len(sink.uploads(node, controller.started)) for node in ("Reality", "Hysteria2")},
                "mock_fixed": controller.fixed, "mock_writes": controller.writes,
                "mock_reachable": controller.reachable, "unexpected_requests": controller.unexpected}), flush=True)
            raise
        finally:
            if process.poll() is None:
                subprocess.run(["taskkill.exe", "/PID", str(process.pid), "/T", "/F"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=0x08000000)
                process.wait(timeout=15)
    return {"generated_without_bandwidth": True, "gui_start_stop": True, "real_tls_upload": True,
            "protocol_switch": True, "healthy_current_retained": True, "full_recovery_hold": full_recovery}


def accept(exe, build_receipt):
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
        for legacy in (False, True):
            for hopping in (False, True):
                name = ("legacy" if legacy else "bbr") + ("-hopping" if hopping else "-single")
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
                                full_recovery=legacy and hopping)
                finally:
                    controller.shutdown()
                    controller.server_close()
                results.append(dict(case=name, portable_package_valid=True, **facts))
                print("[PASS] frozen EXE: " + name + " import, generation, GUI, TLS upload, switch, sticky selection, stop", flush=True)
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
    return {"v": 1, "exe_sha256": digest(exe), "source_commit": expected_source["source_commit"],
            "bundled_data_sha256": expected_source["bundled_data_sha256"], "cases": results,
            "negative_cases": len(invalid) + 1, "negative_control_valid": True, "checkout_verified": True,
            "observation": "controller_mutations_and_authenticated_upload_receipts",
            "windows_only_path": True, "production_contacted": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", required=True)
    parser.add_argument("--build-receipt", required=True)
    parser.add_argument("--report")
    args = parser.parse_args()
    result = accept(args.exe, args.build_receipt)
    if args.report:
        with Path(args.report).open("x", encoding="utf-8") as stream:
            json.dump(result, stream, indent=2)
    print(json.dumps(result))
