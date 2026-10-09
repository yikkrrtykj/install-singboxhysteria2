#!/usr/bin/env python3
"""Opt-in real-core API/identity smoke check; synthetic nodes, no live Clash or Internet."""
import argparse
import importlib.util
import json
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from quality_failover.daily import IdentifiedController, prepare_bundle
from quality_failover.pilot import isolated_profile, module, pinned_binary, tcp_port
from quality_failover.policy import GROUP, OUTER, NODES, Ownership


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mihomo", required=True)
    parser.add_argument("--expect-sha256", required=True)
    args = parser.parse_args()
    binary = pinned_binary(args.mihomo, args.expect_sha256)
    spec = importlib.util.spec_from_file_location("daily_lab_fixture", ROOT / "tests/test_quality_failover.py")
    fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)
    process = None
    with tempfile.TemporaryDirectory(prefix="p48-daily-api-") as directory:
        root = Path(directory).resolve()
        if root.parent != Path(tempfile.gettempdir()).resolve() or not root.name.startswith("p48-daily-api-"):
            raise ValueError("lab_directory")
        home = root / "clash"; home.mkdir()
        (home / "clash-verge.yaml").write_text("external-controller: 127.0.0.1:19099\nsecret: 'lab-only-secret'\n", "utf-8")
        source = root / "event-mihomo.yaml"; fixture.export(source)
        (root / "receiver-ca.pem").write_bytes(b"synthetic-not-a-TLS-test")
        info = root / "receiver-info.json"; info.write_bytes(b'{"v":1}')
        # This checks the real kernel API shape/ownership, not TLS or throughput.
        with patch("quality_failover.daily.receiver_info", return_value={"endpoint": "https://127.0.0.1:19443", "token": "a" * 32}), \
             patch("quality_failover.transport.ssl.create_default_context"):
            bundle = prepare_bundle(root / "private", source, "event", info, home)
        meta = json.loads(bundle.read_bytes())
        prepared = (bundle.parent / meta["profile"]).read_text("utf-8")
        merge = module("mihomo-multi-vps-merge.py", "daily_lab_merge")
        profile = merge.parse_export(source, lambda: ValueError("canonical"))
        port, mixed, secret = tcp_port(), tcp_port(), secrets.token_hex(16)
        wires = [SimpleNamespace(port=tcp_port(), port_range=(20000, 20001)) for _ in NODES[:2]]
        text = isolated_profile(profile, prepared, wires, port, mixed, secret)
        # Both fake nodes end at closed loopback ports. No DNS/geodb/remote requests.
        text = text.replace("https://www.gstatic.com/generate_204", "http://127.0.0.1:1/health")
        config = root / "isolated.yaml"; config.write_text(text, "utf-8")
        try:
            subprocess.run([str(binary), "-t", "-d", str(root), "-f", str(config)], check=True,
                           timeout=15, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            process = subprocess.Popen([str(binary), "-d", str(root), "-f", str(config)],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            controller = IdentifiedController("http://127.0.0.1:%d" % port, secret, meta["marker"], NODES[:2])
            deadline = time.monotonic() + 10
            while True:
                try:
                    before = controller.proxies()
                    break
                except OSError:
                    if time.monotonic() > deadline:
                        raise
                    time.sleep(.05)
            assert before[GROUP]["fixed"] == ""
            foreign = IdentifiedController("http://127.0.0.1:%d" % port, secret,
                                           "quality-profile-" + "b" * 32, NODES[:2])
            try:
                foreign.select("Hysteria2", Ownership(NODES[:2]))
                raise AssertionError("foreign_marker_wrote")
            except ValueError:
                pass
            assert controller.proxies()[GROUP]["fixed"] == ""
            # This PUT simulates the operator's choice, only in this disposable core.
            from urllib.parse import quote
            controller.request("PUT", "/proxies/" + quote(OUTER, safe=""), {"name": GROUP})
            owner = Ownership(NODES[:2])
            assert controller.select("Hysteria2", owner)
            controller.restore(owner)
            after = controller.proxies()
            assert after[GROUP]["fixed"] == ""
            assert after[OUTER]["now"] == GROUP
            assert after["自动选择"]["fixed"] == before["自动选择"]["fixed"]
            print("lab: PASS real-core marker, foreign-profile refusal, dedicated selection and restore; no live Clash touched")
        finally:
            if process is not None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait(timeout=5)


if __name__ == "__main__":
    main()
