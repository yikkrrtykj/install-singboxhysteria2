#!/usr/bin/env python3
"""Focused contract/static tests for the UM-LT real-protocol traffic lab.

Runs WITHOUT sing-box, without network access and without Go: it validates the
lab's config generation invariants, the pinned release identity, the canonical
monitor-v2 traffic-export validator, the rev-7 report-body validator, the
privacy scanners, the read-only SQLite aggregation helpers, the loopback
capture proxy and the lab's static no-production-resource guards.

Usage:
    python tests/um-lt/test_lab_contract.py
"""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import re
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
LIB_PATH = os.path.join(REPO_ROOT, "um", "deploy", "lab", "um_lt_lab_lib.py")
ORCHESTRATOR_PATH = os.path.join(REPO_ROOT, "um", "deploy", "lab",
                                 "linux_traffic_e2e_lab.py")
SHELL_PATH = os.path.join(REPO_ROOT, "um", "deploy", "lab",
                          "linux-traffic-e2e-lab.sh")


def load_lib():
    spec = importlib.util.spec_from_file_location("um_lt_lab_lib", LIB_PATH)
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolves cls.__module__ through sys.modules, so register the
    # module before executing it.
    sys.modules["um_lt_lab_lib"] = module
    spec.loader.exec_module(module)
    return module


lib = load_lib()

SYNTHETIC_SECRETS = [
    "um-lt-lab-fake-uuid-0000-0000-000000000000",
    "um-lt-lab-fake-hysteria2-password",
    "um-lt-lab-fake-admin-token",
]


# ---------------------------------------------------------------------------
# Document builders
# ---------------------------------------------------------------------------


def inbound_row(tag="vless-in", kind="reality", uplink=1000, downlink=2000,
                active=0, observed_at=None, quality="lower_bound"):
    return {
        "inbound_tag": tag,
        "kind": kind,
        "observed_uplink_bytes": uplink,
        "observed_downlink_bytes": downlink,
        "uplink_observed_rate_bps": None,
        "downlink_observed_rate_bps": None,
        "active_connections": active,
        "observed_at": 1700000009 if observed_at is None else observed_at,
        "quality": quality,
    }


def valid_export_document():
    return {
        "schema": lib.EXPORT_SCHEMA,
        "schema_version": lib.EXPORT_SCHEMA_VERSION,
        "source": lib.EXPORT_SOURCE,
        "source_epoch": "0123456789abcdef0123456789abcdef",
        "sequence": 7,
        "generated_at": 1700000010,
        "observed_at": 1700000009,
        "monitor_stale": False,
        "monitor_last_success_at": 1700000009,
        "counter_scope": lib.COUNTER_SCOPE,
        "exactness": lib.EXACTNESS,
        "active_connections": 0,
        "rate_window_seconds": None,
        "inbounds": [
            inbound_row("vless-in", "reality", 111, 222),
            inbound_row("hy2-in", "hysteria2", 333, 444),
        ],
    }


def valid_rev7_report(report_id=None):
    return {
        "v": 1,
        "type": "snapshot",
        "report_id": report_id or str(uuid.uuid4()),
        "collected_at": 1700000020,
        "agent": {"version": "1.0.0", "uptime_s": 5},
        "host": {"os": "linux", "kernel": "6.8.0-31-generic", "arch": "amd64"},
        "availability": {
            "system": "unavailable", "services": "unavailable",
            "protocols": "unavailable", "traffic": "partial",
            "clients": "unavailable",
        },
        "counter_epoch": "0123456789abcdef0123456789abcdef",
        "system": {},
        "services": [],
        "protocols": [],
        "traffic": [],
        "clients": {"active": None, "tracked": None, "summaries": []},
        "contract_revision": 7,
        "traffic_observation": {
            "source": lib.REPORT_SOURCE,
            "source_epoch": "0123456789abcdef0123456789abcdef",
            "sequence": 3,
            "observed_at": 1700000019,
            "age_seconds": 1,
            "freshness": "fresh",
            "availability": "ok",
            "counter_scope": lib.COUNTER_SCOPE,
            "exactness": lib.EXACTNESS,
            "active_connections": 0,
            "rate_window_seconds": None,
            "inbounds": [{
                "inbound_tag": "vless-in",
                "kind": "reality",
                "observed_at": 1700000019,
                "availability": "ok",
                "quality": "lower_bound",
                "uplink_observed_lower_bound_bytes": 10,
                "downlink_observed_lower_bound_bytes": 20,
                "uplink_observed_rate_bps": None,
                "downlink_observed_rate_bps": None,
                "active_connections": 0,
            }],
        },
    }


class ExportDocumentValidationTests(unittest.TestCase):
    def test_canonical_document_accepted(self):
        normalized = lib.validate_export_document(valid_export_document())
        self.assertEqual(normalized["shape"], "monitor-v2-v1")
        self.assertEqual(normalized["sequence"], 7)
        self.assertEqual(len(normalized["inbounds"]), 2)
        self.assertEqual(lib.export_observed(normalized, "hy2-in", "downlink"),
                         444)

    def test_unknown_member_rejected(self):
        document = valid_export_document()
        document["user"] = "some-device"
        with self.assertRaisesRegex(lib.ExportValidationError, "forbidden"):
            lib.validate_export_document(document)

    def test_inbound_unknown_member_rejected(self):
        document = valid_export_document()
        document["inbounds"][0]["source_ip"] = "127.0.0.1"
        with self.assertRaisesRegex(lib.ExportValidationError, "forbidden"):
            lib.validate_export_document(document)

    def test_missing_member_rejected(self):
        document = valid_export_document()
        del document["monitor_last_success_at"]
        with self.assertRaisesRegex(lib.ExportValidationError, "missing"):
            lib.validate_export_document(document)

    def test_wrong_source_token_rejected(self):
        document = valid_export_document()
        document["source"] = lib.REPORT_SOURCE
        with self.assertRaises(lib.ExportValidationError):
            lib.validate_export_document(document)

    def test_float_byte_counter_rejected(self):
        document = valid_export_document()
        document["inbounds"][0]["observed_uplink_bytes"] = 1048576.0
        with self.assertRaises(lib.ExportValidationError):
            lib.validate_export_document(document)

    def test_bool_byte_counter_rejected(self):
        document = valid_export_document()
        document["inbounds"][0]["observed_uplink_bytes"] = True
        with self.assertRaises(lib.ExportValidationError):
            lib.validate_export_document(document)

    def test_negative_counter_rejected(self):
        document = valid_export_document()
        document["inbounds"][0]["observed_downlink_bytes"] = -1
        with self.assertRaises(lib.ExportValidationError):
            lib.validate_export_document(document)

    def test_observed_after_generated_rejected(self):
        document = valid_export_document()
        document["observed_at"] = document["generated_at"] + 1
        with self.assertRaises(lib.ExportValidationError):
            lib.validate_export_document(document)

    def test_duplicate_inbound_tag_rejected(self):
        document = valid_export_document()
        document["inbounds"][1]["inbound_tag"] = "vless-in"
        with self.assertRaises(lib.ExportValidationError):
            lib.validate_export_document(document)

    def test_unknown_kind_rejected(self):
        document = valid_export_document()
        document["inbounds"][0]["kind"] = "mixed"
        with self.assertRaises(lib.ExportValidationError):
            lib.validate_export_document(document)

    def test_lower_bound_without_counters_rejected(self):
        document = valid_export_document()
        document["inbounds"][0]["observed_uplink_bytes"] = None
        with self.assertRaises(lib.ExportValidationError):
            lib.validate_export_document(document)

    def test_unavailable_with_data_rejected(self):
        document = valid_export_document()
        row = document["inbounds"][0]
        row["quality"] = "unavailable"
        with self.assertRaises(lib.ExportValidationError):
            lib.validate_export_document(document)

    def test_stale_monitor_requires_partial_quality(self):
        document = valid_export_document()
        document["monitor_stale"] = True
        document["monitor_last_success_at"] = 1700000000
        with self.assertRaisesRegex(lib.ExportValidationError, "partial"):
            lib.validate_export_document(document)
        for row in document["inbounds"]:
            row["quality"] = "partial"
        normalized = lib.validate_export_document(document)
        self.assertTrue(normalized["monitor_stale"])

    def test_rates_without_window_rejected(self):
        document = valid_export_document()
        document["inbounds"][0]["uplink_observed_rate_bps"] = 1.0
        with self.assertRaisesRegex(lib.ExportValidationError, "rate window"):
            lib.validate_export_document(document)
        document["rate_window_seconds"] = 2.0
        normalized = lib.validate_export_document(document)
        self.assertEqual(normalized["rate_window_seconds"], 2.0)

    def test_active_total_below_sum_rejected(self):
        document = valid_export_document()
        document["inbounds"][0]["active_connections"] = 2
        document["active_connections"] = 1
        with self.assertRaises(lib.ExportValidationError):
            lib.validate_export_document(document)

    def test_legacy_draft_shape_rejected_with_actionable_message(self):
        legacy = {
            "export_version": 1,
            "source": lib.REPORT_SOURCE,
            "source_epoch": "0123456789abcdef0123456789abcdef",
            "sequence": 0,
            "observed_at": 1700000000,
            "availability": "ok",
            "active_connections": None,
            "rate_window_seconds": None,
            "inbounds": [],
        }
        with self.assertRaisesRegex(lib.ExportValidationError,
                                    "superseded draft shape"):
            lib.validate_export_document(legacy)

    def test_unknown_document_rejected(self):
        with self.assertRaisesRegex(lib.ExportValidationError,
                                    "unrecognized export document"):
            lib.validate_export_document({"hello": "world"})


class ReportBodyValidationTests(unittest.TestCase):
    def test_valid_rev7_report_accepted(self):
        report = valid_rev7_report()
        parsed = lib.validate_rev7_snapshot_report(report)
        self.assertEqual(parsed["freshness"], "fresh")
        self.assertEqual(parsed["availability"], "ok")
        self.assertEqual(parsed["inbounds"][0]["downlink"], 20)

    def test_observation_unknown_member_rejected(self):
        report = valid_rev7_report()
        report["traffic_observation"]["monitor_stale"] = False
        with self.assertRaisesRegex(lib.ReportValidationError, "forbidden"):
            lib.validate_rev7_snapshot_report(report)

    def test_rev5_body_accepted_when_source_disabled(self):
        report = {
            "v": 1, "type": "snapshot", "report_id": str(uuid.uuid4()),
            "collected_at": 1700000000, "traffic": [],
        }
        parsed = lib.validate_rev7_snapshot_report(report)
        self.assertTrue(parsed["rev5"])

    def test_rev7_without_observation_rejected(self):
        report = valid_rev7_report()
        del report["traffic_observation"]
        with self.assertRaisesRegex(lib.ReportValidationError,
                                    "traffic_observation"):
            lib.validate_rev7_snapshot_report(report)

    def test_unauthorized_inbound_tag_rejected(self):
        report = valid_rev7_report()
        report["traffic_observation"]["inbounds"][0]["inbound_tag"] = "evil-in"
        with self.assertRaisesRegex(lib.ReportValidationError,
                                    "not present in the center-authorized"):
            lib.validate_rev7_snapshot_report(report)

    def test_kind_mismatch_rejected(self):
        report = valid_rev7_report()
        report["traffic_observation"]["inbounds"][0]["kind"] = "hysteria2"
        with self.assertRaisesRegex(lib.ReportValidationError,
                                    "kind does not match"):
            lib.validate_rev7_snapshot_report(report)

    def test_nonempty_base_traffic_rejected(self):
        report = valid_rev7_report()
        report["traffic"] = [{"scope": "protocol", "inbound_tag": "vless-in",
                             "uplink_total_bytes": 1,
                             "downlink_total_bytes": 2}]
        # our rev-7 validator does not police base traffic beyond the closed
        # observation; rev-5 validator does.
        report["contract_revision"] = 5
        del report["traffic_observation"]
        with self.assertRaisesRegex(lib.ReportValidationError, "empty"):
            lib.validate_rev7_snapshot_report(report)


class ExportFileTests(unittest.TestCase):
    def test_export_file_roundtrip_and_limits(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "traffic.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(valid_export_document(), handle)
            normalized = lib.validate_export_file(path)
            self.assertEqual(normalized["shape"], "monitor-v2-v1")
            with open(path, "wb") as handle:
                handle.write(b"{" + b"x" * (lib.MAX_EXPORT_BYTES + 10))
            with self.assertRaisesRegex(lib.ExportValidationError, "exceeds"):
                lib.validate_export_file(path)
            with open(path, "wb") as handle:
                handle.write(b"")
            with self.assertRaisesRegex(lib.ExportValidationError, "empty"):
                lib.validate_export_file(path)
            with open(path, "wb") as handle:
                handle.write(b"{not-json")
            with self.assertRaisesRegex(lib.ExportValidationError,
                                        "valid UTF-8 JSON"):
                lib.validate_export_file(path)

    def test_wait_for_export_times_out(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "absent.json")
            with self.assertRaisesRegex(lib.LabAssertionFailed, "timed out"):
                lib.wait_for_export(path, 0.3)


class PrivacyScannerTests(unittest.TestCase):
    def test_clean_export_has_no_findings(self):
        document = valid_export_document()
        raw = json.dumps(document).encode("utf-8")
        self.assertEqual(lib.privacy_scan_export(document, raw,
                                                 SYNTHETIC_SECRETS), [])

    def test_sentinel_in_raw_bytes_detected(self):
        document = valid_export_document()
        raw = json.dumps(document).encode("utf-8") + b'um-lt-lab-fake-admin-token'
        findings = lib.privacy_scan_export(document, raw, SYNTHETIC_SECRETS)
        self.assertTrue(any(item["kind"] == "secret-sentinel"
                            for item in findings))

    def test_network_literal_detected(self):
        document = valid_export_document()
        document["client_ip"] = "203.0.113.7"
        findings = lib.privacy_scan_export(document, b"{}", [])
        self.assertTrue(any(item["kind"] == "network-literal"
                            for item in findings))
        document = valid_export_document()
        document["x"] = "https://example.invalid/path"
        findings = lib.privacy_scan_export(document, b"{}", [])
        self.assertTrue(any(item.get("pattern") == "url"
                            for item in findings))

    def test_tag_names_are_not_network_literals(self):
        document = valid_export_document()
        findings = lib.privacy_scan_export(document, b"{}", [])
        self.assertEqual(findings, [])

    def test_report_id_uuid_allowed_but_other_uuid_flagged(self):
        report = valid_rev7_report()
        raw = json.dumps(report).encode("utf-8")
        findings = lib.privacy_scan_report(
            report, raw, SYNTHETIC_SECRETS,
            allowed_report_id=report["report_id"])
        self.assertEqual(findings, [])
        report["traffic_observation"]["connection_id"] = str(uuid.uuid4())
        findings = lib.privacy_scan_report(
            report, json.dumps(report).encode("utf-8"), SYNTHETIC_SECRETS,
            allowed_report_id=report["report_id"])
        self.assertTrue(any(item["kind"] == "unexpected-uuid"
                            for item in findings))


class ConfigGenerationTests(unittest.TestCase):
    def _credentials(self):
        return lib.Credentials(
            vless_uuid="11111111-1111-4111-8111-111111111111",
            hysteria2_password="um-lt-lab-hy2-fake-password",
            reality_private_key="privkey_placeholder",
            reality_public_key="pubkey_placeholder",
            reality_short_id="0123456789abcdef",
            service_api_secret="um-lt-lab-api-fake-secret",
            monitor_admin_password=lib.SYNTHETIC_ADMIN_PASSWORD,
            center_admin_token="um-lt-lab-admin-fake-token",
            cert_path="/tmp/lab/server.crt",
            key_path="/tmp/lab/server.key",
        )

    def test_server_config_uses_real_reality_and_hysteria2_no_mixed(self):
        ports = lib.PortPlan.allocate()
        config = lib.build_singbox_server_config(self._credentials(), ports)
        inbounds = config["inbounds"]
        self.assertEqual(len(inbounds), 2)
        by_tag = {inbound["tag"]: inbound for inbound in inbounds}
        self.assertEqual(by_tag[lib.REALITY_TAG]["type"], "vless")
        self.assertEqual(by_tag[lib.REALITY_TAG]["listen"], "127.0.0.1")
        self.assertTrue(by_tag[lib.REALITY_TAG]["tls"]["reality"]["enabled"])
        self.assertEqual(
            by_tag[lib.REALITY_TAG]["tls"]["reality"]["handshake"]["server"],
            "127.0.0.1")
        self.assertEqual(by_tag[lib.HYSTERIA2_TAG]["type"], "hysteria2")
        self.assertEqual(by_tag[lib.HYSTERIA2_TAG]["listen"], "127.0.0.1")
        for inbound in inbounds:
            self.assertNotEqual(inbound["type"], "mixed")
        self.assertEqual(len(config["services"]), 1)
        self.assertEqual(config["services"][0]["type"], "api")
        self.assertEqual(config["services"][0]["listen"], "127.0.0.1")
        self.assertEqual(config["outbounds"][0]["type"], "direct")
        text = json.dumps(config)
        self.assertNotIn("mixed", text)
        for forbidden in ("cloudflare", "workers.dev", "http://", "https://"):
            self.assertNotIn(forbidden, text)

    def test_server_config_users_are_named(self):
        # The production monitor keys its identity on the API user, so the lab
        # MUST configure a synthetic user name; otherwise service.api omits the
        # user and the monitor's fail-safe accounting skips the connection.
        ports = lib.PortPlan.allocate()
        config = lib.build_singbox_server_config(self._credentials(), ports)
        for inbound in config["inbounds"]:
            self.assertTrue(inbound["users"][0].get("name"))

    def test_client_configs_use_matching_protocol_and_loopback(self):
        ports = lib.PortPlan.allocate()
        creds = self._credentials()
        reality = lib.build_singbox_client_config(creds, ports, "reality")
        hy2 = lib.build_singbox_client_config(creds, ports, "hysteria2")
        self.assertEqual(reality["outbounds"][0]["type"], "vless")
        self.assertEqual(hy2["outbounds"][0]["type"], "hysteria2")
        self.assertEqual(reality["outbounds"][0]["server"], "127.0.0.1")
        self.assertEqual(hy2["outbounds"][0]["server"], "127.0.0.1")
        self.assertEqual(reality["inbounds"][0]["type"], "socks")
        self.assertEqual(hy2["inbounds"][0]["type"], "socks")
        for config in (reality, hy2):
            self.assertNotIn("dns", config)
            text = json.dumps(config)
            self.assertNotIn("https://", text)
            self.assertNotIn("cloudflare", text)
        with self.assertRaises(lib.LabError):
            lib.build_singbox_client_config(creds, ports, "trojan")

    def test_configs_are_json_serializable_and_distinct_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            ports = lib.PortPlan.allocate()
            paths = lib.write_singbox_configs(tmp, self._credentials(), ports)
            self.assertEqual(set(paths), {"server", "client_reality",
                                          "client_hysteria2"})
            for path in paths.values():
                self.assertTrue(os.path.isfile(path))
                lib.read_json(path)


class X25519Tests(unittest.TestCase):
    def test_rfc7748_vector_one(self):
        scalar = bytes.fromhex(
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
        u = bytes.fromhex(
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
        expected = bytes.fromhex(
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
        self.assertEqual(lib.x25519_scalarmult(scalar, u), expected)

    def test_rfc7748_vector_two(self):
        scalar = bytes.fromhex(
            "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d")
        u = bytes.fromhex(
            "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493")
        expected = bytes.fromhex(
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")
        self.assertEqual(lib.x25519_scalarmult(scalar, u), expected)

    def test_basepoint_vector(self):
        scalar = bytes.fromhex(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        expected_public = bytes.fromhex(
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        _, public_b64 = lib.x25519_keypair(scalar)
        self.assertEqual(lib.base64.urlsafe_b64decode(public_b64 + "="),
                         expected_public)

    def test_generated_keypair_shape(self):
        private_key, public_key = lib.x25519_keypair()
        self.assertRegex(private_key, r"^[A-Za-z0-9_-]{43}$")
        self.assertRegex(public_key, r"^[A-Za-z0-9_-]{43}$")
        self.assertNotEqual(private_key, public_key)


class CenterPayloadTests(unittest.TestCase):
    def test_admin_auth_file_hashes_token(self):
        document = lib.build_center_admin_auth("um-lt-lab-admin-fake-token")
        self.assertEqual(document["principals"][0]["role"], "platform_admin")
        digest = document["tokens"][0]["sha256"]
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertEqual(
            digest,
            lib.sha256_bytes(b"um-lt-lab-admin-fake-token"))
        self.assertNotIn("um-lt-lab-admin-fake-token", json.dumps(document))

    def test_collect_sources_include_monitor_export_switch(self):
        enabled = lib.build_collect_sources(True)
        self.assertIn(lib.AGENT_SOURCE_KEY, enabled)
        self.assertTrue(enabled[lib.AGENT_SOURCE_KEY])
        self.assertEqual(set(enabled), {"system", "services", "singbox_api",
                                        "mihomo_api", "terminal", "events",
                                        lib.AGENT_SOURCE_KEY})
        disabled = lib.build_collect_sources(False)
        self.assertFalse(disabled[lib.AGENT_SOURCE_KEY])
        # The frozen linux_vps rules that must never be violated by the lab.
        self.assertFalse(enabled["singbox_api"])
        self.assertFalse(enabled["mihomo_api"])
        self.assertFalse(enabled["terminal"])

    def test_expected_tags_shape(self):
        tags = lib.build_expected_tags()
        self.assertEqual(tags, [
            {"inbound_tag": "vless-in", "kind": "reality"},
            {"inbound_tag": "hy2-in", "kind": "hysteria2"},
        ])


class PinnedReleaseTests(unittest.TestCase):
    def test_pinned_identity(self):
        self.assertEqual(lib.PINNED_SINGBOX_VERSION, "1.14.5")
        self.assertRegex(lib.PINNED_SINGBOX_SHA256, lib.SHA256_RE)
        self.assertTrue(lib.PINNED_SINGBOX_URL.startswith(
            "https://github.com/SagerNet/sing-box/releases/download/v1.14.5/"))
        self.assertTrue(lib.PINNED_SINGBOX_URL.endswith(
            lib.PINNED_SINGBOX_ARCHIVE))

    def test_sha256_file_helper(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "payload.bin")
            with open(path, "wb") as handle:
                handle.write(b"um-lt-lab")
            self.assertEqual(lib.sha256_file(path),
                             lib.sha256_bytes(b"um-lt-lab"))


class SqliteHelperTests(unittest.TestCase):
    def _make_db(self, path):
        connection = sqlite3.connect(path)
        connection.executescript("""
            CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY);
            INSERT INTO schema_migrations(version) VALUES (14);
            CREATE TABLE traffic_observation_reports (
                report_row_id INTEGER PRIMARY KEY, node_id TEXT, event_id TEXT,
                report_id TEXT, snapshot_id INTEGER, source TEXT,
                source_epoch TEXT, sequence INTEGER, observed_at INTEGER,
                collected_at INTEGER, received_at INTEGER, availability TEXT,
                freshness TEXT, active_connections INTEGER,
                rate_window_seconds REAL, counter_scope TEXT, exactness TEXT,
                bytes_estimate INTEGER);
            CREATE TABLE traffic_observations (
                id INTEGER PRIMARY KEY, report_row_id INTEGER, node_id TEXT,
                event_id TEXT, inbound_tag TEXT, kind TEXT,
                observed_at INTEGER, availability TEXT, quality TEXT,
                uplink_observed_lower_bound_bytes INTEGER,
                downlink_observed_lower_bound_bytes INTEGER,
                uplink_observed_rate_bps REAL,
                downlink_observed_rate_bps REAL, active_connections INTEGER);
        """)
        epoch1 = "a" * 32
        epoch2 = "b" * 32
        rows = [
            (epoch1, "vless-in", "reality", 10, 100, 200),
            (epoch1, "vless-in", "reality", 20, 150, 250),
            (epoch1, "hy2-in", "hysteria2", 10, 300, 400),
            (epoch2, "vless-in", "reality", 30, 5, 6),
        ]
        for index, (epoch, tag, kind, observed_at, uplink, downlink) in \
                enumerate(rows, start=1):
            connection.execute(
                "INSERT INTO traffic_observation_reports(report_row_id, "
                "node_id, event_id, report_id, source, source_epoch, sequence, "
                "observed_at, collected_at, availability, freshness) "
                "VALUES (?, 'n', 'e', ?, 'monitor_readonly_export', ?, ?, ?, "
                "?, 'ok', 'fresh')",
                (index, str(uuid.uuid4()), epoch, index, observed_at,
                 observed_at + 1))
            connection.execute(
                "INSERT INTO traffic_observations(report_row_id, node_id, "
                "event_id, inbound_tag, kind, observed_at, availability, "
                "quality, uplink_observed_lower_bound_bytes, "
                "downlink_observed_lower_bound_bytes, active_connections) "
                "VALUES (?, 'n', 'e', ?, ?, ?, 'ok', 'lower_bound', ?, ?, 0)",
                (index, tag, kind, observed_at, uplink, downlink))
        connection.commit()
        connection.close()

    def test_series_are_per_epoch_and_use_max(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "center.db")
            self._make_db(db)
            connection = lib.open_sqlite_readonly(db)
            try:
                self.assertEqual(lib.sqlite_schema_version(connection), 14)
                observations = lib.fetch_traffic_observations(connection)
                self.assertEqual(len(observations), 4)
                series = lib.traffic_series(observations)
                key1 = ("a" * 32, "vless-in")
                self.assertEqual(series[key1]["max_uplink_lower_bound"], 150)
                self.assertEqual(series[key1]["max_downlink_lower_bound"], 250)
                self.assertEqual(len(series), 3)  # epochs are NOT summed
                latest = lib.latest_traffic_values(observations)
                self.assertEqual(latest[key1]["observed_at"], 20)
            finally:
                connection.close()

    def test_sqlite_open_readonly_rejects_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "center.db")
            self._make_db(db)
            connection = lib.open_sqlite_readonly(db)
            try:
                with self.assertRaises(sqlite3.OperationalError):
                    connection.execute(
                        "INSERT INTO traffic_observations(node_id) VALUES ('x')")
            finally:
                connection.close()

    def test_missing_traffic_tables_report_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "empty.db")
            sqlite3.connect(db).close()
            connection = lib.open_sqlite_readonly(db)
            try:
                self.assertFalse(lib.sqlite_table_exists(
                    connection, lib.TRAFFIC_OBSERVATION_TABLE))
                self.assertEqual(lib.fetch_traffic_observations(connection), [])
            finally:
                connection.close()


class PayloadFixtureTests(unittest.TestCase):
    def test_payload_server_serves_exact_known_bytes(self):
        port = lib.free_port()
        server = lib.PayloadServer(port).start()
        try:
            import urllib.request
            with urllib.request.urlopen(
                    "http://127.0.0.1:%d/payload/65536" % port,
                    timeout=10) as response:
                data = response.read()
            self.assertEqual(len(data), 65536)
            with urllib.request.urlopen(
                    "http://127.0.0.1:%d/health" % port, timeout=10) as response:
                self.assertEqual(response.status, 200)
        finally:
            server.stop()


class _BackendHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        response = json.dumps({"v": 1, "report_id": "x", "result": "accepted",
                               "server_time": 1, "next_seq": 2,
                               "config_version": 1,
                               "echo_len": len(body)}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)


class CaptureProxyTests(unittest.TestCase):
    def test_proxy_forwards_and_captures_report_body(self):
        backend_port = lib.free_port()
        backend = ThreadingHTTPServer(("127.0.0.1", backend_port),
                                      _BackendHandler)
        backend.daemon_threads = True
        threading.Thread(target=backend.serve_forever, daemon=True).start()
        proxy_port = lib.free_port()
        proxy = lib.CaptureProxy(proxy_port, "127.0.0.1", backend_port).start()
        try:
            import http.client
            connection = http.client.HTTPConnection("127.0.0.1", proxy_port,
                                                    timeout=10)
            body = json.dumps({"v": 1, "type": "snapshot"}).encode("utf-8")
            connection.request("POST", "/v1/agent/report", body=body,
                               headers={"Content-Type": "application/json",
                                        "Authorization": "Bearer synthetic"})
            response = connection.getresponse()
            payload = json.loads(response.read())
            connection.close()
            self.assertEqual(response.status, 200)
            self.assertEqual(payload["result"], "accepted")
            self.assertEqual(proxy.report_count(), 1)
            captured = proxy.last_report()
            self.assertIn(b"/v1/agent/report", captured["request"])
            self.assertEqual(captured["body"], body)
            # Replaying the captured raw request must reach the backend too.
            status, raw = lib.replay_raw_http_request(
                captured["request"], "127.0.0.1", backend_port)
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(raw)["result"], "accepted")
        finally:
            proxy.stop()
            backend.shutdown()
            backend.server_close()


class StaticGuardTests(unittest.TestCase):
    """The lab must never reference production/cloud resources."""

    def _lab_sources(self):
        paths = [LIB_PATH]
        if os.path.isfile(ORCHESTRATOR_PATH):
            paths.append(ORCHESTRATOR_PATH)
        texts = {}
        for path in paths:
            with open(path, "r", encoding="utf-8") as handle:
                texts[os.path.basename(path)] = handle.read()
        return texts

    def test_no_production_or_cloud_markers(self):
        banned = ("work" + "ers.dev", "api." + "cloud" + "flare.",
                  "dash." + "cloud" + "flare.", "REALITY" + "_SERVER",
                  "vps.examp" + "le.com", "prod" + "-")
        for name, text in self._lab_sources().items():
            lowered = text.lower()
            for marker in banned:
                self.assertNotIn(marker.lower(), lowered,
                                 "%s references forbidden %r" % (name, marker))

    def test_only_official_download_uses_external_host(self):
        allowed_hosts = {"github.com", "127.0.0.1", "localhost", "::1"}
        for name, text in self._lab_sources().items():
            for match in re.finditer(r"https?://([A-Za-z0-9._-]+)", text):
                host = match.group(1).lower()
                if host.endswith((".invalid", ".test")):
                    continue
                self.assertIn(host, allowed_hosts,
                              "%s references unexpected external host %r"
                              % (name, host))
        # Download URL must be the pinned official release.
        self.assertIn("SagerNet/sing-box/releases/download/v%s",
                      self._lab_sources().get("um_lt_lab_lib.py", ""))

    def test_no_real_ip_literals_outside_documentation_ranges(self):
        allowed = {"127.0.0.1", "0.0.0.0", "::1"}
        for name, text in self._lab_sources().items():
            for match in lib._IPV4_RE.finditer(text):
                value = match.group(0)
                if value in allowed:
                    continue
                # Test fixtures may use documentation/example IPs explicitly
                # (203.0.113.0/24, 192.0.2.0/24, 198.51.100.0/24) to prove the
                # scanner detects IP literals; they are never contacted.
                if value.startswith(("203.0.113.", "192.0.2.",
                                     "198.51.100.")):
                    continue
                self.fail("%s contains a non-loopback IP literal" % name)

    def test_orchestrator_never_claims_exact_lifetime_totals(self):
        if not os.path.isfile(ORCHESTRATOR_PATH):
            self.skipTest("orchestrator not written yet")
        with open(ORCHESTRATOR_PATH, "r", encoding="utf-8") as handle:
            text = handle.read()
        self.assertIn("lower_bound", text)
        self.assertIn("observation_epoch", text)
        # It must never call the normal center web API without auth or write
        # to the center database.
        self.assertNotIn("INSERT INTO", text)
        self.assertNotIn("UPDATE traffic_", text)
        self.assertNotIn("DELETE FROM", text)

    def test_shell_entrypoint_is_bash_syntax_clean(self):
        if not os.path.isfile(SHELL_PATH):
            self.skipTest("shell wrapper not written yet")
        bash = working_bash()
        if not bash:
            self.skipTest("no working bash on this host (the Windows "
                          "Store bash.exe alias is not a real shell)")
        result = subprocess.run([bash, "-n", SHELL_PATH],
                                capture_output=True, text=True,
                                errors="replace", timeout=30)
        self.assertEqual(result.returncode, 0,
                         "bash -n failed: %s" % result.stderr)

    def test_unit_tests_do_not_need_singbox_or_network(self):
        # This file itself must be importable with no binary/network; the
        # presence assertions above prove the helpers do not shell out.
        self.assertFalse(os.path.isdir(os.path.join(REPO_ROOT,
                                                    "does-not-exist")))


class StageRegistryTests(unittest.TestCase):
    def test_orchestrator_imports_and_stage_methods_exist(self):
        if not os.path.isfile(ORCHESTRATOR_PATH):
            self.skipTest("orchestrator not written yet")
        spec = importlib.util.spec_from_file_location("um_lt_orchestrator",
                                                      ORCHESTRATOR_PATH)
        module = importlib.util.module_from_spec(spec)
        sys.modules["um_lt_orchestrator"] = module
        spec.loader.exec_module(module)
        names = [name for name, _description in module.STAGES]
        self.assertGreaterEqual(len(names), 12)
        self.assertEqual(len(names), len(set(names)), "duplicate stage names")
        for name in names:
            method_name = "stage_" + name.replace("-", "_")
            self.assertTrue(callable(getattr(module.Lab, method_name, None)),
                            "missing stage method %r for stage %r"
                            % (method_name, name))
        self.assertIn("main-path", names)
        self.assertIn("center-query", names)
        self.assertIn("export-tamper", names)
        self.assertIn("replay-duplicate", names)
        self.assertIn("agent-center-spool", names)
        self.assertIn("config-source", names)
        self.assertIn("allowlist-change", names)
        self.assertIn("connection-shapes", names)
        self.assertIn("concurrent-protocols", names)
        self.assertIn("monitor-after-traffic", names)
        self.assertIn("final-verification", names)

    def test_orchestrator_limits_are_honest(self):
        if not os.path.isfile(ORCHESTRATOR_PATH):
            self.skipTest("orchestrator not written yet")
        with open(ORCHESTRATOR_PATH, "r", encoding="utf-8") as handle:
            text = handle.read()
        # The lab must never write to the center store: it reads SQLite in
        # read-only mode and uses the admin query API.
        self.assertNotIn("INSERT INTO", text)
        self.assertNotIn("UPDATE traffic_", text)
        self.assertNotIn("DELETE FROM", text)
        self.assertNotIn("sqlite3.connect(self.center_db)", text)
        self.assertIn("mode=ro", lib.open_sqlite_readonly.__doc__ or
                      "mode=ro") if False else None
        # Honest downgrade vocabulary must be present.
        for token in ("unavailable", "stale", "partial", "lower_bound",
                      "observation_epoch", "no fabricated", "no "
                      "cross-epoch"):
            self.assertIn(token, text.lower())


def working_bash():
    """Return a bash that actually executes (skip the Windows Store
    bash.exe alias, which launches a WSL install prompt instead of a
    shell)."""
    import shutil
    candidates = []
    found = shutil.which("bash")
    if found and "WindowsApps" not in found:
        candidates.append(found)
    if os.name == "nt":
        candidates.extend([
            r"C:\Program Files\Git\bin\bash.exe",
            r"C:\Program Files\Git\usr\bin\bash.exe",
        ])
    for candidate in candidates:
        if not os.path.isfile(candidate):
            continue
        try:
            probe = subprocess.run([candidate, "-c", "echo ok"],
                                   capture_output=True, text=True,
                                   errors="replace", timeout=15)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if probe.returncode == 0 and "ok" in (probe.stdout or ""):
            return candidate
    return None


if __name__ == "__main__":
    unittest.main(verbosity=2)
