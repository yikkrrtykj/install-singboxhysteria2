#!/usr/bin/env python3
"""Real-protocol end-to-end lab for UM-LT (Linux traffic export).

This is the executable, reproducible lab that proves the complete UM-LT data
path with the real protocol stack, not with fixtures:

    real sing-box server (Reality VLESS inbound `vless-in` + Hysteria2 inbound
    `hy2-in`, official loopback service.api)
        -> real monitor-v2 web runtime (`webapp.py serve`, restricted atomic
           traffic export at an operator path)
        -> real Linux Go agent (`um-agent`, center source `monitor_export`,
           reads the export file read-only)
        -> real Go center (`um-center`) + real SQLite store (rev-7
           normalization/storage and query surface)
        -> lab assertions over measured curl payloads, export documents,
           captured report bodies, read-only SQLite rows and the admin query
           API.

Only synthetic credentials/certificates/test services are used; every
listener is on 127.0.0.1; the only external network operation is downloading
the pinned official sing-box release tarball with SHA-256 verification.

Modes
-----
    python3 um/deploy/lab/linux_traffic_e2e_lab.py --self-check
        Static/no-binary mode: config generation + optional `sing-box check`
        (when a binary is available) + privacy/no-production guards + closed
        contract validators. Runs on any OS without network access.

    python3 um/deploy/lab/linux_traffic_e2e_lab.py [--keep] [--stage NAME ...]
        The full real-protocol lab. Linux x86_64 + Go + Python + curl are
        required; the pinned sing-box release is downloaded when no
        --singbox-bin is supplied.

Exit codes: 0 PASS, 1 FAILED, 2 usage/precondition error, 3 SKIPPED
(only when UM_LT_LAB_ALLOW_SKIP=1 is explicitly set in the environment).
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
UM_DIR = os.path.join(REPO_ROOT, "um")
CONTRACTS_DIR = os.path.join(REPO_ROOT, "docs", "um", "contracts", "v1")
REV7_CONTRACTS_DIR = os.path.join(CONTRACTS_DIR, "rev7")
MONITOR_DIR = os.path.join(REPO_ROOT, "monitor-v2")
WEBAPP_PATH = os.path.join(MONITOR_DIR, "webapp.py")

sys.path.insert(0, HERE)
import um_lt_lab_lib as lab  # noqa: E402

LAB_VERSION = "1.0.0"

STAGES = [
    ("default-disabled", "monitor started without export flags creates no "
                         "export file, dashboard stays healthy"),
    ("agent-version-gate", "center only emits collect.monitor_export after an "
                           "authenticated rev-7 agent snapshot (OD-LT-14): "
                           "rev-5 then rev-7 agent config transition"),
    ("main-path", "real Reality+Hysteria2 traffic -> export -> agent -> center "
                  "store with direction/attribution/lower-bound assertions"),
    ("center-query", "read-only SQLite + admin node-show + fail-closed web "
                     "query route + privacy scans of export/report/rows"),
    ("monitor-restart", "monitor restart changes source_epoch, removes the old "
                        "file, sequence restarts and no cross-epoch total is "
                        "fabricated"),
    ("singbox-reset", "sing-box stop: stale (partial/unavailable) downgrade; "
                      "sing-box restart: fresh recovery without fake peaks"),
    ("export-tamper", "truncated / missing / old valid export files degrade to "
                      "honest unavailable/stale, never fresh or zero-filled"),
    ("replay-duplicate", "verbatim replay of a captured signed report is "
                         "acknowledged duplicate and stores no duplicate rows"),
    ("agent-center-spool", "center outage + agent spool replay after center "
                           "restart is exactly-once; agent restart is clean"),
    ("config-source", "center `collect.monitor_export` disabled -> rev-5 "
                      "identical body/storage; enabled -> observation resumes"),
    ("allowlist-change", "monitor allowlist / center expected tag change keeps "
                         "per-inbound attribution honest (no cross-attribution)"),
    ("connection-shapes", "short/long/idle/multi connections: plausible active "
                          "counts, no connection break, counters settle"),
    ("concurrent-protocols", "both protocols concurrently: per-inbound "
                             "direction correct and not cross-attributed"),
    ("monitor-after-traffic", "monitor started after traffic: new epoch, honest "
                              "observation scope, no fabricated totals"),
    ("final-verification", "aggregate privacy/no-production checks and summary"),
]


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def eprint(*args) -> None:
    print(*args, file=sys.stderr, flush=True)


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="UM-LT real-protocol (Reality + Hysteria2) traffic E2E lab")
    parser.add_argument("--self-check", action="store_true",
                        help="static config/contract/privacy self-check only "
                             "(no Go, no sing-box required, no network)")
    parser.add_argument("--list-stages", action="store_true",
                        help="print stage names and exit")
    parser.add_argument("--stage", action="append", default=[],
                        dest="stages",
                        help="run only the named stage (repeatable); default "
                             "is every stage in order")
    parser.add_argument("--workdir", default=None,
                        help="lab temp directory (default: mkdtemp under "
                             "$RUNNER_TEMP or the system temp dir)")
    parser.add_argument("--artifacts", default=None,
                        help="artifact output directory (default: "
                             "<workdir>/artifacts; CI uploads this)")
    parser.add_argument("--keep", action="store_true",
                        help="keep the lab workdir (secrets are synthetic but "
                             "the default is to remove it)")
    parser.add_argument("--singbox-bin", default=os.environ.get("SINGBOX_BIN"),
                        help="use an existing sing-box binary instead of "
                             "downloading the pinned release (version must "
                             "match the pinned release)")
    parser.add_argument("--center-bin", default=None,
                        help="use an existing um-center binary instead of "
                             "building one")
    parser.add_argument("--agent-bin", default=None,
                        help="use an existing um-agent binary instead of "
                             "building one")
    parser.add_argument("--python", default=sys.executable,
                        help="Python interpreter used for monitor-v2 (default: "
                             "the running interpreter)")
    parser.add_argument("--quiet", action="store_true",
                        help="only print stage results and failures")
    return parser


def allow_skip() -> bool:
    return os.environ.get("UM_LT_LAB_ALLOW_SKIP", "") == "1"


def skip_or_fail(message: str):
    if allow_skip():
        raise lab.LabSkipped(message)
    raise lab.LabError(
        message + "\n\nSet UM_LT_LAB_ALLOW_SKIP=1 only to intentionally skip "
        "the lab in an environment where its prerequisites are unavailable; "
        "this is never a PASS.")


def stage_selection(requested: list[str]) -> list[tuple]:
    if not requested:
        return list(STAGES)
    known = {name for name, _desc in STAGES}
    unknown = [name for name in requested if name not in known]
    if unknown:
        raise lab.LabError("unknown --stage value(s): %s (known: %s)"
                           % (", ".join(unknown), ", ".join(sorted(known))))
    selected = []
    for name, description in STAGES:
        if name in requested:
            selected.append((name, description))
    return selected


# ---------------------------------------------------------------------------
# Self-check mode (no network, no Go, no sing-box required)
# ---------------------------------------------------------------------------


# Marker strings are assembled from fragments so the guard file does not
# match itself when it scans its own source text.
SELF_CHECK_BANNED_MARKERS = (
    "work" + "ers.dev",
    "api." + "cloud" + "flare.",
    "dash." + "cloud" + "flare.",
    "cloud" + "flared tunnel",
    "prod" + "-",
    "vps.examp" + "le.com",
    "REALITY" + "_SERVER",
)
ALLOWED_EXTERNAL_HOSTS = {"github.com"}
ALLOWED_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
SELF_CHECK_FILES = (
    os.path.join(HERE, "um_lt_lab_lib.py"),
    os.path.join(HERE, "linux_traffic_e2e_lab.py"),
    os.path.join(HERE, "linux-traffic-e2e-lab.sh"),
)


def _selfcheck_credentials(cert_dir: str) -> lab.Credentials:
    private_key, public_key = lab.x25519_keypair()
    return lab.Credentials(
        vless_uuid=lab.generate_uuid(),
        hysteria2_password="um-lt-lab-hy2-selfcheck-password",
        reality_private_key=private_key,
        reality_public_key=public_key,
        reality_short_id="0123456789abcdef",
        service_api_secret="um-lt-lab-api-selfcheck-secret",
        monitor_admin_password=lab.SYNTHETIC_ADMIN_PASSWORD,
        center_admin_token="um-lt-lab-admin-selfcheck-token",
        cert_path=os.path.join(cert_dir, "server.crt"),
        key_path=os.path.join(cert_dir, "server.key"),
    )


def assert_generated_config_invariants(creds: lab.Credentials, ports) -> list[str]:
    """Structural invariants the real protocol configs must always satisfy."""
    notes = []
    server = lab.build_singbox_server_config(creds, ports)
    inbounds = server["inbounds"]
    if len(inbounds) != 2:
        raise lab.LabError("server config must have exactly two inbounds")
    tags = [inbound["tag"] for inbound in inbounds]
    if tags != [lab.REALITY_TAG, lab.HYSTERIA2_TAG]:
        raise lab.LabError("server inbounds must be %r in order, got %r"
                           % ([lab.REALITY_TAG, lab.HYSTERIA2_TAG], tags))
    by_tag = {inbound["tag"]: inbound for inbound in inbounds}
    if by_tag[lab.REALITY_TAG]["type"] != "vless":
        raise lab.LabError("Reality inbound must be a real vless inbound")
    if not by_tag[lab.REALITY_TAG]["tls"]["reality"]["enabled"]:
        raise lab.LabError("Reality inbound must have reality enabled")
    if by_tag[lab.HYSTERIA2_TAG]["type"] != "hysteria2":
        raise lab.LabError("second inbound must be a real hysteria2 inbound")
    for inbound in inbounds:
        if inbound["type"] == "mixed":
            raise lab.LabError("the lab must never substitute a mixed inbound")
        if inbound["listen"] != "127.0.0.1":
            raise lab.LabError("every inbound must listen on loopback only")
        user = inbound["users"][0]
        if not user.get("name"):
            raise lab.LabError("inbound users need a synthetic name: the "
                               "production monitor identity requires the "
                               "service.api user field")
    services = server["services"]
    if len(services) != 1 or services[0]["type"] != "api":
        raise lab.LabError("server must expose exactly the official api service")
    if services[0]["listen"] != "127.0.0.1":
        raise lab.LabError("service.api must be loopback")
    reality = lab.build_singbox_client_config(creds, ports, "reality")
    hy2 = lab.build_singbox_client_config(creds, ports, "hysteria2")
    if reality["outbounds"][0]["type"] != "vless":
        raise lab.LabError("Reality client outbound must be vless")
    if hy2["outbounds"][0]["type"] != "hysteria2":
        raise lab.LabError("Hysteria2 client outbound must be hysteria2")
    for config in (reality, hy2):
        if config["outbounds"][0]["server"] != "127.0.0.1":
            raise lab.LabError("client server address must be loopback")
        if config["inbounds"][0]["type"] != "socks":
            raise lab.LabError("client inbound must be a real socks inbound")
        if "https://" in json.dumps(config):
            raise lab.LabError("client config must not reference external URLs")
    notes.append("server: real vless/reality + real hysteria2 (no mixed); "
                 "official api service on loopback")
    notes.append("clients: one real sing-box process per protocol, socks "
                 "inbound -> protocol outbound, loopback only")
    return notes


def self_check_static_guards() -> list[str]:
    banned_hits = []
    external_hosts = set()
    ip_literals = set()
    notes = []
    for path in SELF_CHECK_FILES:
        if not os.path.isfile(path):
            continue
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read()
        lowered = text.lower()
        for marker in SELF_CHECK_BANNED_MARKERS:
            if marker.lower() in lowered:
                banned_hits.append((os.path.basename(path), marker))
        for match in re.finditer(r"https?://([A-Za-z0-9._-]+)", text):
            host = match.group(1).lower()
            external_hosts.add(host)
        for match in lab._IPV4_RE.finditer(text):
            value = match.group(0)
            if value in ALLOWED_LOOPBACK_HOSTS or value.startswith(
                    ("192.0.2.", "198.51.100.", "203.0.113.")):
                continue
            ip_literals.add((os.path.basename(path), value))
    if banned_hits:
        raise lab.LabError("self-check found production/cloud markers: %s"
                           % banned_hits)
    unexpected = {host for host in external_hosts
                  if host not in ALLOWED_EXTERNAL_HOSTS
                  and host not in ALLOWED_LOOPBACK_HOSTS
                  and not host.endswith((".invalid", ".test"))}
    if unexpected:
        raise lab.LabError("self-check found unexpected external host(s): %s"
                           % sorted(unexpected))
    if ip_literals:
        raise lab.LabError("self-check found non-loopback IP literal(s): %s"
                           % sorted(ip_literals))
    notes.append("no production/cloud markers; only the pinned GitHub release "
                 "download is external")
    return notes


def _self_check_documents() -> tuple[list[str], list[str]]:
    """Exercise the closed validators on positive + tampered documents."""
    passes = []
    # -- canonical export ---------------------------------------------------
    tags = list(lab.EXPECTED_TAGS)
    base = {
        "schema": lab.EXPORT_SCHEMA,
        "schema_version": lab.EXPORT_SCHEMA_VERSION,
        "source": lab.EXPORT_SOURCE,
        "source_epoch": "0123456789abcdef0123456789abcdef",
        "sequence": 1,
        "generated_at": 1700000010,
        "observed_at": 1700000009,
        "monitor_stale": False,
        "monitor_last_success_at": 1700000009,
        "counter_scope": lab.COUNTER_SCOPE,
        "exactness": lab.EXACTNESS,
        "active_connections": 0,
        "rate_window_seconds": None,
        "inbounds": [{
            "inbound_tag": tag, "kind": kind,
            "observed_uplink_bytes": 100, "observed_downlink_bytes": 200,
            "uplink_observed_rate_bps": None,
            "downlink_observed_rate_bps": None,
            "active_connections": 0,
            "observed_at": 1700000009,
            "quality": "lower_bound",
        } for tag, kind in tags],
    }
    normalized = lab.validate_export_document(base)
    if len(normalized["inbounds"]) != 2:
        raise lab.LabError("self-check: export validator lost inbound rows")
    passes.append("canonical monitor-v2 export document accepted with a "
                  "closed allow-list")

    import copy as _copy
    tamper_cases = [
        ("forbidden member", lambda doc: doc.__setitem__("user", "x")),
        ("float byte counter",
         lambda doc: doc["inbounds"][0].__setitem__("observed_uplink_bytes",
                                                     1.0)),
        ("duplicate tag",
         lambda doc: doc["inbounds"][1].__setitem__("inbound_tag", "vless-in")),
        ("source token swapped",
         lambda doc: doc.__setitem__("source", lab.REPORT_SOURCE)),
        ("stale but lower_bound",
         lambda doc: doc.__setitem__("monitor_stale", True)),
        ("rates without window",
         lambda doc: doc["inbounds"][0].__setitem__(
             "uplink_observed_rate_bps", 1.0)),
        ("active total below sum",
         lambda doc: (doc.__setitem__("active_connections", 0),
                      doc["inbounds"][0].__setitem__("active_connections", 1))),
    ]
    for name, mutate in tamper_cases:
        candidate = _copy.deepcopy(base)
        mutate(candidate)
        try:
            lab.validate_export_document(candidate)
        except lab.LabAssertionFailed:
            passes.append("tampered export rejected: %s" % name)
        else:
            raise lab.LabError("self-check: tampered export accepted: %s" % name)
    legacy = {"export_version": 1, "source": "monitor_readonly_export"}
    try:
        lab.validate_export_document(legacy)
    except lab.LabAssertionFailed as exc:
        if "superseded draft shape" not in str(exc):
            raise
        passes.append("legacy draft export shape rejected with actionable "
                      "reconciliation message")
    else:
        raise lab.LabError("self-check: legacy draft export accepted")

    # -- rev-7 report body --------------------------------------------------
    report = {
        "v": 1, "type": "snapshot",
        "report_id": lab.generate_uuid(),
        "collected_at": 1700000020,
        "traffic": [],
        "contract_revision": 7,
        "traffic_observation": {
            "source": lab.REPORT_SOURCE,
            "source_epoch": "0123456789abcdef0123456789abcdef",
            "sequence": 2,
            "observed_at": 1700000019,
            "age_seconds": 1,
            "freshness": "fresh",
            "availability": "ok",
            "counter_scope": lab.COUNTER_SCOPE,
            "exactness": lab.EXACTNESS,
            "active_connections": 0,
            "rate_window_seconds": None,
            "inbounds": [{
                "inbound_tag": "vless-in", "kind": "reality",
                "observed_at": 1700000019,
                "availability": "ok", "quality": "lower_bound",
                "uplink_observed_lower_bound_bytes": 10,
                "downlink_observed_lower_bound_bytes": 20,
                "uplink_observed_rate_bps": None,
                "downlink_observed_rate_bps": None,
                "active_connections": 0,
            }],
        },
    }
    parsed = lab.validate_rev7_snapshot_report(report)
    if parsed["source_epoch"] != "0123456789abcdef0123456789abcdef":
        raise lab.LabError("self-check: report observation lost source_epoch")
    passes.append("rev-7 traffic_observation report body accepted and "
                  "normalized")
    observation_tamper = _copy.deepcopy(report)
    observation_tamper["traffic_observation"]["monitor_stale"] = False
    try:
        lab.validate_rev7_snapshot_report(observation_tamper)
    except lab.LabAssertionFailed:
        passes.append("report observation closed allow-list enforced")
    else:
        raise lab.LabError("self-check: report observation accepted an "
                           "unknown member")
    rev5 = {"v": 1, "type": "snapshot",
            "report_id": lab.generate_uuid(), "collected_at": 1700000000,
            "traffic": []}
    if not lab.validate_rev7_snapshot_report(rev5).get("rev5"):
        raise lab.LabError("self-check: disabled-source rev-5 body rejected")
    passes.append("rev-5 byte-identical body accepted when source disabled")

    # -- privacy scanners ---------------------------------------------------
    clean_raw = json.dumps(base).encode("utf-8")
    if lab.privacy_scan_export(base, clean_raw, ["um-lt-lab-secret-sentinel"]):
        raise lab.LabError("self-check: clean export flagged by privacy scan")
    dirty = _copy.deepcopy(base)
    dirty["client_ip"] = "203.0.113.7"
    if not lab.privacy_scan_export(
            dirty, json.dumps(dirty).encode("utf-8"), []):
        raise lab.LabError("self-check: privacy scan missed an IP literal")
    dirty_report = _copy.deepcopy(report)
    dirty_report["connection_id"] = lab.generate_uuid()
    findings = lab.privacy_scan_report(
        dirty_report, json.dumps(dirty_report).encode("utf-8"), [],
        allowed_report_id=report["report_id"])
    if not any(item["kind"] == "unexpected-uuid" for item in findings):
        raise lab.LabError("self-check: privacy scan missed a hidden UUID")
    passes.append("privacy scanners: sentinels and raw network literals are "
                  "detected; report_id is the only allowed UUID")

    # -- center payloads ----------------------------------------------------
    auth = lab.build_center_admin_auth("um-lt-lab-admin-token")
    if auth["tokens"][0]["sha256"] != lab.sha256_bytes(
            b"um-lt-lab-admin-token"):
        raise lab.LabError("self-check: center admin auth hash mismatch")
    sources = lab.build_collect_sources(True)
    if set(sources) != {"system", "services", "singbox_api", "mihomo_api",
                        "terminal", "events", lab.AGENT_SOURCE_KEY}:
        raise lab.LabError("self-check: collect source set is not rev-7")
    if not sources[lab.AGENT_SOURCE_KEY] or sources["singbox_api"]:
        raise lab.LabError("self-check: rev-7 source switches are unsafe")
    passes.append("center auth/collect/tag payloads are rev-7 and keep "
                  "singbox_api disabled")
    return passes, []


def run_self_check(args) -> int:
    print("UM-LT traffic lab self-check (%s)" % LAB_VERSION)
    failures = []
    notes = []
    skipped = []
    try:
        # Pinned release identity.
        if not re.match(r"^[0-9]+\.[0-9]+\.[0-9]+$", lab.PINNED_SINGBOX_VERSION):
            raise lab.LabError("pinned sing-box version is not a release")
        if not lab.SHA256_RE.match(lab.PINNED_SINGBOX_SHA256):
            raise lab.LabError("pinned sing-box SHA-256 is not 64 lowercase hex")
        if "SagerNet/sing-box/releases/download/v%s" % (
                lab.PINNED_SINGBOX_VERSION) not in lab.PINNED_SINGBOX_URL:
            raise lab.LabError("pinned sing-box URL does not match the version")
        notes.append("pinned sing-box %s archive %s sha256=%s"
                     % (lab.PINNED_SINGBOX_VERSION,
                        lab.PINNED_SINGBOX_ARCHIVE,
                        lab.PINNED_SINGBOX_SHA256[:16] + "..."))
        # Credential/config generation (no cert generator needed for layout).
        tmp = tempfile.mkdtemp(prefix="um-lt-selfcheck-")
        try:
            creds = _selfcheck_credentials(tmp)
            ports = lab.PortPlan.allocate()
            notes.extend(assert_generated_config_invariants(creds, ports))
            paths = lab.write_singbox_configs(tmp, creds, ports)
            for name, path in paths.items():
                lab.read_json(path)
            notes.append("generated %d sing-box configs (server + 2 real "
                         "clients)" % len(paths))
            notes.extend(self_check_static_guards())
            passes, _ = _self_check_documents()
            notes.extend(passes)
            # Optional real `sing-box check` when a binary is available.
            binary = lab.resolve_singbox_bin(args.singbox_bin)
            if not binary:
                skipped.append("sing-box check (no --singbox-bin/SINGBOX_BIN "
                               "and no sing-box on PATH)")
            else:
                try:
                    version = lab.singbox_version(binary)
                except lab.LabError as exc:
                    skipped.append("sing-box check (%s)" % exc)
                else:
                    run_check = True
                    if version != lab.PINNED_SINGBOX_VERSION:
                        if os.environ.get(
                                "UM_LT_LAB_SELFCHECK_UNPINNED") != "1":
                            skipped.append(
                                "sing-box check (binary version %s != "
                                "pinned %s; refusing non-pinned protocol "
                                "build. Set "
                                "UM_LT_LAB_SELFCHECK_UNPINNED=1 only for "
                                "a local layout check)"
                                % (version, lab.PINNED_SINGBOX_VERSION))
                            run_check = False
                        else:
                            notes.append(
                                "NOTE: running `sing-box check` with local "
                                "binary %s (not the pinned %s); layout-only, "
                                "never real-lab evidence"
                                % (version, lab.PINNED_SINGBOX_VERSION))
                    if run_check:
                        # The configs reference certificate files; generate
                        # synthetic ones so `sing-box check` can load them.
                        try:
                            lab.generate_self_signed_cert(
                                creds.server_name, creds.cert_path,
                                creds.key_path, binary)
                        except lab.LabError as exc:
                            skipped.append("sing-box check (certificate "
                                           "generation unavailable: %s)" % exc)
                        else:
                            for name, path in paths.items():
                                result = lab.singbox_check(binary, path)
                                if result.returncode != 0:
                                    raise lab.LabError(
                                        "sing-box check failed for %s: %s"
                                        % (name, (result.stderr
                                                  or result.stdout
                                                  ).strip()[-800:]))
                            notes.append("sing-box check passed for server + "
                                         "both real client configs (version %s)"
                                         % version)
            # Optional rev-7 contract example cross-check when integrated.
            example = os.path.join(REV7_CONTRACTS_DIR, "examples",
                                   "report-snapshot.json")
            if os.path.isfile(example):
                try:
                    document = lab.read_json(example)
                except ValueError:
                    skipped.append("rev-7 example cross-check (example is not "
                                   "valid JSON)")
                else:
                    if isinstance(document, dict) and \
                            "traffic_observation" in document:
                        lab.validate_rev7_snapshot_report(document)
                        notes.append("contract example rev7/examples/report-snapshot.json "
                                     "matches the lab report validator")
                    else:
                        skipped.append("rev-7 example cross-check (example has "
                                       "no traffic_observation)")
            else:
                skipped.append("rev-7 contract example cross-check (contract "
                               "PR not integrated in this worktree yet)")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    except lab.LabError as exc:
        failures.append(str(exc))
    except Exception as exc:  # noqa: BLE001 - self-check must report, not crash
        failures.append("unexpected self-check error: %s\n%s"
                        % (exc, traceback.format_exc()))
    for note in notes:
        print("  OK   %s" % note)
    for item in skipped:
        print("  SKIP %s" % item)
    if failures:
        for failure in failures:
            print("  FAIL %s" % failure, file=sys.stderr)
        print("UM-LT lab self-check: FAILED")
        return 1
    print("UM-LT lab self-check: PASS (%d checks, %d skips)"
          % (len(notes), len(skipped)))
    return 0


# ---------------------------------------------------------------------------
# Full lab
# ---------------------------------------------------------------------------


class Lab:
    def __init__(self, args):
        self.args = args
        if args.workdir:
            # A reused workdir would re-open a previous center DB/agent
            # state and silently mix lab runs; refuse it instead of
            # deleting user data.
            if os.path.isdir(args.workdir) and os.listdir(args.workdir):
                raise lab.LabError(
                    "workdir %r already exists and is not empty; pass a "
                    "fresh --workdir (the lab never deletes user data)"
                    % args.workdir)
            os.makedirs(args.workdir, exist_ok=True)
            self.workdir = args.workdir
        else:
            self.workdir = tempfile.mkdtemp(prefix="um-lt-lab-")
        self.artifacts = args.artifacts or os.path.join(self.workdir,
                                                        "artifacts")
        self.logs_dir = os.path.join(self.workdir, "logs")
        self.creds_dir = os.path.join(self.workdir, "creds")
        self.bin_dir = os.path.join(self.workdir, "bin")
        self.singbox_dir = os.path.join(self.workdir, "singbox")
        self.center_dir = os.path.join(self.workdir, "center")
        self.agent_dir = os.path.join(self.workdir, "agent")
        self.monitor_data_dir = os.path.join(self.workdir, "monitor-data")
        self.monitor_export_dir = os.path.join(self.workdir, "export")
        self.evidence_dir = os.path.join(self.artifacts, "evidence")
        for path in (self.artifacts, self.logs_dir, self.creds_dir,
                     self.bin_dir, self.singbox_dir, self.center_dir,
                     self.agent_dir, self.monitor_data_dir,
                     self.monitor_export_dir, self.evidence_dir):
            lab.ensure_dir(path)
        self.ports = None
        self.creds = None
        self.singbox_bin = None
        self.center_bin = None
        self.agent_bin = None
        self.server_proc = None
        self.client_processes = {}
        self.proxy = None
        self.center_proc = None
        self.monitor_proc = None
        self.continuous_agent = None
        self.payload_server = None
        self.tls_server = None
        self.export_path = os.path.join(self.monitor_export_dir,
                                        "traffic-export.json")
        self.health_file = os.path.join(self.monitor_export_dir,
                                        "health.json")
        self.secret_file = os.path.join(self.creds_dir, "service-api.secret")
        self.center_auth_file = os.path.join(self.center_dir, "admin-auth.json")
        self.center_token_file = os.path.join(self.center_dir, "admin.token")
        self.master_key_file = os.path.join(self.center_dir, "master.key")
        self.event_id = lab.generate_uuid()
        self.node_id = None
        self.stages = []
        self.checks = 0
        self.stage_results = []
        self.measurements = {}
        self.started = time.time()
        self.report_history = []
        self.export_samples = []
        self.ledger = lab.TrafficLedger()
        self.monitor_epoch_baselines = {}
        self.current_monitor_epoch = None
        self.current_stage = "setup"
        self._saved_export = None
        self._last_export = None
        self.rev7_schema_paths = {
            "snapshot": os.path.join(REV7_CONTRACTS_DIR,
                                     lab.REV7_SNAPSHOT_SCHEMA_FILE),
            "agent_config": os.path.join(REV7_CONTRACTS_DIR,
                                         lab.REV7_AGENT_CONFIG_SCHEMA_FILE),
        }

    # -- logging / assertions ------------------------------------------------
    def echo(self, message: str) -> None:
        if not self.args.quiet:
            print(message, flush=True)

    def stage(self, name: str) -> None:
        self.current_stage = name
        print("\n=== stage: %s ===" % name, flush=True)

    def check(self, condition, message: str, evidence=None) -> None:
        self.checks += 1
        if not condition:
            details = ""
            if evidence is not None:
                try:
                    details = "\n  evidence: %s" % json.dumps(
                        evidence, sort_keys=True)[:4000]
                except (TypeError, ValueError):
                    details = "\n  evidence: %r" % (evidence,)
            raise lab.LabAssertionFailed("[%s] %s%s"
                                         % (self.current_stage, message,
                                            details))
        if not self.args.quiet:
            print("  ok   %s" % message, flush=True)

    def check_eq(self, actual, expected, message: str) -> None:
        self.check(actual == expected,
                   "%s (expected %r, got %r)" % (message, expected, actual))

    def check_in_range(self, value, minimum, maximum, message: str) -> None:
        self.check(value is not None and minimum <= value <= maximum,
                   "%s (expected %r..%r, got %r)"
                   % (message, minimum, maximum, value))

    def record(self, name: str, value) -> None:
        self.measurements[name] = value

    # -- process management --------------------------------------------------
    def _start_process(self, name: str, command: list, cwd=None) -> lab.ManagedProcess:
        log_path = os.path.join(self.logs_dir, name + ".log")
        process = lab.ManagedProcess(name=name, command=command,
                                     log_path=log_path, cwd=cwd).start()
        time.sleep(0.1)
        if process.returncode() is not None:
            raise lab.LabError(
                "process %r exited immediately (rc=%r)\ncommand: %r\nlog:\n%s"
                % (name, process.returncode(), command,
                   process.log_tail(4000)))
        return process

    def _stop_process(self, process, name: str) -> None:
        if process is None:
            return
        process.terminate(timeout=15)
        if process.returncode() not in (0, -15, 143, None):
            self.echo("  note: %s exited rc=%r during teardown"
                      % (name, process.returncode()))
        time.sleep(0.1)

    # =====================================================================
    # Setup
    # =====================================================================
    def setup(self) -> None:
        self.stage("setup")
        self.assert_environment()
        self.prepare_singbox()
        self.build_binaries()
        self.prepare_credentials_and_configs()
        self.prepare_center_files()
        self.prepare_monitor()
        self.start_singbox_stack()
        self.start_center()
        self.enroll_agent()
        self.update_center_config(True)
        self.run_stage("agent-version-gate",
                       self.stage_agent_version_gate)
        self.run_stage("default-disabled", self.stage_default_disabled)
        self.start_monitor()
        self.wait_monitor_ready()

    def assert_environment(self) -> None:
        if platform.system() != "Linux":
            skip_or_fail(
                "the full UM-LT lab requires Linux (the real Linux Go agent "
                "and Go center are Linux artifacts; current platform is %s)"
                % platform.system())
        machine = platform.machine().lower()
        if machine not in ("x86_64", "amd64"):
            skip_or_fail("the pinned sing-box release is linux-amd64; this "
                         "host is %r" % machine)
        if sys.version_info < (3, 10):
            skip_or_fail("Python >= 3.10 is required, found %s"
                         % sys.version.split()[0])
        for tool in ("go", "curl", "tar"):
            if shutil.which(tool) is None:
                skip_or_fail("required lab tool %r is not on PATH" % tool)
        if not os.path.isfile(WEBAPP_PATH):
            raise lab.LabError("monitor-v2 webapp.py not found at %s"
                               % WEBAPP_PATH)
        if not os.path.isdir(CONTRACTS_DIR):
            raise lab.LabError("frozen contracts directory not found: %s"
                               % CONTRACTS_DIR)
        for key, path in self.rev7_schema_paths.items():
            if not os.path.isfile(path):
                skip_or_fail(
                    "rev-7 %s contract schema is missing at %s; the lab is "
                    "written against the integrated rev-7 contract and must "
                    "not be reported as passing before the contract/Go "
                    "changes land (docs/um/contracts/v1 is not edited by the "
                    "lab)" % (key, path))
        self.echo("repo: %s" % REPO_ROOT)
        self.echo("workdir: %s" % self.workdir)
        self.echo("artifacts: %s" % self.artifacts)

    def prepare_singbox(self) -> None:
        binary = self.args.singbox_bin
        if binary and not os.path.isfile(binary):
            raise lab.LabError("--singbox-bin points at a missing file: %s"
                               % binary)
        if not binary:
            self.echo("downloading pinned sing-box %s (%s)"
                      % (lab.PINNED_SINGBOX_VERSION,
                         lab.PINNED_SINGBOX_ARCHIVE))
            binary = lab.download_pinned_singbox(
                os.path.join(self.singbox_dir, "download"))
        version = lab.assert_singbox_version(binary)
        self.singbox_bin = os.path.abspath(binary)
        self.record("singbox_version", version)
        self.echo("sing-box: %s (%s)" % (version, self.singbox_bin))

    def build_binaries(self) -> None:
        go = shutil.which("go")
        self.center_bin = self.args.center_bin
        if not self.center_bin:
            self.center_bin = os.path.join(self.bin_dir, "um-center")
            self.go_build("./cmd/um-center", self.center_bin)
        self.agent_bin = self.args.agent_bin
        if not self.agent_bin:
            self.agent_bin = os.path.join(self.bin_dir, "um-agent")
            self.go_build("./cmd/um-agent", self.agent_bin)
        for name, path in (("um-center", self.center_bin),
                           ("um-agent", self.agent_bin)):
            if not (os.path.isfile(path) and os.access(path, os.X_OK)):
                raise lab.LabError("Go binary %r was not produced at %s"
                                   % (name, path))
        # Interface capability probe: the agent must expose the expected
        # monitor-export flag before a long lab run starts.
        result = lab.run_capture([self.agent_bin, "run", "-h"], timeout=60)
        help_text = (result.stdout or "") + (result.stderr or "")
        # Go's flag package prints a single leading dash even though it accepts
        # both one and two leading dashes on the command line.
        if (lab.AGENT_MONITOR_EXPORT_FLAG not in help_text
                and lab.AGENT_MONITOR_EXPORT_FLAG[1:] not in help_text):
            skip_or_fail(
                "the um-agent build does not expose the expected %s flag; "
                "the lab is written against the integrated UM-LT interface "
                "(agent reads the monitor-v2 restricted export). Agent help "
                "was:\n%s"
                % (lab.AGENT_MONITOR_EXPORT_FLAG, help_text[-1200:]))
        self.echo("go binaries: %s, %s" % (self.center_bin, self.agent_bin))
        self.record("center_bin", os.path.basename(self.center_bin))
        self.record("agent_bin", os.path.basename(self.agent_bin))

    def go_build(self, package: str, output: str) -> None:
        env = dict(os.environ)
        env.setdefault("CGO_ENABLED", "0")
        self.echo("building %s -> %s" % (package, output))
        result = lab.run_capture(
            [shutil.which("go"), "build", "-trimpath", "-o", output, package],
            timeout=300, cwd=UM_DIR, env=env)
        if result.returncode != 0:
            raise lab.LabError("go build %s failed:\n%s"
                               % (package, (result.stderr
                                            or result.stdout)[-4000:]))

    def prepare_credentials_and_configs(self) -> None:
        self.creds = lab.build_credentials(self.creds_dir, self.singbox_bin)
        lab.write_text(self.secret_file,
                       self.creds.service_api_secret + "\n", 0o600)
        self.ports = lab.PortPlan.allocate()
        self.config_paths = lab.write_singbox_configs(
            self.singbox_dir, self.creds, self.ports)
        for name, path in self.config_paths.items():
            result = lab.singbox_check(self.singbox_bin, path)
            if result.returncode != 0:
                raise lab.LabError(
                    "sing-box check failed for the generated %s config (real "
                    "Reality/Hysteria2 reject the generated shape):\n%s"
                    % (name, (result.stderr or result.stdout)[-3000:]))
        self.echo("generated synthetic Reality/Hysteria2 credentials and "
                  "validated all sing-box configs with `sing-box check`")

    def prepare_center_files(self) -> None:
        lab.write_json(self.center_auth_file,
                       lab.build_center_admin_auth(self.creds.center_admin_token))
        lab.write_text(self.center_token_file, self.creds.center_admin_token,
                       0o600)
        lab.write_bytes(self.master_key_file, os.urandom(32), 0o600)
        self.web_static_dir = lab.ensure_dir(
            os.path.join(self.center_dir, "web-static"))
        self.center_db = os.path.join(self.center_dir, "center.db")

    def prepare_monitor(self) -> None:
        # --traffic-export helpers must exist in the integrated monitor-v2.
        result = lab.run_capture(
            [self.args.python, WEBAPP_PATH, "serve", "-h"], timeout=90,
            cwd=MONITOR_DIR)
        help_text = (result.stdout or "") + (result.stderr or "")
        for flag in (lab.MONITOR_EXPORT_FILE_FLAG,
                     lab.MONITOR_EXPORT_INBOUND_FLAG):
            if flag not in help_text:
                skip_or_fail(
                    "monitor-v2/webapp.py serve does not expose the expected "
                    "%r flag; the lab is written against the integrated "
                    "restricted-export interface. Serve help was:\n%s"
                    % (flag, help_text[-1500:]))
        if not os.path.isfile(os.path.join(self.monitor_data_dir, "auth.json")):
            result = lab.run_capture(
                lab.monitor_setup_command(
                    self.args.python, WEBAPP_PATH, self.monitor_data_dir,
                    self.creds.monitor_admin_password,
                    os.path.join(self.monitor_data_dir, "recovery")),
                timeout=120, cwd=MONITOR_DIR)
            if result.returncode != 0:
                raise lab.LabError(
                    "monitor-v2 setup failed:\n%s"
                    % ((result.stdout or "") + (result.stderr or ""))[-3000:])
        self.monitor = lab.MonitorWebClient(
            "http://127.0.0.1:%d" % self.ports.monitor_web,
            self.creds.monitor_admin_password)

    def start_singbox_stack(self) -> None:
        ports = self.ports
        self.server_proc = self._start_process(
            "singbox-server",
            [self.singbox_bin, "run", "-c", self.config_paths["server"]])
        if not lab.wait_port("127.0.0.1", ports.reality_tcp, timeout=20):
            raise lab.LabError("real Reality inbound did not start on "
                               "127.0.0.1:%d\n%s"
                               % (ports.reality_tcp,
                                  self.server_proc.log_tail(4000)))
        if not lab.wait_port("127.0.0.1", ports.service_api, timeout=20):
            raise lab.LabError("sing-box service.api did not start\n%s"
                               % self.server_proc.log_tail(4000))
        self.payload_server = lab.PayloadServer(ports.http_fixture).start()
        self.tls_server = lab.TlsCamouflageServer(
            ports.handshake_tls, self.creds.cert_path,
            self.creds.key_path).start()
        for protocol, config_key, socks_port in (
                ("reality", "client_reality", ports.socks_reality),
                ("hysteria2", "client_hysteria2", ports.socks_hysteria2)):
            process = self._start_process(
                "singbox-client-%s" % protocol,
                [self.singbox_bin, "run", "-c", self.config_paths[config_key]])
            if not lab.wait_port("127.0.0.1", socks_port, timeout=20):
                raise lab.LabError("real sing-box client (%s) socks inbound "
                                   "did not start\n%s"
                                   % (protocol, process.log_tail(4000)))
            self.client_processes[protocol] = process
        self.echo("real protocol stack up: Reality vless-in tcp/%d, Hysteria2 "
                  "hy2-in udp/%d, official service.api tcp/%d, loopback TLS "
                  "camouflage target tcp/%d"
                  % (ports.reality_tcp, ports.hysteria2_udp,
                     ports.service_api, ports.handshake_tls))

    def _restart_singbox_clients(self) -> None:
        for protocol, config_key in (("reality", "client_reality"),
                                     ("hysteria2", "client_hysteria2")):
            self._stop_process(self.client_processes[protocol],
                               "singbox-client-%s" % protocol)
            self.client_processes[protocol] = self._start_process(
                "singbox-client-%s" % protocol,
                [self.singbox_bin, "run", "-c",
                 self.config_paths[config_key]])
            port = self._socks_port(protocol)
            if not lab.wait_port("127.0.0.1", port, timeout=30):
                raise lab.LabError("real sing-box client %r did not "
                                   "start/recover" % protocol)

    def start_center(self) -> None:
        if self.center_proc is not None:
            self._stop_process(self.center_proc, "um-center")
            self.center_proc = None
        command = [
            self.center_bin,
            "-ingest", "127.0.0.1:%d" % self.ports.center_ingest,
            "-admin", "127.0.0.1:%d" % self.ports.center_admin,
            "-db", self.center_db,
            "-contracts", CONTRACTS_DIR,
            "-admin-auth-file", self.center_auth_file,
            "-web", "127.0.0.1:%d" % self.ports.center_web,
            "-master-key", self.master_key_file,
            "-access-issuer", "https://um-lt-lab.invalid",
            "-access-audience", "um-lt-lab-audience",
            "-access-jwks", "https://um-lt-lab.invalid/jwks",
            "-web-origin", "https://um-lt-lab.invalid",
            "-web-static", self.web_static_dir,
        ]
        self.center_proc = self._start_process("um-center", command)
        for name, port in (("ingest", self.ports.center_ingest),
                           ("admin", self.ports.center_admin),
                           ("web", self.ports.center_web)):
            if not lab.wait_port("127.0.0.1", port, timeout=30):
                raise lab.LabError(
                    "um-center %s listener did not start on 127.0.0.1:%d\n%s"
                    % (name, port, self.center_proc.log_tail(5000)))
        self.center_admin_url = "http://127.0.0.1:%d" % self.ports.center_admin
        self.center_ingest_url = ("http://127.0.0.1:%d"
                                  % self.ports.center_ingest)
        self.center_web_url = ("http://127.0.0.1:%d"
                               % self.ports.center_web)
        # The capture proxy fronts the real center for every agent request so
        # duplicate/replay and report-body privacy evidence are truthful.
        if self.proxy is None:
            self.proxy = lab.CaptureProxy(
                self.ports.capture_proxy, "127.0.0.1",
                self.ports.center_ingest)
            self.agent_center_url = ("http://127.0.0.1:%d"
                                     % self.ports.capture_proxy)
        self.proxy.start()
        lab.wait_port("127.0.0.1", self.ports.capture_proxy, timeout=15)
        lab.wait_until(
            lambda: lab.run_admin_cli(
                self.center_bin, self.center_admin_url,
                self.center_token_file, ["health"]),
            timeout=30, interval=0.3,
            description="the center admin health endpoint")
        self.echo("real um-center up: ingest tcp/%d admin tcp/%d web tcp/%d "
                  "contracts=%s"
                  % (self.ports.center_ingest, self.ports.center_admin,
                     self.ports.center_web, CONTRACTS_DIR))

    def create_event_and_token(self) -> None:
        lab.wait_until(
            lambda: lab.run_admin_cli(
                self.center_bin, self.center_admin_url,
                self.center_token_file, ["event", "list"]),
            timeout=30, interval=0.3,
            description="the center event API")
        lab.run_admin_cli(self.center_bin, self.center_admin_url,
                          self.center_token_file,
                          ["event", "create", "--name", "UM-LT real-protocol "
                           "traffic lab", "--event-id", self.event_id])
        token_document = lab.run_admin_cli(
            self.center_bin, self.center_admin_url, self.center_token_file,
            ["token", "create", self.event_id, "--class", "linux_vps",
             "--ttl-seconds", "1800"])
        token = token_document.get("token")
        if not token:
            raise lab.LabError("center token create did not return a token: %r"
                               % token_document)
        self.enrollment_token_file = os.path.join(self.agent_dir,
                                                  "enroll.token")
        lab.write_text(self.enrollment_token_file, token, 0o600)
        self.echo("created event %s and a single-use linux_vps enrollment "
                  "token" % self.event_id)

    def enroll_agent(self) -> None:
        self.create_event_and_token()
        state_dir = os.path.join(self.agent_dir, "state")
        lab.ensure_dir(state_dir)
        result = lab.run_capture(
            [self.agent_bin, "enroll", "--state-dir", state_dir,
             "--center", self.agent_center_url, "--node-class", "linux_vps",
             "--token-file", self.enrollment_token_file], timeout=120)
        if result.returncode != 0:
            raise lab.LabError(
                "real um-agent enrollment failed:\n%s\nagent log: %s"
                % (((result.stdout or "") + (result.stderr or ""))[-4000:],
                   self.proxy_requests_summary()))
        nodes = lab.run_admin_cli(
            self.center_bin, self.center_admin_url, self.center_token_file,
            ["node", "list", self.event_id, "--class", "linux_vps"])
        node_entries = nodes.get("nodes") or []
        if len(node_entries) != 1:
            raise lab.LabError("expected exactly one enrolled linux_vps node, "
                               "got %r" % node_entries)
        self.node_id = node_entries[0]["node_id"]
        self.agent_state_dir = state_dir
        self.echo("real um-agent enrolled: node %s (center config pull "
                  "included)" % self.node_id)
        self.record("node_id_present", bool(self.node_id))

    # -- agent / monitor / export helpers -----------------------------------
    def agent_flags(self) -> list:
        return ["--state-dir", self.agent_state_dir,
                "--center", self.agent_center_url,
                "--node-class", "linux_vps",
                lab.AGENT_MONITOR_EXPORT_FLAG, self.export_path]

    def run_agent_once(self, stage_note: str,
                       timeout: float = 180.0) -> dict:
        """Run one real agent process cycle; return the captured report body."""
        before = self.proxy.report_count()
        result = lab.run_capture(
            [self.agent_bin, "run", "--once"] + self.agent_flags(),
            timeout=timeout)
        if result.returncode != 0:
            raise lab.LabError(
                "um-agent --once failed (%s):\n%s"
                % (stage_note,
                   ((result.stdout or "") + (result.stderr or ""))[-4000:]))
        lab.wait_until(lambda: self.proxy.report_count() > before, timeout=30,
                       interval=0.1,
                       description="the agent report to reach the center "
                                   "through the capture proxy")
        captured = self.proxy.last_report()
        if captured is None:
            raise lab.LabError("capture proxy lost the agent report")
        try:
            report = json.loads(captured["body"].decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise lab.LabError("agent report body is not valid JSON: %s" % exc)
        self.report_history.append({
            "stage": self.current_stage, "note": stage_note,
            "report": report, "raw": captured["body"],
        })
        return report

    def save_export(self, note: str, normalized=None) -> dict:
        normalized = normalized or lab.wait_for_export(self.export_path, 20)
        raw = normalized.get("raw_bytes", b"")
        findings = lab.privacy_scan_export(normalized["raw"], raw,
                                           self.creds.secret_values())
        if findings:
            raise lab.LabAssertionFailed(
                "[%s] monitor export leaked private data: %r"
                % (self.current_stage, findings))
        index = len(self.export_samples) + 1
        lab.copy_json_artifact(
            normalized["raw"],
            os.path.join(self.evidence_dir, "export-%02d-%s.json"
                         % (index, re.sub(r"[^A-Za-z0-9._-]+", "-", note))))
        sample = {
            "note": note,
            "source_epoch": normalized["source_epoch"],
            "sequence": normalized["sequence"],
            "generated_at": normalized["generated_at"],
            "observed_at": normalized["observed_at"],
            "monitor_stale": normalized["monitor_stale"],
            "active_connections": normalized["active_connections"],
            "rate_window_seconds": normalized["rate_window_seconds"],
            "inbounds": normalized["inbounds"],
            "index": index,
        }
        self.export_samples.append(sample)
        self._last_export = normalized
        return normalized

    def wait_export_lower_bounds(self, minimums: dict, timeout: float = 30.0,
                                 description: str = "") -> dict:
        """Wait until the export reports at least these per-tag/dir lower bounds."""
        def _satisfied():
            try:
                normalized = lab.validate_export_file(self.export_path)
            except lab.LabAssertionFailed:
                return None
            for (tag, direction), minimum in minimums.items():
                value = lab.export_observed(normalized, tag, direction)
                if value is None or value < minimum:
                    return None
            return normalized
        normalized = lab.wait_until(
            _satisfied, timeout, 0.2,
            description or ("the export lower bounds %r" % minimums))
        return self.save_export("lower-bounds-%s"
                                % re.sub(r"[^A-Za-z0-9._-]+", "-",
                                         description or "observed"),
                                normalized)

    def wait_export_matches(self, predicate, timeout: float = 30.0,
                            description: str = "") -> dict:
        def _check():
            try:
                normalized = lab.validate_export_file(self.export_path)
            except lab.LabAssertionFailed:
                return None
            return normalized if predicate(normalized) else None
        return lab.wait_until(_check, timeout, 0.2, description)

    def agent_status(self) -> dict:
        result = lab.run_capture([self.agent_bin, "status",
                                  "--state-dir", self.agent_state_dir],
                                 timeout=60)
        if result.returncode != 0:
            raise lab.LabError("um-agent status failed:\n%s"
                               % ((result.stdout or "")
                                  + (result.stderr or ""))[-2000:])
        try:
            return json.loads(result.stdout)
        except ValueError as exc:
            raise lab.LabError("um-agent status returned non-JSON: %r"
                               % result.stdout[:500]) from exc

    def proxy_requests_summary(self) -> str:
        if self.proxy is None:
            return "capture proxy not running"
        return "captured requests: %s" % json.dumps(
            self.proxy.request_counts(), sort_keys=True)

    def monitor_start(self) -> None:
        command = lab.monitor_serve_command(
            self.args.python, WEBAPP_PATH, self.monitor_data_dir,
            self.ports.monitor_web, self.ports.service_api,
            self.secret_file, poll=0.5, interval=0.5, closed_ttl=120.0,
            export_file=self.export_path,
            export_inbounds=lab.EXPECTED_TAGS,
            health_file=self.health_file)
        self.monitor_proc = self._start_process("monitor-traffic-export",
                                                command, cwd=MONITOR_DIR)

    def monitor_restart(self, export_inbounds=None) -> None:
        self._stop_process(self.monitor_proc, "monitor-traffic-export")
        self.monitor_proc = None
        if export_inbounds is not None:
            command = lab.monitor_serve_command(
                self.args.python, WEBAPP_PATH, self.monitor_data_dir,
                self.ports.monitor_web, self.ports.service_api,
                self.secret_file, poll=0.5, interval=0.5, closed_ttl=120.0,
                export_file=self.export_path,
                export_inbounds=export_inbounds,
                health_file=self.health_file)
            self.monitor_proc = self._start_process(
                "monitor-traffic-export", command, cwd=MONITOR_DIR)
        else:
            self.monitor_start()

    def wait_monitor_ready(self, timeout: float = 45.0) -> dict:
        snapshot = self.monitor.wait_ready(timeout)
        normalized = lab.wait_for_export(
            self.export_path, timeout,
            predicate=lambda doc: not doc["monitor_stale"],
            description="a fresh monitor traffic export")
        self.current_monitor_epoch = normalized["source_epoch"]
        self.monitor_epoch_baselines.setdefault(
            normalized["source_epoch"], self.ledger_snapshot())
        self.check("traffic export enabled:" in self.monitor_proc.log_tail(20000),
                   "enabled monitor logged exactly the restricted-export "
                   "writer activation")
        self.save_export("monitor-ready", normalized)
        self.record("monitor_snapshot_top_keys",
                    sorted(snapshot.keys())[:24])
        return snapshot

    def ledger_snapshot(self) -> dict:
        return {
            "downloads": dict(self.ledger.downloads),
            "uploads": dict(self.ledger.uploads),
        }

    # -- traffic helpers -----------------------------------------------------
    def _socks_port(self, protocol: str) -> int:
        if protocol == "reality":
            return self.ports.socks_reality
        if protocol == "hysteria2":
            return self.ports.socks_hysteria2
        raise lab.LabError("unknown protocol %r" % protocol)

    def _inbound_tag(self, protocol: str) -> str:
        if protocol == "reality":
            return lab.REALITY_TAG
        if protocol == "hysteria2":
            return lab.HYSTERIA2_TAG
        raise lab.LabError("unknown protocol %r" % protocol)

    def produce(self, protocol: str, phase: str, download_bytes: int = 0,
                upload_bytes: int = 0, timeout: float = 180.0,
                expect_ok: bool = True) -> list[dict]:
        """Send traffic through the real protocol and measure payload bytes."""
        tag = self._inbound_tag(protocol)
        socks = self._socks_port(protocol)
        results = []
        http_base = "http://127.0.0.1:%d" % self.ports.http_fixture
        if download_bytes:
            result = lab.run_curl_socks(
                socks, http_base + "/payload/%d" % download_bytes,
                max_time=timeout)
            if expect_ok:
                self.check(result.ok,
                           "real %s download of %s succeeded (http=%d rc=%d)"
                           % (protocol, lab.format_bytes(download_bytes),
                              result.http_code, result.returncode),
                           evidence={"stderr": result.stderr})
                self.check_eq(result.size_download, download_bytes,
                              "%s measured download payload" % protocol)
                self.ledger.record(tag, "downlink", result.size_download,
                                   phase=phase, note="download")
            results.append({"protocol": protocol, "direction": "downlink",
                            "measured": result.size_download,
                            "http_code": result.http_code,
                            "ok": result.ok})
        if upload_bytes:
            result = lab.run_curl_socks(
                socks, http_base + "/upload/echo", method="POST",
                upload_bytes=b"U" * upload_bytes, max_time=timeout)
            if expect_ok:
                self.check(result.ok,
                           "real %s upload of %s succeeded (http=%d rc=%d)"
                           % (protocol, lab.format_bytes(upload_bytes),
                              result.http_code, result.returncode),
                           evidence={"stderr": result.stderr})
                self.check_eq(result.size_upload, upload_bytes,
                              "%s measured upload payload" % protocol)
                self.ledger.record(tag, "uplink", result.size_upload,
                                   phase=phase, note="upload")
            results.append({"protocol": protocol, "direction": "uplink",
                            "measured": result.size_upload,
                            "http_code": result.http_code,
                            "ok": result.ok})
        return results

    def produce_async(self, protocol: str, phase: str, path: str,
                      extra_args=None) -> threading.Thread:
        socks = self._socks_port(protocol)
        tag = self._inbound_tag(protocol)
        http_base = "http://127.0.0.1:%d" % self.ports.http_fixture
        captured = {}

        def _run():
            result = lab.run_curl_socks(
                socks, http_base + path, max_time=120.0,
                extra_args=extra_args)
            captured["result"] = result
            if result.ok:
                direction = ("downlink" if path.startswith("/payload")
                             else "downlink")
                self.ledger.record(tag, direction, result.size_download,
                                   phase=phase, note=path)

        thread = threading.Thread(target=_run, name="traffic-%s" % protocol,
                                  daemon=True)
        thread.captured = captured  # type: ignore[attr-defined]
        thread.start()
        return thread

    def export_current(self) -> dict:
        return lab.validate_export_file(self.export_path)

    def export_observed(self, normalized: dict, tag: str,
                        direction: str):
        return lab.export_observed(normalized, tag, direction)

    def assert_directional_lower_bound(self, normalized: dict, tag: str,
                                       direction: str, minimum: int,
                                       context: str) -> None:
        observed = self.export_observed(normalized, tag, direction)
        self.check(observed is not None and observed >= minimum,
                   "%s: %s %s observed lower bound >= measured %s (got %r)"
                   % (context, tag, direction, lab.format_bytes(minimum),
                      observed), evidence={"minimum": minimum,
                                           "observed": observed})

    def assert_no_fabricated_peak(self, normalized: dict, tag: str,
                                  direction: str, context: str) -> None:
        measured = self.ledger.expected(tag, direction)
        maximum = measured + lab.overhead_tolerance(measured)
        observed = self.export_observed(normalized, tag, direction)
        if observed is None:
            return
        self.check(observed <= maximum,
                   "%s: %s %s observed %s is bounded by the measured payload "
                   "totals %s (+overhead tolerance); no fabricated peak or "
                   "cross-epoch double count"
                   % (context, tag, direction, lab.format_bytes(observed),
                      lab.format_bytes(measured)),
                   evidence={"observed": observed, "measured": measured,
                             "maximum": maximum})

    def assert_monitor_alive(self, context: str) -> None:
        status = self.monitor.health()
        self.check_eq(status, 200, "%s: monitor dashboard HTTP liveness"
                      % context)
        status, session = self.monitor.session()
        self.check(status == 200 and isinstance(session, dict)
                   and session.get("monitor_running"),
                   "%s: monitor /api/v1/session reports a running monitor"
                   % context)
        self.monitor.login()
        status, snapshot = self.monitor.snapshot()
        self.check(status == 200 and isinstance(snapshot, dict),
                   "%s: authenticated loopback dashboard snapshot stays "
                   "available while export is enabled" % context)

    # -- center helpers ------------------------------------------------------
    def admin(self, args: list) -> dict:
        return lab.run_admin_cli(self.center_bin, self.center_admin_url,
                                 self.center_token_file, args)

    def update_center_config(self, monitor_export_enabled: bool,
                             tags=lab.EXPECTED_TAGS) -> dict:
        sources = lab.build_collect_sources(monitor_export_enabled)
        tags_json = json.dumps(lab.build_expected_tags(tags))
        args = ["config", "update", self.event_id, self.node_id,
                "--cadence", "30", "--sources", json.dumps(sources),
                "--tags", tags_json]
        try:
            config = self.admin(args)
        except lab.LabError as exc:
            message = str(exc)
            if ("monitor_export" in message or "source" in message.lower()
                    or "unknown" in message.lower() or "invalid" in
                    message.lower()):
                skip_or_fail(
                    "the center rejected the rev-7 `collect.monitor_export` "
                    "config source; the lab requires the integrated rev-7 "
                    "center. Center said: %s" % message)
            raise
        self.record("last_center_config", {
            "monitor_export": monitor_export_enabled,
            "tags": lab.build_expected_tags(tags),
        })
        return config

    def db_rows(self) -> dict:
        connection = lab.open_sqlite_readonly(self.center_db)
        try:
            reports = lab.fetch_traffic_reports(connection)
            observations = lab.fetch_traffic_observations(connection)
            version = lab.sqlite_schema_version(connection)
            columns = {
                "reports": lab.sqlite_table_columns(
                    connection, lab.TRAFFIC_REPORT_TABLE)
                if lab.sqlite_table_exists(connection,
                                           lab.TRAFFIC_REPORT_TABLE) else [],
                "observations": lab.sqlite_table_columns(
                    connection, lab.TRAFFIC_OBSERVATION_TABLE)
                if lab.sqlite_table_exists(connection,
                                           lab.TRAFFIC_OBSERVATION_TABLE)
                else [],
            }
        finally:
            connection.close()
        return {"reports": reports, "observations": observations,
                "schema_version": version, "columns": columns}

    def traffic_tables_present(self) -> dict:
        rows = self.db_rows()
        if not rows["columns"]["reports"]:
            skip_or_fail(
                "the center store has no %r table (schema_version=%r): the "
                "integrated rev-7 center migration/storage is required"
                % (lab.TRAFFIC_REPORT_TABLE, rows["schema_version"]))
        if not rows["columns"]["observations"]:
            skip_or_fail(
                "the center store has no %r table: the integrated rev-7 "
                "center migration/storage is required"
                % lab.TRAFFIC_OBSERVATION_TABLE)
        return rows

    # -- stage bookkeeping ---------------------------------------------------
    def run_stage(self, name: str, function) -> None:
        self.stage(name)
        started = time.time()
        try:
            function()
        except Exception as exc:  # noqa: BLE001 - evidence first, then raise
            elapsed = time.time() - started
            self.stage_results.append({
                "stage": name, "status": "failed",
                "elapsed_seconds": round(elapsed, 2),
                "error": "%s: %s" % (type(exc).__name__, exc),
            })
            self.echo("STAGE FAILED: %s (%s)" % (name, exc))
            raise
        elapsed = time.time() - started
        self.stage_results.append({
            "stage": name, "status": "passed",
            "elapsed_seconds": round(elapsed, 2),
        })
        self.echo("stage %s: PASS (%.1fs)" % (name, elapsed))

    # =====================================================================
    # Stages
    # =====================================================================
    def stage_agent_version_gate(self) -> None:
        """OD-LT-14: the optional source key is only emitted to rev-7 agents.

        The center records the agent version from the first authenticated
        snapshot; until then the strict six-key config is emitted. The lab
        proves the real transition instead of assuming it.
        """
        stored = self.admin(["config", "show", self.event_id,
                            self.node_id])
        self.check_eq(stored.get("sources", {}).get(
            lab.AGENT_SOURCE_KEY), True,
            "center stores the operator-enabled monitor_export source "
            "switch")
        first = self.run_agent_once("version-gate-first-snapshot")
        first_parsed = lab.validate_rev7_snapshot_report(first)
        self.check(first_parsed.get("rev5") is True,
                   "before an authenticated rev-7 snapshot the center "
                   "emits the strict rev-5 six-key config and the agent "
                   "emits a rev-5 body")
        self.check("traffic_observation" not in first,
                   "first-snapshot body carries no traffic_observation")
        second = self.run_agent_once("version-gate-second-snapshot")
        second_parsed = lab.validate_rev7_snapshot_report(second)
        self.check_eq(second.get("contract_revision"), 7,
                      "after the authenticated snapshot the center "
                      "emits collect.monitor_export and the agent emits "
                      "the rev-7 body")
        self.check_eq(second_parsed["source"], lab.REPORT_SOURCE,
                      "rev-7 observation carries the report-only source "
                      "token")
        self.check_eq(second_parsed["freshness"], "unavailable",
                      "with no monitor export configured yet the source "
                      "is honestly unavailable (not zero-filled)")
        self.check_eq(second_parsed["inbounds"], [],
                      "unavailable source yields no invented inbound rows")
        self.record("agent_version_gate", {
            "first_body": "rev5",
            "second_body": "rev7",
            "second_freshness": second_parsed["freshness"],
        })

    def stage_default_disabled(self) -> None:
        """Monitor without export flags must not create/read the export path."""
        disabled_path = os.path.join(self.monitor_export_dir,
                                     "disabled", "traffic-export.json")
        lab.ensure_dir(os.path.dirname(disabled_path))
        command = lab.monitor_serve_command(
            self.args.python, WEBAPP_PATH, self.monitor_data_dir,
            self.ports.monitor_web, self.ports.service_api,
            self.secret_file, poll=0.5, interval=0.5, closed_ttl=120.0,
            export_file=None,
            health_file=os.path.join(self.monitor_export_dir,
                                     "disabled-health.json"))
        process = self._start_process("monitor-default-disabled", command,
                                      cwd=MONITOR_DIR)
        client = lab.MonitorWebClient(
            "http://127.0.0.1:%d" % self.ports.monitor_web,
            self.creds.monitor_admin_password)
        try:
            snapshot = client.wait_ready(45)
            self.check(isinstance(snapshot, dict) and snapshot,
                       "default-disabled monitor dashboard/snapshot healthy")
            time.sleep(2.0)
            self.check(not os.path.exists(disabled_path),
                       "monitor started without export flags never creates the "
                       "operator export path (feature completely off)")
            self.check("traffic export enabled:" not in
                       process.log_tail(20000),
                       "default-disabled monitor log shows no traffic-export "
                       "writer activation")
        finally:
            self._stop_process(process, "monitor-default-disabled")

    def stage_main_path(self) -> None:
        self.produce("reality", "main-path", download_bytes=6 * 1024 * 1024,
                     upload_bytes=1 * 1024 * 1024)
        self.produce("hysteria2", "main-path", download_bytes=8 * 1024 * 1024,
                     upload_bytes=2 * 1024 * 1024)
        minimums = {
            (lab.REALITY_TAG, "downlink"): 6 * 1024 * 1024,
            (lab.REALITY_TAG, "uplink"): 1 * 1024 * 1024,
            (lab.HYSTERIA2_TAG, "downlink"): 8 * 1024 * 1024,
            (lab.HYSTERIA2_TAG, "uplink"): 2 * 1024 * 1024,
        }
        normalized = self.wait_export_lower_bounds(
            minimums, timeout=45, description="main-path traffic to be banked")
        for (tag, direction), minimum in minimums.items():
            self.assert_directional_lower_bound(normalized, tag, direction,
                                                minimum, "main-path")
            self.assert_no_fabricated_peak(normalized, tag, direction,
                                           "main-path")
        self.check_eq(normalized["active_connections"], 0,
                      "main-path export active_connections settles to 0")
        self.assert_monitor_alive("main-path")
        report = self.run_agent_once("main-path")
        after = self.export_current()
        parsed = lab.validate_rev7_snapshot_report(report)
        self.check_eq(report.get("contract_revision"), 7,
                      "captured snapshot report declares contract_revision 7")
        self.check_eq(report.get("traffic"), [],
                      "captured rev-7 report keeps the frozen base traffic "
                      "array empty (lower bounds are not daemon-lifetime "
                      "totals)")
        self.check_eq(parsed["source_epoch"], after["source_epoch"],
                      "report observation source_epoch equals the live export "
                      "epoch")
        self.check_eq(parsed["freshness"], "fresh",
                      "report observation is fresh")
        self.check_eq(parsed["availability"], "ok",
                      "report observation availability is ok when both "
                      "authorized inbounds carry fresh lower bounds")
        self.check_eq(parsed["counter_scope"], lab.COUNTER_SCOPE,
                      "report observation counter scope is observation_epoch")
        self.check_eq(parsed["exactness"], lab.EXACTNESS,
                      "report observation exactness is lower_bound")
        rows = {row["inbound_tag"]: row for row in parsed["inbounds"]}
        for tag in (lab.REALITY_TAG, lab.HYSTERIA2_TAG):
            self.check(tag in rows, "report observation carries %r" % tag)
            row = rows.get(tag, {})
            minimum = minimums[(tag, "downlink")]
            self.check(row.get("downlink") is not None
                       and row["downlink"] >= minimum,
                       "report %r downlink lower bound >= measured %s"
                       % (tag, lab.format_bytes(minimum)))
            minimum_up = minimums[(tag, "uplink")]
            self.check(row.get("uplink") is not None
                       and row["uplink"] >= minimum_up,
                       "report %r uplink lower bound >= measured %s"
                       % (tag, lab.format_bytes(minimum_up)))
            self.check(row.get("quality") == "lower_bound",
                       "report %r quality is lower_bound" % tag)
        # Directional sanity: the export must not swap the two directions.
        for tag, minimums_row in (
                (lab.REALITY_TAG, (6 * 1024 * 1024, 1 * 1024 * 1024)),
                (lab.HYSTERIA2_TAG, (8 * 1024 * 1024, 2 * 1024 * 1024))):
            row = rows[tag]
            down_expected, up_expected = minimums_row
            self.check(row["downlink"] >= down_expected
                       and row["uplink"] >= up_expected,
                       "%r direction mapping: measured download maps to "
                       "downlink and upload to uplink (received down=%r "
                       "up=%r)" % (tag, row["downlink"], row["uplink"]))
        self.record("main_path_report_observation", {
            "source_epoch": parsed["source_epoch"],
            "sequence": parsed["sequence"],
            "freshness": parsed["freshness"],
            "availability": parsed["availability"],
            "inbounds": parsed["inbounds"],
        })
        self._saved_export = after

    def stage_center_query(self) -> None:
        rows = self.traffic_tables_present()
        reports = rows["reports"]
        observations = rows["observations"]
        self.check(len(reports) >= 1,
                   "center store normalized at least one "
                   "traffic_observation_reports row (got %d)" % len(reports))
        self.check(len(observations) >= 2,
                   "center store normalized per-inbound traffic_observations "
                   "rows (got %d)" % len(observations))
        series = lab.traffic_series(observations)
        tags_seen = {tag for (_epoch, tag) in series}
        for tag in (lab.REALITY_TAG, lab.HYSTERIA2_TAG):
            self.check(tag in tags_seen,
                       "center store carries a normalized series for %r" % tag)
        for row in reports:
            self.check_eq(row.get("source"), lab.REPORT_SOURCE,
                          "stored observation report source is the "
                          "report-only token")
            self.check_eq(row.get("counter_scope"), lab.COUNTER_SCOPE,
                          "stored observation report counter_scope")
            self.check_eq(row.get("exactness"), lab.EXACTNESS,
                          "stored observation report exactness")
        for row in observations:
            self.check(row.get("observed_at") is not None,
                       "stored observation row carries observed_at")
            self.check(row.get("quality") in lab.QUALITIES or
                       row.get("quality") is None,
                       "stored observation quality is a frozen token")
        latest = lab.latest_traffic_values(observations)
        for tag, minimum in ((lab.REALITY_TAG, 6 * 1024 * 1024),
                             (lab.HYSTERIA2_TAG, 8 * 1024 * 1024)):
            candidates = [row for (epoch, series_tag), row in latest.items()
                          if series_tag == tag]
            self.check(candidates,
                       "center store has a latest observation row for %r" % tag)
            best = max(candidates,
                       key=lambda row: row.get(
                           "downlink_observed_lower_bound_bytes") or 0)
            self.check((best.get("downlink_observed_lower_bound_bytes") or 0)
                       >= minimum,
                       "stored %r downlink lower bound >= measured %s"
                       % (tag, lab.format_bytes(minimum)))
            self.check((best.get("uplink_observed_lower_bound_bytes") or 0)
                       > 0, "stored %r uplink lower bound is present" % tag)
        # Store must not be a raw-export carrier: the traffic tables' column
        # allow-list and values are checked for forbidden sentinels/IPs.
        required_report_columns = {
            "node_id", "event_id", "report_id", "source", "source_epoch",
            "sequence", "observed_at", "collected_at", "availability",
            "freshness", "counter_scope", "exactness",
        }
        required_observation_columns = {
            "report_row_id", "inbound_tag", "kind", "observed_at",
            "availability", "quality",
            "uplink_observed_lower_bound_bytes",
            "downlink_observed_lower_bound_bytes",
        }
        forbidden_column_re = re.compile(
            r"(raw|json|payload|secret|token|passwd|password|private|"
            r"addr|dest|user|device|uuid|hostname|url)", re.I)
        missing_report = required_report_columns - set(
            rows["columns"]["reports"])
        missing_observations = required_observation_columns - set(
            rows["columns"]["observations"])
        self.check(not missing_report,
                   "center traffic_observation_reports has the required "
                   "normalized columns (missing: %r; actual: %r)"
                   % (sorted(missing_report), rows["columns"]["reports"]))
        self.check(not missing_observations,
                   "center traffic_observations has the required "
                   "normalized columns (missing: %r; actual: %r)"
                   % (sorted(missing_observations),
                      rows["columns"]["observations"]))
        forbidden_columns = [
            column for column in (list(rows["columns"]["reports"])
                                 + list(rows["columns"]["observations"]))
            if forbidden_column_re.search(column)
            and not column.endswith("_id")]
        self.check(not forbidden_columns,
                   "center traffic tables store no raw IP/user/destination/"
                   "secret/raw-JSON columns (forbidden: %r)"
                   % sorted(set(forbidden_columns)))
        # No raw export JSON is stored: scan every column value of the two
        # tables for the export document tokens and privacy sentinels.
        sentinels = self.creds.secret_values()
        db_leaks = []
        for table, table_rows in (("reports", reports),
                                  ("observations", observations)):
            for row in table_rows:
                blob = json.dumps({key: value for key, value in row.items()
                                   if key not in ("node_id", "event_id")})
                if "singbox-monitor-traffic-export" in blob:
                    db_leaks.append((table, "raw-export-document-token"))
                if "observed_uplink_bytes" in blob:
                    db_leaks.append((table, "raw-export-member"))
                for finding in lab.scan_for_sentinels(
                        blob.encode("utf-8"), sentinels):
                    db_leaks.append((table, "secret-sentinel"))
                for finding in lab.scan_document_for_network_literals(
                        json.loads(blob)):
                    db_leaks.append((table, finding["kind"]))
        self.check(not db_leaks,
                   "normalized center rows store no raw export document, "
                   "secret sentinel or raw network literal",
                   evidence={"findings": db_leaks[:20]})
        # Admin query surface: node-show must expose the rev-7 observation.
        node_view = self.admin(["node", "show", self.event_id, self.node_id])
        snapshot = lab.extract_latest_snapshot(node_view)
        self.check(snapshot is not None,
                   "admin node-show returns the node's latest snapshot")
        revision = (snapshot or {}).get("contract_revision")
        self.check_eq(revision, 7,
                      "admin query surface returns the rev-7 snapshot body")
        observation = (snapshot or {}).get("traffic_observation") or {}
        parsed = lab.validate_rev7_snapshot_report(snapshot)
        self.check_eq(parsed["availability"], "ok",
                      "admin query surface observation availability ok")
        findings = lab.privacy_scan_report(
            snapshot, json.dumps(snapshot).encode("utf-8"),
            self.creds.secret_values(),
            allowed_report_id=snapshot.get("report_id"))
        self.check(not findings,
                   "stored/query-returned rev-7 snapshot body leaks no private "
                   "data", evidence={"findings": findings})
        # Fail-closed web query route: without a Cloudflare Access JWT the
        # origin must reject before any store/query work. Authenticated RBAC
        # query behavior is covered by the Go web tests, not by this offline
        # lab (documented limitation).
        query_paths = ["/web/api/traffic/latest", "/api/traffic/latest"]
        statuses = {}
        for path in query_paths:
            url = ("%s%s?event_id=%s&node_id=%s&limit=10"
                   % (self.center_web_url, path,
                      urllib.parse.quote(self.event_id),
                      urllib.parse.quote(self.node_id)))
            status, body = lab.http_get(url, timeout=15)
            statuses[path] = status
            self.check(status in (401, 403),
                       "web traffic query route %s fails closed without "
                       "Cloudflare Access credentials (status=%d)"
                       % (path, status), evidence={"body": body[:400]})
            self.check(not any(token in body for token in
                               (b"uplink_observed_lower_bound_bytes",
                                b"downlink_observed_lower_bound_bytes",
                                b"traffic_observation")),
                       "unauthenticated query response carries no traffic data")
        self.check(any(status in (401, 403) for status in statuses.values()),
                   "at least one documented /web/api/traffic/* route exists "
                   "and is fail-closed (statuses=%r)" % statuses)
        self.record("center_store", {
            "schema_version": rows["schema_version"],
            "report_rows": len(reports),
            "observation_rows": len(observations),
            "series": [{"source_epoch": key[0][:8] + "...",
                        "inbound_tag": key[1],
                        "max_uplink": value["max_uplink_lower_bound"],
                        "max_downlink": value["max_downlink_lower_bound"]}
                       for key, value in series.items()],
            "web_query_statuses": statuses,
        })
        # Persist sanitized DB evidence for CI.
        lab.copy_json_artifact(
            {"reports": [{key: value for key, value in row.items()
                          if key not in ("node_id", "event_id")}
                         for row in reports],
             "observations": [{key: value for key, value in row.items()
                               if key not in ("node_id", "event_id")}
                              for row in observations]},
            os.path.join(self.evidence_dir, "center-store-rows.json"))

    def stage_monitor_restart(self) -> None:
        old = self.wait_export_matches(lambda doc: True, timeout=10,
                                       description="the pre-restart export")
        old_epoch = old["source_epoch"]
        old_sequence = old["sequence"]
        old_ledger = self.ledger_snapshot()
        self._stop_process(self.monitor_proc, "monitor-traffic-export")
        self.monitor_proc = None
        # Leave a stale complete export from the previous process behind; the
        # monitor must remove it at startup and publish a new epoch.
        lab.write_json(self.export_path, old["raw"])
        self.monitor_start()
        fresh = lab.wait_for_export(
            self.export_path, 45,
            predicate=lambda doc: doc["source_epoch"] != old_epoch
            and not doc["monitor_stale"],
            description="a new monitor observation epoch")
        self.check(fresh["source_epoch"] != old_epoch,
                   "monitor restart generates a new source_epoch (old=%s new=%s)"
                   % (old_epoch[:8], fresh["source_epoch"][:8]))
        self.check(fresh["sequence"] <= 4,
                   "restarted monitor sequence restarts at the new epoch "
                   "(sequence=%d)" % fresh["sequence"])
        self.current_monitor_epoch = fresh["source_epoch"]
        self.monitor_epoch_baselines.setdefault(
            fresh["source_epoch"], self.ledger_snapshot())
        self.monitor.wait_ready(45)
        self.produce("reality", "monitor-restart", download_bytes=512 * 1024)
        self.produce("hysteria2", "monitor-restart", download_bytes=512 * 1024)
        normalized = self.wait_export_lower_bounds({
            (lab.REALITY_TAG, "downlink"): 512 * 1024,
            (lab.HYSTERIA2_TAG, "downlink"): 512 * 1024,
        }, timeout=30, description="restarted monitor to observe traffic")
        self.assert_no_fabricated_peak(normalized, lab.REALITY_TAG,
                                       "downlink", "monitor-restart")
        self.assert_no_fabricated_peak(normalized, lab.HYSTERIA2_TAG,
                                       "downlink", "monitor-restart")
        self.assert_monitor_alive("monitor-restart")
        report = self.run_agent_once("monitor-restart")
        parsed = lab.validate_rev7_snapshot_report(report)
        self.check_eq(parsed["source_epoch"], fresh["source_epoch"],
                      "agent report after monitor restart carries the new "
                      "source_epoch")
        self.check(parsed["freshness"] == "fresh"
                   and parsed["availability"] == "ok",
                   "agent after monitor restart reports fresh/ok observation")
        rows = self.traffic_tables_present()
        epochs = {row.get("source_epoch") for row in rows["reports"]}
        self.check(old_epoch in epochs and fresh["source_epoch"] in epochs,
                   "center store keeps both observation epochs as separate "
                   "normalized rows (never sums them)")
        self.check(len(rows["reports"]) >= len(self.report_history) - 1,
                   "center stored one row per accepted snapshot report")
        self.record("monitor_restart", {
            "old_epoch_prefix": old_epoch[:8],
            "new_epoch_prefix": fresh["source_epoch"][:8],
            "old_sequence": old_sequence,
            "new_sequence": fresh["sequence"],
        })

    def stage_singbox_reset(self) -> None:
        # -- stop the real server: monitor must honestly degrade to stale ----
        self._stop_process(self.server_proc, "singbox-server")
        self.server_proc = None
        stale = self.wait_export_matches(
            lambda doc: doc["monitor_stale"], timeout=45,
            description="the monitor to declare stale after the real "
                        "sing-box server stops")
        for row in stale["inbounds"]:
            self.check_eq(row["quality"], "partial",
                          "stale export row %r degrades to partial (never "
                          "fresh)" % row["inbound_tag"])
            self.check(row["uplink_rate"] is None
                       and row["downlink_rate"] is None,
                       "stale export row %r carries no fabricated rates"
                       % row["inbound_tag"])
        report = self.run_agent_once("server-down")
        parsed = lab.validate_rev7_snapshot_report(report)
        if stale["inbounds"]:
            self.check_eq(parsed["freshness"], "stale",
                          "agent downgrades monitor_stale export to stale")
            self.check_eq(parsed["availability"], "partial",
                          "stale observed export downgrades availability to "
                          "partial (never fresh/ok)")
        else:
            # Producer rule: a stale export omits configured tags that were
            # never observed, so the agent must emit the honest unavailable
            # sentinel instead of inventing rows.
            self.check_eq(parsed["freshness"], "unavailable",
                          "stale export with no observed rows degrades to the "
                          "unavailable sentinel")
            self.check_eq(parsed["inbounds"], [],
                          "stale empty export invents no inbound rows")
        # -- restart the real server: recovery without fake peaks -------------
        self.server_proc = self._start_process(
            "singbox-server",
            [self.singbox_bin, "run", "-c", self.config_paths["server"]])
        if not lab.wait_port("127.0.0.1", self.ports.reality_tcp, timeout=30):
            raise lab.LabError("real Reality inbound did not recover after "
                               "sing-box restart\n%s"
                               % self.server_proc.log_tail(4000))
        self._restart_singbox_clients()
        self.produce("reality", "post-reset", download_bytes=1024 * 1024)
        self.produce("hysteria2", "post-reset", download_bytes=1024 * 1024)
        recovered = self.wait_export_matches(
            lambda doc: not doc["monitor_stale"], timeout=45,
            description="the monitor to recover a fresh export")
        self.check(not recovered["monitor_stale"],
                   "monitor recovers to a fresh export after the real server "
                   "restarts")
        recovered = self.wait_export_lower_bounds({
            (lab.REALITY_TAG, "downlink"): 1024 * 1024,
            (lab.HYSTERIA2_TAG, "downlink"): 1024 * 1024,
        }, timeout=30, description="post-restart traffic to be banked")
        for tag in (lab.REALITY_TAG, lab.HYSTERIA2_TAG):
            self.assert_no_fabricated_peak(recovered, tag, "downlink",
                                           "singbox-reset-recovery")
        # Real business traffic must still work after the reset/recovery.
        self.produce("reality", "post-reset-check", download_bytes=64 * 1024)
        self.produce("hysteria2", "post-reset-check", download_bytes=64 * 1024)
        self.assert_monitor_alive("singbox-reset")
        # A second real client restart after recovery must also preserve
        # business traffic (new processes, same synthetic credentials).
        self._restart_singbox_clients()
        self.produce("reality", "post-client-reset",
                     download_bytes=128 * 1024)
        self.produce("hysteria2", "post-client-reset",
                     download_bytes=128 * 1024)
        self.record("singbox_reset", {
            "stale_export_sequence": stale["sequence"],
            "stale_rows": [{"tag": row["inbound_tag"],
                            "quality": row["quality"]}
                           for row in stale["inbounds"]],
            "recovered": True,
        })

    def stage_export_tamper(self) -> None:
        old = self.wait_export_matches(lambda doc: True, timeout=10,
                                       description="the current export")
        self._stop_process(self.monitor_proc, "monitor-traffic-export")
        self.monitor_proc = None
        reports_before = len(self.db_rows()["reports"])
        observations_before = len(self.db_rows()["observations"])
        # (a) truncated export -> honest unavailable observation, no crash.
        with open(self.export_path, "wb") as handle:
            handle.write(b'{"schema":"singbox-monitor-traffic-export","schema_ver')
        report = self.run_agent_once("export-truncated")
        parsed = lab.validate_rev7_snapshot_report(report)
        self.check_eq(parsed["freshness"], "unavailable",
                      "truncated export degrades to freshness=unavailable")
        self.check_eq(parsed["availability"], "unavailable",
                      "truncated export degrades to availability=unavailable")
        self.check_eq(parsed["source_epoch"], lab.ZERO_SOURCE_EPOCH,
                      "unavailable observation uses the all-zero sentinel "
                      "epoch (never a fabricated source epoch)")
        self.check_eq(parsed["inbounds"], [],
                      "truncated export yields an empty observation, not "
                      "invented rows or zeros")
        rows = self.db_rows()
        self.check_eq(len(rows["reports"]), reports_before + 1,
                      "truncated export report is still stored as an honest "
                      "unavailable observation report")
        self.check_eq(len(rows["observations"]), observations_before,
                      "truncated export stores no invented per-inbound rows")
        # (b) old but structurally valid export -> stale, counters retained.
        old_document = old["raw"]
        now = int(time.time())
        old_document["generated_at"] = now - 3500
        old_document["observed_at"] = now - 3600
        old_document["monitor_last_success_at"] = now - 3500
        old_document["monitor_stale"] = False
        for row in old_document["inbounds"]:
            row["observed_at"] = now - 3600
        lab.write_json(self.export_path, old_document)
        report = self.run_agent_once("export-old")
        parsed = lab.validate_rev7_snapshot_report(report)
        self.check_eq(parsed["freshness"], "stale",
                      "an old structurally valid export is stale, never fresh")
        self.check(parsed["availability"] in ("partial", "unavailable"),
                   "old export availability is downgraded (got %r)"
                   % parsed["availability"])
        if parsed["availability"] == "partial":
            # The agent keeps the validated per-inbound lower-bound quality
            # on a stale export (the observation is stale, not the counter
            # provenance), but it must never present observed data as zero
            # and never claim freshness. Availability is always <= partial.
            self.check(any(row.get("uplink") is not None
                           or row.get("downlink") is not None
                           for row in parsed["inbounds"]),
                       "stale observation retains observed lower-bound "
                       "counters (never zero-filled)")
        # (c) missing export -> unavailable sentinel again.
        os.unlink(self.export_path)
        report = self.run_agent_once("export-missing")
        parsed = lab.validate_rev7_snapshot_report(report)
        self.check_eq(parsed["availability"], "unavailable",
                      "missing export degrades to availability=unavailable")
        self.check_eq(parsed["source_epoch"], lab.ZERO_SOURCE_EPOCH,
                      "missing export uses the all-zero sentinel epoch")
        # Restore a real monitor and prove normal observation resumes.
        self.monitor_start()
        self.wait_monitor_ready(60)
        self.produce("reality", "post-tamper", download_bytes=256 * 1024)
        self.produce("hysteria2", "post-tamper", download_bytes=256 * 1024)
        fresh = self.wait_export_lower_bounds({
            (lab.REALITY_TAG, "downlink"): 256 * 1024,
            (lab.HYSTERIA2_TAG, "downlink"): 256 * 1024,
        }, timeout=30, description="monitor recovery after tamper stage")
        self.check(not fresh["monitor_stale"],
                   "monitor recovers a fresh export after the tamper stage")
        self.record("export_tamper", {
            "truncated": "unavailable-sentinel",
            "old_valid": "stale-lower-bound",
            "missing": "unavailable-sentinel",
        })

    def stage_replay_duplicate(self) -> None:
        # Capture a fresh signed report so the replay timestamp is inside
        # the center freshness window (a verbatim replay must be judged as
        # a duplicate, not as a stale timestamp).
        self.run_agent_once("replay-baseline")
        captured, probe_report = self._last_snapshot_report()
        if captured is None or probe_report is None:
            raise lab.LabError("no snapshot report was captured by the "
                               "proxy before the replay stage")
        rows_before = self.db_rows()
        report_id = probe_report.get("report_id")
        self.check(bool(report_id), "captured report has a report_id")
        status, response_body = lab.replay_raw_http_request(
            captured["request"], "127.0.0.1", self.ports.center_ingest)
        self.check_eq(status, 200, "verbatim replay is acknowledged (HTTP 200)")
        try:
            acknowledgement = json.loads(response_body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise lab.LabError("replay acknowledgement is not JSON: %s" % exc)
        self.check_eq(acknowledgement.get("result"), "duplicate",
                      "verbatim replay returns result=duplicate (not accepted)")
        rows_after = self.db_rows()
        self.check_eq(len(rows_after["reports"]), len(rows_before["reports"]),
                      "replay stores no duplicate traffic observation report")
        self.check_eq(len(rows_after["observations"]),
                      len(rows_before["observations"]),
                      "replay stores no duplicate normalized observation rows")
        ids_before = [row.get("report_id") for row in rows_before["reports"]]
        ids_after = [row.get("report_id") for row in rows_after["reports"]]
        self.check_eq(len(ids_after), len(set(ids_after)),
                      "center report rows keep unique report_id values after "
                      "replay")
        self.check(ids_before == ids_after,
                   "replay never rewrites already-committed report rows")
        # Replay a second time: still duplicate, still exactly-once.
        status2, body2 = lab.replay_raw_http_request(
            captured["request"], "127.0.0.1", self.ports.center_ingest)
        rows_third = self.db_rows()
        self.check(status2 == 200
                   and json.loads(body2.decode("utf-8")).get("result")
                   == "duplicate",
                   "second replay of the same report is still duplicate")
        self.check_eq(len(rows_third["observations"]),
                      len(rows_before["observations"]),
                      "double replay stores no duplicated observations")
        self.record("replay_duplicate", {
            "report_id_present": True,
            "ack_result": "duplicate",
            "report_rows": len(rows_after["reports"]),
            "observation_rows": len(rows_after["observations"]),
        })

    def stage_agent_center_spool(self) -> None:
        if self.continuous_agent is not None:
            self._stop_process(self.continuous_agent, "um-agent-continuous")
        before_reports = len(self.proxy.reports())
        self.continuous_agent = self._start_process(
            "um-agent-continuous",
            [self.agent_bin, "run"] + self.agent_flags())
        lab.wait_until(lambda: len(self.proxy.reports()) > before_reports,
                       timeout=120, interval=0.25,
                       description="the continuous agent's first report")
        # Center outage: the agent keeps collecting and must spool durably.
        # The capture proxy is stopped FIRST so the agent sees a retryable
        # connection error rather than a proxy-generated 502.
        if self.proxy is not None:
            self.proxy.stop()
        self._stop_process(self.center_proc, "um-center")
        self.center_proc = None
        lab.wait_until(
            lambda: self._spooled_records() > 0, timeout=120, interval=0.5,
            description="the agent to spool a report while the center is down")
        pending = self._spooled_records()
        self.check(pending >= 1,
                   "agent spooled %d report(s) durably while the center was "
                   "offline" % pending)
        status = self.agent_status()
        self.check(status.get("pending", 0) >= 1,
                   "agent status reports pending spooled work during the "
                   "center outage")
        self.check(self.continuous_agent.alive(),
                   "agent stays alive and retrying while the center is down")
        # Center restart: spooled reports must drain exactly once.
        self.start_center()
        lab.wait_until(lambda: self._spooled_records() == 0, timeout=180,
                       interval=0.5,
                       description="the agent to drain its spool after the "
                                   "center restarts")
        rows = self.db_rows()
        report_ids = [row.get("report_id") for row in rows["reports"]]
        self.check_eq(len(report_ids), len(set(report_ids)),
                      "spool replay stored every report at most once "
                      "(unique report_ids)")
        self.check(len(rows["reports"]) >= 2,
                   "center committed the spooled report after restart (rows=%d)"
                   % len(rows["reports"]))
        # Agent restart: clean shutdown + restart must not duplicate data.
        reports_before_restart = len(rows["reports"])
        self._stop_process(self.continuous_agent, "um-agent-continuous")
        self.continuous_agent = None
        generation_before = self.agent_status().get("generation")
        captured_before = len(self.proxy.reports())
        self.continuous_agent = self._start_process(
            "um-agent-continuous",
            [self.agent_bin, "run"] + self.agent_flags())
        lab.wait_until(lambda: len(self.proxy.reports()) > captured_before,
                       timeout=120, interval=0.25,
                       description="the restarted agent's first report")
        lab.wait_until(lambda: len(self.db_rows()["reports"])
                       > reports_before_restart, timeout=120, interval=0.5,
                       description="the restarted agent report to be committed")
        status_after = self.agent_status()
        self.check(status_after.get("generation", 0) > (generation_before or 0),
                   "agent restart advances the boot generation")
        rows_after = self.db_rows()
        report_ids_after = [row.get("report_id")
                            for row in rows_after["reports"]]
        self.check_eq(len(report_ids_after), len(set(report_ids_after)),
                      "agent restart does not duplicate report rows")
        self._stop_process(self.continuous_agent, "um-agent-continuous")
        self.continuous_agent = None
        self.record("agent_center_spool", {
            "spooled_while_offline": pending,
            "reports_after_drain": len(rows["reports"]),
            "generation_advanced": True,
        })

    def _spooled_records(self) -> int:
        spool = os.path.join(self.agent_state_dir, "spool")
        try:
            return len([name for name in os.listdir(spool)
                        if name.endswith(".json")])
        except OSError:
            return 0

    def _last_snapshot_report(self):
        for item in reversed(self.proxy.reports()):
            try:
                report = json.loads(item["body"].decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                continue
            if report.get("type") == "snapshot":
                return item, report
        return None, None

    def stage_config_source(self) -> None:
        rows_before = self.traffic_tables_present()
        reports_before = len(rows_before["reports"])
        observations_before = len(rows_before["observations"])
        # Disable the center-managed monitor_export source.
        self.update_center_config(False)
        config_view = self.admin(["config", "show", self.event_id,
                                  self.node_id])
        self.check_eq(config_view.get("sources", {}).get(
            lab.AGENT_SOURCE_KEY), False,
            "center config shows collect.monitor_export disabled")
        report = self.run_agent_once("source-disabled")
        parsed = lab.validate_rev7_snapshot_report(report)
        self.check(parsed.get("rev5") is True,
                   "agent with monitor_export disabled emits the rev-5 body "
                   "with no traffic_observation block")
        self.check("contract_revision" not in report,
                   "disabled source body carries no contract_revision")
        self.check_eq(report.get("traffic"), [],
                      "disabled source body keeps the frozen traffic array "
                      "empty")
        self.check_eq(report.get("availability", {}).get("traffic"),
                      "unavailable",
                      "disabled source honestly reports traffic unavailable")
        rows_after = self.traffic_tables_present()
        self.check_eq(len(rows_after["reports"]), reports_before,
                      "disabled source stores no traffic_observation_reports "
                      "row")
        self.check_eq(len(rows_after["observations"]), observations_before,
                      "disabled source stores no normalized observation rows")
        # Re-enable the source; observation must resume.
        self.update_center_config(True)
        config_view = self.admin(["config", "show", self.event_id,
                                  self.node_id])
        self.check_eq(config_view.get("sources", {}).get(
            lab.AGENT_SOURCE_KEY), True,
            "center config shows collect.monitor_export enabled again")
        report = self.run_agent_once("source-enabled")
        parsed = lab.validate_rev7_snapshot_report(report)
        self.check_eq(parsed["availability"], "ok",
                      "re-enabled source resumes a fresh lower-bound "
                      "observation")
        rows_resumed = self.traffic_tables_present()
        self.check(len(rows_resumed["reports"]) > reports_before,
                   "re-enabled source stores a new traffic observation report")
        self.check(len(rows_resumed["observations"]) > observations_before,
                   "re-enabled source stores normalized per-inbound rows")
        self.record("config_source", {
            "disabled_reports_delta": 0,
            "enabled_reports_after": len(rows_resumed["reports"]),
        })

    def stage_allowlist_change(self) -> None:
        # (a) monitor allow-list drops hy2-in while the center still authorizes
        # both: the agent must mark the missing expected tag unavailable, never
        # invent zero counters or move traffic across protocols.
        self.monitor_restart(export_inbounds=[(lab.REALITY_TAG,
                                               lab.REALITY_KIND)])
        self.wait_monitor_ready(60)
        self.produce("reality", "allowlist-shot", download_bytes=512 * 1024)
        self.produce("hysteria2", "allowlist-shot", download_bytes=768 * 1024)
        export_epoch = self.export_current()["source_epoch"]
        normalized = self.wait_export_lower_bounds(
            {(lab.REALITY_TAG, "downlink"): 512 * 1024}, timeout=30,
            description="allow-listed reality traffic")
        self.check(lab.export_row(normalized, lab.HYSTERIA2_TAG) is None,
                   "monitor export contains only operator-allow-listed inbound "
                   "tags (hy2-in is absent, not fabricated)")
        report = self.run_agent_once("allowlist-restricted")
        parsed = lab.validate_rev7_snapshot_report(report)
        rows = {row["inbound_tag"]: row for row in parsed["inbounds"]}
        self.check(lab.REALITY_TAG in rows,
                   "agent report keeps the observed allow-listed reality row")
        hy2_row = rows.get(lab.HYSTERIA2_TAG)
        self.check(hy2_row is not None,
                   "agent report still lists the center-authorized hy2-in "
                   "expected tag")
        self.check_eq(hy2_row.get("availability"), "unavailable",
                      "missing allow-listed inbound is honestly unavailable")
        self.check(hy2_row.get("uplink") is None
                   and hy2_row.get("downlink") is None,
                   "missing inbound carries null counters (never zero)")
        self.check_eq(parsed["availability"], "partial",
                      "observation availability downgrades to partial when an "
                      "authorized tag has no allow-listed data")
        self.check(parsed["source_epoch"] == export_epoch,
                   "agent read the allow-listed export epoch")
        # hy2 traffic was really sent but must not be attributed to reality.
        reality_row = rows[lab.REALITY_TAG]
        self.check(reality_row["downlink"] is not None
                   and reality_row["downlink"] < 512 * 1024 + 768 * 1024,
                   "hy2 traffic is not cross-attributed to the reality inbound")
        rows_db = self.traffic_tables_present()
        hy2_obs = [row for row in rows_db["observations"]
                   if row.get("inbound_tag") == lab.HYSTERIA2_TAG
                   and row.get("source_epoch") == export_epoch]
        self.check(not hy2_obs
                   or all((row.get("uplink_observed_lower_bound_bytes")
                           is None)
                          and (row.get("downlink_observed_lower_bound_bytes")
                               is None) for row in hy2_obs),
                   "center store has no fabricated hy2 byte counters for the "
                   "restricted allow-list epoch")
        # (b) center expected tags shrink to reality only: the agent emits only
        # the authorized row.
        self.update_center_config(True, tags=[(lab.REALITY_TAG,
                                               lab.REALITY_KIND)])
        report = self.run_agent_once("center-tags-reality-only")
        parsed = lab.validate_rev7_snapshot_report(
            report, expected_tags=((lab.REALITY_TAG, lab.REALITY_KIND),))
        tags_in_report = {row["inbound_tag"] for row in parsed["inbounds"]}
        self.check_eq(tags_in_report, {lab.REALITY_TAG},
                      "agent report lists exactly the center-authorized "
                      "expected tags")
        self.check_eq(parsed["availability"], "ok",
                      "observation availability recovers to ok when the "
                      "authorized tag is fully observed")
        # (c) restore both planes and prove hy2 attribution resumes.
        self.update_center_config(True)
        self.monitor_restart()
        self.wait_monitor_ready(60)
        self.produce("hysteria2", "allowlist-restored",
                     download_bytes=384 * 1024)
        normalized = self.wait_export_lower_bounds(
            {(lab.HYSTERIA2_TAG, "downlink"): 384 * 1024}, timeout=30,
            description="restored hy2 allow-list to resume")
        self.assert_no_fabricated_peak(normalized, lab.HYSTERIA2_TAG,
                                       "downlink", "allowlist-restored")
        report = self.run_agent_once("allowlist-restored")
        parsed = lab.validate_rev7_snapshot_report(report)
        rows = {row["inbound_tag"]: row for row in parsed["inbounds"]}
        self.check(rows.get(lab.HYSTERIA2_TAG, {}).get("quality")
                   == "lower_bound",
                   "restored allow-list resumes a real hy2 lower-bound row")
        self.record("allowlist_change", {
            "restricted_inbounds": [lab.REALITY_TAG],
            "missing_tag_quality": "unavailable",
            "restored": True,
        })

    def stage_connection_shapes(self) -> None:
        # Ensure a clean idle baseline before measuring active connections.
        lab.wait_until(
            lambda: self.export_current()["active_connections"] == 0,
            timeout=30, interval=0.25,
            description="an idle export before connection-shape checks")
        # short connections
        short = self.produce("reality", "shape-short", download_bytes=4096)
        short += self.produce("hysteria2", "shape-short", download_bytes=8192)
        self.check(all(result["ok"] for result in short),
                   "short single-request connections succeed on both protocols")
        # long-lived (slow) connection: active count must be plausible while
        # the transfer is in flight and settle back to zero afterwards.
        long_thread = self.produce_async(
            "reality", "shape-long", "/payload/%d" % (2 * 1024 * 1024),
            extra_args=["--limit-rate", "400k"])
        max_active = 0
        deadline = time.time() + 8
        while time.time() < deadline and long_thread.is_alive():
            try:
                doc = self.export_current()
            except lab.LabAssertionFailed:
                time.sleep(0.1)
                continue
            max_active = max(max_active, doc["active_connections"] or 0)
            time.sleep(0.2)
        long_thread.join(timeout=60)
        result = long_thread.captured.get("result")  # type: ignore[attr-defined]
        self.check(result is not None and result.ok,
                   "long-lived real connection completes through Reality")
        self.check(max_active >= 1,
                   "monitor export observed the in-flight long connection "
                   "(max active=%d)" % max_active)
        lab.wait_until(
            lambda: self.export_current()["active_connections"] == 0,
            timeout=30, interval=0.25,
            description="active connections to settle after the long transfer")
        # idle connection: headers sent, then no data for several seconds.
        idle_thread = self.produce_async(
            "hysteria2", "shape-idle", "/hold?seconds=4")
        idle_max = 0
        deadline = time.time() + 6
        while time.time() < deadline and idle_thread.is_alive():
            try:
                doc = self.export_current()
            except lab.LabAssertionFailed:
                time.sleep(0.1)
                continue
            idle_max = max(idle_max, doc["active_connections"] or 0)
            time.sleep(0.2)
        idle_thread.join(timeout=60)
        self.check(idle_max >= 1,
                   "monitor export observed the idle held connection "
                   "(max active=%d)" % idle_max)
        lab.wait_until(
            lambda: self.export_current()["active_connections"] == 0,
            timeout=30, interval=0.25,
            description="active connections to settle after the idle transfer")
        # multiple concurrent connections.
        multi_threads = []
        for index in range(2):
            multi_threads.append(self.produce_async(
                "reality", "shape-multi",
                "/payload/%d" % (1024 * 1024),
                extra_args=["--limit-rate", "1m"]))
            multi_threads.append(self.produce_async(
                "hysteria2", "shape-multi",
                "/payload/%d" % (1024 * 1024),
                extra_args=["--limit-rate", "1m"]))
        multi_max = 0
        deadline = time.time() + 10
        while time.time() < deadline and any(thread.is_alive()
                                             for thread in multi_threads):
            try:
                doc = self.export_current()
            except lab.LabAssertionFailed:
                time.sleep(0.1)
                continue
            multi_max = max(multi_max, doc["active_connections"] or 0)
            time.sleep(0.15)
        for thread in multi_threads:
            thread.join(timeout=60)
        results = [thread.captured.get("result")  # type: ignore[attr-defined]
                   for thread in multi_threads]
        self.check(all(result is not None and result.ok for result in results),
                   "multiple concurrent real connections complete on both "
                   "protocols (no business connection break)")
        self.check_in_range(multi_max, 2, 8,
                            "concurrent active connection count is plausible "
                            "(at least two of the four real connections were "
                            "observed in flight)")
        lab.wait_until(
            lambda: self.export_current()["active_connections"] == 0,
            timeout=30, interval=0.25,
            description="active connections to settle after concurrent "
                        "transfers")
        self.assert_monitor_alive("connection-shapes")
        self.record("connection_shapes", {
            "long_max_active": max_active,
            "idle_max_active": idle_max,
            "multi_max_active": multi_max,
        })
        # A real agent snapshot after the shape traffic must still be honest
        # and bounded by the measured payload.
        report = self.run_agent_once("connection-shapes")
        parsed = lab.validate_rev7_snapshot_report(report)
        for row in parsed["inbounds"]:
            self.assert_no_fabricated_peak(
                self.export_current(), row["inbound_tag"], "downlink",
                "connection-shapes")

    def stage_concurrent_protocols(self) -> None:
        before = self.export_current()
        before_values = {}
        for tag in (lab.REALITY_TAG, lab.HYSTERIA2_TAG):
            before_values[tag] = {
                "downlink": lab.export_observed(before, tag, "downlink"),
                "uplink": lab.export_observed(before, tag, "uplink"),
            }
        threads = [
            self.produce_async("reality", "concurrent",
                               "/payload/%d" % (3 * 1024 * 1024)),
            self.produce_async("hysteria2", "concurrent",
                               "/payload/%d" % (4 * 1024 * 1024)),
        ]
        for thread in threads:
            thread.join(timeout=120)
        for thread in threads:
            result = thread.captured.get("result")  # type: ignore[attr-defined]
            self.check(result is not None and result.ok,
                       "concurrent real protocol transfer completes")
        # Wait for each protocol's measured bytes to appear in its own series.
        def _reached():
            try:
                doc = self.export_current()
            except lab.LabAssertionFailed:
                return None
            reality = lab.export_observed(doc, lab.REALITY_TAG, "downlink")
            hy2 = lab.export_observed(doc, lab.HYSTERIA2_TAG, "downlink")
            base_r = before_values[lab.REALITY_TAG]["downlink"] or 0
            base_h = before_values[lab.HYSTERIA2_TAG]["downlink"] or 0
            return doc if (reality is not None
                           and hy2 is not None
                           and reality - base_r >= 3 * 1024 * 1024
                           and hy2 - base_h >= 4 * 1024 * 1024) else None
        normalized = lab.wait_until(
            _reached, 60, 0.2,
            "concurrent per-inbound lower bounds to be observed")
        for tag, expected_bytes in ((lab.REALITY_TAG, 3 * 1024 * 1024),
                                    (lab.HYSTERIA2_TAG, 4 * 1024 * 1024)):
            observed = lab.export_observed(normalized, tag, "downlink")
            base = before_values[tag]["downlink"] or 0
            delta = (observed or 0) - base
            self.check(delta >= expected_bytes,
                       "%s concurrent downlink delta >= measured %s"
                       % (tag, lab.format_bytes(expected_bytes)))
            self.check(delta <= expected_bytes + lab.overhead_tolerance(
                expected_bytes),
                "%s concurrent downlink delta is not cross-attributed from the "
                "other protocol (delta=%s measured=%s)"
                % (tag, lab.format_bytes(delta),
                   lab.format_bytes(expected_bytes)))
        # Concurrent uploads in both directions.
        upload_threads = [
            self.produce_async_upload("reality", "concurrent-upload",
                                      b"U" * (512 * 1024)),
            self.produce_async_upload("hysteria2", "concurrent-upload",
                                      b"V" * (512 * 1024)),
        ]
        for thread in upload_threads:
            thread.join(timeout=120)
        self.run_agent_once("concurrent-protocols")
        rows = self.traffic_tables_present()
        epoch = self.current_monitor_epoch
        epoch_series = {
            tag: lab.traffic_series(
                [row for row in rows["observations"]
                 if row.get("source_epoch") == epoch])
            for tag in (lab.REALITY_TAG, lab.HYSTERIA2_TAG)}
        for tag in (lab.REALITY_TAG, lab.HYSTERIA2_TAG):
            series = epoch_series[tag].get((epoch, tag))
            self.check(series is not None,
                       "center store normalized a %r series for the current "
                       "monitor epoch" % tag)
            if series:
                self.check((series["max_uplink_lower_bound"] or 0)
                           >= 512 * 1024,
                           "center %r concurrent uplink lower bound >= "
                           "measured 512KiB" % tag)
                self.check((series["max_downlink_lower_bound"] or 0)
                           >= (3 if tag == lab.REALITY_TAG else 4)
                           * 1024 * 1024,
                           "center %r concurrent downlink lower bound >= "
                           "measured payload" % tag)
        self.record("concurrent_protocols", {
            "reality_downlink_delta": (
                lab.export_observed(normalized, lab.REALITY_TAG, "downlink")
                or 0) - (before_values[lab.REALITY_TAG]["downlink"] or 0),
            "hysteria2_downlink_delta": (
                lab.export_observed(normalized, lab.HYSTERIA2_TAG, "downlink")
                or 0) - (before_values[lab.HYSTERIA2_TAG]["downlink"] or 0),
        })

    def produce_async_upload(self, protocol: str, phase: str,
                             payload: bytes) -> threading.Thread:
        socks = self._socks_port(protocol)
        tag = self._inbound_tag(protocol)
        http_base = "http://127.0.0.1:%d" % self.ports.http_fixture
        captured = {}

        def _run():
            result = lab.run_curl_socks(
                socks, http_base + "/upload/echo", method="POST",
                upload_bytes=payload, max_time=120.0)
            captured["result"] = result
            if result.ok:
                self.ledger.record(tag, "uplink", result.size_upload,
                                   phase=phase, note="concurrent-upload")

        thread = threading.Thread(target=_run,
                                  name="upload-%s" % protocol, daemon=True)
        thread.captured = captured  # type: ignore[attr-defined]
        thread.start()
        return thread

    def stage_monitor_after_traffic(self) -> None:
        old_epoch = self.current_monitor_epoch
        old_epoch_baseline = self.monitor_epoch_baselines.get(old_epoch, {})
        # Traffic happens while no monitor process is observing the daemon.
        self._stop_process(self.monitor_proc, "monitor-traffic-export")
        self.monitor_proc = None
        self.produce("reality", "pre-monitor", download_bytes=3 * 1024 * 1024)
        self.produce("hysteria2", "pre-monitor", download_bytes=2 * 1024 * 1024)
        self.monitor_start()
        self.wait_monitor_ready(60)
        new_epoch = self.current_monitor_epoch
        self.check(new_epoch != old_epoch,
                   "monitor started after traffic has a new observation epoch")
        self.check(new_epoch in self.monitor_epoch_baselines,
                   "new observation epoch has an independent ledger "
                   "baseline (traffic before the epoch is not claimed as "
                   "in-epoch observed data)")
        # Produce fresh post-start traffic; it must be observed as a lower
        # bound for the new epoch and nothing may be invented as a lifetime
        # total.
        self.produce("reality", "post-monitor-start",
                     download_bytes=1024 * 1024)
        self.produce("hysteria2", "post-monitor-start",
                     download_bytes=1024 * 1024)
        normalized = self.wait_export_lower_bounds({
            (lab.REALITY_TAG, "downlink"): 1024 * 1024,
            (lab.HYSTERIA2_TAG, "downlink"): 1024 * 1024,
        }, timeout=45, description="post-start traffic in the new epoch")
        self.check_eq(normalized["source_epoch"], new_epoch,
                      "export carries the new epoch")
        for tag in (lab.REALITY_TAG, lab.HYSTERIA2_TAG):
            self.assert_no_fabricated_peak(normalized, tag, "downlink",
                                           "monitor-after-traffic")
            observed = lab.export_observed(normalized, tag, "downlink")
            total = self.ledger.expected(tag, "downlink")
            self.check(observed is None or observed <= total,
                       "series lower bound does not exceed the total "
                       "measured payload (no lifetime-total claim)")
        report = self.run_agent_once("monitor-after-traffic")
        parsed = lab.validate_rev7_snapshot_report(report)
        self.check_eq(parsed["source_epoch"], new_epoch,
                      "agent report carries the new after-start epoch")
        self.check_eq(parsed["counter_scope"], lab.COUNTER_SCOPE,
                      "after-start observation is scoped to the observation "
                      "epoch, not daemon lifetime")
        self.check(parsed["freshness"] == "fresh"
                   and parsed["availability"] == "ok",
                   "after-start observation becomes fresh/ok once new traffic "
                   "is observed")
        self.record("monitor_after_traffic", {
            "old_epoch_prefix": (old_epoch or "")[:8],
            "new_epoch_prefix": new_epoch[:8],
            "new_epoch_observed": {
                "reality_downlink": lab.export_observed(
                    normalized, lab.REALITY_TAG, "downlink"),
                "hysteria2_downlink": lab.export_observed(
                    normalized, lab.HYSTERIA2_TAG, "downlink"),
            },
            "old_epoch_baseline_keys": sorted(old_epoch_baseline),
        })

    def stage_final_verification(self) -> None:
        sentinels = self.creds.secret_values()
        # Every saved export artifact must be privacy-clean and closed.
        for index, sample in enumerate(self.export_samples, start=1):
            path = os.path.join(self.evidence_dir, "export-%02d-*.json"
                                % index)
            matches = sorted(glob.glob(path))
            for match in matches:
                with open(match, "rb") as handle:
                    raw = handle.read()
                document = json.loads(raw.decode("utf-8"))
                findings = lab.privacy_scan_export(document, raw, sentinels)
                self.check(not findings,
                           "saved export sample %r is privacy-clean (no "
                           "secret/IP/user/destination data)"
                           % os.path.basename(match),
                           evidence={"findings": findings})
        # Every captured report body must be privacy-clean and closed.
        for entry in self.report_history:
            report = entry["report"]
            raw = entry["raw"]
            findings = lab.privacy_scan_report(
                report, raw, sentinels,
                allowed_report_id=report.get("report_id"))
            self.check(not findings,
                       "captured report body (%s/%s) is privacy-clean"
                       % (entry["stage"], entry["note"]),
                       evidence={"findings": findings})
            if report.get("contract_revision") == 7:
                self.check_eq(report.get("traffic"), [],
                              "captured rev-7 report keeps base traffic empty")
                lab.validate_rev7_snapshot_report(report)
            if "traffic_observation" in report:
                observation = report["traffic_observation"]
                self.check("monitor_stale" not in observation,
                           "report observation does not forward the "
                           "export-only monitor_stale field")
                self.check(set(observation) == lab.REPORT_OBSERVATION_KEYS,
                           "report observation is exactly the closed rev-7 "
                           "member set")
        # Center config must keep the frozen unsafe sources disabled.
        config_view = self.admin(["config", "show", self.event_id,
                                  self.node_id])
        sources = config_view.get("sources", {})
        self.check_eq(sources.get("singbox_api"), False,
                      "center config keeps singbox_api disabled")
        self.check_eq(sources.get(lab.AGENT_SOURCE_KEY), True,
                      "center config keeps monitor_export enabled for the "
                      "main path")
        tags = {(item.get("inbound_tag"), item.get("kind"))
                for item in config_view.get("expected_inbound_tags", [])}
        self.check_eq(tags, {(lab.REALITY_TAG, lab.REALITY_KIND),
                             (lab.HYSTERIA2_TAG, lab.HYSTERIA2_KIND)},
                      "center expected tags are the real Reality/Hysteria2 "
                      "inbounds")
        # Store/schema/privacy final checks.
        rows = self.traffic_tables_present()
        report_ids = [row.get("report_id") for row in rows["reports"]]
        self.check_eq(len(report_ids), len(set(report_ids)),
                      "center store holds unique normalized report rows")
        self.check(len(rows["reports"]) >= 8,
                   "center stored normalized observation reports for the "
                   "whole lab (rows=%d)" % len(rows["reports"]))
        self.check(all(row.get("exactness") == lab.EXACTNESS
                       for row in rows["reports"]),
                   "every stored observation report is exactness=lower_bound")
        self.check(all(row.get("counter_scope") == lab.COUNTER_SCOPE
                       for row in rows["reports"]),
                   "every stored observation report is "
                   "counter_scope=observation_epoch")
        self.assert_monitor_alive("final-verification")
        self.check(self.server_proc is not None
                   and self.server_proc.alive(),
                   "real sing-box server is still alive at the end of the lab")
        # Write sanitized evidence + summary.
        self.write_artifacts("passed")
        print("\nUM-LT real-protocol traffic lab: PASS")
        print("  stages: %d, assertions: %d" % (len(self.stage_results),
                                                self.checks))
        print("  artifacts: %s" % self.artifacts)

    # =====================================================================
    # Teardown / evidence / entry point
    # =====================================================================
    def write_artifacts(self, status: str, error: str | None = None) -> None:
        if self.creds is None:
            return
        sentinels = self.creds.secret_values()
        summary = {
            "lab": "um-lt-traffic-e2e",
            "lab_version": LAB_VERSION,
            "status": status,
            "started_at": self.started,
            "elapsed_seconds": round(time.time() - self.started, 2),
            "platform": {
                "system": platform.system(),
                "machine": platform.machine(),
                "python": sys.version.split()[0],
            },
            "pinned_singbox": {
                "version": lab.PINNED_SINGBOX_VERSION,
                "archive": lab.PINNED_SINGBOX_ARCHIVE,
                "sha256": lab.PINNED_SINGBOX_SHA256,
                "url": lab.PINNED_SINGBOX_URL,
            },
            "stages": self.stage_results,
            "assertions": self.checks,
            "measurements": self.measurements,
            "export_samples": self.export_samples,
            "report_observations": [
                {"stage": entry["stage"], "note": entry["note"],
                 "contract_revision": entry["report"].get(
                     "contract_revision"),
                 "observation": entry["report"].get("traffic_observation"),
                 "rev5": "traffic_observation" not in entry["report"]}
                for entry in self.report_history
            ],
            "ledger": self.ledger.records,
            "monitor_epochs": [
                "tracked-epoch-%d" % index
                for index in range(len(self.monitor_epoch_baselines))],
            "error": error,
            "limitations": [
                "Cloudflare Access authenticated /web/api/traffic/* RBAC query "
                "is covered by Go web tests; this offline lab checks the route "
                "exists and fails closed without credentials plus the center "
                "store/admin node-show attribution.",
                "service.api exposes no per-inbound daemon-lifetime counter: "
                "all byte counters are OBSERVED LOWER BOUNDS scoped to the "
                "monitor observation epoch (counter_scope=observation_epoch, "
                "exactness=lower_bound), never lifetime totals.",
                "The independent expected payload is measured at the HTTP "
                "layer with curl (size_download/size_upload); observed "
                "counters include real protocol framing overhead and can be "
                "very slightly larger than the HTTP payload.",
            ],
        }
        lab.copy_json_artifact(summary,
                              os.path.join(self.artifacts, "summary.json"))
        lab.copy_json_artifact({"records": self.ledger.records},
                              os.path.join(self.artifacts,
                                           "measured-payload.json"))
        # Redacted copies of the generated configs and process logs. The
        # configs contain only synthetic lab credentials; they are still
        # redacted before upload.
        redacted_dir = os.path.join(self.artifacts, "redacted-configs")
        if self.creds and getattr(self, "config_paths", None):
            for name, path in self.config_paths.items():
                lab.redact_file(path, os.path.join(redacted_dir,
                                                   name + ".json"), sentinels)
        for entry in sorted(os.listdir(self.logs_dir)) if os.path.isdir(
                self.logs_dir) else []:
            source = os.path.join(self.logs_dir, entry)
            lab.redact_file(source, os.path.join(self.artifacts, "logs",
                                                 entry + ".redacted"),
                            sentinels)
        if os.path.isdir(self.evidence_dir):
            for entry in sorted(os.listdir(self.evidence_dir)):
                source = os.path.join(self.evidence_dir, entry)
                lab.redact_file(source,
                                os.path.join(self.artifacts, "evidence",
                                             entry + ".redacted"), sentinels)

    def cleanup(self) -> None:
        for name, process in (("um-agent-continuous", self.continuous_agent),):
            self._stop_process(process, name)
        self.continuous_agent = None
        self._stop_process(self.monitor_proc, "monitor-traffic-export")
        self.monitor_proc = None
        self._stop_process(self.center_proc, "um-center")
        self.center_proc = None
        for protocol, process in self.client_processes.items():
            self._stop_process(process, "singbox-client-%s" % protocol)
        self.client_processes = {}
        self._stop_process(self.server_proc, "singbox-server")
        self.server_proc = None
        if self.proxy is not None:
            try:
                self.proxy.stop()
            except Exception:  # noqa: BLE001
                pass
            self.proxy = None
        if self.payload_server is not None:
            self.payload_server.stop()
            self.payload_server = None
        if self.tls_server is not None:
            self.tls_server.stop()
            self.tls_server = None
        # Never leave synthetic credential material behind when the lab is
        # asked to clean up. When the artifacts directory lives inside the
        # workdir it is preserved (redacted evidence is the deliverable).
        if not self.args.keep:
            artifacts_inside = (self.artifacts == self.workdir or
                                self.artifacts.startswith(
                                    self.workdir + os.sep))
            if artifacts_inside:
                for child in os.listdir(self.workdir):
                    child_path = os.path.join(self.workdir, child)
                    if child_path == self.artifacts:
                        continue
                    if os.path.isdir(child_path):
                        shutil.rmtree(child_path, ignore_errors=True)
                    else:
                        try:
                            os.unlink(child_path)
                        except OSError:
                            pass
            else:
                shutil.rmtree(self.workdir, ignore_errors=True)

    def run(self) -> None:
        selected = stage_selection(self.args.stages)
        self._selected = selected
        status = "failed"
        error = None
        try:
            self.setup()
            completed = {result["stage"] for result in self.stage_results}
            for name, function in selected:
                if name in completed:
                    continue
                self.run_stage(name, function)
            status = "passed"
        except lab.LabSkipped:
            status = "skipped"
            raise
        except Exception as exc:  # noqa: BLE001 - evidence then re-raise
            error = "%s: %s" % (type(exc).__name__, exc)
            raise
        finally:
            try:
                if self.creds is not None and status != "skipped":
                    if status == "failed":
                        self.write_artifacts("failed", error)
                        print("\nworkdir kept for debugging: %s"
                              % self.workdir, file=sys.stderr, flush=True)
                    else:
                        self.write_artifacts("passed")
            finally:
                self.cleanup()


def main(argv: list[str] | None = None) -> int:
    parser = make_parser()
    args = parser.parse_args(argv)
    if args.self_check:
        return run_self_check(args)
    if args.list_stages:
        for name, description in STAGES:
            print("%-22s %s" % (name, description))
        return 0
    try:
        lab_instance = Lab(args)
        lab_instance.run()
    except lab.LabSkipped as exc:
        print("SKIPPED: %s" % exc)
        print("SKIPPED (not a PASS): the real-protocol lab did not execute.")
        return 3
    except lab.LabAssertionFailed as exc:
        eprint("FAILED: %s" % exc)
        print("artifacts: %s" % (args.artifacts or
                                 os.path.join(args.workdir or "<workdir>",
                                              "artifacts")))
        return 1
    except lab.LabError as exc:
        eprint("FAILED (precondition): %s" % exc)
        return 2
    except KeyboardInterrupt:
        eprint("interrupted")
        return 130
    except Exception as exc:  # noqa: BLE001 - top-level diagnostic boundary
        eprint("FAILED (unexpected error): %s\n%s"
               % (exc, traceback.format_exc()))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
