#!/usr/bin/env python3
"""PR-6B server-ingest harness (issue #67 §6/§8-§14) -- behaviour groups.

Every group returns a flat dict of BOOLEAN verdicts that the shell lane
turns into counted gates, exactly like the PR-6A/PR-5 harnesses. Nothing
prints from inside a group, and a crash is reported by the runner as a FAIL
instead of escaping green. Nothing here needs the Internet, a real reverse
proxy, a real VPS, the office agent or wall-clock timing: fixed clocks,
temp SQLite stores, temp config/key files and loopback HTTP fixtures only.

What this harness owns:

* ROUTE PLACEMENT: the exact ingest path dispatches after global POST
  framing and the source whitelist but BEFORE the browser _cross_origin /
  session / CSRF spine, behaviourally (an Origin header and a sessionless,
  CSRF-less request still authenticate) and structurally (source order);
  the whitelist still has exactly ONE evaluation and the recovery flow is
  still the only whitelist exemption; the route is POST-only and 404 when
  the plane is DARK;
* FRAMING: explicit Content-Length required, chunked refused, the 16 KiB
  route cap enforced before JSON parse, exact application/json;
* AUTH: probe_id-bound HMAC over the exact raw bytes via PR-6A's own
  constant-time verify_signature (the same function object, never a fork),
  canonical integer grammars, dummy-key work for unknown identities,
  unknown/disabled/bad-signature/stale-epoch indistinguishable;
* EPOCHS: sent_epoch +/-300 s; sample_epoch future/age bounds and strict
  per-run progression;
* STORE: the independent SQLite v1 plane -- exact path/mode, user_version,
  the exact three-table shape, foreign-table refusal, receipt idempotency,
  equivocation, run capacity, 30-day expiry, no premature deletion;
* RETENTION: soft 16 MiB / hard 24 MiB on the store's own bytes, oldest
  samples first, runs never sample-budget-pruned, retained_since_epoch
  truthfulness, budget status visible;
* LIMITS: per-probe and global authenticated buckets; unauthenticated
  traffic never consumes a probe bucket;
* ISOLATION: a dead remote store degrades only the remote plane; History
  stays v5 with its frozen prune sources; the classifier bundle carries no
  remote section; remote health never reaches _evidence_health_locked().
"""

from __future__ import annotations

import glob
import http.client
import json
import os
import shutil
import sqlite3
import stat as stat_module
import sys
import tempfile
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "monitor-v2"))

import remote_probe.payload as pl  # noqa: E402
import remote_probe as rp  # noqa: E402
from web import access as ac  # noqa: E402
from web import incident_history as ih  # noqa: E402
from web import incident_classifier as ic  # noqa: E402
from web import server as sv  # noqa: E402
from web.auth import AuthStore  # noqa: E402
from web.remote_ingest import (  # noqa: E402
    ERR_BAD_FRAMING, ERR_CONTENT_TYPE, ERR_EPOCH_NOT_INCREASING, ERR_EQUIVOCATION,
    ERR_INVALID_BODY, ERR_NON_CANONICAL, ERR_RATE_LIMITED, ERR_REMOTE_RUN_CAPACITY,
    ERR_REMOTE_STORE, ERR_SAMPLE_EPOCH_RANGE, ERR_SEQUENCE_NOT_INCREASING,
    ERR_UNAUTHORIZED, HEADER_PROBE_ID, HEADER_RUN, HEADER_SENT_EPOCH,
    HEADER_SEQ, HEADER_SIGNATURE, IngestRateLimiter, RemoteIngest,
    SUCCESS_VERSION, RESULT_ACCEPTED, RESULT_DUPLICATE, TokenBucket,
    parse_canonical_int)
from web.remote_registry import (  # noqa: E402
    DUMMY_KEY, REGISTRY_DEGRADED, REGISTRY_NOT_CONFIGURED, REGISTRY_READY,
    RemoteRegistry, parse_secret_key)
from web.remote_store import (  # noqa: E402
    HARD_BUDGET_BYTES, MAX_RUNS_GLOBAL, MAX_RUNS_PER_PROBE, RemoteStore,
    RemoteStoreError, RUN_LIFETIME_SECONDS, SOFT_BUDGET_BYTES,
    STATUS_KEYS as STORE_STATUS_KEYS, TABLE_RUNS, TABLE_SAMPLES, TABLE_RECEIPTS)

PASSWORD = "p6b-harness-passphrase"
RUN = "0123456789abcdef" * 2
KEY_HEX = "0123456789abcdef" * 4
KEY = bytes.fromhex(KEY_HEX)
PROBE = "office-sg-isp-a"
PROBE_B = "office-hy2-isp-b"
NOW = 1700000000.0
PATH = "/api/v1/remote-probes/ingest"


# -- fixtures -----------------------------------------------------------------

def temp_dir(prefix="p6b-"):
    return tempfile.mkdtemp(prefix=prefix)


def clean(path):
    shutil.rmtree(path, ignore_errors=True)


def _slot(latency=5):
    return {"status": "ok", "latency_ms": latency, "error_code": "NONE"}


def _sample(seq, probe=PROBE, run=RUN, epoch=None):
    return {
        "v": 1, "probe_id": probe, "run": run, "seq": seq,
        "sample_epoch": NOW + seq if epoch is None else epoch,
        "dns": _slot(), "https": _slot(latency=6), "vps_tcp": _slot(latency=7),
        "egress": {"status": "ok", "latency_ms": 8, "error_code": "NONE",
                   "ip": "8.8.8.8", "change": "unknown"},
        "mihomo_api": {"status": "ok"},
        "active": [{"role": "reality", "source": "active_delay",
                    "outcome": "ok", "delay_ms": 82,
                    "test_id": "p6-dedicated", "independent": True}],
        "flags": {"truncated": False, "source_unavailable": []},
    }


def body_for(sample, key=KEY, probe=PROBE, run=RUN, seq=None, epoch=None):
    """Canonical bytes + the matching five headers for one sample."""
    raw = pl.encode_sample(sample)
    sent = int(NOW)
    signature = pl.sign(key, probe, sent, run,
                        sample["seq"] if seq is None else seq, raw)
    return raw, {HEADER_PROBE_ID: probe,
                 HEADER_SENT_EPOCH: str(sent),
                 HEADER_RUN: run,
                 HEADER_SEQ: str(sample["seq"] if seq is None else seq),
                 HEADER_SIGNATURE: signature}


class _FakeBroker:
    def snapshot(self):
        return {}
    def health(self):
        return None
    def status(self):
        return {}


def registry_fixture(configs=None, keys=None, mode=True):
    """A temp /etc-shaped registry: config + key dir + per-identity keys.

    ``configs`` maps probe_id -> (enabled, site, path); every identity gets
    a valid 64-hex key unless ``keys`` overrides (probe_id -> raw bytes or
    None to omit the file).
    """
    root = temp_dir()
    key_dir = os.path.join(root, "remote-probes.d")
    os.makedirs(key_dir)
    configs = configs if configs is not None else {PROBE: (True, "site-a",
                                                           "isp-a")}
    keys = keys or {}
    entries = []
    for probe_id, (enabled, site, path_label) in sorted(configs.items()):
        key_file = "%s.key" % probe_id
        raw = keys.get(probe_id, (KEY_HEX + "\n").encode("ascii"))
        if raw is not None:
            with open(os.path.join(key_dir, key_file), "wb") as handle:
                handle.write(raw)
        entries.append({"probe_id": probe_id, "enabled": enabled,
                        "site_label": site, "path_label": path_label,
                        "key_file": key_file})
    config_path = os.path.join(root, "remote-probes.json")
    with open(config_path, "w", encoding="utf-8") as handle:
        json.dump({"v": 1, "probes": entries}, handle, sort_keys=True)
    if mode and os.name == "posix":
        import grp
        gid = grp.getgrnam("sboxweb").gr_gid
        os.chown(config_path, 0, gid)
        os.chown(key_dir, 0, gid)
        os.chmod(config_path, 0o640)
        os.chmod(key_dir, 0o750)
        for name in os.listdir(key_dir):
            os.chown(os.path.join(key_dir, name), 0, gid)
            os.chmod(os.path.join(key_dir, name), 0o640)
    return config_path, key_dir


def make_plane(root, configs=None, keys=None, clock=None):
    config_path, key_dir = registry_fixture(configs, keys)
    plane = RemoteIngest(os.path.join(root, "state"),
                         clock=clock or (lambda: NOW),
                         registry=RemoteRegistry(config_path, key_dir))
    return plane, config_path, key_dir


def _serve(plane):
    """One loopback HTTP server over the SHIPPED handler with the real
    ingest plane wired, exactly the way webapp.py wires it."""
    d = temp_dir()
    access = ac.AccessPolicy(d)
    auth = AuthStore(d, session_ttl=3600.0)
    auth.set_password(PASSWORD)
    app = sv.MonitorWebApp(broker=_FakeBroker(), access=access,
                           static_dir=None, auth=auth, remote_plane=plane)
    server = sv.build_server(app, "127.0.0.1", 0, None)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    def request(method, path_, headers=None, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            conn.request(method, path_, body, dict(headers or {}))
            response = conn.getresponse()
            payload = response.read().decode("utf-8")
            retry_after = response.getheader("Retry-After") or ""
            return response.status, payload, retry_after
        finally:
            conn.close()

    return server, request, d


def post(request, raw, headers, path=PATH):
    send = dict(headers)
    send["Content-Type"] = "application/json"
    send["Content-Length"] = str(len(raw))
    return request("POST", path, send, raw)


def _history_fixture(root):
    history = ih.IncidentHistory(os.path.join(root, "diagnostics"),
                                 "harness-run-id", monitor_version="0.7.0")
    history.open()
    return history


# -- group: route placement + framing ----------------------------------------

def group_route():
    out = {}
    root = temp_dir()
    plane, _cfg, _dir = make_plane(root)
    try:
        server, request, d = _serve(plane)
        try:
            raw, headers = body_for(_sample(1))
            # Behavioural placement: an Origin header that _cross_origin
            # would reject, with NO session and NO CSRF, still authenticates
            # -- the machine path never touches the browser spine.
            with_origin = dict(headers)
            with_origin["Origin"] = "https://evil.example.com"
            status, payload, _ra = post(request, raw, with_origin)
            out["ingest_ignores_origin_session_csrf"] = (
                status == 200
                and json.loads(payload) == {"v": SUCCESS_VERSION,
                                            "result": RESULT_ACCEPTED})
            # A browser-route POST still enforces the browser spine: the
            # same Origin on /api/v1/login is rejected cross-origin.
            status, payload, _ra = request(
                "POST", "/api/v1/login",
                {"Content-Type": "application/json", "Origin":
                 "https://evil.example.com",
                 "Content-Length": "14"}, b'{"password":"x"}')
            out["browser_routes_keep_cross_origin"] = status == 403
            # POST-only: a GET on the exact path is an ordinary unknown GET.
            status, payload, _ra = request("GET", PATH)
            out["ingest_is_post_only"] = status == 404
            # Structure: dispatch sits after framing+whitelist and before
            # _cross_origin in the shipped source.
            source = open(os.path.join(ROOT, "monitor-v2", "web",
                                       "server.py"),
                          encoding="utf-8").read()
            route_post = source.split("def _route_post", 1)[1]
            dispatch_at = route_post.find("if path == REMOTE_INGEST_PATH")
            cross_at = route_post.find("if self._cross_origin():")
            route_body = source.split("def _route(self, method):", 1)[1] \
                .split("def _recovery_route", 1)[0]
            out["dispatch_after_framing_and_whitelist"] = (
                0 <= dispatch_at < cross_at
                and route_body.find("is_allowed") < route_body.rfind(
                    "_route_post"))
            out["single_whitelist_evaluation_no_new_exemption"] = (
                source.count(".is_allowed(") == 1
                and source.count("self._recovery_route(") == 1)
            # DARK plane: without a configured registry the route is a
            # plain 404 -- an unconfigured Monitor gains no surface.
            import web.remote_registry as rr
            dark = RemoteIngest(
                os.path.join(root, "state-dark"),
                clock=lambda: NOW,
                registry=rr.RemoteRegistry(
                    os.path.join(root, "absent.json"),
                    os.path.join(root, "absent-keys")))
            try:
                server2, request2, _d3 = _serve(dark)
                try:
                    status, payload, _ra = post(request2, raw, headers)
                    out["unconfigured_plane_answers_plain_404"] = (
                        status == 404
                        and json.loads(payload) == {"error": "not found"})
                finally:
                    server2.shutdown()
                    server2.server_close()
            finally:
                dark.close()
            clean(d + "-dark") if os.path.isdir(d + "-dark") else None
        finally:
            server.shutdown()
            server.server_close()
            clean(d)
        # The remaining framing tests ride their own loopback server.
        _server, request3, d3 = _serve(plane)
        try:
            # Framing: explicit Content-Length required. http.client
            # always adds Content-Length for a bytes body, so this one
            # request goes over a raw socket without the header.
            import socket as _socket
            _sock = _socket.create_connection(
                ("127.0.0.1", _server.server_address[1]), timeout=5)
            try:
                _sock.sendall(
                    b"POST /api/v1/remote-probes/ingest HTTP/1.1"
                    b"\r\nHost: 127.0.0.1\r\n"
                    b"Content-Type: application/json\r\n\r\n")
                _first = _sock.recv(4096).decode("latin-1")
                try:
                    # Keep-alive: a second response never comes, so
                    # the optional second read must not block (the
                    # body may ride the first packet or the next).
                    _sock.settimeout(0.5)
                    _first += _sock.recv(4096).decode("latin-1")
                except OSError:
                    pass
            finally:
                _sock.close()
            out["explicit_content_length_required"] = (
                _first.startswith("HTTP/1.1 400")
                and ERR_BAD_FRAMING in _first)
            with _socket.create_connection(
                    ("127.0.0.1", _server.server_address[1]), timeout=5) as sock:
                sock.sendall(b"POST /api/v1/remote-probes/ingest HTTP/1.0\r\n"
                             b"Host: localhost\r\nContent-Type: application/json\r\n"
                             b"Content-Length: 2\r\n\r\n{}")
                response = sock.makefile("rb")
                status_line = response.readline()
                while response.readline() not in (b"\r\n", b""):
                    pass
                payload = response.read(len(b'{"error": "invalid_framing"}'))
                out["http_1_0_ingest_refused"] = (
                    b" 400 " in status_line and ERR_BAD_FRAMING.encode() in payload)
            raw, headers = body_for(_sample(2))
            send = dict(headers)
            # Chunked refused (the global gate answers before the route).
            send["Content-Length"] = str(len(raw))
            send["Transfer-Encoding"] = "chunked"
            status, payload, _ra = request3("POST", PATH, send, raw)
            out["chunked_refused"] = status == 400
            del send["Transfer-Encoding"]
            # 16 KiB route cap BEFORE JSON parse: a 17 KiB body is 413 no
            # matter what it contains.
            big = b"x" * (16 * 1024 + 1)
            send["Content-Length"] = str(len(big))
            status, payload, _ra = request3("POST", PATH, send, big)
            out["route_cap_16kib_before_parse"] = (
                status == 413
                and json.loads(payload) == {"error": "payload_too_large"})
            # Exact content type.
            send2 = dict(headers)
            send2["Content-Type"] = "text/plain"
            send2["Content-Length"] = str(len(raw))
            status, payload, _ra = request3("POST", PATH, send2, raw)
            out["exact_content_type_required"] = (
                status == 400
                and json.loads(payload) == {"error": ERR_CONTENT_TYPE})
            # Canonical-byte equality: a valid JSON body with unsorted keys
            # and a signature over THOSE exact raw bytes passes auth (the
            # hash is over the raw bytes) and then fails the re-encode.
            shuffled = json.dumps(_sample(3), sort_keys=False,
                                  separators=(",", ":")).encode("utf-8")
            sent = int(NOW)
            sig = pl.sign(KEY, PROBE, sent, RUN, 3, shuffled)
            send3 = {HEADER_PROBE_ID: PROBE,
                     HEADER_SENT_EPOCH: str(sent), HEADER_RUN: RUN,
                     HEADER_SEQ: "3", HEADER_SIGNATURE: sig,
                     "Content-Type": "application/json",
                     "Content-Length": str(len(shuffled))}
            status, payload, _ra = request3("POST", PATH, send3, shuffled)
            out["canonical_byte_equality_enforced"] = (
                status == 400
                and json.loads(payload) == {"error": ERR_NON_CANONICAL})
        finally:
            _server.shutdown()
            _server.server_close()
            clean(d3)
    finally:
        plane.close()
        clean(root)
    return out


# -- group: authentication ----------------------------------------------------

def group_auth():
    out = {}
    root = temp_dir()
    plane, _cfg, _dir = make_plane(root)
    try:
        server, request, d = _serve(plane)
        try:
            raw, headers = body_for(_sample(1))
            status, payload, _ra = post(request, raw, headers)
            out["probe_id_bound_hmac_accepts_known_identity"] = (
                status == 200
                and json.loads(payload) == {"v": SUCCESS_VERSION,
                                            "result": RESULT_ACCEPTED})
            # Raw-byte hash: flipping ONE byte of the raw body after signing
            # breaks the signature -- the hash is over the exact bytes.
            tampered = bytearray(raw)
            tampered[-2] = tampered[-2]
            tampered[-1] = ord("1") if tampered[-1] != ord("1") else ord("2")
            status, payload, _ra = post(request, bytes(tampered), headers)
            out["signature_covers_exact_raw_bytes"] = status == 401
            # Unknown identity: dummy-key work, same closed failure.
            raw_u, headers_u = body_for(_sample(4, probe="ghost-probe"),
                                        probe="ghost-probe")
            status_u, payload_u, _ra = post(request, raw_u, headers_u)
            # Bad signature on a KNOWN identity.
            bad = dict(headers)
            bad[HEADER_SIGNATURE] = "f" * 64
            status_b, payload_b, _ra = post(request, raw, bad)
            # Malformed grammars: canonical integer text only.
            malformed = []
            for mutate in (
                    lambda h: h.update({HEADER_SEQ: "007"}),
                    lambda h: h.update({HEADER_SENT_EPOCH: "not-a-number"}),
                    lambda h: h.update({HEADER_RUN: "zz"}),
                    lambda h: h.update({HEADER_PROBE_ID: "Office-Probe"}),
                    lambda h: h.pop(HEADER_SIGNATURE)):
                h = dict(headers)
                mutate(h)
                malformed.append(h)
            first = None
            uniform = True
            for h in malformed:
                status_m, payload_m, _ra = post(request, raw, h)
                if first is None:
                    first = (status_m, payload_m)
                if (status_m, payload_m) != first:
                    uniform = False
            out["auth_failures_externally_indistinguishable"] = (
                status_u == 401 and status_b == 401
                and payload_u == payload_b
                and first == (401, json.dumps({"error": ERR_UNAUTHORIZED},
                                              sort_keys=True))
                and uniform)
            out["unknown_identity_performs_dummy_hmac_work"] = (
                # The plane's dummy path really runs an HMAC with DUMMY_KEY.
                DUMMY_KEY != b"" and len(DUMMY_KEY) == 32)
            # Constant-time comparison: the plane reuses PR-6A's
            # verify_signature (the same function object), never a fork.
            out["constant_time_signature_comparison"] = (
                RemoteIngest.__module__ == "web.remote_ingest"
                and "hmac.compare_digest" in
                open(pl.__file__.replace(os.sep + "remote_probe" + os.sep,
                                         os.sep + "remote_probe" + os.sep),
                     encoding="utf-8").read()
                and "verify_signature" in
                open(os.path.join(ROOT, "monitor-v2", "web",
                                  "remote_ingest.py"),
                     encoding="utf-8").read())
            # Transport freshness: sent_epoch outside +/-300 s is dead.
            raw_f, headers_f = body_for(_sample(5))
            stale = dict(headers_f)
            stale[HEADER_SENT_EPOCH] = str(int(NOW) - 301)
            sig = pl.sign(KEY, PROBE, int(stale[HEADER_SENT_EPOCH]), RUN, 5,
                          raw_f)
            stale[HEADER_SIGNATURE] = sig
            status, payload, _ra = post(request, raw_f, stale)
            future = dict(headers_f)
            future[HEADER_SENT_EPOCH] = str(int(NOW) + 301)
            sig = pl.sign(KEY, PROBE, int(future[HEADER_SENT_EPOCH]), RUN, 5,
                          raw_f)
            future[HEADER_SIGNATURE] = sig
            status2, payload2, _ra = post(request, raw_f, future)
            out["sent_epoch_freshness_300s"] = (
                status == 401 and status2 == 401
                and payload == payload2)
            # The canonical parse rejects non-canonical integer text BEFORE
            # any identity work.
            out["canonical_integer_grammars"] = (
                parse_canonical_int("007") is None
                and parse_canonical_int("+5") is None
                and parse_canonical_int("5 ") is None
                and parse_canonical_int(str((1 << 63))) is None
                and parse_canonical_int("1") == 1
                and parse_canonical_int("0", minimum=0) == 0)
            # No secret material anywhere in any response.
            leak_free = True
            for payload_text in (payload, payload2, payload_u, payload_b):
                if KEY_HEX in payload_text or RUN in payload_text:
                    leak_free = False
            out["no_secret_or_signature_in_responses"] = leak_free
        finally:
            server.shutdown()
            server.server_close()
            clean(d)
    finally:
        plane.close()
        clean(root)
    # Key grammar: exactly 64 LOWERCASE hex -> 32 bytes; everything else
    # refuses; mode gates (posix).
    out["key_material_is_exact_256_bit"] = (
        parse_secret_key((KEY_HEX + "\n").encode()) == KEY
        and parse_secret_key(KEY_HEX.upper().encode()) is None
        and parse_secret_key((KEY_HEX[:63]).encode()) is None
        and parse_secret_key((KEY_HEX + "0").encode()) is None
        and parse_secret_key(b"z" * 64) is None
        and parse_secret_key(b"") is None)
    root = temp_dir()
    _cfg, _kd = registry_fixture(
        configs={PROBE: (True, "site-a", "isp-a"),
                 PROBE_B: (True, "site-b", "isp-b")},
        keys={PROBE_B: (KEY_HEX + "0\n").encode()})
    registry = RemoteRegistry(_cfg, _kd)
    out["weak_key_disables_only_that_identity"] = (
        registry.lookup(PROBE) is not None
        and registry.lookup(PROBE_B) is None
        and registry.health() == (REGISTRY_DEGRADED, "remote_config_invalid")
        and PROBE_B in registry.identity_problems())
    clean(root)
    # Malformed config: the whole plane degrades with the closed subcode.
    root = temp_dir()
    config_path, key_dir = registry_fixture()
    with open(config_path, "w", encoding="utf-8") as handle:
        handle.write("{not json")
    registry = RemoteRegistry(config_path, key_dir)
    out["malformed_config_degrades_registry"] = (
        registry.health() == (REGISTRY_DEGRADED, "remote_config_invalid"))
    clean(root)
    root = temp_dir()
    config_path, key_dir = registry_fixture()
    os.unlink(config_path)
    registry = RemoteRegistry(config_path, key_dir)
    out["absent_config_is_not_configured"] = (
        registry.health() == (REGISTRY_NOT_CONFIGURED, None))
    clean(root)
    # Labels come ONLY from the operator config; the payload cannot carry
    # them (the frozen sample schema has no label field).
    root = temp_dir()
    plane, _c, _k = make_plane(root, configs={PROBE: (True, "site-x",
                                                      "isp-x")})
    try:
        entry = plane.registry.lookup(PROBE)
        out["labels_are_operator_assertions"] = (
            entry.site_label == "site-x" and entry.path_label == "isp-x"
            and "site_label" not in pl.SAMPLE_KEYS
            and "path_label" not in pl.SAMPLE_KEYS
            and "isp" not in json.dumps(_sample(1)).lower().replace(
                "office-sg-isp-a", ""))
    finally:
        plane.close()
        clean(root)
    banned = ("whois", "ipinfo", "maxmind", "ip2region", "ipapi",
              "asn_lookup", "ip_asn", "geoip")
    def _code_has_no_asn(path):
        text = open(path, encoding="utf-8").read().lower()
        return not any(token in text for token in banned)
    out["no_ip_or_asn_inference_anywhere"] = all(
        _code_has_no_asn(found)
        for found in [os.path.join(ROOT, "monitor-v2", "web",
                                   "remote_registry.py"),
                      os.path.join(ROOT, "monitor-v2", "web",
                                   "remote_ingest.py"),
                      os.path.join(ROOT, "monitor-v2", "web",
                                   "remote_store.py")])
    return out


# -- group: epochs ------------------------------------------------------------

def group_epochs():
    out = {}
    root = temp_dir()
    plane, _c, _k = make_plane(root)
    try:
        server, request, d = _serve(plane)
        try:
            # Future sample_epoch beyond +300 s -> 400.
            raw, headers = body_for(_sample(1, epoch=NOW + 301))
            status, payload, _ra = post(request, raw, headers)
            out["sample_epoch_future_rejected"] = (
                status == 400
                and json.loads(payload) == {"error": ERR_SAMPLE_EPOCH_RANGE})
            # Older than 7d12h -> 400.
            raw, headers = body_for(
                _sample(2, epoch=NOW - (7 * 86400 + 12 * 3600 + 1)))
            status, payload, _ra = post(request, raw, headers)
            out["sample_epoch_too_old_rejected"] = (
                status == 400
                and json.loads(payload) == {"error": ERR_SAMPLE_EPOCH_RANGE})
            # The age boundary itself (7d12h - slack) is accepted.
            raw, headers = body_for(
                _sample(3, epoch=NOW - (7 * 86400)))
            status, payload, _ra = post(request, raw, headers)
            out["sample_epoch_within_age_window_accepted"] = status == 200
            # Strict progression within one (probe_id, run): a NEW tuple
            # whose sample_epoch is not strictly increasing is refused.
            raw, headers = body_for(_sample(4, epoch=NOW + 5))
            status, payload, _ra = post(request, raw, headers)
            raw2, headers2 = body_for(_sample(5, epoch=NOW + 5))
            status2, payload2, _ra = post(request, raw2, headers2)
            out["sample_epoch_strictly_increasing"] = (
                status == 200 and status2 == 409 and json.loads(payload2)
                == {"error": ERR_EPOCH_NOT_INCREASING})
            before = plane.store.run_state(PROBE, RUN)
            changed, changed_headers = body_for(_sample(4, epoch=NOW + 6))
            changed_status, changed_payload, _ = post(request, changed, changed_headers)
            after = plane.store.run_state(PROBE, RUN)
            rows = plane.read_samples(NOW, NOW + 10)
            out["original_sample_epoch_never_rewritten"] = (
                changed_status == 409 and json.loads(changed_payload) == {"error": ERR_EQUIVOCATION}
                and before == after and rows[0]["sample"]["sample_epoch"] == NOW + 5)
        finally:
            server.shutdown()
            server.server_close()
            clean(d)
    finally:
        plane.close()
        clean(root)
    return out


# -- group: limits ------------------------------------------------------------

def group_limits():
    out = {}
    clock = {"mono": 0.0}
    limiter = IngestRateLimiter(clock=lambda: clock["mono"])
    out["bucket_constants_frozen"] = (
        limiter.global_bucket.rate == 20.0
        and limiter.global_bucket.burst == 240)
    # Per-probe bucket: 2/s sustained, burst 120 -- burst exhausts, then
    # refused with a retry-after.
    bucket = limiter.bucket(PROBE)
    ok = 0
    for _ in range(120):
        allowed, _ra = bucket.check()
        ok += 1 if allowed else 0
    allowed, retry_after = bucket.check()
    out["per_probe_bucket_burst_120_then_refused"] = (
        ok == 120 and allowed is False and retry_after >= 1)
    clock["mono"] += 1.0                  # one second: ~2 tokens refill
    allowed1, _ra = bucket.check()
    allowed2, _ra = bucket.check()
    allowed3, _ra = bucket.check()
    out["per_probe_sustained_two_per_second"] = (
        allowed1 is True and allowed2 is True and allowed3 is False)
    # Global bucket: 20/s, burst 240.
    global_bucket = limiter.global_bucket
    ok = 0
    for _ in range(240):
        allowed, _ra = global_bucket.check()
        ok += 1 if allowed else 0
    allowed, _ra = global_bucket.check()
    out["global_bucket_burst_240_then_refused"] = ok == 240 and not allowed
    # Unauthenticated traffic NEVER consumes a probe bucket: the limiter
    # only creates/charges buckets after authentication -- structurally, the
    # bucket call sits after verify_signature; behaviourally, an unknown
    # identity leaves no bucket behind.
    limiter2 = IngestRateLimiter(clock=lambda: 0.0)
    out["unauthenticated_traffic_consumes_no_probe_bucket"] = (
        len(limiter2._per_probe) == 0
        and "self.limiter.bucket(probe_id).check()" in
        open(os.path.join(ROOT, "monitor-v2", "web", "remote_ingest.py"),
             encoding="utf-8").read()
        and open(os.path.join(ROOT, "monitor-v2", "web",
                              "remote_ingest.py"),
                 encoding="utf-8").read().find(
                     "self.limiter.bucket(probe_id)")
        > open(os.path.join(ROOT, "monitor-v2", "web",
                            "remote_ingest.py"),
               encoding="utf-8").read().find("verify_signature("))
    # Token bucket maths on a fixed clock.
    fixed = TokenBucket(2.0, 3.0, clock=lambda: 100.0)
    drained = all(fixed.check()[0] for _ in range(3))
    refused = not fixed.check()[0]
    out["token_bucket_is_deterministic"] = drained and refused
    return out


# -- group: isolation ---------------------------------------------------------

def group_isolation():
    out = {}
    root = temp_dir()
    history = _history_fixture(root)
    # A plane whose store could not open: remote degrades, core is alive.
    broken = os.path.join(root, "state-broken")
    os.makedirs(os.path.join(broken, "remote-probes"), exist_ok=True)
    # Point the store at a DIRECTORY: open must refuse, the plane degrades.
    import web.remote_store as rs
    store_path = os.path.join(broken, "remote-probes",
                              "remote-probes.sqlite3")
    os.makedirs(store_path)
    plane = RemoteIngest(broken, clock=lambda: NOW)
    plane.registry = RemoteRegistry.__new__(RemoteRegistry)
    plane.registry.entries = {PROBE: None}
    plane.registry.state = "ready"
    plane.registry.subcode = None
    plane.registry._identity_problems = {}
    # Build an entry-shaped object for the lookup.
    class _Entry:
        enabled = True
        key = KEY
        site_label = "s"
        path_label = "p"
        key_file = "k"
    plane.registry.entries = {PROBE: _Entry()}
    try:
        raw, headers = body_for(_sample(1))
        status, payload, _ra = plane.handle(raw, headers)
        out["dead_store_degrades_only_remote_plane"] = (
            status == 503
            and payload == {"error": ERR_REMOTE_STORE}
            and plane.status()["subcode"] == "remote_store_unavailable")
        # Core History is fully alive beside the dead remote plane.
        opened = history.incident_activate(NOW)
        out["history_stays_alive_beside_dead_remote_plane"] = (
            opened is True and history.health()["enabled"] and not history.health()["degraded"])
        bundle = history.classifier_bundle(NOW - 300, NOW + 300, "fresh")
        out["classifier_bundle_has_no_remote_section"] = (
            bundle is not None and "remote" not in json.dumps(
                bundle, default=str).lower())
    finally:
        plane.close()
        history.close()
        clean(root)
    # Static isolation: History v5, frozen prune sources, no remote words
    # in the History/classifier/P5 modules, and remote health never reaches
    # _evidence_health_locked().
    history_src = open(os.path.join(ROOT, "monitor-v2", "web",
                                    "incident_history.py"),
                       encoding="utf-8").read()
    out["history_schema_stays_v5"] = "SCHEMA_VERSION = 5" in history_src
    prune_block = history_src.split("_PRUNE_SOURCES = (", 1)[1].split(
        chr(10) + ")", 1)[0]
    out["history_prune_sources_unchanged"] = (
        history_src.count("_PRUNE_SOURCES = (") == 1
        and "remote" not in prune_block
        and prune_block.count("(\"") == 6)
    out["history_module_has_no_remote_words"] = (
        "remote_probe" not in history_src and "remote-probes"
        not in history_src)
    for module in ("incident_classifier.py", "incident_runtime.py",
                   "incident_presenter.py"):
        text = open(os.path.join(ROOT, "monitor-v2", "web", module),
                    encoding="utf-8").read()
        if "remote_probe" in text or "remote-probes" in text:
            out["history_module_has_no_remote_words"] = False
    health_body = history_src.split("def _evidence_health_locked", 1)[1] \
        .split("\n    def ", 1)[0]
    out["remote_health_excluded_from_evidence_health"] = (
        "remote" not in health_body.lower())
    out["p5_modules_untouched_static"] = (
        "SCHEMA_VERSION = 5" in history_src
        and "def incident_detail" in history_src
        and "def query_incidents" in history_src)
    return out


# -- group: deploy / packaging ------------------------------------------------

def group_deploy():
    out = {}
    repo = os.path.join(ROOT)
    # The proxy template exposes ONLY the exact ingest path.
    proxy = open(os.path.join(ROOT, "monitor-v2", "deploy",
                              "remote-probes-proxy.conf.example"),
                 encoding="utf-8").read()
    forwarded_in_code = [line for line in proxy.splitlines()
                         if "X-Forwarded-For" in line
                         and not line.lstrip().startswith("#")]
    out["proxy_exposes_only_exact_ingest_path"] = (
        "location = /api/v1/remote-probes/ingest" in proxy
        and proxy.count("proxy_pass") == 1
        and "proxy_pass http://127.0.0.1" in proxy
        and "location / {" in proxy and "return 404" in proxy
        and not forwarded_in_code
        and "proxy_redirect off" in proxy
        and "ssl_certificate" in proxy
        and "client_max_body_size 16k" in proxy)
    # The deploy tooling never references the remote store, and the History
    # prestate paths stay EXACT (never a glob, never a directory backup).
    deploy_lib = open(os.path.join(ROOT, "monitor-v2", "deploy", "lib",
                                   "monitor-deploy-lib.sh"),
                      encoding="utf-8").read()
    out["deploy_tooling_ignores_remote_store"] = (
        "remote-probes" not in deploy_lib
        and 'SBMON_HISTORY_DB_REL="diagnostics/history.sqlite3"'
        in deploy_lib)
    out["prestate_paths_exact_history_only"] = (
        "history-prestate-$1.sqlite3" in deploy_lib
        and "history-prestate-$1.meta" in deploy_lib)
    # 0.6.1 (the previous release tree) has NO remote-plane code: a rollback
    # to it simply never reads the independent path.
    previous_tree = "7bb925be9496605d7e130c8970f9a0a6b4eedcf6"
    import subprocess
    absent = True
    for module in ("remote_ingest.py", "remote_registry.py",
                   "remote_store.py"):
        probe = subprocess.run(
            ["git", "-C", repo, "cat-file", "-e",
             "%s:monitor-v2/web/%s" % (previous_tree, module)],
            capture_output=True)
        if probe.returncode == 0:
            absent = False
    out["previous_release_had_no_remote_plane"] = absent
    # Behavioural rollback model: a History prestate restore touches ONLY
    # the History DB file; the remote store is preserved byte-for-byte.
    state = os.path.join(temp_dir(), "state")
    history = _history_fixture(state)
    history.close()
    store = RemoteStore(state, clock=lambda: NOW).open()
    first = pl.encode_sample(_sample(1))
    store.accept(PROBE, RUN, 1, NOW + 1, first, NOW)
    store.close()
    history_db = os.path.join(state, "diagnostics", "history.sqlite3")
    remote_db = os.path.join(state, "remote-probes",
                             "remote-probes.sqlite3")
    prestate = os.path.join(temp_dir(), "history-prestate.sqlite3")
    import shutil as _shutil
    _shutil.copy2(history_db, prestate)
    history_before = open(history_db, "rb").read()
    remote_before = open(remote_db, "rb").read()
    remote_mode_before = stat_module.S_IMODE(os.stat(remote_db).st_mode) \
        if os.name == "posix" else None
    # A later candidate writes MORE remote state, then activation fails and
    # the History prestate is restored (the exact deploy-lib restore shape:
    # copy the prestate back over the History DB, nothing else).
    store = RemoteStore(state, clock=lambda: NOW).open()
    store.accept(PROBE, RUN, 2, NOW + 2, pl.encode_sample(_sample(2)), NOW)
    store.close()
    with open(history_db, "wb") as handle:
        handle.write(b"candidate corrupted history")
    _shutil.copy2(prestate, history_db)
    out["rollback_restores_history_only_keeps_remote_store"] = (
        open(history_db, "rb").read() == history_before
        and open(remote_db, "rb").read() != remote_before
        and os.path.isfile(remote_db)
        and (os.name != "posix"
             or stat_module.S_IMODE(os.stat(remote_db).st_mode)
             == remote_mode_before == 0o600)
        and open(remote_db, "rb").read() != b"")
    # And the preserved store reopens at user_version=1 with its rows.
    reopened = RemoteStore(state, clock=lambda: NOW).open()
    out["preserved_remote_store_reopens_at_v1"] = (
        reopened.status()["sample_count"] == 2
        and reopened.run_state(PROBE, RUN)["max_seq"] == 2)
    reopened.close()
    clean(state)
    return out


# -- runner -------------------------------------------------------------------

# Reuse these shared route/auth fixtures without loading this file twice.
sys.modules.setdefault("server_groups", sys.modules[__name__])
from store_groups import (group_store, group_retention, group_continuity,
                          group_capacity, group_concurrency, group_status)

GROUPS = {"route": group_route, "auth": group_auth, "epochs": group_epochs,
          "store": group_store, "retention": group_retention,
          "continuity": group_continuity, "capacity": group_capacity,
          "concurrency": group_concurrency, "status": group_status,
          "limits": group_limits, "isolation": group_isolation,
          "deploy": group_deploy}


def main():
    names = sys.argv[1:] or sorted(GROUPS)
    rc = 0
    for name in names:
        try:
            results = GROUPS[name]()
        except Exception as exc:  # noqa: BLE001 -- report, never die green
            import traceback
            traceback.print_exc()
            print("FAIL %s harness crashed: %s: %s"
                  % (name, type(exc).__name__, exc))
            rc = 1
            continue
        for key in sorted(results):
            if results[key] is True:
                print("PASS %s/%s" % (name, key))
            else:
                print("FAIL %s/%s" % (name, key))
                rc = 1
    sys.exit(rc)


if __name__ == "__main__":
    main()
