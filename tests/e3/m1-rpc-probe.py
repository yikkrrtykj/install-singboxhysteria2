#!/usr/bin/env python3
"""E3 M1 -- RPC core probe: schema, framing, peer auth, dispatch, replay.

Runs the real sbox-cm daemon against a mock transaction worker. No root, no
systemd, no sing-box; everything lives in a temporary directory.

Usage: python3 m1-rpc-probe.py <repo-root>
Exit:  0 = all assertions passed, 1 = at least one failed, 2 = environment skip.
"""

import importlib.machinery
import importlib.util
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

VERSION = "e3-rpc/1"

MOCK_WORKER = '''#!/usr/bin/env python3
import json, os, sys
op = sys.argv[1] if len(sys.argv) > 1 else ""
raw = sys.stdin.read()
log = os.environ.get("MOCK_WORKER_LOG")
if log:
    with open(log, "a") as fh:
        fh.write(json.dumps({"op": op, "args": raw}) + "\\n")
print(json.dumps({
    "ok": True, "code": "OK", "stage": "done",
    "data": {"op": op}, "idempotency": {"key_fp": "deadbeef", "replayed": False, "generation": 1},
    "warnings": [],
    "transaction": {"entered": False, "phase": "parse", "changed": False,
                    "reload_performed": False, "health_verified": False,
                    "rollback_attempted": False, "rollback_ok": None, "backup_path": None},
    "error": None,
}))
'''

PASS = [0]
FAIL = [0]
SKIP = [0]


def ok(msg):
    PASS[0] += 1
    sys.stdout.write("  PASS %s\n" % msg)


def bad(msg):
    FAIL[0] += 1
    sys.stdout.write("  FAIL %s\n" % msg)


def skip(msg):
    SKIP[0] += 1
    sys.stdout.write("  SKIP %s\n" % msg)


def note(msg):
    sys.stdout.write("  NOTE %s\n" % msg)


def check(condition, msg):
    ok(msg) if condition else bad(msg)


def eq(got, want, msg):
    if got == want:
        ok(msg)
    else:
        bad("%s (want=%r got=%r)" % (msg, want, got))


def load_daemon(path):
    loader = importlib.machinery.SourceFileLoader("sboxcm_under_test", path)
    spec = importlib.util.spec_from_loader("sboxcm_under_test", loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


# ------------------------------------------------------------------ schema --
def schema_tests(mod):
    sys.stdout.write("\n== request schema ==\n")
    rid = "a" * 16

    def bad_request(payload, code):
        try:
            mod.validate_request(payload)
        except mod.RpcError as exc:
            eq(exc.code, code, "rejected with %s" % code)
            return
        except Exception as exc:  # pragma: no cover
            bad("unexpected exception %r" % exc)
            return
        bad("accepted an invalid request (expected %s)" % code)

    try:
        op, args = mod.validate_request(
            {"v": VERSION, "request_id": rid, "op": "management.status"})
        eq(op, "management.status", "status request accepted")
        eq(args, {"request_id": rid}, "status carries no extra arguments")
    except Exception as exc:  # pragma: no cover
        bad("valid status request rejected: %r" % exc)

    bad_request({"v": "e3-rpc/2", "request_id": rid, "op": "management.status"}, "E_SCHEMA")
    bad_request({"v": VERSION, "request_id": "short", "op": "management.status"}, "E_SCHEMA")
    bad_request({"v": VERSION, "request_id": rid, "op": "client.rotate"}, "E_OP_UNKNOWN")
    bad_request({"v": VERSION, "request_id": rid, "op": "management.status", "x": 1}, "E_SCHEMA")
    bad_request({"v": VERSION, "request_id": rid, "op": "client.add"}, "E_SCHEMA")
    bad_request({"v": VERSION, "request_id": rid, "op": "client.add",
                 "name": "legacy", "idempotency_key": "k" * 16}, "E_RESERVED_NAME")
    bad_request({"v": VERSION, "request_id": rid, "op": "client.add",
                 "name": "../x", "idempotency_key": "k" * 16}, "E_SCHEMA")
    bad_request({"v": VERSION, "request_id": rid, "op": "client.add",
                 "name": "vmix-01", "idempotency_key": "bad key"}, "E_SCHEMA")
    bad_request({"v": VERSION, "request_id": rid, "op": "client.add",
                 "name": "vmix-01", "idempotency_key": "k" * 16,
                 "actor": {"nope": "x"}}, "E_SCHEMA")
    bad_request({"v": VERSION, "request_id": rid, "op": "client.add",
                 "name": "vmix-01", "idempotency_key": "k" * 16,
                 "actor": {"session_fp": "NOTHEX"}}, "E_SCHEMA")

    try:
        op, args = mod.validate_request(
            {"v": VERSION, "request_id": rid, "op": "client.add", "name": "vmix-01",
             "idempotency_key": "k" * 16, "actor": {"session_fp": "0" * 16}})
        eq(args.get("name"), "vmix-01", "add request normalizes the name")
        eq(args.get("actor"), {"session_fp": "0" * 16}, "add request normalizes the actor")
    except Exception as exc:  # pragma: no cover
        bad("valid add request rejected: %r" % exc)

    # M2-A0: management.deactivate carries an optional actor, exactly like
    # management.activate -- a privileged mutation must be attributable in the
    # audit. The read-only ops keep refusing the field.
    try:
        op, args = mod.validate_request(
            {"v": VERSION, "request_id": rid, "op": "management.deactivate",
             "actor": {"session_fp": "0" * 16, "stepup_fp": "1" * 16}})
        eq(op, "management.deactivate", "deactivate request accepted")
        eq(args.get("actor"),
           {"session_fp": "0" * 16, "stepup_fp": "1" * 16},
           "deactivate normalizes the actor")
    except Exception as exc:  # pragma: no cover
        bad("valid deactivate request rejected: %r" % exc)

    try:
        op, args = mod.validate_request(
            {"v": VERSION, "request_id": rid, "op": "management.deactivate"})
        eq(args, {"request_id": rid},
           "deactivate without an actor stays compatible")
    except Exception as exc:  # pragma: no cover
        bad("actor-less deactivate rejected: %r" % exc)

    bad_request({"v": VERSION, "request_id": rid, "op": "management.deactivate",
                 "actor": {"nope": "x"}}, "E_SCHEMA")
    bad_request({"v": VERSION, "request_id": rid, "op": "management.deactivate",
                 "actor": {"session_fp": "NOTHEX"}}, "E_SCHEMA")
    bad_request({"v": VERSION, "request_id": rid, "op": "management.status",
                 "actor": {"session_fp": "0" * 16}}, "E_SCHEMA")
    bad_request({"v": VERSION, "request_id": rid, "op": "client.list",
                 "actor": {"session_fp": "0" * 16}}, "E_SCHEMA")


# ------------------------------------------------------------------ static --
def static_tests(daemon_path):
    """AST-level assertions that a text grep cannot make reliably."""
    import ast

    sys.stdout.write("\n== daemon source invariants (AST) ==\n")
    with open(daemon_path, "r", encoding="utf-8") as fh:
        source = fh.read()
    tree = ast.parse(source)

    timed = []
    killed = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute):
            name = func.attr
        elif isinstance(func, ast.Name):
            name = func.id
        else:
            continue
        if name in ("communicate", "wait", "waitpid") and \
                any(kw.arg == "timeout" for kw in node.keywords):
            timed.append(name)
        if name in ("kill", "terminate", "killpg"):
            killed.append(name)

    check(not timed, "no communicate()/wait() with a timeout (a mutation is never aborted)")
    check(not killed, "the daemon never kills its worker")
    check("SO_PEERCRED" in source, "SO_PEERCRED is used for peer authentication")
    check("AF_INET" not in source, "the daemon has no TCP/UDP address family")


# -------------------------------------------------- framing (socketpair) --
FAKE_TRANSACTION = {"entered": False, "phase": "parse", "changed": False,
                    "reload_performed": False, "health_verified": False,
                    "rollback_attempted": False, "rollback_ok": None, "backup_path": None}


def socketpair_tests(mod):
    """Framing / schema / peer / replay, independent of AF_UNIX availability.

    The transaction worker is replaced by a stub: this isolates the RPC CORE
    (transport, validation, replay, audit ownership), which is exactly the
    boundary this suite is responsible for. The real AF_UNIX transport and the
    real worker are covered by `socket_tests` on Linux.
    """
    sys.stdout.write("\n== framing / dispatch (socketpair) ==\n")
    if not hasattr(socket, "socketpair"):
        skip("socket.socketpair unavailable")
        return

    # Capture FIRST: these overrides must NOT leak into the real AF_UNIX section
    # below, which relies on the kernel's SO_PEERCRED answer (a leaked
    # SBOX_CM_TEST_PEER_UID turns every connection into a fake, mismatched peer
    # and the whole transport suite answers E_PEER_AUTH).
    saved_env = {key: os.environ.get(key) for key in
                 ("SBOX_CM_TEST_PEER_UID", "SB_CM_STATE_DIR", "SBOX_CM_TEST_SANDBOX")}

    os.environ["SBOX_CM_TEST_SANDBOX"] = "1"
    os.environ["SBOX_CM_TEST_PEER_UID"] = "4242"
    state = tempfile.mkdtemp(prefix="scm-sp-")
    os.environ["SB_CM_STATE_DIR"] = state
    audit = os.path.join(state, "audit", "cm.jsonl")

    calls = []
    real = mod.run_worker

    def fake_worker(op, args):
        calls.append({"op": op, "args": args})
        return {"ok": True, "code": "OK", "stage": "done", "data": {"op": op},
                "idempotency": {"key_fp": "deadbeef", "replayed": False, "generation": 1},
                "warnings": [], "transaction": dict(FAKE_TRANSACTION), "error": None}

    mod.run_worker = fake_worker
    try:
        def exchange(payload, timeout=3.0, uid=4242):
            client, server = socket.socketpair()
            thread = threading.Thread(target=mod.handle_connection, args=(server, uid))
            thread.daemon = True
            thread.start()
            try:
                client.settimeout(timeout)
                client.sendall(payload)
                return client, read_frame(client, timeout)
            except OSError:
                try:
                    client.close()
                except OSError:
                    pass
                thread.join(timeout)
                return None, None

        payload = frame({"v": VERSION, "request_id": "reqid-sp-0000001",
                         "op": "management.status"})
        client, resp = exchange(payload)
        check(isinstance(resp, dict) and resp.get("ok") is True, "valid frame is dispatched")
        eq(resp.get("request_id"), "reqid-sp-0000001", "response echoes request_id")
        eq(len(calls), 1, "worker invoked exactly once")
        eq(calls[0]["op"], "management.status", "worker received the validated op")
        client.close()

        audit_before = count_lines(audit)
        before = len(calls)
        client, resp = exchange(frame({"v": VERSION, "request_id": "reqid-sp-0000002",
                                       "op": "client.list"}))
        check(resp and resp.get("ok") is True, "second dispatched request succeeds")
        eq(len(calls), before + 1, "second request reached the worker")
        eq(count_lines(audit), audit_before,
           "RPC core writes no audit for a dispatched request (worker owns it)")
        client.close()

        # replay cache
        rid = "reqid-sp-0000003"
        p = frame({"v": VERSION, "request_id": rid, "op": "management.status"})
        c1, r1 = exchange(p)
        c1.close()
        n_before = len(calls)
        c2, r2 = exchange(p)
        c2.close()
        eq(r2, r1, "same request_id replays the cached response")
        eq(len(calls), n_before, "replay did not re-dispatch the worker")

        # schema errors are answered
        client, resp = exchange(frame({"v": VERSION, "request_id": "reqid-sp-0000004",
                                       "op": "client.rotate"}))
        eq((resp or {}).get("error", {}).get("code"), "E_OP_UNKNOWN",
           "unknown op -> E_OP_UNKNOWN")
        client.close()
        client, resp = exchange(frame({"v": VERSION, "request_id": "reqid-sp-0000005",
                                       "op": "management.status", "zz": 1}))
        eq((resp or {}).get("error", {}).get("code"), "E_SCHEMA", "unknown field -> E_SCHEMA")
        client.close()
        client, resp = exchange(frame({"v": "e3-rpc/9", "request_id": "reqid-sp-0000006",
                                       "op": "management.status"}))
        eq((resp or {}).get("error", {}).get("code"), "E_SCHEMA", "bad version -> E_SCHEMA")
        client.close()

        # malformed frames: close with no protocol oracle
        for name, raw in (
                ("zero-length frame", struct.pack(">I", 0)),
                ("oversize frame", struct.pack(">I", 70000)),
                ("truncated frame", struct.pack(">I", 64) + b"{}"),
                ("invalid UTF-8", struct.pack(">I", 4) + b"\xff\xfe\xfd\xfc"),
                ("invalid JSON", struct.pack(">I", 2) + b"{,"),
        ):
            client, resp = exchange(raw)
            check(resp is None, "%s is rejected silently" % name)
            if client is not None:
                client.close()

        # Peer rejection. The security-relevant assertion (a rejected peer never
        # reaches the worker) holds everywhere; the exact error frame is only
        # asserted where the transport is a real AF_UNIX socketpair (POSIX),
        # because on an emulated-TCP socketpair an immediate close can discard
        # the already-sent response.
        def expect_peer_reject(uid, label, rid):
            before_peer = len(calls)
            client, resp = exchange(frame({"v": VERSION, "request_id": rid,
                                           "op": "management.status"}), uid=uid)
            code = (resp or {}).get("error", {}).get("code")
            if code is None and os.name != "posix":
                skip("%s: error frame lost to the emulated-TCP reset" % label)
            else:
                eq(code, "E_PEER_AUTH", "%s -> E_PEER_AUTH" % label)
            eq(len(calls), before_peer, "a rejected peer never reaches the worker")
            if client is not None:
                client.close()

        expect_peer_reject(1, "mismatched peer uid", "reqid-sp-0000007")
        # root is refused too: root operations go through the CLI/worker, never
        # through a socket back door.
        expect_peer_reject(0, "uid 0 over the socket (no root back door)",
                           "reqid-sp-0000010")

        # one request per connection
        first = frame({"v": VERSION, "request_id": "reqid-sp-0000008", "op": "management.status"})
        second = frame({"v": VERSION, "request_id": "reqid-sp-0000009", "op": "management.status"})
        client, resp = exchange(first + second)
        if resp is None and os.name != "posix":
            skip("pipelined response lost to the emulated-TCP reset on this platform")
        else:
            check(resp is not None, "first frame of a pipelined connection is answered")
        extra = read_frame(client, 1.5) if client is not None else None
        check(extra is None, "pipelines are not supported (one request per connection)")
        if client is not None:
            client.close()

        # read timeout on a half-open frame
        client, resp = exchange(struct.pack(">I", 10), timeout=12.0)
        check(resp is None, "half-open frame is closed after the read timeout")
        if client is not None:
            client.close()
    finally:
        mod.run_worker = real
        for key, value in saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


# ------------------------------------------------------------------ socket --
def send_raw(path, payload, timeout=8.0):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect(path)
    sock.sendall(payload)
    return sock


def read_frame(sock, timeout=8.0):
    sock.settimeout(timeout)
    header = recv_exact(sock, 4)
    if header is None:
        return None
    (length,) = struct.unpack(">I", header)
    body = recv_exact(sock, length)
    if body is None:
        return None
    return json.loads(body.decode("utf-8"))


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except (socket.timeout, OSError):
            return None
        if not chunk:
            return None
        buf += chunk
    return buf


def frame(obj):
    body = json.dumps(obj).encode("utf-8")
    return struct.pack(">I", len(body)) + body


def count_lines(path):
    if not os.path.exists(path):
        return 0
    with open(path, "r") as fh:
        return sum(1 for line in fh if line.strip())


def wait_for_socket(path, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.exists(path):
            try:
                probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                probe.settimeout(0.5)
                probe.connect(path)
                probe.close()
                return True
            except OSError:
                pass
        time.sleep(0.05)
    return False


def start_daemon(mod, daemon_path, tmp, socket_path, worker_path, allowed_uid, state):
    env = dict(os.environ)
    env.update({
        "SBOX_CM_TEST_SANDBOX": "1",
        "SBOX_CM_SOCKET": socket_path,
        "SBOX_CM_WORKER": worker_path,
        "SBOX_CM_ALLOWED_UID": str(allowed_uid),
        "SBOX_CM_SKIP_RECONCILE": "1",
        "SB_CM_STATE_DIR": state,
        "MOCK_WORKER_LOG": os.path.join(tmp, "worker.log"),
        "PATH": os.environ.get("PATH", ""),
    })
    logf = open(os.path.join(tmp, "daemon.log"), "w")
    proc = subprocess.Popen([sys.executable, daemon_path, "run"], env=env,
                            stdout=logf, stderr=subprocess.STDOUT)
    return proc


def socket_tests(mod, root, daemon_path):
    sys.stdout.write("\n== transport / peer / dispatch ==\n")
    if not hasattr(socket, "AF_UNIX"):
        skip("AF_UNIX unavailable on this platform")
        return
    tmp = tempfile.mkdtemp(prefix="scm-probe-")
    socket_path = os.path.join(tmp, "s.sock")
    worker_path = os.path.join(tmp, "mock-worker")
    state = os.path.join(tmp, "state")
    with open(worker_path, "w") as fh:
        fh.write(MOCK_WORKER)
    os.chmod(worker_path, 0o755)

    uid = os.getuid() if hasattr(os, "getuid") else 0
    note("probe uid=%r allowed=%r peer_override=%r sandbox=%r" %
         (uid, uid, os.environ.get("SBOX_CM_TEST_PEER_UID"), os.environ.get("SBOX_CM_TEST_SANDBOX")))
    fails_before = FAIL[0]
    proc = start_daemon(mod, daemon_path, tmp, socket_path, worker_path, uid, state)
    try:
        if not wait_for_socket(socket_path):
            skip("daemon did not come up (see %s/daemon.log)" % tmp)
            return

        audit = os.path.join(state, "audit", "cm.jsonl")
        worker_log = os.path.join(tmp, "worker.log")

        # --- happy path ---
        rid = "reqid-rpc-0000001"
        conn = send_raw(socket_path, frame(
            {"v": VERSION, "request_id": rid, "op": "management.status"}))
        resp = read_frame(conn)
        conn.close()
        check(isinstance(resp, dict) and resp.get("ok") is True, "valid request returns ok")
        eq(resp.get("request_id"), rid, "response echoes the request_id")
        eq(resp.get("op"), "management.status", "response echoes the op")
        eq((resp.get("data") or {}).get("op"), "management.status", "daemon dispatched to the worker")
        check("idempotency" in resp and "transaction" in resp, "envelope carries transaction/idempotency")

        audit_before = count_lines(audit)
        conn = send_raw(socket_path, frame(
            {"v": VERSION, "request_id": "reqid-rpc-0000002", "op": "client.list"}))
        resp = read_frame(conn)
        conn.close()
        check(resp and resp.get("ok") is True, "second op dispatched")
        eq(count_lines(audit), audit_before,
           "the RPC core writes no second audit for a dispatched request")

        # --- replay cache ---
        entries_before = count_lines(worker_log)
        rid3 = "reqid-rpc-0000003"
        payload = frame({"v": VERSION, "request_id": rid3, "op": "management.status"})
        c1 = send_raw(socket_path, payload)
        r1 = read_frame(c1)
        c1.close()
        c2 = send_raw(socket_path, payload)
        r2 = read_frame(c2)
        c2.close()
        eq(r2, r1, "same request_id replays the cached response")
        eq(count_lines(worker_log), entries_before + 1,
           "same request_id invoked the worker exactly once")

        # --- schema errors are answered, not dropped ---
        conn = send_raw(socket_path, frame(
            {"v": VERSION, "request_id": "reqid-rpc-0000004", "op": "client.rotate"}))
        resp = read_frame(conn)
        conn.close()
        eq((resp or {}).get("error", {}).get("code"), "E_OP_UNKNOWN", "unknown op -> E_OP_UNKNOWN")
        conn = send_raw(socket_path, frame(
            {"v": VERSION, "request_id": "reqid-rpc-0000005", "op": "management.status", "zz": 1}))
        resp = read_frame(conn)
        conn.close()
        eq((resp or {}).get("error", {}).get("code"), "E_SCHEMA", "unknown field -> E_SCHEMA")

        # --- malformed frames: closed with no protocol oracle ---
        def expect_silent(payload, msg, timeout=8.0):
            try:
                sock = send_raw(socket_path, payload)
            except OSError:
                ok(msg)
                return
            got = read_frame(sock, timeout=timeout)
            sock.close()
            check(got is None, msg)

        expect_silent(struct.pack(">I", 0), "zero-length frame is rejected silently")
        expect_silent(struct.pack(">I", 70000), "oversize frame is rejected silently")
        expect_silent(struct.pack(">I", 100) + b"{}", "truncated frame is rejected silently")
        expect_silent(struct.pack(">I", 4) + b"\xff\xfe\xfd\xfc", "invalid UTF-8 is rejected silently")
        expect_silent(struct.pack(">I", 2) + b"{,", "invalid JSON is rejected silently")
        expect_silent(struct.pack(">I", 10), "half-open frame times out and is closed",
                      timeout=12.0)

        # --- one request per connection ---
        conn = send_raw(socket_path, frame(
            {"v": VERSION, "request_id": "reqid-rpc-0000006", "op": "management.status"})
            + frame({"v": VERSION, "request_id": "reqid-rpc-0000007", "op": "management.status"}))
        first = read_frame(conn)
        check(first is not None, "first frame on a pipelined connection is answered")
        extra = read_frame(conn, timeout=2.0)
        conn.close()
        check(extra is None, "second frame on the same connection gets nothing (1 req/conn)")

        # --- peer rejection: a different expected uid must refuse ---
        proc.terminate()
        proc.wait(timeout=5)
        other_socket = os.path.join(tmp, "other.sock")
        other = start_daemon(mod, daemon_path, tmp, other_socket, worker_path,
                             uid + 1 if uid + 1 != uid else uid + 2, state)
        try:
            if wait_for_socket(other_socket):
                conn = send_raw(other_socket, frame(
                    {"v": VERSION, "request_id": "reqid-rpc-0000008", "op": "management.status"}))
                resp = read_frame(conn)
                conn.close()
                eq((resp or {}).get("error", {}).get("code"), "E_PEER_AUTH",
                   "mismatched peer uid -> E_PEER_AUTH")
            else:
                skip("second daemon did not come up")
        finally:
            other.terminate()
            other.wait(timeout=5)
    finally:
        if FAIL[0] > fails_before:
            # Diagnose from the daemon's own words instead of guessing.
            try:
                with open(os.path.join(tmp, "daemon.log"), "r") as fh:
                    for line in fh.read().splitlines()[-12:]:
                        note("daemon.log: %s" % line)
            except OSError as exc:
                note("daemon.log unreadable: %r" % exc)
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()


def main(argv):
    if len(argv) < 2:
        sys.stderr.write("usage: m1-rpc-probe.py <repo-root>\n")
        return 2
    root = argv[1]
    daemon_path = os.path.join(root, "sbox-cm", "sbox-cm")
    if not os.path.exists(daemon_path):
        sys.stderr.write("daemon not found: %s\n" % daemon_path)
        return 2

    sys.stdout.write("===== E3 M1 RPC PROBE =====\n")
    mod = load_daemon(daemon_path)
    schema_tests(mod)
    static_tests(daemon_path)
    socketpair_tests(mod)
    socket_tests(mod, root, daemon_path)

    sys.stdout.write("\nPASS=%d FAIL=%d SKIP=%d\n" % (PASS[0], FAIL[0], SKIP[0]))
    if FAIL[0]:
        sys.stdout.write("E3_M1_RPC=FAIL\n")
        return 1
    sys.stdout.write("E3_M1_RPC=PASS\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
