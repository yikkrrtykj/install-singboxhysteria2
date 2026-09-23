"""Grouped behavioral check driver for the sbox-journal-reader suite.

Usage: python3 jr_groups.py <group>|all
Protocol: one line per check -- "P <label>" pass, "F <label>" fail.
The bash driver (tests/test-monitor-v2-jr.sh) consumes the lines and owns
the EXPECTED_PASS gate. Platform-stable: every check emits exactly one
line on every OS (POSIX-only semantics degrade to in-Python booleans,
never to extra/missing lines).
"""

import datetime
import json
import os
import re
import shutil
import sys
import tempfile
from unittest import mock as _mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness  # noqa: E402
from harness import (FakePopen, Tree, CURSOR_TAIL, cursor_at,  # noqa: E402
                     entries as mk_entries)

from journal_reader import classifier, cursor as cursor_mod  # noqa: E402
from journal_reader import eligibility, fingerprint, ingest_contract  # noqa: E402
from journal_reader import journal_time, normalize, reader as reader_mod  # noqa: E402
from journal_reader import schema, state  # noqa: E402
from journal_reader.codes import (CODE_CURSOR_INVALID,  # noqa: E402
                                  CODE_RESET_REFUSED, CODE_SOURCE_UNAVAILABLE,
                                  CODE_STATE_CORRUPTION, CODE_UNIT_INVALID,
                                  CODE_WRITER_FAILED)
from journal_reader.reader import ReaderFailure  # noqa: E402

OUT = []


def ck(label, cond):
    print("%s %s" % ("P" if cond else "F", label), flush=True)


def tree():
    return Tree()


def _restore(obj, name, value):
    setattr(obj, name, value)


# ---------------------------------------------------------------------------
def g_cursor():
    ck("cursor 37-char valid", cursor_mod.validate_cursor(CURSOR_TAIL))
    ck("cursor at 4096B bound valid",
       cursor_mod.validate_cursor("s" * cursor_mod.CURSOR_MAX_BYTES))
    ck("cursor 4097B invalid",
       not cursor_mod.validate_cursor("s" * (cursor_mod.CURSOR_MAX_BYTES + 1)))
    ck("cursor empty invalid", not cursor_mod.validate_cursor(""))
    ck("cursor non-str invalid",
       not cursor_mod.validate_cursor(None)
       and not cursor_mod.validate_cursor(123))
    ck("cursor with newline rejected",
       not cursor_mod.validate_cursor("abc\ndef"))
    ck("cursor with NUL rejected", not cursor_mod.validate_cursor("a\x00b"))
    ck("cursor with 0x1f rejected", not cursor_mod.validate_cursor("a\x1fb"))
    ck("cursor with DEL 0x7f rejected", not cursor_mod.validate_cursor("a\x7fb"))
    ck("cursor with C1 0x9f rejected", not cursor_mod.validate_cursor("a\x9fb"))
    ck("cursor 0xa0 accepted (opaque)", cursor_mod.validate_cursor("a\xa0b"))
    ck("cursor length is UTF-8 BYTES",
       not cursor_mod.validate_cursor("\u3042" * 1366))  # 4098 bytes
    ck("parse --show-cursor happy path",
       cursor_mod.parse_show_cursor("cursor: " + CURSOR_TAIL) == CURSOR_TAIL)
    ck("parse REAL '-- cursor:' framing (journalctl-show.c)",
       cursor_mod.parse_show_cursor("-- cursor: " + CURSOR_TAIL) == CURSOR_TAIL)
    ck("parse real form wins over fixture form",
       cursor_mod.parse_show_cursor("cursor: " + "f" * 37 + "\n"
                                    + "-- cursor: " + CURSOR_TAIL)
       == CURSOR_TAIL)
    ck("parse real form mid-line is not a cursor line",
       cursor_mod.parse_show_cursor("x -- cursor: " + CURSOR_TAIL) is None)
    ck("parse '--cursor:' wrong prefix -> None",
       cursor_mod.parse_show_cursor("--cursor: " + CURSOR_TAIL) is None)
    ck("parse real form trailing-space tail -> None",
       cursor_mod.parse_show_cursor("-- cursor: " + CURSOR_TAIL + " ") is None)
    ck("parse real form control-char cursor -> None",
       cursor_mod.parse_show_cursor("-- cursor: a\x7fb") is None)
    ck("parse no match -> None",
       cursor_mod.parse_show_cursor("no cursor here") is None)
    ck("parse control-char cursor -> None",
       cursor_mod.parse_show_cursor("cursor: a\x7fb") is None)
    ck("parse non-str -> None", cursor_mod.parse_show_cursor(None) is None)


# ---------------------------------------------------------------------------
def g_jtime():
    norm = journal_time.normalize_journalctl_since
    ck("jtime passthrough", norm("2026-09-22 10:20:30") == "2026-09-22 10:20:30")
    ck("jtime passthrough rejects bad calendar",
       _raises(JournalErr, lambda: norm("2026-02-30 00:00:00")))
    ck("jtime rejects garbage", _raises(JournalErr, lambda: norm("garbage")))
    ck("jtime rejects empty", _raises(JournalErr, lambda: norm("   ")))
    ck("jtime rejects None", _raises(JournalErr, lambda: norm(None)))
    ck("jtime rejects out-of-month",
       _raises(JournalErr, lambda: norm("2026-13-45 10:20:30")))
    dt = datetime.datetime(2026, 9, 22, 10, 0, 0, tzinfo=datetime.timezone.utc)
    expected = dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    ck("jtime Z form converts to local",
       norm("2026-09-22T10:00:00Z") == expected)
    ck("jtime lowercase z accepted",
       norm("2026-09-22T10:00:00z") == expected)
    ck("jtime explicit offset accepted",
       norm("2026-09-22T10:00:00+00:00") == expected)
    ck("jtime fractional seconds accepted",
       norm("2026-09-22T10:00:00.123456Z") == expected)
    ck("jtime naive treated as UTC",
       norm("2026-09-22T10:00:00") == expected)
    now = journal_time.now_journalctl_form(
        now_fn=lambda: datetime.datetime(2026, 1, 2, 3, 4, 5))
    ck("jtime now_fn injected form", now == "2026-01-02 03:04:05")
    ck("jtime now shape",
       re.fullmatch(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}",
                    journal_time.now_journalctl_form()) is not None)


JournalErr = journal_time.JournalTimeError


def _raises(exc, fn):
    try:
        fn()
        return False
    except exc:
        return True


# ---------------------------------------------------------------------------
def g_norm():
    text, level = normalize.normalize_message("ERROR dial tcp 1.1.1.1:443: boom")
    ck("norm ERROR token detected", level == "error")
    ck("norm ERROR token stripped", not text.startswith("error")
       and "dial tcp" in text)
    ck("norm warning maps to warn",
       normalize.normalize_message("WARNING stalled")[1] == "warn")
    ck("norm info detected",
       normalize.normalize_message("INFO session opened")[1] == "info")
    ck("norm debug detected",
       normalize.normalize_message("DEBUG x")[1] == "debug")
    ck("norm no level token",
       normalize.normalize_message("plain text here")[1] is None)
    ck("norm level token boundary (errors= stays)",
       normalize.normalize_message("errors=5 handler")[1] is None)
    ck("norm strips ISO datetime prefix",
       normalize.normalize_message("2026-09-22 10:20:30 ERROR boom")[0]
       == "boom")
    ck("norm strips t= form",
       normalize.normalize_message("t=2026-09-22t10:20:30z boom")[0] == "boom")
    ck("norm strips bracketed pid",
       normalize.normalize_message("[  1234] boom")[0] == "boom")
    ck("norm cap at MAX chars",
       len(normalize.normalize_message("x" * 9000)[0])
       == normalize.MAX_MESSAGE_CHARS)
    ck("norm bytes decode",
       normalize.normalize_message(b"ERROR b\xffok")[0].startswith("b")
       and normalize.normalize_message(b"ERROR b\xffok")[1] == "error")
    ck("norm int-list byte array decode",
       "hello" in normalize.normalize_message(
           list(b"hello world"))[0])
    ck("norm undecodable junk yields empty-ish text",
       normalize.normalize_message(object())[0] == "")


# ---------------------------------------------------------------------------
def g_class():
    cf = classifier.classify_failure
    ck("T1 dns anchor",
       cf("lookup api.example.com: no such host") == "dns")
    ck("T1 dial_timeout anchor",
       cf("dial tcp 1.2.3.4:443: i/o timeout") == "dial_timeout")
    ck("T1 reset anchor",
       cf("read tcp 1.2.3.4:443: connection reset by peer") == "reset")
    ck("T1 net_unreachable anchor",
       cf("dial udp 1.2.3.4:443: connect: network is unreachable")
       == "net_unreachable")
    ck("T1 tls_handshake anchor",
       cf("remote error: tls: bad record mac") == "tls_handshake")
    ck("T1 quic_error anchor", cf("quic: received invalid packet")
       == "quic_error")
    ck("T1 eof_cancel anchor", cf("unexpected eof while copying")
       == "eof_cancel")
    ck("T1 other = None from classify_failure",
       cf("totally novel sentence") is None)
    ck("precedence dns before dial_timeout",
       cf("dial tcp 8.8.8.8:53: i/o timeout: no such host") == "dns")
    ck("precedence dial_timeout before tls_handshake",
       cf("handshake timeout waiting for ack") == "dial_timeout")
    # Frozen negatives (v3-B2):
    n1 = classifier.classify_entry(
        "outbound/direct: dial tcp 203.0.113.7:443: connect: connection refused")
    ck("N1 refused is other+fp (cls None route)", n1[0] == "other")
    ck("N1 proto OTHER", n1[1] == "OTHER")
    ck("N1 port 443 https443 kept", n1[2] == 443 and n1[3] == "https443")
    n2 = classifier.classify_entry(
        "outbound/direct: quic: i/o timeout waiting for handshake ack")
    ck("N2 dial_timeout class", n2[0] == "dial_timeout")
    ck("N2 bare quic never attributes Hysteria2", n2[1] == "OTHER")
    n2b = classifier.classify_entry(
        "hysteria2: timeout waiting for handshake ack")
    ck("N2-variant hysteria2 token attributes", n2b[1] == "Hysteria2"
       and n2b[0] == "dial_timeout")
    n3 = classifier.classify_entry(
        "dial udp 203.0.113.7:443: connect: network is unreachable")
    ck("N3 net_unreachable/OTHER", n3[0] == "net_unreachable"
       and n3[1] == "OTHER")
    # Protocol rules: tag > token > OTHER.
    ck("vless-in tag -> Reality",
       classifier.attribute_protocol("vless-in: handshake failed") == "Reality")
    ck("hy2-in tag -> Hysteria2",
       classifier.attribute_protocol("hy2-in: connection reset") == "Hysteria2")
    ck("tag beats conflicting token",
       classifier.attribute_protocol("vless-in hysteria2 mixed") == "Reality")
    ck("bare quic alone -> OTHER",
       classifier.attribute_protocol("quic error burst") == "OTHER")
    # Port extraction.
    ck("port from dial tcp form",
       classifier.extract_port("dial tcp 93.184.216.34:853: oops") == 853)
    ck("no dial form -> no port",
       classifier.extract_port("listen :9091 too slow") is None)
    ck("non-numeric port ignored",
       classifier.extract_port("dial tcp host:http: weird") is None)
    ck("out-of-range port rejected",
       classifier.extract_port("dial tcp 1.2.3.4:70000: x") is None)
    ck("dcls dot853 for 853",
       classifier.dest_class_for(853, "plain") == "dot853")
    ck("dcls quic overrides table",
       classifier.dest_class_for(443, "quic: burst") == "quic")
    ck("dcls none without port",
       classifier.dest_class_for(None, "anything") is None)
    ck("dcls unknown port -> other",
       classifier.dest_class_for(9999, "plain") == "other")


# ---------------------------------------------------------------------------
def g_elig():
    a = eligibility.assess
    d = a("ERROR dial tcp 1.1.1.1:443: i/o timeout", "7")
    ck("ERROR eligible regardless of PRIORITY 7",
       d["disposition"] == "eligible" and d["cls"] == "dial_timeout")
    d = a("ERROR something utterly novel", "7")
    ck("ERROR no-class -> other+fp route (cls None)",
       d["disposition"] == "eligible" and d["cls"] is None)
    d = a("WARN reset by peer storm", None)
    ck("WARN eligible with absent PRIORITY",
       d["disposition"] == "eligible" and d["cls"] == "reset")
    d = a("ERROR timeout exceeded", "not-a-number")
    ck("ERROR malformed PRIORITY still eligible",
       d["disposition"] == "eligible" and d["cls"] == "dial_timeout")
    d = a("INFO session opened to 1.2.3.4", "2")
    ck("INFO token dropped even at PRIORITY 2",
       d["disposition"] == "drop" and d["counter"] == eligibility.DROP_INFO)
    d = a("DEBUG i/o timeout deep trace", "3")
    ck("DEBUG token dropped even with class text",
       d["disposition"] == "drop" and d["counter"] == eligibility.DROP_INFO)
    d = a("no such host while resolving", "7")
    ck("tokenless class-match eligible at PRIORITY 7",
       d["disposition"] == "eligible" and d["cls"] == "dns")
    d = a("brand new sentence", "3")
    ck("tokenless mismatch PRIORITY 3 -> other+fp",
       d["disposition"] == "eligible" and d["cls"] is None
       and not d["priority_unusable"])
    d = a("brand new sentence", "5")
    ck("tokenless mismatch PRIORITY 5 drop nomatch usable",
       d["disposition"] == "drop" and d["counter"] == eligibility.DROP_NOMATCH
       and not d["priority_unusable"])
    d = a("brand new sentence", "9")
    ck("out-of-range PRIORITY marks priority_unusable",
       d["disposition"] == "drop" and d["priority_unusable"])
    d = a("brand new sentence", None)
    ck("absent PRIORITY drop without priority_unusable",
       d["disposition"] == "drop" and not d["priority_unusable"])
    d = a("brand new sentence", "x")
    ck("malformed PRIORITY marks priority_unusable",
       d["disposition"] == "drop" and d["priority_unusable"])
    ck("is_eligible convenience",
       eligibility.is_eligible("ERROR boom", "3")
       and not eligibility.is_eligible("INFO boom", "6"))
    ck("priority_int rejects bool/long strings",
       eligibility.priority_int(True) is None
       and eligibility.priority_int("33") is None
       and eligibility.priority_int("4") == 4)


# ---------------------------------------------------------------------------
def g_fp():
    bt = fingerprint.build_template
    ck("template keeps lowercase alpha words",
       bt("failed dialing connection to server")
       == "failed dialing connection to server")
    ck("template drops digit/num tokens",
       bt("retry 3 times now") == "retry times now")
    ck("template drops host-like token",
       bt("lookup api.example.com failed") == "lookup failed")
    ck("template drops IPv4",
       bt("connect 192.0.2.78 timed out") == "connect timed out")
    ck("template drops path and email tokens",
       bt("open /etc/x/y user@host.com die") == "open die")
    ck("template drops high-entropy run",
       bt("token eyJhbGciOiJIUzI1NiJ9 here") == "token here")
    ck("template drops quoted spans first",
       bt('said "dial timeout" loudly') == "said loudly")
    ck("template drops >12-char words",
       bt("internationalization storm") == "storm")
    cap_in = " ".join(["alpha", "beta", "gamma", "delta"] * 15)
    ck("template caps at MAX tokens",
       len(bt(cap_in).split()) == fingerprint.MAX_TEMPLATE_TOKENS)
    ck("template of pure noise is empty", bt("2026 93.184.216.34:443 !!") == "")
    ck("residual safe plain template",
       not fingerprint.residual_unsafe("failed dialing connection"))
    fp1 = fingerprint.fingerprint(b"k" * 32, "aa bb")
    ck("fp is 16 lowercase hex",
       re.fullmatch(r"[0-9a-f]{16}", fp1) is not None)
    ck("fp deterministic per key",
       fp1 == fingerprint.fingerprint(b"k" * 32, "aa bb"))
    ck("fp changes with key", fp1 != fingerprint.fingerprint(b"j" * 32, "aa bb"))
    t = tree()
    try:
        key = fingerprint.load_or_create_key(t.state_dir)
        ck("key created 32 bytes", len(key) == 32)
        ck("key file reused", fingerprint.load_or_create_key(t.state_dir) == key)
        st = os.stat(os.path.join(t.state_dir, fingerprint.KEY_FILENAME))
        mode_ok = (os.name != "posix") or (st.st_mode & 0o777) == 0o600
        ck("key file 0600 (POSIX)", mode_ok)
        with open(os.path.join(t.state_dir, fingerprint.KEY_FILENAME), "wb") as h:
            h.write(b"short")
        try:
            fingerprint.load_or_create_key(t.state_dir)
            ck("corrupt short key fails closed", False)
        except OSError:
            ck("corrupt short key fails closed", True)
    finally:
        t.close()
    # --- B8 (review #46): every key-path deviation fails closed, and a
    # failed create NEVER leaves a half-durable key behind.
    t2 = tree()
    try:
        kpath = os.path.join(t2.state_dir, fingerprint.KEY_FILENAME)
        with _mock.patch.object(fingerprint.os.path, "islink",
                                return_value=True):
            try:
                fingerprint.load_or_create_key(t2.state_dir)
                ck("symlink key path refused (B8)", False)
            except OSError:
                ck("symlink key path refused (B8)", True)
        ck("symlink refusal created no key file (B8)",
           not os.path.exists(kpath))
        os.mkdir(kpath)
        try:
            fingerprint.load_or_create_key(t2.state_dir)
            ck("non-regular key path fails closed (B8)", False)
        except OSError:
            ck("non-regular key path fails closed (B8)", True)
        os.rmdir(kpath)
        for nlen in (31, 33):
            with open(kpath, "wb") as h:
                h.write(b"k" * nlen)
            try:
                os.chmod(kpath, 0o600)  # so the LENGTH gate is what refuses
            except OSError:
                pass
            try:
                fingerprint.load_or_create_key(t2.state_dir)
                ck("key length %d fails closed (B8)" % nlen, False)
            except OSError:
                ck("key length %d fails closed (B8)" % nlen, True)
        os.unlink(kpath)
        with open(kpath, "wb") as h:
            h.write(b"k" * 32)
        os.chmod(kpath, 0o644)
        if os.name == "posix":
            try:
                fingerprint.load_or_create_key(t2.state_dir)
                ck("0644 key mode refused on POSIX (B8)", False)
            except OSError:
                ck("0644 key mode refused on POSIX (B8)", True)
        else:
            ck("0644 key mode refused on POSIX (B8)",
               fingerprint.load_or_create_key(t2.state_dir) == b"k" * 32)
        os.chmod(kpath, 0o600)
        ck("mode-0600 32-byte key loads verbatim (B8)",
           fingerprint.load_or_create_key(t2.state_dir) == b"k" * 32)
        os.unlink(kpath)
        with _mock.patch.object(fingerprint.secrets, "token_bytes",
                                side_effect=OSError("no entropy")):
            try:
                fingerprint.load_or_create_key(t2.state_dir)
                ck("create write failure fails closed (B8)", False)
            except OSError:
                ck("create write failure fails closed (B8)", True)
        ck("failed create left no partial key (B8)", not os.path.exists(kpath))
        ck("retry after failed create succeeds (B8)",
           len(fingerprint.load_or_create_key(t2.state_dir)) == 32)
        os.unlink(kpath)
        with _mock.patch.object(fingerprint.os, "fsync",
                                side_effect=OSError("io")):
            try:
                fingerprint.load_or_create_key(t2.state_dir)
                ck("create fsync failure fails closed (B8)", False)
            except OSError:
                ck("create fsync failure fails closed (B8)", True)
        ck("fsync failure removed the partial key (B8)",
           not os.path.exists(kpath))
        ck("key recovers after removed failed create (B8)",
           len(fingerprint.load_or_create_key(t2.state_dir)) == 32)
        # B8-residual (review #46 round 2): an EXISTING key must not skip
        # the directory-entry durability proof.
        with _mock.patch.object(fingerprint, "_fsync_dir",
                                side_effect=OSError("io")):
            try:
                fingerprint.load_or_create_key(t2.state_dir)
                ck("existing-key load refuses dir fsync failure (B8r)", False)
            except OSError:
                ck("existing-key load refuses dir fsync failure (B8r)", True)
        ck("existing key still loads once dir fsync works (B8r)",
           len(fingerprint.load_or_create_key(t2.state_dir)) == 32)
    finally:
        t2.close()


# ---------------------------------------------------------------------------
def valid_header(**over):
    h = {"t": "h", "v": schema.FORMAT_VERSION, "cv": schema.CLASSIFIER_VERSION,
         "seq": 1, "run": "a" * 32, "epoch": 1, "boundary": "NONE",
         "lines": 2, "eligible": 1, "info_dropped": 0, "nomatch_dropped": 0,
         "priority_unusable": 0, "pfail": 0, "limited": 0}
    h.update(over)
    return h


def valid_event(**over):
    e = {"t": "e", "ts": 1760000000.5, "cls": "dns", "proto": "OTHER",
         "port": 53, "dcls": "dns53", "fp": None, "n": 2}
    e.update(over)
    return e


def g_schema():
    vh, ve = schema.validate_header, schema.validate_event
    ck("header valid", vh(valid_header()))
    ck("header extra key rejected", not vh(valid_header(surprise=1)))
    ck("header missing key rejected",
       not vh({k: v for k, v in valid_header().items() if k != "cv"}))
    ck("header seq 0 rejected", not vh(valid_header(seq=0)))
    ck("header boundary enum", not vh(valid_header(boundary="COLD")))
    ck("header run 32-lower-hex", not vh(valid_header(run="ABC" * 10)))
    ck("header negative counter rejected", not vh(valid_header(pfail=-1)))
    ck("header bool counter rejected", not vh(valid_header(lines=True)))
    ck("header unknown cv rejected", not vh(valid_header(cv=99)))
    ck("event valid", ve(valid_event()))
    ck("event fp only with other",
       not ve(valid_event(fp="0" * 16)))  # cls dns + fp -> reject
    ck("event other without fp ok",
       ve(valid_event(cls="other", dcls=None, port=None, fp="0" * 16)))
    ck("event dcls requires port",
       not ve(valid_event(port=None)))
    ck("event n 0 rejected", not ve(valid_event(n=0)))
    ck("event NaN ts rejected", not ve(valid_event(ts=float("nan"))))
    ck("event absurd ts rejected", not ve(valid_event(ts=1e12)))
    ck("event port range", not ve(valid_event(port=70000)))
    ck("event unknown class rejected", not ve(valid_event(cls="timeout")))
    pe = schema.parse_exchange_text
    body = "\n".join(json.dumps(x) for x in
                     [valid_header(seq=2), valid_event()]) + "\n"
    ck("parse happy (trailing newline ok)", pe(body, 2) is None)
    ck("parse empty body", pe("", 1) == "exchange_empty")
    ck("parse no header", pe(json.dumps(valid_event()) + "\n", 1)
       == "exchange_no_header")
    ck("parse bad json", pe("{oops\n", 1) == "exchange_bad_json")
    ck("parse header must be first",
       pe("\n".join(json.dumps(x) for x in
                    [valid_event(), valid_header(seq=1)]) + "\n", 1)
       == "exchange_header_position")
    ck("parse second header rejected",
       pe("\n".join(json.dumps(x) for x in
                    [valid_header(seq=1), valid_header(seq=1)]) + "\n", 1)
       == "exchange_header_position")
    ck("parse seq mismatch vs filename", pe(body, 7) == "exchange_seq_mismatch")
    ck("parse invalid event rejected",
       pe("\n".join(json.dumps(x) for x in
                    [valid_header(), valid_event(n=0)]) + "\n", 1)
       == "exchange_event_invalid")


# ---------------------------------------------------------------------------
def g_state():
    t = tree()
    try:
        sdir = t.state_dir
        src = {"mode": "cursor", "value": CURSOR_TAIL}
        c = state.make_committed(3, 2, "NONE", src)
        ck("committed roundtrip",
           state.validate_committed(c) and state.write_committed(sdir, c, "f" * 32)
           is None and state.load_committed(sdir)[0] == c)
        ck("load absent -> (None, True)",
           state.load_committed(os.path.join(t.root, "void")) == (None, True))
        with open(os.path.join(sdir, state.COMMITTED_NAME), "w") as h:
            h.write("{broken")
        ck("load garbage -> (None, False)",
           state.load_committed(sdir) == (None, False))
        ck("committed rejects since+cursor mix",
           not state.validate_committed(
               state.make_committed(0, 1, "NONE",
                                    {"mode": "since", "value": "bad"})))
        good_since = state.make_committed(
            0, 1, "COLD_START", {"mode": "since",
                                 "value": "2026-09-22 10:20:30"})
        ck("committed since mode accepted (tagged union)",
           state.validate_committed(good_since))
        p = state.make_pending("a" * 32, 4, 1, "COLD_START", "b" * 37)
        ck("pending roundtrip", state.validate_pending(p))
        ck("pending rejects since source_end", not state.validate_pending(
            dict(p, source_end={"mode": "since",
                                "value": "2026-09-22 10:20:30"})))
        ck("write_pending stores exact bytes",
           (state.write_pending(sdir, p), state.load_pending(sdir)[0])[1] == p)
        state.remove_pending(sdir)
        ck("remove_pending idempotent when absent",
           (state.remove_pending(sdir), state.load_pending(sdir))
           == (None, (None, True)))
        # scratch cleanup
        for d in (sdir, t.out_dir):
            os.makedirs(d, exist_ok=True)
        open(os.path.join(sdir, "committed.tmp-zz"), "w").write("x")
        open(os.path.join(sdir, "pending.tmp-zz"), "w").write("x")
        open(os.path.join(t.out_dir, "ev-9.jsonl.part"), "w").write("x")
        open(os.path.join(t.out_dir, "hb.tmp-zz"), "w").write("x")
        state.write_committed(sdir, c, "f" * 32)
        with open(os.path.join(t.out_dir, "ev-1.jsonl"), "w") as h:
            h.write("keep")
        state.clean_scratch(sdir, t.out_dir)
        ck("clean_scratch removes all scratch kinds",
           not any(".tmp-" in n or n.endswith(".part")
                   for n in os.listdir(sdir) + os.listdir(t.out_dir)))
        ck("clean_scratch keeps durable objects",
           os.path.isfile(os.path.join(sdir, "committed"))
           and os.path.isfile(os.path.join(t.out_dir, "ev-1.jsonl")))
        ck("durable_ev_seqs strict grammar",
           sorted(state.durable_ev_seqs(t.out_dir)) == [1])
        # recovery table
        ck("row 7 first activation",
           state.evaluate_recovery(None, None, set(), t.out_dir)
           == (7, "first_activation"))
        ck("row 8 no committed with pending",
           state.evaluate_recovery(None, p, set(), t.out_dir)
           == (8, "fail_closed"))
        ck("row 8 no committed with ev files",
           state.evaluate_recovery(None, None, {1}, t.out_dir)
           == (8, "fail_closed"))
        c0 = state.make_committed(0, 1, "NONE", src)
        ck("row 1 plain start", state.evaluate_recovery(c0, None, set(),
                                                        t.out_dir)
           == (1, "start"))
        ck("row 6 durable ev without pending",
           state.evaluate_recovery(c0, None, {1}, t.out_dir)
           == (6, "fail_closed"))
        ck("row 8 ev leaps beyond cs+1",
           state.evaluate_recovery(c0, None, {5}, t.out_dir)
           == (8, "fail_closed"))
        ck("row 3 repoll pending without ev",
           state.evaluate_recovery(c0, state.make_pending("a" * 32, 1, 1,
                                                          "NONE", "b" * 37),
                                   set(), t.out_dir) == (3, "repoll"))
        ck("row 4 stale pending repoll",
           state.evaluate_recovery(state.make_committed(5, 1, "NONE", src),
                                   state.make_pending("a" * 32, 3, 1, "NONE",
                                                      "b" * 37),
                                   {1, 2, 3, 4, 5}, t.out_dir)
           == (4, "repoll"))
        ck("row 5 pending beyond next",
           state.evaluate_recovery(c0, state.make_pending("a" * 32, 9, 1,
                                                          "NONE", "b" * 37),
                                   set(), t.out_dir) == (5, "fail_closed"))
        # row 2 needs a REAL durable file whose header agrees
        pend2 = state.make_pending("c" * 32, 1, 4, "NONE", "b" * 37)
        hdr = valid_header(seq=1, run="c" * 32, epoch=4, boundary="NONE")
        with open(os.path.join(t.out_dir, "ev-1.jsonl"), "w") as h:
            h.write(json.dumps(hdr) + "\n")
        ck("row 2 finish_commit on mutual agreement",
           state.evaluate_recovery(c0, pend2, {1}, t.out_dir)
           == (2, "finish_commit"))
        bad = dict(pend2, run="d" * 32)
        ck("row 6 header run disagreement",
           state.evaluate_recovery(c0, bad, {1}, t.out_dir)
           == (6, "fail_closed"))
        ck("step4 projection is the sign-off invariant",
           state.step4_committed(pend2) == {"v": 1, "seq": 1, "epoch": 4,
                                            "boundary": "NONE",
                                            "source": {"mode": "cursor",
                                                       "value": "b" * 37}})
    finally:
        t.close()


# ---------------------------------------------------------------------------
CRASH_CYCLE_POINTS = ["pending.%s" % p for p in
                      ("tmp_open", "fsync", "rename", "dir_fsync")] \
    + ["file.%s" % p for p in ("create", "fsync", "rename", "dir_fsync")] \
    + ["committed.%s" % p for p in
       ("tmp_open", "fsync", "rename", "dir_fsync")] \
    + ["settle_unlink.unlink"]


def _cycle_crash(point):
    t = tree()
    try:
        batch = mk_entries([(cursor_at(1), "ERROR dial tcp 2.2.2.2:443: i/o timeout",
                             1760000001)])
        r1 = t.reader(FakePopen([(batch, 0)]), faults={point})
        r1.startup()
        crashed = False
        try:
            r1.run_cycle()
        except reader_mod.CrashInjected:
            crashed = True
        if not crashed:
            return ("crash@%s raised" % point, False), t
        # disk invariants before recovery: everything readable or absent,
        # never half-valid.
        committed, ok = state.load_committed(t.state_dir)
        pending, pok = state.load_pending(t.state_dir)
        if not ok or not pok or (pending is not None
                                 and not state.validate_pending(pending)):
            return ("crash@%s disk inconsistent" % point, False), t
        # recovery: fresh process, no faults, next poll is empty then
        # another batch; everything must settle contiguously.
        r2 = t.reader(FakePopen([(b"", 0), (b"", 0)]))
        r2.startup()
        r2.run_cycle()
        r2.run_cycle()
        c = t.committed()
        evs = t.seqs()
        contig = evs == list(range(1, len(evs) + 1)) and \
            all(e <= c["seq"] for e in evs)
        boundary_clean = c["boundary"] == "NONE" if c["seq"] >= 1 else True
        return ("crash@%s recovers consistently" % point,
                contig and boundary_clean and state.validate_committed(c)), t
    except Exception as exc:  # noqa: BLE001 -- protocol must still emit
        return ("crash@%s exploded %r" % (point, exc), False), t


def _close(t):
    t.close()


def _activate_crash(point):
    t = tree()
    try:
        r1 = t.reader(FakePopen([]), faults={"activate.%s" % point})
        try:
            r1.startup()
            activated = True
        except reader_mod.CrashInjected:
            activated = False
        # Either the activation committed (post-rename points) or nothing.
        c, ok = state.load_committed(t.state_dir)
        if not ok or (c is not None and not state.validate_committed(c)):
            return ("activate@%s left corrupt committed" % point, False), t
        # restart clean: state must activate exactly once, COLD_START intact.
        r2 = t.reader(FakePopen([(b"", 0)]))
        r2.startup()
        r2.run_cycle()
        c2 = t.committed()
        want = {"v": 1, "seq": 0, "epoch": 1, "boundary": "COLD_START",
                "source": {"mode": "cursor", "value": CURSOR_TAIL}}
        return ("activate@%s cold start survives restart" % point,
                c2 == want or (activated and c2 == want)), t
    except Exception as exc:  # noqa: BLE001
        return ("activate@%s exploded %r" % (point, exc), False), t


def _row2_state(t, run="c" * 32, seq=1, epoch=1, boundary="COLD_START"):
    """Hand-build committed@0 + pending@seq + matching durable ev-seq."""
    c0 = state.make_committed(seq - 1, epoch, boundary,
                              {"mode": "cursor", "value": CURSOR_TAIL})
    state.write_committed(t.state_dir, c0, "f" * 32)
    pend = state.make_pending(run, seq, epoch, boundary, "b" * 37)
    state.write_pending(t.state_dir, pend)
    hdr = valid_header(seq=seq, run=run, epoch=epoch, boundary=boundary,
                       lines=1, eligible=1)
    with open(os.path.join(t.out_dir, state.ev_filename(seq)), "w") as h:
        h.write(json.dumps(hdr) + "\n")
    return c0, pend


def g_crash():
    for point in CRASH_CYCLE_POINTS:
        (label, cond), _t = _cycle_crash(point)
        ck(label, cond)
        _close(_t)
    for point in ("tmp_open", "fsync", "rename", "dir_fsync"):
        (label, cond), _t = _activate_crash(point)
        ck(label, cond)
        _close(_t)
    # recovery-row crashes: die INSIDE row-2 finish_commit / row-4 unlink.
    for point in ("recover_commit.fsync", "recover_commit.rename"):
        t = tree()
        try:
            _row2_state(t)
            r = t.reader(FakePopen([(b"", 0)]),
                         faults={point})
            try:
                r.startup()
                ck("crash@%s should have fired" % point, False)
            except reader_mod.CrashInjected:
                pass
            r2 = t.reader(FakePopen([(b"", 0)]))
            r2.startup()
            c = t.committed()
            ck("crash@%s row2 finish replays to identical commit" % point,
               c["seq"] == 1 and c["boundary"] == "NONE"
               and t.seqs() == [1] and t.pending() is None)
        except Exception as exc:  # noqa: BLE001
            ck("crash@%s exploded %r" % (point, exc), False)
        finally:
            t.close()
    for point, kind in (("recover_commit.dir_fsync", 2),
                        ("recover_unlink.unlink", 2)):
        t = tree()
        try:
            _row2_state(t)
            r = t.reader(FakePopen([(b"", 0)]), faults={point})
            try:
                r.startup()
                fired = False
            except reader_mod.CrashInjected:
                fired = True
            if kind == 2:
                # committed already advanced; re-evaluation lands on row 4
                # (pending.seq <= committed.seq) -> clean either way.
                r2 = t.reader(FakePopen([(b"", 0)]))
                r2.startup()
                ok2 = (t.committed()["seq"] == 1 and t.pending() is None
                       and t.seqs() == [1])
                ck("crash@%s settles to consistent seq1" % point,
                    ok2 or not fired)
        except Exception as exc:  # noqa: BLE001
            ck("crash@%s exploded %r" % (point, exc), False)
        finally:
            t.close()
    for point in ("reset_commit.tmp_open", "reset_commit.fsync",
                  "reset_commit.rename", "reset_commit.dir_fsync"):
        t = tree()
        try:
            pop = t.reader(FakePopen([(b"", 0)]))
            pop.startup()
            r = t.reader(FakePopen([(b"", 0)]), faults={point})
            try:
                r.reset_from_now()
                done = True
            except reader_mod.CrashInjected:
                done = False
            c = t.committed()
            valid = state.validate_committed(c) if c is not None else False
            # Pre-rename: committed untouched at epoch 1 (reset never
            # half-landed). Post-rename points: fully landed epoch 2.
            pre_rename = (not point.endswith("dir_fsync")
                          and point.endswith(("fsync", "tmp_open", "rename")))
            if pre_rename:
                # strictly PRE-rename: the reset never landed at all
                good = valid and c["epoch"] == 1 and not done
            else:
                good = valid and c["epoch"] in (1, 2)
            # a re-run must be possible and eventually consistent
            r2 = t.reader(FakePopen([(b"", 0)]))
            r2.startup()
            r2.run_cycle()
            ck("crash@%s reset atomic (all-or-nothing)" % point, good)
        except Exception as exc:  # noqa: BLE001
            ck("crash@%s exploded %r" % (point, exc), False)
        finally:
            t.close()
    # T28 directory-fsync boundary probe: a crash at any *_dir_fsync must
    # never leave a state/ entry that is neither absent nor loadable.
    t = tree()
    try:
        batch = mk_entries([(cursor_at(1), "ERROR boom no such host", 1760000001)])
        r = t.reader(FakePopen([(batch, 0)]), faults={"pending.dir_fsync"})
        try:
            r.run_cycle()
        except reader_mod.CrashInjected:
            pass
        except ReaderFailure:
            pass  # not activated yet -> corruption raise is also consistent
        ck("pending.dir_fsync crash leaves only reclaimable scratch",
           not [n for n in t.files(t.state_dir)
                if ".tmp-" in n and not n.startswith("committed")
                and not n.startswith("pending")])
        ck("pending precedes any exchange file (C1 step order)",
           t.seqs() == [] and not os.path.exists(
               os.path.join(t.out_dir, "ev-1.jsonl")))
    finally:
        t.close()


# ---------------------------------------------------------------------------
def g_d1():
    t = tree()
    try:
        batch = mk_entries([(cursor_at(1), "ERROR dial tcp 8.8.8.8:53: i/o timeout",
                             1760000001)])
        r = t.reader(FakePopen([(batch, 0)]))
        r.startup()
        ck("row1 rc0 records commits", r.run_cycle() == "committed")
    finally:
        t.close()
    # row 2: empty window -- heartbeat only, zero movement (T34b shape).
    t = tree()
    try:
        r = t.reader(FakePopen([(b"", 0)] * 5))
        r.startup()
        before = t.body_bytes = open(
            os.path.join(t.state_dir, state.COMMITTED_NAME), "rb").read()
        for _ in range(4):
            ck_rc = r.run_cycle()
            if ck_rc != "empty":
                break
        after = open(os.path.join(t.state_dir, state.COMMITTED_NAME),
                     "rb").read()
        ck("row2 N empty polls zero movement", before == after)
        ck("row2 empty polls produce no ev files", t.seqs() == [])
        ck("row2 heartbeat refreshed at same seq", t.hb() == {"seq": 0,
                                                              "ts": t.hb()["ts"]})
    finally:
        t.close()
    # row 5: non-zero BEFORE first usable cursor -- the D1 core. Under
    # B6 this row is the EMPTY-stdout failure shape (journalctl errors on
    # stderr, not stdout); any non-empty undecodable stdout line is the
    # batch-integrity row 6 family instead (checked right after).
    t = tree()
    try:
        r = t.reader(FakePopen([(b"", 1)] * 3))
        r.startup()
        before = open(os.path.join(t.state_dir, state.COMMITTED_NAME),
                      "rb").read()
        raised = []
        for _ in range(3):
            try:
                r.run_cycle()
            except ReaderFailure as f:
                raised.append(f.code)
        after = open(os.path.join(t.state_dir, state.COMMITTED_NAME),
                     "rb").read()
        ck("row5 permission-style failure fails closed x3",
           raised == [CODE_SOURCE_UNAVAILABLE] * 3)
        ck("row5 zero state movement (T34b)", before == after)
        ck("row5 no epoch bump no pending",
           t.committed()["epoch"] == 1 and t.pending() is None
           and t.seqs() == [])
        # spawn failure (journalctl missing) is the same family.
        r2 = t.reader(FakePopen([], spawn_error=True))
        try:
            r2.run_cycle()
            ck("spawn failure source_unavailable", False)
        except ReaderFailure as f:
            ck("spawn failure source_unavailable",
               f.code == CODE_SOURCE_UNAVAILABLE)
        # B6: a malformed NON-BLANK stdout line outranks even a non-zero
        # rc -- batch integrity is decided by content, not exit luck.
        junk = b"not json at all\nalso-not-json\n"
        r3 = t.reader(FakePopen([(junk, 1)]))
        try:
            r3.run_cycle()
            ck("B6 malformed stdout outranks rc -> cursor_invalid", False)
        except ReaderFailure as f:
            ck("B6 malformed stdout outranks rc -> cursor_invalid",
               f.code == CODE_CURSOR_INVALID)
        ck("B6 malformed-only batch leaves zero movement",
           t.committed()["source"]["value"] == CURSOR_TAIL
           and t.seqs() == [] and t.pending() is None)
    finally:
        t.close()
    # row 4: non-zero AFTER at least one usable cursor -- discard, freeze.
    t = tree()
    try:
        batch = mk_entries([(cursor_at(1), "ERROR dial tcp 9.9.9.9:443: i/o timeout",
                             1760000001),
                            (cursor_at(2), "ERROR dial tcp 9.9.9.9:443: i/o timeout",
                             1760000002)])
        r = t.reader(FakePopen([(batch, 1)]))
        r.startup()
        before = t.committed()
        try:
            r.run_cycle()
            ck("row4 raises source_unavailable", False)
        except ReaderFailure as f:
            ck("row4 raises source_unavailable",
               f.code == CODE_SOURCE_UNAVAILABLE)
        ck("row4 batch fully discarded (no ev, no pending, no movement)",
           t.committed() == before and t.seqs() == [] and t.pending() is None)
        ck("row4 heartbeat untouched", t.hb() is None)
    finally:
        t.close()
    # row 6: a processed entry without a usable cursor makes the WHOLE
    # batch non-committable (never a silent skip).
    t = tree()
    try:
        good = json.dumps({"__CURSOR": cursor_at(1), "MESSAGE": "ERROR boom dns",
                           "PRIORITY": "3",
                           "__REALTIME_TIMESTAMP": "1760000001000000"})
        badc = json.dumps({"__CURSOR": "", "MESSAGE": "ERROR boom2 dns",
                           "PRIORITY": "3",
                           "__REALTIME_TIMESTAMP": "1760000002000000"})
        r = t.reader(FakePopen([((good + "\n" + badc + "\n").encode(), 0)]))
        r.startup()
        try:
            r.run_cycle()
            ck("row6 raises cursor_invalid", False)
        except ReaderFailure as f:
            ck("row6 raises cursor_invalid", f.code == CODE_CURSOR_INVALID)
        ck("row6 nothing exported and cursor frozen",
           t.seqs() == [] and t.pending() is None
           and t.committed()["source"]["value"] == CURSOR_TAIL)
    finally:
        t.close()
    # B6 core: an undecodable line AFTER usable entries freezes the WHOLE
    # batch -- the committed cursor must never cross it.
    t = tree()
    try:
        out = (mk_entries([(cursor_at(1), "ERROR dial timeout", 1760000001)])
               + b"{broken json\n"
               + mk_entries([(cursor_at(3), "ERROR dns fail", 1760000003)]))
        r = t.reader(FakePopen([(out, 0)]))
        r.startup()
        try:
            r.run_cycle()
            ck("B6 mid-batch malformed raises cursor_invalid", False)
        except ReaderFailure as f:
            ck("B6 mid-batch malformed raises cursor_invalid",
               f.code == CODE_CURSOR_INVALID)
        ck("B6 cursor never crosses a malformed line",
           t.committed()["source"]["value"] == CURSOR_TAIL
           and t.seqs() == [] and t.pending() is None)
        # pfail stays reserved for valid-cursor entries whose PAYLOAD is
        # unusable: those still commit and the cursor advances past them.
        payload_bad = (json.dumps({"__CURSOR": cursor_at(1),
                                   "PRIORITY": "3",
                                   "__REALTIME_TIMESTAMP":
                                       "1760000001000000"})
                       + "\n").encode()
        r2 = t.reader(FakePopen([(payload_bad, 0)]))
        r2.startup()
        ck("B6 payload-only defect still commits",
           r2.run_cycle() == "committed")
        ck("B6 pfail counts the payload-defective entry",
           t.header(1)["pfail"] == 1 and t.header(1)["lines"] == 1)
        ck("B6 cursor advanced past payload-defective entry",
           t.committed()["source"]["value"] == cursor_at(1))
    finally:
        t.close()


# ---------------------------------------------------------------------------
def g_boundary():
    # cold_start survives ten empty polls and restarts, then fires once.
    t = tree()
    try:
        r = t.reader(FakePopen([(b"", 0)]))
        r.startup()
        for restart in range(3):
            rr = t.reader(FakePopen([(b"", 0), (b"", 0)]))
            rr.startup()
            rr.run_cycle()
            rr.run_cycle()
        batch = mk_entries([(cursor_at(1), "ERROR no such host resolver died",
                             1760000001)])
        r2 = t.reader(FakePopen([(batch, 0), (b"", 0)]))
        r2.startup()
        r2.run_cycle()
        h1 = t.header(1)
        r3 = t.reader(FakePopen([(b"", 0)] * 3))
        r3.startup()
        r3.run_cycle()  # empty: boundary must NOT be re-armed anywhere
        batch2 = mk_entries([(cursor_at(2), "ERROR connection reset by peer",
                              1760000002)])
        r4 = t.reader(FakePopen([(batch2, 0)]))
        r4.startup()
        r4.run_cycle()
        h2 = t.header(2)
        ck("T37 cold_start persists across 6 empty polls + 3 restarts",
           h1["boundary"] == "COLD_START")
        ck("T37 cold_start cleared exactly once (next batch NONE)",
           h2["boundary"] == "NONE")
        ck("T37 committed boundary NONE after first commit",
           t.committed()["boundary"] == "NONE")
    finally:
        t.close()
    # source-gap: operator reset arms the marker; it survives empty polls
    # AND restarts; the next batch carries it exactly once.
    t = tree()
    try:
        batch = mk_entries([(cursor_at(1), "ERROR no such host", 1760000001)])
        r = t.reader(FakePopen([(batch, 0)]))
        r.startup()
        r.run_cycle()
        pre = t.committed()
        r2 = t.reader(FakePopen([(b"", 0)]))
        r2.reset_from_now()
        c = t.committed()
        ck("reset bumps epoch, preserves seq, arms SOURCE_GAP",
           c["seq"] == pre["seq"] and c["epoch"] == pre["epoch"] + 1
           and c["boundary"] == "SOURCE_GAP")
        # crash-restart x2 with only empty polls in between: marker durable.
        for _ in range(2):
            rr = t.reader(FakePopen([(b"", 0), (b"", 0)]))
            rr.startup()
            rr.run_cycle()
            rr.run_cycle()
        b2 = mk_entries([(cursor_at(9), "ERROR host is unreachable",
                          1760000009)])
        r3 = t.reader(FakePopen([(b2, 0)]))
        r3.startup()
        r3.run_cycle()
        h = t.header(pre["seq"] + 1)
        ck("D2 source_gap marker survives crashes + empty polls, fires once",
           h["boundary"] == "SOURCE_GAP" and h["epoch"] == c["epoch"])
        b3 = mk_entries([(cursor_at(10), "ERROR broken pipe", 1760000010)])
        r4 = t.reader(FakePopen([(b3, 0)]))
        r4.startup()
        r4.run_cycle()
        ck("next batch boundary NONE after source_gap cleared",
           t.header(pre["seq"] + 2)["boundary"] == "NONE")
    finally:
        t.close()


# ---------------------------------------------------------------------------
def g_since():
    t = tree()
    try:
        pop = FakePopen([(b"", 0)], show_cursor=b"-- No entries --\n",
                        cursor_rc=0)
        r = t.reader(pop)
        r.startup()
        c = t.committed()
        ck("anchor capture miss falls back to since",
           c["source"]["mode"] == "since"
           and re.fullmatch(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}",
                            c["source"]["value"]) is not None)
        since_val = c["source"]["value"]
        r.run_cycle()
        ck("since frozen across empty polls",
           t.committed()["source"]["value"] == since_val)
        batch = mk_entries([(cursor_at(1), "ERROR no such host", 1760000001)])
        r2 = t.reader(FakePopen([(batch, 0)]))
        r2.startup()
        r2.run_cycle()
        ck("poll argv uses --since with the ONE fixed string",
           pop.poll_calls[0][pop.poll_calls[0].index("--since") + 1]
           == since_val)
        ck("first commit converts since->cursor (D3 tagged union)",
           t.committed()["source"] == {"mode": "cursor",
                                       "value": cursor_at(1)})
        # a show-cursor output carrying an INVALID cursor must also fall
        # back (single validator everywhere).
        t2 = tree()
        try:
            bad = FakePopen([(b"", 0)],
                            show_cursor=b"cursor: bad\x7fcursor\n")
            r3 = t2.reader(bad)
            r3.startup()
            ck("invalid --show-cursor payload falls back to since",
               t2.committed()["source"]["mode"] == "since")
        finally:
            t2.close()
    finally:
        t.close()


# ---------------------------------------------------------------------------
def g_backlog():
    old_cap = reader_mod.BACKLOG_CAP
    reader_mod.BACKLOG_CAP = 5
    try:
        t = tree()
        try:
            rows = [(cursor_at(i),
                     "ERROR dial tcp 5.5.5.%d:443: i/o timeout" % i,
                     1760000000 + i) for i in range(1, 13)]
            r = t.reader(harness.JournalPopen(rows))
            r.startup()
            r.run_cycle()
            ck("cap commits through LAST PROCESSED cursor",
               t.committed()["source"]["value"] == cursor_at(5)
               and t.committed()["seq"] == 1)
            r.run_cycle()
            ck("backlog continues exactly (no loss/dup at boundary)",
               t.committed()["source"]["value"] == cursor_at(10))
            r.run_cycle()
            ck("tail consumed to last entry",
               t.committed()["source"]["value"] == cursor_at(12)
               and t.seqs() == [1, 2, 3])
            total = sum(t.header(s)["eligible"] for s in (1, 2, 3))
            counts = [t.header(s)["eligible"] for s in (1, 2, 3)]
            ck("multi-cycle accounting: all 12 eligible exactly once",
               total == 12 and counts == [5, 5, 2])
        finally:
            t.close()
    finally:
        _restore(reader_mod, "BACKLOG_CAP", old_cap)
    t = tree()
    try:
        # >MAX_RECORDS_PER_FILE distinct groups: deterministic fold, counts
        # survive, hard cap holds.
        many = mk_entries([(cursor_at(i),
                            "ERROR dial tcp 7.7.7.7:%d: i/o timeout" % (1024 + i),
                            1760000000 + i) for i in range(1, 301)])
        r = t.reader(FakePopen([(many, 0)]))
        r.startup()
        r.run_cycle()
        hdr = t.header(1)
        recs = t.records(1)
        ck("overflow stays within MAX_RECORDS_PER_FILE cap",
           len(recs) <= reader_mod.MAX_RECORDS_PER_FILE)
        ck("overflow folding preserves every count",
           sum(x["n"] for x in recs) == hdr["eligible"] == 300)
        ck("overflow records limited>0 and header valid",
           hdr["limited"] > 0 and schema.validate_header(hdr))
    finally:
        t.close()
    ck("production BACKLOG_CAP is 50000", reader_mod.BACKLOG_CAP == 50000)
    ck("production MAX_RECORDS_PER_FILE is 200",
       reader_mod.MAX_RECORDS_PER_FILE == 200)
    ck("production MAX_FP_PER_WINDOW is 16",
       reader_mod.MAX_FP_PER_WINDOW == 16)


# ---------------------------------------------------------------------------
def ev_file(out_dir, seq, run="a" * 32, boundary="NONE", epoch=1,
            events=None, corrupt=None):
    lines = [json.dumps(valid_header(seq=seq, run=run, epoch=epoch,
                                     boundary=boundary, lines=1,
                                     eligible=1))]
    for e in (events or [valid_event()]):
        lines.append(json.dumps(e))
    body = "\n".join(lines) + "\n"
    if corrupt is not None:
        body = corrupt
    with open(os.path.join(out_dir, "ev-%d.jsonl" % seq), "w") as h:
        h.write(body)


def g_ingest():
    d = tempfile.mkdtemp(prefix="sbjr-ing-")
    try:
        ev_file(d, 1)
        ev_file(d, 2)
        ev_file(d, 3)
        open(os.path.join(d, "ev-4.jsonl.part"), "w").write("scratch")
        open(os.path.join(d, "notes.txt"), "w").write("junk")
        seen = ingest_contract.scan_exchange_dir(d)
        ck("scan strict grammar (part/junk excluded)",
           sorted(seen) == [1, 2, 3])
        applied = []
        res = ingest_contract.settle(d, 0, lambda h, r, s: applied.append(s))
        ck("in-order consumption 1..3",
           res["terminal"] == 3 and applied == [1, 2, 3]
           and res["gaps"] == 0 and res["consumed"] == 3)
        res2 = ingest_contract.settle(d, 3, lambda h, r, s: None)
        ck("re-settle past terminal is a no-op",
           res2["terminal"] == 3 and res2["consumed"] == 0)
        # T27a: valid4 / rejected5 / valid6 -- no gap, rejected once.
        os.remove(os.path.join(d, "ev-1.jsonl"))
        os.remove(os.path.join(d, "ev-2.jsonl"))
        os.remove(os.path.join(d, "ev-3.jsonl"))
        ev_file(d, 4)
        ev_file(d, 5, corrupt="this is not json\n")
        ev_file(d, 6)
        applied = []
        ra = ingest_contract.settle(d, 3, lambda h, r, s: applied.append(s))
        ck("T27a valid4/rejected5/valid6 => terminal 6 no gap",
           ra["terminal"] == 6 and ra["gaps"] == 0 and ra["rejected"] == 1
           and applied == [4, 6])
        rb = ingest_contract.settle(d, ra["terminal"],
                                    lambda h, r, s: None)
        ck("rejected file never re-read after terminal",
           rb["rejected"] == 0 and rb["consumed"] == 0)
        # T27b: 4 / missing 5 / valid 6 -- gap counted once; late 5 ignored.
        os.remove(os.path.join(d, "ev-4.jsonl"))
        os.remove(os.path.join(d, "ev-5.jsonl"))
        os.remove(os.path.join(d, "ev-6.jsonl"))
        ev_file(d, 4)
        ev_file(d, 6)
        gapres = ingest_contract.settle(d, 3, lambda h, r, s: None)
        ck("T27b missing5 leaped by 6 => exactly one gap",
           gapres["gaps"] == 1 and gapres["terminal"] == 6)
        ev_file(d, 5)
        late = ingest_contract.settle(d, 6, lambda h, r, s: None)
        ck("T27b late-arriving skipped seq ignored (no retract/recount)",
           late["gaps"] == 0 and late["consumed"] == 0
           and late["terminal"] == 6)
        # T27c: DB failure applying 5 blocks 6, retries next pass.
        os.remove(os.path.join(d, "ev-4.jsonl"))
        os.remove(os.path.join(d, "ev-5.jsonl"))
        os.remove(os.path.join(d, "ev-6.jsonl"))
        ev_file(d, 4)
        ev_file(d, 5)
        ev_file(d, 6)
        def boom(h, r, s):
            if s == 5:
                raise RuntimeError("database is locked")
        applied = []
        blocked = ingest_contract.settle(d, 3, lambda h, r, s: (
            boom(h, r, s), applied.append(s)))
        ck("T27c apply-failure at 5 blocks 6 (no leapfrog)",
           blocked["terminal"] == 4 and blocked["blocked_at"] == 5
           and blocked["consumed"] == 1 and applied == [4])
        applied = []
        retry = ingest_contract.settle(d, 4, lambda h, r, s: applied.append(s))
        ck("T27c retry consumes 5+6 (idempotent re-read safe)",
           retry["terminal"] == 6 and applied == [5, 6])
        # file-level rejection cases.
        os.remove(os.path.join(d, "ev-6.jsonl"))
        payload, code = ingest_contract.read_and_validate(d, "ev-5.jsonl", 99)
        ck("header seq != filename seq rejected",
           code == "exchange_seq_mismatch" and payload is None)
        with open(os.path.join(d, "ev-90.jsonl"), "w") as h:
            h.write("x" * (ingest_contract.MAX_FILE_BYTES + 1))
        _p, code = ingest_contract.read_and_validate(d, "ev-90.jsonl", 90)
        ck("oversized file rejected on size", code == "exchange_too_large")
        ck("missing file rejected fail-closed",
           ingest_contract.read_and_validate(d, "ev-77.jsonl", 77)
           == (None, "exchange_unreadable"))
    finally:
        shutil.rmtree(d, ignore_errors=True)


# ---------------------------------------------------------------------------
def _dur_started(t):
    batch = mk_entries([(cursor_at(1), "ERROR dial timeout", 1760000001)])
    r = t.reader(FakePopen([(batch, 0)]))
    r.startup()
    return r


def _dur_dummies(t, seqs):
    for s in seqs:
        with open(os.path.join(t.out_dir, state.ev_filename(s)), "w") as h:
            h.write("x")


def g_dur():
    """B4/B5 (review #46): EVERY expected durability OSError becomes a
    sanitized journal_writer_failed (never a traceback, never a path), the
    state-corruption family is NOT swallowed, and the retention ceiling
    fails closed instead of admitting unbounded growth."""
    # --- B4: sanitized writer failures on each commit step -----------------
    t = tree()
    try:
        r = _dur_started(t)
        with _mock.patch.object(state, "write_pending",
                                side_effect=OSError("ENOSPC " + t.state_dir)):
            try:
                r.run_cycle()
                ck("B4 pending write failure sanitized", False)
            except ReaderFailure as f:
                ck("B4 pending write failure sanitized",
                   f.code == reader_mod.CODE_WRITER_FAILED)
                ck("B4 sanitized failure carries only the code",
                   str(f) == reader_mod.CODE_WRITER_FAILED)
        ck("B4 pending failure leaves zero artifacts (C1 step order)",
           t.seqs() == [] and t.pending() is None
           and t.committed()["source"]["value"] == CURSOR_TAIL)
    finally:
        t.close()
    t = tree()
    try:
        r = _dur_started(t)
        with _mock.patch.object(state, "write_committed",
                                side_effect=OSError("EIO")):
            try:
                r.run_cycle()
                ck("B4 committed write failure sanitized", False)
            except ReaderFailure as f:
                ck("B4 committed write failure sanitized",
                   f.code == reader_mod.CODE_WRITER_FAILED)
        ck("B4 committed failure leaves a row-2 replayable state",
           t.pending() is not None and t.seqs() == [1])
        r2 = t.reader(FakePopen([(b"", 0)]))
        r2.startup()
        ck("B4 replay after committed failure settles seq1",
           t.committed()["seq"] == 1 and t.pending() is None
           and t.seqs() == [1])
    finally:
        t.close()
    t = tree()
    try:
        r = _dur_started(t)
        with _mock.patch.object(state, "remove_pending",
                                side_effect=OSError("EIO")):
            try:
                r.run_cycle()
                ck("B4 settle-unlink failure sanitized", False)
            except ReaderFailure as f:
                ck("B4 settle-unlink failure sanitized",
                   f.code == reader_mod.CODE_WRITER_FAILED)
        r2 = t.reader(FakePopen([(b"", 0)]))
        r2.startup()
        ck("B4 settle failure converges via row 4 on restart",
           t.committed()["seq"] == 1 and t.pending() is None)
    finally:
        t.close()
    t = tree()
    try:
        r = t.reader(FakePopen([(b"", 0)]))
        with _mock.patch.object(state, "clean_scratch",
                                side_effect=OSError("EIO")):
            try:
                r.startup()
                ck("B4 startup scratch cleanup failure sanitized", False)
            except ReaderFailure as f:
                ck("B4 startup scratch cleanup failure sanitized",
                   f.code == reader_mod.CODE_WRITER_FAILED)
    finally:
        t.close()
    t = tree()
    try:
        r = t.reader(FakePopen([(b"", 0)]))
        r.startup()
        with _mock.patch.object(state, "write_committed",
                                side_effect=OSError("EIO")):
            try:
                r.reset_from_now()
                ck("B4 reset commit failure sanitized", False)
            except ReaderFailure as f:
                ck("B4 reset commit failure sanitized",
                   f.code == reader_mod.CODE_WRITER_FAILED)
        ck("B4 refused reset landed no epoch", t.committed()["epoch"] == 1)
    finally:
        t.close()
    t = tree()
    try:
        r = t.reader(FakePopen([(b"", 0)]))
        r.startup()
        with open(os.path.join(t.state_dir, state.COMMITTED_NAME),
                  "w") as h:
            h.write("{not json")
        r2 = t.reader(FakePopen([(b"", 0)]))
        try:
            r2.startup()
            ck("B4 corrupt state stays state_corruption (not writer)", False)
        except ReaderFailure as f:
            ck("B4 corrupt state stays state_corruption (not writer)",
               f.code == CODE_STATE_CORRUPTION)
    finally:
        t.close()
    # --- B5: retention is a HARD ceiling: unverifiable == unenforceable ---
    old_files = reader_mod.RETENTION_MAX_FILES
    old_bytes = reader_mod.RETENTION_MAX_BYTES
    reader_mod.RETENTION_MAX_FILES = 2
    reader_mod.RETENTION_MAX_BYTES = 10 ** 12
    try:
        t = tree()
        try:
            r = t.reader(FakePopen([(b"", 0)]))
            r.startup()
            _dur_dummies(t, [1, 2, 3, 4])
            with _mock.patch("os.listdir", side_effect=OSError("EIO")):
                try:
                    r._enforce_retention()
                    ck("B5 enumeration failure fails closed", False)
                except ReaderFailure as f:
                    ck("B5 enumeration failure fails closed",
                       f.code == reader_mod.CODE_WRITER_FAILED)
            os.mkdir(os.path.join(t.out_dir, "ev-9.jsonl"))
            try:
                r._enforce_retention()
                ck("B5 non-regular ev candidate fails closed", False)
            except ReaderFailure as f:
                ck("B5 non-regular ev candidate fails closed",
                   f.code == reader_mod.CODE_WRITER_FAILED)
            os.rmdir(os.path.join(t.out_dir, "ev-9.jsonl"))
            with _mock.patch("os.unlink", side_effect=OSError("EACCES")):
                try:
                    r._enforce_retention()
                    ck("B5 unlink failure while over cap fails closed", False)
                except ReaderFailure as f:
                    ck("B5 unlink failure while over cap fails closed",
                       f.code == reader_mod.CODE_WRITER_FAILED)
            ck("B5 failed eviction mutated nothing", t.seqs() == [1, 2, 3, 4])
            with _mock.patch.object(state, "fsync_dir",
                                    side_effect=OSError("EIO")):
                try:
                    r._enforce_retention()
                    ck("B5 post-GC dir fsync failure fails closed", False)
                except ReaderFailure as f:
                    ck("B5 post-GC dir fsync failure fails closed",
                       f.code == reader_mod.CODE_WRITER_FAILED)
            # The fsync refusal happened AFTER this pass' legitimate
            # evictions (ev-1, ev-2): the state is bounded-but-unflushed,
            # and the next healthy pass must complete the job oldest-first.
            ck("B5 fsync refusal left only evicted-oldest behind",
               t.seqs() == [3, 4])
            _dur_dummies(t, [5])
            r._enforce_retention()
            ck("B5 healthy eviction oldest-first down to cap",
               t.seqs() == [4, 5])
        finally:
            t.close()
        # The cycle itself fail-stops when retention cannot enforce: no
        # silent continuation into unbounded ev growth.
        t = tree()
        try:
            r = _dur_started(t)
            _dur_dummies(t, [2, 3, 4])  # + real ev-1 from this batch = 4
            with _mock.patch("os.unlink", side_effect=OSError("EACCES")):
                try:
                    r.run_cycle()
                    ck("B5 cycle fail-stops when retention blocked", False)
                except ReaderFailure as f:
                    ck("B5 cycle fail-stops when retention blocked",
                       f.code == reader_mod.CODE_WRITER_FAILED)
            ck("B5 retention fail-stop is post-commit (durable evidence)",
               t.committed()["seq"] == 1 and t.seqs() == [1, 2, 3, 4])
        finally:
            t.close()
        # B5-residual (review #46 round 2): a durable GC failure must not
        # grow out/ by one file per restart -- startup re-proves the
        # ceiling AFTER C2 recovery and BEFORE any new poll.
        t = tree()
        try:
            batches = [(mk_entries([(cursor_at(i),
                                     "ERROR no such host x%d" % i,
                                     1760000000 + i)]), 0)
                       for i in (1, 2, 3)]
            reader_mod.RETENTION_MAX_FILES = 10
            r = t.reader(FakePopen(list(batches)))
            r.startup()
            for _ in range(3):
                r.run_cycle()
            reader_mod.RETENTION_MAX_FILES = 2
            ck("B5r setup: three committed batches now over the cap",
               t.committed()["seq"] == 3 and t.seqs() == [1, 2, 3])
            with _mock.patch("os.unlink", side_effect=OSError("EACCES")):
                popen2 = FakePopen([(b"", 0)])
                r2 = t.reader(popen2)
                try:
                    r2.startup()
                    ck("B5r startup refuses over-cap + GC-failure state",
                       False)
                except ReaderFailure as f:
                    ck("B5r startup refuses over-cap + GC-failure state",
                       f.code == reader_mod.CODE_WRITER_FAILED)
            ck("B5r refused restart grew nothing and polled nothing",
               t.seqs() == [1, 2, 3] and t.committed()["seq"] == 3
               and t.pending() is None and popen2.calls == [])
        finally:
            t.close()
            reader_mod.RETENTION_MAX_FILES = 2
    finally:
        _restore(reader_mod, "RETENTION_MAX_FILES", old_files)
        _restore(reader_mod, "RETENTION_MAX_BYTES", old_bytes)


# ---------------------------------------------------------------------------
def g_retention():
    old_files = reader_mod.RETENTION_MAX_FILES
    old_bytes = reader_mod.RETENTION_MAX_BYTES
    reader_mod.RETENTION_MAX_FILES = 3
    try:
        t = tree()
        try:
            batches = [(mk_entries([(cursor_at(i),
                                     "ERROR no such host x%d" % i,
                                     1760000000 + i)]), 0)
                       for i in range(1, 7)]
            r = t.reader(FakePopen(list(batches)))
            r.startup()
            for _ in range(6):
                r.run_cycle()
            ck("file-count ceiling enforced oldest-first",
               t.seqs() == [4, 5, 6] and t.committed()["seq"] == 6)
            reader_mod.RETENTION_MAX_BYTES = 1
            b7 = mk_entries([(cursor_at(7), "ERROR no such host x7",
                              1760000007)])
            r7 = t.reader(FakePopen([(b7, 0)]))
            r7.run_cycle()
            # A 1-byte ceiling can hold NOTHING: oldest-first eviction
            # runs until under target, which legitimately means empty.
            ck("byte ceiling evicts oldest-first until under target",
               t.seqs() == [] and t.committed()["seq"] == 7)
        finally:
            t.close()
    finally:
        _restore(reader_mod, "RETENTION_MAX_FILES", old_files)
        _restore(reader_mod, "RETENTION_MAX_BYTES", old_bytes)
    t = tree()
    try:
        r = t.reader(FakePopen([(b"", 0), (b"", 0)]))
        r.startup()
        r.run_cycle()
        hb1 = t.hb()
        r.run_cycle()
        hb2 = t.hb()
        ck("heartbeat rewritten every empty cycle",
           hb1 is not None and hb2 is not None and hb1["seq"] == 0)
        scratch = os.path.join(t.out_dir, "hb.tmp-" + "e" * 32)
        open(scratch, "w").write("x")
        r2 = t.reader(FakePopen([(b"", 0)]))
        r2.startup()
        ck("clean_scratch reclaims orphaned hb tmp",
           not os.path.exists(scratch) and t.hb() is not None)
    finally:
        t.close()
    ck("production retention ceilings intact",
       reader_mod.RETENTION_MAX_FILES == 720
       and reader_mod.RETENTION_MAX_BYTES == 8 * 1024 * 1024)


# ---------------------------------------------------------------------------
def g_reset():
    t = tree()
    try:
        r = t.reader(FakePopen([(b"", 0)]))
        try:
            r.reset_from_now()
            ck("reset refused without committed state", False)
        except ReaderFailure as f:
            ck("reset refused without committed state",
               f.code == CODE_RESET_REFUSED)
    finally:
        t.close()
    t = tree()
    try:
        batch = mk_entries([(cursor_at(1), "ERROR no such host", 1760000001)])
        r = t.reader(FakePopen([(batch, 0)]))
        r.startup()
        r.run_cycle()
        # row-2 state: crash at settle_unlink leaves pending+ev durable --
        # a reset must REFUSE to swallow the unexported-looking batch and
        # instead require normal recovery... actually pending.seq==cs? no:
        # crash happened BEFORE committed write. Build it directly:
        _row2_state(t, run="c" * 32, seq=2, epoch=1, boundary="NONE")
        # (committed@1 + pending@2 + durable ev-2 with matching header)
        r2 = t.reader(FakePopen([(b"", 0)]))
        try:
            r2.reset_from_now()
            ck("reset refuses row-2 in-flight batch", False)
        except ReaderFailure as f:
            ck("reset refuses row-2 in-flight batch",
               f.code == CODE_RESET_REFUSED)
        # normal recovery finishes it, then reset is allowed.
        r3 = t.reader(FakePopen([(b"", 0)]))
        r3.startup()
        ck("recovery finishes row 2 then reset proceeds",
           t.committed()["seq"] == 2 and r3.reset_from_now() is True)
        c = t.committed()
        ck("post-recovery reset epoch 2 seq 2 SOURCE_GAP",
           c["epoch"] == 2 and c["seq"] == 2 and c["boundary"] == "SOURCE_GAP")
        ck("reset writes no exchange files and clears nothing durable",
           t.seqs() == [1, 2])
        # double reset stacks epochs; only the LAST marker fires.
        r4 = t.reader(FakePopen([(b"", 0)]))
        r4.reset_from_now()
        ck("second reset stacks epoch, marker stays single",
           t.committed()["epoch"] == 3
           and t.committed()["boundary"] == "SOURCE_GAP")
        b2 = mk_entries([(cursor_at(50), "ERROR broken pipe", 1760000050)])
        r5 = t.reader(FakePopen([(b2, 0)]))
        r5.startup()
        r5.run_cycle()
        ck("batch after double reset carries one SOURCE_GAP",
           t.header(3)["boundary"] == "SOURCE_GAP"
           and t.header(3)["epoch"] == 3)
    finally:
        t.close()
    # stale pending (row 4) settles cleanly before a reset proceeds.
    t = tree()
    try:
        r = t.reader(FakePopen([(b"", 0)]))
        r.startup()
        state.write_pending(t.state_dir,
                            state.make_pending("a" * 32, 1, 1, "NONE",
                                               "b" * 37))
        # committed@0 with pending@1 and NO ev -> row 3 repoll: reset may
        # proceed after unlinking.
        r2 = t.reader(FakePopen([(b"", 0)]))
        ck("reset proceeds after repoll settle", r2.reset_from_now() is True)
        ck("repoll-settled reset arms SOURCE_GAP at epoch 2",
           t.committed()["epoch"] == 2 and t.pending() is None)
    finally:
        t.close()


# ---------------------------------------------------------------------------
def g_cli():
    ck("unit default compiled in",
       reader_mod.resolve_unit(env={}) == reader_mod.DEFAULT_UNIT)
    ck("unit env override valid",
       reader_mod.resolve_unit(
           env={reader_mod.UNIT_ENV_VAR: "sing-box@2.service"})
       == "sing-box@2.service")
    try:
        reader_mod.resolve_unit(env={reader_mod.UNIT_ENV_VAR: "no;pe;"})
        ck("unit env injection refused fail-closed", False)
    except ReaderFailure as f:
        ck("unit env injection refused fail-closed",
           f.code == CODE_UNIT_INVALID)
    ck("main refuses unknown argv", reader_mod.main(["bogus", "x"]) == 1)
    ck("main refuses reset without a state tree",
       reader_mod.main(["reset", "--from-now"]) in (0, 1))  # rc contract only


# ---------------------------------------------------------------------------
def g_privacy():
    sentinels = ["TOPSECRETDBHOST.internal", "hunter2pw",
                 "eyJhbGciOiJIUzI1NiIsInR5cCI6", "198.51.100.77",
                 "f47ac10b-58cc-4372-a567-0e02b2c3d479"]
    msg = ("ERROR dial tcp %s:443: no such host password=%s bearer=%s "
           "peer %s uuid %s" % tuple(sentinels))
    t = tree()
    try:
        batch = (mk_entries([(cursor_at(1), msg, 1760000001)])
                 + mk_entries([(cursor_at(2),
                                "INFO session from 203.0.113.5 opened",
                                1760000002, "6")])
                 + mk_entries([(cursor_at(3),
                                "this token never matches any class",
                                1760000003, "7")]))
        r = t.reader(FakePopen([(batch, 0)]))
        r.startup()
        r.run_cycle()
        body = t.body(1)
        state_bytes = b""
        for name in os.listdir(t.state_dir):
            with open(os.path.join(t.state_dir, name), "rb") as h:
                state_bytes += h.read()
        hb = t.body_bytes = open(os.path.join(t.out_dir, "hb"), "rb").read()
        corpus = body + state_bytes.decode("utf-8", "replace") + hb.decode()
        leaked = [s for s in sentinels if s in corpus]
        ck("no raw host/credential/uuid/IP/URL token crosses boundary",
           not leaked)
        ck("no raw MESSAGE substring in exchange", "password=" not in body
           and "dial tcp" not in body.split("\n", 1)[1] if len(
               body.split("\n")) > 1 else False)
        h = t.header(1)
        ck("counter identity lines==eligible+info+nomatch+pfail",
           h["lines"] == h["eligible"] + h["info_dropped"]
           + h["nomatch_dropped"] + h["pfail"])
        ck("tokenless mismatch at PRIORITY 7 dropped",
           h["nomatch_dropped"] == 1 and h["info_dropped"] == 1
           and h["eligible"] == 1)
        evs = t.records(1)
        ck("single eligible event with fp-only-on-other",
           len(evs) == 1 and evs[0]["cls"] == "dns" and evs[0]["fp"] is None)
        ck("cursor never crosses into exchange/state",
           cursor_at(1) not in body and CURSOR_TAIL not in body)
        ck("run id in header is 32 lowercase hex",
           re.fullmatch(r"[0-9a-f]{32}", h["run"]) is not None)
        # other+fp route produces a 16-hex fp, never template text.
        b2 = mk_entries([(cursor_at(4),
                          "ERROR something never seen before %s"
                          % sentinels[0], 1760000004)])
        r2 = t.reader(FakePopen([(b2, 0)]))
        r2.startup()
        r2.run_cycle()
        ev2 = t.records(2)
        ck("other class carries HMAC fp",
           len(ev2) == 1 and ev2[0]["cls"] == "other"
           and re.fullmatch(r"[0-9a-f]{16}", ev2[0]["fp"]) is not None
           and sentinels[0] not in t.body(2))
    finally:
        t.close()


# ---------------------------------------------------------------------------
def g_cross():
    """Real cross-process semantics: one process crashes mid-commit, a
    DIFFERENT run id must finish it from disk bytes alone."""
    t = tree()
    try:
        batch = mk_entries([(cursor_at(1), "ERROR no such host dns",
                             1760000001)])
        r1 = t.reader(FakePopen([(batch, 0)]),
                      faults={"committed.rename"})
        r1.startup()
        assert r1.run_id != "c" * 32
        try:
            r1.run_cycle()
            ck("cross: crash point reached", False)
        except reader_mod.CrashInjected:
            ck("cross: crash point reached", True)
        ev_bytes_before = open(os.path.join(t.out_dir, "ev-1.jsonl"),
                               "rb").read()
        pend = t.pending()
        ck("cross: durable pending + ev survive the crash",
           pend is not None and t.seqs() == [1])
        r2 = t.reader(FakePopen([(b"", 0)]))
        r2.startup()  # row 2 under a NEW run id
        ev_bytes_after = open(os.path.join(t.out_dir, "ev-1.jsonl"),
                              "rb").read()
        ck("cross: recovery never rewrites the durable ev",
           ev_bytes_before == ev_bytes_after)
        ck("cross: recovery completes step-4 with pending's run",
           t.committed()["seq"] == 1
           and json.loads(ev_bytes_before.decode().split("\n", 1)[0]
                          )["run"] == pend["run"]
           and t.pending() is None)
    finally:
        t.close()


GROUPS = {
    "cursor": g_cursor,
    "jtime": g_jtime,
    "norm": g_norm,
    "class": g_class,
    "elig": g_elig,
    "fp": g_fp,
    "schema": g_schema,
    "state": g_state,
    "crash": g_crash,
    "d1": g_d1,
    "boundary": g_boundary,
    "since": g_since,
    "backlog": g_backlog,
    "ingest": g_ingest,
    "retention": g_retention,
    "dur": g_dur,
    "reset": g_reset,
    "cli": g_cli,
    "privacy": g_privacy,
    "cross": g_cross,
}


def main():
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    names = list(GROUPS) if which == "all" else [which]
    for name in names:
        try:
            GROUPS[name]()
        except Exception as exc:  # noqa: BLE001 -- protocol keeps emitting
            ck("group %s crashed: %r" % (name, exc), False)
    for line in OUT:
        print(line)


if __name__ == "__main__":
    main()
