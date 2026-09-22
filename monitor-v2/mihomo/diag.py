#!/usr/bin/env python3
"""Monitor v2 Phase E4-Diag -- client-side Mihomo failover FORENSICS (issue #41).

Read-only, local-only diagnostic recorder. Where E4 (client.py) answers
"what does the controller look like RIGHT NOW" as one display-only enrichment
object, E4-Diag answers "WHAT ACTUALLY HAPPENED around the failover that did
not happen" AFTER the fact, from a local JSONL evidence trail:

    H1 node marked dead        -> member alive=false + history delay 0 (RAW)
    H2 alive-but-failing       -> alive=true + history cadence + stale chains
    H3 manual outer pin        -> group type + now (selectors never inferred)
    H4 probe healthy, relay broken -> per-test-url extra histories
    H5 not yet re-tested       -> >=2 samples inside one health interval
    H6 connections not migrating -> chain attribution + stale_after_switch

Everything the E4 security posture guarantees is reused VERBATIM from
client.py (this module imports the audited pieces, it does not fork them):
fail-closed loopback-only URL parsing, the GET-only-by-construction
transport (its request surface is a single ``get(path)`` -- no mutation verb
can be issued, deliberately), 1-3s clamped per-request timeouts, secret
handling (Authorization header only, env/0600-file resolution) and the
``redact()`` error-sanitization path. Active health probes
(the upstream per-node delay-test endpoint) are NEVER requested:
cached history only. The recorder never mutates, restarts, gates or delays
Mihomo or proxy operation, and it imports NOTHING from model.py's enrichment
layer: ENRICHMENT_KEYS stays a closed E4 invariant and diagnostics get their
own record format.

IDENTITY BOUNDARY (same contract as E4): every node/group name is a Mihomo
DISPLAY name echoed verbatim for local forensics; it is never mapped, matched
or parsed against server-side devices. No server identity field is ever
written.

OUTPUT CONTRACT (issue #41 design, decision areas 1-2): five closed record
kinds -- ``run`` (once per process, carries the non-secret run_id),
``sample`` (per cycle), ``sel`` / ``alive`` (diff events, change-triggered
only) and ``err`` (closed failure-class enum). Records are built
field-by-field from literals, so an upstream schema surprise can never add
a key. Connection evidence is aggregated to counts only -- ids, source and
destination addresses, hosts and rules never leave the parser. The single
free-text field in the format is ``err.detail``, fed exclusively by our own
exception strings already passed through ``redact()`` and capped: no response
body, no config, no credential ever reaches the file.

PERSISTENCE (decision area 5): --out-dir is REQUIRED and fail-closed
(real dir, never a symlink, 0700); records append to diag.jsonl
(O_NOFOLLOW + 0600, one write() per line, fsync once per cycle), rotated by
size through a numeric shift (diag.jsonl.1 .. .{N-1}) via os.replace. A
collection or storage failure is VISIBLE: sanitized err record plus a
non-zero once-mode result (3 api / 4 storage / 5 both) -- never a silent
exit 0 forever.

NO FABRICATED HISTORY: ts is stamped at write time, never backfilled; each
process generates one non-secret run_id so restarts and gaps are explicit.
Diff state survives restarts by tail-reading the last 64 KiB of the JSONL
(torn final line tolerated), so a --once run under a systemd timer emits
correct transition events with zero sidecar state.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import signal
import sys
import time
import uuid

from client import (ConfigurationError, DEFAULT_TIMEOUT, DEFAULT_URL,
                    HttpTransport, MAX_ERROR_BODY, SecretFileError,
                    TransportError, clamp_timeout, parse_controller_url,
                    redact, resolve_secret)

COLLECTOR_VER = 1
DIAG_FILENAME = "diag.jsonl"
OBS_CAP = 64               # observed-name cap per sample (a bound, not a target)
HIST_KEEP = 3              # cached history entries kept per node/group, newest-last
NODE_URL_KEEP = 4          # per-test-url "extra" entries per node (version-dependent)
URL_MAX_LEN = 128          # test-url display cap
DETAIL_MAX_LEN = 200       # err.detail cap -- the only free-text field
MIN_INTERVAL = 30.0        # sampling floor: divisor of the 60s health interval
MAX_INTERVAL = 60.0        # keeps >=2 samples inside the 65s worst-case window
DEFAULT_INTERVAL = 30.0
DEFAULT_MAX_MB = 4
DEFAULT_FILES = 4          # diag.jsonl + .1 .. .(N-1)  -> bounded by rotation
TAIL_BYTES = 64 * 1024     # state-recovery tail window

# Failure classes (closed enum). Cycle classes re-record every failing cycle
# with an incrementing consecutive count n; subject classes (entity
# transitions) record once per appearance so a persistent misconfiguration
# never storms a 30s log.
CYCLE_ERR_CLASSES = ("api_unreachable", "api_malformed", "storage_failed",
                     "rotation_failed")
SUBJECT_ERR_CLASSES = ("group_missing", "node_missing", "history_truncated",
                       "config")
ERR_CLASSES = CYCLE_ERR_CLASSES + SUBJECT_ERR_CLASSES

EXIT_OK = 0
EXIT_CONFIG = 2
EXIT_API = 3
EXIT_STORAGE = 4
EXIT_BOTH = 5

_WINDOWS = os.name == "nt"


class StorageError(Exception):
    """The evidence file could not be written/rotated (path only, no data)."""


# -- small strict parsers -----------------------------------------------------

def clamp_interval(value):
    """Sampling interval stays inside 30-60s (fail-safe to the 30s default)."""
    try:
        value = float(value)
    except (TypeError, ValueError):
        return DEFAULT_INTERVAL
    if value != value:  # NaN
        return DEFAULT_INTERVAL
    return min(max(value, MIN_INTERVAL), MAX_INTERVAL)


def utc_iso(stamp):
    """POSIX seconds -> RFC3339 UTC with explicit offset, second precision."""
    return datetime.datetime.fromtimestamp(
        float(stamp), datetime.timezone.utc).isoformat(timespec="seconds")


def parse_ts(value):
    """Mihomo timestamp field -> aware UTC datetime, or None when unusable.

    Accepts RFC3339 strings (Z or offset) and plain epoch seconds. Booleans
    are NOT numbers here (True is never a timestamp).
    """
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.datetime.fromtimestamp(float(value), datetime.timezone.utc)
        except (ValueError, OSError, OverflowError):
            return None
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed.astimezone(datetime.timezone.utc)


def as_str(value):
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def as_strict_bool(value):
    """alive tri-state: True/False pass, anything else is UNKNOWN (None)."""
    return value if isinstance(value, bool) else None


def parse_history(raw, keep=HIST_KEEP):
    """Mihomo history -> (entries newest-last, malformed count).

    THE E4-H1 FIX: delay==0 encodes a FAILED probe and is preserved RAW as
    ``d`` (E4 display normalized it away); ``t`` is the probe timestamp or
    null. Entries that are not {"time","delay"} shaped are dropped
    individually -- never an abort of the whole history.
    """
    if not isinstance(raw, list):
        return [], 0
    entries = []
    dropped = 0
    for item in reversed(raw):
        if not isinstance(item, dict) or "delay" not in item:
            dropped += 1
            continue
        delay = item.get("delay")
        if isinstance(delay, bool):
            dropped += 1
            continue
        try:
            delay = int(delay)
        except (TypeError, ValueError):
            dropped += 1
            continue
        when = parse_ts(item.get("time"))
        entries.append({"d": delay, "t": when.isoformat(timespec="seconds") if when else None})
        if len(entries) >= keep:
            break
    entries.reverse()
    return entries, dropped


def parse_proxies_summary(payload, group_names):
    """/proxies -> closed per-cycle summary for the CALLER-NAMED groups only.

    Reads ONLY: per named group type/now/all/history; per observed member node
    alive/history(kept 0)/extra per-test-url histories (newer builds only).
    The observed set is the union of named-group members plus their current
    selections; nodes outside it are never even looked up. Everything else in
    the payload is dropped in-reader and never serialized.
    """
    out = {"groups": [], "obs": [], "nodes": [], "missing_groups": [],
           "missing_nodes": [], "history_dropped": False, "usable": False}
    if not isinstance(payload, dict) or not isinstance(payload.get("proxies"), dict):
        return out
    proxies = payload["proxies"]
    observed = []
    member_of = {}          # node -> set of named groups that list it
    for name in group_names:
        entry = proxies.get(name)
        if not isinstance(entry, dict):
            out["groups"].append({"name": name, "error": "missing"})
            out["missing_groups"].append(name)
            continue
        rec = {"name": name}
        gtype = as_str(entry.get("type"))
        if gtype:
            rec["type"] = gtype.lower()
        now = as_str(entry.get("now"))
        if now:
            rec["now"] = now
        members = entry.get("all")
        names = [m for m in members if isinstance(m, str) and m.strip()] \
            if isinstance(members, list) else []
        if names:
            rec["all"] = sorted(names)
        hist, _dropped = parse_history(entry.get("history"))
        if hist:  # fallback/urltest groups carry their own probe history
            rec["hist"] = hist
        out["groups"].append(rec)
        for member in names:
            member_of.setdefault(member, set()).add(name)
        if now:
            member_of.setdefault(now, set()).add(name)
        for candidate in names + ([now] if now else []):
            if candidate not in observed:
                observed.append(candidate)
    observed.sort()
    if len(observed) > OBS_CAP:
        out["history_dropped"] = True
        observed = observed[:OBS_CAP]
    out["obs"] = observed
    for name in observed:
        entry = proxies.get(name)
        if not isinstance(entry, dict):
            out["nodes"].append({"name": name, "alive": None})
            out["missing_nodes"].append(name)
            continue
        rec = {"name": name, "alive": as_strict_bool(entry.get("alive"))}
        hist, dropped = parse_history(entry.get("history"))
        if dropped:
            out["history_dropped"] = True
        if hist:
            rec["hist"] = hist
        extra = entry.get("extra")
        if isinstance(extra, dict):
            urls = []
            for test_url in sorted(extra)[:NODE_URL_KEEP]:
                detail = extra.get(test_url)
                if not isinstance(detail, dict):
                    continue
                entry_hist, _ = parse_history(detail.get("history"), keep=1)
                urls.append({"u": str(test_url)[:URL_MAX_LEN],
                             "alive": as_strict_bool(detail.get("alive")),
                             "hist": entry_hist})
            if urls:
                rec["urls"] = urls
        out["nodes"].append(rec)
    out["member_of"] = {k: sorted(v) for k, v in member_of.items()}
    out["usable"] = True
    return out


def parse_connections_summary(payload, obs, member_of, current_now, sel_ts):
    """/connections -> CLOSED aggregate counts {n, by_node, multi, stale}.

    Per connection ONLY "chains" (node-name path) and "start" are read.
    Connection ids, source/destination addresses, ports, hosts and rules are
    structurally never touched, so they cannot leak. Semantics mirror E4:
    "connections": null is the verified official idle shape -> n=0; a missing
    key or wrong type is contract drift -> None (unknown, never shown as 0).

    stale = stale_after_switch (H6): the connection's chain traverses an
    OBSERVED member of a named group that is NOT that group's current
    selection, AND the connection predates that group's last recorded
    selection change. An unknown start time or an unproven switch never
    counts as stale -- stale>0 must be evidence, not a guess.
    """
    if not isinstance(payload, dict) or "connections" not in payload:
        return None, 0
    raw = payload["connections"]
    if raw is None:
        return {"n": 0, "by_node": {}, "multi": 0, "stale": 0}, 0
    if not isinstance(raw, list):
        return None, 0
    obs_set = set(obs)
    by_node = {}
    multi = 0
    stale = 0
    malformed = 0
    for item in raw:
        if not isinstance(item, dict):
            malformed += 1
            continue
        chains = item.get("chains")
        names = {c for c in chains if isinstance(c, str)} \
            if isinstance(chains, list) else set()
        hit = names & obs_set
        for node in hit:
            by_node[node] = by_node.get(node, 0) + 1
        if len(hit) >= 2:
            multi += 1
        start = parse_ts(item.get("start"))
        if start is not None:
            for node in hit:
                for group in member_of.get(node, ()):
                    changed = sel_ts.get(group)
                    if node != current_now.get(group) and changed is not None \
                            and start < changed:
                        stale += 1
                        break
                else:
                    continue
                break
    return {"n": len(raw), "by_node": {k: by_node[k] for k in sorted(by_node)},
            "multi": multi, "stale": stale}, malformed


# -- diff state and its JSONL tail recovery ------------------------------------

def new_state():
    return {
        "run_id": uuid.uuid4().hex,       # non-secret, per process, never backfilled
        "group_now": {},
        "node_alive": {},
        "sel_ts": {},                     # group -> last selection change (aware dt)
        "missing_groups": set(),
        "missing_nodes": set(),
        "history_dropped": False,
        "cycle_err": {},                  # cycle class -> consecutive count
    }


def _observe(state, ts_iso, rec):
    """Replay one stored record into the diff state (recovery + live cycle)."""
    kind = rec.get("k")
    if kind == "sample":
        for group in rec.get("groups") or []:
            name = group.get("name")
            if not isinstance(name, str):
                continue
            if group.get("error") == "missing":
                state["missing_groups"].add(name)
                continue
            state["missing_groups"].discard(name)
            now = group.get("now")
            if isinstance(now, str):
                state["group_now"][name] = now
        for node in rec.get("nodes") or []:
            name = node.get("name")
            if isinstance(name, str):
                state["node_alive"][name] = node.get("alive")
    elif kind == "sel":
        group = rec.get("g")
        if isinstance(group, str):
            state["group_now"][group] = rec.get("to")
            when = parse_ts(ts_iso)
            if when is not None:
                state["sel_ts"][group] = when
    elif kind == "alive":
        node = rec.get("node")
        if isinstance(node, str):
            state["node_alive"][node] = rec.get("to")
    elif kind == "err":
        # conservative on recovery: a truncation note seen in the tail keeps
        # the transition-suppressed until the NEXT clean parse resets it --
        # err counts themselves always restart with the process (new run_id)
        if rec.get("c") == "history_truncated":
            state["history_dropped"] = True


def load_state(path, byte_cap=TAIL_BYTES):
    """Recover diff state by tail-reading the JSONL (no sidecar state file).

    Reads the last byte_cap bytes, drops everything before the first newline
    (a torn first chunk is expected after a crash mid-write), and tolerates
    any unparseable line. A missing/empty file simply yields fresh state.
    """
    state = new_state()
    try:
        size = os.path.getsize(path)
    except OSError:
        return state
    try:
        with open(path, "rb") as handle:
            if size > byte_cap:
                handle.seek(size - byte_cap)
            blob = handle.read()
    except OSError:
        return state
    newline = blob.find(b"\n")
    if newline == -1:
        return state            # a single torn line: nothing provably complete
    for line in blob[newline + 1:].split(b"\n"):
        if not line.strip():
            continue
        try:
            rec = json.loads(line.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            continue
        if isinstance(rec, dict) and isinstance(rec.get("k"), str):
            _observe(state, rec.get("ts"), rec)
    return state


# -- the evidence writer --------------------------------------------------------

def ensure_out_dir(path):
    """--out-dir is fail-closed: real directory, never a symlink, 0700.

    The evidence file aggregates the user's whole proxy topology, so it gets
    the same treatment as a secret file: refuse to be redirected through a
    link, refuse world-readable defaults. Windows relies on NTFS ACLs (mode
    bits carry no access semantics there) -- documented, like E4's
    --secret-file caveat.
    """
    if os.path.islink(path):
        raise ConfigurationError("diag out dir must not be a symlink: %s" % path)
    if not os.path.isdir(path):
        try:
            os.makedirs(path, mode=0o700)
        except OSError as exc:
            raise ConfigurationError(
                "cannot create diag out dir %s (%s)" % (path, type(exc).__name__)) from None
    elif not _WINDOWS:
        try:
            os.chmod(path, 0o700)
        except OSError:
            pass               # best effort: the 0600 file gate still applies
    return path


class DiagWriter:
    """Append-only JSONL with size-shift rotation. One open per cycle.

    O_APPEND + one os.write() per record line keeps every record atomic at
    the byte level (worst case after a crash: one torn final line, which the
    tail reader tolerates). fsync happens ONCE per cycle batch, not per
    record: durability of a forensic cycle as a unit.
    """

    def __init__(self, out_dir, max_mb=DEFAULT_MAX_MB, files=DEFAULT_FILES):
        self.out_dir = out_dir
        self.path = os.path.join(out_dir, DIAG_FILENAME)
        try:
            max_mb = float(max_mb)
        except (TypeError, ValueError):
            max_mb = DEFAULT_MAX_MB
        self.max_bytes = max(int(max_mb * 1024 * 1024), 4096)
        self.files = max(int(files or DEFAULT_FILES), 2)

    def write(self, records):
        if not records:
            return
        blob = b"".join(encode_record(r) for r in records)
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(self.path, flags, 0o600)
        except OSError as exc:
            raise StorageError("cannot open %s (%s)"
                               % (self.path, type(exc).__name__)) from None
        try:
            if not _WINDOWS:
                # tighten even if the file pre-existed; Windows relies on NTFS
                # ACLs -- mode bits carry no access semantics there (README)
                try:
                    os.fchmod(fd, 0o600)
                except OSError:
                    pass
            for line in blob.splitlines(True):
                os.write(fd, line)
            os.fsync(fd)
        except OSError as exc:
            raise StorageError("cannot write %s (%s)"
                               % (self.path, type(exc).__name__)) from exc
        finally:
            os.close(fd)
        try:
            if os.path.getsize(self.path) > self.max_bytes:
                self.rotate()
        except OSError as exc:
            raise StorageError("cannot size-check/rotate %s (%s)"
                               % (self.path, type(exc).__name__)) from None

    def rotate(self):
        """Numeric shift: diag.jsonl -> .1 -> ... -> .{N-1} (oldest falls off)."""
        try:
            for index in range(self.files - 2, 0, -1):
                src = "%s.%d" % (self.path, index)
                dst = "%s.%d" % (self.path, index + 1)
                if os.path.exists(src):
                    os.replace(src, dst)
            if os.path.exists(self.path):
                os.replace(self.path, self.path + ".1")
        except OSError as exc:
            raise StorageError("rotation failed under %s (%s)"
                               % (self.out_dir, type(exc).__name__)) from None


def encode_record(record):
    """One canonical line: compact, sorted keys, UTF-8, newline-terminated.

    Records are built as closed literal dicts everywhere in this module;
    json.dumps never sees a raw API payload, so response bytes cannot ride
    along into the evidence file.
    """
    return (json.dumps(record, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":")) + "\n").encode("utf-8")


# -- the collector --------------------------------------------------------------

class DiagCollector:
    """One forensic cycle -> the closed records that cycle. Never raises.

    Reuses the audited E4 transport and redaction end to end. /version
    decides reachability (same as E4); with it the run record cannot be
    honestly dated, so a failed cycle records ONLY a sanitized err line --
    never a fabricated sample, never a run header for a run that observed
    nothing.
    """

    def __init__(self, url, groups, secret=None, timeout=DEFAULT_TIMEOUT,
                 transport=None, clock=time.time):
        self.url = url
        self.host, self.port, self.scheme = parse_controller_url(url)
        self.groups = list(groups or [])
        self.secret = secret or ""
        self.timeout = clamp_timeout(timeout)
        self.clock = clock
        self.transport = transport or HttpTransport(
            self.host, self.port, scheme=self.scheme, secret=self.secret,
            timeout=self.timeout)

    # -- helpers --

    def _secrets(self):
        secrets = [self.secret, os.environ.get("MIHOMO_API_SECRET", "")]
        return [s for s in secrets if s]

    def _sanitize(self, text):
        return redact(text, self._secrets())[:DETAIL_MAX_LEN]

    def _get_json(self, path):
        """-> (payload, err_class, detail, http_status). At most one is set."""
        try:
            status, body = self.transport.get(path)
        except TransportError as exc:
            return None, "api_unreachable", self._sanitize("%s: %s" % (type(exc).__name__, exc)), None
        except Exception as exc:  # noqa: BLE001 -- never propagate
            return None, "api_unreachable", self._sanitize(
                "%s: %s" % (type(exc).__name__, exc)), None
        if status != 200:
            # status line + the same capped, redacted body snippet discipline
            # as E4's ApiError -- never the full body, never an unredacted byte
            return None, "api_malformed", self._sanitize(
                "%s returned HTTP %s (%s)" % (path, status,
                    body[:MAX_ERROR_BODY].decode("utf-8", "replace").replace("\n", " "))), status
        try:
            return json.loads(body.decode("utf-8")), None, None, status
        except (ValueError, UnicodeDecodeError):
            return None, "api_malformed", self._sanitize("%s returned malformed JSON" % path), status

    # -- one cycle --

    def collect_cycle(self, state, interval_s):
        """Poll once, diff against state, return (records, flags)."""
        ts = utc_iso(self.clock())
        run_id = state["run_id"]
        records = []
        flags = {"api_failed": False, "sample_ok": False, "malformed_conns": 0}

        cycle_errs = []      # (class, detail) -- cycle classes, re-logged per cycle

        # 1) /version: reachability + the one-shot run header
        version_payload, err_class, detail, _status = self._get_json("/version")
        version = None
        if err_class is None:
            candidate = version_payload.get("version") if isinstance(version_payload, dict) else None
            if isinstance(candidate, str) and candidate.strip():
                version = candidate.strip()
            else:
                err_class, detail = "api_malformed", "/version without a usable version field"
        if version is None:
            flags["api_failed"] = True
            count = state["cycle_err"].setdefault(err_class, 0) + 1
            state["cycle_err"][err_class] = count
            records.append({"k": "err", "ts": ts, "run_id": run_id,
                            "c": err_class, "n": count,
                            "detail": detail or ""})
            return records, flags
        for err_class_name in CYCLE_ERR_CLASSES:
            state["cycle_err"].pop(err_class_name, None)   # clean cycle resets n
        if not state.get("_run_written"):
            records.append({"k": "run", "ts": ts, "run_id": run_id,
                            "url_host": self.host, "url_port": self.port,
                            "groups": list(self.groups),
                            "interval_s": interval_s,
                            "collector_ver": COLLECTOR_VER,
                            "mihomo_version": version})
            state["_run_written"] = True

        # 2) /proxies for the caller-named groups (never guessed, never inferred)
        proxies_summary = None
        if self.groups:
            payload, err_class, detail, _status = self._get_json("/proxies")
            if err_class is None:
                proxies_summary = parse_proxies_summary(payload, self.groups)
                if not proxies_summary["usable"]:
                    cycle_errs.append(("api_malformed", "/proxies shape not understood"))
                    proxies_summary = None
            else:
                cycle_errs.append((err_class, detail))

        # 3) diff the proxy observation BEFORE reading connections: a switch
        #    observed THIS cycle must be able to classify this cycle's
        #    old-path connections as stale. Records stay ordered sample-then-
        #    events; only the state movement is pulled forward.
        diff_records = []
        _apply_diffs(state, diff_records, ts, proxies_summary)

        # 4) /connections (chain topology evidence only). Per-endpoint
        #    isolation: a broken /proxies must not hide the connection view --
        #    with no observed set, chains simply attribute to nothing.
        conns = None
        payload, err_class, detail, _status = self._get_json("/connections")
        if err_class is None:
            member_of = proxies_summary.get("member_of", {}) if proxies_summary else {}
            obs = proxies_summary["obs"] if proxies_summary else []
            current_now = {g["name"]: g.get("now") for g in proxies_summary["groups"]} \
                if proxies_summary else {}
            conns, malformed = parse_connections_summary(payload, obs, member_of,
                                                         current_now, state["sel_ts"])
            if malformed:
                flags["malformed_conns"] = malformed
                cycle_errs.append(("api_malformed",
                                   "%d malformed connection entries" % malformed))
            if conns is None:
                cycle_errs.append(("api_malformed", "/connections shape not understood"))
        else:
            cycle_errs.append((err_class, detail))

        # 5) the sample record (closed keys; sections null when that endpoint
        #    failed -- a missing optional section, never an invented zero)
        if proxies_summary is not None or conns is not None:
            records.append({
                "k": "sample", "ts": ts, "run_id": run_id,
                "obs": proxies_summary["obs"] if proxies_summary else None,
                "groups": proxies_summary["groups"] if proxies_summary else None,
                "nodes": proxies_summary["nodes"] if proxies_summary else None,
                "conns": conns,
            })
            flags["sample_ok"] = True
        records.extend(diff_records)

        # 6) subject-class records: once per appearance-transition only
        if proxies_summary is not None:
            for name in proxies_summary["missing_groups"]:
                if name not in state["missing_groups"]:
                    records.append({"k": "err", "ts": ts, "run_id": run_id,
                                    "c": "group_missing", "n": 1,
                                    "detail": self._sanitize("group %r absent from /proxies" % name)})
            now_missing_groups = set(proxies_summary["missing_groups"])
            state["missing_groups"] = now_missing_groups

            for name in proxies_summary["missing_nodes"]:
                if name not in state["missing_nodes"]:
                    records.append({"k": "err", "ts": ts, "run_id": run_id,
                                    "c": "node_missing", "n": 1,
                                    "detail": self._sanitize("node %r listed but absent" % name)})
            state["missing_nodes"] = set(proxies_summary["missing_nodes"])

            dropped_now = bool(proxies_summary["history_dropped"])
            if dropped_now and not state["history_dropped"]:
                records.append({"k": "err", "ts": ts, "run_id": run_id,
                                "c": "history_truncated", "n": 1,
                                "detail": "observed set capped or malformed history dropped"})
            state["history_dropped"] = dropped_now

        # 6) fold cycle-class errors (deduped via the consecutive-count ledger)
        for err_class_name, err_detail in cycle_errs:
            count = state["cycle_err"].setdefault(err_class_name, 0) + 1
            state["cycle_err"][err_class_name] = count
            records.append({"k": "err", "ts": ts, "run_id": run_id,
                            "c": err_class_name, "n": count,
                            "detail": err_detail or ""})
        return records, flags


def _apply_diffs(state, records, ts, proxies_summary):
    """sel / alive events: change-triggered ONLY (10 identical cycles emit 0)."""
    run_id = state["run_id"]
    if proxies_summary is None:
        return
    for group in proxies_summary["groups"]:
        name = group.get("name")
        now = group.get("now")
        if not isinstance(name, str) or "now" not in group or "error" in group:
            continue
        prev = state["group_now"].get(name, "__unset__")
        if prev != "__unset__" and prev != now:
            records.append({"k": "sel", "ts": ts, "run_id": run_id,
                            "g": name, "from": prev, "to": now})
            when = parse_ts(ts)
            if when is not None:
                state["sel_ts"][name] = when
        state["group_now"][name] = now
    for node in proxies_summary["nodes"]:
        name = node.get("name")
        if not isinstance(name, str):
            continue
        prev = state["node_alive"].get(name, "__unset__")
        alive = node.get("alive")
        if prev != "__unset__" and prev != alive:
            records.append({"k": "alive", "ts": ts, "run_id": run_id,
                            "node": name, "from": prev, "to": alive})
        state["node_alive"][name] = alive


# -- CLI --------------------------------------------------------------------------

def build_arg_parser():
    parser = argparse.ArgumentParser(
        description="Monitor v2 E4-Diag read-only Mihomo failover forensics "
                    "(local JSONL evidence, display-only names, GET-only)")
    parser.add_argument("--url", default=DEFAULT_URL,
                        help="external-controller URL; MUST be loopback "
                             "(default: %(default)s)")
    parser.add_argument("--group", action="append", default=[],
                        help="proxy group to observe, repeatable; caller-"
                             "named, topology-free (no group names are ever "
                             "hard-coded)")
    parser.add_argument("--out-dir", required=True,
                        help="evidence directory (real dir, no symlink, 0700); "
                             "REQUIRED fail-closed")
    parser.add_argument("--interval", type=float, default=DEFAULT_INTERVAL,
                        help="resident sampling seconds, clamped 30-60 "
                             "(default: %(default)s)")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help="per-request timeout, clamped 1-3 (default: %(default)s)")
    parser.add_argument("--max-mb", type=float, default=DEFAULT_MAX_MB,
                        help="rotate above this size (default: %(default)s)")
    parser.add_argument("--files", type=int, default=DEFAULT_FILES,
                        help="diag.jsonl plus N-1 shifted files (default: %(default)s)")
    parser.add_argument("--secret-file", default=None,
                        help="controller secret file, POSIX mode 0600/0400 "
                             "enforced; MIHOMO_API_SECRET takes precedence")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--once", action="store_true",
                      help="single cycle and exit (systemd-timer shape; default)")
    mode.add_argument("--resident", action="store_true",
                      help="sampling loop until SIGTERM")
    mode.add_argument("--prune-now", action="store_true",
                      help="rotate the evidence chain without sampling")
    return parser


def main(argv=None, transport=None, clock=time.time):
    args = build_arg_parser().parse_args(argv)
    interval = clamp_interval(args.interval)
    try:
        secret = resolve_secret(args.secret_file)
        collector = DiagCollector(args.url, args.group, secret=secret,
                                  timeout=args.timeout, transport=transport,
                                  clock=clock)
        writer = DiagWriter(ensure_out_dir(args.out_dir), max_mb=args.max_mb,
                            files=args.files)
    except (ConfigurationError, SecretFileError) as exc:
        print("fatal configuration error: %s" % exc, file=sys.stderr)
        return EXIT_CONFIG

    if args.prune_now:
        try:
            writer.rotate()
        except StorageError as exc:
            print("storage error: %s" % exc, file=sys.stderr)
            return EXIT_STORAGE
        print(json.dumps({"rotated": True, "path": writer.path}))
        return EXIT_OK

    state = load_state(writer.path)
    storage_failed = False

    def one_cycle():
        nonlocal storage_failed
        records, flags = collector.collect_cycle(state, interval)
        if records:
            try:
                writer.write(records)
            except StorageError as exc:
                # the failure itself must be visible, never a silent exit 0
                print("storage error: %s" % exc, file=sys.stderr)
                storage_failed = True
        return flags

    if args.resident:
        stopping = []

        def _stop(signum, frame):
            stopping.append(True)
        try:
            signal.signal(signal.SIGTERM, _stop)
        except (ValueError, OSError):
            pass               # not the main thread (embedded/test use)
        while not stopping:
            one_cycle()
            if storage_failed:
                return EXIT_STORAGE   # supervisor-visible, never loop blind
            # sleep bounded so SIGTERM stays prompt
            deadline = time.monotonic() + interval
            while not stopping and time.monotonic() < deadline:
                time.sleep(min(0.5, max(deadline - time.monotonic(), 0)))
        return EXIT_OK

    flags = one_cycle()
    summary = {"records": 0, "api_failed": flags["api_failed"],
               "sample_ok": flags["sample_ok"], "storage_failed": storage_failed,
               "run_id": state["run_id"]}
    print(json.dumps(summary, sort_keys=True))
    if storage_failed and flags["api_failed"]:
        return EXIT_BOTH
    if storage_failed:
        return EXIT_STORAGE
    if flags["api_failed"]:
        return EXIT_API
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
