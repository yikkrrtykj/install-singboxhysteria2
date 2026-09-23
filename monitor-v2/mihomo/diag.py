#!/usr/bin/env python3
"""Monitor v2 Phase E4-Diag -- client-side Mihomo failover FORENSICS (issue #41).

Read-only, local-only diagnostic recorder implementing the reviewed design
of issue #41. Where E4 (client.py) answers "what does the controller look
like RIGHT NOW" as one display-only enrichment object, E4-Diag answers "WHAT
ACTUALLY HAPPENED" around the failover that did not happen AFTER the fact,
from a local JSONL evidence trail:

    H1 node marked dead        -> member alive=false + history delay 0 (RAW)
    H2 alive-but-failing       -> alive=true + cached history cadence
    H3 manual outer pin        -> group type + now (selectors never inferred)
    H4 probe healthy, relay broken -> per-test-url extra histories (test_id)
    H5 not yet re-tested       -> >=2 samples inside one health interval
    H6 connections not migrating -> per-node chain aggregates (count/start)

Everything the E4 security posture guarantees is reused VERBATIM from
client.py (this module imports the audited pieces, it does not fork them):
fail-closed loopback-only URL parsing, the GET-only-by-construction
transport (its request surface is a single ``get(path)`` -- no mutation verb
can be issued, deliberately), 1-3s clamped per-request timeouts, and secret
handling (Authorization header only, env/0600-file resolution). Active
health probes (the upstream per-node delay-test endpoint) are NEVER
requested: cached history only. The recorder never mutates, restarts, gates
or delays Mihomo or proxy operation, and it imports NOTHING from model.py's
enrichment layer: ENRICHMENT_KEYS stays a closed E4 invariant and
diagnostics get their own record format.

IDENTITY BOUNDARY (same contract as E4): every node/group name is a Mihomo
DISPLAY name echoed verbatim for local forensics; it is never mapped, matched
or parsed against server-side devices. No server identity field is ever
written.

RECORD SCHEMA (reviewed design 5777726169 + review 5778693980): schema
version ``v=1``; EXACTLY FOUR record types -- ``sample`` (one per cycle,
ALWAYS emitted, even when /version is unreachable: api_reachable=false,
mihomo_version=null, endpoint statuses honestly "unavailable"),
``selection_changed`` / ``alive_flipped`` (diff events) and ``collector``
(closed code enum with a bounded ``scope`` field and a consecutive-cycle
``count``). There is deliberately NO run/header record type: a process
restart is visible evidence via the fresh ``run`` (uuid4().hex, one per
process, carried by every record) plus the always-emitted first sample.
Records are built field-by-field from literals, so an upstream schema
surprise can never add a key. NOTHING arbitrary is persisted: no exception
text, no HTTP response body bytes, no status codes, no raw URLs, no
credentials, even redacted or truncated -- the only error vocabulary is the
closed (code, scope, count) triple. Custom health-check test URLs are never
stored: each is replaced by ``test_id = HMAC-SHA256(local 256-bit key, raw
url)[:16 hex]``; the key lives in the evidence dir (0600, fail-closed) so
ids stay stable across samples AND restarts while the URL itself never
crosses the persistence boundary -- and that stability is PROVEN, not
assumed: no key is ever returned until its contents and its directory
entry are both fsync-durable on every load path (review R4). Connection
evidence is per-node
aggregates (active chain count, oldest/newest start, invalid-start count)
-- ids, addresses, hosts, rules and counters never leave the parser, and
no cross-group "stale" inference is derived (it would overclaim under
nested topologies).

CAUSAL BOUNDARY (review B2): selection_changed/alive_flipped events are
emitted ONLY between two valid observations inside the SAME process run
with no invalid/unavailable gap between them. Diff state is never seeded
from a previous run: a restart gap is evidence of a gap, not a proven
transition. A /version failure skips the other reads for that cycle, so it
breaks the diff chain exactly like an unavailable /proxies sample. A
consequence: one-shot ``--once`` invocations (systemd-timer shape) can
never prove transition events across invocations -- the resident
``--resident`` loop is the mode that produces edges.

BOUNDS (review B5): max 8 watched groups, 32 stored members per group, 64
observed nodes per sample -- and caller-demanded ``--node`` names (max 32)
are PROTECTED ahead of group expansion inside that 64 (review R2: a
requested node is never sorted out of existence; when the cap bites, a
group-derived tail is the visible victim), names 1..128 bytes of STRICT
UTF-8 without C0/C1 controls (a string that cannot be UTF-8 encoded at all
-- e.g. a lone surrogate -- is invalid, never measured lossily, review R3),
history tails of 8, per-node test-id entries capped, rotation arguments
bounded (2..32 files, <=8 MiB/file, <=32 MiB total). The hard record
ceiling is measured on the FINAL ENCODED BYTES INCLUDING the trailing
newline: an oversized record is trimmed STRUCTURALLY (never byte-sliced)
and marked by a ``truncated`` flag plus an ``invalid_fields`` counter.
History delays are BOUNDED INTEGERS only: a float -- even 1.0 -- is not a
probe result and is dropped and counted, never coerced.

PERSISTENCE (review B4): --out-dir is REQUIRED and fail-closed (no symlink
component anywhere on the path -- and ONLY ENOENT may mean "absent": an
EACCES/EIO lstat proves nothing and refuses startup, review B4 round 4;
real directory, 0700 -- a permission-
tightening failure is fatal on POSIX). diag.jsonl is opened O_NOFOLLOW,
fstat-verified regular, fchmod 0600 (failure fatal), appended with one
write-until-complete loop per batch, fsynced per cycle; on startup the
current file is VALIDATED before it is MEASURED (review B4 round 4): the
repair opens O_RDWR|O_NOFOLLOW first (a FIFO can never block it), a clean
FileNotFoundError is the ONLY benign outcome, and the fd is fstat-proved a
regular file before any zero-size short circuit -- a pre-existing zero-byte
symlink or special file is refused, every other fault is a storage_error
stop. Only then is at most one incomplete trailing fragment truncated back
to the last newline (fsynced, per frozen design section 8). Rotation is a
numeric size shift
(diag.jsonl.1 .. .{N-1}) with file fsync before the rename and directory
fsync after it; the same prune pass (every cycle and --prune-now) enforces
7-day age retention oldest-first plus the 32 MiB total and chain-count
ceilings -- and retention is fail-closed (review R1): only a
FileNotFoundError race is skipped, any other stat/getsize fault stops
storage, and chain members are verified with a NON-FOLLOWING lstat that
demands a regular file. One diag.lock (advisory exclusive,
non-blocking) makes a second collector on the same directory refuse to
start. A collection or storage failure is VISIBLE: collector records plus
a non-zero once-mode result (3 api / 4 storage / 5 both) -- never a silent
exit 0 forever.

NO FABRICATED HISTORY: ts is stamped at write time, never backfilled; each
process generates one non-secret run id so restarts and gaps are explicit.
Error accounting (review B6): the whole cycle's error-code set is computed
FIRST; each present code increments its consecutive-cycle counter exactly
once (one collector record per code per cycle -- the bounded scope field,
never detail text, is what distinguishes endpoints) and a code resets only
after a FULL cycle in which it was absent; a /version failure shortens the
cycle, so it increments and never resets.
"""

from __future__ import annotations

import argparse
import copy
import datetime
import hashlib
import hmac
import json
import os
import signal
import stat as stat_module
import sys
import time
import uuid

from client import (ConfigurationError, DEFAULT_TIMEOUT, DEFAULT_URL,
                    HttpTransport, SecretFileError, clamp_timeout,
                    parse_controller_url, resolve_secret)

try:
    import fcntl
except ImportError:
    fcntl = None
try:
    import msvcrt
except ImportError:
    msvcrt = None

SCHEMA_V = 1
# The closed record vocabulary (design section 6): exactly four types, no
# header/run record. The regression suite proves the persisted "t" set is
# strictly within this tuple.
RECORD_TYPES = ("sample", "selection_changed", "alive_flipped", "collector")
DIAG_FILENAME = "diag.jsonl"
KEY_FILENAME = "diag.key"
LOCK_FILENAME = "diag.lock"
HMAC_KEY_BYTES = 32
TEST_ID_HEX = 16

# Cardinality bounds (reviewed design section 2 -- fail-closed everywhere).
MAX_GROUPS = 8             # caller-named groups per collector
MAX_NODES = 32             # caller-named explicit nodes per collector (B5)
OBS_CAP = 64               # distinct observed nodes per sample
MAX_MEMBERS = 32           # stored members per group (rest counted+flagged)
NAME_MAX_BYTES = 128       # group/node names and version strings, UTF-8
HIST_KEEP = 8              # cached history entries kept per subject, newest-last
NODE_URL_KEEP = 8          # per-test-url extra entries per node (version-dependent)
DELAY_MAX = 1000000        # plausible ms bound; larger values are not evidence
RECORD_MAX_BYTES = 64 * 1024  # hard ceiling for one encoded line, newline INCLUDED

MIN_INTERVAL = 30.0        # sampling floor: divisor of the 60s health interval
MAX_INTERVAL = 60.0        # keeps >=2 samples inside the 65s worst-case window
DEFAULT_INTERVAL = 30.0
DEFAULT_MAX_MB = 4
DEFAULT_FILES = 4          # diag.jsonl + .1 .. .(N-1)  -> bounded by rotation
MIN_FILES = 2
MAX_FILES = 32             # reviewed retention ceiling
MAX_FILE_MB = 8            # per-file rotation cap
TOTAL_MB_BUDGET = 32       # whole evidence chain hard budget
RETENTION_SECONDS = 7 * 24 * 3600   # frozen design section 8: 7-day age prune

# Collector failure codes (closed enum, design section 6D) with their fixed
# scopes. A cycle's whole code set is computed before any record is folded
# (review B6); CODE_SCOPE is the fail-closed definition of scope -- a code
# outside this map can never be recorded.
COLLECTOR_CODES = ("mihomo_unreachable", "proxies_invalid", "connections_invalid",
                   "group_missing", "node_missing", "storage_error")
COLLECTOR_SCOPES = ("version", "proxies", "connections", "storage")
CODE_SCOPE = {"mihomo_unreachable": "version", "proxies_invalid": "proxies",
              "connections_invalid": "connections", "group_missing": "proxies",
              "node_missing": "proxies", "storage_error": "storage"}
ENDPOINT_STATUSES = ("ok", "unavailable", "invalid")

EXIT_OK = 0
EXIT_CONFIG = 2
EXIT_API = 3
EXIT_STORAGE = 4
EXIT_BOTH = 5

_WINDOWS = os.name == "nt"
# Windows CRT defaults os.open to TEXT mode, which silently rewrites 0x0A
# bytes to CRLF -- a raw key or JSONL line must never pass through it.
# Zero on POSIX.
_O_BINARY = getattr(os, "O_BINARY", 0)


class StorageError(Exception):
    """The evidence chain could not be written/rotated (path only, no data)."""


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


def iso_z(value):
    """Aware datetime -> "YYYY-MM-DDTHH:MM:SSZ" (design examples are Z-form)."""
    if value is None:
        return None
    return (value.astimezone(datetime.timezone.utc)
            .isoformat(timespec="seconds").replace("+00:00", "Z"))


def utc_iso(stamp):
    """POSIX seconds -> RFC3339 UTC, second precision, Z form."""
    return iso_z(datetime.datetime.fromtimestamp(float(stamp),
                                                 datetime.timezone.utc))


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


def safe_name(value):
    """Validate one display name against the reviewed bound -- EXACTLY.

    Non-empty, <=128 bytes under STRICT UTF-8 encoding, no C0/C1 control
    characters. The validated string is returned UNCHANGED: a name is a
    display identity, so legal characters (including U+0020 space) are never
    stripped or otherwise normalized into a different name (review B5
    residual). A string that cannot be encoded as UTF-8 at all (e.g. a lone
    surrogate, which json.loads can hand back from escaped upstream input)
    is invalid, never measured with a lossy 'replace' stand-in (review R3).
    An invalid name returns None -- dropped AND counted upstream, never
    truncated into something that looks real, never serialized raw.
    """
    if not isinstance(value, str) or not value:
        return None
    try:
        encoded = value.encode("utf-8")      # STRICT: no replace-mode laundering
    except UnicodeEncodeError:
        return None
    if len(encoded) > NAME_MAX_BYTES:
        return None
    for ch in value:
        code = ord(ch)
        if code < 0x20 or 0x7f <= code <= 0x9f:
            return None
    return value


def as_strict_bool(value):
    """alive tri-state: True/False pass, anything else is UNKNOWN (None)."""
    return value if isinstance(value, bool) else None


def test_identify(key, raw_url):
    """Stable local correlation id for a health-check test URL (review B1).

    The raw URL (which may embed credentials, private paths or query tokens)
    exists only transiently during parsing; what is persisted is the 16-hex
    HMAC-SHA256 prefix under a collector-owned random key. Same key + same
    URL across samples AND restarts yields the same id; the id is not
    reversible without the key file.
    """
    digest = hmac.new(key, raw_url.encode("utf-8", "replace"),
                      hashlib.sha256).hexdigest()
    return digest[:TEST_ID_HEX]


def parse_history(raw, keep=HIST_KEEP):
    """Mihomo history -> (entries newest-last, dropped count, soft count).

    THE E4-H1 FIX: delay==0 encodes a FAILED probe and is preserved RAW as
    ``delay_ms`` (E4 display normalized it away); ``ts`` is the probe
    timestamp or null. Delay must be a TRUE non-negative integer within a
    plausible bound -- a float (even 1.0), bool or string is not a probe
    result and is dropped and counted, never coerced. A delay whose ``time``
    does not parse is still evidence: the entry is kept with ts null and
    counted as soft-invalid. Entries that are not {"time","delay"} shaped
    are dropped individually and counted -- never an abort of the whole
    history.
    """
    if not isinstance(raw, list):
        return [], 0, 0
    entries = []
    dropped = 0
    soft = 0
    for item in reversed(raw):
        if not isinstance(item, dict) or "delay" not in item:
            dropped += 1
            continue
        delay = item["delay"]
        if isinstance(delay, bool) or not isinstance(delay, int):
            dropped += 1          # a float or string is not a probe result
            continue
        if delay < 0 or delay > DELAY_MAX:
            dropped += 1
            continue
        when = parse_ts(item.get("time"))
        if when is None:
            soft += 1             # delay kept as evidence, ts honestly null
        entries.append({"ts": iso_z(when), "delay_ms": delay})
        if len(entries) >= keep:
            break
    entries.reverse()
    return entries, dropped, soft


def parse_proxies_summary(payload, group_names, hmac_key=None,
                          explicit_nodes=None):
    """/proxies -> closed per-cycle summary for the CALLER-NAMED groups only.

    Reads ONLY the design section 4 whitelist: per named group
    name/type/now/members/alive (alive only when boolean); per observed
    node name/type/alive/history (delay 0 preserved RAW)/extra per-test-url
    histories (newer builds only) projected to HMAC test_id. The observed
    set is the union of caller-named explicit nodes (review B5: observable
    even outside any group's expansion), named-group members and their
    current selections; nodes outside it are never even looked up. Raw
    test-URL keys are NEVER persisted (review B1); names, members and
    histories are bounded with explicit counters (review B5). Everything
    else in the payload is dropped in-reader and never serialized. This dict
    is INTERNAL to the collector -- the sample record copies its closed
    fields, it never serializes the summary itself.
    """
    out = {"groups": [], "watched": [], "nodes": [], "missing_groups": [],
           "missing_nodes": [], "broken_groups": [], "invalid_fields": 0,
           "truncated": False, "usable": False}
    invalid = 0
    if not isinstance(payload, dict) or not isinstance(payload.get("proxies"), dict):
        return out
    proxies = payload["proxies"]
    explicit = []
    for node_name in explicit_nodes or []:
        checked = safe_name(node_name)
        if checked is None:
            invalid += 1
        elif checked not in explicit:
            explicit.append(checked)
    group_watched = []
    for name in group_names:
        entry = proxies.get(name)
        if not isinstance(entry, dict):
            out["groups"].append({"name": name, "type": None, "now": None,
                                  "members": []})
            out["missing_groups"].append(name)
            continue
        rec = {"name": name, "type": None, "now": None, "members": []}
        gtype = safe_name(entry.get("type"))
        if gtype:
            rec["type"] = gtype.lower()
        elif entry.get("type") is not None:
            invalid += 1
        now = safe_name(entry.get("now"))
        if now:
            rec["now"] = now
        elif entry.get("now") is not None:
            invalid += 1          # present but unusable: chain-breaker below
            out["broken_groups"].append(name)
        galive = entry.get("alive")
        if isinstance(galive, bool):
            rec["alive"] = galive
        elif galive is not None:
            invalid += 1
        members = entry.get("all")
        names = []
        if isinstance(members, list):
            for member in members:
                checked = safe_name(member)
                if checked is None:
                    invalid += 1
                elif checked not in names:
                    names.append(checked)
        elif members is not None:
            invalid += 1
        if len(names) > MAX_MEMBERS:
            out["truncated"] = True
            names = sorted(names)[:MAX_MEMBERS]
        else:
            names = sorted(names)
        rec["members"] = names
        out["groups"].append(rec)
        for candidate in names + ([now] if now else []):
            if candidate not in group_watched:
                group_watched.append(candidate)
    # Review R2: caller-demanded nodes are PROTECTED first -- an explicit
    # --node must never be sorted out of existence by group expansion.
    # The remaining OBS_CAP slots go to the lexically-first group-derived
    # names, so truncation always eats the group tail, never a demand.
    protected = sorted(explicit)
    group_only = sorted(set(group_watched) - set(protected))
    room = max(OBS_CAP - len(protected), 0)
    if len(group_only) > room:
        out["truncated"] = True
        group_only = group_only[:room]
    watched = sorted(protected + group_only)
    out["watched"] = watched
    for name in watched:
        entry = proxies.get(name)
        if not isinstance(entry, dict):
            out["nodes"].append({"name": name, "type": None, "alive": None,
                                 "history": [], "extra": []})
            out["missing_nodes"].append(name)
            continue
        rec = {"name": name, "type": None, "alive": None, "history": [],
               "extra": []}
        ntype = safe_name(entry.get("type"))
        if ntype:
            rec["type"] = ntype.lower()
        elif entry.get("type") is not None:
            invalid += 1
        nalive = entry.get("alive")
        rec["alive"] = as_strict_bool(nalive)
        if nalive is not None and not isinstance(nalive, bool):
            invalid += 1
        hist, dropped, soft = parse_history(entry.get("history"))
        invalid += dropped + soft
        rec["history"] = hist
        extra = entry.get("extra")
        if isinstance(extra, dict) and hmac_key is not None:
            urls = []
            keys = sorted(k for k in extra if isinstance(k, str))
            if len(keys) > NODE_URL_KEEP:
                out["truncated"] = True
            for test_url in keys[:NODE_URL_KEEP]:
                detail = extra.get(test_url)
                if not isinstance(detail, dict):
                    invalid += 1
                    continue
                entry_hist, e_dropped, e_soft = parse_history(
                    detail.get("history"))          # tail 8 PER test URL (B5)
                invalid += e_dropped + e_soft
                # the raw URL exists only on this line -- HMAC id is persisted
                urls.append({"test_id": test_identify(hmac_key, test_url),
                             "alive": as_strict_bool(detail.get("alive")),
                             "history": entry_hist})
            rec["extra"] = urls
        elif extra is not None and not isinstance(extra, dict):
            invalid += 1
        out["nodes"].append(rec)
    out["invalid_fields"] = invalid
    out["usable"] = True
    return out


def parse_connections_summary(payload, watched):
    """/connections -> per watched-node AGGREGATES (review B3, no inference).

    Per connection ONLY "chains" (node-name path) and "start" are read.
    Connection ids, source/destination addresses, ports, hosts, rules and
    counters are structurally never touched, so they cannot leak. Returns
    (aggregates, malformed): aggregates is a list with one entry per
    watched node

        {"node", "active_chain_count", "oldest_start", "newest_start",
         "invalid_start_count"}

    or None when the connections field itself is missing/wrong-typed --
    unknown, NEVER shown as zero. "connections": null and [] are the
    verified official empty shapes -> confirmed zero. Only VALID connection
    objects (dict with a chains list) count toward active_chain_count;
    malformed elements are counted separately and never inflate evidence.
    A valid connection without a usable start raises the node's
    invalid_start_count. NO derived staleness verdict is computed: under a
    nested topology (outer Selector -> inner automatic group) any
    cross-group attribution would overclaim, so the analyst compares these
    raw-safe facts against proven same-run selection_changed records.
    """
    if not isinstance(payload, dict) or "connections" not in payload:
        return None, 0
    raw = payload["connections"]
    stats = {name: {"node": name, "active_chain_count": 0, "oldest_start": None,
                    "newest_start": None, "invalid_start_count": 0}
             for name in watched}
    if raw is None:
        return [stats[name] for name in watched], 0
    if not isinstance(raw, list):
        return None, 0
    watched_set = set(watched)
    malformed = 0
    for item in raw:
        if not isinstance(item, dict) or not isinstance(item.get("chains"), list):
            malformed += 1
            continue
        hits = watched_set.intersection(
            c for c in item["chains"] if isinstance(c, str))
        if not hits:
            continue
        start = parse_ts(item.get("start"))
        start_iso = iso_z(start)
        for node in hits:
            st = stats[node]
            st["active_chain_count"] += 1
            if start is None:
                st["invalid_start_count"] += 1
                continue
            oldest = parse_ts(st["oldest_start"])
            newest = parse_ts(st["newest_start"])
            if oldest is None or start < oldest:
                st["oldest_start"] = start_iso
            if newest is None or start > newest:
                st["newest_start"] = start_iso
    return [stats[name] for name in watched], malformed


# -- diff state (process-local; review B2: NEVER seeded across runs) -----------

def new_state():
    """Run-local diff/ledger state. A restart builds a fresh one on purpose."""
    return {
        "run": uuid.uuid4().hex,       # non-secret, per process, never backfilled
        "seq": 0,                      # strictly increasing record counter
        "group_now": {},
        "node_alive": {},
        "proxies_gap": False,          # an invalid sample breaks diff chains
        "err_counts": {},              # collector code -> consecutive cycles
    }


def _apply_diffs(state, events, ts, proxies_summary):
    """selection_changed / alive_flipped edges, WITHIN one run only (B2).

    The first valid sample seeds silently (no edge from "nothing"). After an
    unavailable/invalid /proxies cycle the next valid sample re-seeds
    silently too -- across the gap the change may have happened at any
    time, so an edge there would be a fabricated causal claim. A missing
    group/node, a group whose ``now`` is present but unusable, or a node
    whose alive is unknown breaks that subject's chain. A group whose
    ``now`` is simply absent is a KNOWN null and participates in diffs.
    Events are appended WITHOUT v/run/seq -- the caller stamps those.
    """
    if proxies_summary is None:
        state["proxies_gap"] = True
        return
    gap = state["proxies_gap"]
    state["proxies_gap"] = False
    missing_groups = set(proxies_summary["missing_groups"])
    broken_groups = set(proxies_summary["broken_groups"])
    for group in proxies_summary["groups"]:
        name = group.get("name")
        if not isinstance(name, str):
            continue
        if name in missing_groups or name in broken_groups:
            state["group_now"].pop(name, None)   # absence breaks the chain
            continue
        now = group.get("now")      # None here is a KNOWN value, not unknown
        prev = state["group_now"].get(name, "__unset__")
        if not gap and prev != "__unset__" and prev != now:
            events.append({"t": "selection_changed", "ts": ts,
                           "group": name, "from": prev, "to": now})
        state["group_now"][name] = now
    missing_nodes = set(proxies_summary["missing_nodes"])
    for node in proxies_summary["nodes"]:
        name = node.get("name")
        if not isinstance(name, str):
            continue
        if name in missing_nodes:
            state["node_alive"].pop(name, None)
            continue
        alive = node.get("alive")
        if alive is None:
            state["node_alive"].pop(name, None)  # unknown breaks the chain
            continue
        prev = state["node_alive"].get(name, "__unset__")
        if not gap and prev != "__unset__" and prev != alive:
            events.append({"t": "alive_flipped", "ts": ts,
                           "node": name, "from": prev, "to": alive})
        state["node_alive"][name] = alive


# -- fail-closed storage primitives (review B4) --------------------------------

def _fsync_dir(path):
    """fsync a directory so a rename/creation is durable (POSIX only).

    Windows has no directory fsync; NTFS rename durability is handled by the
    OS -- documented limitation, same ACL territory as E4's secret file.
    """
    if _WINDOWS:
        return
    try:
        fd = os.open(path, os.O_RDONLY | _O_BINARY)
    except OSError as exc:
        raise StorageError("cannot open evidence dir for fsync: %s (%s)"
                           % (path, type(exc).__name__)) from None
    try:
        os.fsync(fd)
    except OSError as exc:
        raise StorageError("cannot fsync evidence dir: %s (%s)"
                           % (path, type(exc).__name__)) from None
    finally:
        os.close(fd)


def _write_all(fd, data, write_fn=os.write):
    """write-until-complete: a short os.write return never loses bytes."""
    view = memoryview(data)
    while view:
        written = write_fn(fd, view)
        if not written:      # zero/negative progress would spin forever
            raise OSError("write made no progress")
        view = view[written:]


def check_no_symlink_component(path, lstat=os.lstat):
    """Reject a path with ANY symlink component (review B4 traversal hole).

    Walks every existing prefix from the first component up; a symlink
    anywhere on the route could redirect the evidence chain. The FINAL
    component may not exist yet (we create it); prefixes must be real dirs.
    Review B4 round 4: ONLY ENOENT may mean "absent". An EACCES/EIO lstat
    proves nothing, so it fails closed as a ConfigurationError instead of
    silently trusting an unverifiable route.
    """
    absolute = os.path.abspath(path)
    prefix = absolute
    while True:
        parent = os.path.dirname(prefix)
        if parent == prefix:
            break
        try:
            st = lstat(parent)
        except FileNotFoundError:
            st = None                    # not existing above here: makedirs will
        except OSError as exc:
            raise ConfigurationError(
                "cannot verify symlink-free route to diag out dir (%s)"
                % type(exc).__name__) from None
        if st is not None and stat_module.S_ISLNK(st.st_mode):
            raise ConfigurationError(
                "diag out dir path must not contain a symlink component: %s" % parent)
        prefix = parent
    try:
        st = lstat(absolute)
    except FileNotFoundError:
        st = None                        # final component absent: allowed
    except OSError as exc:
        raise ConfigurationError(
            "cannot verify symlink-free route to diag out dir (%s)"
            % type(exc).__name__) from None
    if st is not None:
        if stat_module.S_ISLNK(st.st_mode):
            raise ConfigurationError("diag out dir must not be a symlink: %s" % path)
        if not stat_module.S_ISDIR(st.st_mode):
            raise ConfigurationError("diag out dir must be a directory: %s" % path)
    return absolute


def ensure_out_dir(path, chmod_fn=os.chmod):
    """--out-dir is fail-closed: no symlink route, real directory, 0700.

    The evidence file aggregates the user's whole proxy topology, so it gets
    the same treatment as a secret file. On POSIX, failing to (tighten to)
    0700 is FATAL (review B4): evidence that cannot be provably private is
    not written at all. Windows relies on NTFS ACLs (mode bits carry no
    access semantics there) -- documented, like E4's --secret-file caveat.
    """
    absolute = check_no_symlink_component(path, lstat=os.lstat)
    if not os.path.isdir(absolute):
        try:
            os.makedirs(absolute, mode=0o700)
        except OSError as exc:
            raise ConfigurationError(
                "cannot create diag out dir %s (%s)"
                % (path, type(exc).__name__)) from None
    if not _WINDOWS:
        try:
            chmod_fn(absolute, 0o700)
        except OSError as exc:
            raise ConfigurationError(
                "cannot enforce 0700 on diag out dir %s (%s)"
                % (path, type(exc).__name__)) from None
    return absolute


def load_or_create_hmac_key(out_dir, open_fn=os.open, fstat_fn=os.fstat,
                            read_fn=os.read, fsync_fn=os.fsync,
                            fsync_dir_fn=_fsync_dir):
    """Random 256-bit key for test-id HMACs, created once per evidence dir.

    The file is 0600, regular, never a symlink (O_NOFOLLOW + fstat), and a
    permission-violating pre-existing key refuses startup: fail-closed
    BEFORE collection, per the reviewed design. Creation uses
    O_CREAT|O_EXCL so a lost race never truncates or overwrites another
    writer's key -- EEXIST falls back to re-reading through this same safe
    loader. NO KEY IS RETURNED UNTIL DURABILITY IS PROVEN (review R4, the
    same laundering hole #46 closed for the reader key): every load path --
    first create AND every later reuse -- fsyncs the key file itself and
    fsyncs the containing directory before handing bytes back. A key whose
    write or fsync failed is therefore never silently trusted by the next
    process: that process re-proves durability and refuses while the
    storage fault persists, so "test_id stable across restarts" cannot be
    bypassed by a failed first init. Key bytes never appear in any record
    or output -- they only feed hmac.new().
    """
    path = os.path.join(out_dir, KEY_FILENAME)
    try:
        # O_RDWR (not O_RDONLY): the durability fsync below must be a
        # provable write-path sync on every platform (Windows _commit
        # rejects read-only handles).
        fd = open_fn(path, os.O_RDWR | _O_BINARY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        fd = None
    except OSError as exc:
        if getattr(exc, "errno", None) == getattr(os, "ELOOP", 40):
            raise ConfigurationError(
                "diag key file must not be a symlink: %s" % path) from exc
        raise ConfigurationError(
            "cannot open diag key file %s (%s)" % (path, type(exc).__name__)) from None
    if fd is not None:
        try:
            st = fstat_fn(fd)
            if not stat_module.S_ISREG(st.st_mode):
                raise ConfigurationError(
                    "diag key file must be a regular file: %s" % path)
            if not _WINDOWS and st.st_mode & 0o077:
                raise ConfigurationError(
                    "diag key file permissions too open (%s): %s"
                    % (oct(st.st_mode & 0o777), path))
            # read-until-EOF: a single os.read can return a SHORT read on
            # Windows CRT; a partial key must never be called corrupt.
            chunks = []
            got = 0
            while got < HMAC_KEY_BYTES:
                part = read_fn(fd, HMAC_KEY_BYTES * 4)
                if not part:
                    break
                chunks.append(part)
                got += len(part)
            blob = b"".join(chunks)
            if len(blob) != HMAC_KEY_BYTES:
                raise ConfigurationError("diag key file corrupt: %s" % path)
            try:
                fsync_fn(fd)      # R4: contents durably on disk, or no return
            except OSError as exc:
                raise ConfigurationError(
                    "cannot prove durability of diag key file %s (%s)"
                    % (path, type(exc).__name__)) from None
        finally:
            os.close(fd)
        fsync_dir_fn(out_dir)     # R4: the directory ENTRY is durable too
        return blob
    try:
        fd = open_fn(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_BINARY
                     | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError:
        # lost race: read theirs, same injection surface
        return load_or_create_hmac_key(out_dir, open_fn=open_fn,
                                       fstat_fn=fstat_fn, read_fn=read_fn,
                                       fsync_fn=fsync_fn,
                                       fsync_dir_fn=fsync_dir_fn)
    except OSError as exc:
        raise ConfigurationError(
            "cannot create diag key file %s (%s)" % (path, type(exc).__name__)) from None
    fd_owned = True
    key = os.urandom(HMAC_KEY_BYTES)
    try:
        _write_all(fd, key)
        if not _WINDOWS:
            try:
                os.fchmod(fd, 0o600)
            except OSError as exc:
                raise ConfigurationError(
                    "cannot enforce 0600 on diag key file (%s)"
                    % type(exc).__name__) from None
        fsync_fn(fd)
        fd_owned = False
        os.close(fd)
    except OSError as exc:
        # the (possibly partial) file stays on disk; no key is returned and
        # every later load must re-prove durability before trusting it (R4)
        raise ConfigurationError(
            "cannot write diag key file %s (%s)" % (path, type(exc).__name__)) from None
    finally:
        if fd_owned:
            os.close(fd)
    fsync_dir_fn(out_dir)
    return key


def _try_lock(fd, lock_fn=None):
    if lock_fn is not None:
        return lock_fn(fd)
    if fcntl is not None:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    if msvcrt is not None:
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        return True
    return True  # platform without advisory locks: documented, single-writer


def acquire_instance_lock(out_dir, open_fn=os.open, lock_fn=None):
    """One collector per evidence directory (review B4).

    An advisory exclusive non-blocking lock on diag.lock; contention means
    another resident collector owns this evidence chain and a second writer
    would interleave/rotate under it -> refusal BEFORE polling, never two
    writers. The fd must stay open for the process lifetime.
    """
    path = os.path.join(out_dir, LOCK_FILENAME)
    try:
        fd = open_fn(path, os.O_RDWR | os.O_CREAT | _O_BINARY
                     | getattr(os, "O_NOFOLLOW", 0),
                     0o600)
    except OSError as exc:
        raise ConfigurationError(
            "cannot open diag lock file %s (%s)" % (path, type(exc).__name__)) from None
    try:
        st = os.fstat(fd)
        if not stat_module.S_ISREG(st.st_mode):
            raise ConfigurationError(
                "diag lock file must be a regular file: %s" % path)
        if not _WINDOWS:
            try:
                os.fchmod(fd, 0o600)
            except OSError as exc:
                raise ConfigurationError(
                    "cannot enforce 0600 on diag lock file (%s)"
                    % type(exc).__name__) from None
        if not _try_lock(fd, lock_fn=lock_fn):
            raise OSError("lock refused")
    except ConfigurationError:
        os.close(fd)
        raise
    except OSError as exc:
        os.close(fd)
        raise ConfigurationError(
            "another diag collector holds this output dir: %s (%s)"
            % (out_dir, type(exc).__name__)) from None
    return fd


# -- the evidence writer --------------------------------------------------------

class DiagWriter:
    """Append-only JSONL with durable size-shift rotation (review B4).

    O_APPEND + one write-until-complete loop per batch keeps every record
    line intact at the byte level (worst case after a crash: one torn final
    line -- the next process truncates that fragment back to the last
    newline before appending, so the file stays valid JSONL). The opened fd
    is fstat-verified a
    regular file and fchmod-secured to 0600; a permission-tightening
    failure is FATAL on POSIX. fsync happens once per cycle batch:
    durability of a forensic cycle as a unit; rotation additionally fsyncs
    the file before the rename and the directory after it. The OS-facing
    calls are instance attributes so the storage tests can inject failures
    deterministically on any platform.
    """

    def __init__(self, out_dir, max_mb=DEFAULT_MAX_MB, files=DEFAULT_FILES):
        self.out_dir = out_dir
        self.path = os.path.join(out_dir, DIAG_FILENAME)
        try:
            max_mb = float(max_mb)
        except (TypeError, ValueError):
            max_mb = DEFAULT_MAX_MB
        self.max_bytes = max(int(max_mb * 1024 * 1024), 4096)
        self.files = max(int(files or DEFAULT_FILES), MIN_FILES)
        self.open_fn = os.open
        self.write_fn = os.write
        self.fsync_fn = os.fsync
        self.fstat_fn = os.fstat
        self.fchmod_fn = os.fchmod
        self.close_fn = os.close
        self.replace_fn = os.replace
        self.exists_fn = os.path.exists
        self.getsize_fn = os.path.getsize
        self.fsync_dir_fn = _fsync_dir
        self.clock_fn = time.time
        self.listdir_fn = os.listdir
        self.lstat_fn = os.lstat
        self.remove_fn = os.remove
        self.ftruncate_fn = os.ftruncate
        self.lseek_fn = os.lseek
        self.read_fn = os.read
        # frozen design section 8: on startup truncate AT MOST one
        # incomplete trailing fragment back to the last newline, then
        # continue collection. Torn bytes are never frame-protected into
        # a permanently invalid JSONL line (review B4 residual).
        self._torn_bytes = self._repair_torn_tail()

    def _repair_torn_tail(self):
        """Drop only the incomplete trailing fragment; return bytes removed.

        Review B4 round 4: the current file is VALIDATED before it is
        measured. The only benign startup outcome is a clean
        FileNotFoundError; the fd is then fstat-verified a regular file
        BEFORE any size == 0 short circuit, so a pre-existing zero-byte
        symlink or FIFO can never slip through, and every other
        open/fstat/read/truncate/fsync OSError fails closed as a
        StorageError. Opening O_RDWR (never O_WRONLY) also means an
        accidental FIFO cannot block startup waiting for a reader.

        A well-formed line (trailing newline INCLUDED) never exceeds
        RECORD_MAX_BYTES, so if any complete line exists its final newline
        lies inside the last RECORD_MAX_BYTES window. No newline at all in a
        bigger-than-one-record file means MORE than one fragment would be
        lost -- outside the reviewed recovery contract, so fail closed.
        """
        fd = None
        try:
            try:
                fd = self.open_fn(self.path, os.O_RDWR | _O_BINARY
                                  | getattr(os, "O_NOFOLLOW", 0))
            except FileNotFoundError:
                return 0         # clean absence is the ONLY benign outcome
            st = self.fstat_fn(fd)
            if not stat_module.S_ISREG(st.st_mode):
                raise StorageError("evidence target is not a regular file: %s"
                                   % self.path)
            size = st.st_size
            if size == 0:
                return 0
            window = min(size, RECORD_MAX_BYTES)
            self.lseek_fn(fd, size - window, os.SEEK_SET)
            chunks = []
            got = 0
            while got < window:          # os.read may short-read; loop to EOF
                chunk = self.read_fn(fd, window - got)
                if not chunk:
                    break
                chunks.append(chunk)
                got += len(chunk)
            tail = b"".join(chunks)
            cut = tail.rfind(b"\n")
            if cut < 0 and size > RECORD_MAX_BYTES:
                raise StorageError("evidence tail unrecoverable beyond one "
                                   "fragment: %s" % self.path)
            keep = size - window + cut + 1 if cut >= 0 else 0
            removed = size - keep
            if removed:
                self.ftruncate_fn(fd, keep)
                self.fsync_fn(fd)   # only file metadata changed; no dir fsync
            return removed
        except OSError as exc:
            raise StorageError("cannot repair torn tail of %s (%s)"
                               % (self.path, type(exc).__name__)) from None
        finally:
            if fd is not None:
                self.close_fn(fd)

    def write(self, records):
        if not records:
            return
        blob = b"".join(encode_record(r) for r in records)
        flags = (os.O_WRONLY | os.O_CREAT | os.O_APPEND | _O_BINARY
                 | getattr(os, "O_NOFOLLOW", 0))
        try:
            fd = self.open_fn(self.path, flags, 0o600)
        except OSError as exc:
            raise StorageError("cannot open %s (%s)"
                               % (self.path, type(exc).__name__)) from None
        try:
            st = self.fstat_fn(fd)
            if not stat_module.S_ISREG(st.st_mode):
                raise StorageError("evidence target is not a regular file: %s"
                                   % self.path)
            if not _WINDOWS:
                # tighten even if the file pre-existed; FAILURE IS FATAL --
                # non-private evidence is refused, not "best effort"
                try:
                    self.fchmod_fn(fd, 0o600)
                except OSError as exc:
                    raise StorageError("cannot enforce 0600 on %s (%s)"
                                       % (self.path, type(exc).__name__)) from None
            _write_all(fd, blob, write_fn=self.write_fn)
            self.fsync_fn(fd)
        except OSError as exc:
            raise StorageError("cannot write %s (%s)"
                               % (self.path, type(exc).__name__)) from exc
        finally:
            self.close_fn(fd)
        try:
            if self.getsize_fn(self.path) > self.max_bytes:
                self.rotate()
        except StorageError:
            raise
        except OSError as exc:
            raise StorageError("cannot size-check %s (%s)"
                               % (self.path, type(exc).__name__)) from None

    def rotate(self):
        """Durable numeric shift: diag.jsonl -> .1 -> ... -> .{N-1}.

        fsync current -> rename -> fsync directory (POSIX), so a crash
        between the rename steps never loses a whole chain generation.
        """
        try:
            if self.exists_fn(self.path):
                # O_RDWR: Windows CRT _commit() rejects read-only fds, so a
                # plain O_RDONLY fsync handle would break --prune-now there;
                # fsync semantics on POSIX are identical either way.
                fd = self.open_fn(self.path, os.O_RDWR | _O_BINARY)
                try:
                    self.fsync_fn(fd)
                finally:
                    self.close_fn(fd)
            for index in range(self.files - 2, 0, -1):
                src = "%s.%d" % (self.path, index)
                dst = "%s.%d" % (self.path, index + 1)
                if self.exists_fn(src):
                    self.replace_fn(src, dst)
            if self.exists_fn(self.path):
                self.replace_fn(self.path, self.path + ".1")
        except OSError as exc:
            raise StorageError("rotation failed under %s (%s)"
                               % (self.out_dir, type(exc).__name__)) from None
        self.fsync_dir_fn(self.out_dir)

    def prune(self, now=None):
        """Age retention (frozen design section 8, review B4 residual).

        Rotated files older than RETENTION_SECONDS are removed OLDEST-FIRST;
        the 32 MiB total budget and the <=32-file chain bound are enforced by
        the same pass (overflow indexes and over-budget tails drop oldest
        first). The current diag.jsonl is never touched here -- it is under
        size-cap rotation control. Returns the number of files removed.
        Retention is only provable over VERIFIABLE metadata (review R1): a
        FileNotFoundError mid-scan is the one tolerated race; any other
        stat/getsize error raises StorageError instead of silently dropping
        that file from the age/count/budget accounting. Chain members are
        checked with a NON-FOLLOWING lstat and must be regular files --
        symlink or special-file members fail closed, they are never walked
        through or ignored. All OS surfaces are injectable for
        deterministic tests.
        """
        if now is None:
            now = self.clock_fn()
        try:
            names = self.listdir_fn(self.out_dir)
        except OSError as exc:
            raise StorageError("cannot list evidence dir (%s)"
                               % type(exc).__name__) from None
        prefix = DIAG_FILENAME + "."
        rotated = []
        total = 0
        for name in names:
            if not name.startswith(prefix):
                continue
            suffix = name[len(prefix):]
            if not suffix.isdigit():
                continue
            path = os.path.join(self.out_dir, name)
            try:
                st = self.lstat_fn(path)
            except FileNotFoundError:
                continue          # vanished mid-scan: nothing left to prune
            except OSError as exc:
                raise StorageError("cannot verify evidence file metadata (%s)"
                                   % type(exc).__name__) from None
            if not stat_module.S_ISREG(st.st_mode):
                raise StorageError(
                    "evidence chain member is not a regular file")
            rotated.append((st.st_mtime, int(suffix), path, st.st_size))
            total += st.st_size
        try:
            total += self.getsize_fn(self.path)
        except FileNotFoundError:
            pass                  # current file absent: nothing to budget
        except OSError as exc:
            raise StorageError("cannot size current evidence file (%s)"
                               % type(exc).__name__) from None
        rotated.sort()            # oldest mtime first, index as tie-break
        budget_bytes = TOTAL_MB_BUDGET * 1024 * 1024
        removed = 0
        for mtime, index, path, size in rotated:
            # A break would be wrong: chain indexes are not mtime-ordered,
            # so an overflow-index (or over-budget) victim can sit behind a
            # file the age rule keeps. The scan is bounded by MAX_FILES.
            if not (now - mtime > RETENTION_SECONDS
                    or index >= self.files
                    or total > budget_bytes):
                continue
            try:
                self.remove_fn(path)
            except OSError as exc:
                raise StorageError("cannot prune evidence file (%s)"
                                   % type(exc).__name__) from None
            total -= size
            removed += 1
        return removed


def encode_record(record):
    """One canonical line: compact, sorted keys, ASCII-safe, newline-terminated.

    Hard 64 KiB ceiling (review B5) measured on the FINAL ENCODED BYTES
    INCLUDING the trailing newline: an oversized record is TRIMMED
    STRUCTURALLY (element by element, largest evidence arrays first -- never
    byte-sliced) and marked ``truncated``; a sample that still cannot fit
    collapses to its scalar facts, any other unfixable record collapses to
    a storage collector note. Silent oversized serialization never happens.
    Records are built as closed literal dicts everywhere in this module;
    json.dumps never sees a raw API payload, so response bytes cannot ride
    along into the evidence file.
    """
    line = _encode(record)
    if len(line) <= RECORD_MAX_BYTES:
        return line
    data = copy.deepcopy(record)
    data["truncated"] = True
    while len(line) > RECORD_MAX_BYTES and _trim_once(data):
        line = _encode(data)
    if len(line) <= RECORD_MAX_BYTES:
        return line
    if record.get("t") == "sample":
        data = {"v": record.get("v"), "t": "sample", "ts": record.get("ts"),
                "run": record.get("run"), "seq": record.get("seq"),
                "api_reachable": record.get("api_reachable"),
                "mihomo_version": record.get("mihomo_version"),
                "proxies_status": record.get("proxies_status"),
                "connections_status": record.get("connections_status"),
                "groups": [], "nodes": [], "connection_chains": [],
                "truncated": True,
                "invalid_fields": record.get("invalid_fields")}
    else:
        data = {"v": record.get("v"), "t": "collector", "ts": record.get("ts"),
                "run": record.get("run"), "seq": record.get("seq"),
                "code": "storage_error", "scope": "storage", "count": 1}
    return _encode(data)


def _encode(record):
    return (json.dumps(record, ensure_ascii=True, sort_keys=True,
                       separators=(",", ":")) + "\n").encode("utf-8")


def _trim_once(data):
    """Drop exactly one element from the largest evidence array."""
    nodes = data.get("nodes")
    if isinstance(nodes, list) and nodes:
        last = nodes[-1]
        if isinstance(last, dict):
            if isinstance(last.get("extra"), list) and last["extra"]:
                last["extra"].pop()
                return True
            if isinstance(last.get("history"), list) and last["history"]:
                last["history"].pop()
                return True
        nodes.pop()
        return True
    chains = data.get("connection_chains")
    if isinstance(chains, list) and chains:
        chains.pop()
        return True
    groups = data.get("groups")
    if isinstance(groups, list) and groups:
        last = groups[-1]
        if isinstance(last, dict):
            if isinstance(last.get("members"), list) and last["members"]:
                last["members"].pop()
                return True
        groups.pop()
        return True
    return False


# -- the collector --------------------------------------------------------------

class DiagCollector:
    """One forensic cycle -> the closed records that cycle. Never raises.

    Reuses the audited E4 transport end to end. /version decides
    reachability: ANY version failure (transport error, non-200, malformed
    body, missing/unusable version field) maps to the single version-scope
    collector code ``mihomo_unreachable`` and the other reads are SKIPPED
    for that cycle -- but the sample is still emitted (api_reachable=false,
    mihomo_version=null, endpoint statuses honestly "unavailable") and the
    diff chain is marked broken, so an outage or restart during a version
    failure is visible evidence, never a hole and never a fabricated edge
    (review B2). /proxies and /connections are attempted independently; a
    failed one yields its own status and code, never a fabricated empty
    result.
    """

    def __init__(self, url, groups, secret=None, timeout=DEFAULT_TIMEOUT,
                 transport=None, clock=time.time, hmac_key=None, nodes=None):
        self.url = url
        self.host, self.port, self.scheme = parse_controller_url(url)
        self.groups = list(groups or [])
        self.nodes = list(nodes or [])   # caller-named explicit nodes (B5)
        self.secret = secret or ""
        self.timeout = clamp_timeout(timeout)
        self.hmac_key = hmac_key
        self.clock = clock
        self.transport = transport or HttpTransport(
            self.host, self.port, scheme=self.scheme, secret=self.secret,
            timeout=self.timeout)

    # -- helpers --

    def _get(self, path):
        """-> (payload, status) with status in ("ok", "unavailable", "invalid").

        There is deliberately NO detail channel: no exception text, no HTTP
        status code, no response body bytes ever leave this method (review
        B1) -- the closed status vocabulary is all the evidence gets.
        """
        try:
            status_code, body = self.transport.get(path)
        except Exception:  # noqa: BLE001 -- never propagate, never describe
            return None, "unavailable"
        if status_code != 200:
            return None, "unavailable"
        try:
            return json.loads(body.decode("utf-8")), "ok"
        except (ValueError, UnicodeDecodeError):
            return None, "invalid"

    # -- one cycle --

    def collect_cycle(self, state):
        """Poll once, diff against run-local state, return (records, flags)."""
        ts = utc_iso(self.clock())
        run = state["run"]
        records = []
        events = []
        present = set()
        seq_box = [state["seq"]]

        def next_seq():
            seq_box[0] += 1
            return seq_box[0]

        # 1) the sample exists FIRST and is completed in place -- every
        #    cycle produces exactly one sample no matter what fails below.
        sample = {"v": SCHEMA_V, "t": "sample", "ts": ts, "run": run,
                  "seq": next_seq(), "api_reachable": False,
                  "mihomo_version": None,
                  "proxies_status": "unavailable",
                  "connections_status": "unavailable",
                  "groups": [], "nodes": [], "connection_chains": [],
                  "truncated": False, "invalid_fields": 0}
        records.append(sample)
        flags = {"api_failed": False, "codes": [],
                 "proxies_status": "unavailable",
                 "connections_status": "unavailable"}

        # 2) /version: reachability + version (bounded display string; a
        #    version field that fails the name bound is a failure, kept
        #    honest as mihomo_unreachable, never a truncated fake).
        payload, status = self._get("/version")
        version = None
        if status == "ok" and isinstance(payload, dict):
            version = safe_name(payload.get("version"))
        if version is None:
            present.add("mihomo_unreachable")
            # no /proxies observation this cycle: the diff chain is broken
            state["proxies_gap"] = True
            codes = _fold_collector(state, records, present, ts, run, next_seq,
                                    full_cycle=False)
            flags.update(api_failed=True, codes=codes)
            state["seq"] = seq_box[0]
            return records, flags
        sample["api_reachable"] = True
        sample["mihomo_version"] = version

        # 3) /proxies for the caller-named groups (never guessed, never
        #    inferred). A broken /proxies yields an honest status and its
        #    own code; it never fabricates empty groups/nodes.
        proxies_summary = None
        if self.groups:
            payload, status = self._get("/proxies")
            if status == "ok":
                proxies_summary = parse_proxies_summary(payload, self.groups,
                                                        hmac_key=self.hmac_key,
                                                        explicit_nodes=self.nodes)
                if not proxies_summary["usable"]:
                    proxies_summary = None
                    status = "invalid"
            if proxies_summary is not None:
                sample["groups"] = proxies_summary["groups"]
                sample["nodes"] = proxies_summary["nodes"]
                sample["truncated"] = bool(proxies_summary["truncated"])
                sample["invalid_fields"] += proxies_summary["invalid_fields"]
                sample["proxies_status"] = "ok"
                if proxies_summary["missing_groups"]:
                    present.add("group_missing")
                if proxies_summary["missing_nodes"]:
                    present.add("node_missing")
            else:
                sample["proxies_status"] = status
                present.add("proxies_invalid")

        # 4) /connections (per-node chain aggregates only). Per-endpoint
        #    isolation: a broken /proxies must not hide the connection view.
        payload, status = self._get("/connections")
        if status == "ok":
            watched = (proxies_summary["watched"]
                       if proxies_summary is not None else [])
            chains, malformed = parse_connections_summary(payload, watched)
            if chains is None:
                sample["connections_status"] = "invalid"
                present.add("connections_invalid")
            else:
                sample["connection_chains"] = chains
                sample["connections_status"] = "ok"
                if malformed:
                    sample["invalid_fields"] += malformed
        else:
            sample["connections_status"] = status
            present.add("connections_invalid")

        # 5) diff THIS run's observations only (review B2), then stamp the
        #    events with the schema envelope.
        _apply_diffs(state, events, ts, proxies_summary)
        for event in events:
            records.append({"v": SCHEMA_V, "run": run, "seq": next_seq(),
                            **event})

        # 6) whole-cycle ledger fold: one collector record per present code,
        #    reset only absent codes and only on a full cycle (review B6).
        codes = _fold_collector(state, records, present, ts, run, next_seq,
                                full_cycle=True)
        flags.update(api_failed=(sample["proxies_status"] != "ok"
                                 or sample["connections_status"] != "ok"),
                     codes=codes, proxies_status=sample["proxies_status"],
                     connections_status=sample["connections_status"])
        state["seq"] = seq_box[0]
        return records, flags


def _fold_collector(state, records, present, ts, run, next_seq, full_cycle):
    """Whole-cycle collector accounting (review B6).

    present: the SET of codes this cycle produced, computed BEFORE this
    call so one code shared by several endpoints yields exactly ONE record
    with ONE increment. Each present code bumps its consecutive-cycle
    count; absent codes are removed from the ledger ONLY on a full cycle
    (all endpoints attempted) and never for a code that was present.
    """
    codes = []
    for code in sorted(present):
        count = state["err_counts"].get(code, 0) + 1
        state["err_counts"][code] = count
        codes.append(code)
        records.append({"v": SCHEMA_V, "t": "collector", "ts": ts, "run": run,
                        "seq": next_seq(), "code": code,
                        "scope": CODE_SCOPE[code], "count": count})
    if full_cycle:
        for code in list(state["err_counts"]):
            if code not in present:
                del state["err_counts"][code]
    return codes


# -- CLI --------------------------------------------------------------------------

def validate_cli_groups(groups):
    """Caller-named groups: 1..8, each a valid bounded name.

    At least one group is REQUIRED: a zero-group collector would sample
    empty evidence forever, which is a misconfiguration the CLI refuses
    outright rather than records.
    """
    if not groups:
        raise ConfigurationError("at least one --group is required")
    if len(groups) > MAX_GROUPS:
        raise ConfigurationError(
            "too many --group values (%s), maximum is %s" % (len(groups), MAX_GROUPS))
    for name in groups:
        if safe_name(name) != name:
            raise ConfigurationError(
                "invalid --group name (empty, over %s bytes, or control characters)"
                % NAME_MAX_BYTES)
    return list(groups)


def validate_cli_nodes(nodes):
    """Caller-named explicit nodes: 0..32, exact bounded names, first-seen dedup.

    Explicit nodes are optional -- groups stay REQUIRED (a zero-group run
    has no selection topology to forensic). A named node outside every
    group's member expansion is still observed (review B5 residual); a
    repeated --node collapses deterministically to its first occurrence.
    """
    if len(nodes) > MAX_NODES:
        raise ConfigurationError(
            "too many --node values (%s), maximum is %s" % (len(nodes), MAX_NODES))
    out = []
    for name in nodes:
        if safe_name(name) != name:
            raise ConfigurationError(
                "invalid --node name (empty, over %s bytes, or control characters)"
                % NAME_MAX_BYTES)
        if name not in out:
            out.append(name)
    return out


def validate_rotation_args(max_mb, files):
    """Rotation arguments stay inside the reviewed budget (never silent)."""
    try:
        max_mb = float(max_mb)
        files = int(files)
    except (TypeError, ValueError):
        raise ConfigurationError("--max-mb/--files must be numbers") from None
    if not 0 < max_mb <= MAX_FILE_MB:
        raise ConfigurationError("--max-mb must be in (0, %s]" % MAX_FILE_MB)
    if not MIN_FILES <= files <= MAX_FILES:
        raise ConfigurationError("--files must be in [%s, %s]" % (MIN_FILES, MAX_FILES))
    if max_mb * files > TOTAL_MB_BUDGET:
        raise ConfigurationError(
            "evidence budget %.0f MiB x %s files exceeds %s MiB total"
            % (max_mb, files, TOTAL_MB_BUDGET))
    return max_mb, files


class _CategoryArgParser(argparse.ArgumentParser):
    """argparse's default error() prints usage and the offending value to
    stderr; the frozen contract (design section 9) allows only the fixed
    category line, so parse-time refusals route through it as well."""

    def error(self, message):
        print("config_error", file=sys.stderr)
        raise SystemExit(EXIT_CONFIG)


def build_arg_parser():
    parser = _CategoryArgParser(
        description="Monitor v2 E4-Diag read-only Mihomo failover forensics "
                    "(local JSONL evidence, display-only names, GET-only)")
    parser.add_argument("--url", default=DEFAULT_URL,
                        help="external-controller URL; MUST be loopback "
                             "(default: %(default)s)")
    parser.add_argument("--group", action="append", default=[],
                        help="proxy group to observe; REQUIRED, repeatable "
                             "(1..%s); caller-named, topology-free (no group "
                             "names are ever hard-coded)" % MAX_GROUPS)
    parser.add_argument("--node", action="append", default=[],
                        help="explicit node to observe in addition to group "
                             "expansion; optional, repeatable (0..%s), "
                             "de-duplicated; final observed set stays capped "
                             "at %s" % (MAX_NODES, OBS_CAP))
    parser.add_argument("--out-dir", required=True,
                        help="evidence directory (no symlink component, "
                             "real dir, 0700 fail-closed); REQUIRED")
    parser.add_argument("--interval", type=float, default=DEFAULT_INTERVAL,
                        help="resident sampling seconds, clamped 30-60 "
                             "(default: %(default)s)")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help="per-request timeout, clamped 1-3 (default: %(default)s)")
    parser.add_argument("--max-mb", type=float, default=DEFAULT_MAX_MB,
                        help="rotate above this size, max %s (default: %s)"
                             % (MAX_FILE_MB, DEFAULT_MAX_MB))
    parser.add_argument("--files", type=int, default=DEFAULT_FILES,
                        help="diag.jsonl plus N-1 shifted files, [%s, %s], "
                             "max-mb*files <= %s MiB (default: %s)"
                             % (MIN_FILES, MAX_FILES, TOTAL_MB_BUDGET,
                                DEFAULT_FILES))
    parser.add_argument("--secret-file", default=None,
                        help="controller secret file, POSIX mode 0600/0400 "
                             "enforced; MIHOMO_API_SECRET takes precedence")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--once", action="store_true",
                      help="single cycle and exit (systemd-timer shape; default). "
                           "Cannot prove selection_changed/alive_flipped "
                           "transitions across invocations -- see README")
    mode.add_argument("--resident", action="store_true",
                      help="sampling loop until SIGTERM; this is the mode "
                           "that produces transition edges")
    mode.add_argument("--prune-now", action="store_true",
                      help="rotate the evidence chain without sampling")
    return parser


def main(argv=None, transport=None, clock=time.time):
    args = build_arg_parser().parse_args(argv)
    interval = clamp_interval(args.interval)
    try:
        groups = validate_cli_groups(args.group)
        nodes = validate_cli_nodes(args.node)
        max_mb, files = validate_rotation_args(args.max_mb, args.files)
        secret = resolve_secret(args.secret_file)
        collector = DiagCollector(args.url, groups, secret=secret,
                                  timeout=args.timeout, transport=transport,
                                  clock=clock, nodes=nodes)
        out_dir = ensure_out_dir(args.out_dir)
        lock_fd = acquire_instance_lock(out_dir)   # noqa: F841 -- held for process life
        collector.hmac_key = load_or_create_hmac_key(out_dir)
        writer = DiagWriter(out_dir, max_mb=max_mb, files=files)
    except (ConfigurationError, SecretFileError):
        # category-only stderr (frozen design section 9): paths, types and
        # messages stay inside the exception -- production never prints them
        print("config_error", file=sys.stderr)
        return EXIT_CONFIG
    except StorageError:
        print("storage_error", file=sys.stderr)
        return EXIT_STORAGE

    if args.prune_now:
        try:
            writer.rotate()
            removed = writer.prune()
        except StorageError:
            print("storage_error", file=sys.stderr)
            return EXIT_STORAGE
        print(json.dumps({"rotated": True, "pruned": removed,
                          "path": writer.path}))
        return EXIT_OK

    state = new_state()           # review B2: every process starts causally clean
    storage_failed = False

    def one_cycle():
        nonlocal storage_failed
        records, flags = collector.collect_cycle(state)
        try:
            writer.write(records)
            # age retention rides every cycle: a months-long resident run
            # and a systemd-timer --once burst both prune oldest-first
            writer.prune()
        except StorageError:
            # the failure itself must be visible, never a silent exit 0
            print("storage_error", file=sys.stderr)
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
    summary = {"api_failed": flags["api_failed"], "codes": flags["codes"],
               "proxies_status": flags["proxies_status"],
               "connections_status": flags["connections_status"],
               "storage_failed": storage_failed, "run": state["run"]}
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
