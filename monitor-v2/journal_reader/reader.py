"""sbox-journal-reader: the dedicated journal-read producer (issue #33 P2).

Runs ONLY as the sbox-jr identity under singbox-journal-reader.service.
Poll mode (v3-B3): every cycle spawns a BOUNDED ``journalctl`` child with
the reader-owned ``--after-cursor`` / ``--since`` position, consumes
stdout strictly line-by-line, applies the whitelist
parse -> classify -> sanitize pipeline, and commits through the
C1/D2/D3 pending -> exchange-file -> committed protocol. The durable
cursor advances ONLY after a durable exchange file exists, so writer
failure is lag + explicit gap, never silent loss.

D1 poll-child outcome table (frozen):
  1 rc 0 with records                -> commit per C1
  2 rc 0 zero records                -> no batch, no file, heartbeat only,
                                        ZERO state movement
  3 reader-self SIGTERM at backlog   -> truncated_batch: commit through the
     cap                               LAST PROCESSED usable cursor
  4 rc!=0 AFTER >=1 usable cursor    -> discard batch (nothing exported),
                                        sanitized journal_source_unavailable,
                                        exit non-zero, state frozen
  5 rc!=0 BEFORE first usable cursor -> fail-stop, same code, ZERO movement
                                        (no epoch bump, no cursor guess --
                                        source-gap epochs exist ONLY via the
                                        reviewed operator reset path)
  6 processed entry w/o valid cursor -> journal_cursor_invalid, batch
                                        non-committable, exit

Rows 3-6 are why this process never retries internally: exit non-zero
FAST, let systemd's Restart=on-failure/StartLimit own the backoff.
Nothing resembling a raw journal line, address, cursor or key ever
reaches stderr, the exchange, or an exception message.

Python 3.10 stdlib only. Importable as ``journal_reader.reader`` (tests)
and runnable standalone (production entry point).
"""

import io
import json
import os
import re
import stat as _stat
import subprocess
import sys
import time
import uuid

try:  # package import (tests, `python3 -m`)
    from . import cursor as cursor_mod
    from . import fingerprint, state
    from .codes import (CODE_CURSOR_INVALID, CODE_RESET_REFUSED,
                        CODE_SOURCE_UNAVAILABLE, CODE_STATE_CORRUPTION,
                        CODE_UNIT_INVALID, CODE_WRITER_FAILED)
    from .eligibility import DROP_INFO, DROP_NOMATCH, assess
    from .journal_time import (JournalTimeError, normalize_journalctl_since,
                               now_journalctl_form)
    from .schema import (CLASSIFIER_VERSION, CLASSES, FORMAT_VERSION,
                         validate_event, validate_header)
except ImportError:  # standalone script exec (production ExecStart)
    sys.path.insert(0, os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))
    from journal_reader import cursor as cursor_mod
    from journal_reader import fingerprint, state
    from journal_reader.codes import (CODE_CURSOR_INVALID,
                                      CODE_RESET_REFUSED,
                                      CODE_SOURCE_UNAVAILABLE,
                                      CODE_STATE_CORRUPTION,
                                      CODE_UNIT_INVALID, CODE_WRITER_FAILED)
    from journal_reader.eligibility import DROP_INFO, DROP_NOMATCH, assess
    from journal_reader.journal_time import (
        JournalTimeError, normalize_journalctl_since, now_journalctl_form)
    from journal_reader.schema import (CLASSIFIER_VERSION, CLASSES,
                                       FORMAT_VERSION, validate_event,
                                       validate_header)

DEFAULT_UNIT = "sing-box.service"
UNIT_ENV_VAR = "SBOX_JR_UNIT"
UNIT_RE = re.compile(r"\A[A-Za-z0-9_.@-]{1,64}\Z")

DEFAULT_STATE_DIR = "/var/lib/sbox-journal/state"
DEFAULT_OUT_DIR = "/var/lib/sbox-journal/out"

# Hard limits (design §9 as amended): all code defaults, no runtime knobs.
WINDOW_SECONDS = 10.0
BACKLOG_CAP = 50000            # decoded entries per poll (hang guard)
MAX_RECORDS_PER_FILE = 200     # aggregated records; overflow folds by class
MAX_FP_PER_WINDOW = 16         # unknown-template flood bound
RETENTION_MAX_FILES = 720      # ~2h of non-empty windows
RETENTION_MAX_BYTES = 8 * 1024 * 1024
CHILD_WAIT_TIMEOUT = 5.0

HB_NAME = "hb"


class ReaderFailure(Exception):
    """Sanitized terminal failure: carries ONE code from codes.py only."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


class CrashInjected(Exception):
    """Test-harness-only signal simulating power loss at a named
    durability boundary (never raised when faults is empty)."""


def resolve_unit(env=None):
    """Compiled-in default; overridable ONLY via the unit's own
    Environment= with strict grammar -- an invalid value fails closed, it
    is never sanitized into something usable."""
    value = (env if env is not None else os.environ).get(UNIT_ENV_VAR)
    if value is None or value == "":
        return DEFAULT_UNIT
    if not UNIT_RE.match(value):
        raise ReaderFailure(CODE_UNIT_INVALID)
    return value


class Reader:
    def __init__(self, state_dir=DEFAULT_STATE_DIR, out_dir=DEFAULT_OUT_DIR,
                 journalctl="journalctl", unit=None, popen=None,
                 now_fn=None, faults=None):
        self.state_dir = state_dir
        self.out_dir = out_dir
        self.journalctl = journalctl
        self.unit = unit if unit is not None else resolve_unit()
        self._popen = popen or subprocess.Popen
        self._now = now_fn or time.time
        # faults: set of "<kind>.<point>" names at which a CrashInjected is
        # raised INSTEAD of crossing that durability boundary (T28 only).
        self.faults = faults or set()
        self.run_id = uuid.uuid4().hex
        self._key = None

    # ------------------------------------------------------------------
    # fault gate plumbing (test hook; production passes gate=None no-ops)
    # ------------------------------------------------------------------

    def _gate(self, kind):
        if not self.faults:
            return None

        def gate(point):
            if "%s.%s" % (kind, point) in self.faults:
                raise CrashInjected("%s.%s" % (kind, point))

        return gate

    # ------------------------------------------------------------------
    # journalctl child
    # ------------------------------------------------------------------

    def _spawn(self, argv):
        # Fixed argv, direct list form: unit name and opaque cursor are
        # NEVER shell-interpolated, stderr is DEVNULL (journalctl wording
        # never reaches any of our artifacts), secrets never in argv/env.
        return self._popen(argv, stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL,
                           stdin=subprocess.DEVNULL)

    def _capture_tail_anchor(self):
        """C5/D3: obtain the journal tail cursor ONCE ('now' as a fact in
        the journal, never a recomputed timestamp). On any failure returns
        the durable since fallback: ONE fixed local-form string reused
        verbatim by every poll until the first committable cursor."""
        argv = [self.journalctl, "-u", self.unit, "-n", "0",
                "--show-cursor"]
        try:
            child = self._spawn(argv)
        except OSError:
            child = None
        if child is not None:
            stdout = b""
            try:
                stdout, _ = child.communicate(timeout=CHILD_WAIT_TIMEOUT)
                rc = child.returncode
            except Exception:
                self._kill_child(child)
                rc = -1
            if rc == 0:
                cursor = cursor_mod.parse_show_cursor(
                    stdout.decode("utf-8", "replace")
                    if isinstance(stdout, (bytes, bytearray)) else str(stdout))
                if cursor is not None:
                    return {"mode": "cursor", "value": cursor}
        try:
            since = normalize_journalctl_since(now_journalctl_form())
        except JournalTimeError:
            raise ReaderFailure(CODE_STATE_CORRUPTION)
        return {"mode": "since", "value": since}

    def _poll_argv(self, source):
        argv = [self.journalctl, "-u", self.unit, "-o", "json", "--quiet"]
        if source["mode"] == "cursor":
            argv += ["--after-cursor", source["value"]]
        else:
            argv += ["--since", source["value"]]
        return argv

    @staticmethod
    def _kill_child(child):
        try:
            child.kill()
        except OSError:
            pass
        try:
            child.wait(timeout=CHILD_WAIT_TIMEOUT)
        except Exception:
            pass

    def _terminate_child(self, child):
        """C4 truncated-batch termination: SIGTERM, close stdout, bounded
        wait, hard kill only if the child ignores the signal. The unread
        tail is DISCARDED -- never represented as committed."""
        try:
            child.terminate()
        except OSError:
            pass
        try:
            child.wait(timeout=CHILD_WAIT_TIMEOUT)
        except Exception:
            try:
                self._kill_child(child)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # startup / crash recovery (C2 table; cross-run pending is legitimate)
    # ------------------------------------------------------------------

    def _durably(self, fn, *args, **kwargs):
        """Review #46 B4: an EXPECTED state-durability failure (tmp open /
        write / fsync / rename / unlink OSError) becomes the sanitized
        journal_writer_failed code -- never a traceback or path into
        journald. Malformed/invalid LOADED state stays
        journal_state_corruption at the load/validation sites."""
        try:
            return fn(*args, **kwargs)
        except OSError:
            raise ReaderFailure(CODE_WRITER_FAILED)

    def startup(self):
        self._durably(state.clean_scratch, self.state_dir, self.out_dir)
        committed, ok = state.load_committed(self.state_dir)
        if not ok:
            raise ReaderFailure(CODE_STATE_CORRUPTION)
        pending, ok = state.load_pending(self.state_dir)
        if not ok:
            raise ReaderFailure(CODE_STATE_CORRUPTION)
        seqs = state.durable_ev_seqs(self.out_dir)
        row, action = state.evaluate_recovery(committed, pending, seqs,
                                              self.out_dir)
        if action == "fail_closed":
            # Zero writes to state/ and out/: un-stucking is a human /
            # reviewed action, never an automatic regenerate. A durable
            # ev-N can never be silently regenerated under N or N+1.
            raise ReaderFailure(CODE_STATE_CORRUPTION)
        if action == "first_activation":
            anchor = self._capture_tail_anchor()
            self._durably(
                state.write_committed,
                self.state_dir,
                state.make_committed(0, 1, "COLD_START", anchor),
                self.run_id, self._gate("activate"))
            self._enforce_retention()
            return
        if action == "finish_commit":
            # Sign-off frozen invariant: recovery row 2 executes the SAME
            # logical step-4 as the original cycle (seq, epoch,
            # source=source_end, boundary cleared to NONE), then durably
            # removes pending. The durable ev-N is NEVER rewritten.
            self._durably(state.write_committed, self.state_dir,
                          state.step4_committed(pending),
                          self.run_id, self._gate("recover_commit"))
            self._durably(state.remove_pending, self.state_dir,
                          self._gate("recover_unlink"))
            self._enforce_retention()
            return
        if action == "repoll" and pending is not None:
            # Rows 3/4: nothing durable exists for that seq, so
            # re-polling from the UNCHANGED committed cursor regenerates
            # the same window under the same seq (pending is rewritten by
            # the normal cycle). Unlinking stale/abandoned pending here is
            # the recipe's step-5 operation.
            self._durably(state.remove_pending, self.state_dir,
                          self._gate("stale_unlink"))
        # Review #46 B5-residual: every restart re-proves the hard ceiling
        # AFTER C2 recovery and BEFORE any new poll -- a durable GC
        # failure can never grow out/ by one file per restart.
        self._enforce_retention()

    def _load_committed(self):
        committed, ok = state.load_committed(self.state_dir)
        if not ok or committed is None:
            raise ReaderFailure(CODE_STATE_CORRUPTION)
        return committed

    # ------------------------------------------------------------------
    # reader-local HMAC key (R4)
    # ------------------------------------------------------------------

    def _fingerprint_key(self):
        if self._key is None:
            try:
                self._key = fingerprint.load_or_create_key(self.state_dir)
            except OSError:
                raise ReaderFailure(CODE_WRITER_FAILED)
        return self._key

    # ------------------------------------------------------------------
    # one poll+commit cycle
    # ------------------------------------------------------------------

    def run_cycle(self):
        """Execute one full cycle. Returns "committed" | "empty". ANY
        failure raises ReaderFailure and the PROCESS exits -- no
        in-process retry loop (R5/D1)."""
        committed = self._load_committed()
        try:
            child = self._spawn(self._poll_argv(committed["source"]))
        except OSError:
            # journalctl could not even start: indeterminate source failure
            # (D1 row 5 family) -- fail-stop with ZERO state movement.
            raise ReaderFailure(CODE_SOURCE_UNAVAILABLE)
        consumed, truncated = self._consume(child)
        return self._finish_cycle(committed, consumed, truncated)

    def _consume(self, child):
        consumed = _Batch()
        truncated = False
        rc = -1
        stream = None
        try:
            stream = io.TextIOWrapper(child.stdout, encoding="utf-8",
                                      errors="replace", newline="\n")
            for line in stream:
                line = line.strip()
                if not line:
                    continue
                consumed.lines += 1
                try:
                    entry = json.loads(line)
                except ValueError:
                    entry = None
                if not isinstance(entry, dict):
                    # C4/D5 (review #46 B6): EVERY non-blank output line
                    # must decode to a JSON dict carrying a usable
                    # __CURSOR. A malformed line makes the WHOLE batch
                    # non-committable -- the committed cursor may never
                    # cross it. (`pfail` is only for valid-cursor entries
                    # whose MESSAGE/timestamp payload is unusable.)
                    consumed.cursor_invalid = True
                    break
                cursor = entry.get("__CURSOR")
                if not cursor_mod.validate_cursor(cursor):
                    # D1 row 6: the WHOLE batch becomes non-committable --
                    # never a silent skip past an unlocatable record.
                    consumed.cursor_invalid = True
                    break
                # The cursor is usable: this entry counts as PROCESSED and
                # the commit cursor may advance past it (even if its
                # payload is unparsable, re-polling must not loop on it).
                consumed.processed += 1
                consumed.last_cursor = cursor
                message = entry.get("MESSAGE")
                ts = _entry_ts(entry)
                if message is None or ts is None:
                    consumed.pfail += 1
                else:
                    consumed.absorb(assess(message, entry.get("PRIORITY")),
                                    ts, self)
                    if consumed.processed >= BACKLOG_CAP:
                        # D1 row 3: self-induced termination is a
                        # truncated_batch, NEVER a source failure.
                        truncated = True
                        break
        finally:
            try:
                if stream is not None:
                    stream.close()
            except OSError:
                pass
            try:
                if child.poll() is None or truncated:
                    self._terminate_child(child)
            except Exception:
                self._kill_child(child)
            try:
                rc = child.wait(timeout=CHILD_WAIT_TIMEOUT)
            except Exception:
                self._kill_child(child)
                rc = -1
        consumed.final_rc = rc
        return (consumed, truncated)

    def _finish_cycle(self, committed, consumed, truncated):
        if consumed.cursor_invalid:
            # D1 row 6: discard, no pending written, nothing exported.
            raise ReaderFailure(CODE_CURSOR_INVALID)
        if consumed.processed == 0:
            if truncated or consumed.final_rc != 0:
                # D1 row 5: non-zero exit BEFORE the first usable cursor,
                # any cause: fail-stop, ZERO movement -- no epoch bump, no
                # cursor guessing (D1: source-gap epochs are operator-only).
                raise ReaderFailure(CODE_SOURCE_UNAVAILABLE)
            # D1 row 2: empty window -> heartbeat only, no file, no batch,
            # and (since mode included) NO source-anchor movement.
            self._write_heartbeat(committed["seq"])
            return "empty"
        if consumed.final_rc != 0 and not truncated:
            # D1 row 4: mid-batch source failure: DISCARD the whole batch
            # (nothing exported), restart re-polls the unchanged range.
            raise ReaderFailure(CODE_SOURCE_UNAVAILABLE)
        # D1 rows 1/3: commit through the LAST PROCESSED usable cursor.
        self._commit_batch(committed, consumed)
        return "committed"

    # ------------------------------------------------------------------
    # commit protocol (C1 steps 2-5 + exchange file + hb + retention)
    # ------------------------------------------------------------------

    def _commit_batch(self, committed, consumed):
        seq = committed["seq"] + 1
        pending = state.make_pending(self.run_id, seq, committed["epoch"],
                                     committed["boundary"],
                                     consumed.last_cursor)
        # Step 2: pending durable FIRST (incl. state-dir fsync) before any
        # exchange-file write begins.
        self._durably(state.write_pending, self.state_dir, pending,
                      self._gate("pending"))
        # Step 3: ev-<seq>.jsonl.part -> fsync -> rename -> fsync out dir.
        body = consumed.exchange_body(seq, self.run_id, pending)
        self._write_exchange_file(seq, body)
        # Step 4: THE authoritative commit -- also the ONLY place the
        # boundary clears to NONE and since->cursor converts (v5-D2/D3):
        # one atomic object replacement.
        self._durably(state.write_committed, self.state_dir,
                      state.step4_committed(pending),
                      self.run_id, self._gate("committed"))
        # Step 5: settle pending.
        self._durably(state.remove_pending, self.state_dir,
                      self._gate("settle_unlink"))
        self._write_heartbeat(seq)
        self._enforce_retention()

    def _require_out_dir(self):
        if not os.path.isdir(self.out_dir) or os.path.islink(self.out_dir):
            # The reader NEVER creates its exchange dir: an installer
            # contract violation is a writer failure, not a mutation.
            raise ReaderFailure(CODE_WRITER_FAILED)

    def _write_exchange_file(self, seq, body):
        self._require_out_dir()
        part = os.path.join(self.out_dir, "ev-%d.jsonl.part" % seq)
        final = os.path.join(self.out_dir, state.ev_filename(seq))
        gate = self._gate("file")
        try:
            if gate:
                gate("create")
            fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
            with os.fdopen(fd, "w") as handle:
                handle.write(body)
                handle.flush()
                if gate:
                    gate("fsync")
                os.fsync(handle.fileno())
            os.chmod(part, 0o640)
            if gate:
                gate("rename")
            os.replace(part, final)
            if gate:
                gate("dir_fsync")
            state.fsync_dir(self.out_dir)
        except OSError:
            # R5 fail-stop mechanics: abandon the partial window; the
            # cursor NEVER advances past unexported evidence.
            _unlink_quiet(part)
            raise ReaderFailure(CODE_WRITER_FAILED)

    def _write_heartbeat(self, seq):
        """§6.3: rewritten EVERY cycle, event batch or not. Reader
        staleness is Monitor-derived from this file's age (>180s) and
        nothing else."""
        self._require_out_dir()
        tmp = os.path.join(self.out_dir, HB_NAME + ".tmp-" + self.run_id)
        final = os.path.join(self.out_dir, HB_NAME)
        payload = json.dumps({"seq": seq, "ts": int(self._now())},
                             separators=(",", ":"), sort_keys=True)
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
            with os.fdopen(fd, "w") as handle:
                handle.write(payload + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp, 0o640)
            os.replace(tmp, final)
            state.fsync_dir(self.out_dir)
        except OSError:
            _unlink_quiet(tmp)
            raise ReaderFailure(CODE_WRITER_FAILED)

    def _enforce_retention(self):
        """§6.3 bounded failure semantics: oldest-first (lowest-seq)
        eviction of THIS reader's own durable ev files only -- never the
        hb, never anything else in out/. A stopped Monitor causes bounded,
        gap-detectable loss, never unbounded /var/lib growth.

        Review #46 B5: the 720-file / 8 MiB ceiling is a HARD bound, so
        every failure that makes it unverifiable or unenforceable is
        fail-stop (sanitized writer failure): enumeration, stat of an
        expected-regular ev file, unlink while still over bound, and the
        post-GC directory fsync. A candidate that merely VANISHED is not
        growth and never bypasses the ceiling."""
        try:
            names = os.listdir(self.out_dir)
        except OSError:
            raise ReaderFailure(CODE_WRITER_FAILED)
        entries = []
        for name in names:
            match = re.fullmatch(r"ev-([0-9]{1,20})\.jsonl", name)
            if not match:
                continue
            path = os.path.join(self.out_dir, name)
            try:
                st = os.lstat(path)
            except FileNotFoundError:
                continue  # vanished candidate: cannot contribute growth
            except OSError:
                raise ReaderFailure(CODE_WRITER_FAILED)
            if not _stat.S_ISREG(st.st_mode):
                # symlink/dir/FIFO wearing our ev grammar: the byte bound
                # cannot be trusted around it -- fail closed.
                raise ReaderFailure(CODE_WRITER_FAILED)
            entries.append((int(match.group(1)), st.st_size))
        entries.sort()
        total = sum(size for _, size in entries)
        changed = False
        while entries and (len(entries) > RETENTION_MAX_FILES
                           or total > RETENTION_MAX_BYTES):
            seq, size = entries.pop(0)
            try:
                os.unlink(os.path.join(self.out_dir,
                                       state.ev_filename(seq)))
            except FileNotFoundError:
                total -= size
                continue
            except OSError:
                # unlink failure while OVER the hard bound: the growth
                # would continue unchecked next cycle -- fail-stop.
                raise ReaderFailure(CODE_WRITER_FAILED)
            changed = True
            total -= size
        if changed:
            try:
                state.fsync_dir(self.out_dir)
            except OSError:
                raise ReaderFailure(CODE_WRITER_FAILED)

    # ------------------------------------------------------------------
    # operator source-gap reset (D1: the ONLY epoch-transition path apart
    # from first activation; run as sbox-jr with the service STOPPED)
    # ------------------------------------------------------------------

    def reset_from_now(self):
        """`sbox-journal-reader reset --from-now` (runbook: systemctl stop
        singbox-journal-reader first; root invokes via runuser -u sbox-jr).
        Re-validates state through the C2 table and refuses unless
        settled/consistent; then performs the epoch transition atomically:
        epoch+1, boundary=SOURCE_GAP, seq PRESERVED, source = a freshly
        captured tail anchor (or the durable since fallback). No other
        code path ever resets a source position."""
        self._durably(state.clean_scratch, self.state_dir, self.out_dir)
        committed, ok = state.load_committed(self.state_dir)
        if not ok or committed is None:
            raise ReaderFailure(CODE_RESET_REFUSED)
        pending, pok = state.load_pending(self.state_dir)
        if not pok:
            raise ReaderFailure(CODE_RESET_REFUSED)
        seqs = state.durable_ev_seqs(self.out_dir)
        row, action = state.evaluate_recovery(committed, pending, seqs,
                                              self.out_dir)
        if action == "repoll" and pending is not None:
            # Rows 3/4 settle cleanly (no durable file was ever visible
            # for that seq), so a reset may proceed afterwards.
            self._durably(state.remove_pending, self.state_dir)
            pending = None
            action = "start"
        if action != "start" or pending is not None:
            # Anything still in flight or unsettled must be recovered by a
            # normal run first -- a reset must never swallow an
            # unexported-but-durable batch.
            raise ReaderFailure(CODE_RESET_REFUSED)
        anchor = self._capture_tail_anchor()
        self._durably(
            state.write_committed,
            self.state_dir,
            state.make_committed(committed["seq"], committed["epoch"] + 1,
                                 "SOURCE_GAP", anchor),
            self.run_id, self._gate("reset_commit"))
        return True

    # ------------------------------------------------------------------
    # service loop
    # ------------------------------------------------------------------

    def run_forever(self):
        self.startup()
        while True:
            self.run_cycle()
            time.sleep(WINDOW_SECONDS)


def _entry_ts(entry):
    """Journal-clock ONLY: __REALTIME_TIMESTAMP with
    _SOURCE_REALTIME_TIMESTAMP fallback (microseconds). In-line text
    timestamps are never trusted or propagated (v1 §4.1)."""
    for field in ("__REALTIME_TIMESTAMP", "_SOURCE_REALTIME_TIMESTAMP"):
        raw = entry.get(field)
        if isinstance(raw, bool):
            continue
        if isinstance(raw, str) and raw.isdigit():
            return int(raw) / 1_000_000.0
        if isinstance(raw, int) and raw > 0:
            return raw / 1_000_000.0
    return None


class _Batch:
    """Per-window aggregation. The ONLY evidence that leaves it is the
    closed-schema §5.2/v5 record set -- the original line is dropped by
    construction, never redacted after the fact."""

    def __init__(self):
        self.lines = 0
        self.processed = 0
        self.pfail = 0
        self.eligible = 0
        self.info_dropped = 0
        self.nomatch_dropped = 0
        self.priority_unusable = 0
        self.limited = 0
        self.cursor_invalid = False
        self.last_cursor = None
        self.groups = {}   # key -> [first_ts, last_ts, count]
        self.fps = set()
        self.final_rc = None

    def absorb(self, decision, ts, reader):
        if decision["disposition"] == "drop":
            if decision["counter"] == DROP_INFO:
                self.info_dropped += 1
            elif decision["counter"] == DROP_NOMATCH:
                self.nomatch_dropped += 1
                if decision["priority_unusable"]:
                    self.priority_unusable += 1
            return
        self.eligible += 1
        cls = decision["cls"]
        proto = decision["proto"]
        port = decision["port"]
        dcls = decision["dcls"]
        fp = None
        if cls is None:
            cls = "other"
            template = fingerprint.build_template(decision["text"])
            if fingerprint.residual_unsafe(template):
                # R4 defense-in-depth fold: never hash questionable text.
                fp = None
                self.limited += 1
            else:
                fp = fingerprint.fingerprint(reader._fingerprint_key(),
                                             template)
                if fp not in self.fps:
                    if len(self.fps) >= MAX_FP_PER_WINDOW:
                        # Template-flood fold: everything past the bound
                        # becomes counted class-level records, and neither
                        # exchange size nor DB cardinality is attackable
                        # by a storm of novel formats.
                        fp = None
                        proto = "OTHER"
                        port = None
                        dcls = None
                        self.limited += 1
                    else:
                        self.fps.add(fp)
        key = (cls, proto, port or 0, dcls or "", fp or "")
        group = self.groups.get(key)
        if group is None:
            self.groups[key] = [ts, ts, 1]
        else:
            if ts < group[0]:
                group[0] = ts
            if ts > group[1]:
                group[1] = ts
            group[2] += 1

    def exchange_body(self, seq, run_id, pending):
        # Records FIRST: deterministic overflow folding bumps `limited`,
        # and the header counters must describe the file as written.
        records = self._records()
        header = {"t": "h", "v": FORMAT_VERSION, "cv": CLASSIFIER_VERSION,
                  "seq": seq, "run": run_id, "epoch": pending["epoch"],
                  "boundary": pending["boundary"], "lines": self.lines,
                  "eligible": self.eligible,
                  "info_dropped": self.info_dropped,
                  "nomatch_dropped": self.nomatch_dropped,
                  "priority_unusable": self.priority_unusable,
                  "pfail": self.pfail, "limited": self.limited}
        if not validate_header(header):
            raise ReaderFailure(CODE_WRITER_FAILED)
        out = [json.dumps(header, separators=(",", ":"), sort_keys=True)]
        for record in records:
            if not validate_event(record):
                raise ReaderFailure(CODE_WRITER_FAILED)
            out.append(json.dumps(record, separators=(",", ":"),
                                  sort_keys=True))
        return "\n".join(out) + "\n"

    def _records(self):
        rows = [
            {"t": "e", "ts": group[0], "cls": key[0], "proto": key[1],
             "port": key[2] or None, "dcls": key[3] or None,
             "fp": key[4] or None, "n": group[2]}
            for key, group in self.groups.items()
        ]
        if len(rows) <= MAX_RECORDS_PER_FILE:
            return rows
        # Deterministic overflow folding (v1 §6.2): counts ALWAYS survive;
        # detail is reduced to class level, never dropped silently.
        # MAX-|CLASSES| kept + at most |CLASSES| fold rows keeps the file
        # within the hard cap.
        rows.sort(key=lambda r: (-r["n"], r["cls"], r["proto"],
                                 r["port"] or 0, r["dcls"] or "",
                                 r["fp"] or ""))
        keep = rows[:MAX_RECORDS_PER_FILE - len(CLASSES)]
        fold = {}
        for row in rows[MAX_RECORDS_PER_FILE - len(CLASSES):]:
            self.limited += 1
            bucket = fold.setdefault(row["cls"], {
                "t": "e", "ts": row["ts"], "cls": row["cls"],
                "proto": "OTHER", "port": None, "dcls": None, "fp": None,
                "n": 0})
            if row["ts"] < bucket["ts"]:
                bucket["ts"] = row["ts"]
            bucket["n"] += row["n"]
        return keep + [fold[cls] for cls in sorted(fold)]


def main(argv=None):
    """Production entry: run the service loop, or the reviewed operator
    reset. Exit rc: 0 normal stop, 1 fail-stop with ONE sanitized code."""
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        reader = Reader()
    except ReaderFailure as failure:
        sys.stderr.write("[sbjr] failure=%s\n" % failure.code)
        return 1
    if argv == ["reset", "--from-now"]:
        try:
            reader.reset_from_now()
        except ReaderFailure as failure:
            sys.stderr.write("[sbjr] failure=%s\n" % failure.code)
            return 1
        sys.stderr.write("[sbjr] reset=ok\n")
        return 0
    if argv:
        sys.stderr.write("[sbjr] failure=usage\n")
        return 1
    try:
        reader.run_forever()
    except ReaderFailure as failure:
        sys.stderr.write("[sbjr] failure=%s\n" % failure.code)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
