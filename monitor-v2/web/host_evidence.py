"""Bounded server-local facts for issue #33; no classifier/control dependency."""
import hashlib
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import threading
import time
import uuid

CADENCE = 10
RETENTION = 7 * 86400
MAX_ROWS = RETENTION // CADENCE
READ_LIMIT = 1024
MAX_GAP = 25
STATES = frozenset(('active', 'inactive', 'failed', 'activating',
                    'deactivating', 'reloading', 'maintenance', 'refreshing'))
RESOURCES = ('cpu_percent', 'memory_percent', 'load_1m', 'disk_percent',
             'fd_percent', 'conntrack_percent')
FIELDS = ('epoch', 'run', 'boot', 'service_state', 'pid', 'restarts',
          'start_us') + RESOURCES
DDL = '''CREATE TABLE samples (
 id INTEGER PRIMARY KEY, epoch REAL NOT NULL CHECK(epoch>=0),
 run TEXT NOT NULL, boot TEXT, service_state TEXT,
 pid INTEGER, restarts INTEGER, start_us INTEGER,
 cpu_percent REAL, memory_percent REAL, load_1m REAL,
 disk_percent REAL, fd_percent REAL, conntrack_percent REAL)'''


def number(value, ceiling=9007199254740991):
    return type(value) in (int, float) and 0 <= value <= ceiling and math.isfinite(value)


def valid(row):
    if type(row) is not dict or set(row) != set(FIELDS):
        return False
    if not number(row['epoch']) or type(row['run']) is not str or not re.fullmatch('[a-f0-9]{32}', row['run']):
        return False
    if row['boot'] is not None and (type(row['boot']) is not str or not re.fullmatch('[a-f0-9]{64}', row['boot'])):
        return False
    if row['service_state'] is None:
        if any(row[k] is not None for k in ('pid', 'restarts', 'start_us')):
            return False
    elif type(row['service_state']) is not str or row['service_state'] not in STATES:
        return False
    else:
        if any(type(row[k]) is not int or not number(row[k],
            2147483647 if k == 'pid' else 4294967295 if k == 'restarts' else 9007199254740991)
            for k in ('pid', 'restarts', 'start_us')):
            return False
    return all(row[k] is None or number(row[k], 65536 if k == 'load_1m' else 100) for k in RESOURCES)


def bounded_text(path, limit=16384):
    with open(path, 'rb') as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError('oversize')
    return raw.decode('ascii', errors='strict')


class HostReader:
    """Only fixed /proc paths, statvfs(state root), fixed systemctl show argv.

    No config, journal, environment, command line, network or privileged RPC.
    CPU is a delta over consecutive samples; the first observation is unknown.
    """
    def __init__(self, data_dir, proc_root='/proc', runner=subprocess.run):
        self.data_dir = data_dir
        self.proc = Path(proc_root)
        self.runner = runner
        self.previous_cpu = None

    def sample(self, epoch, run):
        row = dict.fromkeys(FIELDS)
        row.update(epoch=epoch, run=run)
        try:
            boot = bounded_text(self.proc/'sys/kernel/random/boot_id', 64).strip()
            if re.fullmatch('[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', boot):
                row['boot'] = hashlib.sha256(boot.encode('ascii')).hexdigest()
        except (OSError, ValueError, UnicodeError):
            pass
        try:
            # Fixed unit and properties. No service lifecycle operation exists.
            result = self.runner(['/usr/bin/systemctl', 'show', 'sing-box.service', '--no-pager',
                '--property=ActiveState,MainPID,NRestarts,ExecMainStartTimestampMonotonic'],
                capture_output=True, timeout=1, check=False)
            if result.returncode == 0 and len(result.stdout) <= 4096:
                pairs = [line.split('=', 1) for line in result.stdout.decode('ascii').splitlines()]
                props = dict(pairs)
                if len(pairs) == 4 and set(props) == {'ActiveState', 'MainPID', 'NRestarts', 'ExecMainStartTimestampMonotonic'}:
                    values = [props[k] for k in ('MainPID', 'NRestarts', 'ExecMainStartTimestampMonotonic')]
                    if props['ActiveState'] in STATES and all(re.fullmatch('[0-9]{1,16}', x) for x in values):
                        numbers = list(map(int, values))
                        if all(number(n, bound) for n, bound in zip(numbers, (2147483647, 4294967295, 9007199254740991))):
                            row.update(service_state=props['ActiveState'], pid=numbers[0],
                                       restarts=numbers[1], start_us=numbers[2])
        except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
            pass
        try:
            line = bounded_text(self.proc/'stat').splitlines()[0].split()
            if line[0] != 'cpu' or len(line) < 9:
                raise ValueError('cpu shape')
            ticks = [int(x) for x in line[1:9]]
            if any(x < 0 for x in ticks):
                raise ValueError('cpu counters')
            current = (row['boot'], epoch, sum(ticks), ticks[3] + ticks[4])
            prev = self.previous_cpu
            if prev and current[0] is not None and prev[0] == current[0] and 0 < epoch-prev[1] <= MAX_GAP:
                total, idle = current[2]-prev[2], current[3]-prev[3]
                if total > 0 and 0 <= idle <= total:
                    row['cpu_percent'] = 100.0 * (total-idle)/total
            self.previous_cpu = current
        except (OSError, ValueError, IndexError, UnicodeError):
            self.previous_cpu = None
        try:
            mem = {}
            for line in bounded_text(self.proc/'meminfo').splitlines():
                key, _, text = line.partition(':')
                if key in ('MemTotal', 'MemAvailable'):
                    value = text.split()
                    if len(value) != 2 or value[1] != 'kB':
                        raise ValueError('memory unit')
                    mem[key] = int(value[0])
            if mem['MemTotal'] > 0 and 0 <= mem['MemAvailable'] <= mem['MemTotal']:
                row['memory_percent'] = 100.0 * (1-mem['MemAvailable']/mem['MemTotal'])
        except (OSError, ValueError, KeyError, UnicodeError):
            pass
        try:
            load = float(bounded_text(self.proc/'loadavg', 512).split()[0])
            if number(load, 65536):
                row['load_1m'] = load
        except (OSError, ValueError, IndexError, UnicodeError):
            pass
        try:
            disk = os.statvfs(self.data_dir)
            if disk.f_blocks > 0 and 0 <= disk.f_bavail <= disk.f_blocks:
                row['disk_percent'] = 100.0 * (1-disk.f_bavail/disk.f_blocks)
        except (OSError, AttributeError):
            pass
        try:
            allocated, unused, maximum = map(int, bounded_text(self.proc/'sys/fs/file-nr', 512).split())
            used = allocated-unused
            if maximum > 0 and 0 <= used <= maximum:
                row['fd_percent'] = 100.0*used/maximum
        except (OSError, ValueError, UnicodeError):
            pass
        try:
            count = int(bounded_text(self.proc/'sys/net/netfilter/nf_conntrack_count', 64))
            maximum = int(bounded_text(self.proc/'sys/net/netfilter/nf_conntrack_max', 64))
            if maximum > 0 and 0 <= count <= maximum:
                row['conntrack_percent'] = 100.0*count/maximum
        except (OSError, ValueError, UnicodeError):
            pass
        return row


class HostStore:
    """Independent v1 store; History v5 and its rollback remain untouched.

    Owner-only directory/database, no link adoption, strict schema, bounded
    pages/rows/reads. It never creates or migrates an existing unknown database.
    """
    def __init__(self, data_dir, clock=time.time):
        self.root = Path(data_dir).absolute()/'host-evidence'
        self.path = self.root/'host.sqlite3'
        self.clock = clock
        self.lock = threading.RLock()
        self.conn = None

    @staticmethod
    def check_path(path, directory=False):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or (directory and not stat.S_ISDIR(info.st_mode)) or (not directory and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1)):
            raise ValueError('unsafe host store')
        if os.name == 'posix' and (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600)):
            raise ValueError('unsafe host ownership')

    def open(self):
        with self.lock:
            if self.conn is not None:
                return self
            # The application's existing owner-only state root is the boundary.
            self.check_path(self.root.parent, directory=True)
            try:
                self.root.mkdir(mode=0o700)
            except FileExistsError:
                pass
            self.check_path(self.root, directory=True)
            fresh = False
            try:
                descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
                os.close(descriptor)
                fresh = True
            except FileExistsError:
                pass
            self.check_path(self.path)
            # Existing unknown/hot-journal databases are inspected read-only
            # before opening a writer, so refusal cannot recover/mutate them.
            if self.path.stat().st_size > 16*1024*1024:
                raise ValueError('host storage oversized')
            conn = sqlite3.connect(self.path if fresh else self.path.as_uri()+'?mode=ro',
                                   uri=not fresh, timeout=1, check_same_thread=False)
            try:
                if fresh:
                    conn.execute('PRAGMA auto_vacuum=INCREMENTAL')
                    conn.execute(DDL)
                    conn.execute('CREATE INDEX sample_time ON samples(epoch)')
                    conn.execute('PRAGMA user_version=1')
                    conn.commit()
                if conn.execute('PRAGMA user_version').fetchone()[0] != 1:
                    raise ValueError('host schema unsupported')
                tables = conn.execute("SELECT name,sql FROM sqlite_master WHERE type='table'").fetchall()
                if tables != [('samples', DDL)]:
                    raise ValueError('host schema unsupported')
                objects = conn.execute("SELECT type,name FROM sqlite_master").fetchall()
                if set(objects) != {('table', 'samples'), ('index', 'sample_time')}:
                    raise ValueError('host objects unsupported')
                if conn.execute('PRAGMA page_size').fetchone()[0] != 4096:
                    raise ValueError('host page size unsupported')
                if conn.execute('PRAGMA page_count').fetchone()[0] > 4096:
                    raise ValueError('host storage oversized')
                if not fresh:
                    conn.close()
                    self.check_path(self.path)
                    conn = sqlite3.connect(self.path, timeout=1, check_same_thread=False)
                conn.execute('PRAGMA max_page_count=4096')
                conn.execute('PRAGMA journal_mode=DELETE')
                conn.execute('PRAGMA synchronous=FULL')
                self.conn = conn
            except BaseException:
                conn.close()
                raise
            return self

    def append(self, row):
        if not valid(row):
            raise ValueError('invalid host sample')
        with self.lock:
            if self.conn is None:
                raise ValueError('host store unavailable')
            with self.conn:
                self.conn.execute('DELETE FROM samples WHERE epoch<?', (max(0, self.clock()-RETENTION),))
                # Leave room for the new record, even after backward wall clock.
                self.conn.execute('DELETE FROM samples WHERE id IN (SELECT id FROM samples ORDER BY id DESC LIMIT -1 OFFSET ?)', (MAX_ROWS-1,))
                self.conn.execute('INSERT INTO samples('+','.join(FIELDS)+') VALUES('+','.join('?' for _ in FIELDS)+')', tuple(row[k] for k in FIELDS))
            self.conn.execute('PRAGMA incremental_vacuum(16)')

    def window(self, start, end):
        if not number(start) or not number(end) or start > end:
            raise ValueError('invalid host window')
        with self.lock:
            if self.conn is None:
                raise ValueError('host store unavailable')
            cutoff = max(0, self.clock()-RETENTION)
            rows = self.conn.execute('SELECT '+','.join(FIELDS)+' FROM samples WHERE epoch>=? AND epoch<=? ORDER BY epoch,id LIMIT ?', (max(start, cutoff), end, READ_LIMIT+1)).fetchall()
            samples = [dict(zip(FIELDS, values)) for values in rows[:READ_LIMIT]]
            if any(not valid(row) for row in samples):
                raise ValueError('invalid retained host sample')
            return summarize(samples, start, end, len(rows)>READ_LIMIT, cutoff)

    def close(self):
        with self.lock:
            if self.conn is not None:
                self.conn.close()
                self.conn = None


def summarize(rows, start, end, truncated, cutoff):
    service_rows = [r for r in rows if r['service_state'] is not None]
    service = dict(observations=len(service_rows), not_running_samples=0,
        automatic_restart_increments=0, process_changes_observed=0,
        counter_resets=0, incomparable_transitions=0)
    service['not_running_samples'] = sum(r['service_state'] not in ('active', 'reloading') for r in service_rows)
    gaps = 0
    for a, b in zip(rows, rows[1:]):
        comparable = (0 < b['epoch']-a['epoch'] <= MAX_GAP and a['run'] == b['run']
                      and a['boot'] is not None and a['boot'] == b['boot'])
        if not comparable:
            gaps += 1
        if not comparable or a['service_state'] is None or b['service_state'] is None:
            service['incomparable_transitions'] += 1
            continue
        delta = b['restarts']-a['restarts']
        if delta >= 0:
            service['automatic_restart_increments'] += delta
        else:
            service['counter_resets'] += 1
        if a['pid'] > 0 and b['pid'] > 0 and (a['pid'], a['start_us']) != (b['pid'], b['start_us']):
            service['process_changes_observed'] += 1
    complete = bool(rows and not truncated and start >= cutoff and
        rows[0]['epoch']-start <= MAX_GAP and end-rows[-1]['epoch'] <= MAX_GAP and gaps == 0)
    return dict(v=1, window=dict(start_epoch=start, end_epoch=end),
        availability='available' if complete else 'partial' if rows else 'no_records',
        sample_count=len(rows), first_sample_epoch=rows[0]['epoch'] if rows else None,
        last_sample_epoch=rows[-1]['epoch'] if rows else None,
        cadence_seconds=CADENCE, gaps=gaps, truncated=truncated,
        retention_cutoff_epoch=cutoff, service=service,
        resources={key: dict(observations=sum(r[key] is not None for r in rows),
            peak=max((r[key] for r in rows if r[key] is not None), default=None)) for key in RESOURCES})


class HostEvidence:
    def __init__(self, data_dir, clock=time.time, reader=None, store=None):
        self.clock = clock
        self.reader = reader or HostReader(data_dir)
        self.store = store or HostStore(data_dir, clock)
        self.run = uuid.uuid4().hex
        self.stop_event = threading.Event()
        self.thread = None
        self.collection_status = 'disabled'

    def start(self):
        if self.thread is not None:
            return
        try:
            self.store.open()
        except (OSError, ValueError, sqlite3.Error):
            self.collection_status = 'unavailable'
            return
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._loop, name='host-evidence', daemon=True)
        self.thread.start()

    def cycle(self):
        try:
            self.store.append(self.reader.sample(self.clock(), self.run))
            self.collection_status = 'recording'
        except Exception:  # isolated evidence plane; never escape into Monitor
            self.collection_status = 'unavailable'

    def _loop(self):
        while not self.stop_event.is_set():
            self.cycle()
            self.stop_event.wait(CADENCE)

    def incident(self, incident_id, start, end):
        try:
            result = self.store.window(start, end)
        except (OSError, ValueError, sqlite3.Error):
            result = summarize([], start, end, False, max(0, self.clock()-RETENTION))
            result['availability'] = 'unavailable'
        result['incident_id'] = incident_id
        result['collection_status'] = self.collection_status
        return result

    def stop(self):
        self.stop_event.set()
        if self.thread is not None:
            self.thread.join(timeout=3)
            if self.thread.is_alive():
                # Don't close an in-flight writer; it is daemon-isolated.
                return
            self.thread = None
        self.store.close()
        self.collection_status = 'disabled'
