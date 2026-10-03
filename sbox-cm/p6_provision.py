#!/usr/bin/env python3
"""Root-only P6B2 device lifecycle worker. No bundle/credential response.

The root-only desired-state ledger precedes registry publication. Retried
operations reconcile the same identity/key; revoked slots remain tombstones.
config.lock (owned by sbox-cm-ops) orders this worker with Client mutations.
provision.lock orders independent invocations, and the registry's shared /
exclusive lock fences live authentication through the P6B evidence commit.
No operation changes remote-probes.sqlite3 or proxy credentials.
"""
from contextlib import contextmanager
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import re
import secrets
import ssl
import stat
import sys
import tempfile
import threading
import time
from urllib.parse import urlsplit

MAX_RECORDS = 4096             # permanent idempotency/revocation tombstones
MAX_STATE_BYTES = 4 * 1024 * 1024
MAX_IDENTITIES = 64             # includes operator-managed identities
MAX_CONFIRMATIONS = 64          # bounded retirement work per retry
INGEST_PATH = '/api/v1/remote-probes/ingest'
NAME = re.compile(r'\A[A-Za-z0-9][A-Za-z0-9._-]{0,31}\Z')
IDEMPOTENCY = re.compile(r'\A[A-Za-z0-9._:-]{16,128}\Z')
HEX32 = re.compile(r'\A[0-9a-f]{32}\Z')
HEX64 = re.compile(r'\A[0-9a-f]{64}\Z')
PROBE = re.compile(r'\A[a-z0-9-]{1,64}\Z')
LABEL = re.compile(r'\A[ -~]{1,64}\Z')
KEYFILE = re.compile(r'\A[a-z0-9][a-z0-9._-]{0,127}\Z')
ROW_KEYS = {'name', 'device', 'client_generation', 'enrollment', 'probe_id',
            'secret', 'site_label', 'path_label', 'desired', 'verified', 'verified_epoch'}


class ProvisionError(Exception):
    """Closed code only: never include request/credential/exception text."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def require(pattern, value):
    if type(value) is not str or not pattern.fullmatch(value):
        raise ProvisionError('E_P6_SCHEMA')
    return value


def encoded(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii') + b'\n'


def proof_headers(probe_id, key, raw=b'{}'):
    """Frozen HMAC challenge: intentionally invalid evidence, never accepted.

    invalid_body proves valid live authentication; unauthorized proves the
    retired secret failed authentication. All other results are unconfirmed.
    Tests cross-check this signature with the shared P6A verifier.
    """
    sent = str(int(time.time()))
    run = secrets.token_hex(16)
    message = ('p6-v1\nPOST\n%s\n%s\n%s\n%s\n1\n%s' %
               (INGEST_PATH, probe_id, sent, run, hashlib.sha256(raw).hexdigest()))
    return {'X-Remote-Probe-Id': probe_id, 'X-Remote-Probe-Sent-Epoch': sent,
            'X-Remote-Probe-Run': run, 'X-Remote-Probe-Seq': '1',
            'X-Remote-Probe-Signature': hmac.new(bytes.fromhex(key),
                message.encode('ascii'), hashlib.sha256).hexdigest(),
            'Content-Type': 'application/json', 'Content-Length': str(len(raw)),
            'Connection': 'close'}


def live_proof(port, row, active):
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=2)
    connected = None
    def abort():
        import socket
        if connected is not None:
            try:
                connected.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        connection.close()
    timer = threading.Timer(3, abort)
    timer.daemon = True
    try:
        timer.start()
        connection.connect()
        connected = connection.sock
        connection.request('POST', INGEST_PATH, body=b'{}',
                           headers=proof_headers(row['probe_id'], row['secret']))
        response = connection.getresponse()
        content = response.read(257)
        expected = (400, {'error': 'invalid_body'}) if active else (401, {'error': 'unauthorized'})
        return len(content) <= 256 and (response.status, json.loads(content)) == expected
    except (OSError, ValueError, http.client.HTTPException):
        return False
    finally:
        timer.cancel()
        connection.close()


class Provisioner:
    def __init__(self, state_dir='/var/lib/sbox-cm/p6',
                 config_dir='/etc/singbox-monitor', port=9191, *,
                 fixture=False, proof=None, fault=None):
        if os.name != 'posix' or os.geteuid() != 0:
            raise ProvisionError('E_P6_AUTHORITY')
        import grp
        self.gid = grp.getgrnam('sboxweb').gr_gid
        self.state_dir = os.path.abspath(state_dir)
        self.config_dir = os.path.abspath(config_dir)
        self.key_dir = os.path.join(self.config_dir, 'remote-probes.d')
        self.config = os.path.join(self.config_dir, 'remote-probes.json')
        self.gate = self.config + '.lock'
        self.state_path = os.path.join(self.state_dir, 'devices.json')
        self.port = port
        self.proof = proof or (lambda row, active: live_proof(port, row, active))
        self.fault = fault or (lambda phase: None)
        # Constructor-only fixture control. Production CLI never accepts paths,
        # ports, authority overrides, injected proof or injected failure hooks.
        for path in (self.config_dir, self.state_dir):
            if not fixture:
                self._ancestors(os.path.dirname(path))
            # Existing Monitor installation owns a root:root 0755 config
            # directory. Preserve it; P6 key subdirectory has its own stricter
            # root:sboxweb 0750 contract. Never chmod/chown unrelated config.
            if path == self.config_dir and os.path.lexists(path):
                st = os.lstat(path)
                if stat.S_ISDIR(st.st_mode) and (st.st_uid, st.st_gid,
                        stat.S_IMODE(st.st_mode)) == (0, 0, 0o755):
                    continue
            self._directory(path, 0o700 if path == self.state_dir else 0o750,
                            0 if path == self.state_dir else self.gid)

    def _ancestors(self, path):
        while True:
            st = os.lstat(path)
            if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
                raise ProvisionError('E_P6_AUTHORITY')
            parent = os.path.dirname(path)
            if parent == path:
                return
            path = parent

    def _directory(self, path, mode, gid):
        if not os.path.lexists(path):
            os.mkdir(path, mode)
            os.chown(path, 0, gid)
            os.chmod(path, mode)
            self._sync(os.path.dirname(path))
        st = os.lstat(path)
        if not stat.S_ISDIR(st.st_mode) or (st.st_uid, st.st_gid,
                stat.S_IMODE(st.st_mode)) != (0, gid, mode):
            raise ProvisionError('E_P6_AUTHORITY')

    @staticmethod
    def _sync(path):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _open(self, path, mode, gid, flags=os.O_RDONLY):
        before = os.lstat(path)
        if not stat.S_ISREG(before.st_mode):
            raise ProvisionError('E_P6_AUTHORITY')
        fd = os.open(path, flags | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            st = os.fstat(fd)
            after = os.lstat(path)
            if (st.st_dev, st.st_ino) != (before.st_dev, before.st_ino) or \
                    (st.st_dev, st.st_ino) != (after.st_dev, after.st_ino) or \
                    not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or \
                    (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) != (0, gid, mode):
                raise ProvisionError('E_P6_AUTHORITY')
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _read(self, path, mode, gid, limit):
        fd = self._open(path, mode, gid)
        try:
            parts, size = [], 0
            while size <= limit:
                chunk = os.read(fd, min(65536, limit + 1 - size))
                if not chunk:
                    break
                parts.append(chunk)
                size += len(chunk)
            if size > limit:
                raise ProvisionError('E_P6_CAPACITY')
            return b''.join(parts)
        finally:
            os.close(fd)

    def _write(self, path, raw, mode, gid):
        if os.path.lexists(path):
            fd = self._open(path, mode, gid)
            os.close(fd)
        temporary_fd, temporary = tempfile.mkstemp(prefix='.p6-', dir=os.path.dirname(path))
        try:
            os.fchown(temporary_fd, 0, gid)
            os.fchmod(temporary_fd, mode)
            view = memoryview(raw)
            while view:
                count = os.write(temporary_fd, view)
                if count <= 0:
                    raise OSError('incomplete write')
                view = view[count:]
            os.fsync(temporary_fd)
            os.close(temporary_fd)
            temporary_fd = None
            os.replace(temporary, path)
            self._sync(os.path.dirname(path))
        finally:
            if temporary_fd is not None:
                os.close(temporary_fd)
            if os.path.lexists(temporary):
                os.unlink(temporary)

    @contextmanager
    def _lock(self, path, mode, gid):
        import fcntl
        if not os.path.lexists(path):
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
            except FileExistsError:
                # Another first invocation won creation. Open/authority-check
                # the same anchor and acquire its flock; never replace it.
                pass
            else:
                try:
                    os.fchown(fd, 0, gid)
                    os.fchmod(fd, mode)
                    os.fsync(fd)
                finally:
                    os.close(fd)
                self._sync(os.path.dirname(path))
        fd = self._open(path, mode, gid)
        try:
            deadline = time.monotonic() + 5
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise ProvisionError('E_P6_BUSY') from None
                    time.sleep(0.01)
            yield
        finally:
            os.close(fd)

    def _binding(self):
        binding = json.loads(self._read(os.path.join(self.config_dir, 'p6-server.json'),
                                      0o600, 0, 4096))
        if type(binding) is not dict or set(binding) != {'v', 'server_id', 'ingest_url', 'certificate_sha256'} \
                or type(binding['v']) is not int or binding['v'] != 1:
            raise ProvisionError('E_P6_BINDING')
        require(HEX32, binding['server_id'])
        require(HEX64, binding['certificate_sha256'])
        if type(binding['ingest_url']) is not str or len(binding['ingest_url']) > 256 or \
                any(ord(char) <= 32 or ord(char) >= 127 for char in binding['ingest_url']):
            raise ProvisionError('E_P6_BINDING')
        try:
            url = urlsplit(binding['ingest_url'])
            address = ipaddress.ip_address(url.hostname)
            port = url.port
        except (ValueError, TypeError):
            raise ProvisionError('E_P6_BINDING') from None
        if url.scheme != 'https' or url.username or url.password or \
                url.path != INGEST_PATH or url.query or url.fragment or \
                port is None or not 1024 <= port <= 65535 or \
                address.is_loopback or address.is_unspecified or address.is_multicast:
            raise ProvisionError('E_P6_BINDING')
        path = os.path.join(self.config_dir, 'p6-server.pem')
        certificate = self._read(path, 0o640, self.gid, 32768).decode('ascii')
        if certificate.count('-----BEGIN CERTIFICATE-----') != 1 or \
                'PRIVATE KEY' in certificate:
            raise ProvisionError('E_P6_BINDING')
        der = ssl.PEM_cert_to_DER_cert(certificate)
        if hashlib.sha256(der).hexdigest() != binding['certificate_sha256']:
            raise ProvisionError('E_P6_BINDING')
        # Decode the already same-object/authority-checked public cert; only
        # root can replace this directory. No private key or trust-store writes.
        details = ssl._ssl._test_decode_cert(path)
        now = time.time()
        if not ssl.cert_time_to_seconds(details['notBefore']) <= now < \
                ssl.cert_time_to_seconds(details['notAfter']) or not any(
                    kind == 'IP Address' and ipaddress.ip_address(value) == address
                    for kind, value in details.get('subjectAltName', ())):
            raise ProvisionError('E_P6_BINDING')
        return binding

    def _load(self, binding=None):
        if not os.path.lexists(self.state_path):
            if binding is None:
                return None
            return {'v': 1, 'binding': binding, 'records': []}
        state = json.loads(self._read(self.state_path, 0o600, 0, MAX_STATE_BYTES))
        if type(state) is not dict or set(state) != {'v', 'binding', 'records'} or \
                type(state['v']) is not int or state['v'] != 1 or \
                type(state['records']) is not list or len(state['records']) > MAX_RECORDS:
            raise ProvisionError('E_P6_STATE')
        stored_binding = state['binding']
        if type(stored_binding) is not dict or set(stored_binding) != {
                'v', 'server_id', 'ingest_url', 'certificate_sha256'} or \
                type(stored_binding['v']) is not int or stored_binding['v'] != 1 or \
                type(stored_binding['ingest_url']) is not str or len(stored_binding['ingest_url']) > 256:
            raise ProvisionError('E_P6_STATE')
        require(HEX32, stored_binding['server_id'])
        require(HEX64, stored_binding['certificate_sha256'])
        if binding is not None and state['binding'] != binding:
            raise ProvisionError('E_P6_BINDING_CHANGED')
        probes, enrollments, slots = set(), set(), set()
        for row in state['records']:
            if type(row) is not dict or set(row) != ROW_KEYS:
                raise ProvisionError('E_P6_STATE')
            for field, pattern in (('name', NAME), ('device', NAME),
                    ('client_generation', HEX64), ('enrollment', HEX64),
                    ('probe_id', PROBE), ('secret', HEX64),
                    ('site_label', LABEL), ('path_label', LABEL)):
                require(pattern, row[field])
            slot = (row['name'], row['client_generation'], row['device'])
            if row['probe_id'] in probes or row['enrollment'] in enrollments or slot in slots or \
                    row['desired'] not in ('active', 'revoked') or \
                    row['verified'] not in ('pending', 'active', 'revoked') or \
                    (row['desired'] == 'revoked' and row['verified'] == 'active') or \
                    (row['verified'] == 'pending' and row['verified_epoch'] is not None) or \
                    (row['verified'] != 'pending' and (type(row['verified_epoch']) is not int or
                                                      row['verified_epoch'] < 0)):
                raise ProvisionError('E_P6_STATE')
            probes.add(row['probe_id']); enrollments.add(row['enrollment']); slots.add(slot)
        return state

    def _save(self, state):
        raw = encoded(state)
        if len(raw) > MAX_STATE_BYTES:
            raise ProvisionError('E_P6_CAPACITY')
        self._write(self.state_path, raw, 0o600, 0)

    def _clean_staging(self):
        # Atomic publication uses a reserved root-owned .p6-* namespace.
        # Reconcile interrupted staging only while provision.lock is held.
        # A bounded inventory prevents adversarial/corrupt directory scans.
        for directory in (self.state_dir, self.config_dir, self.key_dir):
            if not os.path.lexists(directory):
                continue
            st = os.lstat(directory)
            expected = {(0, 0, 0o700)} if directory == self.state_dir else {(0, self.gid, 0o750)}
            if directory == self.config_dir:
                expected.add((0, 0, 0o755))
            if not stat.S_ISDIR(st.st_mode) or (st.st_uid, st.st_gid,
                    stat.S_IMODE(st.st_mode)) not in expected:
                raise ProvisionError('E_P6_AUTHORITY')
            entries = []
            with os.scandir(directory) as stream:
                for entry in stream:
                    if len(entries) >= MAX_RECORDS * 2 + 64:
                        raise ProvisionError('E_P6_CAPACITY')
                    entries.append(entry)
            for entry in entries:
                if not entry.name.startswith('.p6-'):
                    continue
                st = os.lstat(entry.path)
                mode, gid = stat.S_IMODE(st.st_mode), st.st_gid
                if mode not in (0o600, 0o640) or gid not in (0, self.gid):
                    raise ProvisionError('E_P6_AUTHORITY')
                fd = self._open(entry.path, mode, gid)
                os.close(fd)
                os.unlink(entry.path)
                self._sync(directory)

    def _registry(self):
        if not os.path.lexists(self.config):
            return []
        registry = json.loads(self._read(self.config, 0o640, self.gid, 256 * 1024))
        if type(registry) is not dict or set(registry) != {'v', 'probes'} or \
                type(registry['v']) is not int or registry['v'] != 1 or \
                type(registry['probes']) is not list or len(registry['probes']) > MAX_IDENTITIES:
            raise ProvisionError('E_P6_REGISTRY')
        seen = set()
        for row in registry['probes']:
            if type(row) is not dict or set(row) != {'probe_id', 'enabled', 'site_label', 'path_label', 'key_file'}:
                raise ProvisionError('E_P6_REGISTRY')
            for field, pattern in (('probe_id', PROBE), ('site_label', LABEL),
                                   ('path_label', LABEL), ('key_file', KEYFILE)):
                require(pattern, row[field])
            if row['probe_id'] in seen or type(row['enabled']) is not bool:
                raise ProvisionError('E_P6_REGISTRY')
            seen.add(row['probe_id'])
        return registry['probes']

    def _publish(self, state):
        self._directory(self.key_dir, 0o750, self.gid)
        with self._lock(self.gate, 0o640, self.gid):
            own = {row['probe_id'] for row in state['records']}
            existing = self._registry()
            by_id = {row['probe_id']: row for row in existing}
            rows = [row for row in existing if row['probe_id'] not in own]
            for row in state['records']:
                expected = {'probe_id': row['probe_id'], 'enabled': True,
                            'site_label': row['site_label'], 'path_label': row['path_label'],
                            'key_file': row['probe_id'] + '.key'}
                if row['probe_id'] in by_id and by_id[row['probe_id']] != expected:
                    raise ProvisionError('E_P6_REGISTRY_CHANGED')
                if row['desired'] == 'active' and row['verified'] == 'active' and row['probe_id'] not in by_id:
                    raise ProvisionError('E_P6_REGISTRY_CHANGED')
                if row['desired'] == 'active':
                    path = os.path.join(self.key_dir, row['probe_id'] + '.key')
                    raw = (row['secret'] + '\n').encode('ascii')
                    if os.path.lexists(path):
                        if self._read(path, 0o640, self.gid, 4096) != raw:
                            raise ProvisionError('E_P6_KEY_CHANGED')
                    else:
                        self._write(path, raw, 0o640, self.gid)
                    rows.append(expected)
            if len(rows) > MAX_IDENTITIES:
                raise ProvisionError('E_P6_CAPACITY')
            self.fault('keys_durable')
            self._write(self.config, encoded({'v': 1, 'probes': rows}), 0o640, self.gid)
            self.fault('registry_durable')
        # At exclusive-lock release, prior authenticated ingest has completed
        # and every subsequent ingest reloads the new authentication authority.

    def _confirm(self, state, rows):
        for row in rows:
            active = row['desired'] == 'active'
            if not self.proof(row, active):
                raise ProvisionError('E_P6_LIVE_UNCONFIRMED')
            self.fault('live_confirmed')
            row['verified'] = row['desired']
            row['verified_epoch'] = int(time.time())
        # One durable checkpoint per bounded batch, not a ledger rewrite for
        # every historical record. A crash before this checkpoint simply
        # repeats proof; it never restores an authentication identity.
        self._save(state)
        for row in rows:
            active = row['desired'] == 'active'
            if not active:
                path = os.path.join(self.key_dir, row['probe_id'] + '.key')
                if os.path.lexists(path):
                    fd = self._open(path, 0o640, self.gid)
                    os.close(fd)
                    os.unlink(path)
                    self._sync(self.key_dir)

    @staticmethod
    def public(state, row):
        return {field: row[field] for field in ('name', 'device', 'probe_id', 'desired', 'verified', 'verified_epoch', 'site_label', 'path_label')} | {
            'server_id': state['binding']['server_id'],
            'certificate_sha256': state['binding']['certificate_sha256'],
            'ingest_url': state['binding']['ingest_url']}

    def enroll(self, name, device, generation, idempotency_key, site_label, path_label):
        for pattern, value in ((NAME, name), (NAME, device), (HEX64, generation),
                (IDEMPOTENCY, idempotency_key), (LABEL, site_label), (LABEL, path_label)):
            require(pattern, value)
        with self._lock(os.path.join(self.state_dir, 'provision.lock'), 0o600, 0):
            self._clean_staging()
            binding = self._binding()
            state = self._load(binding)
            enrollment = hashlib.sha256(idempotency_key.encode('ascii')).hexdigest()
            row = next((r for r in state['records'] if r['enrollment'] == enrollment), None)
            semantic = (name, device, generation, site_label, path_label)
            if row is not None:
                if tuple(row[k] for k in ('name', 'device', 'client_generation', 'site_label', 'path_label')) != semantic:
                    raise ProvisionError('E_P6_IDEMPOTENCY_CONFLICT')
            else:
                slot = next((r for r in state['records'] if (r['name'], r['device'], r['client_generation']) ==
                             (name, device, generation)), None)
                if slot is not None:
                    raise ProvisionError('E_P6_DEVICE_EXISTS')
                if len(state['records']) >= MAX_RECORDS:
                    raise ProvisionError('E_P6_CAPACITY')
                active = sum(r['desired'] == 'active' for r in state['records'])
                own = {r['probe_id'] for r in state['records']}
                registry = self._registry()
                if active + sum(r['probe_id'] not in own for r in registry) >= MAX_IDENTITIES:
                    raise ProvisionError('E_P6_CAPACITY')
                probe = 'p6-' + secrets.token_hex(16)
                if probe in own or any(r['probe_id'] == probe for r in registry) or \
                        os.path.lexists(os.path.join(self.key_dir, probe + '.key')):
                    raise ProvisionError('E_P6_IDENTITY_COLLISION')
                row = dict(zip(('name', 'device', 'client_generation', 'site_label', 'path_label'), semantic))
                row.update(enrollment=enrollment, probe_id=probe, secret=secrets.token_hex(32),
                           desired='active', verified='pending', verified_epoch=None)
                state['records'].append(row)
                self._save(state)
                self.fault('intent_durable')
            # Replaying a revoked enrollment reconciles revocation; never revive.
            self._publish(state)
            self._confirm(state, [row])
            return self.public(state, row)

    def revoke(self, name, device=None, generation=None, probe_id=None):
        require(NAME, name)
        if device is not None:
            require(NAME, device)
        if generation is not None:
            require(HEX64, generation)
        if probe_id is not None:
            require(PROBE, probe_id)
        with self._lock(os.path.join(self.state_dir, 'provision.lock'), 0o600, 0):
            self._clean_staging()
            state = self._load()
            if state is None:
                if probe_id is not None:
                    raise ProvisionError('E_P6_NOT_ENROLLED')
                return {'revoked': True, 'count': 0}
            rows = [r for r in state['records'] if r['name'] == name and
                    (device is None or r['device'] == device) and
                    (generation is None or r['client_generation'] == generation) and
                    (probe_id is None or r['probe_id'] == probe_id)]
            if probe_id is not None and not rows:
                raise ProvisionError('E_P6_NOT_ENROLLED')
            for row in rows:
                if row['desired'] != 'revoked':
                    row.update(desired='revoked', verified='pending', verified_epoch=None)
            self._save(state)
            self.fault('intent_durable')
            self._publish(state)
            pending = [row for row in rows if row['verified'] == 'pending']
            confirming = pending[:MAX_CONFIRMATIONS]
            if not pending and rows:
                # Already confirmed tombstones cannot be republished as live
                # identities. Fresh proof of the selected device/retirement
                # representative still checks the running Monitor on retry.
                confirming = rows[-1:]
            self._confirm(state, confirming)
            if len(pending) > MAX_CONFIRMATIONS:
                raise ProvisionError('E_P6_CONFIRM_PENDING')
            return {'revoked': True, 'count': len(rows)}

    def listing(self, name, cursor=None):
        require(NAME, name)
        if cursor is not None:
            require(PROBE, cursor)
        with self._lock(os.path.join(self.state_dir, 'provision.lock'), 0o600, 0):
            state = self._load()
            rows = [] if state is None else sorted((row for row in state['records']
                    if row['name'] == name and (cursor is None or row['probe_id'] > cursor)),
                    key=lambda row: row['probe_id'])
            page = rows[:64]
            # Every response remains comfortably below the existing 64-KiB
            # RPC frame cap even after lifetime tombstones accumulate.
            return {'devices': [self.public(state, row) for row in page],
                    'next_cursor': page[-1]['probe_id'] if len(rows) > 64 else None}

    def export_material(self, name, device, generation):
        """Fresh sensitive read for one live device of the current Client.

        Caller holds canonical config.lock through YAML rendering and this
        read. Never enroll, rotate, reconcile, revive or modify the ledger.
        provision.lock orders export with revocation and identity installation.
        """
        for pattern, value in ((NAME, name), (NAME, device), (HEX64, generation)):
            require(pattern, value)
        with self._lock(os.path.join(self.state_dir, 'provision.lock'), 0o600, 0):
            binding = self._binding()
            state = self._load(binding)
            row = next((row for row in state['records'] if (row['name'], row['device'],
                        row['client_generation']) == (name, device, generation)), None)
            if row is None:
                raise ProvisionError('E_P6_NOT_ENROLLED')
            if row['desired'] != 'active' or row['verified'] != 'active':
                raise ProvisionError('E_P6_REVOKED')
            expected = {'probe_id': row['probe_id'], 'enabled': True,
                        'site_label': row['site_label'], 'path_label': row['path_label'],
                        'key_file': row['probe_id'] + '.key'}
            if next((entry for entry in self._registry() if entry['probe_id'] == row['probe_id']), None) != expected:
                raise ProvisionError('E_P6_REGISTRY_CHANGED')
            if self._read(os.path.join(self.key_dir, expected['key_file']), 0o640, self.gid, 128) != \
                    (row['secret'] + '\n').encode('ascii'):
                raise ProvisionError('E_P6_KEY_CHANGED')
            if not self.proof(row, True):
                raise ProvisionError('E_P6_LIVE_UNCONFIRMED')
            certificate = self._read(os.path.join(self.config_dir, 'p6-server.pem'),
                                     0o640, self.gid, 16384).decode('ascii')
            if hashlib.sha256(ssl.PEM_cert_to_DER_cert(certificate)).hexdigest() != binding['certificate_sha256']:
                raise ProvisionError('E_P6_BINDING')
            return {'binding': binding, 'probe_id': row['probe_id'],
                    'secret': row['secret'], 'certificate': certificate,
                    'site_label': row['site_label'], 'path_label': row['path_label']}

    def resume(self, name, device, generation):
        """Explicit recovery after the browser loses an enrollment key.

        Reconcile only an existing current-generation live intent. No new
        identity, changed labels/key, or revoked-intent resurrection is allowed.
        """
        for pattern, value in ((NAME, name), (NAME, device), (HEX64, generation)):
            require(pattern, value)
        with self._lock(os.path.join(self.state_dir, 'provision.lock'), 0o600, 0):
            state = self._load(self._binding())
            row = next((row for row in state['records'] if (row['name'], row['device'],
                        row['client_generation']) == (name, device, generation)), None)
            if row is None:
                raise ProvisionError('E_P6_NOT_ENROLLED')
            if row['desired'] != 'active':
                raise ProvisionError('E_P6_REVOKED')
            self._publish(state)
            self._confirm(state, [row])
            return self.public(state, row)


def main():
    try:
        if len(sys.argv) != 2 or sys.argv[1] not in ('enroll', 'revoke', 'retire', 'list', 'resume'):
            raise ProvisionError('E_P6_SCHEMA')
        op = sys.argv[1]
        raw = sys.stdin.buffer.read(8193)
        if len(raw) > 8192:
            raise ProvisionError('E_P6_SCHEMA')
        args = json.loads(raw)
        allowed = {'name', 'request_id', 'actor'}
        allowed |= {'device', 'client_generation', 'idempotency_key', 'site_label', 'path_label'} if op == 'enroll' else set()
        allowed |= {'device', 'probe_id'} if op == 'revoke' else set()
        allowed |= {'client_generation'} if op == 'retire' else set()
        allowed |= {'cursor'} if op == 'list' else set()
        allowed |= {'device', 'client_generation'} if op == 'resume' else set()
        if type(args) is not dict or not set(args) <= allowed:
            raise ProvisionError('E_P6_SCHEMA')
        if os.environ.get('SBOX_CM_TEST_SANDBOX') == '1':
            worker = Provisioner(os.environ['SB_P6_STATE_DIR'], os.environ['SB_P6_CONFIG_DIR'],
                                 int(os.environ['SB_P6_MONITOR_PORT']), fixture=True)
        else:
            worker = Provisioner()
        if op == 'enroll':
            result = worker.enroll(*(args[field] for field in ('name', 'device', 'client_generation',
                                   'idempotency_key', 'site_label', 'path_label')))
        elif op in ('revoke', 'retire'):
            result = worker.revoke(args['name'], args.get('device'), args.get('client_generation'), args.get('probe_id'))
        elif op == 'resume':
            result = worker.resume(args['name'], args['device'], args['client_generation'])
        else:
            result = worker.listing(args['name'], args.get('cursor'))
        response = {'ok': True, 'data': result}
    except ProvisionError as exc:
        response = {'ok': False, 'code': exc.code}
    except (OSError, ValueError, TypeError, KeyError, ssl.SSLError):
        response = {'ok': False, 'code': 'E_P6_UNAVAILABLE'}
    sys.stdout.buffer.write(encoded(response))


if __name__ == '__main__':
    main()
