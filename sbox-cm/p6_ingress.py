#!/usr/bin/env python3
"""Root-only, explicitly operated P6 identity and dedicated TLS ingress.

prepare never starts/enables a service or changes firewall rules. activate is
an independent operation. No environment path/authority overrides or automatic
identity rotation. Constructor-only fixtures bind loopback and random units.
"""
from contextlib import contextmanager
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time

_spec = importlib.util.spec_from_file_location('p6_provision', Path(__file__).with_name('p6_provision.py'))
p6 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(p6)
Error = p6.ProvisionError
SERVICE = 'sbox-p6-ingress.service'
TABLE = 'sbox_p6_ingress'


class Ingress:
    def __init__(self, *, fixture=False, config_dir='/etc/singbox-monitor',
                 state_dir='/var/lib/sbox-cm/p6', unit_dir='/etc/systemd/system',
                 runtime='/run/sbox-p6-ingress', service=SERVICE, table=TABLE,
                 listen=None, upstream=9191, fault=None):
        if not fixture and (config_dir, state_dir, unit_dir, runtime, service,
                table, listen, upstream) != ('/etc/singbox-monitor', '/var/lib/sbox-cm/p6',
                '/etc/systemd/system', '/run/sbox-p6-ingress', SERVICE, TABLE, None, 9191):
            raise Error('E_P6_AUTHORITY')
        self.fs = p6.Provisioner(state_dir, config_dir, fixture=fixture)
        self.root = Path(config_dir) / 'p6-ingress'
        self.fs._directory(str(self.root), 0o700, 0)
        self.identity = self.root / 'identity'
        self.config = self.root / 'nginx.conf'
        self.journal = self.root / 'activation.json'
        self.unit = Path(unit_dir) / service
        self.runtime = runtime
        self.service, self.table = service, table
        self.listen, self.upstream = listen, upstream
        self.fixture = fixture
        self.fault = fault or (lambda phase: None)
        if not fixture:
            self.fs._ancestors(unit_dir)
        if not re.fullmatch(r'[A-Za-z0-9_-]+\.service', service) or not re.fullmatch(r'[a-z0-9_]+', table):
            raise Error('E_P6_SCHEMA')
        # Paths are internal authority, never interpolated from browser input.
        for path in (str(self.root), str(self.unit), runtime):
            if not re.fullmatch(r'/[A-Za-z0-9/_.-]+', path):
                raise Error('E_P6_AUTHORITY')

    @contextmanager
    def locked(self):
        # Also orders publication against device enrollment / revocation.
        with self.fs._lock(os.path.join(self.fs.state_dir, 'provision.lock'), 0o600, 0):
            yield

    @staticmethod
    def command(args, *, data=None, check=True, timeout=15):
        # No credential-bearing arguments, environment or output. OpenSSL
        # private key is generated directly into a private root-only directory.
        env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}
        result = subprocess.run(args, input=data, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=timeout, env=env, umask=0o077)
        if check and result.returncode:
            raise Error('E_P6_INGRESS_COMMAND')
        return result

    def read(self, path, mode=0o600, gid=0, limit=65536):
        return self.fs._read(str(path), mode, gid, limit)

    def write(self, path, raw, mode=0o600, gid=0):
        self.fs._write(str(path), raw, mode, gid)

    def remove(self, path, mode=0o600):
        if os.path.lexists(path):
            self.read(path, mode)
            os.unlink(path)
            self.fs._sync(str(Path(path).parent))

    def _settings(self, address, port, firewall):
        try:
            ip = ipaddress.ip_address(address)
        except (ValueError, TypeError):
            raise Error('E_P6_BINDING') from None
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local or \
                type(port) is not int or not 1024 <= port <= 65535 or port == 9191 or firewall not in ('nft', 'none'):
            raise Error('E_P6_BINDING')
        host = '[' + str(ip) + ']' if ip.version == 6 else str(ip)
        return {'address': str(ip), 'port': port, 'firewall': firewall,
                'url': 'https://' + host + ':' + str(port) + p6.INGEST_PATH}

    def _identity(self):
        if not os.path.lexists(self.identity):
            raise Error('E_P6_NOT_PREPARED')
        self.fs._directory(str(self.identity), 0o700, 0)
        meta = json.loads(self.read(self.identity / 'metadata.json'))
        if type(meta) is not dict or set(meta) != {'v', 'settings', 'binding'} or meta['v'] != 1:
            raise Error('E_P6_BINDING')
        settings = meta['settings']
        if type(settings) is not dict or set(settings) != {'address', 'port', 'firewall', 'url'} or \
                settings != self._settings(settings['address'], settings['port'], settings['firewall']):
            raise Error('E_P6_BINDING')
        binding = meta['binding']
        if type(binding) is not dict or set(binding) != {'v', 'server_id', 'ingest_url', 'certificate_sha256'} or \
                type(binding['v']) is not int or binding['v'] != 1 or binding['ingest_url'] != settings['url']:
            raise Error('E_P6_BINDING')
        p6.require(p6.HEX32, binding['server_id'])
        p6.require(p6.HEX64, binding['certificate_sha256'])
        pem = self.read(self.identity / 'server.pem').decode('ascii')
        self.read(self.identity / 'server.key', limit=16384)
        if pem.count('-----BEGIN CERTIFICATE-----') != 1 or 'PRIVATE KEY' in pem or \
                hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest() != binding['certificate_sha256']:
            raise Error('E_P6_BINDING')
        details = ssl._ssl._test_decode_cert(str(self.identity / 'server.pem'))
        now = time.time()
        if not ssl.cert_time_to_seconds(details['notBefore']) <= now < ssl.cert_time_to_seconds(details['notAfter']) or \
                not any(kind == 'IP Address' and ipaddress.ip_address(value) == ipaddress.ip_address(settings['address'])
                        for kind, value in details.get('subjectAltName', ())):
            raise Error('E_P6_BINDING')
        pub_cert = self.command(['/usr/bin/openssl', 'x509', '-in', str(self.identity / 'server.pem'), '-pubkey', '-noout']).stdout
        pub_key = self.command(['/usr/bin/openssl', 'pkey', '-in', str(self.identity / 'server.key'), '-pubout']).stdout
        if pub_cert != pub_key:
            raise Error('E_P6_BINDING')
        self.command(['/usr/bin/openssl', 'verify', '-purpose', 'sslserver', '-CAfile',
                      str(self.identity / 'server.pem'), str(self.identity / 'server.pem')])
        return meta

    def _generate(self, settings):
        # Uncommitted stages never become authority. Clean only our root-owned
        # bounded namespace under the provision lock; no recursive deletion.
        stages = list(self.root.glob('.identity-*'))
        if len(stages) > 16:
            raise Error('E_P6_CAPACITY')
        for stage in stages:
            self.fs._directory(str(stage), 0o700, 0)
            children = list(stage.iterdir())
            if len(children) > 3 or any(x.name not in ('server.pem', 'server.key', 'metadata.json') for x in children):
                raise Error('E_P6_AUTHORITY')
            for child in children:
                self.remove(child)
            os.rmdir(stage)
        stage = Path(tempfile.mkdtemp(prefix='.identity-', dir=self.root))
        self.command(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-nodes',
                      '-days', '3650', '-subj', '/CN=P6 VPS', '-addext', 'subjectAltName=IP:' + settings['address'],
                      '-addext', 'basicConstraints=critical,CA:FALSE', '-addext', 'keyUsage=critical,digitalSignature,keyEncipherment',
                      '-addext', 'extendedKeyUsage=serverAuth', '-keyout', str(stage / 'server.key'),
                      '-out', str(stage / 'server.pem')], timeout=60)
        for name in ('server.pem', 'server.key'):
            os.chmod(stage / name, 0o600)
            fd = self.fs._open(str(stage / name), 0o600, 0)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(self.read(stage / 'server.pem').decode('ascii'))).hexdigest()
        meta = {'v': 1, 'settings': settings, 'binding': {'v': 1, 'server_id': secrets.token_hex(16),
                'ingest_url': settings['url'], 'certificate_sha256': pin}}
        self.write(stage / 'metadata.json', p6.encoded(meta))
        self.fs._sync(str(stage))
        os.rename(stage, self.identity)
        self.fs._sync(str(self.root))
        self.fault('identity_durable')
        return self._identity()

    def _publish_binding(self, meta):
        for path, raw, mode, gid in (
                (Path(self.fs.config_dir) / 'p6-server.pem', self.read(self.identity / 'server.pem'), 0o640, self.fs.gid),
                (Path(self.fs.config_dir) / 'p6-server.json', p6.encoded(meta['binding']), 0o600, 0)):
            if os.path.lexists(path):
                if self.read(path, mode, gid) != raw:
                    raise Error('E_P6_BINDING_CHANGED')
            else:
                self.write(path, raw, mode, gid)
            self.fault('binding_' + path.suffix[1:] + '_durable')
        if self.fs._binding() != meta['binding']:
            raise Error('E_P6_BINDING')

    def render(self, meta):
        address = self.listen or ('[::]' if ':' in meta['settings']['address'] else '0.0.0.0')
        return f'''# Managed P6 ingress only. nginx >= 1.18.0, TLS enabled.
worker_processes 1;
user nobody nogroup;
pid {self.runtime}/nginx.pid;
error_log /dev/null crit;
events {{ worker_connections 128; }}
http {{
    access_log off;
    client_body_temp_path {self.runtime}/body;
    proxy_temp_path {self.runtime}/proxy;
    limit_req_zone $binary_remote_addr zone=p6_peer:1m rate=20r/s;
    limit_req_zone $server_name zone=p6_global:1m rate=40r/s;
    limit_conn_zone $binary_remote_addr zone=p6_conn:1m;
    limit_conn_zone $server_name zone=p6_total:1m;
    server {{
        listen {address}:{meta['settings']['port']} ssl;
        server_name _;
        ssl_certificate {self.identity}/server.pem;
        ssl_certificate_key {self.identity}/server.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        client_max_body_size 16k;
        client_body_buffer_size 16k;
        client_header_buffer_size 1k;
        large_client_header_buffers 2 8k;
        client_header_timeout 5s;
        client_body_timeout 5s;
        send_timeout 5s;
        keepalive_timeout 0;
        reset_timedout_connection on;
        location = {p6.INGEST_PATH} {{
            if ($request_uri != "{p6.INGEST_PATH}") {{ return 404; }}
            if ($request_method != POST) {{ return 405; }}
            if ($server_protocol != "HTTP/1.1") {{ return 400; }}
            if ($http_transfer_encoding != "") {{ return 400; }}
            if ($http_content_length = "") {{ return 400; }}
            limit_req zone=p6_peer burst=40 nodelay;
            limit_req zone=p6_global burst=80 nodelay;
            limit_req_status 429;
            limit_conn p6_conn 12;
            limit_conn p6_total 32;
            limit_conn_status 429;
            proxy_pass http://127.0.0.1:{self.upstream};
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_request_buffering on;
            proxy_connect_timeout 2s;
            proxy_send_timeout 5s;
            proxy_read_timeout 5s;
            proxy_redirect off;
            proxy_next_upstream off;
        }}
        location / {{ return 404; }}
    }}
}}
'''.encode('ascii')

    def render_unit(self):
        # A narrowly selected root pre-start restores ONLY the owned nft table
        # after reboot. Normal nginx workers have no CAP_NET_ADMIN. It requires
        # a durable activation journal, so starting a merely prepared unit fails.
        firewall_pre = ''
        if os.path.lexists(self.identity / 'metadata.json'):
            meta = json.loads(self.read(self.identity / 'metadata.json'))
            if meta['settings']['firewall'] == 'nft':
                firewall_pre = 'ExecStartPre=+/usr/bin/python3 -I /usr/local/lib/sbox-cm/p6_ingress.py firewall-ensure\n'
        return f'''# Managed P6 dedicated ingress; never operates nginx.service.
[Unit]
Description=P6 machine TLS ingress
After=network.target
[Service]
Type=simple
RuntimeDirectory={Path(self.runtime).name}
RuntimeDirectoryMode=0755
{firewall_pre}ExecStartPre=/usr/sbin/nginx -t -p {self.runtime}/ -c {self.config}
ExecStart=/usr/sbin/nginx -p {self.runtime}/ -c {self.config} -g 'daemon off;'
KillSignal=SIGQUIT
TimeoutStopSec=10
Restart=on-failure
RestartSec=3
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths={self.runtime}
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=CAP_SETUID CAP_SETGID
LimitNOFILE=512
MemoryMax=128M
TasksMax=16
CPUQuota=50%
UMask=0077
[Install]
WantedBy=multi-user.target
'''.encode('ascii')

    def runtime_directory(self):
        # The runtime path belongs to this service, never a global nginx path.
        if not os.path.lexists(self.runtime):
            os.mkdir(self.runtime, 0o755)
        self.fs._directory(self.runtime, 0o755, 0)
        import pwd
        uid = pwd.getpwnam('nobody').pw_uid
        gid = pwd.getpwnam('nobody').pw_gid
        for name in ('body', 'proxy'):
            path = Path(self.runtime) / name
            if not os.path.lexists(path):
                os.mkdir(path, 0o700)
                os.chown(path, uid, gid)
            st = os.lstat(path)
            if not stat.S_ISDIR(st.st_mode) or (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) != (uid, gid, 0o700):
                raise Error('E_P6_AUTHORITY')

    def validate(self, meta):
        if self.read(self.config) != self.render(meta) or self.read(self.unit, 0o644) != self.render_unit():
            raise Error('E_P6_MANAGED_CHANGED')
        self.runtime_directory()
        version = self.command(['/usr/sbin/nginx', '-v']).stderr.decode('ascii')
        match = re.search(r'nginx/(\d+)\.(\d+)\.(\d+)', version)
        if not match or tuple(map(int, match.groups())) < (1, 18, 0):
            raise Error('E_P6_NGINX_VERSION')
        result = self.command(['/usr/sbin/nginx', '-t', '-p', self.runtime + '/', '-c', str(self.config)], check=False)
        if result.returncode:
            if self.fixture:
                # Fixture-only diagnostic: generated private paths, no headers,
                # keys or credentials. Production keeps the closed error code.
                sys.stderr.buffer.write(result.stderr)
            raise Error('E_P6_NGINX_CONFIG')
        self.command(['/usr/bin/systemd-analyze', 'verify', str(self.unit)])

    def _port_free(self, meta):
        family = socket.AF_INET6 if ':' in meta['settings']['address'] else socket.AF_INET
        host = self.listen or ('::' if family == socket.AF_INET6 else '0.0.0.0')
        with socket.socket(family) as sock:
            try:
                sock.bind((host, meta['settings']['port']))
            except OSError:
                raise Error('E_P6_PORT_OCCUPIED') from None

    def service_state(self):
        active = self.command(['/usr/bin/systemctl', 'is-active', self.service], check=False).stdout.strip() == b'active'
        enabled = self.command(['/usr/bin/systemctl', 'is-enabled', self.service], check=False).stdout.strip() == b'enabled'
        return active, enabled

    def prepare(self, address, port=38443, firewall='nft'):
        settings = self._settings(address, port, firewall)
        with self.locked():
            exists = os.path.lexists(self.identity)
            if not exists and any(os.path.lexists(Path(self.fs.config_dir) / name)
                                  for name in ('p6-server.json', 'p6-server.pem')):
                # Never take ownership of an operator-prepared binding/key.
                raise Error('E_P6_BINDING_CHANGED')
            if exists:
                meta = self._identity()
                if meta['settings'] != settings:
                    raise Error('E_P6_BINDING_CHANGED')
            else:
                if os.path.lexists(self.config) or os.path.lexists(self.unit):
                    raise Error('E_P6_MANAGED_CHANGED')
                self._port_free({'settings': settings})
                meta = self._generate(settings)
            self._publish_binding(meta)
            for path, raw, mode in ((self.config, self.render(meta), 0o600), (self.unit, self.render_unit(), 0o644)):
                if os.path.lexists(path):
                    if self.read(path, mode) != raw:
                        raise Error('E_P6_MANAGED_CHANGED')
                else:
                    self.write(path, raw, mode)
                self.fault('managed_' + path.suffix[1:] + '_durable')
            self.validate(meta)
            return dict(meta['binding'], prepared=True, activation='explicit',
                        firewall=settings['firewall'], external_reachability='unverified')

    def firewall_snapshot(self):
        # Missing and unavailable are different. A native JSON ruleset read
        # must succeed; EPERM/missing nft cannot masquerade as an absent table.
        raw = self.command(['/usr/sbin/nft', '-j', 'list', 'tables']).stdout
        tables = json.loads(raw)['nftables']
        exists = any(x.get('table', {}).get('family') == 'inet' and x.get('table', {}).get('name') == self.table for x in tables)
        if not exists:
            return None
        rules = json.loads(self.command(['/usr/sbin/nft', '-j', 'list', 'table', 'inet', self.table]).stdout)
        # Strip only volatile native handles/metainfo, keep every expression.
        def strip(value):
            if isinstance(value, dict):
                return {k: strip(v) for k, v in value.items() if k not in ('handle', 'metainfo')}
            if isinstance(value, list):
                return [strip(x) for x in value if not isinstance(x, dict) or 'metainfo' not in x]
            return value
        return hashlib.sha256(p6.encoded(strip(rules))).hexdigest()

    def firewall_add(self, meta):
        # An accept here does NOT override a drop in another base chain. This
        # is deliberately not a promise of host/cloud reachability. Never
        # flush/rewrite another firewall; report policy integration separately.
        text = f'''add table inet {self.table}
add chain inet {self.table} ingress {{ type filter hook input priority -5; policy accept; }}
add rule inet {self.table} ingress tcp dport {meta['settings']['port']} accept comment "P6 managed ingress"
'''
        self.command(['/usr/sbin/nft', '-c', '-f', '-'], data=text.encode('ascii'))
        self.command(['/usr/sbin/nft', '-f', '-'], data=text.encode('ascii'))

    def firewall_owned(self, meta):
        """Exact native semantic proof, including recovery after add/fsync death."""
        result = json.loads(self.command(['/usr/sbin/nft', '-j', 'list', 'table', 'inet', self.table]).stdout)
        rows = [{k: {a: b for a, b in v.items() if a != 'handle'} for k, v in row.items()}
                for row in result['nftables'] if 'metainfo' not in row]
        expected = [
            {'table': {'family': 'inet', 'name': self.table}},
            {'chain': {'family': 'inet', 'table': self.table, 'name': 'ingress',
                       'type': 'filter', 'hook': 'input', 'prio': -5, 'policy': 'accept'}},
            {'rule': {'family': 'inet', 'table': self.table, 'chain': 'ingress',
                      'expr': [{'match': {'op': '==', 'left': {'payload': {'protocol': 'tcp', 'field': 'dport'}},
                                         'right': meta['settings']['port']}}, {'accept': None}],
                      'comment': 'P6 managed ingress'}}]
        if rows != expected:
            raise Error('E_P6_FIREWALL_CHANGED')

    def firewall_ensure(self):
        # Internal systemd pre-start. The activating parent holds provision.lock
        # while awaiting this child; do not recursively acquire that same lock.
        # Every write is bounded to the exact journaled table, never global policy.
        meta = self._identity()
        journal = self._journal()
        if journal is None or journal['phase'] not in ('starting', 'active') or journal['firewall'] != 'nft':
            raise Error('E_P6_STATE')
        current = self.firewall_snapshot()
        if current is None:
            self.firewall_add(meta)
            current = self.firewall_snapshot()
        self.firewall_owned(meta)
        if journal['fingerprint'] is not None and journal['fingerprint'] != current:
            raise Error('E_P6_FIREWALL_CHANGED')
        journal['fingerprint'] = current
        self._save_journal(journal)
        return {'firewall_rule': 'managed', 'external_reachability': 'unverified'}

    def _journal(self):
        if not os.path.lexists(self.journal):
            return None
        obj = json.loads(self.read(self.journal))
        if type(obj) is not dict or set(obj) != {'v', 'phase', 'firewall', 'fingerprint'} or \
                type(obj['v']) is not int or obj['v'] != 1 or obj['phase'] not in ('starting', 'active', 'stopping') or \
                obj['firewall'] not in ('nft', 'none') or \
                (obj['fingerprint'] is not None and not p6.HEX64.fullmatch(obj['fingerprint'])):
            raise Error('E_P6_STATE')
        return obj

    def _save_journal(self, journal):
        self.write(self.journal, p6.encoded(journal))

    def _rollback(self, journal):
        # Disable/stop ONLY our verified dedicated unit. Identity, history,
        # registry, bindings and unrelated nginx/firewall are retained.
        self.command(['/usr/bin/systemctl', 'disable', '--now', self.service])
        if self.service_state() != (False, False):
            raise Error('E_P6_ROLLBACK')
        if journal['firewall'] == 'nft':
            current = self.firewall_snapshot()
            if current is not None:
                if journal['fingerprint'] is None:
                    self.firewall_owned(self._identity())
                elif current != journal['fingerprint']:
                    raise Error('E_P6_FIREWALL_CHANGED')
                self.command(['/usr/sbin/nft', 'delete', 'table', 'inet', self.table])
        self.remove(self.journal)

    def activate(self):
        with self.locked():
            meta = self._identity()
            self._publish_binding(meta)
            self.validate(meta)
            journal = self._journal()
            if journal:
                if journal['phase'] == 'active' and self.service_state() == (True, True):
                    if journal['firewall'] == 'nft' and self.firewall_snapshot() != journal['fingerprint']:
                        raise Error('E_P6_FIREWALL_CHANGED')
                    self._tls_probe(meta)
                    return {'active': True, 'external_reachability': 'unverified'}
                # An interrupted attempt is reconciled closed before retry.
                self._rollback(journal)
            elif self.service_state() != (False, False):
                raise Error('E_P6_MANAGED_CHANGED')
            self._port_free(meta)
            if meta['settings']['firewall'] == 'nft' and self.firewall_snapshot() is not None:
                raise Error('E_P6_FIREWALL_CHANGED')
            journal = {'v': 1, 'phase': 'starting', 'firewall': meta['settings']['firewall'], 'fingerprint': None}
            self._save_journal(journal)
            self.fault('activation_intent_durable')
            try:
                if journal['firewall'] == 'nft':
                    self.firewall_add(meta)
                    journal['fingerprint'] = self.firewall_snapshot()
                    self._save_journal(journal)
                    self.fault('firewall_durable')
                self.command(['/usr/bin/systemctl', 'daemon-reload'])
                self.command(['/usr/bin/systemctl', 'enable', '--now', self.service])
                self.fault('service_started')
                if self.service_state() != (True, True):
                    raise Error('E_P6_INGRESS_UNCONFIRMED')
                self._tls_probe(meta)
                journal['phase'] = 'active'
                self._save_journal(journal)
                return {'active': True, 'external_reachability': 'unverified'}
            except Exception:
                try:
                    self._rollback(journal)
                except Exception:
                    raise Error('E_P6_ROLLBACK') from None
                raise

    def _tls_probe(self, meta):
        # Local TLS/route proof with public IP SAN validation + exact leaf pin.
        # No HMAC/key/evidence, no public client contact. A missing route must
        # return local 404; no dependency on Monitor enrollment.
        context = ssl.create_default_context(cafile=str(self.identity / 'server.pem'))
        host = self.listen or ('::1' if ':' in meta['settings']['address'] else '127.0.0.1')
        deadline = time.monotonic() + 5
        while True:
            try:
                with socket.create_connection((host, meta['settings']['port']), timeout=1) as raw:
                    with context.wrap_socket(raw, server_hostname=meta['settings']['address']) as conn:
                        if hashlib.sha256(conn.getpeercert(binary_form=True)).hexdigest() != meta['binding']['certificate_sha256']:
                            raise Error('E_P6_BINDING')
                        conn.sendall(b'GET / HTTP/1.1\r\nHost: p6\r\nConnection: close\r\n\r\n')
                        response = conn.recv(4096)
                        if not response.startswith(b'HTTP/1.1 404 '):
                            raise Error('E_P6_INGRESS_UNCONFIRMED')
                        return
            except OSError:
                if time.monotonic() >= deadline:
                    raise Error('E_P6_INGRESS_UNCONFIRMED') from None
                time.sleep(.05)

    def deactivate(self):
        with self.locked():
            meta = self._identity()
            self.validate(meta)
            journal = self._journal()
            if journal is None:
                if self.service_state() != (False, False):
                    raise Error('E_P6_MANAGED_CHANGED')
                return {'active': False}
            journal['phase'] = 'stopping'
            self._save_journal(journal)
            self._rollback(journal)
            return {'active': False}


def main():
    try:
        if len(sys.argv) < 2 or sys.argv[1] not in ('prepare', 'activate', 'deactivate', 'firewall-ensure'):
            raise Error('E_P6_SCHEMA')
        op = sys.argv[1]
        worker = Ingress()
        if op == 'prepare':
            if len(sys.argv) not in (3, 4, 5):
                raise Error('E_P6_SCHEMA')
            result = worker.prepare(sys.argv[2], int(sys.argv[3]) if len(sys.argv) >= 4 else 38443,
                                    sys.argv[4] if len(sys.argv) == 5 else 'nft')
        else:
            if len(sys.argv) != 2:
                raise Error('E_P6_SCHEMA')
            result = worker.activate() if op == 'activate' else worker.deactivate() if op == 'deactivate' else worker.firewall_ensure()
        response = {'ok': True, 'data': result}
    except Error as exc:
        response = {'ok': False, 'code': exc.code}
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError, ssl.SSLError):
        response = {'ok': False, 'code': 'E_P6_INGRESS_UNAVAILABLE'}
    sys.stdout.buffer.write(p6.encoded(response))
    return 0 if response['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
