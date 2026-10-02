"""Native Linux root identity, nginx TLS, systemd, nft namespace and load gates.

Every listener is temporary LOOPBACK. Missing native dependencies fail, never
skip. No production key, service, rule, public listener or VPS is contacted.
"""
import concurrent.futures
import hashlib
import http.client
import importlib.util
import json
import multiprocessing
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'monitor-v2'))
sys.path.insert(0, str(ROOT / 'tests/remote-server'))
import server_groups as harness
from web.remote_registry import RemoteRegistry
from web.remote_ingest import RemoteIngest

spec = importlib.util.spec_from_file_location('p6_ingress', ROOT / 'sbox-cm/p6_ingress.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
p6 = mod.p6


def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class IngressTests(unittest.TestCase):
    def setUp(self):
        # Native PrivateTmp units must read the same fixture authority. /run
        # avoids incorrectly depending on the host's /tmp inside a private mount.
        self.tmp = tempfile.TemporaryDirectory(prefix='p6-ingress-', dir='/run')
        self.root = Path(self.tmp.name)
        self.unit_dir = self.root / 'units'
        self.unit_dir.mkdir()
        self.runtime = '/run/p6-fixture-' + os.urandom(8).hex()
        self.service = 'p6-fixture-' + os.urandom(8).hex() + '.service'
        self.worker = mod.Ingress(fixture=True, config_dir=str(self.root / 'config'),
                state_dir=str(self.root / 'state'), unit_dir=str(self.unit_dir), runtime=self.runtime,
                service=self.service, table='p6_fixture_' + os.urandom(8).hex(), listen='127.0.0.1')
        self.port = port()
        self.nginx = None

    def tearDown(self):
        if self.nginx is not None:
            self.nginx.terminate()
            self.nginx.wait(timeout=10)
            self.nginx.stderr.close()
        runtime = Path(self.runtime)
        if runtime.exists():
            # Checked exact random fixture root, one Python filesystem API.
            self.assertEqual(runtime.parent, Path('/run'))
            self.assertTrue(runtime.name.startswith('p6-fixture-'))
            shutil.rmtree(runtime)
        self.tmp.cleanup()

    def prepare(self, firewall='none'):
        return self.worker.prepare('192.0.2.10', self.port, firewall)

    def error(self, code, call):
        with self.assertRaises(p6.ProvisionError) as caught:
            call()
        self.assertEqual(caught.exception.code, code)

    def start_nginx(self):
        self.nginx = subprocess.Popen(['/usr/sbin/nginx', '-p', self.runtime + '/', '-c', str(self.worker.config),
                                       '-g', 'daemon off;'], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        self.worker._tls_probe(self.worker._identity())

    def request(self, *, method='POST', path=p6.INGEST_PATH, version='HTTP/1.1', framing='Content-Length: 2\r\n',
                body=b'{}', headers=None):
        context = ssl.create_default_context(cafile=str(self.worker.identity / 'server.pem'))
        with socket.create_connection(('127.0.0.1', self.port), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname='192.0.2.10') as conn:
                prefix = f'{method} {path} {version}\r\nHost: p6\r\nConnection: close\r\nContent-Type: application/json\r\n'
                prefix += ''.join(k + ': ' + v + '\r\n' for k, v in (headers or {}).items()
                                  if k not in ('Content-Length', 'Connection', 'Content-Type'))
                conn.sendall((prefix + framing + '\r\n').encode('ascii') + body)
                response = conn.makefile('rb').readline()
                return int(response.split()[1])

    def test_prepare_validates_without_listener_firewall_or_service_enable(self):
        with patch.object(self.worker, 'service_state', side_effect=AssertionError('prepare changed service')), \
                patch.object(self.worker, 'firewall_add', side_effect=AssertionError('prepare opened firewall')):
            result = self.prepare()
        self.assertTrue(result['prepared'])
        self.assertEqual(result['activation'], 'explicit')
        self.assertEqual(result['external_reachability'], 'unverified')
        self.assertFalse(self.worker.journal.exists())
        self.worker._port_free(self.worker._identity())

    def test_unprepared_activate_does_not_poison_future_identity_creation(self):
        self.error('E_P6_NOT_PREPARED', self.worker.activate)
        self.assertFalse(self.worker.identity.exists())
        self.assertTrue(self.prepare()['prepared'])

    def test_idempotent_reinstall_preserves_server_id_cert_pin_and_private_key(self):
        first = self.prepare()
        key = (self.worker.identity / 'server.key').read_bytes()
        certificate = (self.worker.identity / 'server.pem').read_bytes()
        self.assertEqual(self.prepare(), first)
        self.assertEqual((self.worker.identity / 'server.key').read_bytes(), key)
        self.assertEqual((self.worker.identity / 'server.pem').read_bytes(), certificate)
        self.assertNotIn(key.decode(), json.dumps(first))

    def test_native_private_public_authority_modes_and_ip_san_pin(self):
        self.prepare()
        for file, mode, gid in ((self.worker.identity / 'server.key', 0o600, 0),
                (self.worker.identity / 'metadata.json', 0o600, 0),
                (Path(self.worker.fs.config_dir) / 'p6-server.json', 0o600, 0),
                (Path(self.worker.fs.config_dir) / 'p6-server.pem', 0o640, self.worker.fs.gid)):
            st = file.lstat()
            self.assertEqual((st.st_uid, st.st_gid, st.st_mode & 0o777), (0, gid, mode))
        self.assertEqual(self.worker.fs._binding(), self.worker._identity()['binding'])
        cert = ssl._ssl._test_decode_cert(str(self.worker.identity / 'server.pem'))
        self.assertIn(('IP Address', '192.0.2.10'), cert['subjectAltName'])
        self.assertLessEqual(ssl.cert_time_to_seconds(cert['notAfter']) - ssl.cert_time_to_seconds(cert['notBefore']), 3650 * 86400)

    def test_changed_ip_port_or_firewall_requires_explicit_replacement(self):
        self.prepare()
        key = (self.worker.identity / 'server.key').read_bytes()
        for address, number, firewall in (('192.0.2.11', self.port, 'none'),
                ('192.0.2.10', self.port + 1, 'none'), ('192.0.2.10', self.port, 'nft')):
            self.error('E_P6_BINDING_CHANGED', lambda: self.worker.prepare(address, number, firewall))
        self.assertEqual((self.worker.identity / 'server.key').read_bytes(), key)

    def test_occupied_port_refused_before_identity_publication(self):
        with socket.socket() as occupied:
            occupied.bind(('127.0.0.1', self.port)); occupied.listen()
            self.error('E_P6_PORT_OCCUPIED', self.prepare)
        self.assertFalse(self.worker.identity.exists())

    def test_preexisting_binding_is_not_taken_over(self):
        path = Path(self.worker.fs.config_dir) / 'p6-server.json'
        self.worker.write(path, b'operator authority\n')
        self.error('E_P6_BINDING_CHANGED', self.prepare)
        self.assertEqual(path.read_bytes(), b'operator authority\n')

    def test_invalid_addresses_low_ports_and_monitor_port_refused(self):
        for address, number in (('localhost', 38443), ('127.0.0.1', 38443), ('0.0.0.0', 38443),
                ('224.0.0.1', 38443), ('192.0.2.10', 443), ('192.0.2.10', 9191), ('192.0.2.10', 65536)):
            self.error('E_P6_BINDING', lambda: self.worker.prepare(address, number, 'none'))
        self.assertFalse(self.worker.identity.exists())

    def test_ipv6_binding_and_certificate_san_validate(self):
        self.worker.listen = '[::1]'
        # prepare/identity can be tested independently of IPv6 availability.
        with patch.object(self.worker, '_port_free'):
            result = self.worker.prepare('2001:db8::10', self.port, 'none')
        self.assertIn('https://[2001:db8::10]:', result['ingest_url'])
        self.assertEqual(self.worker.fs._binding()['certificate_sha256'], result['certificate_sha256'])

    def test_real_process_death_after_each_durable_prepare_boundary_recovers_same_identity(self):
        for phase in ('identity_durable', 'binding_pem_durable', 'binding_json_durable', 'managed_conf_durable', 'managed_service_durable'):
            def child():
                self.worker.fault = lambda value: os._exit(91) if value == phase else None
                self.prepare()
            # On retries prior boundaries still execute; identity_durable only
            # executes once, so test that boundary on the initial attempt.
            if phase == 'identity_durable' or not self.worker.unit.exists():
                proc = multiprocessing.get_context('fork').Process(target=child)
                proc.start(); proc.join(65)
                self.assertEqual(proc.exitcode, 91, phase)
            else:
                self.worker.remove(self.worker.unit, 0o644)
                proc = multiprocessing.get_context('fork').Process(target=child)
                proc.start(); proc.join(65)
                self.assertEqual(proc.exitcode, 91, phase)
            meta = self.worker._identity()
            key = (self.worker.identity / 'server.key').read_bytes()
            self.prepare()
            self.assertEqual(self.worker._identity(), meta)
            self.assertEqual((self.worker.identity / 'server.key').read_bytes(), key)

    def test_concurrent_first_prepare_publishes_one_identity(self):
        def child(pipe):
            pipe.send(self.prepare())
        context = multiprocessing.get_context('fork')
        pairs = [context.Pipe(False) for _ in range(2)]
        procs = [context.Process(target=child, args=(b,)) for a, b in pairs]
        for proc in procs: proc.start()
        results = []
        for a, b in pairs:
            self.assertTrue(a.poll(70), 'first-prepare child failed to respond')
            results.append(a.recv())
        for proc in procs:
            proc.join(65); self.assertEqual(proc.exitcode, 0)
        self.assertEqual(results[0], results[1])

    def test_changed_managed_config_unit_and_symlink_authority_refused(self):
        self.prepare()
        for path, mode in ((self.worker.config, 0o600), (self.worker.unit, 0o644)):
            original = path.read_bytes()
            path.write_bytes(original + b'# external edit\n')
            self.error('E_P6_MANAGED_CHANGED', self.prepare)
            self.assertEqual(path.read_bytes(), original + b'# external edit\n')
            path.write_bytes(original)
        key = self.worker.identity / 'server.key'
        backup = key.with_suffix('.saved'); key.rename(backup); key.symlink_to(backup)
        self.error('E_P6_AUTHORITY', self.prepare)

    def test_mismatched_private_key_refused_without_regeneration(self):
        self.prepare()
        key = self.worker.identity / 'server.key'
        self.worker.command(['/usr/bin/openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', str(key)])
        original = key.read_bytes()
        self.error('E_P6_BINDING', self.prepare)
        self.assertEqual(key.read_bytes(), original)

    def test_native_parser_rejects_old_zone_context_and_invalid_config(self):
        self.prepare()
        raw = self.worker.config.read_bytes()
        # Feed a separate mutation to the real parser, without replacing managed authority.
        bad = self.root / 'bad.conf'
        bad.write_bytes(raw.replace(b'http {', b'http {\n server { limit_req_zone $binary_remote_addr zone=bad:1m rate=1r/s; }'))
        result = self.worker.command(['/usr/sbin/nginx', '-t', '-p', self.runtime + '/', '-c', str(bad)], check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'directive is not allowed here', result.stderr)

    def capture(self):
        import http.server
        seen = []
        class Capture(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'
            def do_POST(self):
                seen.append((self.request_version, dict(self.headers), self.rfile.read(int(self.headers['Content-Length']))))
                self.send_response(200); self.send_header('Content-Length', '0'); self.end_headers()
            def log_message(self, *args): pass
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Capture)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close); self.addCleanup(server.shutdown)
        self.worker.upstream = server.server_port
        return seen

    def test_real_tls_legal_request_preserves_body_five_headers_and_framing(self):
        seen = self.capture(); self.prepare(); self.start_nginx()
        headers = p6.proof_headers('fixture', 'a' * 64)
        self.assertEqual(self.request(headers=headers), 200)
        self.assertEqual(len(seen), 1)
        version, received, body = seen[0]
        self.assertEqual((version, body, received['Content-Length']), ('HTTP/1.1', b'{}', '2'))
        for name, value in headers.items():
            if name.startswith('X-Remote-Probe-'): self.assertEqual(received[name], value)
        self.assertNotIn('Transfer-Encoding', received)

    def test_real_tls_bad_wire_framing_never_reaches_upstream(self):
        seen = self.capture(); self.prepare(); self.start_nginx()
        for args in ({'version': 'HTTP/1.0'}, {'framing': ''},
                {'framing': 'Transfer-Encoding: chunked\r\n', 'body': b'2\r\n{}\r\n0\r\n\r\n'},
                {'framing': 'Content-Length: 2\r\nTransfer-Encoding: chunked\r\n', 'body': b'{}'}):
            self.assertEqual(self.request(**args), 400)
            self.assertEqual(seen, [])

    def test_real_tls_wrong_methods_paths_queries_and_encoded_route_stay_local(self):
        seen = self.capture(); self.prepare(); self.start_nginx()
        self.assertEqual(self.request(method='GET'), 405)
        for path in ('/', '/login', '/static/x', '/api/v1/incidents', p6.INGEST_PATH + '/',
                     p6.INGEST_PATH + '?x=1', '/api/v1/remote-probes/%69ngest'):
            self.assertEqual(self.request(path=path), 404, path)
        self.assertEqual(seen, [])

    def test_real_tls_oversize_body_stays_local(self):
        seen = self.capture(); self.prepare(); self.start_nginx()
        self.assertEqual(self.request(framing='Content-Length: 16385\r\n', body=b'{}'), 413)
        self.assertEqual(seen, [])

    def test_dedicated_instance_keeps_unrelated_nginx_running_and_files_unchanged(self):
        seen = self.capture(); self.prepare(); self.start_nginx()
        other_port = port()
        other = self.root / 'unrelated.conf'
        other.write_text(f'pid {self.root}/other.pid; error_log /dev/null; events {{}} http {{ access_log off; server {{ listen 127.0.0.1:{other_port}; return 204; }} }}')
        before = other.read_bytes()
        proc = subprocess.Popen(['/usr/sbin/nginx', '-p', str(self.root) + '/', '-c', str(other), '-g', 'daemon off;'], stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 5
            while True:
                try:
                    conn = http.client.HTTPConnection('127.0.0.1', other_port, timeout=1)
                    conn.request('GET', '/'); status = conn.getresponse().status; conn.close()
                    break
                except OSError:
                    if time.monotonic() >= deadline: raise
                    time.sleep(.05)
            self.assertEqual(status, 204)
            self.assertEqual(self.request(), 200)
            self.assertEqual(self.prepare()['certificate_sha256'], self.worker._identity()['binding']['certificate_sha256'])
            self.assertIsNone(proc.poll())
            self.assertEqual(other.read_bytes(), before)
        finally:
            proc.terminate(); proc.wait(timeout=10)
            proc.stderr.close()

    def test_native_systemd_activate_deactivate_and_failed_activation_rollback(self):
        # Random service, loopback port and temporary certificate/config.
        self.worker.unit = Path('/etc/systemd/system') / self.service
        self.prepare()
        try:
            self.assertEqual(self.worker.activate()['active'], True)
            self.assertEqual(self.worker.activate()['active'], True)
            properties = self.worker.command(['/usr/bin/systemctl', 'show', self.service,
                    '--property=CPUQuotaPerSecUSec,MemoryMax,TasksMax,LimitNOFILE,NoNewPrivileges']).stdout.decode()
            for expected in ('CPUQuotaPerSecUSec=500ms', 'MemoryMax=134217728', 'TasksMax=16',
                             'LimitNOFILE=512', 'NoNewPrivileges=yes'):
                self.assertIn(expected, properties)
            identity = self.worker._identity()
            self.assertEqual(self.worker.deactivate(), {'active': False})
            self.assertEqual(self.worker.service_state(), (False, False))
            with patch.object(self.worker, '_tls_probe', side_effect=p6.ProvisionError('E_P6_INGRESS_UNCONFIRMED')):
                self.error('E_P6_INGRESS_UNCONFIRMED', self.worker.activate)
            self.assertEqual(self.worker.service_state(), (False, False))
            self.assertFalse(self.worker.journal.exists())
            self.assertEqual(self.worker._identity(), identity)
            for phase in ('activation_intent_durable', 'service_started'):
                def child():
                    self.worker.fault = lambda value: os._exit(92) if value == phase else None
                    self.worker.activate()
                proc = multiprocessing.get_context('fork').Process(target=child)
                proc.start(); proc.join(30)
                self.assertEqual(proc.exitcode, 92)
                self.assertEqual(self.worker.activate()['active'], True)
                self.assertEqual(self.worker.deactivate(), {'active': False})
                self.assertEqual(self.worker._identity(), identity)
            self.assertTrue(self.worker.activate()['active'])
            key = self.worker.identity / 'server.key'
            original = key.read_bytes()
            key.write_bytes(b'compromised / unavailable TLS key\n')
            self.assertEqual(self.worker.deactivate(), {'active': False})
            self.assertEqual(self.worker.service_state(), (False, False))
            key.write_bytes(original)
        except Exception:
            sys.stderr.buffer.write(self.worker.command(['/usr/bin/journalctl', '-u', self.service,
                                    '--no-pager', '-n', '30'], check=False).stdout)
            raise
        finally:
            self.worker.command(['/usr/bin/systemctl', 'disable', '--now', self.service], check=False)
            self.worker.unit.unlink(missing_ok=True)
            self.worker.command(['/usr/bin/systemctl', 'daemon-reload'])
            self.worker.command(['/usr/bin/systemctl', 'reset-failed', self.service], check=False)

    def test_actual_nft_namespace_managed_rule_crash_recovery_and_unrelated_preservation(self):
        self.prepare('nft')
        context = multiprocessing.get_context('fork')
        def child():
            # Real network namespace isolates ALL native rules from the runner.
            subprocess.run(['/usr/bin/unshare', '-n', '/usr/bin/true'], check=True)
            import ctypes
            if ctypes.CDLL(None, use_errno=True).unshare(0x40000000):
                raise OSError(ctypes.get_errno(), 'unshare network')
            self.worker.command(['/usr/sbin/nft', 'add', 'table', 'inet', 'unrelated'])
            before = self.worker.command(['/usr/sbin/nft', '-j', 'list', 'table', 'inet', 'unrelated']).stdout
            meta = self.worker._identity()
            journal = {'v': 1, 'phase': 'starting', 'firewall': 'nft', 'fingerprint': None, 'owner': 'a' * 32}
            self.worker._save_journal(journal)
            self.worker.firewall_add(meta)
            self.worker.firewall_owned(meta)
            # Simulate add->checkpoint death by leaving fingerprint=None.
            self.worker.firewall_ensure()
            journal = self.worker._journal()
            self.assertEqual(journal['fingerprint'], self.worker.firewall_snapshot())
            # Simulate reboot: owned ephemeral table gone, restored from journal.
            self.worker.command(['/usr/sbin/nft', 'delete', 'table', 'inet', self.worker.table])
            self.worker.firewall_ensure()
            self.assertEqual(journal['fingerprint'], self.worker.firewall_snapshot())
            # Extra external rule is never deleted/reinterpreted as owned.
            self.worker.command(['/usr/sbin/nft', 'add', 'rule', 'inet', self.worker.table, 'ingress', 'tcp', 'dport', '12345', 'accept'])
            self.error('E_P6_FIREWALL_CHANGED', self.worker.firewall_ensure)
            self.worker.command(['/usr/sbin/nft', 'delete', 'table', 'inet', self.worker.table])
            self.assertEqual(before, self.worker.command(['/usr/sbin/nft', '-j', 'list', 'table', 'inet', 'unrelated']).stdout)
        proc = context.Process(target=child); proc.start(); proc.join(30)
        self.assertEqual(proc.exitcode, 0)

    def test_native_nft_systemd_prestart_restores_after_rule_loss_and_deactivation_cleans_only_owned_table(self):
        # The whole dedicated unit joins a temporary child's network namespace;
        # real pre-start permissions/boot restoration are tested, not mocked.
        self.worker.unit = Path('/etc/systemd/system') / self.service
        executable = Path('/opt/p6-fixture-' + os.urandom(8).hex())
        executable.mkdir(mode=0o700)
        for name in ('p6_ingress.py', 'p6_provision.py'):
            shutil.copyfile(ROOT / 'sbox-cm' / name, executable / name)
            (executable / name).chmod(0o600)
        args = {'fixture': True, 'config_dir': self.worker.fs.config_dir, 'state_dir': self.worker.fs.state_dir,
                'unit_dir': '/etc/systemd/system', 'runtime': self.runtime, 'service': self.service,
                'table': self.worker.table, 'listen': '127.0.0.1'}
        entry = executable / 'entry.py'
        entry.write_text('import importlib.util\ns=importlib.util.spec_from_file_location("p6_ingress",' + repr(str(executable / 'p6_ingress.py')) + ')\nm=importlib.util.module_from_spec(s);s.loader.exec_module(m)\nm.Ingress(**' + repr(args) + ').firewall_ensure()\n')
        entry.chmod(0o600)
        def child():
            import ctypes
            if ctypes.CDLL(None, use_errno=True).unshare(0x40000000):
                raise OSError(ctypes.get_errno(), 'unshare network')
            self.worker.command(['/usr/sbin/ip', 'link', 'set', 'lo', 'up'])
            original_render = self.worker.render_unit
            self.worker.render_unit = lambda: original_render().replace(
                b'/usr/local/lib/sbox-cm/p6_ingress.py firewall-ensure', str(entry).encode()).replace(
                b'[Service]\n', ('[Service]\nNetworkNamespacePath=/proc/%d/ns/net\n' % os.getpid()).encode())
            self.prepare('nft')
            self.worker.command(['/usr/sbin/nft', 'add', 'table', 'inet', 'unrelated'])
            before = self.worker.command(['/usr/sbin/nft', '-j', 'list', 'table', 'inet', 'unrelated']).stdout
            try:
                self.assertTrue(self.worker.activate()['active'])
                fingerprint = self.worker.firewall_snapshot()
                self.worker.command(['/usr/sbin/nft', 'delete', 'table', 'inet', self.worker.table])
                self.worker.command(['/usr/bin/systemctl', 'restart', self.service])
                self.worker._tls_probe(self.worker._identity())
                self.assertEqual(self.worker.firewall_snapshot(), fingerprint)
                self.assertEqual(self.worker.deactivate(), {'active': False})
                self.assertIsNone(self.worker.firewall_snapshot())
                self.assertEqual(before, self.worker.command(['/usr/sbin/nft', '-j', 'list', 'table', 'inet', 'unrelated']).stdout)
            finally:
                self.worker.command(['/usr/bin/systemctl', 'disable', '--now', self.service], check=False)
        proc = multiprocessing.get_context('fork').Process(target=child)
        try:
            proc.start(); proc.join(60)
            if proc.exitcode != 0:
                sys.stderr.buffer.write(self.worker.command(['/usr/bin/journalctl', '-u', self.service,
                                        '--no-pager', '-n', '30'], check=False).stdout)
            self.assertEqual(proc.exitcode, 0)
        finally:
            if proc.is_alive(): proc.terminate(); proc.join(10)
            self.worker.command(['/usr/bin/systemctl', 'disable', '--now', self.service], check=False)
            self.worker.unit.unlink(missing_ok=True)
            self.worker.command(['/usr/bin/systemctl', 'daemon-reload'])
            self.worker.command(['/usr/bin/systemctl', 'reset-failed', self.service], check=False)
            self.assertEqual(executable.parent, Path('/opt'))
            self.assertTrue(executable.name.startswith('p6-fixture-'))
            shutil.rmtree(executable)

    def test_actual_monitor_hostile_preauth_burst_records_resource_and_control_latency(self):
        # Separate native process enables honest server-only /proc CPU/RSS.
        context = multiprocessing.get_context('fork')
        parent, child = context.Pipe()
        def monitor_process(pipe):
            sink = os.open(os.devnull, os.O_WRONLY)
            os.dup2(sink, 2); os.close(sink)
            registry = RemoteRegistry(str(Path(self.worker.fs.config_dir) / 'remote-probes.json'),
                                      str(Path(self.worker.fs.config_dir) / 'remote-probes.d'))
            plane = RemoteIngest(str(self.root / 'evidence'), registry=registry)
            counts = {}
            original = plane.handle
            def counted(*args, **kwargs):
                response = original(*args, **kwargs)
                counts[str(response[0])] = counts.get(str(response[0]), 0) + 1
                return response
            plane.handle = counted
            server, request, webroot = harness._serve(plane)
            pipe.send(server.server_address[1])
            pipe.recv()
            status = plane.store.status()
            pipe.send({'upstream_outcomes': counts, 'sample_count': status['sample_count'],
                       'receipt_count': status['receipt_count']})
            server.shutdown(); server.server_close(); plane.close(); harness.clean(webroot)
        process = context.Process(target=monitor_process, args=(child,)); process.start()
        try:
            self.assertTrue(parent.poll(15))
            monitor_port = parent.recv()
            self.worker.upstream = monitor_port
            self.worker.unit = Path('/etc/systemd/system') / self.service
            self.prepare()
            self.worker.fs.port = monitor_port
            self.worker.fs.proof = lambda row, active: p6.live_proof(monitor_port, row, active)
            result = self.worker.fs.enroll('load-client', 'device', 'a' * 64, 'load-enrollment-0001', 'fixture', 'path')
            # Worst permitted registry size, with actual root:sboxweb key files.
            rows = self.worker.fs._registry()
            for n in range(63):
                name = 'manual-%02d' % n
                rows.append({'probe_id': name, 'enabled': True, 'site_label': 'fixture', 'path_label': 'path', 'key_file': name + '.key'})
                self.worker.fs._write(str(Path(self.worker.fs.key_dir) / (name + '.key')), b'b' * 64 + b'\n', 0o640, self.worker.fs.gid)
            self.worker.fs._write(self.worker.fs.config, p6.encoded({'v': 1, 'probes': rows}), 0o640, self.worker.fs.gid)
            self.assertTrue(self.worker.activate()['active'])
            nginx_pid = int(self.worker.command(['/usr/bin/systemctl', 'show', self.service,
                                                '--property=MainPID', '--value']).stdout)
            self.assertGreater(nginx_pid, 0)
            def ticks(pid):
                fields = Path('/proc/%d/stat' % pid).read_text().rsplit(')', 1)[1].split()
                return int(fields[11]) + int(fields[12])
            def rss(pid):
                for line in Path('/proc/%d/status' % pid).read_text().splitlines():
                    if line.startswith('VmRSS:'): return int(line.split()[1]) * 1024
                raise AssertionError('missing native RSS')
            def control():
                start = time.monotonic()
                connection = http.client.HTTPConnection('127.0.0.1', monitor_port, timeout=3)
                connection.request('GET', '/api/v1/session')
                response = connection.getresponse(); response.read(); connection.close()
                self.assertEqual(response.status, 200)
                return (time.monotonic() - start) * 1000
            baseline = [control() for _ in range(20)]
            latencies = []
            samples = []
            observation_errors = []
            finished = threading.Event()
            def observe():
                try:
                    while not finished.is_set():
                        latencies.append(control())
                        samples.append(rss(process.pid))
                        finished.wait(.05)
                except Exception as exc:
                    observation_errors.append(type(exc).__name__)
            observer = threading.Thread(target=observe)
            observer.start()
            before_ticks, start = ticks(process.pid), time.monotonic()
            nginx_pids = [nginx_pid] + [int(value) for value in
                    Path('/proc/%d/task/%d/children' % (nginx_pid, nginx_pid)).read_text().split()]
            nginx_before_ticks = sum(ticks(pid) for pid in nginx_pids)
            nginx_rss = sum(rss(pid) for pid in nginx_pids)
            headers = p6.proof_headers(result['probe_id'], '0' * 64)  # deliberately wrong HMAC
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
                    results = list(pool.map(lambda n: self.request(headers=headers if n % 2 else {}), range(640)))
            finally:
                finished.set(); observer.join(5)
            seconds = time.monotonic() - start
            cpu = (ticks(process.pid) - before_ticks) / os.sysconf('SC_CLK_TCK')
            nginx_cpu = (sum(ticks(pid) for pid in nginx_pids) - nginx_before_ticks) / os.sysconf('SC_CLK_TCK')
            nginx_rss = max(nginx_rss, sum(rss(pid) for pid in nginx_pids))
            self.assertFalse(observer.is_alive())
            self.assertEqual(observation_errors, [])
            self.assertTrue(latencies)
            self.assertTrue(samples)
            self.assertEqual(set(results) - {401, 429}, set())
            self.assertIn(401, results)
            self.assertIn(429, results)
            self.assertLess(max(latencies), 3000)  # bounded responsiveness, not a fabricated 5ms target
            self.assertLess(max(samples), 160 * 1024 * 1024)
            parent.send('status'); self.assertTrue(parent.poll(15)); final = parent.recv()
            self.assertEqual((final['sample_count'], final['receipt_count']), (0, 0))
            self.assertGreater(final['upstream_outcomes'].get('401', 0), 0)
            def p95(values): return sorted(values)[int((len(values) - 1) * .95)]
            receipt = {'kind': 'temporary-loopback-server-load', 'registry_identities': 64, 'requests': len(results),
                'client_concurrency': 16, 'duration_seconds': round(seconds, 3), 'monitor_cpu_seconds': round(cpu, 3),
                'monitor_cpu_percent_one_core': round(cpu / seconds * 100, 2),
                'monitor_cpu_percent_machine': round(cpu / seconds * 100 / (os.cpu_count() or 1), 2),
                'monitor_peak_rss_bytes': max(samples), 'control_baseline_p95_ms': round(p95(baseline), 3),
                'nginx_cpu_seconds': round(nginx_cpu, 3),
                'nginx_cpu_percent_one_core': round(nginx_cpu / seconds * 100, 2),
                'nginx_cpu_percent_machine': round(nginx_cpu / seconds * 100 / (os.cpu_count() or 1), 2),
                'nginx_rss_sum_endpoint_bytes': nginx_rss,
                'nginx_execution': 'actual-dedicated-systemd-unit', 'nginx_cpu_quota_one_core_percent': 50,
                'control_under_load_p95_ms': round(p95(latencies), 3), 'control_max_ms': round(max(latencies), 3),
                'proxy_outcomes': {str(x): results.count(x) for x in sorted(set(results))}, **final,
                'production_windows_resource_acceptance': 'not_performed'}
            print('P6_INGRESS_LOAD_RECEIPT ' + json.dumps(receipt, sort_keys=True), flush=True)
            process.join(10); self.assertEqual(process.exitcode, 0)
        finally:
            self.worker.command(['/usr/bin/systemctl', 'disable', '--now', self.service], check=False)
            if self.worker.unit.parent == Path('/etc/systemd/system'):
                self.worker.unit.unlink(missing_ok=True)
                self.worker.command(['/usr/bin/systemctl', 'daemon-reload'])
                self.worker.command(['/usr/bin/systemctl', 'reset-failed', self.service], check=False)
            if process.is_alive():
                process.terminate(); process.join(10)


if __name__ == '__main__':
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise SystemExit('Linux root ingress fixtures required; no skipped acceptance')
    unittest.main(verbosity=2)
