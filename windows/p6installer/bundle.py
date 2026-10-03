"""Bounded passive bundle reader and read-only local controller verification."""
import hashlib
import http.client
import io
import json
import re
import socket
import ssl
import stat
import struct
import os
from pathlib import Path
import time
import threading
import zipfile

from remote_probe.agent import ConfigError
from remote_probe.delivery import UploadConfigError
from remote_probe.mihomo_probe import ConfigurationError, parse_controller_url
from remote_probe.production import incoming
from remote_probe.profiles import CERT_LIMIT, MANIFEST_LIMIT, ProfileVault, profile_id

MAX_BUNDLE = 5 * 1024 * 1024
LIMITS = {'profile.json': MANIFEST_LIMIT, 'ingest.key': 128, 'server.pem': CERT_LIMIT,
          'agent/p6-agent.pyz': 4 * 1024 * 1024, 'agent/artifact.json': 2048,
          'bundle.json': 4096, 'README.txt': 8192}


def object_json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ConfigError('duplicate JSON key')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ConfigError('nonfinite JSON')))



DISPLAY_LIMIT = 4096


def validate_display(value, profile):
    if type(value) is not dict or set(value) != {'v','client','device','location','network_path','probe_id','server_id'} \
            or type(value['v']) is not int or value['v'] != 1 \
            or value['probe_id'] != profile['probe_id'] or value['server_id'] != profile['server_id']:
        raise ConfigError('display identity mismatch')
    for key in ('client','device'):
        if type(value[key]) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,31}|',value[key]):
            raise ConfigError('invalid display label')
    for key in ('location','network_path'):
        if type(value[key]) is not str or not re.fullmatch(r'[ -~]{0,64}',value[key]):
            raise ConfigError('invalid display label')
    if len(json_bytes(value)) > DISPLAY_LIMIT:
        raise ConfigError('display capacity')
    return value


def json_bytes(value):
    import json
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode('utf-8')


def discover_adjacent(directory, expected_artifact):
    """Only the explicitly supplied original setup directory; passive input."""
    from remote_probe.spool import check_no_symlink_component
    root = os.path.abspath(directory)
    if root.startswith('\\\\'):
        raise ConfigError('network input directory')
    check_no_symlink_component(root)
    if os.name == 'nt':
        from remote_probe.windows_security import WindowsSecurity
        WindowsSecurity().check_components(root)
    if not stat.S_ISDIR(os.lstat(root).st_mode):
        raise ConfigError('invalid input directory')
    candidates=[]
    with os.scandir(root) as entries:
        for index,entry in enumerate(entries):
            if index>=128:
                raise ConfigError('input directory capacity')
            if entry.name=='device-bundle.zip' or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,100}-client-bundle\.zip',entry.name):
                candidates.append(entry.path)
    if not candidates:
        return {'state':'missing'}
    if len(candidates)!=1:
        return {'state':'ambiguous'}
    _,_,_,display=read_bundle(candidates[0],expected_artifact,include_display=True)
    return {'state':'selected','path':candidates[0],'display':display}


def read_bundle(path, expected_artifact, include_display=False):
    """Never extract or execute bundle code. The installed Agent is authority."""
    try:
        raw = incoming(path, MAX_BUNDLE)
        if len(raw)<22:
            raise ConfigError('invalid bundle directory')
        end=struct.unpack('<4s4H2LH',raw[-22:])
        if end[0]!=b'PK\x05\x06' or end[1:3]!=(0,0) or end[3:5]!=(8,8) \
                or end[5]>4096 or end[6]+end[5]!=len(raw)-22 or end[7]!=0:
            raise ConfigError('invalid bundle directory')
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            items = archive.infolist()
            if len(items) != 8 or len({i.filename for i in items}) != 8:
                raise ConfigError('invalid bundle members')
            names = {i.filename for i in items}
            yaml_names = names - set(LIMITS)
            if len(yaml_names) != 1:
                raise ConfigError('invalid bundle YAML')
            yaml_name = next(iter(yaml_names))
            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,31}-mihomo.yaml', yaml_name):
                raise ConfigError('invalid bundle YAML name')
            limits = dict(LIMITS, **{yaml_name: 32768})
            data = {}
            total = 0
            for item in items:
                mode = item.external_attr >> 16
                if item.flag_bits & 1 or item.compress_type != zipfile.ZIP_STORED \
                        or stat.S_IFMT(mode) not in (0, stat.S_IFREG) \
                        or item.is_dir() or item.file_size > limits[item.filename] \
                        or item.compress_size != item.file_size:
                    raise ConfigError('unsafe bundle member')
                total += item.file_size
                if total > MAX_BUNDLE:
                    raise ConfigError('bundle oversized')
                with archive.open(item) as stream:
                    value = stream.read(limits[item.filename] + 1)
                if len(value) != item.file_size:
                    raise ConfigError('bundle member changed')
                data[item.filename] = value
        meta = object_json(data['bundle.json'])
        artifact = object_json(data['agent/artifact.json'])
        fields = {'v', 'client', 'device', 'artifact', 'kind'}
        if type(meta) is not dict or type(meta.get('v')) is not int or meta['v'] not in (1,2) \
                or set(meta) != (fields if meta['v']==1 else fields|{'location','network_path'}) \
                or meta['kind'] != 'source-foundation' \
                or artifact != expected_artifact or meta['artifact'] != artifact \
                or len(data['agent/p6-agent.pyz']) != artifact['size'] \
                or hashlib.sha256(data['agent/p6-agent.pyz']).hexdigest() != artifact['sha256']:
            raise ConfigError('bundle differs from installed artifact')
        for label in (meta['client'], meta['device']):
            if type(label) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,31}', label):
                raise ConfigError('invalid bundle label')
        if yaml_name != meta['client'] + '-mihomo.yaml' or not data[yaml_name]:
            raise ConfigError('bundle YAML mismatch')
        secret = data['ingest.key'].strip()
        if not re.fullmatch(b'[0-9a-f]{64}', secret):
            raise ConfigError('invalid bundle secret')
        profile = object_json(data['profile.json'])
        certificate = data['server.pem'].decode('ascii')
        # Use the real Agent parser, including pinned certificate/IP/URL gate.
        ProfileVault('.')._validate(profile, certificate)
        display = validate_display({'v':1,'client':meta['client'],'device':meta['device'],
            'location':meta.get('location',''),'network_path':meta.get('network_path',''),
            'probe_id':profile['probe_id'],'server_id':profile['server_id']},profile)
        result=(profile,bytes.fromhex(secret.decode('ascii')),certificate)
        return result+(display,) if include_display else result
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, UploadConfigError, zipfile.BadZipFile,
            NotImplementedError, RuntimeError):
        raise ConfigError('invalid client bundle') from None


def verify_controller(profile, secret):
    """Only two GETs. Absolute budget and body limit; no redirects or probes."""
    try:
        if type(secret) is not str or len(secret.encode('utf-8')) > 4096 \
                or any(ord(c) < 32 or ord(c) == 127 for c in secret):
            raise ConfigError('invalid local controller credential')
        host, port, scheme = parse_controller_url(profile['agent']['mihomo_url'])
        # Literal loopback prevents DNS/environment routing changes.
        host = '127.0.0.1' if host == 'localhost' else host
        deadline = time.monotonic() + 6
        payloads = []
        for route in ('/version', '/proxies'):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ConfigError('controller unavailable')
            conn_type = http.client.HTTPSConnection if scheme == 'https' else http.client.HTTPConnection
            options = {'timeout': min(2, remaining)}
            if scheme == 'https':
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.load_default_certs()
                options['context'] = context
            conn = conn_type(host, port, **options)
            connected = []
            expired = threading.Event()
            def abort(connection=conn, peers=connected, ended=expired):
                ended.set()
                sock = peers[0] if peers else connection.sock
                if sock is not None:
                    try:
                        sock.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
            timer = threading.Timer(min(3, remaining), abort)
            timer.daemon = True
            timer.start()
            try:
                headers = {'Accept': 'application/json'}
                if secret:
                    headers['Authorization'] = 'Bearer ' + secret
                conn.connect()
                connected.append(conn.sock)
                if expired.is_set():
                    raise ConfigError('controller unavailable')
                conn.request('GET', route, headers=headers)
                response = conn.getresponse()
                if response.status != 200:
                    raise ConfigError('controller unavailable')
                body = bytearray()
                socket_handle = response.fp.raw._sock
                expected_length = response.length
                while len(body) <= 512 * 1024:
                    if response.fp is None:
                        break
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ConfigError('controller unavailable')
                    # Retune the actual response socket, including detached
                    # Connection: close responses (conn.sock can be None).
                    socket_handle.settimeout(min(2, remaining))
                    chunk = response.read1(min(16384, 512 * 1024 + 1 - len(body)))
                    if not chunk:
                        break
                    body.extend(chunk)
                if len(body) > 512 * 1024 or (expected_length is not None and len(body) != expected_length):
                    raise ConfigError('controller oversized')
                if expired.is_set():
                    raise ConfigError('controller unavailable')
                payloads.append(object_json(bytes(body)))
            finally:
                timer.cancel()
                conn.close()
        version, proxies = payloads
        if type(version) is not dict or type(version.get('version')) is not str \
                or not version['version'] or type(proxies) is not dict \
                or type(proxies.get('proxies')) is not dict:
            raise ConfigError('controller invalid')
        mapping = proxies['proxies']
        agent = profile['agent']
        for field in ('reality_node', 'hy2_node', 'watched_group'):
            name = agent[field]
            if type(name) is not str or type(mapping.get(name)) is not dict:
                raise ConfigError('configured controller node missing')
        return {'controller': 'verified', 'nodes': 'verified'}
    except (OSError, ValueError, TypeError, KeyError, AttributeError, ConfigurationError, http.client.HTTPException):
        raise ConfigError('controller unavailable') from None
