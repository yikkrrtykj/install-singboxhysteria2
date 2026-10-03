"""One-response in-memory ZIP assembly; no credential file/cache or extractor."""
import hashlib
import io
import ipaddress
import json
import re
import ssl
import zipfile
from urllib.parse import urlsplit

from p6_artifact import ArtifactError, MAX_ARTIFACT_BYTES, validate_manifest

MAX_BUNDLE_BYTES = 5 * 1024 * 1024
PARTS_KEYS = {'format', 'yaml', 'profile', 'secret', 'certificate', 'artifact'}


class BundleError(Exception):
    def __init__(self):
        super().__init__('E_P6_BUNDLE')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def validate_profile(profile, certificate):
    # Server packaging deliberately excludes client-only Mihomo code. Verify
    # this slice's closed generated profile shape without importing the Agent
    # runtime into the server. Artifact tests run the real Agent parser too.
    if type(profile) is not dict or set(profile) != {'v', 'server_id', 'probe_id',
            'ingest_url', 'certificate_sha256', 'agent'} or type(profile['v']) is not int or profile['v'] != 1:
        raise BundleError()
    for field, pattern in (('server_id', r'[0-9a-f]{32}'), ('probe_id', r'[a-z0-9-]{1,64}'),
                           ('certificate_sha256', r'[0-9a-f]{64}')):
        if type(profile[field]) is not str or not re.fullmatch(pattern, profile[field]):
            raise BundleError()
    if type(profile['ingest_url']) is not str or len(profile['ingest_url']) > 256:
        raise BundleError()
    url = urlsplit(profile['ingest_url'])
    address = ipaddress.ip_address(url.hostname)
    if url.scheme != 'https' or url.path != '/api/v1/remote-probes/ingest' or url.username or url.password \
            or url.query or url.fragment or url.port is None or not 1024 <= url.port <= 65535 \
            or address.is_loopback or address.is_unspecified or address.is_multicast \
            or any(ord(char) <= 32 or ord(char) >= 127 for char in profile['ingest_url']):
        raise BundleError()
    agent = profile['agent']
    if type(agent) is not dict or type(agent.get('vps_port')) is not int or not 1 <= agent['vps_port'] <= 65535:
        raise BundleError()
    expected = {'mihomo_url': 'http://127.0.0.1:9090', 'reality_node': 'Reality', 'hy2_node': 'Hysteria2',
                'watched_group': '自动选择', 'dns_host': 'dns.google', 'https_host': 'www.gstatic.com',
                'egress_host': 'iplark.com', 'vps_host': url.hostname, 'vps_port': agent['vps_port'],
                'cadence': 60, 'cycle_deadline': 20, 'diagnostic_timeout': 5}
    if canonical(agent) != canonical(expected) or certificate.count('-----BEGIN CERTIFICATE-----') != 1 \
            or hashlib.sha256(ssl.PEM_cert_to_DER_cert(certificate)).hexdigest() != profile['certificate_sha256']:
        raise BundleError()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=certificate)


def assemble(name, device, parts, generic):
    """Generic bytes have already passed the installed artifact DAC gate.

    Recheck them against the root worker's manifest to contain a concurrent
    artifact upgrade. Validate this slice's closed generated profile shape.
    Never serialize this result in a JSON/error response or web cache.
    """
    try:
        for value in (name, device):
            if type(value) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,31}', value):
                raise BundleError()
        if type(parts) is not dict or set(parts) not in (PARTS_KEYS, PARTS_KEYS | {'display'}) or parts['format'] != 'p6-client-bundle-parts/1':
            raise BundleError()
        manifest = validate_manifest(parts['artifact'])
        if type(generic) is not bytes or len(generic) > MAX_ARTIFACT_BYTES \
                or len(generic) != manifest['size'] or hashlib.sha256(generic).hexdigest() != manifest['sha256']:
            raise BundleError()
        yaml = parts['yaml']
        secret = parts['secret']
        certificate = parts['certificate']
        if type(yaml) is not str or not yaml or len(yaml.encode('utf-8')) > 32768 \
                or type(secret) is not str or not re.fullmatch(r'[0-9a-f]{64}', secret) \
                or type(certificate) is not str or len(certificate.encode('ascii')) > 16384 \
                or 'PRIVATE KEY' in certificate:
            raise BundleError()
        profile = parts['profile']
        validate_profile(profile, certificate)
        display = parts.get('display')
        metadata = {'v': 1, 'client': name, 'device': device, 'artifact': manifest, 'kind': 'source-foundation'}
        if 'display' in parts:
            if type(display) is not dict or set(display) != {'client', 'device', 'location', 'network_path'} \
                    or display['client'] != name or display['device'] != device \
                    or any(type(display[k]) is not str or not re.fullmatch(r'[ -~]{1,64}', display[k])
                           for k in ('location', 'network_path')):
                raise BundleError()
            metadata.update(v=2, location=display['location'], network_path=display['network_path'])
        output = io.BytesIO()
        files = {
            name + '-mihomo.yaml': yaml.encode('utf-8'),
            'profile.json': canonical(profile) + b'\n',
            'ingest.key': secret.encode('ascii') + b'\n',
            'server.pem': certificate.encode('ascii'),
            'agent/p6-agent.pyz': generic,
            'agent/artifact.json': canonical(manifest) + b'\n',
            'bundle.json': canonical(metadata) + b'\n',
            'README.txt': (
                '客户端设备配置包\n\n'
                'Sensitive: contains this device\'s proxy and P6 credentials.\n'
                'Use only on the selected device. Enroll other devices separately.\n'
                'Import the Mihomo YAML through your existing client.\n'
                'The generic Agent zipapp requires Python 3.10+; it contains no profile/key.\n'
                'Windows software is a separate administrator-published signed download.\n'
                'Download it from the Monitor device panel; extract and run P6Setup.exe.\n'
                'Select this device Bundle in the graphical manager. Lab software is test-only.\n'
                'The Windows installer verifies local controller/node binding\n'
                'and artifact digest, then import profile.json, ingest.key and server.pem\n'
                'into native protected storage. Never install server.pem in the system CA store.\n'
                'Profile defaults: loopback controller 127.0.0.1:9090; canonical Reality/Hysteria2 nodes.\n'
                'Do not assume these defaults prove your installed Clash controller is configured.\n'
                'Server TLS private key is deliberately absent.\n'
            ).encode('utf-8')}
        with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_STORED) as archive:
            for filename, raw in sorted(files.items()):
                info = zipfile.ZipInfo(filename, (1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = 0o100600 << 16
                archive.writestr(info, raw)
        result = output.getvalue()
        if len(result) > MAX_BUNDLE_BYTES:
            raise BundleError()
        return result
    except (ArtifactError, ValueError, TypeError, KeyError, UnicodeError, OSError):
        raise BundleError() from None
