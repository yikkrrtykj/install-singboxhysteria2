#!/usr/bin/env python3
"""Bounded sensitive bundle parts, not ZIP/binary RPC or an enrollment verb."""
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import ssl
import sys
from urllib.parse import urlsplit

def sibling(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

p6 = sibling('p6_provision')
artifact = sibling('p6_artifact')
PARTS_LIMIT = 64512  # leaves 1024 bytes for the existing daemon envelope
YAML_LIMIT = 32768


def make_parts(worker, args, artifact_dir=artifact.ARTIFACT_DIR):
    if type(args) is not dict or set(args) != {'name', 'device', 'client_generation',
                                            'yaml', 'server_ip', 'vps_port'}:
        raise p6.ProvisionError('E_P6_SCHEMA')
    if type(args['yaml']) is not str or not args['yaml'] or len(args['yaml'].encode('utf-8')) > YAML_LIMIT \
            or type(args['vps_port']) is not int or not 1 <= args['vps_port'] <= 65535:
        raise p6.ProvisionError('E_P6_SCHEMA')
    # A protected, complete generic artifact must exist before credentials
    # are eligible for delivery. Its binary bytes never enter this response.
    manifest, _ = artifact.read_artifact(artifact_dir)
    material = worker.export_material(args['name'], args['device'], args['client_generation'])
    binding = material['binding']
    host = urlsplit(binding['ingest_url']).hostname
    if ipaddress.ip_address(args['server_ip']) != ipaddress.ip_address(host):
        raise p6.ProvisionError('E_P6_BINDING')
    profile = {field: binding[field] for field in ('v', 'server_id', 'ingest_url', 'certificate_sha256')}
    profile.update(probe_id=material['probe_id'], agent={
        'mihomo_url': 'http://127.0.0.1:9090',
        # These are the canonical renderer's explicit node identities, never
        # protocol guesses from Client names, labels or arbitrary YAML.
        'reality_node': 'Reality', 'hy2_node': 'Hysteria2', 'watched_group': '自动选择',
        'dns_host': 'dns.google', 'https_host': 'www.gstatic.com',
        'egress_host': 'api.ipify.org', 'vps_host': host, 'vps_port': args['vps_port'],
        'cadence': 60, 'cycle_deadline': 20, 'diagnostic_timeout': 5})
    result = {'format': 'p6-client-bundle-parts/1', 'yaml': args['yaml'],
              'profile': profile, 'secret': material['secret'],
              'certificate': material['certificate'], 'artifact': manifest,
              'display': {'client': args['name'], 'device': args['device'],
                          'location': material['site_label'], 'network_path': material['path_label']}}
    response = {'ok': True, 'data': result}
    if len(p6.encoded(response)) > PARTS_LIMIT:
        raise p6.ProvisionError('E_P6_CAPACITY')
    return response


def main():
    try:
        raw = sys.stdin.buffer.read(65537)
        if len(raw) > 65536:
            raise p6.ProvisionError('E_P6_SCHEMA')
        args = json.loads(raw)
        if os.environ.get('SBOX_CM_TEST_SANDBOX') == '1':
            worker = p6.Provisioner(os.environ['SB_P6_STATE_DIR'], os.environ['SB_P6_CONFIG_DIR'],
                                   int(os.environ['SB_P6_MONITOR_PORT']), fixture=True)
            directory = os.environ['SB_P6_ARTIFACT_DIR']
        else:
            worker = p6.Provisioner()
            directory = artifact.ARTIFACT_DIR
        response = make_parts(worker, args, directory)
    except artifact.ArtifactError:
        response = {'ok': False, 'code': 'E_P6_ARTIFACT'}
    except p6.ProvisionError as exc:
        response = {'ok': False, 'code': exc.code}
    except (OSError, ValueError, TypeError, KeyError, ssl.SSLError):
        response = {'ok': False, 'code': 'E_P6_UNAVAILABLE'}
    sys.stdout.buffer.write(p6.encoded(response))


if __name__ == '__main__':
    main()
