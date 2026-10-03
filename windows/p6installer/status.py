"""Bounded local observation snapshot; no runtime/recovery or credential reads."""
import base64
import ctypes
import os
from pathlib import Path
import re

from remote_probe.agent import ConfigError
from remote_probe.payload import validate_sample
from remote_probe.production_storage import closed_diagnostics, DIAGNOSTIC_KEY
from remote_probe.windows_security import StorageSecurityError
from .bundle import object_json, validate_display, DISPLAY_LIMIT

COUNTERS = ('next_record_id', 'resolved_through', 'acknowledged_total',
            'quarantined_total', 'expired_total', 'budget_dropped_total',
            'corrupt_total', 'state_save_failures')


def read_live(security, path, limit, tail=False):
    """Same-object native authority check; share append/replace with the service."""
    import msvcrt
    security.check_components(str(path))
    handle = security.k.CreateFileW(os.path.abspath(path), 0x80020000, 7, None,
                                    3, 0x00200000 | 0x02000000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise StorageSecurityError('local observation unavailable')
    fd = None
    try:
        security._check_handle(handle, False)
        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
        handle = None
        size = os.fstat(fd).st_size
        if not tail and size > limit:
            raise StorageSecurityError('local observation oversized')
        offset = max(0, size - limit) if tail else 0
        os.lseek(fd, offset, os.SEEK_SET)
        remaining = size - offset
        result = bytearray()
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                raise StorageSecurityError('local observation changed')
            result.extend(chunk)
            remaining -= len(chunk)
        return bytes(result)
    finally:
        if fd is not None:
            os.close(fd)
        elif handle is not None:
            security.k.CloseHandle(handle)


def summarize_spool(raw):
    state = object_json(raw)
    if type(state) is not dict:
        raise ConfigError('local observation invalid')
    result = {}
    for field in COUNTERS:
        value = state.get(field)
        if type(value) is not int or not 0 <= value <= 2**63 - 1:
            raise ConfigError('local observation invalid')
        result[field] = value
    if not 0 <= result['resolved_through'] < result['next_record_id'] \
            or result['acknowledged_total'] >= result['next_record_id']:
        raise ConfigError('local observation invalid')
    retry = state.get('retry_attempts')
    if type(retry) is not dict or len(retry) > 8192:
        raise ConfigError('local observation invalid')
    result['storage_diagnostics'] = closed_diagnostics(state.get(DIAGNOSTIC_KEY))
    result['tracked_retry_records'] = len(retry)
    # This is deliberately not described as the exact number of pending records.
    result['unresolved_record_span'] = result['next_record_id'] - 1 - result['resolved_through']
    return result


def latest_sample(raw, probe):
    lines = raw.split(b'\n')
    # The first tail line may be partial; the last line may be an in-flight append.
    for line in reversed(lines[(1 if len(raw) >= 65536 else 0):-1]):
        if len(line) > 32768:
            continue
        try:
            record = object_json(line)
            if record.get('probe_id') != probe or type(record.get('body_b64')) is not str \
                    or len(record['body_b64']) > 22000:
                continue
            body = base64.b64decode(record['body_b64'], validate=True)
            if len(body) > 16384:
                continue
            sample = object_json(body)
            if validate_sample(sample) or sample['probe_id'] != probe \
                    or sample['run'] != record.get('run') or sample['seq'] != record.get('seq'):
                continue
            result = {k: sample[k] for k in ('sample_epoch', 'seq', 'dns', 'https', 'vps_tcp', 'mihomo_api', 'active')}
            result['egress_status'] = sample['egress']['status']
            result['egress_error_code'] = sample['egress']['error_code']
            result['egress_latency_ms'] = sample['egress']['latency_ms']
            return result
        except (ValueError, TypeError, KeyError, AttributeError, ConfigError):
            continue
    return None


def snapshot(manager, reader=None):
    """No mkdir, installer lock creation, recovery, spool open or service control."""
    read = reader or (lambda path, limit, tail=False: read_live(manager.security, path, limit, tail))
    if not manager.root.exists():
        return {'v': 1, 'installed': False, 'pending_recovery': False, 'profiles': [], 'retired': []}
    manager.security.validate(str(manager.root), True)
    pending = False
    for name in ('upgrade.json', 'uninstall.json'):
        path = manager.root / name
        if os.path.lexists(path):
            manager.security.validate(str(path))
            pending = True
    active = manager._active()
    if pending:
        return {'v': 1, 'installed': active is not None, 'pending_recovery': True, 'profiles': [], 'retired': []}
    retired = sorted(os.listdir(manager.root / 'retired'))
    if len(retired) > 8 or any(not re.fullmatch(r'[0-9a-f]{64}', key) for key in retired):
        raise ConfigError('local observation invalid')
    for key in retired:
        manager.security.validate(str(manager.root / 'retired' / key), True)
    result = {'v': 1, 'installed': active is not None, 'pending_recovery': False,
              'profiles': [], 'retired': retired}
    if active is not None:
        manager._check_release(active)
        result.update(release=active, service_state=manager.service.state(manager._command(active)))
        keys = manager.vault.keys()
        if len(keys) + len(retired) > 8:
            raise ConfigError('local observation invalid')
        for key in keys:
            manifest = manager.vault.load(key)
            path = Path(manager.vault._path(key)) / 'spool'
            manager.security.validate(str(path), True)
            profile = {'id': key, 'probe_id': manifest['probe_id'], 'server_id': manifest['server_id'],
                       'enabled': manager.vault.enabled(key), 'cadence_seconds': manifest['agent'].get('cadence', 60),
                       'spool': None, 'sample': None}
            display_path=Path(manager.vault._path(key))/'display.json'
            if os.path.lexists(display_path):
                profile['display']=validate_display(object_json(read(display_path,DISPLAY_LIMIT)),manifest)
            else:
                profile['display']=validate_display({'v':1,'client':'','device':'','location':'','network_path':'',
                    'probe_id':manifest['probe_id'],'server_id':manifest['server_id']},manifest)
            state = path / 'spool.state.json'
            if state.exists():
                profile['spool'] = summarize_spool(read(state, 524288))
            for name in ('spool.jsonl', 'spool.jsonl.1', 'spool.jsonl.2', 'spool.jsonl.3'):
                sample_path = path / name
                if sample_path.exists():
                    # Prepend a newline only for a complete file start. The
                    # reader returns a tail; losing its first complete record
                    # is preferable to treating a partial record as evidence.
                    profile['sample'] = latest_sample(read(sample_path, 65536, True), manifest['probe_id'])
                    if profile['sample'] is not None:
                        break
            result['profiles'].append(profile)
    if manager._active() != active or any(os.path.lexists(manager.root / name) for name in ('upgrade.json', 'uninstall.json')):
        raise ConfigError('local observation changed')
    return result
