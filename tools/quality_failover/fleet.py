"""Bounded two-device receiver credentials; administrator publication only."""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import tempfile
from .persistent import checked_file, config, root_check

MAX_DEVICES = 2
DEVICE_MINUTE_BYTES = 2097152


def account_id(name, device):
    if any(type(v) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,31}', v) for v in (name, device)):
        raise ValueError('binding')
    return hashlib.sha256((name + '\0' + device).encode('ascii')).hexdigest()


def validate_accounts(value, legacy):
    if (type(value) is not dict or not 1 <= len(value) <= MAX_DEVICES + 1
            or len(set(value.values())) > MAX_DEVICES
            or hashlib.sha256(legacy.encode('ascii')).hexdigest() not in value):
        raise ValueError('receiver_accounts')
    for key, account in value.items():
        if any(type(v) is not str or not re.fullmatch(r'[0-9a-f]{64}', v) for v in (key, account)):
            raise ValueError('receiver_accounts')
    return value


def prepare(root, bindings, previous=None):
    """No write: retain exact device tokens from a validated previous publication."""
    root = root_check(root)
    cfg = config(root)
    if type(bindings) is not list or not 1 <= len(bindings) <= MAX_DEVICES:
        raise ValueError('receiver_capacity')
    ids = [account_id(row['name'], row['device']) for row in bindings]
    if len(set(ids)) != len(ids):
        raise ValueError('binding')
    previous = previous or {}
    pairs, accounts = {}, {}
    ca = checked_file(root / 'receiver-ca.pem')
    authority = hashlib.sha256(ca).hexdigest()
    host = '[' + cfg['address'] + ']' if ':' in cfg['address'] else cfg['address']
    for row, ident in zip(bindings, ids):
        old = previous.get(ident)
        if old is not None and (old.get('certificate') != ca.decode('ascii') or old['info'].get('endpoint') != 'https://%s:%d' % (host,cfg['port'])):
            raise ValueError('receiver_binding')
        token = old['info']['token'] if old is not None else secrets.token_hex(32)
        if not re.fullmatch(r'[0-9a-f]{64}', token):
            raise ValueError('receiver_accounts')
        pairs[ident] = {'v': 1, 'name': row['name'], 'device': row['device'],
                        'info': {'v': 1, 'endpoint': 'https://%s:%d' % (host, cfg['port']),
                                 'token': token, 'certificate_sha256': authority},
                        'certificate': ca.decode('ascii')}
        accounts[hashlib.sha256(token.encode()).hexdigest()] = ident
    # Existing operator's old pair remains valid, sharing its new device's quota.
    # This is a compatibility alias, never a credential distributed to coworkers.
    legacy_digest = hashlib.sha256(cfg['token'].encode()).hexdigest()
    old_accounts = cfg.get('accounts', {})
    legacy_owner = old_accounts.get(legacy_digest, ids[0])
    if legacy_owner not in ids:
        raise ValueError('legacy_owner_removed')
    accounts[legacy_digest] = legacy_owner
    validate_accounts(accounts, cfg['token'])
    updated = dict(cfg, v=2, accounts=accounts)
    return updated, pairs


def activate(root, value):
    root = root_check(root)
    old = config(root)
    if any(value.get(k) != old[k] for k in ('address', 'port', 'token', 'minute_bytes')):
        raise ValueError('receiver_binding')
    validate_accounts(value.get('accounts'), old['token'])
    fd, name = tempfile.mkstemp(prefix='.accounts-', dir=root)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(json.dumps(value).encode()); stream.flush(); os.fsync(stream.fileno())
        os.replace(name, root / 'receiver.json')
    finally:
        Path(name).unlink(missing_ok=True)
