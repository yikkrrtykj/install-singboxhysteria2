#!/usr/bin/env python3
"""Root-only publication of locally signed software and two prepared device pairs."""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import ssl

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'monitor-v2'),str(ROOT/'tools')]
from web import quality_distribution as distribution
from quality_failover import fleet, persistent


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':')).encode()


def record(raw):
    return {'sha256':hashlib.sha256(raw).hexdigest(),'size':len(raw)}


def write(path,raw,mode=0o644,gid=0):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    try:
        os.fchown(fd,0,gid);os.fchmod(fd,mode)
        with os.fdopen(fd,'wb',closefd=False) as stream:
            stream.write(raw);stream.flush();os.fsync(stream.fileno())
    finally:os.close(fd)


def wait_receiver_ready(state):
    """systemd active precedes socket readiness; never bypass TLS/auth checks."""
    deadline=time.monotonic()+10
    while True:
        try:return persistent.check(state)
        except ssl.SSLError:raise
        except OSError:
            if time.monotonic()>=deadline:raise
            time.sleep(.5)


def active_bindings(bindings, path='/var/lib/sbox-cm/p6/devices.json'):
    raw=persistent.checked_file(path,2*1024*1024)
    state=distribution.object_json(raw)
    if type(state) is not dict or state.get('v') != 1 or type(state.get('records')) is not list:
        raise ValueError('device_registry')
    for binding in bindings:
        distribution.binding_id(binding['name'],binding['device'])
        rows=[row for row in state['records'] if row.get('name')==binding['name'] and row.get('device')==binding['device']
              and row.get('desired')=='active' and row.get('verified')=='active']
        if len(rows)!=1:raise ValueError('device_not_active')


def previous(root):
    if not (root/'current.json').exists():return {}
    cur=distribution.object_json(distribution.read(root/'current.json',1024))
    if set(cur)!={'v','release'} or not distribution.HEX.fullmatch(cur['release']):raise ValueError('publication')
    base=root/'releases'/cur['release']
    raw=distribution.read(base/'release.json',16384)
    if record(raw)['sha256']!=cur['release']:raise ValueError('publication')
    manifest=distribution.object_json(raw)
    pairs={}
    for ident in manifest['clients']:
        data=distribution.read(base/'clients'/(ident+'.json'),32768,True)
        if record(data)!=manifest['clients'][ident]:raise ValueError('publication')
        value=distribution.object_json(data)
        with distribution.recipient(value['name'],value['device'],str(root)):
            pairs[ident]=value
    return pairs


def publish(input_directory, bindings, *, root=distribution.ROOT, state='/etc/singbox-quality-receiver', restart=None):
    if os.name!='posix' or os.geteuid()!=0:raise ValueError('root_required')
    import fcntl,grp
    root=Path(root);source=Path(input_directory);state=Path(state)
    distribution.authority_directory(root.parent)
    if not root.exists():root.mkdir(mode=0o755);root.chmod(0o755)
    distribution.authority_directory(root)
    fd=os.open(root/'.publish.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'a+b') as lock:
        row=os.fstat(lock.fileno())
        if row.st_uid!=0 or row.st_nlink!=1 or not stat.S_ISREG(row.st_mode) or row.st_mode&0o077:
            raise ValueError('publish_lock')
        fcntl.flock(lock,fcntl.LOCK_EX)
        active_bindings(bindings)
        # Input must come from the local Windows signature-gated publication builder.
        # Linux verifies exact bytes and root authority; it does not claim Authenticode validation.
        meta=distribution.object_json(distribution.read(source/'software.json',16384))
        if set(meta)!={'v','publisher','software','notices'} or type(meta['v']) is not int or meta['v']!=1 or meta['publisher']!=distribution.PUBLISHER:
            raise ValueError('software')
        distribution.record_checked(meta['software'],16*1024*1024)
        distribution.record_checked(meta['notices'],65536)
        exe=distribution.read(source/'quality.exe',16*1024*1024)
        notices=distribution.read(source/'notices.txt',65536)
        if record(exe)!=meta['software'] or record(notices)!=meta['notices']:raise ValueError('software')
        cfg,pairs=fleet.prepare(state,bindings,previous(root))
        manifest=dict(meta,clients={ident:record(canonical(pair)) for ident,pair in pairs.items()})
        raw=canonical(manifest);release=record(raw)['sha256']
        releases=root/'releases'
        if not releases.exists():releases.mkdir(mode=0o755);releases.chmod(0o755)
        distribution.authority_directory(releases)
        target=releases/release
        if not target.exists():
            staging=Path(tempfile.mkdtemp(prefix='.staging-',dir=releases))
            try:
                staging.chmod(0o755)
                clients=staging/'clients';clients.mkdir(mode=0o750)
                gid=grp.getgrnam('sboxweb').gr_gid;os.chown(clients,0,gid);clients.chmod(0o750)
                write(staging/'quality.exe',exe);write(staging/'notices.txt',notices);write(staging/'release.json',raw)
                for ident,pair in pairs.items():write(clients/(ident+'.json'),canonical(pair),0o640,gid)
                os.rename(staging,target)
            finally:
                if staging.exists():shutil.rmtree(staging)
        else:
            if distribution.read(target/'release.json',16384)!=raw:raise ValueError('publication')
        old=persistent.checked_file(state/'receiver.json')
        old_pointer=distribution.read(root/'current.json',1024) if (root/'current.json').exists() else None
        def pointer(value):
            fd,temporary=tempfile.mkstemp(prefix='.pointer-',dir=root);os.close(fd);Path(temporary).unlink()
            try:write(temporary,value);os.replace(temporary,root/'current.json')
            finally:Path(temporary).unlink(missing_ok=True)
        try:
            fleet.activate(state,cfg)
            if restart is None:
                subprocess.run(['systemctl','restart',persistent.SERVICE],check=True,timeout=30,
                               stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            else:restart()
            wait_receiver_ready(state)
            pointer(canonical({'v':1,'release':release}))
            for pair in pairs.values():
                with distribution.recipient(pair['name'],pair['device'],str(root)):pass
        except BaseException:
            fd,temp=tempfile.mkstemp(prefix='.rollback-',dir=state)
            with os.fdopen(fd,'wb') as stream:stream.write(old);stream.flush();os.fsync(stream.fileno())
            os.replace(temp,state/'receiver.json')
            if old_pointer is None:(root/'current.json').unlink(missing_ok=True)
            else:pointer(old_pointer)
            if restart is None:subprocess.run(['systemctl','restart',persistent.SERVICE],check=True,timeout=30)
            else:restart()
            raise
        return {'published':True,'prepared_devices':len(bindings),'capacity':2,'per_device_bytes_per_minute':2097152,
                'global_bytes_per_minute':cfg['minute_bytes'],'release':release,'publisher':meta['publisher']}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input',required=True);parser.add_argument('--bindings',required=True)
    args=parser.parse_args()
    try:
        bindings=distribution.object_json(persistent.checked_file(args.bindings,16384))
        print(json.dumps(publish(args.input,bindings)))
    except Exception as error:
        code=type(error).__name__
        if isinstance(error,OSError) and type(error.errno) is int:code+=':'+str(error.errno)
        print('[FAIL] Quality publication incomplete; error_type='+code+'; private values not displayed',file=sys.stderr);return 1
    return 0


if __name__=='__main__':raise SystemExit(main())
