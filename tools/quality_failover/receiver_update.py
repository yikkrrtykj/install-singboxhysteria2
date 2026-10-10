"""Explicit receiver-pair migration of an idle private bundle; live groups are read-only."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
from .config import client
from .daily import load_bundle, WorkerLock, IdentifiedController, directory_check
from .pilot import receiver_info


def atomic_bytes(path,data):
    fd,name=tempfile.mkstemp(prefix='.receiver-update-',dir=path.parent)
    temporary=Path(name)
    try:
        with os.fdopen(fd,'wb') as handle:
            handle.write(data);handle.flush();os.fsync(handle.fileno())
        os.replace(temporary,path)
    finally:
        temporary.unlink(missing_ok=True)


def update_receiver(bundle,info_path,home):
    bundle=Path(bundle);info_path=Path(info_path)
    directory_check(bundle.parent)
    lock=WorkerLock(bundle.parent/'worker.lock')
    lock.acquire()
    try:
        meta,old=load_bundle(bundle,home)
        ca=info_path.with_name('receiver-ca.pem')
        info=receiver_info(info_path,ca)
        candidate=json.loads(json.dumps(old))
        for entry in candidate['paths']:
            entry.update(endpoint=info['endpoint'],token=info['token'],ca_file=str(ca))
        engine,probes,ports,_=client(candidate)
        controller=IdentifiedController(old['controller'],old['controller_secret'],meta['marker'],meta['nodes'])
        controller.proxies() # refuses a foreign/unloaded profile before any upload or file change
        for index,name in enumerate(engine.paths):
            probe=probes[name]
            result=probe.measure(ports[name],verifier=lambda source_port,n=name,i=index,p=probe:
                controller.confirm_route(n,'quality-probe-%d'%i,source_port,p.host,p.port))
            if result.verdict(engine.policies[name])!='good':
                raise ValueError('receiver_not_confirmed')
        target_ca=bundle.parent/'receiver-ca.pem'
        saved={key:value for key,value in candidate.items() if key not in ('controller','controller_secret')}
        for entry in saved['paths']:entry['ca_file']=str(target_ca)
        changed_meta=dict(meta,certificate_sha256=hashlib.sha256(ca.read_bytes()).hexdigest())
        files={target_ca:ca.read_bytes(),bundle.parent/'client.json':json.dumps(saved).encode(),
               bundle:json.dumps(changed_meta).encode()}
        originals={path:path.read_bytes() for path in files}
        written=[]
        try:
            for path,data in files.items():
                atomic_bytes(path,data);written.append(path)
            load_bundle(bundle,home)
        except BaseException:
            for path in reversed(written):atomic_bytes(path,originals[path])
            raise
        return {'receiver_updated':True,'all_paths_upload_confirmed':True,'profile_preserved':True,
                'clash_groups_changed':False,'windows_startup_changed':False}
    finally:
        lock.close()
