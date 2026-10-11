"""Two-device receiver fairness and private recipient packaging contracts."""
import concurrent.futures
import hashlib
import http.client
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
import zipfile
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'monitor-v2')]
from quality_failover import fleet,persistent
from quality_failover.receiver import Server
from quality_failover.transport import Probe
from web import quality_distribution as distribution


def fixture_pair(name='event',device='laptop',token='a'*64):
    ca='-----BEGIN CERTIFICATE-----\nsynthetic\n-----END CERTIFICATE-----\n'
    return {'v':1,'name':name,'device':device,'info':{'v':1,'endpoint':'https://192.0.2.10:8449',
            'token':token,'certificate_sha256':hashlib.sha256(ca.encode()).hexdigest()},'certificate':ca}


class ReceiverFleetTests(unittest.TestCase):
    def setUp(self):
        self.a,self.b,self.old='a'*64,'b'*64,'c'*64
        self.accounts={hashlib.sha256(v.encode()).hexdigest():account for v,account in
                       ((self.a,'1'*64),(self.b,'2'*64),(self.old,'1'*64))}
        self.server=Server(('127.0.0.1',0),self.old,minute_bytes=4194304,accounts=self.accounts)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()

    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.thread.join(3)

    def request(self,token,size,headers_only=False):
        conn=http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=4)
        try:
            conn.request('POST','/quality-v1/upload',None if headers_only else b'\0'*size,
                         {'Authorization':'Bearer '+token,'X-Probe-Nonce':'f'*32,'Content-Length':str(size)})
            reply=conn.getresponse();reply.read(1025);return reply.status
        finally:conn.close()

    def test_simultaneous_distinct_devices_upload_then_isolate_budget(self):
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            self.assertEqual(list(pool.map(lambda token:self.request(token,1048576),(self.a,self.b))),[200,200])
        self.assertEqual(self.request(self.a,1048576),200)
        self.assertEqual(self.request(self.a,32768,True),429)
        self.assertEqual(self.request(self.old,32768,True),429) # compatibility alias has no extra quota
        self.assertEqual(self.request(self.b,1048576),200)
        self.assertEqual(self.request(self.b,32768,True),429)
        self.assertEqual(self.request('d'*64,32768,True),403)

    def test_one_upload_slot_per_device_and_release(self):
        gate=self.server.account_gates['1'*64]
        self.assertTrue(gate.acquire(blocking=False))
        try:self.assertEqual(self.request(self.a,32768,True),429)
        finally:gate.release()
        self.assertEqual(self.request(self.a,32768),200)
        self.assertTrue(gate.acquire(blocking=False));gate.release()

    def test_overloaded_receiver_is_unknown_not_fault(self):
        with patch('quality_failover.transport.ssl.create_default_context'):
            probe=Probe('https://192.0.2.10:8449',self.a,'synthetic-ca',524288,20,6)
        with patch.object(probe,'request',side_effect=ValueError('response')):
            verdict=probe.measure(19000)
        self.assertFalse(verdict.endpoint_ready)
        self.assertFalse(verdict.timed_out)


class PairTests(unittest.TestCase):
    def test_independent_pairs_legacy_alias_and_retention(self):
        ca=b'synthetic authority'
        cfg={'v':1,'address':'192.0.2.10','port':8449,'token':'c'*64,'minute_bytes':4194304}
        bindings=[{'name':'event','device':'a'},{'name':'event','device':'b'}]
        with (patch.object(fleet,'root_check',return_value=Path('/fixture')),
              patch.object(fleet,'config',return_value=cfg),patch.object(fleet,'checked_file',return_value=ca)):
            updated,pairs=fleet.prepare('/fixture',bindings)
            again,retained=fleet.prepare('/fixture',bindings,pairs)
        self.assertEqual(updated,again);self.assertEqual(pairs,retained)
        self.assertEqual(len(updated['accounts']),3)
        self.assertEqual(len(set(updated['accounts'].values())),2)
        self.assertEqual(len({p['info']['token'] for p in pairs.values()}),2)
        self.assertNotIn(cfg['token'],{p['info']['token'] for p in pairs.values()})
        with self.assertRaises(ValueError):fleet.validate_accounts({**updated['accounts'],'d'*64:'3'*64},cfg['token'])

    def test_third_device_and_changed_authority_are_refused(self):
        cfg={'v':1,'address':'192.0.2.10','port':8449,'token':'c'*64,'minute_bytes':4194304}
        with patch.object(fleet,'root_check',return_value=Path('/fixture')),patch.object(fleet,'config',return_value=cfg):
            with self.assertRaises(ValueError):fleet.prepare('/fixture',[{'name':'event','device':str(n)} for n in range(3)])


class RecipientZipTests(unittest.TestCase):
    def software(self,raw=b'synthetic signed exe'):
        stream=io.BytesIO(raw);stream.quality_sha256=hashlib.sha256(raw).hexdigest();return stream

    def test_generic_exe_and_exact_adjacent_files_without_other_device_secrets(self):
        pair=fixture_pair()
        output,size=distribution.package(self.software(),pair,'synthetic canonical YAML','licenses'.encode())
        try:
            raw=output.read();self.assertEqual(len(raw),size)
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                self.assertEqual(set(archive.namelist()),{'质量切换.exe','event-mihomo.yaml','receiver-info.json',
                    'receiver-ca.pem','quality-package.json','先看这里.txt','第三方许可.txt'})
                self.assertEqual(archive.read('质量切换.exe'),b'synthetic signed exe')
                meta=json.loads(archive.read('quality-package.json'))
                for key,digest in meta['files'].items():self.assertEqual(hashlib.sha256(archive.read(key)).hexdigest(),digest)
                self.assertNotIn(b'operator-path',raw)
        finally:output.close()

    def test_tampered_software_and_pair_are_refused(self):
        software=self.software();software.quality_sha256='0'*64
        with self.assertRaises(distribution.QualityUnavailable):distribution.package(software,fixture_pair(),'yaml',b'license')
        pair=fixture_pair();pair['info']['certificate_sha256']='0'*64
        with self.assertRaises(distribution.QualityUnavailable):distribution.package(self.software(),pair,'yaml',b'license')
        with self.assertRaises(distribution.QualityUnavailable):distribution.binding_id('../escape','pc')
        with self.assertRaises(distribution.QualityUnavailable):distribution.object_json(b'{"v":1,"v":2}')


if __name__=='__main__':unittest.main()
