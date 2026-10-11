"""Native root publication, peer-authenticated device export and private HTTP package."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import sys
import threading
import unittest
import zipfile
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'monitor-v2'),str(ROOT/'tests/remote-production')]
from test_bundle_linux import BundleLinuxTests
from quality_failover import persistent
from quality_failover.receiver import Server
from web import quality_distribution as distribution
spec=importlib.util.spec_from_file_location('quality_publish',ROOT/'tools/publish-quality-windows.py')
publisher=importlib.util.module_from_spec(spec);spec.loader.exec_module(publisher)


@unittest.skipUnless(os.name=='posix' and os.geteuid()==0,'native root fixture only')
class QualityDownloadTests(BundleLinuxTests):
    def setUp(self):
        super().setUp()
        self.distribution=self.root/'quality-publication'
        self.source=self.root/'quality-software';self.source.mkdir(mode=0o755)
        self.exe=b'synthetic signed executable fixture, not an Authenticode claim'
        notices=b'synthetic licenses'
        meta={'v':1,'publisher':distribution.PUBLISHER,'software':publisher.record(self.exe),'notices':publisher.record(notices)}
        for name,raw in (('quality.exe',self.exe),('notices.txt',notices),('software.json',publisher.canonical(meta))):
            p=self.source/name;p.write_bytes(raw);p.chmod(0o644)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        self.receiver_state=self.root/'quality-receiver'
        persistent.init(self.receiver_state,'127.0.0.1',port)
        self.receiver=None;self.receiver_thread=None
        self.addCleanup(self.close_receiver)
        self.bindings=[{'name':'event-pc','device':'laptop-01'}]
        real_active=publisher.active_bindings
        def active(bindings):return real_active(bindings,Path(self.env['SB_P6_STATE_DIR'])/'devices.json')
        with patch.object(publisher,'active_bindings',side_effect=active):
            self.published=publisher.publish(self.source,self.bindings,root=str(self.distribution),
                                             state=str(self.receiver_state),restart=self.restart_receiver)
        self.app.quality_distribution=lambda name,device:distribution.recipient(name,device,str(self.distribution))

    def close_receiver(self):
        if self.receiver is not None:
            self.receiver.shutdown();self.receiver.server_close();self.receiver_thread.join(3);self.receiver=None

    def restart_receiver(self):
        self.close_receiver()
        value=persistent.config(self.receiver_state)
        context=persistent.validate_leaf(self.receiver_state,self.receiver_state/'server-cert.pem')
        self.receiver=Server(('127.0.0.1',value['port']),value['token'],context,value['minute_bytes'],accounts=value.get('accounts'))
        self.receiver_thread=threading.Thread(target=self.receiver.serve_forever,daemon=True);self.receiver_thread.start()

    def download(self,**kwargs):return self.http(path='/api/v1/clients/quality-bundle',**kwargs)

    def test_quality_zip_authorized_bound_device_and_generic_exe(self):
        status,headers,raw=self.download()
        self.assertEqual(status,200,raw)
        self.assertEqual(int(headers['Content-Length']),len(raw));self.assertIn('no-store',headers['Cache-Control'])
        self.assertIn('client.bundle',self.calls)
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            self.assertEqual(archive.read('质量切换.exe'),self.exe)
            info=json.loads(archive.read('receiver-info.json'))
            self.assertNotEqual(info['token'],persistent.config(self.receiver_state)['token'])
            self.assertEqual(hashlib.sha256(archive.read('receiver-ca.pem')).hexdigest(),info['certificate_sha256'])
            descriptor=json.loads(archive.read('quality-package.json'))
            self.assertEqual(descriptor['client'],'event-pc')
            self.assertNotIn(self.row()['secret'].encode(),raw)
        cfg=persistent.config(self.receiver_state)
        self.assertEqual(self.receiver.authorize('Bearer '+info['token']),distribution.binding_id('event-pc','laptop-01'))
        self.assertEqual(cfg['v'],2)

    def test_quality_full_auth_gates_before_publication_io(self):
        with patch.object(self.app,'quality_distribution',side_effect=AssertionError('unauthorized publication I/O')):
            for status,kw in ((401,{'auth':False}),(403,{'csrf':False}),
                              (403,{'headers':{'Origin':'https://foreign.example'}})):
                self.assertEqual(self.download(**kw)[0],status)
            from web.e3_broker import BrokerUnavailable
            with patch.object(self.app.e3_broker,'require_export_ready',side_effect=BrokerUnavailable()):
                self.assertEqual(self.download()[0],503)
            self.app.auth.sessions.revoke_all_step_ups();self.assertEqual(self.download()[0],401)
        self.assertEqual(self.calls,[])

    def test_quality_wrong_device_tamper_and_revocation_refuse_export(self):
        self.assertEqual(self.download(body={'name':'event-pc','device':'not-prepared'})[0],503)
        self.assertNotIn('client.bundle',self.calls)
        cur=json.loads((self.distribution/'current.json').read_bytes())
        exe=self.distribution/'releases'/cur['release']/'quality.exe'
        old=exe.read_bytes();exe.write_bytes(b'tampered')
        self.assertEqual(self.download()[0],503);self.assertNotIn('client.bundle',self.calls)
        exe.write_bytes(old)
        result=self.call_worker('probe.revoke',name='event-pc',device='laptop-01',idempotency_key='quality-revoke-0001')
        self.assertTrue(result['ok'],result)
        self.assertNotEqual(self.download()[0],200)

    def test_quality_publication_retries_preserve_tokens_and_changed_device_refused(self):
        before=(self.receiver_state/'receiver.json').read_bytes()
        real_active=publisher.active_bindings
        def active(bindings):return real_active(bindings,Path(self.env['SB_P6_STATE_DIR'])/'devices.json')
        with patch.object(publisher,'active_bindings',side_effect=active):
            retry=publisher.publish(self.source,self.bindings,root=str(self.distribution),state=str(self.receiver_state),restart=self.restart_receiver)
            self.assertEqual(self.published,retry)
            with self.assertRaises(ValueError):publisher.publish(self.source,[{'name':'event-pc','device':'not-active'}],
                root=str(self.distribution),state=str(self.receiver_state),restart=self.restart_receiver)
        self.assertEqual((self.receiver_state/'receiver.json').read_bytes(),before)


def load_tests(loader,tests,pattern):
    return unittest.TestSuite(QualityDownloadTests(name) for name in QualityDownloadTests.__dict__ if name.startswith('test_quality_'))


if __name__=='__main__':unittest.main()
