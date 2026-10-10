"""Receiver migration contracts: no live controller or receiver is contacted."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from quality_failover import receiver_update, daily
from quality_failover.policy import Confirmation
spec=importlib.util.spec_from_file_location('daily_fixture',ROOT/'tests/test_quality_daily.py')
fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)

class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)
        self.tls=patch('quality_failover.transport.ssl.create_default_context');self.tls.start()
        self.bundle,self.home,self.original,_,_=fixture.BundleTests().build(self.root)
        connection=self.root/'new-connection';connection.mkdir(mode=0o700)
        ca=connection/'receiver-ca.pem';ca.write_bytes(b'new-synthetic-ca')
        self.info=connection/'receiver-info.json'
        self.info.write_text(json.dumps({'v':1,'endpoint':'https://127.0.0.1:19444','token':'n'*32,
            'certificate_sha256':hashlib.sha256(ca.read_bytes()).hexdigest()}),'utf-8');self.info.chmod(0o600)
        self.originals={p:p.read_bytes() for p in (self.bundle,self.bundle.parent/'client.json',
            self.bundle.parent/'receiver-ca.pem',self.original,self.home/'clash-verge.yaml',
            self.bundle.parent/json.loads(self.bundle.read_bytes())['profile'])}
        self.controller=Mock()
        self.controller_patch=patch.object(receiver_update,'IdentifiedController',return_value=self.controller)
        self.controller_patch.start()
        self.measure=patch('quality_failover.transport.Probe.measure',return_value=Confirmation(12,endpoint_ready=True))
        self.probe=self.measure.start()

    def tearDown(self):
        self.measure.stop();self.controller_patch.stop();self.tls.stop();self.temp.cleanup()

    def assert_unchanged(self):
        self.assertEqual(self.originals,{p:p.read_bytes() for p in self.originals})

    def test_all_paths_confirm_before_migration_original_profile_and_choices_preserved(self):
        result=receiver_update.update_receiver(self.bundle,self.info,self.home)
        self.assertTrue(result['all_paths_upload_confirmed'])
        self.assertFalse(result['clash_groups_changed'])
        self.assertEqual(self.probe.call_count,2)
        self.assertEqual([call[0] for call in self.controller.method_calls],['proxies'])
        meta,cfg=daily.load_bundle(self.bundle,self.home)
        for entry in cfg['paths']:self.assertEqual(entry['endpoint'],'https://127.0.0.1:19444')
        self.assertNotIn('controller_secret',json.loads((self.bundle.parent/'client.json').read_bytes()))
        for p in (self.original,self.home/'clash-verge.yaml',self.bundle.parent/meta['profile']):
            self.assertEqual(p.read_bytes(),self.originals[p])

    def test_unconfirmed_or_slow_path_keeps_old_pair(self):
        for confirmation in (Confirmation(),Confirmation(1,endpoint_ready=True)):
            self.probe.side_effect=[Confirmation(12,endpoint_ready=True),confirmation]
            with self.assertRaises(ValueError):receiver_update.update_receiver(self.bundle,self.info,self.home)
            self.assert_unchanged()

    def test_foreign_profile_refuses_before_upload_or_file_write(self):
        self.controller.proxies.side_effect=ValueError('foreign_profile')
        with self.assertRaises(ValueError):receiver_update.update_receiver(self.bundle,self.info,self.home)
        self.probe.assert_not_called();self.assert_unchanged()

    def test_running_worker_refuses_before_any_probe(self):
        lock=daily.WorkerLock(self.bundle.parent/'worker.lock');lock.acquire()
        try:
            with self.assertRaises(ValueError):receiver_update.update_receiver(self.bundle,self.info,self.home)
            self.probe.assert_not_called();self.assert_unchanged()
        finally:lock.close()

    def test_ca_pair_mismatch_refuses_without_changing_bundle(self):
        self.info.with_name('receiver-ca.pem').write_bytes(b'wrong-ca')
        with self.assertRaises(ValueError):receiver_update.update_receiver(self.bundle,self.info,self.home)
        self.probe.assert_not_called();self.assert_unchanged()

    def test_failed_second_save_rolls_back_the_first(self):
        real=receiver_update.atomic_bytes
        calls=0
        def write(path,data):
            nonlocal calls
            calls+=1
            if calls==2:raise OSError('synthetic write fault')
            real(path,data)
        with patch.object(receiver_update,'atomic_bytes',side_effect=write):
            with self.assertRaises(OSError):receiver_update.update_receiver(self.bundle,self.info,self.home)
        self.assert_unchanged()

if __name__=='__main__':unittest.main(verbosity=2)
