#!/usr/bin/env python3
"""Hermetic real-OpenSSL/TLS tests; no service, trust, live Clash or remote host."""
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch, Mock

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from quality_failover import persistent
from quality_failover.pilot import receiver_info
from quality_failover.receiver import Server

OPENSSL=os.environ.get('P48_TEST_OPENSSL','openssl')


class PersistentTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='p48-persistent-test-')
        self.root=Path(self.temp.name)/'receiver'
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0));self.port=sock.getsockname()[1]
        persistent.init(self.root,'127.0.0.1',self.port,OPENSSL)

    def tearDown(self):
        self.temp.cleanup()

    def test_existing_state_is_never_replaced(self):
        before=(self.root/'receiver.json').read_bytes()
        with self.assertRaises(ValueError): persistent.init(self.root,'127.0.0.1',self.port,OPENSSL)
        self.assertEqual(before,(self.root/'receiver.json').read_bytes())

    def test_client_pair_is_compatible_without_system_trust(self):
        info=receiver_info(self.root/'receiver-info.json',self.root/'receiver-ca.pem')
        self.assertEqual(info['endpoint'],'https://127.0.0.1:%d'%self.port)
        self.assertEqual(len(info['token']),64)
        self.assertEqual(info['certificate_sha256'],hashlib.sha256((self.root/'receiver-ca.pem').read_bytes()).hexdigest())
        persistent.validate_leaf(self.root,self.root/'server-cert.pem',OPENSSL)

    def test_fresh_cert_no_renew_and_no_identity_changes(self):
        files=['receiver-ca.pem','receiver-info.json','receiver.json','server-key.pem','server-cert.pem']
        before={name:(self.root/name).read_bytes() for name in files}
        self.assertEqual(persistent.renew(self.root,OPENSSL),{'renewed':False})
        self.assertEqual(before,{name:(self.root/name).read_bytes() for name in files})

    def test_renewed_leaf_works_with_original_client_ca_and_token(self):
        names=['receiver-ca.pem','receiver-info.json','receiver.json','server-key.pem']
        before={name:(self.root/name).read_bytes() for name in names}
        leaf=(self.root/'server-cert.pem').read_bytes()
        self.assertTrue(persistent.renew(self.root,OPENSSL,force=True)['renewed'])
        self.assertNotEqual(leaf,(self.root/'server-cert.pem').read_bytes())
        self.assertEqual(before,{name:(self.root/name).read_bytes() for name in names})
        cfg=persistent.config(self.root)
        context=persistent.validate_leaf(self.root,self.root/'server-cert.pem',OPENSSL)
        server=Server(('127.0.0.1',self.port),cfg['token'],context)
        worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
        try:
            self.assertEqual(persistent.check(self.root),{'receiver_tls_and_token_verified':True})
        finally:
            server.shutdown();server.server_close();worker.join()

    def test_failed_restart_retries_without_rotating_identity_or_leaf_again(self):
        before=(self.root/'receiver-info.json').read_bytes()
        failed=Mock(side_effect=RuntimeError('restart failed'))
        with self.assertRaises(RuntimeError):
            persistent.renew(self.root,OPENSSL,force=True,restart=failed)
        leaf=(self.root/'server-cert.pem').read_bytes()
        self.assertTrue((self.root/'restart-needed').is_file())
        retry=Mock()
        self.assertEqual(persistent.renew(self.root,OPENSSL,restart=retry),{'renewed':False})
        retry.assert_called_once_with()
        self.assertFalse((self.root/'restart-needed').exists())
        self.assertEqual(leaf,(self.root/'server-cert.pem').read_bytes())
        self.assertEqual(before,(self.root/'receiver-info.json').read_bytes())

    def test_expired_leaf_can_be_replaced(self):
        # The actual OpenSSL -days 0 leaf is expired, not a mocked clock verdict.
        with patch.object(persistent,'LEAF_DAYS',0), patch.object(persistent,'validate_leaf'):
            expired=persistent.issue_leaf(self.root,OPENSSL)
        (self.root/'server-cert.pem').write_bytes(expired)
        time.sleep(1.1)
        with self.assertRaises(ValueError):
            persistent.validate_leaf(self.root,self.root/'server-cert.pem',OPENSSL)
        self.assertTrue(persistent.renew(self.root,OPENSSL)['renewed'])
        persistent.validate_leaf(self.root,self.root/'server-cert.pem',OPENSSL)

    def test_wrong_ip_and_wrong_key_refused(self):
        cfg=json.loads((self.root/'receiver.json').read_bytes());cfg['address']='127.0.0.2'
        (self.root/'receiver.json').write_text(json.dumps(cfg),'utf-8')
        with self.assertRaises(ValueError): persistent.validate_leaf(self.root,self.root/'server-cert.pem',OPENSSL)
        cfg['address']='127.0.0.1';(self.root/'receiver.json').write_text(json.dumps(cfg),'utf-8')
        (self.root/'server-key.pem').write_bytes((self.root/'authority-key.pem').read_bytes())
        with self.assertRaises(ssl.SSLError): persistent.validate_leaf(self.root,self.root/'server-cert.pem',OPENSSL)

    def test_authority_identity_tamper_refused(self):
        leaf=(self.root/'server-cert.pem').read_bytes()
        meta=json.loads((self.root/'installation.json').read_bytes());meta['authority_sha256']='0'*64
        (self.root/'installation.json').write_text(json.dumps(meta),'utf-8')
        with self.assertRaises(ValueError):persistent.renew(self.root,OPENSSL,force=True)
        self.assertEqual(leaf,(self.root/'server-cert.pem').read_bytes())

    def test_failed_issuance_keeps_working_certificate_and_pair(self):
        before={name:(self.root/name).read_bytes() for name in ('server-cert.pem','receiver-info.json','receiver-ca.pem')}
        with patch.object(persistent,'issue_leaf',side_effect=ValueError('certificate_operation')):
            with self.assertRaises(ValueError):persistent.renew(self.root,OPENSSL,force=True)
        self.assertEqual(before,{name:(self.root/name).read_bytes() for name in before})

    def test_runtime_credentials_do_not_need_authority_private_key(self):
        credentials=Path(self.temp.name)/'credentials';credentials.mkdir(mode=0o700)
        for name in ('receiver.json','receiver-ca.pem','server-key.pem','server-cert.pem'):
            persistent.private_write(credentials/name,(self.root/name).read_bytes())
        persistent.validate_leaf(credentials,credentials/'server-cert.pem',OPENSSL)
        self.assertFalse((credentials/'authority-key.pem').exists())

    def test_invalid_configuration_is_closed(self):
        for change in ({'minute_bytes':999999999},{'port':True},{'address':'0.0.0.0'},{'token':'x'*64},{'extra':'unknown'}):
            original=json.loads((self.root/'receiver.json').read_bytes())
            altered=dict(original,**change);(self.root/'receiver.json').write_text(json.dumps(altered),'utf-8')
            with self.assertRaises(ValueError):persistent.config(self.root)
            (self.root/'receiver.json').write_text(json.dumps(original),'utf-8')

    def test_closed_secret_file_and_duplicate_json_refused(self):
        path=self.root/'receiver.json'
        path.write_bytes(b'{"v":1,"v":1}')
        with self.assertRaises(ValueError):persistent.config(self.root)
        path.write_bytes(b'x'*16385)
        with self.assertRaises(ValueError):persistent.config(self.root)


if __name__=='__main__':unittest.main(verbosity=2)
