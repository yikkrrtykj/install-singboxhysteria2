import importlib.util
from pathlib import Path
import ssl
import unittest
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('publication',Path(__file__).resolve().parents[1]/'tools/publish-quality-windows.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
class StartupTests(unittest.TestCase):
    def test_delayed_socket_must_pass_full_receipt_check(self):
        with patch.object(p.persistent,'check',side_effect=[ConnectionRefusedError(111,'refused'),ConnectionRefusedError(111,'refused'),{'verified':True}]) as check,patch.object(p.time,'sleep'):
            self.assertEqual(p.wait_receiver_ready('/fixture'),{'verified':True})
            self.assertEqual(check.call_count,3)
    def test_authentication_and_tls_failures_are_not_retried(self):
        for error in (ValueError('readiness_receipt'),ssl.SSLError('certificate')):
            with self.subTest(error=type(error)),patch.object(p.persistent,'check',side_effect=error) as check,patch.object(p.time,'sleep') as sleep:
                with self.assertRaises(type(error)):p.wait_receiver_ready('/fixture')
                self.assertEqual(check.call_count,1);sleep.assert_not_called()
    def test_readiness_timeout_is_not_success(self):
        with patch.object(p.persistent,'check',side_effect=ConnectionRefusedError(111,'refused')),patch.object(p.time,'monotonic',side_effect=[0,11]),patch.object(p.time,'sleep') as sleep:
            with self.assertRaises(ConnectionRefusedError):p.wait_receiver_ready('/fixture')
            sleep.assert_not_called()
if __name__=='__main__':unittest.main()
