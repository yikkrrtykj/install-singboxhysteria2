"""Reproduce executable /run fixture failure without changing host mounts.

Run as root in a disposable Linux CI runner. The shell step gives this process
a private mount namespace and a new noexec directory beneath /run.
"""
import errno
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_bundle_linux import BundleLinuxTests, fixtures


TARGET = 'test_real_rpc_http_zip_has_canonical_yaml_and_one_device_key'


class ClientFixtureExecTest(unittest.TestCase):
    def test_legacy_placement_fails_before_mutation_and_split_placement_works(self):
        runtime = Path(os.environ['P6_FIXTURE_NOEXEC_DIR'])
        self.assertTrue(os.statvfs(runtime).f_flag & os.ST_NOEXEC, 'isolated noexec mount required')
        print('fixture-mounts /run_noexec=%s temp_noexec=%s isolated_noexec=True' % (
            bool(os.statvfs('/run').f_flag & os.ST_NOEXEC),
            bool(os.statvfs(tempfile.gettempdir()).f_flag & os.ST_NOEXEC)), flush=True)

        # Exercise the legacy placement with the unchanged real worker and
        # the safe diagnostics. A setup failure must precede the RPC server.
        with patch.object(BundleLinuxTests, 'TEMP_DIR', runtime):
            BundleLinuxTests.setUpClass()
            try:
                old = BundleLinuxTests(TARGET)
                try:
                    with patch.object(fixtures.ProvisioningTests, 'new_client_fixture_exec_dir',
                                      lambda case: case.root):
                        with self.assertRaisesRegex(AssertionError, r'^client[.]add failed: ') as failed:
                            old.setUp()
                    detail = json.loads(str(failed.exception).split(': ', 1)[1])
                    self.assertEqual((detail['code'], detail['stage'], detail['transaction_entered']),
                                     ('E_INTERNAL', 'candidate', False))
                    self.assertEqual(detail['mock_check_exec'], {'errno': errno.EACCES})
                    self.assertEqual(detail['shim_systemctl_exec'], {'errno': errno.EACCES})
                    users = json.loads(old.proxy_config.read_text())['inbounds']
                    self.assertTrue(all([row['name'] for row in inbound['users']] == ['legacy']
                                        for inbound in users), 'legacy failure changed live fixture config')
                    print('legacy placement: E_INTERNAL at candidate, EACCES, no mutation', flush=True)
                finally:
                    self.assertTrue(old.doCleanups(), 'legacy fixture cleanup failed')

                fixed = BundleLinuxTests(TARGET)
                try:
                    fixed.setUp()
                    self.assertEqual(fixed.root.parent, runtime)
                    self.assertTrue(os.statvfs(fixed.socket).f_flag & os.ST_NOEXEC)
                    self.assertFalse(os.statvfs(fixed.helper).f_flag & os.ST_NOEXEC)
                    getattr(fixed, TARGET)()
                    print('split placement: real worker, Unix RPC and bundle HTTP passed', flush=True)
                finally:
                    self.assertTrue(fixed.doCleanups(), 'split fixture cleanup failed')
            finally:
                BundleLinuxTests.tearDownClass()


if __name__ == '__main__':
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise SystemExit('mandatory Linux root fixture')
    unittest.main(verbosity=2)
