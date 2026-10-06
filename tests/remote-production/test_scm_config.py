"""SCM configuration ownership policy without touching installed services."""
import ctypes
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'monitor-v2'))
sys.path.insert(0, str(ROOT / 'windows'))
from p6installer.scm import Config, Service
from remote_probe.agent import ConfigError


class ConfigurationTests(unittest.TestCase):
    def service(self, start=2, **changes):
        config = Config(kind=0x10, start=start, error=1,
                        binary='trusted exact command', group='', dependencies='',
                        account='LocalSystem', display='fixture')
        for key, value in changes.items():
            setattr(config, key, value)
        service = object.__new__(Service)
        service.a = Mock()
        service._buffer = Mock(return_value=ctypes.pointer(config))
        service._acl = Mock()
        return service

    def test_auto_and_manual_pass_the_same_ownership_validation(self):
        for mode in (2, 3):
            with self.subTest(mode=mode):
                service = self.service(mode)
                self.assertEqual(service._config('handle', 'trusted exact command'), mode)
                service._acl.assert_called_once_with('handle')

    def test_disabled_boot_system_and_unknown_modes_still_refuse(self):
        for mode in (0, 1, 4, 5, 0xffffffff):
            with self.subTest(mode=mode):
                with self.assertRaises(ConfigError):
                    self.service(mode)._config('handle', 'trusted exact command')

    def test_manual_does_not_relax_image_account_kind_or_dependencies(self):
        for changes in ({'binary': 'foreign command'}, {'account': 'LocalService'},
                        {'kind': 0x20}, {'dependencies': 'foreign'}, {'group': 'foreign'}):
            with self.subTest(changes=changes):
                with self.assertRaises(ConfigError):
                    self.service(3, **changes)._config('handle', 'trusted exact command')

    def test_manual_does_not_relax_acl_failure(self):
        service = self.service(3)
        service._acl.side_effect = ConfigError('unowned service ACL')
        with self.assertRaises(ConfigError):
            service._config('handle', 'trusted exact command')


if __name__ == '__main__':
    unittest.main(verbosity=2)
