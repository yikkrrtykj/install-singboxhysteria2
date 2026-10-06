"""SCM configuration ownership policy without touching installed services."""
import ctypes
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'monitor-v2'))
sys.path.insert(0, str(ROOT / 'windows'))
from p6installer.scm import Config, Service
from p6installer.manager import Manager
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


class StartupTests(unittest.TestCase):
    def service(self, modes=(2, 3)):
        service = object.__new__(Service)
        service.a = Mock()
        service._open = Mock(return_value=('scm', 'handle'))
        service._close = Mock()
        service._config = Mock(side_effect=modes)
        return service

    def test_only_start_type_changes_with_verified_readback(self):
        service = self.service()
        self.assertIs(service.set_autostart('exact command', False), False)
        service.a.ChangeServiceConfigW.assert_called_once_with('handle',
            0xffffffff, 3, 0xffffffff, None, None, None, None, None, None, None)
        service._close.assert_called_once_with('scm', 'handle')
        service.a.StartServiceW.assert_not_called()
        service.a.ControlService.assert_not_called()

    def test_noop_and_refused_configuration_never_mutate(self):
        service = self.service((2, 2))
        self.assertIs(service.set_autostart('exact command', True), True)
        service.a.ChangeServiceConfigW.assert_not_called()
        for enabled in (None, 0, 1, 'on'):
            with self.assertRaises(ConfigError):
                service.set_autostart('exact command', enabled)
        service = self.service()
        service._config.side_effect = ConfigError('unowned service')
        with self.assertRaises(ConfigError):
            service.set_autostart('foreign', False)
        service.a.ChangeServiceConfigW.assert_not_called()

    def test_failed_write_and_mismatched_readback_are_not_success(self):
        service = self.service()
        service.a.ChangeServiceConfigW.return_value = False
        with self.assertRaises(ConfigError):
            service.set_autostart('exact command', False)
        service._close.assert_called_once()
        with self.assertRaises(ConfigError):
            self.service((2, 2)).set_autostart('exact command', False)

    def test_manager_refuses_pending_recovery_before_service_access(self):
        with tempfile.TemporaryDirectory() as directory:
            manager = object.__new__(Manager)
            manager.root = Path(directory)
            manager.service = Mock()
            manager._lock = Mock(return_value=Mock())
            manager._active = Mock(return_value='a'*64)
            manager._check_release = Mock()
            manager._command = Mock(return_value='exact command')
            for name in ('upgrade.json', 'uninstall.json'):
                marker = manager.root/name
                marker.write_bytes(b'pending operation')
                with self.assertRaises(ConfigError):
                    manager.set_autostart(False)
                self.assertEqual(marker.read_bytes(), b'pending operation')
                marker.unlink()
            manager.service.set_autostart.assert_not_called()
            manager._active.assert_not_called()
            manager.service.start_mode.return_value = 3
            manager.service.state.return_value = 1
            self.assertEqual(manager.set_autostart(False), {'autostart': False, 'service_state': 1})
            manager.service.stop.assert_not_called()
            manager.service.start.assert_not_called()
            manager._lock.return_value.release.assert_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
