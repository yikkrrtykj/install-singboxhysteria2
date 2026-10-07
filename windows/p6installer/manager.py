"""Durable admin lifecycle. Constructor injection is isolated fixture wiring."""
import argparse
import base64
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import uuid

from remote_probe.agent import ConfigError
from remote_probe.production import incoming
from remote_probe.profiles import ProfileVault, canonical, durable_replace, profile_id
from remote_probe.spool import SpoolError, _InstanceLock
from remote_probe.windows_security import StorageSecurityError, WindowsSecurity
from .bundle import object_json, read_bundle, verify_controller, validate_display, discover_adjacent, DISPLAY_LIMIT
from .scm import Service
from .controller import DiscoveryError, discover_credential

MAX_RELEASE = 64 * 1024 * 1024
SERVICE = 'P6RemoteProbe'


def verify_signatures(package, publisher):
    """Trusted constant script: only base64 data, no untrusted script execution."""
    if not re.fullmatch(r'[0-9A-F]{40}', publisher):
        raise ConfigError('production publisher not configured')
    encoded = base64.b64encode(os.fspath(package).encode('utf-8')).decode('ascii')
    script = "$p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + encoded + "'));"
    script += "$ErrorActionPreference='Stop';$PSModuleAutoloadingPreference='None';try {"
    script += "foreach($m in @('Microsoft.PowerShell.Security','Microsoft.PowerShell.Management','Microsoft.PowerShell.Utility')) {"
    script += "Import-Module -Name ([IO.Path]::Combine($PSHOME,'Modules',$m,($m+'.psd1'))) -ErrorAction Stop};$PSModuleAutoloadingPreference='None';"
    script += "$files=@('Setup.ps1','payload.cat');if(Test-Path -LiteralPath (Join-Path $p 'P6Setup.exe')){$files+= 'P6Setup.exe'};"
    script += "foreach($f in $files) {$s=Get-AuthenticodeSignature -LiteralPath (Join-Path $p $f);"
    script += "if($s.Status -ne 'Valid' -or $s.SignerCertificate.Thumbprint -ne '" + publisher + "'){exit 2}};"
    script += "if((Test-FileCatalog -Path (Join-Path $p 'payload') -CatalogFilePath (Join-Path $p 'payload.cat')) -ne 'Valid'){exit 2};exit 0}catch{exit 2}"
    # Windows directory from a native API, never PATH/COMSPEC/PYTHONPATH/env.
    buffer = ctypes.create_unicode_buffer(32768)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.GetSystemDirectoryW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
    if not kernel.GetSystemDirectoryW(buffer, len(buffer)):
        raise ConfigError('system verifier unavailable')
    powershell = Path(buffer.value) / 'WindowsPowerShell/v1.0/powershell.exe'
    result = subprocess.run([str(powershell), '-NoProfile', '-NonInteractive', '-EncodedCommand',
                            base64.b64encode(script.encode('utf-16le')).decode('ascii')],
                            capture_output=True, timeout=60, creationflags=0x08000000)
    if result.returncode:
        raise ConfigError('release signature unavailable')


def validate_release(package, security):
    package = Path(package)
    security.validate(str(package), True)
    entries = set(os.listdir(package))
    if entries not in ({'Setup.ps1', 'payload.cat', 'payload'}, {'P6Setup.exe', 'Setup.ps1', 'payload.cat', 'payload'}):
        raise ConfigError('unexpected package files')
    security.validate(str(package / 'payload'), True)
    for name in ('Setup.ps1', 'payload.cat'):
        security.validate(str(package / name))
    raw = security.read(str(package / 'payload/release.json'), 32768)
    meta = object_json(raw)
    if type(meta) is not dict or set(meta) not in ({'v', 'release', 'runtime', 'artifact', 'files'},
                                                   {'v', 'release', 'runtime', 'artifact', 'files', 'entry'}) \
            or type(meta['v']) is not int or meta['v'] != 1 or meta['runtime'] != 'cpython-3.13.16-amd64' \
            or type(meta['files']) is not dict or not 4 <= len(meta['files']) <= 64:
        raise ConfigError('invalid release manifest')
    if 'entry' in meta:
        if meta['entry'] not in ('gui-v1', 'gui-v2') or 'P6Setup.exe' not in entries:
            raise ConfigError('invalid graphical release entry')
        security.validate(str(package / 'P6Setup.exe'))
    elif 'P6Setup.exe' in entries:
        raise ConfigError('unexpected graphical release entry')
    from p6_artifact import ArtifactError, validate_manifest
    try:
        validate_manifest(meta['artifact'])
    except ArtifactError:
        raise ConfigError('invalid release artifact') from None
    expected = hashlib.sha256(canonical({k: meta[k] for k in meta if k != 'release'})).hexdigest()
    if meta['release'] != expected:
        raise ConfigError('invalid release identity')
    total = len(raw)
    for name in sorted(entries - {'payload'}):
        total += len(security.read(str(package / name), 4 * 1024 * 1024))
    actual = set()
    for root, dirs, files in os.walk(package / 'payload', followlinks=False):
        security.validate(root, True)
        if len(dirs) + len(files) > 64:
            raise ConfigError('release capacity')
        for directory in dirs:
            security.validate(os.path.join(root, directory), True)
        for name in files:
            actual.add(Path(root, name).relative_to(package / 'payload').as_posix())
    if actual != set(meta['files']) | {'release.json'}:
        raise ConfigError('unexpected release files')
    required = {'runtime/python.exe', 'runtime/pythonw.exe', 'runtime/python313.dll',
                'runtime/python313.zip', 'runtime/python313._pth', 'p6-agent.pyz', 'p6-installer.pyz'}
    if not required <= set(meta['files']):
        raise ConfigError('incomplete release')
    for name, item in meta['files'].items():
        if not re.fullmatch(r'(runtime/[A-Za-z0-9_.-]+|p6-agent.pyz|p6-installer.pyz)', name) \
                or type(item) is not dict or set(item) != {'sha256', 'size'} \
                or type(item['size']) is not int or not 0 < item['size'] <= MAX_RELEASE \
                or type(item['sha256']) is not str or not re.fullmatch(r'[0-9a-f]{64}', item['sha256']):
            raise ConfigError('invalid release file')
        value = security.read(str(package / 'payload' / name), item['size'])
        total += len(value)
        if total > MAX_RELEASE or len(value) != item['size'] or hashlib.sha256(value).hexdigest() != item['sha256']:
            raise ConfigError('release digest mismatch')
    if meta['files']['p6-agent.pyz'] != {k: meta['artifact'][k] for k in ('sha256', 'size')}:
        raise ConfigError('Agent artifact mismatch')
    if security.read(str(package / 'payload/runtime/python313._pth'), 128) != b'python313.zip\n.\n../p6-agent.pyz\n../p6-installer.pyz\n':
        raise ConfigError('runtime isolation mismatch')
    return meta


class Manager:
    def __init__(self, root, service=None, security=None, signature_verifier=None, publisher=None):
        self.root = Path(root).absolute()
        self.security = security or WindowsSecurity()
        self.service = service or Service()
        self.publisher = publisher
        self.verifier = signature_verifier or verify_signatures
        self.vault = ProfileVault(str(self.root / 'profiles'), self.security)

    def open(self):
        self.security.mkdir(str(self.root))
        for name in ('profiles', 'retired', 'releases'):
            self.security.mkdir(str(self.root / name))
        return self

    def _write(self, path, value):
        path = Path(path)
        self.security.validate(str(path.parent), True)
        if path.exists():
            self.security.validate(str(path))
        temp = '.write-' + uuid.uuid4().hex
        self.vault._write(str(path.parent), temp, canonical(value))
        durable_replace(str(path.parent / temp), str(path))

    def _read(self, name):
        path = self.root / name
        if not path.exists():
            return None
        return object_json(self.security.read(str(path), 32768))

    def _id(self, value):
        if type(value) is not str or not re.fullmatch(r'[0-9a-f]{64}', value):
            raise ConfigError('invalid release selector')
        return value

    def _command(self, release):
        base = self.root / 'releases' / self._id(release) / 'payload'
        return subprocess.list2cmdline([str(base / 'runtime/python.exe'), '-I', '-B',
                    str(base / 'p6-agent.pyz'), '--vault', str(self.vault.root), 'service', '--name', self.service.name])

    def _active(self):
        value = self._read('active.json')
        if value is None:
            return None
        if type(value) is not dict or set(value) != {'v', 'release'} or value['v'] != 1:
            raise ConfigError('invalid installation state')
        return self._id(value['release'])

    def _check_release(self, release):
        path = self.root / 'releases' / self._id(release)
        self.verifier(path, self.publisher)
        meta = validate_release(path, self.security)
        if meta['release'] != release:
            raise ConfigError('installation identity mismatch')
        return meta

    def _slots(self):
        names = os.listdir(self.root / 'retired')
        if any(not re.fullmatch(r'[0-9a-f]{64}', name) for name in names):
            raise ConfigError('unknown retirement state')
        return len(self.vault.keys()) + len(names)

    def _copy(self, source, target):
        if target.exists():
            return validate_release(target, self.security)
        stage = target.parent / ('.stage-' + uuid.uuid4().hex)
        self.security.mkdir(str(stage))
        try:
            for current, dirs, files in os.walk(source, followlinks=False):
                self.security.validate(current, True)
                relative = Path(current).relative_to(source)
                destination = stage / relative
                self.security.validate(str(destination), True)
                for directory in dirs:
                    self.security.validate(str(Path(current) / directory), True)
                    self.security.mkdir(str(destination / directory))
                for name in files:
                    raw = self.security.read(str(Path(current) / name), MAX_RELEASE)
                    self.vault._write(str(destination), name, raw)
            meta = validate_release(stage, self.security)
            self.verifier(stage, self.publisher)
            durable_replace(str(stage), str(target))
            return meta
        except BaseException:
            # Failed unpublished staging is inert, never activated.
            raise

    def _recover(self):
        self._recover_uninstall()
        intent = self._read('upgrade.json')
        if intent is None:
            return
        if type(intent) is not dict or set(intent) != {'v', 'old', 'new'} or intent['v'] != 1:
            raise ConfigError('invalid upgrade intent')
        old, new = intent['old'], self._id(intent['new'])
        if old is not None:
            self._check_release(self._id(old))
        self._check_release(new)
        # The only acceptable in-flight configurations are this exact journal's
        # old/new commands. Never reconfigure a different service to recover.
        current = self._active()
        if current not in (old, new):
            raise ConfigError('upgrade state mismatch')
        try:
            exists = self.service.state(self._command(new))
            command = self._command(new)
        except ConfigError:
            if old is None:
                raise
            exists = self.service.state(self._command(old))
            command = self._command(old)
        if exists:
            self.service.stop(command)
        self.service.configure(self._command(new), previous=command if exists else None)
        if old is not None and old != new:
            self._write(self.root / 'previous.json', {'v': 1, 'release': old})
        self._write(self.root / 'active.json', {'v': 1, 'release': new})
        self.service.start(self._command(new))
        self.security.validate(str(self.root / 'upgrade.json'))
        os.unlink(self.root / 'upgrade.json')
        self._collect_releases()

    def _collect_releases(self):
        """Retain current and explicit rollback target. Profiles are separate."""
        keep = {self._active()}
        previous = self._read('previous.json')
        if previous is not None:
            if type(previous) is not dict or set(previous) != {'v', 'release'} or previous['v'] != 1:
                raise ConfigError('invalid previous release')
            keep.add(self._id(previous['release']))
        for name in os.listdir(self.root / 'releases'):
            if name in keep:
                continue
            if not re.fullmatch(r'[0-9a-f]{64}|\.stage-[0-9a-f]{32}', name):
                raise ConfigError('unknown release state')
            target = self.root / 'releases' / name
            self._tree(target)
            shutil.rmtree(target)

    def _recover_uninstall(self):
        intent = self._read('uninstall.json')
        if intent is None:
            return
        if type(intent) is not dict or set(intent) != {'v', 'release'} or intent['v'] != 1 \
                or self.vault.keys() or self._active() not in (None, intent['release']):
            raise ConfigError('invalid uninstall intent')
        command = self._command(self._id(intent['release']))
        self.service.stop(command)
        lease = _InstanceLock(str(Path(self.vault.root) / 'service.lock'))
        self.security.check_components(lease.path)
        lease.acquire()
        try:
            self.security.validate_fd(lease.fd)
            self.service.delete(command)
            if (self.root / 'releases').exists():
                self._tree(self.root / 'releases')
                shutil.rmtree(self.root / 'releases')
            self._write(self.root / 'uninstalled.json', intent)
            if (self.root / 'active.json').exists():
                self.security.validate(str(self.root / 'active.json'))
                os.unlink(self.root / 'active.json')
            if (self.root / 'previous.json').exists():
                self.security.validate(str(self.root / 'previous.json'))
                os.unlink(self.root / 'previous.json')
            self.security.validate(str(self.root / 'uninstall.json'))
            os.unlink(self.root / 'uninstall.json')
        finally:
            lease.release()

    def _lock(self):
        self.open()
        lock = _InstanceLock(str(self.root / 'installer.lock'))
        self.security.check_components(lock.path)
        lock.acquire()
        try:
            self.security.validate_fd(lock.fd)
        except BaseException:
            lock.release()
            raise
        return lock

    def install(self, package):
        lock = self._lock()
        try:
            self._recover()
            self.verifier(package, self.publisher)
            meta = validate_release(package, self.security)
            old = self._active()
            if old is not None:
                self._check_release(old)
                self.service.state(self._command(old))
            target = self.root / 'releases' / meta['release']
            if not target.exists() and len(os.listdir(target.parent)) >= 4:
                raise ConfigError('retained release capacity reached')
            self._copy(Path(package), target)
            self._write(self.root / 'upgrade.json', {'v': 1, 'old': old, 'new': meta['release']})
            self._recover()
            return {'release': meta['release'], 'service': 'running'}
        finally:
            lock.release()

    def rollback(self):
        lock = self._lock()
        try:
            intent = self._read('upgrade.json')
            if intent is None:
                previous = self._read('previous.json')
                current = self._active()
                if type(previous) is not dict or set(previous) != {'v', 'release'} or previous['v'] != 1 \
                        or current is None:
                    raise ConfigError('no previous release')
                self._check_release(current)
                self._check_release(self._id(previous['release']))
                self._write(self.root / 'upgrade.json', {'v': 1, 'old': current, 'new': previous['release']})
                self._recover()
                return {'release': previous['release'], 'rollback': True}
            if type(intent) is not dict or set(intent) != {'v', 'old', 'new'} or intent['v'] != 1 \
                    or intent['old'] is None or self._active() not in (intent['old'], intent['new']):
                raise ConfigError('no recoverable previous release')
            old, new = self._id(intent['old']), self._id(intent['new'])
            self._check_release(old)
            try:
                exists = self.service.state(self._command(new))
                command = self._command(new)
            except ConfigError:
                exists = self.service.state(self._command(old))
                command = self._command(old)
            if exists:
                self.service.stop(command)
            self.service.configure(self._command(old), previous=command if exists else None)
            self._write(self.root / 'active.json', {'v': 1, 'release': old})
            self.service.start(self._command(old))
            self.security.validate(str(self.root / 'upgrade.json'))
            os.unlink(self.root / 'upgrade.json')
            self._write(self.root / 'previous.json', {'v': 1, 'release': new})
            self._collect_releases()
            return {'release': old, 'rollback': True}
        finally:
            lock.release()

    def set_autostart(self, enabled):
        if type(enabled) is not bool:
            raise ConfigError('invalid startup preference')
        if not self.root.exists():
            raise ConfigError('installed client required')
        lock = self._lock()
        try:
            # Startup preferences must not implicitly recover an interrupted
            # upgrade, or restart a currently stopped client.
            if any(os.path.lexists(self.root / name) for name in ('upgrade.json', 'uninstall.json')):
                raise ConfigError('explicit recovery required')
            active = self._active()
            if active is None:
                raise ConfigError('installed client required')
            self._check_release(active)
            command = self._command(active)
            self.service.set_autostart(command, enabled)
            mode = self.service.start_mode(command)
            if mode != (2 if enabled else 3):
                raise ConfigError('startup preference readback failed')
            return {'autostart': enabled, 'service_state': self.service.state(command)}
        finally:
            lock.release()

    def operate(self, operation, profile=None, bundle=None, controller_secret=''):
        lock = self._lock()
        try:
            self._recover()
            release = self._active()
            if release is None:
                if operation == 'status':
                    return {'v': 1, 'service_state': 0, 'profiles': [], 'retired': sorted(os.listdir(self.root / 'retired'))}
                previous = self._read('uninstalled.json')
                if operation != 'purge' or type(previous) is not dict or previous.get('v') != 1 \
                        or self.service.state(self._command(self._id(previous['release']))) != 0:
                    raise ConfigError('install runtime first')
                self.vault._path(profile)
                target = self.root / 'retired' / profile
                if target.exists():
                    self._tree(target)
                    shutil.rmtree(target)
                return {'profile': profile, 'purged': True}
            meta = self._check_release(release)
            command = self._command(release)
            state = self.service.state(command)
            if operation == 'status':
                return {'v': 1, 'release': release, 'service_state': state,
                        'profiles': [{'id': key, 'enabled': self.vault.enabled(key)} for key in self.vault.keys()],
                        'retired': sorted(os.listdir(self.root / 'retired'))}
            if operation == 'import':
                manifest, secret, certificate, display = read_bundle(bundle, meta['artifact'], include_display=True)
                key = profile_id(manifest)
                if (self.root / 'retired' / key).exists() or (key not in self.vault.keys() and self._slots() >= 8):
                    raise ConfigError('profile retired or capacity reached')
                display_path=Path(self.vault._path(key))/'display.json'
                if os.path.lexists(display_path):
                    existing=validate_display(object_json(self.security.read(str(display_path),DISPLAY_LIMIT)),manifest)
                    if existing!=display:
                        raise ConfigError('display identity change requires explicit replacement')
                verify_controller(manifest, controller_secret)
            elif operation in ('pause', 'resume', 'remove'):
                self.vault._path(profile)
                if operation == 'remove' and profile not in self.vault.keys() \
                        and (self.root / 'retired' / profile).exists():
                    self._tree(self.root / 'retired' / profile)
                    return {'profile': profile, 'removed': True, 'data': 'retained'}
                self.vault.load(profile)
                if operation == 'resume':
                    path = Path(self.vault._path(profile)) / 'mihomo.key'
                    credential = self.security.read(str(path), 4096).decode('utf-8') if path.exists() else ''
                    verify_controller(self.vault.load(profile), credential)
            elif operation == 'purge':
                self.vault._path(profile)  # validates the selector before path construction
                if not (self.root / 'retired' / profile).exists():
                    raise ConfigError('remove profile before explicit purge')
            elif operation == 'uninstall':
                if self.vault.keys():
                    raise ConfigError('remove all live profiles before uninstall')
                self._write(self.root / 'uninstall.json', {'v': 1, 'release': release})
                self._recover_uninstall()
                return {'uninstalled': True, 'retained_profiles': self._slots()}
            else:
                raise ConfigError('unknown lifecycle operation')
            self.service.stop(command)  # actual drain, never kill a process
            # Single-writer service lease also detects a direct/rogue runtime.
            lease = _InstanceLock(str(Path(self.vault.root) / 'service.lock'))
            self.security.check_components(lease.path)
            lease.acquire()
            try:
                self.security.validate_fd(lease.fd)
                if operation == 'import':
                    key, created = self.vault.import_profile(manifest, secret, certificate,
                                                           controller_secret=controller_secret)
                    self._write(Path(self.vault._path(key))/'display.json',display)
                    result = {'profile': key, 'created': created}
                elif operation in ('pause', 'resume'):
                    self.vault.set_enabled(profile, operation == 'resume')
                    result = {'profile': profile, 'enabled': operation == 'resume'}
                elif operation == 'remove':
                    self.vault.set_enabled(profile, False)
                    source = Path(self.vault._path(profile))
                    self._tree(source)
                    if (self.root / 'retired' / profile).exists():
                        raise ConfigError('retired identity collision')
                    durable_replace(str(source), str(self.root / 'retired' / profile))
                    result = {'profile': profile, 'removed': True, 'data': 'retained'}
                elif operation == 'purge':
                    target = self.root / 'retired' / profile
                    self._tree(target)
                    shutil.rmtree(target)
                    result = {'profile': profile, 'purged': True}
            finally:
                lease.release()
            self.service.start(command)
            return result
        finally:
            lock.release()

    def _tree(self, path):
        # Called only inside the verified product root, never on input paths.
        absolute = Path(path).absolute()
        if self.root not in absolute.parents:
            raise ConfigError('cleanup outside installation')
        objects = 0
        for current, dirs, files in os.walk(absolute, followlinks=False):
            self.security.validate(current, True)
            objects += len(dirs) + len(files)
            if objects > 8192:
                raise ConfigError('cleanup capacity reached')
            for name in dirs:
                self.security.validate(os.path.join(current, name), True)
            for name in files:
                self.security.validate(os.path.join(current, name))


def main(argv=None):
    parser = argparse.ArgumentParser(description='P6 Windows lifecycle installer')
    parser.add_argument('operation', choices=('install', 'rollback', 'import', 'status', 'ui-status', 'adjacent-bundle', 'autostart-on', 'autostart-off', 'pause', 'resume', 'remove', 'purge', 'uninstall'))
    parser.add_argument('--package', required=True)
    parser.add_argument('--bundle')
    parser.add_argument('--profile')
    parser.add_argument('--controller-key-file')
    parser.add_argument('--discover-controller', action='store_true')
    args = parser.parse_args(argv)
    try:
        if os.name != 'nt' or not ctypes.windll.shell32.IsUserAnAdmin() or ctypes.sizeof(ctypes.c_void_p) != 8:
            raise ConfigError('administrator Windows x64 required')
        from .publisher import PUBLISHER, INSTALLATION_NAME
        if not re.fullmatch(r'P6RemoteProbe|P6InstallerFixture[0-9a-f]{32}', INSTALLATION_NAME):
            raise ConfigError('invalid installed service binding')
        buffer = ctypes.create_unicode_buffer(32768)
        # CSIDL_COMMON_APPDATA from the native known-folder API, not environment.
        if ctypes.windll.shell32.SHGetFolderPathW(None, 35, None, 0, buffer):
            raise ConfigError('system state directory unavailable')
        manager = Manager(Path(buffer.value) / INSTALLATION_NAME, Service(INSTALLATION_NAME), publisher=PUBLISHER)
        discovered = ''
        if args.discover_controller:
            if args.operation not in ('install', 'import') or not args.bundle or args.controller_key_file:
                raise ConfigError('invalid local discovery interaction')
            manager.verifier(args.package, PUBLISHER)
            meta = validate_release(args.package, manager.security)
            manifest, _, _ = read_bundle(args.bundle, meta['artifact'])
            discovered = discover_credential(manifest['agent']['mihomo_url'])
            verify_controller(manifest, discovered)
        if args.operation == 'adjacent-bundle':
            if not args.bundle or args.profile or args.controller_key_file or args.discover_controller:
                raise ConfigError('invalid adjacent selector')
            manager.verifier(args.package,PUBLISHER)
            meta=validate_release(args.package,manager.security)
            result=discover_adjacent(args.bundle,meta['artifact'])
        elif args.operation == 'ui-status':
            if args.bundle or args.profile or args.controller_key_file or args.discover_controller:
                raise ConfigError('invalid snapshot selector')
            from .status import snapshot
            result = snapshot(manager)
        elif args.operation in ('autostart-on', 'autostart-off'):
            if args.bundle or args.profile or args.controller_key_file or args.discover_controller:
                raise ConfigError('invalid startup selector')
            result = manager.set_autostart(args.operation == 'autostart-on')
        elif args.operation == 'install':
            result = manager.install(args.package)
            if args.bundle:
                credential = manager.security.read(args.controller_key_file, 4096).decode('utf-8').rstrip('\r\n') if args.controller_key_file else discovered
                result['import'] = manager.operate('import', bundle=args.bundle, controller_secret=credential)
        elif args.operation == 'rollback':
            result = manager.rollback()
        else:
            credential = discovered
            if args.controller_key_file:
                if args.operation != 'import':
                    raise ConfigError('controller credential only accepted for import')
                credential = manager.security.read(args.controller_key_file, 4096).decode('utf-8').rstrip('\r\n')
            result = manager.operate(args.operation, args.profile, args.bundle, credential)
        print('[PASS] ' + json.dumps(result, sort_keys=True))
        return 0
    except DiscoveryError:
        print('[FAIL] local_controller_discovery_unavailable', file=sys.stderr)
        return 2
    except (ConfigError, SpoolError, StorageSecurityError, OSError, ValueError, TypeError, KeyError,
            subprocess.SubprocessError):
        print('[FAIL] p6_installer_unavailable', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
