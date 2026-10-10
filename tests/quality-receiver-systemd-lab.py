#!/usr/bin/env python3
"""Explicit root-only ephemeral systemd credential/renewal lab; never run on a production receiver."""
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from quality_failover import persistent


def main():
    if os.name!='posix' or os.geteuid()!=0 or not Path('/run/systemd/system').is_dir():
        raise SystemExit('lab: requires root on a disposable systemd host')
    root=Path(tempfile.mkdtemp(prefix='p48-receiver-test-',dir='/run')).resolve()
    root.chmod(0o755)
    name=root.name+'.service';unit=Path('/run/systemd/system')/name
    expected=None
    renew_name=root.name+'-renew.service'
    renew_unit=Path('/run/systemd/system')/renew_name
    renew_expected=None
    try:
        code=root/'code';(code/'quality_failover').mkdir(parents=True,mode=0o755)
        code.chmod(0o755)
        for relative in ('quality-receiver-service.py','quality_failover/__init__.py','quality_failover/persistent.py',
                         'quality_failover/receiver.py','quality_failover/transport.py','quality_failover/policy.py'):
            destination=code/relative;shutil.copyfile(ROOT/'tools'/relative,destination);destination.chmod(0o644)
        module=code/'quality_failover/persistent.py'
        module.write_text(module.read_text('utf-8').replace(persistent.SERVICE,name),'utf-8')
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        state=root/'state';persistent.init(state,'127.0.0.1',port)
        original_ca=(state/'receiver-ca.pem').read_bytes()
        original_info=(state/'receiver-info.json').read_bytes()
        original_cert=(state/'server-cert.pem').read_bytes()
        expected=(ROOT/'tools/quality-receiver/singbox-quality-receiver.service').read_text('utf-8')
        expected=expected.replace('/usr/local/lib/singbox-quality-receiver',str(code)).replace('/etc/singbox-quality-receiver',str(state))
        # Only this ephemeral copy omits restart-on-failure to make failures immediate.
        expected=expected.replace('Restart=on-failure','Restart=no')
        if unit.exists() or unit.is_symlink():raise ValueError('owned_unit_collision')
        unit.write_text(expected,'utf-8');unit.chmod(0o644)
        renew_expected=(ROOT/'tools/quality-receiver/singbox-quality-receiver-renew.service').read_text('utf-8')
        renew_expected=renew_expected.replace('/usr/local/lib/singbox-quality-receiver',str(code))
        renew_expected=renew_expected.replace('/etc/singbox-quality-receiver',str(state))
        renew_expected=renew_expected.replace(' renew --restart',' renew --restart --root '+str(state))
        if renew_unit.exists() or renew_unit.is_symlink():raise ValueError('owned_unit_collision')
        renew_unit.write_text(renew_expected,'utf-8');renew_unit.chmod(0o644)
        subprocess.run(['systemd-analyze','verify',str(unit),str(renew_unit)],check=True)
        subprocess.run(['systemctl','daemon-reload'],check=True)
        def verify_started():
            subprocess.run(['systemctl','start',name],check=True)
            for attempt in range(20):
                try:
                    persistent.check(state);return
                except Exception:
                    if subprocess.run(['systemctl','is-failed',name],text=True,capture_output=True).stdout.strip()=='failed':
                        break
                    time.sleep(.25)
            subprocess.run(['journalctl','-u',name,'-n','8','--no-pager','-o','cat'],check=False)
            raise ValueError('credential_service_readiness')
        verify_started()
        assert subprocess.check_output(['systemctl','show',name,'-p','DynamicUser','--value'],text=True).strip()=='yes'
        assert not (Path('/run/credentials')/name/'authority-key.pem').exists()
        assert persistent.renew(state,force=True)['renewed']
        assert (state/'receiver-ca.pem').read_bytes()==original_ca
        assert (state/'receiver-info.json').read_bytes()==original_info
        assert (state/'server-cert.pem').read_bytes()!=original_cert
        # Pending renewal is reloaded by the actual restricted root unit, not a
        # direct unrestricted restart. The one-shot must clear its durable marker.
        subprocess.run(['systemctl','start',renew_name],check=True)
        assert not (state/'restart-needed').exists()
        verify_started()
        print('lab: PASS actual DynamicUser/LoadCredential, TLS receipt, renewal and same client pair',flush=True)
    finally:
        subprocess.run(['systemctl','stop',renew_name],check=False,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        subprocess.run(['systemctl','stop',name],check=False,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        if expected is not None and unit.exists() and not unit.is_symlink() and unit.read_text('utf-8')==expected:
            unit.unlink()
        if renew_expected is not None and renew_unit.exists() and not renew_unit.is_symlink() and renew_unit.read_text('utf-8')==renew_expected:
            renew_unit.unlink()
        subprocess.run(['systemctl','daemon-reload'],check=False)
        if root.parent!=Path('/run') or root.is_symlink() or not root.name.startswith('p48-receiver-test-'):
            raise ValueError('cleanup_target')
        shutil.rmtree(root)


if __name__=='__main__':main()
