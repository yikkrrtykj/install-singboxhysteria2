#!/usr/bin/env bash
# Manual first installation only. Existing pilot, Monitor, proxy and firewall stay untouched.
set -euo pipefail
umask 077
fail() { printf '[FAIL] %s\n' "$1" >&2; exit 2; }
[[ $EUID -eq 0 ]] || fail 'Run as root on the receiver host'
[[ $# -eq 1 ]] || fail 'Supply the receiver numeric IP address'
source_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
code=/usr/local/lib/singbox-quality-receiver
state=/etc/singbox-quality-receiver
units=/etc/systemd/system
command -v openssl >/dev/null || fail 'OpenSSL unavailable'
/usr/bin/python3 -I -c 'import sys; assert sys.version_info >= (3,10)' || fail 'Python 3.10 required'
/usr/bin/python3 -I -c 'import ipaddress,sys; a=ipaddress.ip_address(sys.argv[1]); assert not(a.is_unspecified or a.is_multicast)' "$1" || fail 'Invalid address'
version=$(systemctl --version | head -n1)
[[ $version =~ ^systemd\ ([0-9]+) && ${BASH_REMATCH[1]} -ge 249 ]] || fail 'systemd 249 or later required'
[[ ! -e $code && ! -L $code && ! -e $state && ! -L $state ]] || fail 'Receiver already prepared; refuse overwrite'
for name in singbox-quality-receiver.service singbox-quality-receiver-renew.service singbox-quality-receiver-renew.timer; do
  [[ ! -e $units/$name && ! -L $units/$name && ! -e $units/$name.d ]] || fail 'Existing unit name; refuse overwrite'
  [[ $(systemctl show "$name" -p LoadState --value) == not-found ]] || fail 'Unit name already in use'
done
# Reserve-check the new port before any install. The old foreground pilot uses 8448.
/usr/bin/python3 -I -c 'import ipaddress,socket,sys; v=ipaddress.ip_address(sys.argv[1]).version; s=socket.socket(socket.AF_INET6 if v==6 else socket.AF_INET); s.bind(("::" if v==6 else "0.0.0.0",8449)); s.close()' "$1" || fail 'Port 8449 already in use'
files=(quality-receiver-service.py quality_failover/__init__.py quality_failover/persistent.py quality_failover/receiver.py quality_failover/transport.py quality_failover/policy.py)
for name in "${files[@]}"; do [[ -f $source_root/$name && ! -L $source_root/$name ]] || fail 'Missing source'; done
install -d -m0755 "$code" "$code/quality_failover"
for name in "${files[@]}"; do install -m0644 "$source_root/$name" "$code/$name"; done
/usr/bin/python3 -I -B "$code/quality-receiver-service.py" init --address "$1"
for name in singbox-quality-receiver.service singbox-quality-receiver-renew.service singbox-quality-receiver-renew.timer; do
  install -m0644 "$source_root/quality-receiver/$name" "$units/$name"
done
systemd-analyze verify "$units/singbox-quality-receiver.service" "$units/singbox-quality-receiver-renew.service" "$units/singbox-quality-receiver-renew.timer"
systemctl daemon-reload
started=0
cleanup() {
  result=$?
  if [[ $result -ne 0 && $started -eq 1 ]]; then
    systemctl disable --now singbox-quality-receiver.service singbox-quality-receiver-renew.timer >/dev/null 2>&1 || true
    printf '[FAIL] New receiver disabled; protected files retained for diagnosis\n' >&2
  fi
}
trap cleanup EXIT
started=1
systemctl start singbox-quality-receiver.service
for attempt in {1..10}; do
  if /usr/bin/python3 -I -B "$code/quality-receiver-service.py" check; then break; fi
  [[ $attempt -lt 10 ]] || fail 'Receiver TLS/readiness verification failed'
  sleep 1
done
systemctl enable singbox-quality-receiver.service singbox-quality-receiver-renew.timer
systemctl start singbox-quality-receiver-renew.timer
printf '[PASS] Dedicated receiver active; daily renewal timer enabled\n'
printf '[PASS] No Monitor, sing-box, old pilot, client startup, TUN or firewall change\n'
printf '[INFO] Pair only receiver-info.json and receiver-ca.pem from /etc/singbox-quality-receiver; private keys stay on VPS\n'
