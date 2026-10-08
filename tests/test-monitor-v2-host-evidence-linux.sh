#!/usr/bin/env bash
# Run ONLY on the disposable Linux CI machine. No real service is installed,
# restarted or stopped; nobody reads existing /proc/systemd and its own fixture.
set -euo pipefail
[ "$(id -u)" = 0 ] || { printf 'FAIL: Linux identity fixture requires root\n'; exit 1; }
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
fixture="$(mktemp -d /tmp/monitor-host-evidence.XXXXXXXX)"
trap 'rm -rf -- "$fixture"' EXIT
cp -- "$root/monitor-v2/web/host_evidence.py" "$fixture/host_evidence.py"
chmod 0644 "$fixture/host_evidence.py"
chown nobody "$fixture"
runuser -u nobody -- env PYTHONDONTWRITEBYTECODE=1 python3 - "$fixture" <<'PY'
import os, sys, time
sys.path.insert(0, sys.argv[1])
from host_evidence import HostReader, HostEvidence, valid
assert os.geteuid() != 0
reader = HostReader(sys.argv[1])
reader.sample(time.time(), 'a'*32)
time.sleep(0.05)
sample = reader.sample(time.time(), 'a'*32)
assert valid(sample)
assert all(sample[k] is not None for k in ('boot', 'cpu_percent', 'memory_percent', 'disk_percent'))
plane = HostEvidence(sys.argv[1])
plane.start()
for _ in range(300):
    if plane.collection_status == 'recording':
        break
    time.sleep(0.01)
assert plane.collection_status == 'recording'
result = plane.incident(1, time.time()-20, time.time())
assert result['sample_count'] >= 1 and result['availability'] != 'unavailable'
assert result['resources']['memory_percent']['observations'] >= 1
plane.stop()
assert plane.thread is None
print('PASS: non-root real Linux proc/systemd reader, owner-only SQLite and worker lifecycle')
PY
