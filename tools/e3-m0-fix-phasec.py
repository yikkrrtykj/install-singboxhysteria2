#!/usr/bin/env python3
from pathlib import Path

p = Path(__file__).resolve().parents[1] / "install.sh"
s = p.read_text()

start_marker = "# Atomically restores <live> from a hardened <backup>, keeping the original\n"
end_marker = "# rc 0 when $1 is a usable TCP/UDP port number (1-65535, digits only).\n"
insert_marker = "# Internal transaction commit. The CALLER must already hold the client config\n"

start = s.find(start_marker)
if start < 0:
    raise SystemExit("restore_file_atomically block start not found")
end = s.find(end_marker, start)
if end < 0:
    raise SystemExit("restore_file_atomically block end not found")
insert_at = s.find(insert_marker)
if insert_at < 0:
    raise SystemExit("commit_server_config insertion point not found")
if not (insert_at < start):
    raise SystemExit("unexpected source ordering")

block = s[start:end]
s = s[:start] + s[end:]
insert_at = s.find(insert_marker)
s = s[:insert_at] + block + "\n" + s[insert_at:]

if s.count("restore_file_atomically()") != 1:
    raise SystemExit("restore_file_atomically must exist exactly once")

p.write_text(s)
print("restore_file_atomically moved into shared Phase C/D transaction region")
