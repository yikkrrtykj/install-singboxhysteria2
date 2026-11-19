"""Canonical client-name patterns shared by the Monitor web modules.

The web layer validates logical client names before the privileged helper
re-validates them in-lock. Keep the single canonical shape here so the server,
the bundle builders and the quality-distribution validator cannot drift apart.
"""
import re

# Byte-for-byte parity with lib/client-management.sh :: CLIENT_NAME_PATTERN:
# one alphanumeric, then up to 31 of [A-Za-z0-9._-] -- 32 characters at most.
PATTERN = r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}"

# `.match` callers historically used an anchored ^...$ pattern; keep that exact
# acceptance (including a trailing newline accepted by `$`) at those sites.
CLIENT_NAME_RE = re.compile(r"^" + PATTERN + r"$")
# `.fullmatch` callers require the whole string; no anchors/`$` involved.
CLIENT_NAME_FULL_RE = re.compile(PATTERN)
# The canonical export file name is <client>-mihomo.yaml. The dot before yaml
# is escaped DELIBERATELY: the previous inline pattern's unescaped '.' also
# accepted a wrong separator such as 'client-mihomoXyaml'. Rejecting that is an
# intentional fail-closed tightening (behaviour change recorded/tested), not a
# claim of byte-identical regex semantics.
YAML_NAME_FULL_RE = re.compile(PATTERN + r"-mihomo\.yaml")
