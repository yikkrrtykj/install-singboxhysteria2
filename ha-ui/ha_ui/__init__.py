"""Windows local dual-VPS A-first/B-first configuration generator (HA-UI).

This package is a local operator assistant only. It never opens a public
listener, never activates TUN/Clash, never changes the remote sing-box
configuration, and never replaces the existing HA-02/03/04 tools: it calls
those reviewed modules unchanged and publishes their verified output under a
human-readable ``<client>-A-first.yaml`` / ``<client>-B-first.yaml`` name.
"""

APP_ID = "ha-ui"
APP_NAME = "双 VPS 主备配置生成器"
APP_VERSION = "0.1.0"

# The two physical roles are fixed. VPS A/B are identities the operator names;
# their credentials must stay independent (never synchronised or reused).
SERVER_IDS = ("A", "B")

# Windows Credential Manager service namespace for SSH passwords.
CREDENTIAL_SERVICE = "ha-ui-ssh"

__all__ = [
    "APP_ID",
    "APP_NAME",
    "APP_VERSION",
    "CREDENTIAL_SERVICE",
    "SERVER_IDS",
]
