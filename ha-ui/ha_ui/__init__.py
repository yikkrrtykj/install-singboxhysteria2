"""Windows local dual-VPS A-first/B-first configuration generator (HA-UI).

The 0.2.0 tool can also create the same logical client on both VPSes through the
reviewed server-side canonical add path. Creation is an explicit, confirmed
remote write; YAML generation itself remains local and never imports Clash,
enables TUN or changes the system proxy. The existing HA-02/03/04 tools are used
unchanged.
"""

APP_ID = "ha-ui"
APP_NAME = "双 VPS 主备配置生成器"
APP_VERSION = "0.2.0"

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
