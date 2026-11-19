# Canonical sbox-cm capability facts, shared by the deploy installer and the
# E3 rollback tool. This file defines NAMES/paths only: each caller keeps its
# own stop/remove ordering, failure accounting, fail-closed checks, state
# retention policy and transaction boundary. Keep this file data-only so it
# cannot silently change a caller's security semantics.
SBXCM_UNIT_DIR_DEFAULT="/etc/systemd/system"
SBXCM_SOCKET_UNIT_NAME="sbox-cm.socket"
SBXCM_SERVICE_UNIT_NAME="sbox-cm.service"
# libexec files that together form the privileged capability; the shared lib/
# files are installed in the same tree and must disappear with it.
SBXCM_LIBEXEC_FILE_LIST=(
    "sbox-cm"
    "sbox-cm-ops"
    "lib/client-management.sh"
    "lib/sbox-cm-state.sh"
)
