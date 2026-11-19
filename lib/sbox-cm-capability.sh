# Canonical sbox-cm capability facts, shared by the deploy installer, the E3
# preflight and the E3 rollback tool. This file defines NAMES/paths only: each
# caller keeps its own stop/remove ordering, failure accounting, fail-closed
# checks, state retention policy and transaction boundary. Keep this file
# data-only so it cannot silently change a caller's security semantics.
#
# The unit directory is a FIXED default. There is deliberately no new
# environment override for it: a destructive rollback must never be retargeted
# away from the directory the preflight checked. (The installer keeps its
# pre-existing fixture override SBXCM_UNIT_DIR; tests use a sandbox path.)
SBXCM_UNIT_DIR_DEFAULT="/etc/systemd/system"
SBXCM_SOCKET_UNIT_NAME="sbox-cm.socket"
SBXCM_SERVICE_UNIT_NAME="sbox-cm.service"
# libexec files that together form the privileged capability; the shared lib/
# files are installed in the same tree and must disappear with it. Consumed by
# the installer's post-install verification, the preflight's P00 absence check
# and the rollback's R3 removal/verification.
SBXCM_LIBEXEC_FILE_LIST=(
    "sbox-cm"
    "sbox-cm-ops"
    "lib/client-management.sh"
    "lib/sbox-cm-state.sh"
)
