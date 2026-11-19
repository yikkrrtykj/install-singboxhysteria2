"""Single bridge to the canonical Mihomo merge/parser tool and frozen topology names.

The quality-failover modules must not each reimplement the dynamic loader or
restate the canonical node/group names. This internal module is the one place
that resolves `tools/mihomo-multi-vps-merge.py` by path (stdlib only, no
network/subprocess) and exposes the topology names used by the quality trial.

Keeping the loader here preserves the existing invocation contract: callers
still receive a loaded module object with the same API (`parse_export`,
`check_*`, `build_output`, `CLIENT_NAME_RE`, `GROUPS_SINGLE_AUTO`, ...).
"""
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

# Canonical topology names. The parity test in tests/test_quality_failover.py
# pins these against mihomo-multi-vps-merge.py's own constants so the two
# cannot drift silently.
NODES = ("Reality", "Hysteria2", "Backup-Reality", "Backup-Hysteria2")
AUTO = "自动选择"
OUTER = "节点选择"


def module(filename, name):
    """Load a sibling canonical tool by path without packaging it as a module."""
    spec = spec_from_file_location(name, Path(__file__).resolve().parents[1] / filename)
    if spec is None or spec.loader is None:
        raise ImportError("canonical tool unavailable")
    value = module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def merge():
    """Return the repository's canonical offline merge/parser module."""
    return module("mihomo-multi-vps-merge.py", "quality_canonical_merge")
