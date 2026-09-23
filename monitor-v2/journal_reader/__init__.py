"""sing-box journal reader (issue #33 Phase 2, PR-2A dark delivery).

Dedicated sbox-jr-side package: polls journalctl for the sing-box unit,
applies whitelist parse -> classify -> sanitize, and writes only the
closed-schema structured NDJSON exchange under /var/lib/sbox-journal/out.

Nothing here is imported or executed by the unprivileged Monitor process;
PR-2A ships this code plus its unit TEMPLATE and installer HELPERS without
creating any production identity, directory, unit or activation (G8).

Python 3.10+ standard library only -- never any third-party import, never
anything from tests/ (C5 / G9).
"""
