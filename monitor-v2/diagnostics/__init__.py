"""Monitor diagnostics package (issue #33 Phase 3, PR-3A dark delivery).

Holds the standalone outbound probe engine (``network_probes``). Nothing
here is imported or executed by the production Monitor runtime: the
packaged release manifest (``sbmon_stage_release``) deliberately excludes
this package, no unit or entrypoint references it, and the engine carries
no default external endpoint at all (activation is PR-3B+ review scope).

Python 3.10+ standard library only -- never any third-party import.
"""
