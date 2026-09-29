"""Monitor diagnostics package (issue #33 Phase 3).

Holds the outbound probe engine (``network_probes``, PR-3A) and its
PR-3B activation surface (``probe_scheduler``): one dedicated
non-publisher thread driving bounded cycles against the frozen,
reviewed production endpoint set, persisting closed results through
the IncidentHistory v3 boundary. The package ships in the immutable
release tree through the explicit ``DIAGNOSTICS_MODULE_FILES`` staging
manifest (``sbmon_stage_release``) -- never a ``cp -R`` of this
directory.

Python 3.10+ standard library only -- never any third-party import.
"""
