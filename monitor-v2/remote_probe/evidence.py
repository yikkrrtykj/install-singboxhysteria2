"""Evidence merge rules -- the anti-double-count wall (issue #67 §2).

P6 active delay requests mutate Mihomo's own delay cache/history. A later
E4/E4-Diag observation of that node may therefore contain a measurement P6
ITSELF caused. The frozen causal rule is:

    a cache echo of our own active test is NOT independent corroboration.

This module owns that rule as a pure function so it can be proven
deterministically: one active test can never be counted as two evidence
sources, no matter what the passive cache later shows.
"""

from __future__ import annotations

from . import P6_DIAGNOSTIC_ID

# Closed evidence-source vocabulary.
SOURCE_ACTIVE = "active_delay"
SOURCE_PASSIVE = "passive_cache"
EVIDENCE_SOURCES = (SOURCE_ACTIVE, SOURCE_PASSIVE)


def active_entry(role, outcome, delay_ms=None, test_id=None):
    """One active-probe evidence entry (schema-valid as built).

    ``independent`` defaults to True: an entry P6 measured itself is a real
    source. It is demoted only by ``merge_evidence`` when the SAME test stream
    reappears as a cache echo."""
    return {
        "role": role,
        "source": SOURCE_ACTIVE,
        "outcome": outcome,
        "delay_ms": delay_ms,
        "test_id": test_id or P6_DIAGNOSTIC_ID,
        "independent": True,
    }


def passive_entry(role, outcome, delay_ms=None, test_id=None):
    """One passive-cache evidence entry (E4 semantics, schema-valid as built).

    Independent by default: a cached measurement for a test stream P6 did NOT
    run is genuine evidence. Only our own echo is demoted by
    ``merge_evidence``."""
    return {
        "role": role,
        "source": SOURCE_PASSIVE,
        "outcome": outcome,
        "delay_ms": delay_ms,
        "test_id": test_id or P6_DIAGNOSTIC_ID,
        "independent": True,
    }


def merge_evidence(active_entries, passive_entries):
    """Merge active + passive entries under the non-corroboration rule.

    Returns ``(entries, corroboration_count, dropped_echoes)``:

    * an entry pair with the SAME ``(role, test_id)`` where one side is our
      own active test is NOT two sources -- the passive side is kept for the
      operator but marked ``independent=False`` and is excluded from
      ``corroboration_count``; the active side is marked ``independent=True``;
    * passive entries for other test streams (organic health checks, other
      URLs) remain independent evidence because P6 did not cause them;
    * ``dropped_echoes`` counts exactly how many echoes were demoted, so the
      demotion is never silent.

    The rule is deliberately keyed on ``(role, test_id)`` rather than on
    timing: a cache echo may arrive much later than the active test.
    """
    entries = []
    active_keys = set()
    for entry in active_entries or ():
        active_keys.add((entry["role"], entry["test_id"]))
    corroboration = 0
    dropped = 0
    for entry in active_entries or ():
        marked = dict(entry)
        marked["independent"] = True
        corroboration += 1
        entries.append(marked)
    for entry in passive_entries or ():
        marked = dict(entry)
        if (marked["role"], marked["test_id"]) in active_keys:
            # P6 caused this measurement: it can never corroborate itself.
            # The demotion is carried by independent=False alone: the wire
            # schema is closed, so no extra key is ever added.
            marked["independent"] = False
            dropped += 1
        else:
            marked["independent"] = True
            corroboration += 1
        entries.append(marked)
    return entries, corroboration, dropped
