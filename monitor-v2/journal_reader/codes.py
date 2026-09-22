"""Sanitized failure codes for the journal reader (issue #33 P2).

Every reader-visible failure is ONE of these codes -- never exception text,
never a path, never journal content (security contract §2).
"""

# Exchange/state write failed (R5): child killed, process exits, the
# durable cursor never advances past uncommitted evidence.
CODE_WRITER_FAILED = "journal_writer_failed"

# journalctl child exited non-zero (D1 rows 4/5). Committed state does NOT
# move; restart re-polls the unchanged range (lag, never silent loss).
CODE_SOURCE_UNAVAILABLE = "journal_source_unavailable"

# A decoded journal entry exposed a missing/malformed __CURSOR (D1 row 6):
# the whole batch is non-committable.
CODE_CURSOR_INVALID = "journal_cursor_invalid"

# Startup recovery hit C2 table rows 5/6/8, OR state/committed /
# state/pending violates the D2/D3/D5 grammar at load: fail closed, zero
# writes, human/reviewed action required.
CODE_STATE_CORRUPTION = "journal_state_corruption"

# Operator reset refused because state is not settled/consistent.
CODE_RESET_REFUSED = "journal_reset_refused"

# SBOX_JR_UNIT environment override present but invalid grammar (fail closed).
CODE_UNIT_INVALID = "journal_unit_config_invalid"

# journalctl timestamp normalization failed (never proceeds on a wrong window).
CODE_TIME_UNUSABLE = "journal_time_unusable"
