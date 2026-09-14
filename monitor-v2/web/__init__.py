"""Monitor v2 Phase E2 web dashboard package.

Read-only: the dashboard consumes E1 collector snapshots through a
long-lived SnapshotBroker and never mutates sing-box state (no client
management, no config writes, no reload/restart -- that is Phase E3 scope
and deliberately absent here).
"""
