"""Qt widgets for the local HA-UI app.

The UI layer is intentionally thin: it owns no security decision of its own.
Every SSH/vault/config operation is delegated to :mod:`ha_ui.core` (directly or
through :class:`ha_ui.ui.services.ServerActions`) and every blocking SSH or
Credential Manager call runs in a :class:`ha_ui.ui.workers.WorkerRunner` worker,
never on the Qt GUI thread.

Passwords are only ever read from a ``QLineEdit`` (masked by default) or from
the Windows Credential Manager inside a worker. They are never rendered in a
status label, a dialog, a log line, or the local ``servers.json``.
"""
