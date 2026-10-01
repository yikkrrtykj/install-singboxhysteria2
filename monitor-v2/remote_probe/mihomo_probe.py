"""P6 active/read Mihomo surface -- GET-only by construction (issue #67 §2).

REUSE, NEVER FORK. This module imports the audited E4/adapter pieces from
``monitor-v2/mihomo/`` exactly as that module's own ``diag.py`` does (flat
imports against the adapter directory; the directory itself is added to
``sys.path`` here, once, documented). Nothing in ``monitor-v2/mihomo/`` is
modified: its ``HttpTransport`` already IS the narrow surface P6 needs
(``get(path)`` and nothing else), and adding an active-delay call to it would
contradict that module's own documented read-only contract.

What P6 adds is a CLOSED set of named operations over that transport:

* ``version()``    -- controller reachability
* ``proxies()``    -- the audited ``/proxies`` payload semantics
* ``delay(role)``  -- the ONE explicitly enumerated active diagnostic GET

There is no generic request/method API, so no mutation verb (PUT/POST/PATCH/
DELETE) is reachable from this module -- selection, connections, config,
restart and upgrade cannot be touched even by a bug.

A failing probe is an OBSERVATION. Nothing here ever restarts, gates or
mutates Mihomo, and no outcome token in the closed vocabulary may be rendered
as a path failure when the cause was configuration (``invalid``).
"""

from __future__ import annotations

import os
import sys
import urllib.parse

from . import (DELAY_TIMEOUT_SECONDS, OUTCOME_INVALID, OUTCOME_OK,
               OUTCOME_TIMEOUT, OUTCOME_UNAVAILABLE, P6_DIAGNOSTIC_ID,
               P6_DIAGNOSTIC_URL, ROLES, ROLE_HY2, ROLE_REALITY)

_MIHOMO_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "mihomo")
if _MIHOMO_DIR not in sys.path:
    # The adapter package is a flat, self-contained directory (its own
    # diag.py imports the same way). Adding it once here keeps P6 a strict
    # consumer of the audited sources instead of a second implementation.
    sys.path.insert(0, _MIHOMO_DIR)

from client import (ApiError, ConfigurationError, HttpTransport,  # noqa: E402
                    SecretFileError, TransportError, clamp_timeout,
                    parse_controller_url, resolve_secret)
from model import parse_proxies  # noqa: E402

# The audited transport clamps every request to 1..3 s. The contract allows up
# to 5 s per active delay test; reusing the audited clamp means P6 is STRICTER
# than the contract (<=3 s wall) rather than looser. Stated as a constant so a
# lane can pin the relationship.
TRANSPORT_TIMEOUT_SECONDS = clamp_timeout(DELAY_TIMEOUT_SECONDS)
assert TRANSPORT_TIMEOUT_SECONDS <= DELAY_TIMEOUT_SECONDS

__all__ = ["P6Mihomo", "ConfigurationError", "SecretFileError",
           "TRANSPORT_TIMEOUT_SECONDS", "TransportError"]


class P6Mihomo:
    """The P6 view of one office-local Mihomo controller.

    Construction is fail-closed: a non-loopback controller URL raises
    ``ConfigurationError`` before a single byte (and never a secret) leaves
    the machine, and the secret is emitted ONLY as an Authorization header by
    the audited transport (never in a path or query string).
    """

    def __init__(self, url, watched_group=None, secret=None, transport=None,
                 timeout=DELAY_TIMEOUT_SECONDS, diagnostic_url=P6_DIAGNOSTIC_URL,
                 diagnostic_timeout_ms=None):
        self.host, self.port, self.scheme = parse_controller_url(url)
        self.watched_group = watched_group
        self.secret = secret or ""
        self.timeout = clamp_timeout(timeout)
        self.diagnostic_url = diagnostic_url
        # Mihomo's own test budget for the active delay request, in ms. Bounded
        # by the contract's 5 s and expressed in the endpoint's unit.
        self.diagnostic_timeout_ms = int(diagnostic_timeout_ms
                                         if diagnostic_timeout_ms is not None
                                         else DELAY_TIMEOUT_SECONDS * 1000)
        if not 0 < self.diagnostic_timeout_ms <= DELAY_TIMEOUT_SECONDS * 1000:
            raise ConfigurationError("diagnostic timeout out of bounds")
        self._transport = transport or HttpTransport(
            self.host, self.port, scheme=self.scheme, secret=self.secret,
            timeout=self.timeout)

    # -- named read operations ---------------------------------------------

    def version(self):
        """Controller reachability. ``(ok, payload|None, token)``."""
        return self._get_json("/version")

    def proxies(self):
        """The raw ``/proxies`` payload (audited semantics applied by the
        parser, never by a second implementation)."""
        return self._get_json("/proxies")

    # -- the ONE enumerated active diagnostic operation ---------------------

    def delay(self, role, node):
        """ONE active delay test through the explicitly configured node.

        Returns a closed outcome tuple ``(outcome, delay_ms, note)``:

        * ``ok``          -- a positive bounded delay came back;
        * ``timeout``     -- the node's test did not complete in budget;
        * ``unavailable`` -- no usable answer (controller or node unreachable,
                             including Mihomo's raw ``delay == 0`` failure
                             encoding, which is NEVER 0 ms of latency);
        * ``invalid``     -- no usable measurement for a NON-network reason
                             (missing node, refused credentials, malformed
                             contract): configuration, never path evidence.

        Exactly one request is issued per call; the caller bounds the call
        count per cycle.
        """
        if role not in ROLES:
            return OUTCOME_INVALID, None, "role_not_configured"
        if not isinstance(node, str) or not node.strip():
            return OUTCOME_INVALID, None, "node_not_configured"
        path = self._delay_path(node.strip())
        try:
            status, body = self._transport.get(path)
        except TransportError:
            return OUTCOME_UNAVAILABLE, None, "controller_unreachable"
        except (OSError, ApiError):
            return OUTCOME_UNAVAILABLE, None, "controller_unreachable"
        outcome, delay_ms = self._classify_delay(status, body)
        return outcome, delay_ms, ""

    def _delay_path(self, node):
        """The enumerated active-test path. Query values are URL-ENCODED; no
        credential ever appears here (the secret travels in the audited
        Authorization header only)."""
        query = urllib.parse.urlencode({
            "url": self.diagnostic_url,
            "timeout": self.diagnostic_timeout_ms,
        })
        return "/proxies/%s/delay?%s" % (
            urllib.parse.quote(node, safe=""), query)

    @staticmethod
    def _classify_delay(status, body):
        """Closed status/shape -> outcome table (never raises)."""
        import json
        if status == 200:
            try:
                payload = json.loads(body.decode("utf-8"))
            except (ValueError, UnicodeDecodeError, AttributeError):
                return OUTCOME_INVALID, None      # malformed reply (drift)
            if not isinstance(payload, dict):
                return OUTCOME_INVALID, None
            delay = payload.get("delay")
            # EXACT plain int: a bool/float/str is drift, never coerced.
            if isinstance(delay, bool) or not isinstance(delay, int):
                return OUTCOME_INVALID, None
            if delay < 0 or delay > 10 ** 7:
                return OUTCOME_INVALID, None
            if delay == 0:
                # Mihomo encodes a FAILED node test as delay 0. It is never
                # 0 ms of latency, and it is not a configuration error.
                return OUTCOME_UNAVAILABLE, None
            return OUTCOME_OK, delay
        if status == 404:
            return OUTCOME_INVALID, None          # configured node missing
        if status in (401, 403):
            return OUTCOME_INVALID, None          # refused credentials
        if status in (400, 408, 504):
            return OUTCOME_TIMEOUT, None          # the node's test failed
        if 500 <= status < 600:
            return OUTCOME_UNAVAILABLE, None      # controller-side failure
        return OUTCOME_INVALID, None              # any other status: drift

    # -- internals ----------------------------------------------------------

    def _get_json(self, path):
        import json
        try:
            status, body = self._transport.get(path)
        except (TransportError, OSError, ApiError):
            return OUTCOME_UNAVAILABLE, None, "controller_unreachable"
        if status != 200:
            return OUTCOME_UNAVAILABLE, None, "controller_status"
        try:
            payload = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, AttributeError):
            return OUTCOME_INVALID, None, "payload_malformed"
        return OUTCOME_OK, payload, ""

    def node_present(self, payload, node):
        """Is ``node`` a real entry in this ``/proxies`` payload?

        A keyed LOOKUP on the audited payload shape -- deliberately not a
        second parser. Used only to decide ``invalid`` (missing configured
        node) before spending an active test on it.
        """
        if not isinstance(payload, dict):
            return False
        proxies = payload.get("proxies")
        if not isinstance(proxies, dict):
            return False
        entry = proxies.get(node)
        return isinstance(entry, dict)

    def selected_node(self, payload):
        """The watched group's selected node + its cached delay, via the
        audited ``parse_proxies`` semantics (None when unconfigured/absent).
        Display/correlation value only -- never an identity."""
        if self.watched_group is None:
            return None, None
        return parse_proxies(payload, self.watched_group)

    @staticmethod
    def role_for(node_name, reality_node, hy2_node):
        """Explicit role lookup. A display name is NEVER parsed to infer a
        protocol: only the two operator-configured identities match."""
        if node_name is not None and node_name == reality_node:
            return ROLE_REALITY
        if node_name is not None and node_name == hy2_node:
            return ROLE_HY2
        return None
