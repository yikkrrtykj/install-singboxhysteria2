#!/usr/bin/env python3
"""Monitor v2 Phase E4 -- OPTIONAL Mihomo local API enrichment adapter.

READ-ONLY by mandate. This adapter polls a Mihomo (Clash.Meta) local
external-controller REST API on the CLIENT device and produces ONE enriched,
self-dated object per call. It is strictly additive to the server Monitor
(Phase E1): the service.api stream remains the ONLY authority for
Device / Protocol / Lifecycle identity and traffic. If the Mihomo API is
unreachable, disabled, misconfigured or answers with the wrong secret, the
server Monitor is completely unaffected and this adapter simply reports
reachable=false with a redacted error.

IDENTITY BOUNDARY (hard):
    * the enrichment object is a FIXED whitelist of display-only fields
      (model.ENRICHMENT_KEYS) -- it cannot carry an identity field;
    * a Mihomo node display name ("vmix-01-HY2", "香港-01", anything) is echoed
      verbatim as selected_proxy for DISPLAY ONLY and is never matched,
      parsed or mapped onto a server-side Device;
    * this module MUST NOT import anything from the server-side monitor code.

SECURITY MODEL (hard):
    * the controller URL must target the loopback interface -- fail-closed at
      construction time, exactly like the service.api adapter. The Mihomo API
      is a client-local service (e.g. 127.0.0.1:9090) and is NEVER exposed to
      the public internet; if a server ever needs this data, that is an
      explicit agent / tunnel design, not a widened bind address;
    * the secret goes out ONLY in the Authorization: Bearer header. It is
      never logged, never serialized into the output object, never placed in
      a URL query string (the websocket-style query fallback of the upstream
      API is deliberately not implemented);
    * errors are redacted through the same mechanism as the server adapter
      before they are stored;
    * every INDIVIDUAL request is bounded to 1-3 seconds; one full poll may
      take multiple request budgets (a global poll deadline is a later,
      explicit design). collect() never raises.

CONTROL PLANE FORBIDDEN (read-only mandate): selecting proxies (PUT), mode
changes or config reloads (PATCH/PUT on /configs), closing connections
(DELETE), triggering a delay probe (that endpoint performs an ACTIVE test
through the node), restart / upgrade endpoints. Only GET is ever issued.

Endpoint contract verified against the real Mihomo REST source
(MetaCubeX/mihomo, hub/route/ + tunnel/statistic/ + adapter/) -- field table
and stability classes in monitor-v2/mihomo/README.md.
"""

from __future__ import annotations

import argparse
import datetime
import errno
import http.client
import json
import os
import socket
import sys
import time
import urllib.parse

from model import (finish_enrichment, new_enrichment, parse_connections,
                   parse_mode, parse_proxies, parse_traffic_line,
                   parse_version)

LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
DEFAULT_URL = "http://127.0.0.1:9090"
DEFAULT_GROUP = None          # no guessing: the caller names the group to watch
DEFAULT_TIMEOUT = 2.0
MIN_TIMEOUT = 1.0
MAX_TIMEOUT = 3.0             # per-request bound; a poll may span several
SECRET_ENV = "MIHOMO_API_SECRET"
MAX_ERROR_BODY = 120          # bytes of a non-200 body kept for diagnostics


class ConfigurationError(Exception):
    """Fatal adapter configuration problem (e.g. non-loopback URL)."""


class TransportError(Exception):
    """A request could not be completed (connect/timeout/EOF/socket)."""


class ApiError(Exception):
    """The controller answered with a non-200 status."""

    def __init__(self, status, body=b""):
        snippet = body[:MAX_ERROR_BODY].decode("utf-8", "replace").replace("\n", " ")
        super().__init__("HTTP %s%s" % (status, " (%s)" % snippet if snippet else ""))
        self.status = status


def clamp_timeout(value):
    """Keep every timeout inside the 1-3 second budget (fail-safe to 2.0)."""
    try:
        value = float(value)
    except (TypeError, ValueError):
        return DEFAULT_TIMEOUT
    if value != value:  # NaN
        return DEFAULT_TIMEOUT
    return min(max(value, MIN_TIMEOUT), MAX_TIMEOUT)


def parse_controller_url(url):
    """Parse and VALIDATE the controller URL. Loopback only, fail-closed.

    Returns (host, port, scheme). The Mihomo external-controller is a
    client-local service; anything non-loopback is refused before a single
    byte (and never a secret) leaves the machine. Also refused: embedded
    credentials, non-root paths, query strings and fragments.

    ANY malformed URL (bad port literal, out-of-range port, broken IPv6
    brackets, ...) becomes a ConfigurationError -- never a ValueError/trace,
    so the CLI always exits via "fatal configuration error" with rc=2.

    Error messages deliberately never echo the full URL or user-supplied URL
    fragments (path included): a URL can carry user:pass-like content, and
    configuration errors end up in logs/stderr. Only vetted components
    (scheme, host, port) are named.
    """
    try:
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https"):
            raise ConfigurationError(
                "mihomo controller URL scheme must be http(s), got %r" % parts.scheme)
        if parts.username is not None or parts.password is not None \
                or "@" in (parts.netloc or ""):
            raise ConfigurationError(
                "mihomo controller URL must not embed credentials (user:pass form)")
        host = (parts.hostname or "").lower()
        if host not in LOOPBACK_HOSTS:
            raise ConfigurationError(
                "mihomo controller URL must target the loopback interface "
                "(127.0.0.1 / localhost / ::1), got host %r. The external-"
                "controller is a client-local service and must never be exposed "
                "to a network." % host)
        port = parts.port  # raises ValueError for non-numeric / out-of-range
        if port is None:
            port = 443 if parts.scheme == "https" else 9090
        if not 0 < port < 65536:
            raise ConfigurationError("invalid mihomo controller port")
        if parts.path not in ("", "/"):
            raise ConfigurationError("mihomo controller URL must use the root path")
        if parts.query or parts.fragment:
            raise ConfigurationError(
                "mihomo controller URL must not carry a query string or fragment")
        return host, port, parts.scheme
    except ValueError:
        raise ConfigurationError(
            "malformed mihomo controller URL (bad host or port)") from None


def redact(text, secrets):
    """Strip every known secret from text before it can be stored or shown."""
    if not text:
        return text
    for secret in secrets:
        if secret:
            text = text.replace(secret, "[redacted]")
    return text


class HttpTransport:
    """Minimal stdlib REST transport: one short-lived connection per request.

    READ-ONLY BY CONSTRUCTION: the only request surface is ``get(path)`` --
    there is no ``method`` parameter anywhere on this class, so no mutation
    verb (PUT/POST/PATCH/DELETE) can be issued, not even by accident. The
    secret is emitted ONLY as an Authorization header on the request line's
    headers -- never in the path (no query string, ever).
    """

    def __init__(self, host, port, scheme="http", secret=None, timeout=DEFAULT_TIMEOUT):
        self.host = host
        self.port = port
        self.scheme = scheme
        self.secret = secret
        self.timeout = clamp_timeout(timeout)

    def _connection(self):
        if self.scheme == "https":
            import ssl
            context = ssl.create_default_context()
            return http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout,
                                               context=context)
        return http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)

    def _headers(self):
        headers = {"Accept": "application/json"}
        if self.secret:
            headers["Authorization"] = "Bearer %s" % self.secret
        return headers

    def get(self, path):
        """One GET request -> (status, body bytes). Raises TransportError."""
        try:
            conn = self._connection()
            try:
                conn.request("GET", path, headers=self._headers())
                response = conn.getresponse()
                body = response.read()
                return response.status, body
            finally:
                conn.close()
        except (OSError, http.client.HTTPException) as exc:
            raise TransportError("%s: %s" % (type(exc).__name__, exc)) from exc

    def read_stream_sample(self, path, sample_deadline):
        """Read ONE JSON line from an INDEFINITE streaming endpoint.

        The Mihomo /traffic handler streams one flushed ``JSON + newline`` per
        second and KEEPS THE CONNECTION OPEN -- it is never closed for the
        client. This reader therefore returns the moment the FIRST complete
        newline-terminated line has arrived; it never waits for the connection
        to close, never waits for a full read buffer, never consumes a second
        line, and is bounded by the ABSOLUTE deadline ``sample_deadline``.

        Mechanics (newline framing over bounded reads):
        * the socket timeout is applied BEFORE ``getresponse()`` -- for a
          will-close response http.client detaches the socket during read, so
          it cannot be retuned afterwards;
        * each iteration performs ONE bounded ``read1()`` (a single recv --
          unlike ``read(n)``, which would block for ``n`` bytes on a healthy
          stream and stall exactly the way the first line must not);
        * between reads the ABSOLUTE deadline is re-checked, and on a
          keep-alive response (the real mihomo case) the socket timeout is
          re-tuned to the remaining budget;
        * worst-case overshoot is one bounded read (<= sample_deadline) on a
          will-close stream, and ≈ deadline on keep-alive streams.
        """
        deadline = time.monotonic() + max(sample_deadline, MIN_TIMEOUT)
        try:
            conn = self._connection()
            try:
                conn.request("GET", path, headers=self._headers())
                if conn.sock is not None:
                    conn.sock.settimeout(max(sample_deadline, MIN_TIMEOUT))
                response = conn.getresponse()
                if response.status != 200:
                    raise ApiError(response.status, response.read())
                buffer_ = bytearray()
                while True:
                    newline = buffer_.find(b"\n")
                    if newline != -1:
                        return bytes(buffer_[:newline])
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TransportError("stream sample timed out after %.1fs"
                                             % sample_deadline)
                    if conn.sock is not None:
                        try:
                            conn.sock.settimeout(remaining)
                        except OSError:
                            pass  # will-close response: pre-set timeout still bounds recv
                    chunk = response.read1(4096)
                    if not chunk:
                        raise TransportError("stream ended before a full sample")
                    buffer_.extend(chunk)
            finally:
                conn.close()
        except (OSError, http.client.HTTPException) as exc:
            raise TransportError("%s: %s" % (type(exc).__name__, exc)) from exc


class MihomoClient:
    """One enrichment object per collect(); never raises after construction.

    Per-endpoint failure isolation: a broken optional endpoint (configs,
    proxies, connections, traffic) only nulls its own fields and appends a
    redacted note to ``error``; the object stays reachable=true as long as
    /version answered. /version itself decides reachable: a 401, a timeout,
    a refused connection or unparseable JSON all mean reachable=false --
    which MUST NEVER be interpreted as a device problem server-side.
    """

    def __init__(self, url=DEFAULT_URL, group=DEFAULT_GROUP, secret=None,
                 timeout=DEFAULT_TIMEOUT, transport=None, clock=time.time):
        self.url = url
        self.host, self.port, self.scheme = parse_controller_url(url)
        self.group = group
        self.secret = secret
        self.timeout = clamp_timeout(timeout)
        self.clock = clock
        self.transport = transport or HttpTransport(
            self.host, self.port, scheme=self.scheme, secret=secret,
            timeout=self.timeout)

    # -- endpoint helpers ---------------------------------------------------

    def _secrets(self):
        secrets = [self.secret, os.environ.get(SECRET_ENV, "")]
        return [s for s in secrets if s]

    def _get_json(self, path, errors):
        """Fetch + decode one JSON endpoint. Returns the payload or None."""
        try:
            status, body = self.transport.get(path)
        except TransportError as exc:
            errors.append("%s transport failed: %s" % (path, redact(str(exc), self._secrets())))
            return None
        except Exception as exc:  # noqa: BLE001 -- never propagate
            errors.append("%s unexpected error: %s"
                          % (path, redact("%s: %s" % (type(exc).__name__, exc),
                                          self._secrets())))
            return None
        if status != 200:
            errors.append("%s returned HTTP %s" % (path, status))
            return None
        try:
            return json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            errors.append("%s returned malformed JSON" % path)
            return None

    def _traffic_sample(self, errors):
        """OPTIONAL one-shot instantaneous rate; any failure is silently null."""
        deadline = max(self.timeout, 2.0)  # upstream emits the first sample ~1s in
        try:
            line = self.transport.read_stream_sample("/traffic", deadline)
        except (TransportError, ApiError) as exc:
            errors.append("/traffic sample failed: %s" % redact(str(exc), self._secrets()))
            return None
        except Exception as exc:  # noqa: BLE001 -- never propagate
            errors.append("/traffic unexpected error: %s"
                          % redact("%s: %s" % (type(exc).__name__, exc),
                                   self._secrets()))
            return None
        return parse_traffic_line(line)

    # -- main entry -----------------------------------------------------------

    def collect(self):
        """Poll the local API once and return a sealed enrichment object.

        Freshness semantics (stateless v1): ``checked_at`` is stamped on every
        poll; ``updated_at`` is stamped ONLY when the poll obtained valid data
        (reachable /version success). A failed poll therefore seals as
        ``stale=true`` with ``updated_at=null`` -- an unreachable API can
        never look fresh, and the failure is never backdated.
        """
        errors = []
        snap = new_enrichment()

        # 1) /version decides reachability; failure short-circuits the rest
        #    (one refused/timeout request, bounded by the clamped timeout).
        status, body = None, b""
        try:
            status, body = self.transport.get("/version")
        except TransportError as exc:
            errors.append("version probe failed: %s" % redact(str(exc), self._secrets()))
        except Exception as exc:  # noqa: BLE001 -- never propagate
            errors.append("version probe unexpected error: %s"
                          % redact("%s: %s" % (type(exc).__name__, exc),
                                   self._secrets()))
        version = None
        if status == 200:
            try:
                version = parse_version(json.loads(body.decode("utf-8")))
            except (ValueError, UnicodeDecodeError):
                errors.append("/version returned malformed JSON")
            else:
                if version is None:
                    errors.append("/version responded without a usable version field")
        elif status is not None:
            errors.append("/version returned HTTP %s%s"
                          % (status, (": %s" % body[:MAX_ERROR_BODY].decode("utf-8", "replace")
                                      .replace("\n", " ")) if body else ""))
        errors = [redact(e, self._secrets()) for e in errors]
        if version is None:
            # failed poll: no valid data was obtained, so updated_at stays
            # null and the sample is sealed stale -- never "unreachable but
            # fresh", and no older success may be invented here (stateless).
            # checked_at stamps when THIS (failed) poll finished.
            return finish_enrichment(snap, self._iso(), None,
                                     error="; ".join(errors) or None)

        snap["reachable"] = True
        snap["version"] = version

        # 2..4) optional enrichment endpoints, each isolated
        configs = self._get_json("/configs", errors)
        if configs is not None:
            snap["mode"] = parse_mode(configs)

        if self.group:
            proxies = self._get_json("/proxies", errors)
            if proxies is not None:
                selected, delay = parse_proxies(proxies, self.group)
                if selected is None and self.group not in \
                        (proxies.get("proxies") if isinstance(proxies, dict) else {}):
                    errors.append("group %r not found in /proxies" % self.group)
                snap["selected_group"] = self.group
                snap["selected_proxy"] = selected
                snap["delay_ms"] = delay

        connections = self._get_json("/connections", errors)
        if connections is not None:
            snap["active_connections"] = parse_connections(connections)

        traffic = self._traffic_sample(errors)
        if traffic is not None:
            snap["traffic_up_bps"] = traffic["up"]
            snap["traffic_down_bps"] = traffic["down"]

        # checked_at/updated_at stamp the moment the WHOLE poll completed --
        # AFTER the optional endpoints, per the documented semantics, never
        # the moment /version answered.
        finished_at = self._iso()
        return finish_enrichment(snap, finished_at, finished_at,
                                 error="; ".join(errors) or None)

    def _iso(self):
        return datetime.datetime.fromtimestamp(
            float(self.clock()), datetime.timezone.utc).isoformat()


class SecretFileError(Exception):
    """The --secret-file violates the permission contract (never a secret)."""


# Branch point for the secret-file contract; module attribute so tests can
# exercise both code paths deterministically on any OS.
_WINDOWS = os.name == "nt"


def check_secret_mode(st_mode, path, platform=None):
    """Enforce the secret-file permission contract on one stat result.

    ALL platforms: the file must be a REGULAR file.

    POSIX: it must additionally be owner-readable (0400 / 0600 pass; 0000 and
    0200 are rejected) and carry NO group/other permission bits (0644 / 0664 /
    0666 and anything more open are rejected).

    Windows: POSIX permission-bit rejection is NOT applied -- the NTFS mode
    bits carry no access semantics there; E4 v1 relies on filesystem ACLs and
    documents that limitation (see README).
    """
    import stat as stat_module
    if platform is None:
        platform = "windows" if _WINDOWS else "posix"
    if not stat_module.S_ISREG(st_mode):
        raise SecretFileError("secret file must be a regular file: %s" % path)
    if platform == "windows":
        return  # ACL territory; POSIX bits are meaningless on NTFS
    if not st_mode & 0o400:
        raise SecretFileError("secret file must be owner-readable: %s" % path)
    if st_mode & 0o077:
        raise SecretFileError(
            "secret file permissions too open (%s), want 0600 or stricter: %s"
            % (oct(st_mode & 0o777), path))


def _read_secret_file(path):
    """Read the secret file AFTER validating its permissions. POSIX uses an
    O_NOFOLLOW descriptor + fstat so the checked object is the read object
    (symlink best-effort rejection, no stat/open race). Any open/read failure
    becomes SecretFileError -- never a traceback, never secret content.
    """
    if os.path.islink(path):
        raise SecretFileError("secret file must not be a symlink: %s" % path)
    if _WINDOWS:
        try:
            st = os.stat(path)
        except FileNotFoundError:
            raise SecretFileError("secret file not found: %s" % path) from None
        except OSError:
            raise SecretFileError("secret file not readable: %s" % path) from None
        check_secret_mode(st.st_mode, path, platform="windows")
        try:
            with open(path, encoding="utf-8") as handle:
                return handle.read().strip()
        except OSError:
            raise SecretFileError("secret file not readable: %s" % path) from None
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        raise SecretFileError("secret file not found: %s" % path) from None
    except OSError as exc:
        if getattr(exc, "errno", None) == errno.ELOOP:
            raise SecretFileError(
                "secret file must not be a symlink: %s" % path) from exc
        raise SecretFileError("secret file not readable: %s" % path) from exc
    fd_owned = True  # os.open handed it to us; fdopen takes over on success
    try:
        st = os.fstat(fd)
        check_secret_mode(st.st_mode, path, platform="posix")
        handle = os.fdopen(fd, "r", encoding="utf-8")
        fd_owned = False  # the handle owns the fd now
        try:
            return handle.read().strip()
        except OSError:
            raise SecretFileError("secret file not readable: %s" % path) from None
        finally:
            handle.close()
    finally:
        if fd_owned:
            os.close(fd)


def resolve_secret(secret_file):
    """MIHOMO_API_SECRET environment wins; otherwise read --secret-file.

    The file is permission-checked BEFORE its content is read, and error
    messages contain only the path and permission bits -- never the secret
    content, never a traceback.
    """
    env_secret = os.environ.get(SECRET_ENV, "")
    if env_secret:
        return env_secret
    if secret_file:
        return _read_secret_file(secret_file)
    return ""


def build_arg_parser():
    parser = argparse.ArgumentParser(
        description="Monitor v2 E4 optional Mihomo enrichment "
                    "(read-only, loopback-only, display-only fields)")
    parser.add_argument("--url", default=DEFAULT_URL,
                        help="external-controller URL; MUST be loopback "
                             "(default: %(default)s)")
    parser.add_argument("--group", default=DEFAULT_GROUP,
                        help="proxy GROUP whose selected node should be "
                             "reported (display only; no identity meaning)")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help="per-request timeout in seconds, clamped to 1-3 "
                             "(default: %(default)s)")
    parser.add_argument("--secret-file", default=None,
                        help="file holding the controller secret; POSIX: "
                             "regular file, mode 0600/0400 enforced (Windows "
                             "relies on filesystem ACLs); "
                             "%s takes precedence" % SECRET_ENV)
    parser.add_argument("--pretty", action="store_true", help="indent JSON output")
    return parser


def main(argv=None):
    args = build_arg_parser().parse_args(argv)
    try:
        client = MihomoClient(url=args.url, group=args.group,
                              secret=resolve_secret(args.secret_file),
                              timeout=args.timeout)
    except (ConfigurationError, SecretFileError) as exc:
        print("fatal configuration error: %s" % exc, file=sys.stderr)
        return 2
    enrichment = client.collect()
    # Always exit 0: an unreachable client API is an OBSERVATION, not an
    # error condition -- the exit code must never gate the server Monitor.
    print(json.dumps(enrichment, indent=2 if args.pretty else None, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
