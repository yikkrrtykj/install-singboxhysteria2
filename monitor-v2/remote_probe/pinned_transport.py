"""P6B2 HTTPS transport. Authenticate TLS before sending any HTTP bytes.

Trust is profile-local: one self-signed certificate, its DER SHA-256, IP SAN
and normal validity verification. No system trust, TOFU, redirects or TLS
key logging. The collection/payload/HMAC protocol remains P6A/P6B v1.
"""
from __future__ import annotations

import hashlib
import hmac
import http.client
import ipaddress
import math
import re
import socket
import ssl
import threading

from . import MAX_BODY_BYTES
from .delivery import UploadConfigError, classify_url


class PinnedHttpsIngest:
    def __init__(self, url, certificate_pem, certificate_sha256, timeout=10):
        self.host, self.port, scheme, self.path = classify_url(url)
        if scheme != "https":
            raise UploadConfigError("production requires HTTPS")
        try:
            ipaddress.ip_address(self.host)
        except ValueError:
            raise UploadConfigError("production target must be an IP") from None
        if type(certificate_sha256) is not str or not re.fullmatch(
                r"[0-9a-f]{64}", certificate_sha256):
            raise UploadConfigError("invalid certificate pin")
        if type(certificate_pem) is not str or len(certificate_pem) > 16384:
            raise UploadConfigError("invalid certificate")
        if certificate_pem.count("-----BEGIN CERTIFICATE-----") != 1:
            raise UploadConfigError("one certificate required")
        try:
            der = ssl.PEM_cert_to_DER_cert(certificate_pem)
        except (ValueError, TypeError):
            raise UploadConfigError("invalid certificate") from None
        if not hmac.compare_digest(hashlib.sha256(der).hexdigest(),
                                   certificate_sha256):
            raise UploadConfigError("certificate pin mismatch")
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 10:
            raise UploadConfigError("invalid transport timeout")
        self.timeout = float(timeout)
        self.pin = certificate_sha256
        # Construct directly: create_default_context() can enable SSLKEYLOGFILE
        # from the environment, which would undermine credential confidentiality.
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.load_verify_locations(cadata=certificate_pem)

    def post(self, body, header_map):
        if type(body) is not bytes or not 0 < len(body) <= MAX_BODY_BYTES:
            raise UploadConfigError("invalid body size")
        if any(k.lower() in ("transfer-encoding", "content-length", "host",
                             "connection") for k in header_map):
            raise UploadConfigError("caller cannot override framing")
        conn = http.client.HTTPSConnection(self.host, self.port,
                                           timeout=self.timeout,
                                           context=self.context)
        expired = threading.Event()
        connected = []

        def abort():
            expired.set()
            sock = connected[0] if connected else conn.sock
            if sock is not None:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

        # Socket timeouts alone do not bound a peer that drips HTTP header/body
        # bytes continuously. Abort the whole exchange at the absolute budget.
        timer = threading.Timer(self.timeout, abort)
        timer.daemon = True
        timer.start()
        try:
            # Explicit connect/verification precedes request() and HMAC headers.
            conn.connect()
            connected.append(conn.sock)
            if expired.is_set():
                raise TimeoutError("transport deadline")
            peer = conn.sock.getpeercert(binary_form=True)
            if not hmac.compare_digest(hashlib.sha256(peer).hexdigest(), self.pin):
                raise ssl.SSLCertVerificationError("pinned identity mismatch")
            headers = dict(header_map)
            headers["Content-Length"] = str(len(body))
            conn.request("POST", self.path, body=body, headers=headers)
            response = conn.getresponse()
            # http.client never follows redirects. Oversized bodies become the
            # existing malformed-success disposition; no arbitrary text logging.
            return response.status, response.read(4096)
        finally:
            timer.cancel()
            conn.close()
