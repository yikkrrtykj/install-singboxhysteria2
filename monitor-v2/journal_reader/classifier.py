"""Failure-mode classification, cv=1 (issue #33 P2 §5.3, v2-R3 + v3-B2).

Classes are PURE FAILURE MODES; protocol attribution is orthogonal and
independent (v2-R3): the 2026-09-22 incident anchor must keep BOTH
`cls=dial_timeout` and `proto=Reality`, so no class is ever a
"Reality bucket" or an "HY2 bucket".

ORDERED, first match wins -- the ordering is part of the contract:
  1 dns            2 dial_timeout     3 reset          4 net_unreachable
  5 tls_handshake  6 quic_error       7 eof_cancel     8 other (fp-keyed)

v3-B2 tightening (frozen): `dial_timeout` uses TIMEOUT-SPECIFIC tokens only
-- bare `dial ` is removed, so `dial tcp ...: connect: connection refused`
falls to `other`+fp; PROTO attribution NEVER maps bare `quic` to
Hysteria2 (tag first, explicit protocol tokens second, else OTHER).
"""

import re

CLASS_VERSION = 1

# (class, ordered trigger list). Substring tokens are matched against the
# normalized (lowercased, level/timestamp-stripped) message text.
_CLASS_ROWS = (
    ("dns", ("no such host", "name resolution", "temporary failure in name resolution",
             "lookup ", "dns")),
    ("dial_timeout", ("i/o timeout", "timeout exceeded", "deadline exceeded",
                      "timeout waiting for", "timed out")),
    ("reset", ("connection reset by peer", "reset by peer", "broken pipe",
               "forcibly closed")),
    ("net_unreachable", ("network is unreachable", "host is unreachable",
                         "no route to host", "cannot assign requested address")),
    ("tls_handshake", ("tls:", "handshake", "certificate", "x509",
                       "bad record mac", "alert", "processed invalid")),
    ("quic_error", ("quic", "invalid packet", "connection id",
                    "version negotiation")),
    ("eof_cancel", ("unexpected eof", "eof", "context canceled",
                    "context cancelled", "use of closed",
                    "connection is closed")),
)

# Distance form "dial tcp <addr> ... timeout" without ever matching bare
# "dial " (v3-B2). Bounded gap keeps the scan linear.
_DIAL_TIMEOUT_RX = re.compile(r"\bdial (?:tcp|udp)[^\n]{0,120}?\btimeout\b")

# Destination port is extracted ONLY from dial-style address forms, and
# only the port digits survive (v1 §5.4: host/IP discarded at the byte
# level, never assigned to anything that outlives the match).
_DIAL_ADDR_RX = re.compile(r"\bdial (?:tcp|udp) (\S+)")


def classify_failure(text):
    """Return one of the seven specific class tokens, or None (= `other`)."""
    for name, tokens in _CLASS_ROWS:
        if name == "dial_timeout":
            if _DIAL_TIMEOUT_RX.search(text):
                return name
        for token in tokens:
            if token in text:
                return name
    return None


# PROTO attribution (v3-B2 final): authoritative inbound/component tag
# first, explicit protocol tokens second, otherwise OTHER. The bare `quic`
# token is a CLASS trigger only -- it never attributes a protocol.
_TAG_RULES = (("vless-in", "Reality"), ("hy2-in", "Hysteria2"))
_TOKEN_RULES = (("hysteria2", "Hysteria2"), ("hy2", "Hysteria2"),
                ("reality", "Reality"))


def attribute_protocol(text):
    for tag, proto in _TAG_RULES:
        if tag in text:
            return proto
    for token, proto in _TOKEN_RULES:
        if token in text:
            return proto
    return "OTHER"


_PORT_TABLE = {
    443: "https443",
    80: "http80",
    53: "dns53",
    853: "dot853",  # R9: DNS-over-TLS, NOT DoH (DoH rides 443 by design)
    25: "smtpish",
    465: "smtpish",
    587: "smtpish",
}


def extract_port(text):
    """Return the destination port int from a dial-style address token, or
    None. Only digits are kept; the host portion is discarded here and
    never referenced again."""
    for match in _DIAL_ADDR_RX.finditer(text):
        token = match.group(1).rstrip(":,;")
        idx = token.rfind(":")
        if idx < 0:
            continue
        digits = token[idx + 1:]
        if digits.isdigit() and 1 <= int(digits) <= 65535:
            return int(digits)
    return None


def dest_class_for(port, text):
    """DCLS is populated only when a port was extracted (v1 §5.2)."""
    if port is None:
        return None
    if "quic" in text:
        return "quic"
    return _PORT_TABLE.get(port, "other")


def classify_entry(text):
    """Full whitelist extraction for one normalized message: returns
    (class, proto, port, dcls). `other` + fp is finalized by the reader."""
    failure = classify_failure(text)
    proto = attribute_protocol(text)
    port = extract_port(text)
    dcls = dest_class_for(port, text)
    if failure is None:
        return "other", proto, port, dcls
    return failure, proto, port, dcls
