"""Privacy fingerprint `fp` for the `other` class (issue #33 P2, v2-R4).

R4 (accepted): an unsalted hash of lightly-normalized raw text is NOT used.
fp = HMAC-SHA256(reader-local key, STRICTLY privacy-tokenized template)
truncated to 16 hex. The template keeps ONLY lowercase alphabetic word
tokens <=12 chars (first 24, space-joined) after dropping host-like,
IP-like, path-like, user/email-shaped, quoted spans, high-entropy runs,
digits and hex runs -- the classifier-visible grammar of the line, never
hostnames/paths/tokens. A defense-in-depth residual check folds any
template that still matches a drop-rule shape to fp=NONE counted `other`.

The 256-bit key is created at first start, stored state/hmac.key (0600,
sbox-jr only), never leaves the reader, never appears in the exchange, DB
or logs.
"""

import hashlib
import hmac
import os
import re
import secrets

KEY_FILENAME = "hmac.key"
FP_HEX_LEN = 16
MAX_TEMPLATE_TOKENS = 24

# Drop rules operate on the normalized (lowercase) message text.
_QUOTED_RES = (re.compile(r'"[^"]*"'), re.compile(r"'[^']*'"))
_DROP_TOKEN_RES = (
    re.compile(r"\A[a-z0-9._-]+\.[a-z]{2,}\Z"),                 # host-like
    re.compile(r"[a-z0-9._-]*\d[a-z0-9._-]*\.[a-z]{2,}"),       # host w/ digits
    re.compile(r"\A\d{1,3}(\.\d{1,3}){3}\Z"),                   # IPv4
    re.compile(r"\A[0-9a-f:]{2,}\Z"),                           # IPv6-ish
    re.compile(r"/"),                                           # path-like
    re.compile(r"@"),                                           # user/email
    re.compile(r"\A[a-z0-9+/=_-]{16,}\Z"),                      # high-entropy run
)
_KEPT_RE = re.compile(r"\A[a-z]{1,12}\Z")

# Residual check on the JOINED template (defense-in-depth, R4): anything
# that still looks like host/path/credential material folds to NONE.
_RESIDUAL_RXS = tuple(rx for rx in _DROP_TOKEN_RES if rx is not _KEPT_RE)


def build_template(normalized_text):
    """Privacy-tokenize a normalized message into the hashed template."""
    text = normalized_text
    for rx in _QUOTED_RES:
        text = rx.sub(" ", text)
    kept = []
    for token in text.split():
        if not _KEPT_RE.match(token):
            continue  # digits/hex/hosts/paths/tokens are dropped BY CONSTRUCTION
        if any(rx.search(token) for rx in _DROP_TOKEN_RES):
            continue
        kept.append(token)
        if len(kept) >= MAX_TEMPLATE_TOKENS:
            break
    return " ".join(kept)


def residual_unsafe(template):
    return any(rx.search(template) for rx in _RESIDUAL_RXS)


def fingerprint(key_bytes, template):
    """16-hex fp for one template. Caller folds to None when
    residual_unsafe(template) is True (R4 defense-in-depth)."""
    digest = hmac.new(key_bytes, template.encode("utf-8"), hashlib.sha256)
    return digest.hexdigest()[:FP_HEX_LEN]


def load_or_create_key(state_dir):
    """Reader-local HMAC key: created once at first start (0600), never
    rotated automatically. O_EXCL create race falls back to read."""
    path = os.path.join(state_dir, KEY_FILENAME)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        fd = -1
    if fd >= 0:
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(secrets.token_bytes(32))
                handle.flush()
                os.fsync(handle.fileno())
        except OSError:
            # Best-effort: a key that could not be written must not be
            # "remembered" -- next call re-reads or re-creates.
            pass
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError:
        raise OSError("hmac_key_unavailable")
    if len(raw) != 32:
        raise OSError("hmac_key_corrupt")  # fail closed; never silently re-create
    return raw
