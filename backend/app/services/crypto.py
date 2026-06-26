"""Symmetric encryption for connector credentials at rest (Fernet / AES-128-CBC+HMAC).

The key comes from SECRET_KEY. For local dev, if that's unset, a key is generated
once and persisted to .vulnunify_secret_key so restarts keep working — set
SECRET_KEY explicitly in any real deployment.
"""
from __future__ import annotations

import os

import structlog
from cryptography.fernet import Fernet, InvalidToken

from backend.app.config import settings

log = structlog.get_logger()

_KEY_FILE = ".vulnunify_secret_key"
_fernet: Fernet | None = None


def _read_key(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read().strip()


def _load_key() -> bytes:
    if settings.secret_key:
        return settings.secret_key.encode()
    path = os.path.abspath(_KEY_FILE)
    if os.path.exists(path):
        return _read_key(path)
    key = Fernet.generate_key()
    try:
        # Atomic create with owner-only perms; if another process wins the race,
        # read theirs so we never end up with two different keys.
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(key)
        log.warning("crypto.dev_key_generated", file=path, hint="set SECRET_KEY for production")
        return key
    except FileExistsError:
        return _read_key(path)


def _cipher() -> Fernet:
    global _fernet
    if _fernet is None:
        _fernet = Fernet(_load_key())
    return _fernet


def encrypt(plaintext: str) -> str:
    return _cipher().encrypt(plaintext.encode()).decode()


def decrypt(token: str) -> str:
    """Decrypt a stored value; raises InvalidToken if the key doesn't match."""
    return _cipher().decrypt(token.encode()).decode()


# Re-export so callers can catch a bad-key/corrupt-value case.
__all__ = ["encrypt", "decrypt", "InvalidToken"]
