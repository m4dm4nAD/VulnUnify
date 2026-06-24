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


def _load_key() -> bytes:
    if settings.secret_key:
        return settings.secret_key.encode()
    if os.path.exists(_KEY_FILE):
        return open(_KEY_FILE, "rb").read().strip()
    key = Fernet.generate_key()
    with open(_KEY_FILE, "wb") as fh:
        fh.write(key)
    log.warning("crypto.dev_key_generated", file=_KEY_FILE,
                hint="set SECRET_KEY for production")
    return key


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
