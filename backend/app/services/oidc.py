"""OIDC / SSO login (Authorization Code + PKCE), provider-agnostic via discovery.

Local password login is unaffected and remains the default; this path is inert
unless issuer + client id + secret are all configured. The flow:

  begin_login()  -> build the IdP authorization URL + an encrypted transaction
                    cookie holding state / nonce / PKCE verifier
  complete_login()-> validate state, exchange the code, verify the ID token
                    signature (JWKS) + iss/aud/exp/nonce, then map the claims to
                    a local user (link by subject or verified email; optionally
                    provision) and hand back the User for a normal session.

Only the local session that follows is trusted — the IdP tokens are used once,
here, and never stored.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets

import httpx
import jwt
import structlog
from jwt import PyJWKClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession

from backend.app.config import settings
from backend.app.models.user import User, UserRole
from backend.app.services import crypto

log = structlog.get_logger()

# Tight timeouts: these blocking calls run in the shared request threadpool, so a
# slow IdP must not hold workers long enough to starve local password login. (A
# hostile IdP that trickles bytes under the per-read timeout is a residual risk;
# it's a configured trust anchor, and a total-deadline needs an async rewrite.)
_HTTP_TIMEOUT = httpx.Timeout(connect=4.0, read=6.0, write=4.0, pool=4.0)
_JWKS_TIMEOUT = 6.0       # PyJWKClient fetches over urllib; wants a plain seconds value
_TXN_TTL = 600            # seconds a login transaction cookie stays valid
# Asymmetric algs only — the ID token is verified against the IdP's public JWKS.
# "none"/HS* are excluded to prevent algorithm-confusion / secret-as-key attacks.
_ALLOWED_ALGS = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"]

_discovery_cache: dict | None = None
_jwks_client: PyJWKClient | None = None


class OidcError(Exception):
    """A recoverable SSO failure; str(exc) is safe to log, not to echo verbatim."""


def is_configured() -> bool:
    return settings.oidc_configured


# --- provider discovery ---

def _discovery() -> dict:
    global _discovery_cache
    if _discovery_cache is None:
        url = settings.oidc_issuer.rstrip("/") + "/.well-known/openid-configuration"
        resp = httpx.get(url, timeout=_HTTP_TIMEOUT)
        resp.raise_for_status()
        doc = resp.json()
        # The discovery issuer must match the configured one (spec requirement).
        if doc.get("issuer", "").rstrip("/") != settings.oidc_issuer.rstrip("/"):
            raise OidcError("OIDC issuer mismatch in discovery document")
        for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            if not doc.get(key):
                raise OidcError(f"OIDC discovery missing {key}")
        _discovery_cache = doc
    return _discovery_cache


def _jwks() -> PyJWKClient:
    global _jwks_client
    if _jwks_client is None:
        _jwks_client = PyJWKClient(_discovery()["jwks_uri"], timeout=_JWKS_TIMEOUT)
    return _jwks_client


def reset_cache() -> None:
    """Drop cached discovery/JWKS (tests; config changes need a restart otherwise)."""
    global _discovery_cache, _jwks_client
    _discovery_cache = None
    _jwks_client = None


# --- transaction cookie (state / nonce / PKCE verifier), encrypted + TTL'd ---

def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    return verifier, challenge


def _encode_txn(data: dict) -> str:
    return crypto.encrypt(json.dumps(data))


def _decode_txn(token: str) -> dict:
    try:
        return json.loads(crypto.decrypt_with_ttl(token, _TXN_TTL))
    except Exception as exc:  # noqa: BLE001 — tampered/expired/absent all fail closed
        raise OidcError("login transaction expired or invalid") from exc


# --- the two request steps ---

def begin_login(redirect_uri: str, next_path: str) -> tuple[str, str]:
    """Return (authorization_url, txn_cookie_value)."""
    if not is_configured():
        raise OidcError("SSO is not configured")
    disc = _discovery()
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    verifier, challenge = _pkce_pair()
    params = {
        "response_type": "code",
        "client_id": settings.oidc_client_id,
        "redirect_uri": redirect_uri,
        "scope": " ".join(settings.oidc_scope_list),
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    auth_url = str(httpx.URL(disc["authorization_endpoint"], params=params))
    txn = _encode_txn({"state": state, "nonce": nonce, "verifier": verifier,
                       "redirect_uri": redirect_uri, "next": next_path})
    return auth_url, txn


def _exchange_code(code: str, redirect_uri: str, verifier: str) -> dict:
    disc = _discovery()
    resp = httpx.post(
        disc["token_endpoint"],
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": settings.oidc_client_id,
            "client_secret": settings.oidc_client_secret,
            "code_verifier": verifier,
        },
        headers={"Accept": "application/json"},
        timeout=_HTTP_TIMEOUT,
    )
    if resp.status_code != 200:
        raise OidcError(f"token exchange failed ({resp.status_code})")
    return resp.json()


def _verify_id_token(id_token: str, nonce: str) -> dict:
    # jwt/JWKS failures (expired, bad sig, bad aud, JWKS-fetch errors) are all
    # subclasses of jwt.PyJWTError; funnel them into OidcError so the callback
    # renders a friendly redirect instead of a 500.
    try:
        signing_key = _jwks().get_signing_key_from_jwt(id_token)
        claims = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=_ALLOWED_ALGS,
            audience=settings.oidc_client_id,
            issuer=_discovery()["issuer"],
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except jwt.PyJWTError as exc:
        raise OidcError(f"ID token validation failed: {exc}") from exc
    if claims.get("nonce") != nonce:
        raise OidcError("OIDC nonce mismatch")
    # When the token is issued to multiple audiences, OIDC requires azp to name
    # this client — otherwise a token minted for another client that merely lists
    # our id in aud would be accepted.
    aud = claims.get("aud")
    if isinstance(aud, list) and len(aud) > 1 and claims.get("azp") != settings.oidc_client_id:
        raise OidcError("OIDC azp does not authorize this client")
    return claims


def complete_login(code: str, state: str, txn_cookie: str, redirect_uri: str,
                   db: DbSession) -> tuple[User, str]:
    """Validate the callback; return (local User, post-login path)."""
    if not is_configured():
        raise OidcError("SSO is not configured")
    txn = _decode_txn(txn_cookie)
    if not state or not secrets.compare_digest(state, txn.get("state", "")):
        raise OidcError("OIDC state mismatch")
    # The redirect_uri in the token exchange must match the one used at authorize.
    tokens = _exchange_code(code, txn.get("redirect_uri", redirect_uri), txn["verifier"])
    id_token = tokens.get("id_token")
    if not id_token:
        raise OidcError("no id_token in token response")
    claims = _verify_id_token(id_token, txn["nonce"])
    user = _find_or_provision(db, claims)
    return user, txn.get("next") or "/"


# --- claims -> local user ---

def _find_or_provision(db: DbSession, claims: dict) -> User:
    sub = claims.get("sub")
    if not sub:
        raise OidcError("ID token missing sub")
    email = (claims.get("email") or "").strip().lower() or None
    # Must be a real JSON boolean true — NOT bool("false"), which is True. Some
    # IdPs serialize this claim as a string; treat anything non-True as unverified.
    email_verified = claims.get("email_verified") is True
    username = (claims.get(settings.oidc_username_claim) or sub).strip()[:128]

    # Domain allowlist: applies to every SSO login when set.
    domains = settings.oidc_allowed_domain_list
    if domains:
        if not (email and email_verified):
            raise OidcError("verified email required for SSO")
        if email.rsplit("@", 1)[-1] not in domains:
            raise OidcError("email domain not allowed for SSO")

    # 1) Known identity: match on the stable subject.
    user = db.scalar(select(User).where(User.oidc_subject == sub))
    if user is not None:
        if not user.is_active:
            raise OidcError("account is disabled")
        return user

    # 2) Link to an existing local account by VERIFIED email only.
    if email and email_verified:
        # case-insensitive email match
        existing = db.scalar(select(User).where(func.lower(User.email) == email))
        if existing is not None:
            if existing.oidc_subject and existing.oidc_subject != sub:
                raise OidcError("email already linked to a different SSO identity")
            if not existing.is_active:
                raise OidcError("account is disabled")
            # Never auto-link an admin by IdP-asserted email: a compromised/loose
            # IdP would otherwise be a direct path to the highest privilege. Admins
            # must sign in with their password (or be linked by subject match).
            if existing.role == UserRole.SECURITY_ADMIN.value:
                raise OidcError("admin accounts cannot be linked via SSO email")
            existing.oidc_subject = sub
            db.commit()
            log.info("oidc.linked", user=existing.username, sub=sub)
            return existing

    # 3) Provision a new account, if enabled.
    if not settings.oidc_auto_provision:
        raise OidcError("no local account for this SSO identity")
    if db.scalar(select(User).where(User.username == username)):
        # Don't hijack an unrelated local username we couldn't verify-match above.
        raise OidcError("username already exists; cannot auto-provision")
    user = User(
        username=username,
        email=email,
        oidc_subject=sub,
        role=settings.oidc_default_role,
        is_active=True,
        password_hash=None,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    log.info("oidc.provisioned", user=user.username, role=user.role, sub=sub)
    return user
