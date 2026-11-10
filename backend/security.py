"""Password hashing (bcrypt) and signed session-cookie helpers (itsdangerous)."""
import os
import secrets

import bcrypt
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-secret-change-me-in-production")
SESSION_COOKIE = "cl_session"
SESSION_MAX_AGE = 7 * 24 * 60 * 60  # 7 days, in seconds

_serializer = URLSafeTimedSerializer(SECRET_KEY, salt="cl-session-v1")

# Separate salt for Google OAuth "state" values, so a session cookie can
# never be replayed as an OAuth state (or vice versa). Short-lived: the
# whole Google round-trip should take seconds, 10 minutes is generous.
_state_serializer = URLSafeTimedSerializer(SECRET_KEY, salt="cl-google-state-v1")
OAUTH_STATE_MAX_AGE = 10 * 60  # 10 minutes, in seconds


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8")[:72], bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8")[:72], hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def create_session_token(user_id: int, email: str, epoch: int = 0) -> str:
    """A fresh signed session token. Every login mints a NEW token
    (rotation), and the token carries the account's session epoch:
    logging out bumps the epoch server-side, which invalidates every
    previously issued token for that account at once."""
    return _serializer.dumps({
        "uid": user_id, "email": email, "epoch": int(epoch),
        # Random per-token id: without it, itsdangerous tokens are
        # deterministic and two logins in the same second would mint
        # the SAME token (no rotation). With it, every login's token
        # is unique.
        "jti": secrets.token_hex(8),
    })


def read_session_token(token: str):
    """Return the session payload dict, or None if invalid/expired."""
    if not token:
        return None
    try:
        return _serializer.loads(token, max_age=SESSION_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return None


def create_oauth_state() -> str:
    """A signed, short-lived CSRF state value for the Google OAuth flow."""
    return _state_serializer.dumps({"nonce": secrets.token_urlsafe(24)})


def verify_oauth_state(token: str) -> bool:
    """True only if the state value is ours, untampered and fresh."""
    if not token:
        return False
    try:
        _state_serializer.loads(token, max_age=OAUTH_STATE_MAX_AGE)
        return True
    except (BadSignature, SignatureExpired):
        return False


# ---------------------------------------------------------------------------
# Platform-admin session (Farhan's /control page). A separate salt, so an
# owner session can never be replayed as an admin one (or vice versa).
# The token also carries the CSRF value every control-page form must
# send back — a forged cross-site form cannot know it.
# ---------------------------------------------------------------------------
_admin_serializer = URLSafeTimedSerializer(SECRET_KEY, salt="cl-admin-v1")
ADMIN_COOKIE = "cl_admin"
ADMIN_MAX_AGE = 12 * 60 * 60  # 12 hours, in seconds

# Standalone signed CSRF tokens (e.g. the control-page login form, which
# is rendered before any admin session exists).
_csrf_serializer = URLSafeTimedSerializer(SECRET_KEY, salt="cl-csrf-v1")
CSRF_MAX_AGE = 60 * 60  # 1 hour, in seconds


def create_admin_token() -> tuple[str, str]:
    """Return (signed admin session token, CSRF value bound into it)."""
    csrf = secrets.token_urlsafe(24)
    return _admin_serializer.dumps({"admin": True, "csrf": csrf}), csrf


def read_admin_token(token: str):
    """Admin session payload {"admin": True, "csrf": ...}, or None."""
    if not token:
        return None
    try:
        payload = _admin_serializer.loads(token, max_age=ADMIN_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return None
    return payload if isinstance(payload, dict) and payload.get("admin") else None


def create_csrf_token() -> str:
    return _csrf_serializer.dumps({"nonce": secrets.token_urlsafe(24)})


def verify_csrf_token(token: str) -> bool:
    if not token:
        return False
    try:
        _csrf_serializer.loads(token, max_age=CSRF_MAX_AGE)
        return True
    except (BadSignature, SignatureExpired):
        return False
