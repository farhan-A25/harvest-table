"""Each cafe's public ordering token.

Tenant isolation: the token is PER OWNER, stored in the settings table
under an owner-scoped key (``cafe_token:<user_id>``), so it survives
restarts. The token sits inside the cafe's public /t/<token> URL —
printed on the table QR cards. Resetting a cafe's token retires that
cafe's old table cards only.
"""
import secrets

from sqlalchemy.orm import Session

import models

CAFE_TOKEN_KEY = "cafe_token"


def _get_setting(db: Session, key: str, default: str = "") -> str:
    row = db.query(models.Setting).filter(models.Setting.key == key).first()
    return row.value if row else default


def _set_setting(db: Session, key: str, value: str) -> None:
    row = db.query(models.Setting).filter(models.Setting.key == key).first()
    if not row:
        db.add(models.Setting(key=key, value=value))
    else:
        row.value = value


def _token_key(user_id: int) -> str:
    return f"{CAFE_TOKEN_KEY}:{user_id}"


def get_or_create_cafe_token(db: Session, user_id: int) -> str:
    """This cafe's public ordering token, generated on first use."""
    token = _get_setting(db, _token_key(user_id), "")
    if not token:
        token = secrets.token_urlsafe(16)
        _set_setting(db, _token_key(user_id), token)
        db.commit()
    return token


def reset_cafe_token(db: Session, user_id: int) -> str:
    """A fresh token for THIS cafe: its previously printed table cards
    stop working; other cafes' cards are untouched."""
    token = secrets.token_urlsafe(16)
    _set_setting(db, _token_key(user_id), token)
    db.commit()
    return token


def cafe_token_owner(db: Session, token: str) -> int | None:
    """Resolve a public ordering token to its owning cafe (user id),
    or None when the token matches no cafe."""
    if not token:
        return None
    rows = (
        db.query(models.Setting)
        .filter(models.Setting.key.like(f"{CAFE_TOKEN_KEY}:%"))
        .all()
    )
    for row in rows:
        if row.value and secrets.compare_digest(row.value, token):
            try:
                return int(row.key.split(":", 1)[1])
            except ValueError:
                continue
    return None
