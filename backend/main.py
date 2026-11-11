"""CafeLoop — Owner App (FastAPI backend).

CafeLoop helps a cafe bring one-time customers back: table-QR ordering
that quietly captures the customer's phone number, an automatic stamp
card (5th drink free), automatic rewards, and a Come Back list with
one-tap WhatsApp offers.

Run from this folder:
    pip install -r requirements.txt
    uvicorn main:app --port 8000
"""
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sys
import time
from collections import defaultdict
from datetime import date, datetime, timedelta
from html import escape as html_escape
from logging.handlers import RotatingFileHandler
from pathlib import Path
from urllib.parse import quote, urlparse

from fastapi import Depends, FastAPI, Form, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

import models
from billing import SUBSCRIPTION_PLANS, get_subscription_plan
from cafe_tokens import cafe_token_owner, get_or_create_cafe_token, reset_cafe_token
from database import Base, SessionLocal, engine, get_db
from google_auth import (
    app_base_url,
    build_authorize_url,
    exchange_code_for_token,
    fetch_google_userinfo,
    google_auth_enabled,
)
from security import (
    ADMIN_COOKIE,
    ADMIN_MAX_AGE,
    SESSION_COOKIE,
    SESSION_MAX_AGE,
    create_admin_token,
    create_csrf_token,
    create_oauth_state,
    create_session_token,
    hash_password,
    read_admin_token,
    read_session_token,
    verify_csrf_token,
    verify_oauth_state,
    verify_password,
)

BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = BASE_DIR.parent / "frontend"
STATIC_DIR = BASE_DIR / "static"
PAYMENT_QR_FILE = STATIC_DIR / "payment-qr.png"
# The cafe's own brand logo (white-label): shown on the public ordering
# page. Belongs to the CAFE, not to the CafeLoop product.
CAFE_LOGO_FILE = STATIC_DIR / "cafe-logo.png"
LOG_DIR = BASE_DIR.parent / "logs"

# ---------------------------------------------------------------------------
# Logging: important events go to logs/app.log (rotating) AND to stderr
# (the host's log stream). Personal data is scrubbed from every line.
# ---------------------------------------------------------------------------
LOG_DIR.mkdir(parents=True, exist_ok=True)
logger = logging.getLogger("cafeloop")
logger.setLevel(logging.INFO)


class _RedactFilter(logging.Filter):
    """Scrub personal data out of every log line: email addresses are
    masked and 10-digit phone numbers are starred."""

    _EMAIL = re.compile(r"([\w.+-]{1,2})[\w.+-]*@([\w-]+(?:\.[\w-]+)+)")
    _PHONE = re.compile(r"\b\d{10}\b")

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
            redacted = self._EMAIL.sub(r"\1***@\2", msg)
            redacted = self._PHONE.sub("**********", redacted)
            if redacted != msg:
                record.msg = redacted
                record.args = ()
        except Exception:
            pass
        return True


if not logger.handlers:
    _formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    _handler = RotatingFileHandler(LOG_DIR / "app.log", maxBytes=1_000_000, backupCount=3)
    _handler.setFormatter(_formatter)
    _handler.addFilter(_RedactFilter())
    logger.addHandler(_handler)
    _console = logging.StreamHandler(sys.stderr)
    _console.setFormatter(_formatter)
    _console.addFilter(_RedactFilter())
    logger.addHandler(_console)
logger.addFilter(_RedactFilter())

Base.metadata.create_all(bind=engine)
logger.info("CafeLoop backend started")

app = FastAPI(title="CafeLoop Owner App", docs_url=None, redoc_url=None, openapi_url=None)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Never leak a stack trace: log it server-side, answer politely."""
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"detail": "Something went wrong on our side. Please try again in a moment."},
    )


@app.get("/health")
def health():
    """App + database status. Public, safe (no data exposed)."""
    db_status = "ok"
    try:
        with engine.connect() as conn:
            conn.exec_driver_sql("SELECT 1")
    except Exception:
        logger.exception("Health check: database unreachable")
        db_status = "error"
    return {"status": "ok" if db_status == "ok" else "degraded", "database": db_status}


@app.get("/api/config")
def public_config():
    """Public, non-sensitive UI configuration (no user data)."""
    return {"app": "cafeloop"}


# ---------------------------------------------------------------------------
# Security headers on every response
# ---------------------------------------------------------------------------
CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'"
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = CSP
    # Camera is allowed ONLY for this site itself (face unlock +
    # enrollment); microphone, location and sensors are off entirely.
    response.headers["Permissions-Policy"] = (
        "camera=(self), microphone=(), geolocation=(), usb=(), "
        "magnetometer=(), gyroscope=(), accelerometer=()"
    )
    if _request_is_https(request):
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
    return response


def _request_is_https(request: Request) -> bool:
    return (
        request.url.scheme == "https"
        or request.headers.get("x-forwarded-proto", "").split(",")[0].strip() == "https"
        or os.environ.get("COOKIE_SECURE", "") == "1"
    )


@app.middleware("http")
async def csrf_origin_check(request: Request, call_next):
    """CSRF defense-in-depth for the owner API: a non-GET /api call that
    arrives WITH an Origin header naming a DIFFERENT host is refused
    outright. Server-to-server callers (no Origin) are unaffected; the
    admin endpoints (secret header / token-protected forms) are exempt."""
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        path = request.url.path
        if (
            path.startswith("/api/")
            and not path.startswith("/api/admin/")
            and not path.startswith("/api/control/")
        ):
            origin = request.headers.get("origin")
            if origin:
                origin_host = urlparse(origin).netloc
                if origin_host and origin_host != request.headers.get("host", ""):
                    logger.warning(
                        "CSRF origin check refused %s %s (Origin host %s)",
                        request.method, path, origin_host,
                    )
                    return _gate_block_response(
                        403, {"detail": "Cross-site request refused."}, request
                    )
    return await call_next(request)


# ---------------------------------------------------------------------------
# Pay-first gate: an authenticated owner whose subscription is not
# ACTIVE gets NO working app. Only the entry flow and the payment step
# stay reachable:
#   * details step .......... /api/details (GET/PUT)
#   * plan + payment ........ /api/plans, /api/plan, /api/plan/switch,
#                             /payment-qr.png (the QR image), and the
#                             face-unlock flow itself (it IS an unlock
#                             path: /api/face-unlock/*)
#   * session ............... /api/me, /api/logout, login/signup, Google
#                             auth, /api/auth/config, /api/config
# Everything else under /api/ answers 402 with code "payment_required".
# The PUBLIC customer ordering (/t/<token>, /api/public/*) is NEVER
# gated: customers keep ordering regardless of the owner's billing.
# The /api/admin/* endpoints authenticate themselves with ADMIN_SECRET.
# ---------------------------------------------------------------------------
GATE_OPEN_PATHS = {
    "/health",
    "/api/config", "/api/plans", "/api/auth/config",
    "/auth/google", "/auth/google/callback",
    "/api/login", "/api/signup", "/api/logout", "/api/me",
    "/api/auth/forgot", "/api/auth/reset",
    "/api/details", "/api/plan", "/api/plan/switch",
    "/api/face-unlock/template",
    "/api/face-unlock/challenge",
    "/api/face-unlock/verify",
    "/payment-qr.png", "/cafe-logo.png", "/icon-512.png",
}

OTP_OPEN_PATHS = {"/api/me", "/api/logout", "/api/config", "/api/auth/config"}


def _gate_block_response(status_code: int, content: dict, request: Request = None) -> JSONResponse:
    """A gate refusal. Sets the security headers inline because this
    response short-circuits before the headers middleware on some paths."""
    response = JSONResponse(status_code=status_code, content=content)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = CSP
    response.headers["Permissions-Policy"] = (
        "camera=(self), microphone=(), geolocation=(), usb=(), "
        "magnetometer=(), gyroscope=(), accelerometer=()"
    )
    if request is not None and _request_is_https(request):
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
    return response


@app.middleware("http")
async def subscription_gate(request: Request, call_next):
    path = request.url.path
    if (
        path.startswith("/api/admin/")
        or path.startswith("/api/control/")
        or path.startswith("/api/public/")
        or path.startswith("/t/")
        or not path.startswith("/api/")
    ):
        return await call_next(request)
    payload = read_session_token(request.cookies.get(SESSION_COOKIE, ""))
    if not payload:
        return await call_next(request)  # not logged in -> endpoints 401
    with SessionLocal() as db:
        user = (
            db.query(models.User)
            .filter(models.User.id == payload.get("uid"))
            .first()
        )
        if user is None:
            return await call_next(request)
        # Canonical flow, stage 2: until the email OTP is entered,
        # EVERYTHING except the OTP endpoints themselves (and a small
        # status set) is blocked. This runs before the payment gate.
        if getattr(user, "otp_pending", False):
            if path in OTP_OPEN_PATHS or (
                path.startswith("/api/auth/") and request.method != "GET"
            ):
                return await call_next(request)
            logger.info(
                "OTP gate blocked %s %s for %s (OTP not yet entered)",
                request.method, path, user.email,
            )
            return _gate_block_response(403, {
                "detail": "Please enter the OTP we sent to your email first.",
                "code": "otp_required",
            }, request)
        info = subscription_info(db, user_id=user.id)
    if path in GATE_OPEN_PATHS:
        return await call_next(request)
    if info["active"]:
        return await call_next(request)
    logger.info(
        "Pay-first gate blocked %s %s for %s (subscription %s)",
        request.method, path, user.email, info["status"],
    )
    return _gate_block_response(402, {
        "detail": "Your subscription is not active. "
                  "Please complete your payment to use CafeLoop.",
        "code": "payment_required",
        "subscription_status": info["status"],
    }, request)


# ---------------------------------------------------------------------------
# Login rate limiting: max 5 attempts / minute / IP (in-memory)
# ---------------------------------------------------------------------------
_login_attempts: dict[str, list[float]] = defaultdict(list)
LOGIN_LIMIT = 5
LOGIN_WINDOW = 60.0


def login_rate_limited(ip: str) -> bool:
    now = time.time()
    attempts = [t for t in _login_attempts[ip] if now - t < LOGIN_WINDOW]
    _login_attempts[ip] = attempts
    if len(attempts) >= LOGIN_LIMIT:
        return True
    attempts.append(now)
    return False


# ---------------------------------------------------------------------------
# Public ordering rate limiting: max 60 attempts / minute / (IP + token).
# Generous for a busy cafe, strict enough to stop abuse.
# ---------------------------------------------------------------------------
_order_attempts: dict[str, list[float]] = defaultdict(list)
ORDER_LIMIT = 60
ORDER_WINDOW = 60.0


def order_rate_limited(key: str) -> bool:
    now = time.time()
    attempts = [t for t in _order_attempts[key] if now - t < ORDER_WINDOW]
    _order_attempts[key] = attempts
    if len(attempts) >= ORDER_LIMIT:
        return True
    attempts.append(now)
    return False


# ---------------------------------------------------------------------------
# Schemas (Pydantic validation on every endpoint)
# ---------------------------------------------------------------------------
class LoginIn(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=1, max_length=200)


class SignupIn(BaseModel):
    owner_name: str = Field(default="", max_length=120)
    cafe_name: str = Field(default="", max_length=160)
    email: str = Field(default="", max_length=255)
    mobile: str = Field(default="", max_length=20)
    password: str = Field(default="", max_length=200)


class DetailsIn(BaseModel):
    cafe_name: str = Field(default="", max_length=160)
    cafe_address: str = Field(default="", max_length=255)
    cafe_city: str = Field(default="", max_length=80)
    cafe_phone: str = Field(default="", max_length=20)
    owner_name: str = Field(default="", max_length=120)
    mobile: str = Field(default="", max_length=20)
    whatsapp: str = Field(default="", max_length=20)


class PlanSwitchIn(BaseModel):
    plan_id: str = Field(default="pro", pattern="^(pro)$")
    period: str = Field(pattern="^(monthly|yearly)$")


class OtpVerifyIn(BaseModel):
    code: str = Field(min_length=4, max_length=8)


class ForgotIn(BaseModel):
    email: str = Field(min_length=3, max_length=255)


class ResetIn(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    code: str = Field(min_length=4, max_length=8)
    new_password: str = Field(min_length=1, max_length=200)


class CategoryIn(BaseModel):
    name: str = Field(default="", max_length=60)


class MenuItemIn(BaseModel):
    name: str = Field(default="", max_length=80)
    price: int = Field(default=0, ge=0, le=100000)
    emoji: str = Field(default="☕", max_length=16)
    category_id: int | None = None
    available: bool = True


class OrderStatusIn(BaseModel):
    status: str = Field(pattern="^(ACCEPTED|PREPARING|SERVED|COMPLETED)$")
    # Set when accepting: the preparation time the owner promises.
    prep_minutes: int | None = Field(default=None, ge=1, le=180)
    # A later delay: push the promised ready time out by this much.
    add_minutes: int | None = Field(default=None, ge=1, le=120)


class RedeemIn(BaseModel):
    code: str = Field(min_length=3, max_length=32)


class OrderPaidIn(BaseModel):
    paid: bool = True


class PublicOrderItemIn(BaseModel):
    item_id: int
    qty: int = Field(default=1, ge=1, le=20)


class PublicOrderIn(BaseModel):
    name: str = Field(default="", max_length=120)
    phone: str = Field(default="", max_length=20)
    table: str = Field(default="", max_length=16)
    items: list[PublicOrderItemIn] = Field(default_factory=list, max_length=50)


class AdminActivateIn(BaseModel):
    user_id: int | None = None
    email: str = Field(default="", max_length=255)
    period: str | None = Field(default=None, pattern="^(monthly|yearly)$")
    csrf: str = Field(default="", max_length=256)


# ---------------------------------------------------------------------------
# Friendly validation helpers (field-by-field messages, never raw errors)
# ---------------------------------------------------------------------------
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def clean_phone(raw: str) -> str:
    """Normalise an Indian phone number to 10 digits where possible."""
    digits = re.sub(r"\D", "", raw or "")
    if len(digits) == 12 and digits.startswith("91"):
        digits = digits[2:]
    if len(digits) == 11 and digits.startswith("0"):
        digits = digits[1:]
    return digits


def valid_mobile(raw: str) -> bool:
    return len(clean_phone(raw)) == 10


def field_error(fields: dict, message: str) -> JSONResponse:
    return JSONResponse(status_code=400, content={"detail": message, "fields": fields})


def user_payload(user: models.User) -> dict:
    return {
        "email": user.email,
        "owner_name": user.owner_name or "",
        "cafe_name": user.cafe_name or "",
        "details_completed": bool(user.details_completed),
        "plan_chosen": bool(user.plan_chosen),
        # Canonical flow stage: True between account creation and the
        # email OTP being entered (details/payment/app stay blocked).
        "otp_pending": bool(getattr(user, "otp_pending", False)),
    }


def details_payload(user: models.User) -> dict:
    return {
        "cafe_name": user.cafe_name or "",
        "cafe_address": user.cafe_address or "",
        "cafe_city": user.cafe_city or "",
        "cafe_phone": user.cafe_phone or "",
        "owner_name": user.owner_name or "",
        "mobile": user.mobile or "",
        "whatsapp": user.whatsapp or "",
        "email": user.email,
    }


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------
def _session_epoch(db: Session, user_id: int) -> int:
    """The account's current session epoch (logout bumps it, killing
    every previously issued session token for that account)."""
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user is None:
        return 0
    return int(getattr(user, "session_epoch", 0) or 0)


def current_user(request: Request, db: Session = Depends(get_db)):
    """Return the logged-in User, or a 401 JSONResponse (endpoints check for it)."""
    payload = read_session_token(request.cookies.get(SESSION_COOKIE, ""))
    if not payload:
        return _unauthorized()
    user = db.query(models.User).filter(models.User.id == payload.get("uid")).first()
    if not user:
        return _unauthorized()
    if int(payload.get("epoch", 0) or 0) != _session_epoch(db, user.id):
        return _unauthorized()  # logged out since this token was issued
    return user


def _unauthorized() -> JSONResponse:
    return JSONResponse(status_code=401, content={"detail": "Not logged in."})


def err(status: int, message: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"detail": message})


# ---------------------------------------------------------------------------
# Settings (small key/value store — plan choice, tokens, overrides)
# ---------------------------------------------------------------------------
def get_setting(db: Session, key: str, default: str = "") -> str:
    row = db.query(models.Setting).filter(models.Setting.key == key).first()
    return row.value if row else default


def set_setting(db: Session, key: str, value: str) -> None:
    row = db.query(models.Setting).filter(models.Setting.key == key).first()
    if not row:
        db.add(models.Setting(key=key, value=value))
    else:
        row.value = value


def _pay_method_label(method: str) -> str:
    """Human label for a recorded payment method — the same wording
    the owner app uses (mirrors Do Gym's payMethodLabel)."""
    return {
        "face_unlock": "Farhan's face scan",
        "collected_in_person": "our team, in person",
        "upi_qr": "UPI QR",
        "razorpay": "Razorpay",
    }.get(method or "", "online payment")


def payment_dict(p: models.SubscriptionPayment) -> dict:
    return {
        "plan_id": p.plan_id,
        "plan_name": p.plan_name,
        "period": p.period,
        "amount": p.amount,
        "method": p.method,
        "method_label": _pay_method_label(p.method),
        "status": p.status,  # paid | pending
        "date": p.created_at.date().isoformat() if p.created_at else "",
    }


# ---------------------------------------------------------------------------
# Subscription state — the pay-first gate's single source of truth.
# ACTIVE means THIS account's latest payment is "paid" and today is
# inside its billing window (monthly = 30 days, yearly = 365 days,
# counted from the payment date). A paid period that has ended is
# "expired": the gate closes again and the payment step is a renewal.
# An account Farhan has SWITCHED OFF from Control counts as not active
# even inside a paid window.
# ---------------------------------------------------------------------------
PERIOD_DAYS = {"monthly": 30, "yearly": 365}
PLAN_ID = "pro"


def _period_end(start: date, period: str) -> date:
    return start + timedelta(days=PERIOD_DAYS.get(period, 30))


def _latest_payment_for(db: Session, user_id: int):
    return (
        db.query(models.SubscriptionPayment)
        .filter(models.SubscriptionPayment.user_id == user_id)
        .order_by(models.SubscriptionPayment.id.desc())
        .first()
    )


def _revoked_key(user_id: int) -> str:
    return f"revoked_user_{user_id}"


def is_revoked(db: Session, user_id: int) -> bool:
    return get_setting(db, _revoked_key(user_id)) == "1"


def set_revoked(db: Session, user_id: int, off: bool) -> None:
    set_setting(db, _revoked_key(user_id), "1" if off else "")


def _user_subscription_state(db: Session, user_id: int) -> dict:
    """One account's subscription from ITS OWN latest payment only —
    another account's payment never unlocks this one."""
    today = date.today()
    latest = _latest_payment_for(db, user_id)
    if latest is None:
        return {"active": False, "status": "unpaid", "expires_on": None}
    if latest.status != "paid":
        return {"active": False, "status": "payment_pending", "expires_on": None}
    start = latest.created_at.date() if latest.created_at else today
    end = _period_end(start, latest.period)
    if today < end:
        return {"active": True, "status": "active", "expires_on": end.isoformat()}
    return {"active": False, "status": "expired", "expires_on": end.isoformat()}


def subscription_info(db: Session, user_id: int) -> dict:
    """{"active": bool, "status": active|payment_pending|expired|unpaid|
    switched_off, "expires_on": ISO date | None} for ONE account."""
    info = _user_subscription_state(db, user_id)
    if is_revoked(db, user_id):
        return {
            "active": False,
            "status": "switched_off",
            "expires_on": info["expires_on"],
        }
    return info


def _account_period(db: Session, user: models.User) -> str:
    """The billing period this cafe runs on: its latest payment's if it
    has ever paid, otherwise its entry-flow choice (default monthly)."""
    latest = _latest_payment_for(db, user.id)
    if latest is not None:
        return latest.period
    return get_setting(db, f"plan_period:{user.id}", "monthly") or "monthly"


def get_plan_state(db: Session, user_id: int) -> dict:
    """The cafe's current subscription, computed server-side from
    billing.py and the recorded payments — the client never supplies
    an amount. There is ONE plan: CafeLoop Pro."""
    plan = get_subscription_plan(PLAN_ID)
    user = db.query(models.User).filter(models.User.id == user_id).first()
    period = _account_period(db, user) if user is not None else "monthly"
    recent = (
        db.query(models.SubscriptionPayment)
        .filter(models.SubscriptionPayment.user_id == user_id)
        .order_by(models.SubscriptionPayment.id.desc())
        .limit(5)
        .all()
    )
    info = subscription_info(db, user_id=user_id)
    customers_used = (
        db.query(models.Customer)
        .filter(models.Customer.user_id == user_id)
        .count()
    )
    return {
        "plan_id": plan["id"],
        "period": period,
        "plan": plan,
        "price": plan["yearly"] if period == "yearly" else plan["monthly"],
        "subscription_active": info["active"],
        "subscription_status": info["status"],
        "subscription_expires_on": info["expires_on"],
        # The locked payment screen shows its "Unlock by Face Scan"
        # action only when Farhan has enrolled his face in Control.
        "face_unlock_available": _face_template(db) is not None,
        "last_payment": payment_dict(recent[0]) if recent else None,
        "payments": [payment_dict(p) for p in recent],
        "usage": {"customers_used": customers_used, "customer_limit": None},
    }


# ---------------------------------------------------------------------------
# Session cookie helpers
# ---------------------------------------------------------------------------
def _apply_session_cookie(resp: Response, request: Request, user: models.User) -> Response:
    """Set the signed, HTTP-only session cookie on any response type."""
    with SessionLocal() as _db:
        token = create_session_token(
            user.id, user.email, _session_epoch(_db, user.id)
        )
    behind_https = (
        request.url.scheme == "https"
        or request.headers.get("x-forwarded-proto", "").split(",")[0].strip() == "https"
        or os.environ.get("COOKIE_SECURE", "") == "1"
    )
    resp.set_cookie(
        SESSION_COOKIE, token, max_age=SESSION_MAX_AGE,
        httponly=True, samesite="lax", path="/",
        secure=behind_https,
    )
    return resp


def _session_response(request: Request, user: models.User, extra: dict | None = None) -> JSONResponse:
    """JSON response that also sets the signed, HTTP-only session cookie."""
    resp = JSONResponse(content={"ok": True, **user_payload(user), **(extra or {})})
    return _apply_session_cookie(resp, request, user)


def _session_redirect(request: Request, user: models.User) -> RedirectResponse:
    """Browser redirect to the app that also logs the user in (OAuth return)."""
    resp = RedirectResponse(url="/", status_code=302)
    return _apply_session_cookie(resp, request, user)


# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------
@app.post("/api/signup")
def signup(body: SignupIn, request: Request, db: Session = Depends(get_db)):
    ip = request.client.host if request.client else "unknown"
    if login_rate_limited("signup:" + ip):
        return err(429, "Too many sign-up attempts. Please wait a minute and try again.")
    fields: dict[str, str] = {}
    owner_name = body.owner_name.strip()
    cafe_name = body.cafe_name.strip()
    email = body.email.strip().lower()
    mobile = clean_phone(body.mobile)
    if len(owner_name) < 2:
        fields["owner_name"] = "Please enter your full name."
    if len(cafe_name) < 2:
        fields["cafe_name"] = "Please enter your cafe's name."
    if not EMAIL_RE.match(email):
        fields["email"] = "Please enter a correct email address."
    if len(mobile) != 10:
        fields["mobile"] = "Please enter a 10-digit mobile number."
    if len(body.password) < 6:
        fields["password"] = "Please choose a password of at least 6 characters."
    if fields:
        return field_error(fields, "Please check the highlighted fields.")
    existing = db.query(models.User).filter(models.User.email == email).first()
    if existing:
        return field_error(
            {"email": "An account with this email already exists. Please log in instead."},
            "An account with this email already exists. Please log in instead.",
        )
    user = models.User(
        email=email,
        password_hash=hash_password(body.password),
        owner_name=owner_name,
        cafe_name=cafe_name,
        mobile=mobile,
        auth_provider="email",
        details_completed=False,
        plan_chosen=False,
        otp_pending=True,  # canonical flow: OTP stage comes next
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    logger.info("New cafe signed up: %s (%s)", email, cafe_name)
    code = _issue_otp(db, user)
    extra = {"otp_pending": True}
    if _dev_otp_echo():
        extra["dev_otp"] = code
    return _session_response(request, user, extra)


@app.post("/api/login")
def login(body: LoginIn, request: Request, db: Session = Depends(get_db)):
    ip = request.client.host if request.client else "unknown"
    if login_rate_limited(ip):
        return err(429, "Too many login attempts. Please wait a minute and try again.")
    user = db.query(models.User).filter(models.User.email == body.email.strip().lower()).first()
    if not user or not verify_password(body.password, user.password_hash):
        return err(401, "Wrong email or password. Please try again.")
    logger.info("Login success for %s from %s", user.email, ip)
    extra = None
    if getattr(user, "otp_pending", False):
        # Still in the OTP stage: make sure a live code exists (a
        # fresh one is sent when the old one expired or was used up).
        extra = {"otp_pending": True}
        if _otp_live(db, user) is None:
            code = _issue_otp(db, user)
            if _dev_otp_echo():
                extra["dev_otp"] = code
        elif _dev_otp_echo():
            row = _otp_challenge(db, user)
            if row is not None and row.dev_code:
                extra["dev_otp"] = row.dev_code
    return _session_response(request, user, extra)


@app.post("/api/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    # Bump the account's session epoch: every token issued so far stops
    # working at once, not just this browser's cookie.
    payload = read_session_token(request.cookies.get(SESSION_COOKIE, ""))
    if payload and payload.get("uid"):
        user = db.query(models.User).filter(
            models.User.id == int(payload["uid"])
        ).first()
        if user is not None:
            user.session_epoch = int(getattr(user, "session_epoch", 0) or 0) + 1
            db.commit()
            logger.info("Logout: session epoch bumped for user %s", user.id)
    resp = JSONResponse(content={"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


# ---------------------------------------------------------------------------
# Google sign-in (OAuth 2.0 / OpenID Connect) — config in google_auth.py.
# The browser flow is: /auth/google -> Google consent -> /auth/google/callback
# Every failure lands back on the login page with a friendly message in
# ?auth_error=... — never a raw error page.
# ---------------------------------------------------------------------------
def _auth_error_redirect(message: str) -> RedirectResponse:
    return RedirectResponse(url="/?auth_error=" + quote(message), status_code=302)


@app.get("/api/auth/config")
def auth_config():
    """Public: which sign-in options the frontend should offer, and
    whether outgoing mail is configured (a boolean only)."""
    return {
        "google_enabled": google_auth_enabled(),
        "mail_configured": _smtp_config() is not None,
    }


@app.get("/auth/google")
def google_start(request: Request):
    """Start Google sign-in: send the browser to Google's consent screen."""
    if not google_auth_enabled():
        return _auth_error_redirect(
            "Google sign-in is not switched on for this app yet. "
            "Please log in with your email and password."
        )
    ip = request.client.host if request.client else "unknown"
    if login_rate_limited("google:" + ip):
        return _auth_error_redirect(
            "Too many sign-in attempts. Please wait a minute and try again."
        )
    return RedirectResponse(url=build_authorize_url(create_oauth_state()), status_code=302)


@app.get("/auth/google/callback")
def google_callback(
    request: Request,
    code: str = "",
    state: str = "",
    error: str = "",
    db: Session = Depends(get_db),
):
    """Google redirects the browser here after the consent screen."""
    if not google_auth_enabled():
        return _auth_error_redirect(
            "Google sign-in is not switched on for this app yet. "
            "Please log in with your email and password."
        )
    if error or not code:
        logger.info("Google sign-in cancelled or denied (error=%s)", error or "no code")
        return _auth_error_redirect(
            "Google sign-in was cancelled. Please try again, "
            "or log in with your email and password."
        )
    if not verify_oauth_state(state):
        logger.warning("Google sign-in arrived with an invalid or expired state value")
        return _auth_error_redirect(
            "That Google sign-in attempt has expired. Please try signing in with Google again."
        )
    try:
        access_token = exchange_code_for_token(code)
        info = fetch_google_userinfo(access_token)
    except Exception:
        logger.exception("Google sign-in failed while talking to Google")
        return _auth_error_redirect(
            "We could not complete Google sign-in just now. Please try again in a moment."
        )
    email = (info.get("email") or "").strip().lower()
    if not info.get("email_verified") or not EMAIL_RE.match(email):
        logger.warning("Google sign-in refused: no verified email from Google")
        return _auth_error_redirect(
            "Google did not share a verified email address, so we cannot sign you in. "
            "Please log in with your email and password instead."
        )
    user = db.query(models.User).filter(models.User.email == email).first()
    if user is None:
        # First Google sign-in: create the account. Google's verified
        # email IS the verification: the account is born verified, no
        # OTP is issued, and the entry flow goes straight to details.
        user = models.User(
            email=email,
            password_hash=hash_password(secrets.token_urlsafe(32)),
            owner_name=(info.get("name") or "").strip()[:120],
            auth_provider="google",
            details_completed=False,
            plan_chosen=False,
            otp_pending=False,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        logger.info("New cafe signed up via Google: %s", email)
    else:
        logger.info("Login via Google for %s", email)
        if getattr(user, "otp_pending", False):
            # Google just proved ownership of this inbox, so a pending
            # OTP stage is cleared on the spot.
            row = _otp_challenge(db, user)
            if row is not None:
                db.delete(row)
            user.otp_pending = False
            db.commit()
            logger.info(
                "Google sign-in verified %s — pending OTP stage cleared", email
            )
    return _session_redirect(request, user)


# ---------------------------------------------------------------------------
# Email OTP — stage 2 of the email/password signup flow: (1) account
# created via email/password, (2) a 6-digit OTP is emailed and entered
# here, (3) only then Cafe & Owner Details, (4) payment.
#
# Delivery: real email via SMTP when SMTP_HOST / SMTP_PORT / SMTP_USER /
# SMTP_PASS / SMTP_FROM are set. Until then the code is written to the
# server log ONLY when the dev flag DEV_OTP_ECHO=1 is set (local
# dev/tests — must stay OFF in production). Codes are stored HASHED,
# live 10 minutes, allow 5 attempts, resend waits 60 seconds.
# ---------------------------------------------------------------------------
OTP_TTL = timedelta(minutes=10)
OTP_MAX_ATTEMPTS = 5
OTP_RESEND_COOLDOWN = 60  # seconds


def _dev_otp_echo() -> bool:
    return os.environ.get("DEV_OTP_ECHO", "").strip() == "1"


def _smtp_config() -> dict | None:
    host = os.environ.get("SMTP_HOST", "").strip()
    user = os.environ.get("SMTP_USER", "").strip()
    password = os.environ.get("SMTP_PASS", "").strip()
    sender = os.environ.get("SMTP_FROM", "").strip()
    if not (host and user and password and sender):
        return None
    try:
        port = int(os.environ.get("SMTP_PORT", "587"))
    except ValueError:
        port = 587
    return {"host": host, "port": port, "user": user, "pass": password, "from": sender}


def _otp_hash(user: models.User, code: str) -> str:
    raw = f"{user.id}:{user.email.lower()}:{code}".encode()
    return hashlib.sha256(raw).hexdigest()


def _deliver_code(email: str, code: str, subject: str, body: str, label: str) -> None:
    """The one SMTP path every emailed code travels. Never raises."""
    cfg = _smtp_config()
    if cfg is None:
        if _dev_otp_echo():
            logger.info(
                "%s for %s: %s (DEV_OTP_ECHO on — code logged for dev only)",
                label, email, code,
            )
        else:
            logger.info(
                "%s issued for %s (SMTP not configured — code not logged; "
                "set SMTP_* to email codes for real)", label, email,
            )
        return
    try:
        import smtplib
        from email.message import EmailMessage

        msg = EmailMessage()
        msg["From"] = cfg["from"]
        msg["To"] = email
        msg["Subject"] = subject
        msg.set_content(body)
        with smtplib.SMTP(cfg["host"], cfg["port"], timeout=15) as server:
            server.starttls()
            server.login(cfg["user"], cfg["pass"])
            server.send_message(msg)
        logger.info("%s email sent to %s via SMTP", label, email)
    except Exception:
        logger.exception("%s email to %s FAILED via SMTP", label, email)


def _deliver_otp(email: str, code: str) -> None:
    _deliver_code(
        email, code,
        "Your CafeLoop OTP",
        f"Your CafeLoop one-time passcode is {code}.\n\n"
        "It works for 10 minutes. If you did not ask for it, "
        "you can ignore this email.\n",
        "OTP",
    )


def _deliver_password_reset(email: str, code: str) -> None:
    _deliver_code(
        email, code,
        "Reset your CafeLoop password",
        f"Your CafeLoop password-reset code is {code}.\n\n"
        "It works for 10 minutes. Enter it on the Forgot Password "
        "screen to set a new password.\n\n"
        "If you did not ask for it, you can ignore this email — "
        "your password stays unchanged.\n",
        "Password-reset code",
    )


def _otp_challenge(db: Session, user: models.User):
    return (
        db.query(models.OtpChallenge)
        .filter(models.OtpChallenge.user_id == user.id)
        .first()
    )


def _otp_live(db: Session, user: models.User):
    """The account's challenge row if it is still usable, else None."""
    row = _otp_challenge(db, user)
    if row is None or row.expires_at <= datetime.now():
        return None
    return row


def _issue_otp(db: Session, user: models.User) -> str:
    """Generate a fresh OTP (replacing any old one), deliver it, and
    return the plain code (used only for the dev echo)."""
    code = f"{secrets.randbelow(900000) + 100000:06d}"
    now = datetime.now()
    row = _otp_challenge(db, user)
    if row is None:
        row = models.OtpChallenge(user_id=user.id)
        db.add(row)
    row.code_hash = _otp_hash(user, code)
    row.dev_code = code if _dev_otp_echo() else None
    row.attempts = 0
    row.last_sent_at = now
    row.expires_at = now + OTP_TTL
    db.commit()
    _deliver_otp(user.email, code)
    return code


def _otp_state(db: Session, user: models.User) -> dict:
    """OTP timing fields for /api/me — drives the OTP screen."""
    state = {"otp_resend_in": 0, "otp_expires_in": None}
    if not getattr(user, "otp_pending", False):
        return state
    row = _otp_challenge(db, user)
    if row is None:
        return state
    now = datetime.now()
    state["otp_resend_in"] = max(
        0, OTP_RESEND_COOLDOWN - int((now - row.last_sent_at).total_seconds())
    )
    state["otp_expires_in"] = max(0, int((row.expires_at - now).total_seconds()))
    return state


def _otp_err(status: int, message: str, code: str) -> JSONResponse:
    return JSONResponse(
        status_code=status, content={"detail": message, "code": code}
    )


@app.post("/api/auth/otp/send")
def otp_send(
    db: Session = Depends(get_db),
    user: models.User | JSONResponse = Depends(current_user),
):
    """(Re)send the OTP. A resend waits out the 60-second cooldown;
    with DEV_OTP_ECHO=1 the response carries the live code (dev/tests
    only — off in production)."""
    if isinstance(user, JSONResponse):
        return user
    if not getattr(user, "otp_pending", False):
        return {"ok": True, "otp_pending": False}
    row = _otp_challenge(db, user)
    if row is not None:
        waited = (datetime.now() - row.last_sent_at).total_seconds()
        if waited < OTP_RESEND_COOLDOWN:
            if _dev_otp_echo() and row.dev_code:
                return {"ok": True, "otp_pending": True, "dev_otp": row.dev_code}
            return _otp_err(
                429,
                f"Please wait {int(OTP_RESEND_COOLDOWN - waited)} seconds "
                "before asking for a new OTP.",
                "otp_cooldown",
            )
    code = _issue_otp(db, user)
    out = {"ok": True, "otp_pending": True}
    if _dev_otp_echo():
        out["dev_otp"] = code
    return out


@app.post("/api/auth/otp/verify")
def otp_verify(
    body: OtpVerifyIn,
    db: Session = Depends(get_db),
    user: models.User | JSONResponse = Depends(current_user),
):
    """Enter the OTP. The right code ends the OTP stage and the normal
    flow (details -> payment) opens."""
    if isinstance(user, JSONResponse):
        return user
    if not getattr(user, "otp_pending", False):
        return {"ok": True, "otp_pending": False, "already_verified": True}
    row = _otp_challenge(db, user)
    if row is None or row.expires_at <= datetime.now():
        return _otp_err(
            400,
            "That OTP has expired. Please tap Resend for a fresh one.",
            "otp_expired",
        )
    if row.attempts >= OTP_MAX_ATTEMPTS:
        return _otp_err(
            400,
            "Too many wrong attempts. Please tap Resend for a fresh OTP.",
            "otp_locked",
        )
    if not hmac.compare_digest(_otp_hash(user, body.code.strip()), row.code_hash):
        row.attempts += 1
        db.commit()
        left = OTP_MAX_ATTEMPTS - row.attempts
        logger.info("OTP verify failed for %s (%d attempt(s) left)", user.email, left)
        if left <= 0:
            return _otp_err(
                400,
                "Too many wrong attempts. Please tap Resend for a fresh OTP.",
                "otp_locked",
            )
        return _otp_err(
            400, f"That OTP is not correct. {left} attempt(s) left.", "otp_wrong"
        )
    user.otp_pending = False
    db.delete(row)
    db.commit()
    logger.info("OTP verified for %s — details/payment stage unlocked", user.email)
    return {"ok": True, **user_payload(user)}


# ---------------------------------------------------------------------------
# Password reset — "Forgot password?" on the login screen. The response
# to /api/auth/forgot is ALWAYS the same generic success so the endpoint
# can never probe which emails have accounts. Reset codes live in their
# own table, hashed with a "pwreset:" domain prefix.
# ---------------------------------------------------------------------------
RESET_GENERIC_MESSAGE = (
    "If an account with this email exists, a reset code has been sent."
)


def _reset_hash(user: models.User, code: str) -> str:
    raw = f"pwreset:{user.id}:{user.email.lower()}:{code}".encode()
    return hashlib.sha256(raw).hexdigest()


def _reset_challenge(db: Session, user: models.User):
    return (
        db.query(models.PasswordResetChallenge)
        .filter(models.PasswordResetChallenge.user_id == user.id)
        .first()
    )


def _issue_password_reset(db: Session, user: models.User) -> str:
    code = f"{secrets.randbelow(900000) + 100000:06d}"
    now = datetime.now()
    row = _reset_challenge(db, user)
    if row is None:
        row = models.PasswordResetChallenge(user_id=user.id)
        db.add(row)
    row.code_hash = _reset_hash(user, code)
    row.dev_code = code if _dev_otp_echo() else None
    row.attempts = 0
    row.last_sent_at = now
    row.expires_at = now + OTP_TTL
    db.commit()
    _deliver_password_reset(user.email, code)
    return code


@app.post("/api/auth/forgot")
def forgot_password(body: ForgotIn, request: Request, db: Session = Depends(get_db)):
    ip = request.client.host if request.client else "unknown"
    email = body.email.strip().lower()
    generic = {"ok": True, "message": RESET_GENERIC_MESSAGE}
    if login_rate_limited("forgot:" + ip):
        return generic
    if login_rate_limited("forgot-email:" + email):
        return generic
    user = db.query(models.User).filter(models.User.email == email).first()
    if user is None:
        return generic
    row = _reset_challenge(db, user)
    if row is not None:
        waited = (datetime.now() - row.last_sent_at).total_seconds()
        if waited < OTP_RESEND_COOLDOWN:
            return generic
    _issue_password_reset(db, user)
    return generic


def _reset_invalid() -> JSONResponse:
    return _otp_err(
        400,
        "That code is not correct or has expired. "
        "Please check it, or ask for a new one.",
        "reset_invalid",
    )


@app.post("/api/auth/reset")
def reset_password(body: ResetIn, request: Request, db: Session = Depends(get_db)):
    ip = request.client.host if request.client else "unknown"
    if login_rate_limited("reset:" + ip):
        return err(429, "Too many attempts. Please wait a minute and try again.")
    if len(body.new_password) < 6:
        return field_error(
            {"new_password": "Please choose a password of at least 6 characters."},
            "Please check the highlighted fields.",
        )
    email = body.email.strip().lower()
    user = db.query(models.User).filter(models.User.email == email).first()
    if user is None:
        return _reset_invalid()
    row = _reset_challenge(db, user)
    if row is None or row.expires_at <= datetime.now():
        return _reset_invalid()
    if row.attempts >= OTP_MAX_ATTEMPTS:
        return _reset_invalid()
    if not hmac.compare_digest(_reset_hash(user, body.code.strip()), row.code_hash):
        row.attempts += 1
        db.commit()
        return _reset_invalid()
    user.password_hash = hash_password(body.new_password)
    user.session_epoch = int(getattr(user, "session_epoch", 0) or 0) + 1
    db.delete(row)
    db.commit()
    logger.info("Password reset completed for %s — all sessions invalidated", user.email)
    return {"ok": True}


# ---------------------------------------------------------------------------
# Me + details (collected ONCE — a same-account re-login never re-asks,
# because details_completed lives on the account row itself)
# ---------------------------------------------------------------------------
@app.get("/api/me")
def me(db: Session = Depends(get_db), user: models.User = Depends(current_user)):
    if isinstance(user, JSONResponse):
        return user
    return {**user_payload(user), **_otp_state(db, user)}


@app.get("/api/details")
def get_details(user: models.User = Depends(current_user)):
    if isinstance(user, JSONResponse):
        return user
    return details_payload(user)


# The full starter menu (Farhan's order, 2026-11-10): a complete
# Indian cafe menu — not just coffee — with realistic ₹ prices, so the
# ordering page feels complete from the first minute. The owner edits
# it freely afterwards.
SAMPLE_MENU = [
    ("Hot Coffee", [
        ("Cappuccino", 180, "☕"),
        ("Cafe Latte", 200, "🥛"),
        ("Espresso", 120, "☕"),
        ("Mocha", 220, "🍫"),
        ("Filter Coffee", 90, "☕"),
    ]),
    ("Cold Coffee & Shakes", [
        ("Cold Coffee", 160, "🧊"),
        ("Iced Latte", 190, "🥤"),
        ("KitKat Shake", 240, "🥤"),
        ("Oreo Shake", 230, "🥤"),
    ]),
    ("Chai & Hot Drinks", [
        ("Masala Chai", 60, "🍵"),
        ("Adrak Chai", 70, "🍵"),
        ("Hot Chocolate", 160, "🍫"),
    ]),
    ("Juices & Coolers", [
        ("Fresh Orange Juice", 120, "🍊"),
        ("Watermelon Cooler", 110, "🍉"),
        ("Virgin Mint Mojito", 150, "🍋"),
    ]),
    ("Snacks & Fries", [
        ("Peri Peri Fries", 140, "🍟"),
        ("Garlic Bread", 150, "🍞"),
        ("Nachos with Salsa", 180, "🧀"),
    ]),
    ("Sandwiches & Burgers", [
        ("Veg Sandwich", 140, "🥪"),
        ("Grilled Cheese Sandwich", 170, "🧀"),
        ("Veg Burger", 130, "🍔"),
        ("Paneer Tikka Sandwich", 190, "🥪"),
    ]),
    ("Maggi & Pasta", [
        ("Masala Maggi", 100, "🍜"),
        ("White Sauce Pasta", 220, "🍝"),
        ("Red Sauce Pasta", 210, "🍝"),
    ]),
    ("Pizza", [
        ("Margherita Pizza", 220, "🍕"),
        ("Veggie Delight Pizza", 300, "🍕"),
        ("Paneer Tikka Pizza", 340, "🍕"),
    ]),
    ("Breakfast", [
        ("Bun Maska", 80, "🥐"),
        ("Poha", 90, "🍽️"),
        ("Upma", 90, "🍽️"),
        ("Aloo Paratha (2 pc)", 130, "🫓"),
    ]),
    ("Desserts & Cakes", [
        ("Brownie with Ice Cream", 180, "🍫"),
        ("Choco Lava Cake", 110, "🍰"),
        ("Muffin", 70, "🧁"),
    ]),
]


def ensure_sample_menu(db: Session, user_id: int) -> None:
    """Seed the sample menu for a cafe that has no categories yet."""
    exists = (
        db.query(models.MenuCategory)
        .filter(models.MenuCategory.user_id == user_id)
        .first()
    )
    if exists is not None:
        return
    for ci, (cat_name, items) in enumerate(SAMPLE_MENU):
        cat = models.MenuCategory(user_id=user_id, name=cat_name, sort=ci)
        db.add(cat)
        db.flush()
        for ii, (name, price, emoji) in enumerate(items):
            db.add(models.MenuItem(
                user_id=user_id, category_id=cat.id,
                name=name, price=price, emoji=emoji, available=True, sort=ii,
            ))
    db.commit()
    logger.info("Sample menu seeded for cafe user %s", user_id)


@app.put("/api/details")
def save_details(body: DetailsIn, db: Session = Depends(get_db), user: models.User = Depends(current_user)):
    if isinstance(user, JSONResponse):
        return user
    fields: dict[str, str] = {}
    cafe_phone = clean_phone(body.cafe_phone)
    mobile = clean_phone(body.mobile)
    whatsapp = clean_phone(body.whatsapp) if body.whatsapp.strip() else ""
    if len(body.cafe_name.strip()) < 2:
        fields["cafe_name"] = "Please enter your cafe's name."
    if len(body.cafe_address.strip()) < 5:
        fields["cafe_address"] = "Please enter your cafe's full address."
    if len(body.cafe_city.strip()) < 2:
        fields["cafe_city"] = "Please enter your city."
    if len(cafe_phone) != 10:
        fields["cafe_phone"] = "Please enter a 10-digit phone number for the cafe."
    if len(body.owner_name.strip()) < 2:
        fields["owner_name"] = "Please enter your full name."
    if len(mobile) != 10:
        fields["mobile"] = "Please enter your 10-digit mobile number."
    if whatsapp and len(whatsapp) != 10:
        fields["whatsapp"] = "Please enter a 10-digit WhatsApp number, or leave it empty."
    if fields:
        return field_error(fields, "Please check the highlighted fields.")
    user.cafe_name = body.cafe_name.strip()
    user.cafe_address = body.cafe_address.strip()
    user.cafe_city = body.cafe_city.strip()
    user.cafe_phone = cafe_phone
    user.owner_name = body.owner_name.strip()
    user.mobile = mobile
    user.whatsapp = whatsapp
    user.details_completed = True
    db.commit()
    ensure_sample_menu(db, user.id)
    logger.info("Cafe & owner details saved for %s", user.email)
    return {"ok": True, **details_payload(user), **user_payload(user)}


# ---------------------------------------------------------------------------
# Cafe domain helpers (everything computed from real rows, always)
# ---------------------------------------------------------------------------
STAMPS_PER_CARD = 5
REWARD_VALID_DAYS = 7
COMEBACK_MIN_VISITS = 2
COMEBACK_MIN_DAYS = 14
AUTO_COMPLETE_AFTER = timedelta(minutes=30)

_REWARD_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"


def cafe_display_name(db: Session, user_id: int) -> str:
    owner = db.query(models.User).filter(models.User.id == user_id).first()
    if owner and (owner.cafe_name or "").strip():
        return owner.cafe_name.strip()
    return "CafeLoop"


def category_dict(c: models.MenuCategory) -> dict:
    return {"id": c.id, "name": c.name, "sort": c.sort}


def menu_item_dict(db: Session, item: models.MenuItem) -> dict:
    cat = None
    if item.category_id is not None:
        row = db.query(models.MenuCategory).filter(
            models.MenuCategory.id == item.category_id
        ).first()
        cat = row.name if row else None
    return {
        "id": item.id,
        "name": item.name,
        "price": item.price,
        "emoji": item.emoji or "☕",
        "available": bool(item.available),
        "category_id": item.category_id,
        "category": cat,
        "sort": item.sort,
    }


def menu_payload(db: Session, user_id: int, only_available: bool = False) -> dict:
    cats = (
        db.query(models.MenuCategory)
        .filter(models.MenuCategory.user_id == user_id)
        .order_by(models.MenuCategory.sort, models.MenuCategory.id)
        .all()
    )
    q = db.query(models.MenuItem).filter(models.MenuItem.user_id == user_id)
    if only_available:
        q = q.filter(models.MenuItem.available.is_(True))
    items = q.order_by(models.MenuItem.sort, models.MenuItem.id).all()
    return {
        "categories": [category_dict(c) for c in cats],
        "items": [menu_item_dict(db, i) for i in items],
    }


def favourite_item(db: Session, customer_id: int) -> str | None:
    """The item this customer has ordered most (by quantity), from
    order-line snapshots. None when they have never ordered."""
    rows = (
        db.query(models.OrderItem.item_name, func.sum(models.OrderItem.qty).label("q"))
        .join(models.Order, models.Order.id == models.OrderItem.order_id)
        .filter(models.Order.customer_id == customer_id)
        .group_by(models.OrderItem.item_name)
        .order_by(func.sum(models.OrderItem.qty).desc(), models.OrderItem.item_name)
        .all()
    )
    return rows[0][0] if rows else None


def active_reward(db: Session, customer_id: int) -> models.Reward | None:
    """The customer's live reward: issued, not redeemed, not expired."""
    today = date.today()
    return (
        db.query(models.Reward)
        .filter(
            models.Reward.customer_id == customer_id,
            models.Reward.status == "active",
            models.Reward.expires_on >= today,
        )
        .order_by(models.Reward.id.desc())
        .first()
    )


def reward_dict(r: models.Reward) -> dict:
    return {
        "code": r.code,
        "status": r.status,
        "issued_at": r.issued_at.isoformat() if r.issued_at else None,
        "expires_on": r.expires_on.isoformat() if r.expires_on else None,
        "redeemed_at": r.redeemed_at.isoformat() if r.redeemed_at else None,
    }


def customer_dict(db: Session, c: models.Customer, today: date | None = None) -> dict:
    today = today or date.today()
    r = active_reward(db, c.id)
    return {
        "id": c.id,
        "name": c.name or "",
        "phone": c.phone,
        "visits": c.visits,
        "stamps": c.stamps,
        "stamps_per_card": STAMPS_PER_CARD,
        "favourite": favourite_item(db, c.id),
        "first_visit": c.first_visit.isoformat() if c.first_visit else None,
        "last_visit": c.last_visit.isoformat() if c.last_visit else None,
        "days_absent": (today - c.last_visit).days if c.last_visit else None,
        "active_reward": reward_dict(r) if r else None,
    }


def order_dict(db: Session, o: models.Order) -> dict:
    cust = o.customer
    minutes_left = None
    if o.status in ("ACCEPTED", "PREPARING") and o.ready_at is not None:
        minutes_left = max(0, int((o.ready_at - datetime.now()).total_seconds() // 60))
    return {
        "id": o.id,
        "table": o.table_no,
        "status": o.status,
        "total": o.total,
        "prep_minutes": o.prep_minutes,
        "accepted_at": o.accepted_at.isoformat() if o.accepted_at else None,
        "ready_at": o.ready_at.isoformat() if o.ready_at else None,
        "minutes_left": minutes_left,
        "items": [
            {"name": i.item_name, "price": i.price, "qty": i.qty} for i in o.items
        ],
        "customer": {
            "id": cust.id if cust else None,
            "name": (cust.name or "") if cust else "",
            "phone": cust.phone if cust else "",
        },
        "stamp_awarded": bool(o.stamp_awarded),
        "paid": bool(o.paid),
        "created_at": o.created_at.isoformat() if o.created_at else None,
        "served_at": o.served_at.isoformat() if o.served_at else None,
    }


def _issue_reward(db: Session, user_id: int, customer: models.Customer) -> models.Reward:
    """Create a fresh FREE-drink reward with a unique CL-XXXXXX code,
    valid 7 days from today. Caller commits."""
    for _ in range(20):
        code = "CL-" + "".join(secrets.choice(_REWARD_ALPHABET) for _ in range(6))
        clash = db.query(models.Reward).filter(models.Reward.code == code).first()
        if clash is None:
            break
    reward = models.Reward(
        user_id=user_id,
        customer_id=customer.id,
        code=code,
        status="active",
        issued_at=datetime.now(),
        expires_on=date.today() + timedelta(days=REWARD_VALID_DAYS),
    )
    db.add(reward)
    db.flush()
    logger.info("Reward %s issued to customer %s (cafe %s)", code, customer.id, user_id)
    return reward


def _award_stamp_for_order(db: Session, order: models.Order) -> None:
    """THE automatic loyalty step, run exactly once per order when it
    is served: +1 visit, +1 stamp, and a full card (5) issues a reward
    and resets the card — all without any human tapping anything."""
    if order.stamp_awarded:
        return
    customer = order.customer
    today = date.today()
    customer.visits += 1
    if customer.first_visit is None:
        customer.first_visit = today
    customer.last_visit = today
    customer.stamps += 1
    if customer.stamps >= STAMPS_PER_CARD:
        customer.stamps = 0
        _issue_reward(db, order.user_id, customer)
    order.stamp_awarded = True


def _auto_complete_orders(db: Session, user_id: int) -> None:
    """SERVED orders flip to COMPLETED automatically once they are
    half an hour old — the owner's order list stays clean by itself."""
    cutoff = datetime.now() - AUTO_COMPLETE_AFTER
    stale = (
        db.query(models.Order)
        .filter(
            models.Order.user_id == user_id,
            models.Order.status == "SERVED",
            models.Order.served_at.isnot(None),
            models.Order.served_at <= cutoff,
        )
        .all()
    )
    for o in stale:
        o.status = "COMPLETED"
    if stale:
        db.commit()


def own_order(db: Session, user_id: int, order_id: int) -> models.Order | None:
    return (
        db.query(models.Order)
        .filter(models.Order.id == order_id, models.Order.user_id == user_id)
        .first()
    )


def own_customer(db: Session, user_id: int, customer_id: int) -> models.Customer | None:
    return (
        db.query(models.Customer)
        .filter(models.Customer.id == customer_id, models.Customer.user_id == user_id)
        .first()
    )


# ---------------------------------------------------------------------------
# Owner app endpoints (all require login + active subscription)
# ---------------------------------------------------------------------------
@app.get("/api/dashboard")
def dashboard(db: Session = Depends(get_db), user: models.User = Depends(current_user)):
    if isinstance(user, JSONResponse):
        return user
    _auto_complete_orders(db, user.id)
    today = date.today()
    day_start = datetime(today.year, today.month, today.day)
    todays = (
        db.query(models.Order)
        .filter(models.Order.user_id == user.id, models.Order.created_at >= day_start)
        .all()
    )
    # Revenue = money actually taken at the counter today (orders the
    # owner marked paid). The website never collects customer money.
    revenue = sum(o.total for o in todays if o.paid)
    customers = (
        db.query(models.Customer)
        .filter(models.Customer.user_id == user.id)
        .all()
    )
    repeat = sum(1 for c in customers if c.visits >= 2)
    repeat_pct = round(100.0 * repeat / len(customers), 1) if customers else 0.0
    rewards_active = (
        db.query(models.Reward)
        .filter(
            models.Reward.user_id == user.id,
            models.Reward.status == "active",
            models.Reward.expires_on >= today,
        )
        .count()
    )
    week_start = datetime.combine(today - timedelta(days=6), datetime.min.time())
    top_rows = (
        db.query(models.OrderItem.item_name, func.sum(models.OrderItem.qty).label("q"))
        .join(models.Order, models.Order.id == models.OrderItem.order_id)
        .filter(models.Order.user_id == user.id, models.Order.created_at >= week_start)
        .group_by(models.OrderItem.item_name)
        .order_by(func.sum(models.OrderItem.qty).desc(), models.OrderItem.item_name)
        .limit(5)
        .all()
    )
    return {
        "cafe_name": user.cafe_name or "",
        "orders_today": len(todays),
        "orders_open": sum(1 for o in todays if o.status in ("NEW", "ACCEPTED", "PREPARING")),
        "orders_new": sum(1 for o in todays if o.status == "NEW"),
        "orders_unpaid": sum(1 for o in todays if o.status in ("SERVED", "COMPLETED") and not o.paid),
        "revenue_today": revenue,
        "total_customers": len(customers),
        "repeat_customers": repeat,
        "repeat_pct": repeat_pct,
        "rewards_active": rewards_active,
        "comeback_count": len(_comeback_rows(db, user.id, today)),
        "top_items": [{"name": n, "qty": int(q)} for n, q in top_rows],
    }


@app.get("/api/orders")
def list_orders(db: Session = Depends(get_db), user: models.User = Depends(current_user)):
    """The owner's live orders: newest first. The owner app polls this
    every ~2 seconds; SERVED orders auto-complete behind the scenes."""
    if isinstance(user, JSONResponse):
        return user
    _auto_complete_orders(db, user.id)
    rows = (
        db.query(models.Order)
        .filter(models.Order.user_id == user.id)
        .order_by(models.Order.id.desc())
        .limit(100)
        .all()
    )
    return {"orders": [order_dict(db, o) for o in rows]}


@app.post("/api/orders/{order_id}/status")
def set_order_status(
    order_id: int,
    body: OrderStatusIn,
    db: Session = Depends(get_db),
    user: models.User = Depends(current_user),
):
    """Move an order along NEW -> ACCEPTED -> PREPARING -> SERVED
    (-> COMPLETED). Accepting sets the promised preparation time
    (ready_at = now + prep_minutes) that the customer's phone tracks
    live; while ACCEPTED/PREPARING the owner can push the ready time
    out with add_minutes (a delay) and the customer sees it move.
    Reaching SERVED awards the customer's stamp automatically —
    exactly once per order, however many times this is called."""
    if isinstance(user, JSONResponse):
        return user
    order = own_order(db, user.id, order_id)
    if order is None:
        return err(404, "Order not found.")
    flow = {"NEW": 0, "ACCEPTED": 1, "PREPARING": 2, "SERVED": 3, "COMPLETED": 4}
    target = body.status
    now = datetime.now()
    if target == order.status:
        # Same-status call: only a time update is meaningful here.
        if body.add_minutes and order.status in ("ACCEPTED", "PREPARING") and order.ready_at is not None:
            order.ready_at = order.ready_at + timedelta(minutes=body.add_minutes)
            if order.prep_minutes is not None:
                order.prep_minutes += body.add_minutes
            db.commit()
            logger.info("Order %s (cafe %s) delayed by %s min", order.id, user.id, body.add_minutes)
        return {"ok": True, "order": order_dict(db, order)}  # idempotent
    if flow[target] < flow[order.status]:
        return err(400, f"An order cannot go back from {order.status} to {target}.")
    if target == "ACCEPTED":
        minutes = body.prep_minutes or order.prep_minutes or 15
        order.prep_minutes = minutes
        order.accepted_at = now
        order.ready_at = now + timedelta(minutes=minutes)
    elif body.add_minutes and order.ready_at is not None:
        order.ready_at = order.ready_at + timedelta(minutes=body.add_minutes)
        if order.prep_minutes is not None:
            order.prep_minutes += body.add_minutes
    if target in ("SERVED", "COMPLETED"):
        if order.served_at is None:
            order.served_at = now
        _award_stamp_for_order(db, order)
    order.status = target
    db.commit()
    logger.info("Order %s (cafe %s) -> %s", order.id, user.id, target)
    return {"ok": True, "order": order_dict(db, order)}


@app.post("/api/orders/{order_id}/paid")
def set_order_paid(
    order_id: int,
    body: OrderPaidIn,
    db: Session = Depends(get_db),
    user: models.User = Depends(current_user),
):
    """The owner's counter bookkeeping: the customer paid at the
    counter (cash/UPI in person — the website never takes customer
    money). Dashboard revenue counts orders marked paid."""
    if isinstance(user, JSONResponse):
        return user
    order = own_order(db, user.id, order_id)
    if order is None:
        return err(404, "Order not found.")
    order.paid = bool(body.paid)
    order.paid_at = datetime.now() if body.paid else None
    db.commit()
    return {"ok": True, "order": order_dict(db, order)}


@app.get("/api/customers")
def list_customers(db: Session = Depends(get_db), user: models.User = Depends(current_user)):
    if isinstance(user, JSONResponse):
        return user
    rows = (
        db.query(models.Customer)
        .filter(models.Customer.user_id == user.id)
        .order_by(models.Customer.visits.desc(), models.Customer.id)
        .all()
    )
    today = date.today()
    return {"customers": [customer_dict(db, c, today) for c in rows]}


def _comeback_rows(db: Session, user_id: int, today: date) -> list[models.Customer]:
    """Customers who came at least twice but have been gone at least
    14 days — the ones a WhatsApp offer can win back."""
    rows = (
        db.query(models.Customer)
        .filter(
            models.Customer.user_id == user_id,
            models.Customer.visits >= COMEBACK_MIN_VISITS,
            models.Customer.last_visit.isnot(None),
        )
        .all()
    )
    out = [c for c in rows if (today - c.last_visit).days >= COMEBACK_MIN_DAYS]
    out.sort(key=lambda c: (-(today - c.last_visit).days, c.id))
    return out


@app.get("/api/comeback")
def comeback(db: Session = Depends(get_db), user: models.User = Depends(current_user)):
    if isinstance(user, JSONResponse):
        return user
    today = date.today()
    cafe = cafe_display_name(db, user.id)
    result = []
    for c in _comeback_rows(db, user.id, today):
        d = customer_dict(db, c, today)
        fav = d["favourite"] or "coffee"
        d["message"] = (
            f"Namaste {c.name or 'friend'}! We miss you at {cafe}. "
            f"Your favourite {fav} is waiting — 20% OFF this week, "
            f"just for you. Come soon!"
        )
        result.append(d)
    return {"customers": result}


@app.post("/api/rewards/redeem")
def redeem_reward(
    body: RedeemIn,
    db: Session = Depends(get_db),
    user: models.User = Depends(current_user),
):
    """Owner confirms a customer's reward code: one tap, recorded.
    A code can be redeemed exactly once, and only at its own cafe."""
    if isinstance(user, JSONResponse):
        return user
    code = body.code.strip().upper()
    reward = (
        db.query(models.Reward)
        .filter(models.Reward.user_id == user.id, models.Reward.code == code)
        .first()
    )
    if reward is None:
        return err(404, "That reward code was not found for your cafe.")
    if reward.status == "redeemed":
        return err(400, "That reward has already been redeemed.")
    if reward.expires_on < date.today():
        return err(400, "That reward has expired.")
    reward.status = "redeemed"
    reward.redeemed_at = datetime.now()
    db.commit()
    cust = reward.customer
    logger.info("Reward %s redeemed at cafe %s", code, user.id)
    return {
        "ok": True,
        "reward": reward_dict(reward),
        "customer": {"name": (cust.name or "") if cust else "", "phone": cust.phone if cust else ""},
        "message": "Reward redeemed — one FREE drink given.",
    }


# ---------------------------------------------------------------------------
# Menu management (owner)
# ---------------------------------------------------------------------------
@app.get("/api/menu")
def get_menu(db: Session = Depends(get_db), user: models.User = Depends(current_user)):
    if isinstance(user, JSONResponse):
        return user
    ensure_sample_menu(db, user.id)
    return menu_payload(db, user.id)


@app.post("/api/menu/categories")
def create_category(body: CategoryIn, db: Session = Depends(get_db), user: models.User = Depends(current_user)):
    if isinstance(user, JSONResponse):
        return user
    name = body.name.strip()
    if len(name) < 2:
        return field_error({"name": "Please enter a category name."}, "Please check the highlighted fields.")
    count = db.query(models.MenuCategory).filter(models.MenuCategory.user_id == user.id).count()
    cat = models.MenuCategory(user_id=user.id, name=name, sort=count)
    db.add(cat)
    db.commit()
    db.refresh(cat)
    return {"ok": True, "category": category_dict(cat)}


@app.put("/api/menu/categories/{category_id}")
def rename_category(category_id: int, body: CategoryIn, db: Session = Depends(get_db), user: models.User = Depends(current_user)):
    if isinstance(user, JSONResponse):
        return user
    cat = (
        db.query(models.MenuCategory)
        .filter(models.MenuCategory.id == category_id, models.MenuCategory.user_id == user.id)
        .first()
    )
    if cat is None:
        return err(404, "Category not found.")
    name = body.name.strip()
    if len(name) < 2:
        return field_error({"name": "Please enter a category name."}, "Please check the highlighted fields.")
    cat.name = name
    db.commit()
    return {"ok": True, "category": category_dict(cat)}


@app.delete("/api/menu/categories/{category_id}")
def delete_category(category_id: int, db: Session = Depends(get_db), user: models.User = Depends(current_user)):
    if isinstance(user, JSONResponse):
        return user
    cat = (
        db.query(models.MenuCategory)
        .filter(models.MenuCategory.id == category_id, models.MenuCategory.user_id == user.id)
        .first()
    )
    if cat is None:
        return err(404, "Category not found.")
    # Items keep existing — they just lose their grouping.
    db.query(models.MenuItem).filter(
        models.MenuItem.category_id == category_id
    ).update({"category_id": None})
    db.delete(cat)
    db.commit()
    return {"ok": True}


def _validate_item(db: Session, user_id: int, body: MenuItemIn):
    fields: dict[str, str] = {}
    if len(body.name.strip()) < 2:
        fields["name"] = "Please enter the item's name."
    if body.price < 1:
        fields["price"] = "Please enter a price of at least ₹1."
    if body.category_id is not None:
        cat = (
            db.query(models.MenuCategory)
            .filter(models.MenuCategory.id == body.category_id,
                    models.MenuCategory.user_id == user_id)
            .first()
        )
        if cat is None:
            fields["category_id"] = "That category does not belong to your cafe."
    return fields


@app.post("/api/menu/items")
def create_menu_item(body: MenuItemIn, db: Session = Depends(get_db), user: models.User = Depends(current_user)):
    if isinstance(user, JSONResponse):
        return user
    fields = _validate_item(db, user.id, body)
    if fields:
        return field_error(fields, "Please check the highlighted fields.")
    count = db.query(models.MenuItem).filter(models.MenuItem.user_id == user.id).count()
    item = models.MenuItem(
        user_id=user.id, category_id=body.category_id,
        name=body.name.strip(), price=body.price,
        emoji=(body.emoji or "☕").strip() or "☕",
        available=bool(body.available), sort=count,
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return {"ok": True, "item": menu_item_dict(db, item)}


@app.put("/api/menu/items/{item_id}")
def update_menu_item(item_id: int, body: MenuItemIn, db: Session = Depends(get_db), user: models.User = Depends(current_user)):
    if isinstance(user, JSONResponse):
        return user
    item = (
        db.query(models.MenuItem)
        .filter(models.MenuItem.id == item_id, models.MenuItem.user_id == user.id)
        .first()
    )
    if item is None:
        return err(404, "Menu item not found.")
    # Partial updates are welcome (the availability toggle sends only
    # {available}); validate and apply just the fields that were sent.
    sent = body.model_fields_set
    fields: dict[str, str] = {}
    if "name" in sent and len(body.name.strip()) < 2:
        fields["name"] = "Please enter the item's name."
    if "price" in sent and body.price < 1:
        fields["price"] = "Please enter a price of at least ₹1."
    if "category_id" in sent and body.category_id is not None:
        cat = (
            db.query(models.MenuCategory)
            .filter(models.MenuCategory.id == body.category_id,
                    models.MenuCategory.user_id == user.id)
            .first()
        )
        if cat is None:
            fields["category_id"] = "That category does not belong to your cafe."
    if fields:
        return field_error(fields, "Please check the highlighted fields.")
    if "name" in sent:
        item.name = body.name.strip()
    if "price" in sent:
        item.price = body.price
    if "emoji" in sent:
        item.emoji = (body.emoji or "☕").strip() or "☕"
    if "category_id" in sent:
        item.category_id = body.category_id
    if "available" in sent:
        item.available = bool(body.available)
    db.commit()
    return {"ok": True, "item": menu_item_dict(db, item)}


@app.delete("/api/menu/items/{item_id}")
def delete_menu_item(item_id: int, db: Session = Depends(get_db), user: models.User = Depends(current_user)):
    if isinstance(user, JSONResponse):
        return user
    item = (
        db.query(models.MenuItem)
        .filter(models.MenuItem.id == item_id, models.MenuItem.user_id == user.id)
        .first()
    )
    if item is None:
        return err(404, "Menu item not found.")
    db.delete(item)
    db.commit()
    return {"ok": True}


# ---------------------------------------------------------------------------
# The cafe's public ordering link (what the table QR cards encode)
# ---------------------------------------------------------------------------
@app.get("/api/cafe/link")
def cafe_link(db: Session = Depends(get_db), user: models.User = Depends(current_user)):
    if isinstance(user, JSONResponse):
        return user
    token = get_or_create_cafe_token(db, user.id)
    return {
        "url": f"{app_base_url()}/t/{token}",
        "token": token,
        "cafe_name": cafe_display_name(db, user.id),
    }


@app.post("/api/cafe/link/reset")
def cafe_link_reset(db: Session = Depends(get_db), user: models.User = Depends(current_user)):
    """A fresh token — every previously printed table card dies."""
    if isinstance(user, JSONResponse):
        return user
    token = reset_cafe_token(db, user.id)
    logger.info("Ordering link reset by %s (old table cards retired)", user.email)
    return {
        "url": f"{app_base_url()}/t/{token}",
        "token": token,
        "cafe_name": cafe_display_name(db, user.id),
    }


# ---------------------------------------------------------------------------
# Public customer ordering — /t/<token> + /api/public/*
#
# NEVER gated by the pay-first gate and never needs a login: a customer
# scans the table QR with their own phone, orders, and the order lands
# on the owner's phone dashboard. Placing an order automatically
# creates/updates the cafe's customer record for that phone number —
# that record is what stamps, rewards and the Come Back list run on.
# ---------------------------------------------------------------------------
def _public_cafe_or_404(db: Session, token: str):
    owner_id = cafe_token_owner(db, token)
    if owner_id is None:
        return None, err(404, "This ordering link is not valid. Please ask the cafe staff for the current table card.")
    return owner_id, None


@app.get("/api/public/{token}/info")
def public_info(token: str, db: Session = Depends(get_db)):
    """Public: the cafe's name + its live menu (available items only)."""
    owner_id, deny = _public_cafe_or_404(db, token)
    if deny is not None:
        return deny
    payload = menu_payload(db, owner_id, only_available=True)
    return {"cafe_name": cafe_display_name(db, owner_id), **payload}


@app.get("/api/public/{token}/card")
def public_card(token: str, phone: str = "", db: Session = Depends(get_db)):
    """Public "My stamps": a customer enters their phone number and
    sees their stamp card, visits, favourite and any live reward code."""
    owner_id, deny = _public_cafe_or_404(db, token)
    if deny is not None:
        return deny
    digits = clean_phone(phone)
    if len(digits) != 10:
        return field_error({"phone": "Please enter your 10-digit mobile number."}, "Please check the highlighted fields.")
    customer = (
        db.query(models.Customer)
        .filter(models.Customer.user_id == owner_id, models.Customer.phone == digits)
        .first()
    )
    if customer is None:
        return err(404, "No visits found for this number yet. Order once and your stamp card starts!")
    return {
        "cafe_name": cafe_display_name(db, owner_id),
        "customer": customer_dict(db, customer),
    }


@app.get("/api/public/{token}/order-status")
def public_order_status(token: str, order_id: int = 0, phone: str = "", db: Session = Depends(get_db)):
    """Public LIVE order tracking for the customer's phone: the order
    id (kept in their browser) + their phone number open the status —
    placed → accepted (ready in ~N min) → preparing → ready/served —
    plus their stamp card as it stands now (the stamp lands at serve
    time, and this is where they watch it land)."""
    owner_id, deny = _public_cafe_or_404(db, token)
    if deny is not None:
        return deny
    digits = clean_phone(phone)
    order = (
        db.query(models.Order)
        .filter(models.Order.id == order_id, models.Order.user_id == owner_id)
        .first()
    )
    if order is None or order.customer is None or order.customer.phone != digits:
        return err(404, "We could not find that order. Please check the order number and your mobile number.")
    cust = customer_dict(db, order.customer)
    return {
        "cafe_name": cafe_display_name(db, owner_id),
        "order": order_dict(db, order),
        "customer": {
            "name": cust["name"],
            "stamps": cust["stamps"],
            "stamps_per_card": cust["stamps_per_card"],
            "visits": cust["visits"],
            "active_reward": cust["active_reward"],
        },
    }


@app.post("/api/public/{token}/order")
def public_place_order(token: str, body: PublicOrderIn, request: Request, db: Session = Depends(get_db)):
    """Public: place an order. The total is computed SERVER-SIDE from
    the cafe's own menu prices — prices a client sends are ignored.
    The customer record for the phone is created/updated automatically."""
    ip = request.client.host if request.client else "unknown"
    if order_rate_limited(f"{ip}:{token}"):
        return err(429, "Too many orders. Please wait a minute and try again.")
    owner_id, deny = _public_cafe_or_404(db, token)
    if deny is not None:
        return deny
    fields: dict[str, str] = {}
    name = body.name.strip()
    phone = clean_phone(body.phone)
    if len(name) < 2:
        fields["name"] = "Please enter your name."
    if len(phone) != 10:
        fields["phone"] = "Please enter your 10-digit mobile number."
    if not body.items:
        fields["items"] = "Please add at least one item to your order."
    if fields:
        return field_error(fields, "Please check the highlighted fields.")

    # Resolve every line against THIS cafe's live menu.
    lines: list[tuple[models.MenuItem, int]] = []
    total = 0
    for line in body.items:
        item = (
            db.query(models.MenuItem)
            .filter(models.MenuItem.id == line.item_id, models.MenuItem.user_id == owner_id)
            .first()
        )
        if item is None or not item.available:
            return err(400, "One of the items in your order is no longer available. Please refresh the menu.")
        lines.append((item, line.qty))
        total += item.price * line.qty

    # The automatic customer record: keyed by phone inside this cafe.
    customer = (
        db.query(models.Customer)
        .filter(models.Customer.user_id == owner_id, models.Customer.phone == phone)
        .first()
    )
    if customer is None:
        customer = models.Customer(user_id=owner_id, phone=phone, name=name)
        db.add(customer)
        db.flush()
    elif name and customer.name != name:
        customer.name = name

    order = models.Order(
        user_id=owner_id,
        customer_id=customer.id,
        table_no=(body.table or "").strip()[:16],
        status="NEW",
        total=total,
    )
    db.add(order)
    db.flush()
    for item, qty in lines:
        db.add(models.OrderItem(
            order_id=order.id, item_name=item.name, price=item.price, qty=qty,
        ))
    db.commit()
    db.refresh(order)
    logger.info(
        "Public order #%s at cafe %s (table %s, ₹%s)",
        order.id, owner_id, order.table_no or "-", total,
    )
    cust = customer_dict(db, customer)
    return {
        "ok": True,
        "order": order_dict(db, order),
        "cafe_name": cafe_display_name(db, owner_id),
        "customer": {
            "name": cust["name"],
            "stamps": cust["stamps"],
            "stamps_per_card": cust["stamps_per_card"],
            "visits": cust["visits"],
            "active_reward": cust["active_reward"],
        },
        "message": f"Order placed! We have it — Table {order.table_no or '—'}. Sit back, it's being made fresh for you.",
    }


@app.get("/t/{token}")
def public_order_page(token: str, db: Session = Depends(get_db)):
    """Public ordering page behind the table QR. No login, ever.
    Unknown token -> a friendly customer-facing 404 page."""
    owner_id = cafe_token_owner(db, token)
    if owner_id is None:
        page = FRONTEND_DIR / "order-404.html"
        if page.exists():
            return FileResponse(page, status_code=404, media_type="text/html")
        return JSONResponse(status_code=404, content={"detail": "Not found."})
    html = (FRONTEND_DIR / "order.html").read_text(encoding="utf-8")
    html = html.replace("__CAFE_NAME__", html_escape(cafe_display_name(db, owner_id)))
    # Cafe branding: the cafe's own logo when one is on file, else empty
    # (the page hides the <img>, leaving the name-only hero).
    html = html.replace("__CAFE_LOGO__", "/cafe-logo.png" if CAFE_LOGO_FILE.exists() else "")
    html = html.replace("__CAFE_TOKEN__", token)
    return HTMLResponse(content=html, status_code=200)


# ---------------------------------------------------------------------------
# Plan endpoints (ONE plan — CafeLoop Pro)
# ---------------------------------------------------------------------------
@app.get("/api/plans")
def list_plans():
    """Public: the subscription plan (single source = billing.py)."""
    return {"plans": SUBSCRIPTION_PLANS}


@app.get("/api/plan")
def current_plan(db: Session = Depends(get_db), user: models.User = Depends(current_user)):
    if isinstance(user, JSONResponse):
        return user
    return get_plan_state(db, user_id=user.id)


@app.post("/api/plan/switch")
def switch_plan(body: PlanSwitchIn, db: Session = Depends(get_db), user: models.User = Depends(current_user)):
    """Record the owner's billing-period CHOICE (entry flow / payment
    step). Choosing is not paying: this never activates a subscription.
    The pay-first gate lifts only when Farhan records the payment from
    Control after collecting in person."""
    if isinstance(user, JSONResponse):
        return user
    plan = get_subscription_plan(body.plan_id)
    if not plan:
        return err(404, "Plan not found.")
    set_setting(db, f"plan_period:{user.id}", body.period)
    user.plan_chosen = True
    db.commit()
    logger.info(
        "Plan period chosen by %s -> %s; subscription state unchanged (payment still required)",
        user.email, body.period,
    )
    state = get_plan_state(db, user_id=user.id)
    state["message"] = f"You have chosen CafeLoop Pro ({body.period})."
    return state


@app.get("/payment-qr.png")
def payment_qr():
    """Farhan's PhonePe UPI QR — the image owners pay by. Deliberately
    public (the locked payment screen shows it before any session
    exists in some flows, and it carries no account data)."""
    if PAYMENT_QR_FILE.exists():
        return FileResponse(PAYMENT_QR_FILE, media_type="image/png")
    return err(404, "Payment QR is not set up yet.")


@app.get("/cafe-logo.png")
def cafe_logo():
    """The cafe's own brand logo — white-label cafe branding for the
    public ordering page (the CAFE's logo, not CafeLoop product art).
    Public like the ordering page itself; carries no account data."""
    if CAFE_LOGO_FILE.exists():
        return FileResponse(CAFE_LOGO_FILE, media_type="image/png")
    return err(404, "Cafe logo is not set up yet.")


@app.get("/icon-512.png")
def app_icon():
    """Square cup-mark icon (favicon / app icon) for the cafe pages."""
    icon = FRONTEND_DIR / "icon-512.png"
    if icon.exists():
        return FileResponse(icon, media_type="image/png")
    return err(404, "Icon not found.")


# ---------------------------------------------------------------------------
# Subscription payments — owners can NEVER activate themselves. A
# payment is recorded only by Farhan from his Control page (/control)
# or the ADMIN_SECRET API, after he collects the money in person. The
# owner's app unlocks by itself the moment a payment lands: the open
# payment page polls /api/plan and walks into the dashboard.
# ---------------------------------------------------------------------------
def _record_subscription_payment(
    db: Session,
    user: models.User,
    period: str,
    method: str = "collected_in_person",
):
    """Record a CONFIRMED subscription payment and activate the plan.
    The amount ALWAYS comes from billing.py (server-side)."""
    plan = get_subscription_plan(PLAN_ID)
    amount = plan["monthly"] if period == "monthly" else plan["yearly"]
    db.add(models.SubscriptionPayment(
        user_id=user.id,
        plan_id=plan["id"],
        plan_name=plan["name"],
        period=period,
        amount=amount,
        method=method,
        status="paid",
        created_at=datetime.now(),
    ))
    set_setting(db, f"plan_period:{user.id}", period)
    user.plan_chosen = True
    db.commit()
    logger.info(
        "Subscription payment PAID by %s -> CafeLoop Pro (%s), amount ₹%d via %s",
        user.email, period, amount, method,
    )
    state = get_plan_state(db, user_id=user.id)
    state["message"] = (
        f"Payment recorded — your CafeLoop Pro plan ({period}) is active. Thank you!"
    )
    return state


# ---------------------------------------------------------------------------
# Platform admin — Farhan's control. He personally visits each cafe,
# collects the subscription money in person, then activates that cafe
# from here. Owners can never activate themselves. He can also SWITCH
# a cafe OFF (non-payment): the account locks at once, nothing deleted.
#
# Access is the ADMIN_SECRET environment variable, read on every call:
#   * unset → every admin route answers 404 (they do not exist);
#   * API: header "X-Admin-Secret", compared in constant time;
#   * Page: GET /control — a password form (the secret itself), then a
#     signed admin cookie (12h, HTTP-only). Page POSTs must also send
#     the CSRF value bound into that cookie.
# No link to /control exists anywhere in the owner UI.
# ---------------------------------------------------------------------------
def _admin_secret() -> str:
    return os.environ.get("ADMIN_SECRET", "").strip()


def _admin_enabled() -> bool:
    return bool(_admin_secret())


def _secret_matches(candidate) -> bool:
    secret = _admin_secret()
    return (
        bool(secret)
        and bool(candidate)
        and hmac.compare_digest(str(candidate), secret)
    )


def _inr(n) -> str:
    """₹ amount with Indian digit grouping (2549 → '2,549')."""
    s = str(int(n or 0))
    if len(s) <= 3:
        return s
    head, tail = s[:-3], s[-3:]
    parts = []
    while len(head) > 2:
        parts.insert(0, head[-2:])
        head = head[:-2]
    if head:
        parts.insert(0, head)
    return ",".join(parts + [tail])


def _fmt_date(iso) -> str:
    if not iso:
        return "—"
    try:
        return date.fromisoformat(str(iso)[:10]).strftime("%d %b %Y")
    except ValueError:
        return "—"


def _account_subscription(db: Session, user: models.User) -> dict:
    """One account's subscription for Control, from THAT account's own
    latest payment with the same 30/365-day windows as the gate."""
    period = _account_period(db, user)
    latest = _latest_payment_for(db, user.id)
    today = date.today()
    if latest is not None:
        if latest.status != "paid":
            status, active, expires_on = "not_paid", False, None
        else:
            start = latest.created_at.date() if latest.created_at else today
            end = _period_end(start, latest.period)
            expires_on = end.isoformat()
            if today < end:
                status, active = "active", True
            else:
                status, active = "expired", False
    else:
        status, active, expires_on = "not_paid", False, None
    if is_revoked(db, user.id):
        status, active = "switched_off", False
    return {
        "period": period,
        "status": status,
        "active": active,
        "expires_on": expires_on,
    }


def _account_dict(db: Session, user: models.User) -> dict:
    """Everything Farhan sees about one cafe on Control."""
    return {
        "user_id": user.id,
        "email": user.email,
        "owner_name": user.owner_name or "",
        "cafe_name": user.cafe_name or "",
        "mobile": user.mobile or "",
        "auth_provider": user.auth_provider or "email",
        "otp_pending": bool(getattr(user, "otp_pending", False)),
        "joined": user.created_at.isoformat() if user.created_at else None,
        **_account_subscription(db, user),
    }


def _admin_summary(db: Session) -> dict:
    users = db.query(models.User).order_by(models.User.id).all()
    accounts = [_account_dict(db, u) for u in users]
    total_collected = (
        db.query(func.sum(models.SubscriptionPayment.amount))
        .filter(models.SubscriptionPayment.status == "paid")
        .scalar()
    ) or 0
    return {
        "total_cafes": len(accounts),
        "active_cafes": sum(1 for a in accounts if a["status"] == "active"),
        "total_collected": int(total_collected),
        "accounts": accounts,
    }


def _find_account(db: Session, user_id, email):
    if user_id is not None:
        return db.query(models.User).filter(models.User.id == user_id).first()
    if email and str(email).strip():
        return (
            db.query(models.User)
            .filter(models.User.email == str(email).strip().lower())
            .first()
        )
    return None


def _activate_account(db: Session, user: models.User, period=None):
    """Farhan's one-tap activation after collecting in person.

    Clears any switch-off override first. If the cafe is already
    ACTIVE on the very period being activated, NOTHING more is
    recorded — the money for this window was already collected once.
    Otherwise a fresh payment goes through the standard recording path
    (server-computed amount), and the gate lifts at once."""
    period = period or _account_period(db, user)
    if is_revoked(db, user.id):
        set_revoked(db, user.id, False)
        db.commit()
        logger.info("Admin cleared the switch-off for %s", user.email)
    info = _account_subscription(db, user)
    if info["active"] and info["period"] == period:
        logger.info(
            "Admin re-activated %s — paid window still valid, no new payment recorded",
            user.email,
        )
        return {"recorded_payment": False, "account": _account_dict(db, user)}
    state = _record_subscription_payment(db, user, period, method="collected_in_person")
    if state is None:
        return None
    return {"recorded_payment": True, "account": _account_dict(db, user)}


def _record_admin_action(db: Session, action: str, user: models.User, detail: str = "") -> None:
    db.add(models.AdminAction(
        action=action,
        target_user_id=user.id,
        target_email=user.email,
        detail=detail,
    ))
    db.commit()


def _admin_auth(request: Request):
    """Admin credential check for the API. None when admin is not
    configured (routes answer 404), False for bad credentials (403),
    or {"via": "secret" | "cookie", ...}."""
    if not _admin_enabled():
        return None
    if _secret_matches(request.headers.get("x-admin-secret")):
        return {"via": "secret"}
    payload = read_admin_token(request.cookies.get(ADMIN_COOKIE, ""))
    if payload:
        return {"via": "cookie", "csrf": payload.get("csrf", "")}
    return False


def _admin_api_guard(request: Request):
    """(auth, None) when the caller is Farhan; (None, response) otherwise."""
    auth = _admin_auth(request)
    if auth is None:
        return None, err(404, "Not found.")
    if not auth:
        return None, err(403, "Admin access denied.")
    return auth, None


def _admin_csrf_ok(auth: dict, csrf_value) -> bool:
    """Cookie-authenticated POSTs must echo the cookie's CSRF value;
    the secret header is itself the credential, so it needs none."""
    if auth.get("via") != "cookie":
        return True
    return hmac.compare_digest(str(csrf_value or ""), str(auth.get("csrf", "")))


@app.get("/api/admin/cafes")
def admin_cafes(request: Request, db: Session = Depends(get_db)):
    """Every cafe account + subscription status + collected totals."""
    auth, deny = _admin_api_guard(request)
    if deny is not None:
        return deny
    return _admin_summary(db)


@app.post("/api/admin/activate")
def admin_activate(body: AdminActivateIn, request: Request, db: Session = Depends(get_db)):
    """Record an in-person collection for one cafe and unlock it.
    period may be omitted — the cafe's chosen period is used."""
    auth, deny = _admin_api_guard(request)
    if deny is not None:
        return deny
    if not _admin_csrf_ok(auth, body.csrf):
        return err(403, "Admin session check failed. Please reload the control page.")
    user = _find_account(db, body.user_id, body.email)
    if user is None:
        return err(404, "Cafe account not found.")
    result = _activate_account(db, user, body.period)
    if result is None:
        return err(404, "Plan not found.")
    _record_admin_action(db, "activate", user, body.period or "")
    return {"ok": True, **result, "summary": _admin_summary(db)}


@app.post("/api/admin/switch-off")
def admin_switch_off(body: AdminActivateIn, request: Request, db: Session = Depends(get_db)):
    """Switch one cafe OFF: its gate locks at once (even inside a paid
    window). NOTHING is deleted — Activate restores it as it was."""
    auth, deny = _admin_api_guard(request)
    if deny is not None:
        return deny
    if not _admin_csrf_ok(auth, body.csrf):
        return err(403, "Admin session check failed. Please reload the control page.")
    user = _find_account(db, body.user_id, body.email)
    if user is None:
        return err(404, "Cafe account not found.")
    set_revoked(db, user.id, True)
    db.commit()
    _record_admin_action(db, "switch_off", user)
    logger.info("Admin SWITCHED OFF %s — locked immediately, all data kept", user.email)
    return {"ok": True, "account": _account_dict(db, user), "summary": _admin_summary(db)}


# ---------------------------------------------------------------------------
# Face unlock — Farhan's final unlock decision (ported from Do Gym,
# 2026-10-23). He is physically at the cafe (he just collected the
# money in person). The owner opens the locked payment screen and taps
# "Pay — Unlock by Face Scan": the OWNER's device camera matches
# Farhan's face against the template he enrolled from Control, with a
# liveness beat (blink / head-turn) against photo spoofing. On a
# verified match the server records the activation through the
# standard path (method "face_unlock", the period selected on the pay
# screen, server-computed amount) and the pay-first gate lifts — the
# owner's page flips into the app exactly like every other route.
#
# The honest security shape (same as Do Gym): the face MATCH runs in
# the browser, so this is convenience-grade, not bank-grade — Farhan's
# informed choice. What the server enforces: a short-lived (120s),
# single-use challenge bound to this owner with a SERVER-chosen
# liveness action; the reported match distance must beat the
# threshold; 5 failed verifications lock face unlock for that cafe
# for 15 minutes; Switch Off still overrides a face-unlocked cafe; and
# the stored template is numeric descriptors only — never a photo.
# ---------------------------------------------------------------------------
FACE_CHALLENGE_TTL = 120  # seconds
FACE_MAX_FAILS = 5
FACE_LOCKOUT_SECONDS = 15 * 60
FACE_MATCH_THRESHOLD = 0.5  # face-api euclidean distance for a match
FACE_ACTIONS = ("blink", "turn_left", "turn_right")
_face_challenges: dict[str, dict] = {}
_face_fails: dict[int, list[float]] = defaultdict(list)
_face_lockouts: dict[int, float] = {}


def _face_template(db: Session):
    """{"descriptors": [[128 floats], ...], "updated_at": iso} or None."""
    row = db.query(models.FaceTemplate).order_by(models.FaceTemplate.id).first()
    if row is None:
        return None
    try:
        descriptors = json.loads(row.descriptors or "[]")
    except ValueError:
        return None
    if not descriptors:
        return None
    updated = getattr(row, "updated_at", None)
    return {
        "descriptors": descriptors,
        "updated_at": updated.isoformat() if updated else None,
    }


def _face_locked_out(user_id: int) -> bool:
    until = _face_lockouts.get(user_id, 0)
    if until and time.time() < until:
        return True
    if until:
        _face_lockouts.pop(user_id, None)
    return False


def _face_record_fail(user_id: int) -> None:
    now = time.time()
    fails = [t for t in _face_fails[user_id] if now - t < FACE_LOCKOUT_SECONDS]
    fails.append(now)
    if len(fails) >= FACE_MAX_FAILS:
        _face_lockouts[user_id] = now + FACE_LOCKOUT_SECONDS
        _face_fails[user_id] = []
        logger.warning(
            "Face unlock LOCKED OUT for user %s after %d failed attempts",
            user_id, FACE_MAX_FAILS,
        )
    else:
        _face_fails[user_id] = fails


@app.get("/static/face/{name}")
def face_asset(name: str):
    """The vendored face-api library + model weights (served locally —
    no runtime CDN). A strict filename pattern; nothing else in
    static/ is reachable through this route."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name) or ".." in name:
        return err(404, "Not found.")
    path = STATIC_DIR / "face" / name
    if not path.is_file():
        return err(404, "Not found.")
    if name.endswith(".js"):
        media = "application/javascript"
    elif name.endswith(".json"):
        media = "application/json"
    else:
        media = "application/octet-stream"
    return FileResponse(path, media_type=media)


class FaceTemplateIn(BaseModel):
    descriptors: list = Field(default_factory=list)
    csrf: str = ""


@app.post("/api/admin/face-template")
def admin_face_template_enroll(
    body: FaceTemplateIn, request: Request, db: Session = Depends(get_db)
):
    """Enroll or replace Farhan's face template (numeric descriptors
    only — computed in his browser in Control; no photo ever arrives
    here). Admin: secret header OR the /control session (with CSRF)."""
    auth, deny = _admin_api_guard(request)
    if deny is not None:
        return deny
    if not _admin_csrf_ok(auth, body.csrf):
        return err(403, "Admin session check failed. Please reload Control.")
    descriptors = body.descriptors
    if not isinstance(descriptors, list) or not (1 <= len(descriptors) <= 6):
        return err(400, "Please capture between 1 and 6 poses.")
    cleaned = []
    for d in descriptors:
        if (
            not isinstance(d, list)
            or len(d) != 128
            or any(isinstance(x, bool) or not isinstance(x, (int, float)) for x in d)
        ):
            return err(400, "That face data does not look right. Please try again.")
        cleaned.append([round(float(x), 6) for x in d])
    row = db.query(models.FaceTemplate).order_by(models.FaceTemplate.id).first()
    payload = json.dumps(cleaned)
    if row is None:
        db.add(models.FaceTemplate(descriptors=payload, updated_at=datetime.now()))
    else:
        row.descriptors = payload
        row.updated_at = datetime.now()
    db.commit()
    logger.info("Face template (re)enrolled by admin: %d pose(s)", len(cleaned))
    return {"ok": True, "poses": len(cleaned), "face_enrolled": True}


@app.get("/api/admin/face-template")
def admin_face_template_get(request: Request, db: Session = Depends(get_db)):
    """The enrolled descriptors, for admin-side reads. Admin auth
    required."""
    auth, deny = _admin_api_guard(request)
    if deny is not None:
        return deny
    tpl = _face_template(db)
    if tpl is None:
        return {"enrolled": False, "descriptors": []}
    return {"enrolled": True, "descriptors": tpl["descriptors"]}


@app.post("/api/admin/face-template/remove")
def admin_face_template_remove(request: Request, db: Session = Depends(get_db)):
    """Remove the enrolled template (face unlock hides everywhere)."""
    auth, deny = _admin_api_guard(request)
    if deny is not None:
        return deny
    if not _admin_csrf_ok(auth, None):
        return err(403, "Admin session check failed. Please reload Control.")
    db.query(models.FaceTemplate).delete()
    db.commit()
    logger.info("Face template removed by admin")
    return {"ok": True, "face_enrolled": False}


@app.get("/api/face-unlock/template")
def face_unlock_template(
    db: Session = Depends(get_db),
    user: models.User | JSONResponse = Depends(current_user),
):
    """The enrolled descriptors, for the owner's browser to match
    against locally. Owner session required; reachable while gated —
    it is part of the unlock flow itself."""
    if isinstance(user, JSONResponse):
        return user
    tpl = _face_template(db)
    if tpl is None:
        return {"enrolled": False, "descriptors": []}
    return {"enrolled": True, "descriptors": tpl["descriptors"]}


@app.post("/api/face-unlock/challenge")
def face_unlock_challenge(
    db: Session = Depends(get_db),
    user: models.User | JSONResponse = Depends(current_user),
):
    """Start a scan session: a single-use, 120-second challenge bound
    to this owner, with a server-chosen liveness action."""
    if isinstance(user, JSONResponse):
        return user
    if _face_template(db) is None:
        return err(400, "Face unlock is not set up yet.")
    if _face_locked_out(user.id):
        return err(
            429,
            "Too many failed face attempts. Please wait 15 minutes, or "
            "ask CafeLoop to activate you from Control.",
        )
    for cid in [c for c, ch in _face_challenges.items() if ch["user_id"] == user.id]:
        _face_challenges.pop(cid, None)
    cid = secrets.token_urlsafe(24)
    _face_challenges[cid] = {
        "user_id": user.id,
        "action": secrets.choice(FACE_ACTIONS),
        "expires": time.time() + FACE_CHALLENGE_TTL,
        "used": False,
    }
    return {
        "challenge_id": cid,
        "action": _face_challenges[cid]["action"],
        "expires_in": FACE_CHALLENGE_TTL,
        "threshold": FACE_MATCH_THRESHOLD,
    }


class FaceVerifyIn(BaseModel):
    challenge_id: str = Field(min_length=8, max_length=128)
    distance: float | None = None
    liveness: str = Field(default="", max_length=32)
    # The billing period selected on the pay screen (CafeLoop has ONE
    # plan with a monthly/yearly toggle). Anything else falls back to
    # the account's stored period choice.
    period: str = Field(default="", max_length=16)


@app.post("/api/face-unlock/verify")
def face_unlock_verify(
    body: FaceVerifyIn,
    db: Session = Depends(get_db),
    user: models.User | JSONResponse = Depends(current_user),
):
    """Confirm a scan. The challenge must be live, unused, this
    owner's, with the liveness action the server chose and a match
    distance under the threshold. Any verify attempt burns the
    challenge (single-use). Success records the activation."""
    if isinstance(user, JSONResponse):
        return user
    if _face_locked_out(user.id):
        return err(
            429,
            "Face unlock is locked for 15 minutes after too many "
            "failed attempts. Please ask CafeLoop to activate you from Control.",
        )
    if _face_template(db) is None:
        return err(400, "Face unlock is not set up yet.")
    if is_revoked(db, user.id):
        return err(403, "⏸️ Your plan is currently off. Please contact CafeLoop to restart.")
    ch = _face_challenges.get(body.challenge_id)
    if (
        ch is None
        or ch["user_id"] != user.id
        or ch["used"]
        or time.time() > ch["expires"]
    ):
        _face_record_fail(user.id)
        return err(400, "That face scan session has expired. Please start again.")
    ch["used"] = True  # single-use — any attempt burns the challenge
    if body.liveness != ch["action"]:
        _face_record_fail(user.id)
        logger.info(
            "Face unlock failed for %s: liveness %r, wanted %r",
            user.email, body.liveness, ch["action"],
        )
        return err(400, "The liveness check did not match. Please try again.")
    if body.distance is None or body.distance > FACE_MATCH_THRESHOLD:
        _face_record_fail(user.id)
        logger.info(
            "Face unlock failed for %s: distance %s over threshold",
            user.email, body.distance,
        )
        return err(400, "That face did not match closely enough. Please try again.")
    # Verified.
    _face_fails.pop(user.id, None)
    if subscription_info(db, user_id=user.id)["active"]:
        state = get_plan_state(db, user_id=user.id)
        state["ok"] = True
        state["already_active"] = True
        return state
    period = body.period if body.period in ("monthly", "yearly") else _account_period(db, user)
    state = _record_subscription_payment(
        db, user, period, method="face_unlock"
    )
    if state is None:
        return err(404, "Plan not found.")
    logger.info(
        "Face unlock ACTIVATED %s -> CafeLoop Pro (%s), amount ₹%s via face_unlock",
        user.email, period, state["last_payment"]["amount"],
    )
    state["ok"] = True
    return state


# ---------------------------------------------------------------------------
# Control page (/control) — server-rendered, warm light theme to match
# the product. Login is the ADMIN_SECRET itself; while it is unset the
# page does not exist.
# ---------------------------------------------------------------------------
_CONTROL_CSS = """
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,sans-serif;background:linear-gradient(180deg,#FFF9F1,#FBEEDC);color:#3B2416;min-height:100vh}
.wrap{max-width:880px;margin:0 auto;padding:28px 16px 60px}
.wrap.narrow{max-width:430px}
.brand{font-size:26px;font-weight:900;letter-spacing:-.02em}
.brand span{background:linear-gradient(135deg,#FFB800,#FF7A00 55%,#E63329);-webkit-background-clip:text;background-clip:text;color:transparent}
.muted{color:#8A6D4F;font-size:14px;line-height:1.55}
.card{background:#FFFDF9;border:1px solid #F0DFC4;border-radius:18px;padding:18px;margin-top:16px;box-shadow:0 10px 30px rgba(146,96,32,.10)}
label{display:block;font-size:13px;font-weight:700;margin:0 0 6px;color:#6B4A2B}
input{width:100%;padding:12px 14px;border:1.5px solid #EAD9BC;border-radius:12px;font-size:15px;font-family:inherit;background:#FFFDF9;color:#3B2416}
.btn{display:inline-block;padding:11px 18px;border:none;border-radius:12px;font-size:14px;font-weight:800;cursor:pointer;font-family:inherit;background:#F3E5CB;color:#6B4A2B}
.btn-grad{background:linear-gradient(135deg,#FFB800,#FF7A00 55%,#E63329);color:#fff;box-shadow:0 8px 20px rgba(230,51,41,.30);width:100%}
.btn-sm{padding:8px 13px;font-size:13px;border-radius:10px}
.btn-off{background:#FDECEC;color:#A33}
.error{background:#FDECEC;color:#A33;border:1px solid #F5C6C6;border-radius:12px;padding:11px 14px;font-size:14px;margin-top:14px}
.flash{background:#EAF7EA;color:#256B25;border:1px solid #BEE3BE;border-radius:12px;padding:11px 14px;font-size:14px;margin-top:14px}
.topbar{display:flex;justify-content:space-between;align-items:center;gap:12px}
.summary{display:flex;gap:12px;margin-top:18px;flex-wrap:wrap}
.stat{flex:1;min-width:130px;background:#FFFDF9;border:1px solid #F0DFC4;border-radius:16px;padding:14px;box-shadow:0 8px 22px rgba(146,96,32,.08)}
.stat b{display:block;font-size:22px}
.stat span{font-size:12px;color:#8A6D4F;font-weight:700}
.acct{display:flex;justify-content:space-between;gap:14px;align-items:flex-start;flex-wrap:wrap}
.acct h3{font-size:16px}
.acct .meta{font-size:13px;color:#8A6D4F;line-height:1.5}
.tag{display:inline-block;font-size:11px;font-weight:800;letter-spacing:.05em;padding:4px 10px;border-radius:999px;text-transform:uppercase}
.tag-g{background:#EAF7EA;color:#256B25}
.tag-d{background:#FDF3E2;color:#9A6A12}
.tag-o{background:#FDECEC;color:#A33}
.actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
select{padding:9px;border:1.5px solid #EAD9BC;border-radius:10px;font-family:inherit;background:#FFFDF9}
"""


# Face enrollment on the Control page: lazy-loads face-api from
# /static/face (vendored — no CDN), walks Farhan through three poses,
# and posts ONLY the numeric descriptors to /api/admin/face-template.
_CONTROL_FACE_JS = """
(function(){
  var btn = document.getElementById("face-reg-btn");
  if (!btn) return;
  var box = document.getElementById("face-reg"),
      video = document.getElementById("ctl-face-video"),
      step = document.getElementById("ctl-face-step"),
      start = document.getElementById("ctl-face-start"),
      stream = null, modelsOk = false;
  btn.addEventListener("click", function(){
    box.style.display = box.style.display === "none" ? "block" : "none";
  });
  function loadLib(){
    return new Promise(function(res, rej){
      if (window.faceapi) return res();
      var s = document.createElement("script");
      s.src = "/static/face/face-api.min.js";
      s.onload = res; s.onerror = rej;
      document.head.appendChild(s);
    });
  }
  async function loadModels(){
    if (modelsOk) return;
    await loadLib();
    await faceapi.nets.tinyFaceDetector.loadFromUri("/static/face");
    await faceapi.nets.faceLandmark68Net.loadFromUri("/static/face");
    await faceapi.nets.faceRecognitionNet.loadFromUri("/static/face");
    modelsOk = true;
  }
  function wait(ms){ return new Promise(function(r){ setTimeout(r, ms); }); }
  async function capturePose(label){
    step.textContent = label + " — hold still…";
    var det = null, tries = 0;
    while (tries < 48 && !det) {
      det = await faceapi.detectSingleFace(video, new faceapi.TinyFaceDetectorOptions()).withFaceLandmarks().withFaceDescriptor();
      if (!det) { tries++; await wait(250); }
    }
    if (!det) throw new Error("No face found. Face the camera in good light and try again.");
    return Array.from(det.descriptor);
  }
  start.addEventListener("click", async function(){
    start.disabled = true;
    try {
      step.textContent = "Loading the face tools…";
      await loadModels();
      stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "user" } });
      video.srcObject = stream;
      await video.play();
      var poses = [];
      poses.push(await capturePose("Pose 1 of 3: look straight at the camera"));
      poses.push(await capturePose("Pose 2 of 3: turn your head a little to YOUR left"));
      poses.push(await capturePose("Pose 3 of 3: turn your head a little to YOUR right"));
      step.textContent = "Saving your face template…";
      var csrf = document.querySelector('input[name="csrf"]').value;
      var r = await fetch("/api/admin/face-template", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ descriptors: poses, csrf: csrf })
      });
      if (!r.ok) throw new Error("Saving failed. Please try again.");
      location.href = "/control?msg=" + encodeURIComponent("Your face is registered ✓ — cafes can now unlock with your face scan.");
    } catch (e) {
      step.textContent = (e && e.message) ? e.message : "Something went wrong. Please try again.";
      start.disabled = false;
    } finally {
      if (stream) { stream.getTracks().forEach(function(t){ t.stop(); }); stream = null; }
    }
  });
})();
"""


def _control_login_html(error: str = "") -> str:
    err_box = f'<div class="error">{html_escape(error)}</div>' if error else ""
    return (
        '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        "<title>CafeLoop — Control</title><style>" + _CONTROL_CSS + "</style></head>"
        '<body><div class="wrap narrow">'
        '<div class="brand">Cafe<span>Loop</span> — Control</div>'
        '<p class="muted" style="margin-top:8px">This page is only for the owner of CafeLoop. '
        "Enter your admin password to see every cafe, activate the payments "
        "you collect in person, and switch cafes on or off.</p>"
        + err_box
        + '<form method="post" action="/control/login" class="card">'
        f'<input type="hidden" name="csrf" value="{create_csrf_token()}">'
        '<label for="pw">Admin password</label>'
        '<input id="pw" type="password" name="password" autocomplete="current-password" required>'
        '<button class="btn" type="button" style="margin:10px 0 12px" onclick="var i=document.getElementById(\'pw\');var s=i.type===\'password\';i.type=s?\'text\':\'password\';this.textContent=s?\'Hide password\':\'Show password\'">Show password</button>'
        '<button class="btn btn-grad" type="submit">Open Control</button>'
        "</form></div></body></html>"
    )


_ADMIN_STATUS_LABELS = {
    "active": ("Active ✓", "tag-g"),
    "not_paid": ("Not Paid", "tag-d"),
    "expired": ("Expired", "tag-d"),
    "switched_off": ("Switched Off", "tag-o"),
}


def _control_dashboard_html(db: Session, csrf: str, msg: str = "") -> str:
    summary = _admin_summary(db)
    e = html_escape
    parts = [
        '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        "<title>CafeLoop — Control</title><style>" + _CONTROL_CSS + "</style></head>"
        '<body><div class="wrap">'
        '<div class="topbar"><div class="brand">Cafe<span>Loop</span> — Control</div>'
        '<form method="post" action="/control/logout">'
        f'<input type="hidden" name="csrf" value="{e(csrf)}">'
        '<button class="btn btn-sm" type="submit">Logout</button></form></div>'
        '<p class="muted" style="margin-top:6px">Every cafe on CafeLoop. When you collect a '
        "payment in person, tap <b>Activate</b> — that cafe's app unlocks by itself. "
        "<b>Switch Off</b> locks a cafe that has not paid; nothing is deleted.</p>",
    ]
    if msg:
        parts.append(f'<div class="flash">{e(msg)}</div>')
    parts.append(
        '<div class="summary">'
        f'<div class="stat"><b>{summary["total_cafes"]}</b><span>Total cafes</span></div>'
        f'<div class="stat"><b>{summary["active_cafes"]}</b><span>Active now</span></div>'
        f'<div class="stat"><b>₹{_inr(summary["total_collected"])}</b><span>Collected</span></div>'
        "</div>"
    )
    tpl = _face_template(db)
    if tpl is not None:
        face_inner = (
            '<span class="tag tag-g">Registered ✓</span></div>'
            f'<p class="muted" style="margin-top:8px">{len(tpl["descriptors"])} pose(s) on file. When you visit a cafe, '
            'the owner taps Pay and your face scan on their device unlocks '
            "their app. Only the numeric template is stored — never a photo. "
            "Re-registering replaces it.</p>"
        )
        face_btn = "Re-register my face"
    else:
        face_inner = (
            '<span class="tag tag-d">Not registered</span></div>'
            '<p class="muted" style="margin-top:8px">Register once — then, when you visit a cafe, the owner taps '
            'Pay and your face scan on their device unlocks their app. '
            "Only the numeric template is stored — never a photo.</p>"
        )
        face_btn = "Register my face"
    parts.append(
        '<div class="card"><div class="acct"><div><h3>Your face — cafe unlock</h3></div>'
        + face_inner
        + f'<div class="actions" style="margin-top:12px"><button class="btn btn-sm" style="background:linear-gradient(135deg,#FFB800,#FF7A00 55%,#E63329);color:#fff" id="face-reg-btn" type="button">{face_btn}</button></div>'
        '<div id="face-reg" style="display:none;margin-top:14px">'
        '<video id="ctl-face-video" autoplay playsinline muted style="width:100%;border-radius:14px;background:#000"></video>'
        '<p class="muted" id="ctl-face-step" style="margin-top:10px">Tap "Start camera", then follow the three poses.</p>'
        '<div class="actions" style="margin-top:12px"><button class="btn btn-grad" id="ctl-face-start" type="button">Start camera</button></div>'
        "</div>"
        "</div>"
    )
    if not summary["accounts"]:
        parts.append('<div class="card"><p class="muted">No cafe accounts yet.</p></div>')
    for a in summary["accounts"]:
        label, cls = _ADMIN_STATUS_LABELS.get(a["status"], (a["status"], "tag-d"))
        expires = f' · till {_fmt_date(a["expires_on"])}' if a["expires_on"] else ""
        joined = f' · joined {_fmt_date(a["joined"][:10] if a["joined"] else None)}'
        parts.append(
            '<div class="card"><div class="acct"><div>'
            f'<h3>{e(a["cafe_name"] or a["email"])}</h3>'
            f'<div class="meta">{e(a["owner_name"])} · {e(a["email"])}<br>'
            f'{e(a["mobile"])} · {e(a["auth_provider"])} sign-in{joined}</div></div>'
            f'<span class="tag {cls}">{label}</span></div>'
            f'<div class="meta" style="margin-top:8px">CafeLoop Pro ({e(a["period"])}){expires}</div>'
            '<div class="actions" style="margin-top:12px">'
            '<form method="post" action="/control/activate" style="display:flex;gap:8px;align-items:center">'
            f'<input type="hidden" name="csrf" value="{e(csrf)}">'
            f'<input type="hidden" name="user_id" value="{a["user_id"]}">'
            '<select name="period"><option value="monthly">Monthly ₹1,499</option>'
            '<option value="yearly">Yearly ₹14,990</option></select>'
            '<button class="btn btn-sm" style="background:linear-gradient(135deg,#FFB800,#FF7A00 55%,#E63329);color:#fff" type="submit">Activate</button></form>'
            '<form method="post" action="/control/switch-off">'
            f'<input type="hidden" name="csrf" value="{e(csrf)}">'
            f'<input type="hidden" name="user_id" value="{a["user_id"]}">'
            '<button class="btn btn-sm btn-off" type="submit">Switch Off</button></form>'
            "</div></div>"
        )
    parts.append("<script>" + _CONTROL_FACE_JS + "</script>")
    parts.append("</div></body></html>")
    return "".join(parts)


def _behind_https(request: Request) -> bool:
    return (
        request.url.scheme == "https"
        or request.headers.get("x-forwarded-proto", "").split(",")[0].strip() == "https"
        or os.environ.get("COOKIE_SECURE", "") == "1"
    )


def _set_admin_cookies(resp: Response, request: Request) -> None:
    token, _csrf = create_admin_token()
    for path in ("/control", "/api/admin"):
        resp.set_cookie(
            ADMIN_COOKIE, token, max_age=ADMIN_MAX_AGE,
            httponly=True, samesite="lax", path=path,
            secure=_behind_https(request),
        )


def _clear_admin_cookies(resp: Response) -> None:
    for path in ("/control", "/api/admin"):
        resp.delete_cookie(ADMIN_COOKIE, path=path)


def _admin_session(request: Request):
    return read_admin_token(request.cookies.get(ADMIN_COOKIE, ""))


@app.get("/control", response_class=HTMLResponse)
def control_page(request: Request, db: Session = Depends(get_db)):
    if not _admin_enabled():
        return Response("Not found.", status_code=404, media_type="text/plain")
    sess = _admin_session(request)
    if sess is None:
        return HTMLResponse(_control_login_html())
    return HTMLResponse(
        _control_dashboard_html(db, sess.get("csrf", ""), request.query_params.get("msg", ""))
    )


@app.post("/control/login")
def control_login(request: Request, password: str = Form(""), csrf: str = Form("")):
    if not _admin_enabled():
        return Response("Not found.", status_code=404, media_type="text/plain")
    ip = request.client.host if request.client else "unknown"
    if login_rate_limited("admin:" + ip):
        return HTMLResponse(
            _control_login_html("Too many attempts. Please wait a minute and try again."),
            status_code=429,
        )
    if not verify_csrf_token(csrf):
        return HTMLResponse(
            _control_login_html("That form has expired. Please try again."),
            status_code=400,
        )
    if not _secret_matches(password):
        logger.warning("Control page: wrong admin password from %s", ip)
        return HTMLResponse(
            _control_login_html("Wrong password. Please try again."),
            status_code=401,
        )
    resp = RedirectResponse(url="/control", status_code=303)
    _set_admin_cookies(resp, request)
    logger.info("Control page: admin logged in from %s", ip)
    return resp


def _control_post_guard(request: Request):
    if not _admin_enabled():
        return None, Response("Not found.", status_code=404, media_type="text/plain")
    sess = _admin_session(request)
    if sess is None:
        return None, RedirectResponse(url="/control", status_code=303)
    return sess, None


def _control_csrf_bad(sess: dict, csrf: str):
    if hmac.compare_digest(str(csrf or ""), str(sess.get("csrf", ""))):
        return None
    return Response(
        "Session check failed. Please reload the control page and try again.",
        status_code=403, media_type="text/plain",
    )


@app.post("/control/activate")
def control_activate(
    request: Request,
    user_id: int = Form(0),
    period: str = Form("monthly"),
    csrf: str = Form(""),
    db: Session = Depends(get_db),
):
    sess, deny = _control_post_guard(request)
    if deny is not None:
        return deny
    bad = _control_csrf_bad(sess, csrf)
    if bad is not None:
        return bad
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user is None:
        return RedirectResponse(
            url="/control?msg=" + quote("That cafe account was not found."), status_code=303
        )
    _activate_account(db, user, period if period in ("monthly", "yearly") else "monthly")
    _record_admin_action(db, "activate", user, period)
    name = user.cafe_name or user.email
    return RedirectResponse(
        url="/control?msg=" + quote(f"{name} is now Active ✓"), status_code=303
    )


@app.post("/control/switch-off")
def control_switch_off(request: Request, user_id: int = Form(0), csrf: str = Form(""), db: Session = Depends(get_db)):
    sess, deny = _control_post_guard(request)
    if deny is not None:
        return deny
    bad = _control_csrf_bad(sess, csrf)
    if bad is not None:
        return bad
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user is None:
        return RedirectResponse(
            url="/control?msg=" + quote("That cafe account was not found."), status_code=303
        )
    set_revoked(db, user.id, True)
    db.commit()
    _record_admin_action(db, "switch_off", user)
    logger.info("Control page: SWITCHED OFF %s — all data kept", user.email)
    name = user.cafe_name or user.email
    return RedirectResponse(
        url="/control?msg=" + quote(f"{name} is now Switched Off"), status_code=303
    )


@app.post("/control/logout")
def control_logout(request: Request, csrf: str = Form("")):
    sess, deny = _control_post_guard(request)
    if deny is not None:
        return deny
    bad = _control_csrf_bad(sess, csrf)
    if bad is not None:
        return bad
    resp = RedirectResponse(url="/control", status_code=303)
    _clear_admin_cookies(resp)
    return resp


# ---------------------------------------------------------------------------
# Pages (frontend + legal + custom 404)
# ---------------------------------------------------------------------------
@app.get("/")
def home():
    return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/pricing")
def pricing():
    return FileResponse(FRONTEND_DIR / "pricing.html")


@app.get("/privacy")
def privacy():
    return FileResponse(FRONTEND_DIR / "privacy.html")


@app.get("/terms")
def terms():
    return FileResponse(FRONTEND_DIR / "terms.html")


@app.exception_handler(404)
async def not_found(request: Request, exc):
    if request.url.path.startswith("/api"):
        return JSONResponse(status_code=404, content={"detail": "Not found."})
    page = FRONTEND_DIR / "404.html"
    if page.exists():
        return FileResponse(page, status_code=404)
    return JSONResponse(status_code=404, content={"detail": "Not found."})


if __name__ == "__main__":
    # Local / simple-host entry point:  python3 main.py
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
