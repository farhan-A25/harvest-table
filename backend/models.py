"""SQLAlchemy models for the CafeLoop Owner App.

Tenant rule (same as Do Gym): every cafe-owned row carries the owning
user's id, and every owner-facing query is scoped by it — one cafe can
never see another cafe's menu, orders, customers or rewards.
"""
from datetime import datetime

from sqlalchemy import Boolean, Column, Date, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import relationship

from database import Base


class User(Base):
    """A cafe owner account (the tenant)."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    # Entry-flow + cafe/owner details (collected ONCE on the Details page)
    owner_name = Column(String(120), default="")
    cafe_name = Column(String(160), default="")
    mobile = Column(String(20), default="")
    whatsapp = Column(String(20), default="")
    cafe_address = Column(String(255), default="")
    cafe_city = Column(String(80), default="")
    cafe_phone = Column(String(20), default="")
    details_completed = Column(Boolean, default=False)
    plan_chosen = Column(Boolean, default=False)
    # How this account was created: "email" (password signup) or
    # "google" (Continue with Google — email verified by Google).
    auth_provider = Column(String(16), nullable=False, default="email")
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    # Canonical signup flow: account created (Google or email) -> OTP to
    # that email -> details -> payment. While True, everything except
    # the OTP endpoints is blocked. Google accounts are born verified.
    otp_pending = Column(Boolean, nullable=False, default=False)
    # Session epoch: every issued session token carries it; logging
    # out bumps it, invalidating all previously issued tokens at once.
    session_epoch = Column(Integer, nullable=False, default=0)


class OtpChallenge(Base):
    """The live email-OTP challenge for one account (at most one row).

    Only the HASH of the 6-digit code is stored (plus, ONLY when the
    dev-only DEV_OTP_ECHO=1 flag is on, the plain code in dev_code so
    tests/local dev can complete the flow without an SMTP server).
    """

    __tablename__ = "otp_challenges"

    user_id = Column(Integer, ForeignKey("users.id"), primary_key=True)
    code_hash = Column(String(64), nullable=False)
    dev_code = Column(String(8), nullable=True)
    attempts = Column(Integer, nullable=False, default=0)
    last_sent_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class PasswordResetChallenge(Base):
    """The live password-reset challenge for one account (at most one
    row) — a SEPARATE table from OtpChallenge with a different hash
    domain, so a code issued for one purpose can never be spent on
    the other. Same storage rules as the signup OTP."""

    __tablename__ = "password_reset_challenges"

    user_id = Column(Integer, ForeignKey("users.id"), primary_key=True)
    code_hash = Column(String(64), nullable=False)
    dev_code = Column(String(8), nullable=True)
    attempts = Column(Integer, nullable=False, default=0)
    last_sent_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class AdminAction(Base):
    """Audit trail for Farhan's Control support actions: what was
    done, which account it hit, and when. Stores NO secrets."""
    __tablename__ = "admin_actions"

    id = Column(Integer, primary_key=True)
    action = Column(String(64), nullable=False)
    target_user_id = Column(Integer, nullable=True)
    target_email = Column(String(255), nullable=False, default="")
    detail = Column(String(255), nullable=False, default="")
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class FaceTemplate(Base):
    """Farhan's enrolled face template for face unlock (singleton row).

    ONLY the numeric face descriptors computed in his browser during
    enrollment (a JSON list of 128-float arrays, one per pose) — never
    a photo. Re-registering from Control replaces the descriptors.
    """

    __tablename__ = "face_templates"

    id = Column(Integer, primary_key=True)
    descriptors = Column(Text, nullable=False, default="[]")
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class SubscriptionPayment(Base):
    """One recorded subscription payment for using this app.

    A row is written when a payment is CONFIRMED — by Farhan's admin
    activation after in-person collection (method
    "collected_in_person") or by a verified face-scan unlock on the
    owner's device after the same in-person collection (method
    "face_unlock"). Amounts are always computed server-side from
    billing.py — never taken from the client.
    """
    __tablename__ = "subscription_payments"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    plan_id = Column(String(32), nullable=False)      # pro
    plan_name = Column(String(80), nullable=False)    # CafeLoop Pro
    period = Column(String(16), nullable=False)       # monthly | yearly
    amount = Column(Integer, nullable=False)          # ₹, from billing.py
    method = Column(String(32), nullable=False, default="upi_qr")
    status = Column(String(16), nullable=False)       # paid | pending
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class Setting(Base):
    __tablename__ = "settings"

    key = Column(String(64), primary_key=True)
    value = Column(String(255), nullable=False)


# ---------------------------------------------------------------------------
# Cafe data: menu, customers, orders, rewards — all tenant-scoped.
# ---------------------------------------------------------------------------
class MenuCategory(Base):
    __tablename__ = "menu_categories"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    name = Column(String(60), nullable=False)
    sort = Column(Integer, nullable=False, default=0)


class MenuItem(Base):
    __tablename__ = "menu_items"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    category_id = Column(Integer, ForeignKey("menu_categories.id"), nullable=True, index=True)
    name = Column(String(80), nullable=False)
    price = Column(Integer, nullable=False)  # ₹
    emoji = Column(String(16), nullable=False, default="☕")
    available = Column(Boolean, nullable=False, default=True)
    sort = Column(Integer, nullable=False, default=0)


class Customer(Base):
    """A cafe's customer, keyed by phone INSIDE that cafe. Created and
    updated automatically by the public ordering flow — customers have
    no accounts and never log in."""
    __tablename__ = "customers"
    __table_args__ = (
        UniqueConstraint("user_id", "phone", name="uq_customer_cafe_phone"),
    )

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    phone = Column(String(20), nullable=False)  # 10 digits
    name = Column(String(120), nullable=False, default="")
    # Lifetime SERVED orders (a "visit"). Incremented automatically
    # when an order is marked served — never by hand.
    visits = Column(Integer, nullable=False, default=0)
    # Stamps on the CURRENT card (0..4 — hitting 5 issues a reward and
    # resets the card to 0; lifetime counts live in visits/rewards).
    stamps = Column(Integer, nullable=False, default=0)
    first_visit = Column(Date, nullable=True)
    last_visit = Column(Date, nullable=True)


class Order(Base):
    __tablename__ = "orders"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=False, index=True)
    table_no = Column(String(16), nullable=False, default="")
    # NEW -> ACCEPTED -> PREPARING -> SERVED -> COMPLETED (SERVED orders
    # flip to COMPLETED automatically once they are half an hour old).
    status = Column(String(16), nullable=False, default="NEW", index=True)
    # Acceptance: when the owner accepts, they pick a preparation time;
    # ready_at = accepted_at + prep_minutes. A later "+5 min" delay
    # pushes ready_at — the customer's phone tracks all of it live.
    prep_minutes = Column(Integer, nullable=True)
    accepted_at = Column(DateTime, nullable=True)
    ready_at = Column(DateTime, nullable=True)
    total = Column(Integer, nullable=False, default=0)  # ₹, server-computed
    # Customer payment happens at the COUNTER, never on the website
    # (no checkout, no gateway). This flag is only the owner's own
    # bookkeeping, toggled by hand on the Orders screen; dashboard
    # revenue counts orders marked paid.
    paid = Column(Boolean, nullable=False, default=False)
    paid_at = Column(DateTime, nullable=True)
    # One stamp per order, awarded automatically at SERVED time. This
    # flag is the duplicate protection: serving twice never re-stamps.
    stamp_awarded = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    served_at = Column(DateTime, nullable=True)

    items = relationship("OrderItem", back_populates="order", cascade="all, delete-orphan")
    customer = relationship("Customer")


class OrderItem(Base):
    """One line of an order. Name and price are SNAPSHOTS from the
    menu at order time, so later menu edits never rewrite history
    (and the favourite-item math reads these)."""
    __tablename__ = "order_items"

    id = Column(Integer, primary_key=True)
    order_id = Column(Integer, ForeignKey("orders.id"), nullable=False, index=True)
    item_name = Column(String(80), nullable=False)
    price = Column(Integer, nullable=False)  # ₹ snapshot
    qty = Column(Integer, nullable=False, default=1)

    order = relationship("Order", back_populates="items")


class Reward(Base):
    """A FREE-drink reward, issued AUTOMATICALLY when a customer's
    stamp card fills (5 stamps). Valid 7 days from issue; redeemed
    once, by the owner entering/confirming its code."""
    __tablename__ = "rewards"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=False, index=True)
    code = Column(String(16), unique=True, nullable=False, index=True)  # CL-XXXXXX
    status = Column(String(16), nullable=False, default="active")  # active | redeemed
    issued_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    expires_on = Column(Date, nullable=False)  # issued date + 7 days
    redeemed_at = Column(DateTime, nullable=True)

    customer = relationship("Customer")
