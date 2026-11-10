"""Pytest suite for the CafeLoop backend.

Run from the cafe-app folder:
    python -m pytest tests/ -q

Uses a throwaway SQLite database (DATABASE_URL points at a temp file), so
the real cafeloop.db is never touched.
"""
import os
import sys
import tempfile
import uuid
from pathlib import Path

import pytest

BACKEND_DIR = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(BACKEND_DIR))

_TMP = tempfile.mkdtemp(prefix="cafeloop-tests-")
os.environ["DATABASE_URL"] = f"sqlite:///{_TMP}/cafeloop-test.db"
os.environ.setdefault("SECRET_KEY", "test-secret-key")
os.environ.setdefault("ADMIN_SECRET", "test-admin-secret")
# Dev-only OTP echo: signup responses carry the live code (dev_otp) so
# tests can complete the OTP stage without SMTP. Production never sets it.
os.environ.setdefault("DEV_OTP_ECHO", "1")

import main  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

ADMIN_HEADERS = {"X-Admin-Secret": os.environ["ADMIN_SECRET"]}


def uniq_email() -> str:
    return f"owner-{uuid.uuid4().hex[:10]}@cafe.in"


def new_client() -> TestClient:
    return TestClient(main.app)


def signup_owner(client: TestClient, email: str = None, password: str = "Brew@2026"):
    """Full canonical flow: signup -> OTP verify. Returns the email."""
    email = email or uniq_email()
    r = client.post("/api/signup", json={
        "owner_name": "Test Owner", "cafe_name": "Test Cafe",
        "email": email, "mobile": "9876543210", "password": password,
    })
    assert r.status_code == 200, r.text
    code = r.json().get("dev_otp")
    assert code, "DEV_OTP_ECHO=1 should echo the code in tests"
    r = client.post("/api/auth/otp/verify", json={"code": code})
    assert r.status_code == 200, r.text
    return email


DETAILS = {
    "cafe_name": "Brew & Bean", "cafe_address": "Road 12, Banjara Hills",
    "cafe_city": "Hyderabad", "cafe_phone": "9876501234",
    "owner_name": "Test Owner", "mobile": "9876543210", "whatsapp": "9876543210",
}


def save_details(client: TestClient, **overrides):
    body = dict(DETAILS)
    body.update(overrides)
    r = client.put("/api/details", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def admin_activate(client: TestClient, email: str, period: str = "monthly"):
    r = client.post("/api/admin/activate",
                    json={"email": email, "period": period},
                    headers=ADMIN_HEADERS)
    assert r.status_code == 200, r.text
    return r.json()


def make_active_cafe(email: str = None):
    """Returns (client, email, cafe_token) for a fully onboarded cafe."""
    client = new_client()
    email = signup_owner(client, email)
    save_details(client)
    admin_activate(client, email)
    r = client.get("/api/cafe/link")
    assert r.status_code == 200, r.text
    token = r.json()["url"].rstrip("/").split("/")[-1]
    return client, email, token


def place_order(client: TestClient, token: str, phone: str = "9811111111",
                name: str = "Aarav", items=None, table: str = "5"):
    """Place a public order as a walk-in customer (uses the cafe's own
    seeded menu: item ids come from the public info endpoint)."""
    info = client.get(f"/api/public/{token}/info")
    assert info.status_code == 200, info.text
    menu = info.json()
    flat = list(menu["items"])
    if items is None:
        cap = next(i for i in flat if i["name"] == "Cappuccino")
        items = [{"item_id": cap["id"], "qty": 1}]
    r = client.post(f"/api/public/{token}/order", json={
        "name": name, "phone": phone, "table": table, "items": items,
    })
    assert r.status_code == 200, r.text
    return r.json()


def serve_order(client: TestClient, order_id: int):
    """NEW -> ACCEPTED -> PREPARING -> SERVED (the full owner flow)."""
    for status, extra in (("ACCEPTED", {"prep_minutes": 15}), ("PREPARING", {}), ("SERVED", {})):
        body = {"status": status}
        body.update(extra)
        r = client.post(f"/api/orders/{order_id}/status", json=body)
        assert r.status_code == 200, r.text
    return r.json()


@pytest.fixture(autouse=True)
def _clear_rate_limits():
    main._login_attempts.clear()
    main._order_attempts.clear()
    yield
