"""Face unlock — Farhan's in-person unlock (ported from Do Gym).

Covers: enrollment storage/replacement + validation, the /api/plan
face_unlock_available flag that drives the pay screen's button, the
challenge lifecycle (issue / expiry / single-use), a stubbed
successful verification recording method "face_unlock" for the period
selected on the pay screen and lifting the gate, failed-attempt
lockout, the switch-off override, the Control enrollment card, and
local-only asset serving. No camera exists in CI — the browser match
is stubbed at the verify call, exactly the seam the server enforces
(challenge + liveness + distance threshold).
"""
import json as _json
import re
import time

import pytest
from fastapi.testclient import TestClient

import main
import models
from conftest import (
    ADMIN_HEADERS, admin_activate, new_client, save_details, signup_owner,
)
from database import SessionLocal

POSE_A = [0.01] * 128
POSE_B = [0.02] * 128
SECRET = "test-admin-secret"


@pytest.fixture(autouse=True)
def _face_cleanup():
    yield
    with SessionLocal() as db:
        db.query(models.FaceTemplate).delete()
        db.query(models.Setting).filter(
            models.Setting.key.like("revoked_user_%")
        ).delete(synchronize_session=False)
        db.commit()
    main._face_challenges.clear()
    main._face_fails.clear()
    main._face_lockouts.clear()


def _enroll(client, poses=(POSE_A, POSE_B, POSE_A)):
    r = client.post(
        "/api/admin/face-template", headers=ADMIN_HEADERS,
        json={"descriptors": [list(p) for p in poses]},
    )
    assert r.status_code == 200, r.text
    return r


def _templates():
    with SessionLocal() as db:
        return db.query(models.FaceTemplate).all()


def _unpaid_owner():
    """A cafe that signed up, verified OTP and saved details — but
    has NOT paid: the pay-first gate is closed for it."""
    client = new_client()
    email = signup_owner(client)
    save_details(client)
    assert client.get("/api/dashboard").status_code == 402
    return client, email


def _challenge(client):
    r = client.post("/api/face-unlock/challenge")
    assert r.status_code == 200, r.text
    return r.json()


def _verify(client, challenge, distance=0.31, liveness=None, period=None):
    body = {
        "challenge_id": challenge["challenge_id"],
        "distance": distance,
        "liveness": challenge["action"] if liveness is None else liveness,
    }
    if period is not None:
        body["period"] = period
    return client.post("/api/face-unlock/verify", json=body)


def _control_login(client):
    page = client.get("/control")
    assert page.status_code == 200
    m = re.search(r'name="csrf" value="([^"]+)"', page.text)
    assert m, "login form carries a csrf token"
    r = client.post(
        "/control/login",
        data={"password": SECRET, "csrf": m.group(1)},
        follow_redirects=False,
    )
    assert r.status_code == 303, r.text


# ------------------------------------------------------------- enrollment ----
def test_enroll_stores_descriptors_and_replaces():
    client = new_client()
    r = _enroll(client)
    assert r.json()["poses"] == 3
    rows = _templates()
    assert len(rows) == 1
    stored = _json.loads(rows[0].descriptors)
    assert stored == [[0.01] * 128, [0.02] * 128, [0.01] * 128]
    # The record holds numbers only — no image-ish payload anywhere.
    assert "data:" not in rows[0].descriptors and "base64" not in rows[0].descriptors

    # Re-registering replaces the single template.
    _enroll(client, poses=(POSE_B,))
    rows = _templates()
    assert len(rows) == 1
    assert _json.loads(rows[0].descriptors) == [[0.02] * 128]


def test_enroll_requires_admin():
    client = new_client()
    r = client.post("/api/admin/face-template",
                    json={"descriptors": [POSE_A]})
    assert r.status_code == 403
    r = client.post("/api/admin/face-template",
                    headers={"X-Admin-Secret": "wrong"},
                    json={"descriptors": [POSE_A]})
    assert r.status_code == 403
    assert _templates() == []


def test_enroll_validation():
    client = new_client()
    r = client.post("/api/admin/face-template", headers=ADMIN_HEADERS,
                    json={"descriptors": []})
    assert r.status_code == 400
    r = client.post("/api/admin/face-template", headers=ADMIN_HEADERS,
                    json={"descriptors": [[0.1] * 64]})  # wrong length
    assert r.status_code == 400
    r = client.post("/api/admin/face-template", headers=ADMIN_HEADERS,
                    json={"descriptors": [POSE_A] * 7})  # too many poses
    assert r.status_code == 400
    assert _templates() == []


def test_admin_template_readback():
    client = new_client()
    r = client.get("/api/admin/face-template", headers=ADMIN_HEADERS)
    assert r.json() == {"enrolled": False, "descriptors": []}
    _enroll(client)
    r = client.get("/api/admin/face-template", headers=ADMIN_HEADERS)
    assert r.json()["enrolled"] is True
    assert len(r.json()["descriptors"]) == 3


def test_remove_template_hides_face_unlock():
    client, _email = _unpaid_owner()
    _enroll(new_client())
    assert client.get("/api/plan").json()["face_unlock_available"] is True
    r = new_client().post("/api/admin/face-template/remove", headers=ADMIN_HEADERS)
    assert r.status_code == 200
    assert _templates() == []
    assert client.get("/api/plan").json()["face_unlock_available"] is False


# ------------------------------------------------------------- availability ----
def test_plan_flag_and_template_endpoint():
    client, _email = _unpaid_owner()
    assert client.get("/api/plan").json()["face_unlock_available"] is False
    t = client.get("/api/face-unlock/template").json()
    assert t == {"enrolled": False, "descriptors": []}

    _enroll(new_client())
    assert client.get("/api/plan").json()["face_unlock_available"] is True
    t = client.get("/api/face-unlock/template").json()
    assert t["enrolled"] is True
    assert len(t["descriptors"]) == 3


def test_challenge_needs_enrollment_and_login():
    anon = new_client()
    assert anon.post("/api/face-unlock/challenge").status_code == 401
    client, _email = _unpaid_owner()
    assert client.post("/api/face-unlock/challenge").status_code == 400  # not enrolled
    _enroll(new_client())
    ch = _challenge(client)
    assert ch["action"] in ("blink", "turn_left", "turn_right")
    assert ch["expires_in"] == 120
    assert ch["threshold"] == 0.5


# ----------------------------------------------------------------- verify ----
def test_successful_verify_activates_pay_screen_period():
    client, _email = _unpaid_owner()
    _enroll(new_client())

    # The pay screen's Yearly toggle is what this owner picked.
    r = _verify(client, _challenge(client), period="yearly")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["subscription_active"] is True
    assert body["last_payment"]["method"] == "face_unlock"
    assert body["last_payment"]["method_label"] == "Farhan's face scan"
    # CafeLoop Pro yearly, server-computed from billing.py.
    assert body["last_payment"]["amount"] == 14990
    assert body["last_payment"]["period"] == "yearly"
    assert client.get("/api/dashboard").status_code == 200

    with SessionLocal() as db:
        pay = (
            db.query(models.SubscriptionPayment)
            .order_by(models.SubscriptionPayment.id.desc())
            .first()
        )
        assert pay.method == "face_unlock" and pay.status == "paid"


def test_successful_verify_defaults_to_account_period():
    client, _email = _unpaid_owner()
    _enroll(new_client())
    r = _verify(client, _challenge(client))  # no period sent
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["last_payment"]["period"] == "monthly"
    assert body["last_payment"]["amount"] == 1499


def test_verify_rejects_bad_distance_and_missing_liveness():
    client, _email = _unpaid_owner()
    _enroll(new_client())
    r = _verify(client, _challenge(client), distance=0.9)
    assert r.status_code == 400
    r = _verify(client, _challenge(client), liveness="nod")
    assert r.status_code == 400
    r = _verify(client, _challenge(client), liveness="")
    assert r.status_code == 400
    assert client.get("/api/dashboard").status_code == 402  # still gated


def test_challenge_is_single_use():
    client, _email = _unpaid_owner()
    _enroll(new_client())
    ch = _challenge(client)
    assert _verify(client, ch).status_code == 200
    with SessionLocal() as db:
        count = db.query(models.SubscriptionPayment).count()
    r = _verify(client, ch)  # same challenge again
    assert r.status_code == 400
    with SessionLocal() as db:
        assert db.query(models.SubscriptionPayment).count() == count


def test_expired_challenge_is_refused():
    client, _email = _unpaid_owner()
    _enroll(new_client())
    ch = _challenge(client)
    main._face_challenges[ch["challenge_id"]]["expires"] = time.time() - 1
    assert _verify(client, ch).status_code == 400
    assert client.get("/api/dashboard").status_code == 402


def test_five_failures_lock_face_unlock_for_15_minutes():
    client, _email = _unpaid_owner()
    _enroll(new_client())
    with SessionLocal() as db:
        before = db.query(models.SubscriptionPayment).count()
    for _ in range(5):
        assert _verify(client, _challenge(client), distance=0.95).status_code == 400
    # Locked: no new challenges, and even a perfect claim is refused.
    assert client.post("/api/face-unlock/challenge").status_code == 429
    ch = {"challenge_id": "whatever-1234", "action": "blink"}
    assert _verify(client, ch).status_code == 429
    with SessionLocal() as db:
        assert db.query(models.SubscriptionPayment).count() == before


def test_switch_off_overrides_face_unlock():
    client, email = _unpaid_owner()
    _enroll(new_client())
    admin_activate(client, email)  # active via in-person collection
    assert client.get("/api/dashboard").status_code == 200
    r = client.post("/api/admin/switch-off", headers=ADMIN_HEADERS,
                    json={"email": email})
    assert r.status_code == 200
    assert client.get("/api/dashboard").status_code == 402
    r = _verify(client, _challenge(client))
    assert r.status_code == 403  # switched off — a scan cannot override
    assert client.get("/api/dashboard").status_code == 402


# ------------------------------------------------------------- assets/page ----
def test_face_assets_are_served_locally_and_safely():
    client = new_client()
    r = client.get("/static/face/face-api.min.js")
    assert r.status_code == 200
    assert "javascript" in r.headers["content-type"]
    r = client.get("/static/face/tiny_face_detector_model-weights_manifest.json")
    assert r.status_code == 200
    # Nothing outside the face folder is reachable through this route.
    assert client.get("/static/face/payment-qr.png").status_code == 404
    assert client.get("/static/face/nonexistent.bin").status_code == 404


def test_control_page_shows_face_card():
    client = new_client()
    _control_login(client)
    page = client.get("/control").text
    assert "Your face — cafe unlock" in page
    assert "Not registered" in page
    assert 'id="face-reg-btn"' in page
    assert 'id="ctl-face-video"' in page
    _enroll(new_client())
    page = client.get("/control").text
    assert "Registered ✓" in page
    assert "3 pose(s) on file" in page


def test_pay_screen_has_face_scan_path():
    page = new_client().get("/").text
    # The pay screen carries the face-unlock action (shown when a
    # template is enrolled — the button ships hidden)…
    assert 'id="pay-face-btn"' in page
    assert "Pay — Unlock by Face Scan" in page
    # …leading to the DEDICATED scan page with its green done state…
    assert 'id="facescan-view"' in page
    assert "Farhan's Face" in page
    assert 'id="scan-face-video"' in page
    assert 'id="facescan-done"' in page
    # …and the unlock completes ONLY through the face-verify call,
    # while the QR "waiting for activation" auto-check stays in place.
    assert "/api/face-unlock/verify" in page
    assert "startPlanPoll" in page
    assert 'id="up-wait"' in page
