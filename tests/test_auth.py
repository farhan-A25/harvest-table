"""Auth, OTP, details-once and Google sign-in."""
import main
from conftest import (DETAILS, admin_activate, new_client, save_details,
                      signup_owner, uniq_email)


def test_signup_otp_details_once():
    c = new_client()
    email = signup_owner(c)
    me = c.get("/api/me").json()
    assert me["otp_pending"] is False
    assert me["details_completed"] is False

    save_details(c)
    me = c.get("/api/me").json()
    assert me["details_completed"] is True
    assert me["cafe_name"] == "Brew & Bean"

    # Log out and back in: details must NOT be asked again (the Do Gym
    # "asks my details every login" bug class, designed out here).
    c.post("/api/logout")
    r = c.post("/api/login", json={"email": email, "password": "Brew@2026"})
    assert r.status_code == 200, r.text
    me = c.get("/api/me").json()
    assert me["details_completed"] is True
    assert me["cafe_name"] == "Brew & Bean"


def test_signup_validation_errors_are_field_level():
    c = new_client()
    r = c.post("/api/signup", json={
        "owner_name": "", "cafe_name": "", "email": "not-an-email",
        "mobile": "123", "password": "x",
    })
    assert r.status_code == 400
    fields = r.json()["fields"]
    assert "email" in fields and "password" in fields and "mobile" in fields


def test_wrong_otp_rejected_then_right_one_works():
    c = new_client()
    email = uniq_email()
    r = c.post("/api/signup", json={
        "owner_name": "Test Owner", "cafe_name": "Test Cafe", "email": email,
        "mobile": "9876543210", "password": "Brew@2026",
    })
    code = r.json()["dev_otp"]
    bad = "000000" if code != "000000" else "111111"
    assert c.post("/api/auth/otp/verify", json={"code": bad}).status_code == 400
    assert c.post("/api/auth/otp/verify", json={"code": code}).status_code == 200


def test_google_login_born_verified_and_details_once(monkeypatch):
    monkeypatch.setattr(main, "google_auth_enabled", lambda: True)
    monkeypatch.setattr(main, "verify_oauth_state", lambda state: True)
    monkeypatch.setattr(main, "exchange_code_for_token", lambda code: "tok")
    monkeypatch.setattr(main, "fetch_google_userinfo",
                        lambda tok: {"email": "google-owner@cafe.in",
                                     "name": "Google Owner", "email_verified": True})
    c = new_client()
    r = c.get("/auth/google/callback?code=x&state=y", follow_redirects=False)
    assert r.status_code in (302, 307)
    me = c.get("/api/me").json()
    assert me["email"] == "google-owner@cafe.in"
    assert me["otp_pending"] is False  # Google IS the verification
    assert me["details_completed"] is False
    save_details(c, cafe_name="Google Cafe")
    # Second Google login on the same account: no details form again.
    c.get("/auth/google/callback?code=x&state=y", follow_redirects=False)
    me = c.get("/api/me").json()
    assert me["details_completed"] is True
    assert me["cafe_name"] == "Google Cafe"


def test_password_reset_flow():
    import models
    from database import SessionLocal
    c = new_client()
    email = signup_owner(c)
    save_details(c)
    r = c.post("/api/auth/forgot", json={"email": email})
    assert r.status_code == 200
    # The forgot response is deliberately generic (no account probing);
    # the code lives hashed in the DB with the plaintext kept only in
    # dev_code while DEV_OTP_ECHO=1 (tests).
    db = SessionLocal()
    try:
        user = db.query(models.User).filter(models.User.email == email).first()
        row = (db.query(models.PasswordResetChallenge)
               .filter(models.PasswordResetChallenge.user_id == user.id).first())
        code = row.dev_code
    finally:
        db.close()
    assert code
    r = c.post("/api/auth/reset", json={
        "email": email, "code": code, "new_password": "Fresh@2026"})
    assert r.status_code == 200, r.text
    # Old password dead, new one works.
    assert c.post("/api/login", json={"email": email, "password": "Brew@2026"}).status_code == 401
    assert c.post("/api/login", json={"email": email, "password": "Fresh@2026"}).status_code == 200
