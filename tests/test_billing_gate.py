"""The ONE plan + the pay-first gate (mirrors the Do Gym gate)."""
from conftest import (admin_activate, make_active_cafe, new_client,
                      place_order, save_details, signup_owner)


def test_exactly_one_plan_at_1499_14990():
    c = new_client()
    plans = c.get("/api/plans").json()["plans"]
    assert len(plans) == 1
    p = plans[0]
    assert p["id"] == "pro"
    assert p["name"] == "CafeLoop Pro"
    assert p["monthly"] == 1499
    assert p["yearly"] == 14990
    assert p["yearly"] == 10 * p["monthly"]


def test_unpaid_owner_is_gated_402():
    c = new_client()
    email = signup_owner(c)
    save_details(c)
    # Everything beyond details/plans/payment/logout is closed.
    for path in ("/api/dashboard", "/api/orders", "/api/customers",
                 "/api/comeback", "/api/menu", "/api/cafe/link"):
        r = c.get(path)
        assert r.status_code == 402, (path, r.status_code, r.text)
        assert "not active" in r.json()["detail"]
    # …but the open set works.
    assert c.get("/api/me").status_code == 200
    assert c.get("/api/plans").status_code == 200
    assert c.get("/api/plan").status_code == 200
    assert c.get("/api/details").status_code == 200


def test_public_ordering_never_gated_even_when_unpaid():
    c = new_client()
    email = signup_owner(c)
    save_details(c)
    # The token exists in settings even before activation; fetch it via a
    # co-activated second step is not possible (gate), so activate, grab
    # the token, then switch the account OFF and prove the public page
    # still serves the menu.
    admin_activate(c, email)
    token = c.get("/api/cafe/link").json()["url"].rstrip("/").split("/")[-1]
    from conftest import ADMIN_HEADERS
    r = c.post("/api/admin/switch-off", json={"email": email}, headers=ADMIN_HEADERS)
    assert r.status_code == 200, r.text
    info = c.get(f"/api/public/{token}/info")
    assert info.status_code == 200
    assert info.json()["cafe_name"] == "Brew & Bean"
    # Owner APIs are gated again after switch-off.
    assert c.get("/api/orders").status_code == 402


def test_activation_unlocks_and_records_payment():
    c, email, token = make_active_cafe()
    assert c.get("/api/dashboard").status_code == 200
    plan = c.get("/api/plan").json()
    assert plan["subscription_active"] is True
    assert plan["period"] == "monthly"
    from conftest import ADMIN_HEADERS
    summary = c.get("/api/admin/cafes", headers=ADMIN_HEADERS).json()
    me = next(x for x in summary["accounts"] if x["email"] == email)
    assert me["status"] == "active"
    assert me["period"] == "monthly"


def test_yearly_activation_records_14990():
    from conftest import ADMIN_HEADERS
    c = new_client()
    before = c.get("/api/admin/cafes", headers=ADMIN_HEADERS).json()["total_collected"]
    email = signup_owner(c)
    save_details(c)
    admin_activate(c, email, period="yearly")
    summary = c.get("/api/admin/cafes", headers=ADMIN_HEADERS).json()
    me = next(x for x in summary["accounts"] if x["email"] == email)
    assert me["period"] == "yearly"
    assert me["status"] == "active"
    # The collected total grew by exactly the yearly price.
    assert summary["total_collected"] - before == 14990


def test_control_hidden_without_admin_secret(monkeypatch):
    import main
    monkeypatch.delenv("ADMIN_SECRET", raising=False)
    c = new_client()
    assert c.get("/control").status_code == 404
    assert c.get("/api/admin/cafes").status_code == 404
