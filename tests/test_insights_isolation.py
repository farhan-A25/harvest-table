"""Come Back math, dashboard math, tenant isolation, menu CRUD."""
from datetime import datetime, timedelta

import models
from database import SessionLocal
from conftest import make_active_cafe, new_client, place_order, serve_order


def _backdate_customer(user_email: str, phone: str, days_ago: int, visits: int = None):
    db = SessionLocal()
    try:
        user = db.query(models.User).filter(models.User.email == user_email).first()
        cust = (db.query(models.Customer)
                .filter(models.Customer.user_id == user.id,
                        models.Customer.phone == phone).first())
        cust.last_visit = datetime.now() - timedelta(days=days_ago)
        if visits is not None:
            cust.visits = visits
        db.commit()
    finally:
        db.close()


def test_comeback_math():
    c, email, token = make_active_cafe()
    # Regular gone 20 days (2 visits) -> IN.
    for _ in range(2):
        serve_order(c, place_order(c, token, phone="9811111111")["order"]["id"])
    _backdate_customer(email, "9811111111", days_ago=20)
    # Recent regular (2 visits, today) -> OUT.
    for _ in range(2):
        serve_order(c, place_order(c, token, phone="9822222222", name="Recent")["order"]["id"])
    # One-timer gone 30 days -> OUT (needs >= 2 visits).
    serve_order(c, place_order(c, token, phone="9833333333", name="Once")["order"]["id"])
    _backdate_customer(email, "9833333333", days_ago=30)

    rows = c.get("/api/comeback").json()["customers"]
    phones = [r["phone"] for r in rows]
    assert phones == ["9811111111"]
    row = rows[0]
    assert row["visits"] == 2
    assert row["days_absent"] >= 20
    assert row["favourite"] == "Cappuccino"
    assert "20% OFF" in row["message"]
    assert "Cappuccino" in row["message"]


def test_dashboard_math_and_repeat_percent():
    c, email, token = make_active_cafe()
    # Customer 1: two paid orders. Customer 2: one unpaid order.
    for _ in range(2):
        oid = place_order(c, token, phone="9811111111")["order"]["id"]
        serve_order(c, oid)
        c.post(f"/api/orders/{oid}/paid", json={"paid": True})
    oid = place_order(c, token, phone="9822222222", name="Second")["order"]["id"]
    serve_order(c, oid)

    d = c.get("/api/dashboard").json()
    assert d["orders_today"] == 3
    assert d["revenue_today"] == 360  # only PAID orders count
    assert d["total_customers"] == 2
    assert d["repeat_customers"] == 1
    assert d["repeat_pct"] == 50
    assert d["rewards_active"] == 0
    assert d["top_items"][0]["name"] == "Cappuccino"
    assert d["top_items"][0]["qty"] == 3


def test_tenant_isolation():
    ca, email_a, token_a = make_active_cafe()
    cb, email_b, token_b = make_active_cafe()
    out = place_order(ca, token_a, phone="9855555555")
    serve_order(ca, out["order"]["id"])

    # Cafe B sees none of cafe A's world.
    assert cb.get("/api/orders").json()["orders"] == []
    assert cb.get("/api/customers").json()["customers"] == []
    assert cb.get("/api/comeback").json()["customers"] == []
    dash_b = cb.get("/api/dashboard").json()
    assert dash_b["orders_today"] == 0 and dash_b["total_customers"] == 0
    # B cannot move A's order.
    r = cb.post(f"/api/orders/{out['order']['id']}/status", json={"status": "PREPARING"})
    assert r.status_code == 404
    # B's public token serves B's cafe, and A's customer is unknown there.
    info_b = cb.get(f"/api/public/{token_b}/info").json()
    assert info_b["cafe_name"] == "Brew & Bean"
    r = cb.get(f"/api/public/{token_b}/card", params={"phone": "9855555555"})
    assert r.status_code == 404
    # A bogus token 404s cleanly.
    assert ca.get("/api/public/nope-nope/info").status_code == 404


def test_menu_crud_persists_to_public_page():
    c, email, token = make_active_cafe()
    menu = c.get("/api/menu").json()
    cat = menu["categories"][0]
    r = c.post("/api/menu/items", json={
        "name": "Biscoff Cheesecake", "price": 260, "emoji": "🍰",
        "category_id": cat["id"], "available": True})
    assert r.status_code == 200, r.text
    item_id = r.json()["item"]["id"]

    info = c.get(f"/api/public/{token}/info").json()
    names = [i["name"] for i in info["items"]]
    assert "Biscoff Cheesecake" in names

    # Toggle unavailable -> disappears from the public menu.
    r = c.put(f"/api/menu/items/{item_id}", json={"available": False})
    assert r.status_code == 200
    info = c.get(f"/api/public/{token}/info").json()
    names = [i["name"] for i in info["items"]]
    assert "Biscoff Cheesecake" not in names

    # New category + delete flows.
    r = c.post("/api/menu/categories", json={"name": "Seasonal"})
    assert r.status_code == 200
    new_cat = r.json()["category"]["id"]
    assert c.delete(f"/api/menu/categories/{new_cat}").status_code == 200
    assert c.delete(f"/api/menu/items/{item_id}").status_code == 200
