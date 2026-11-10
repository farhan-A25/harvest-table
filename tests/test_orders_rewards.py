"""Orders, accept-with-ETA live tracking, stamps, rewards — the core loop."""
from datetime import date, timedelta

from conftest import make_active_cafe, new_client, place_order, serve_order


def _menu_item(client, token, name):
    info = client.get(f"/api/public/{token}/info").json()
    for c in info["categories"]:
        for i in info["items"]:
            if i["category_id"] == c["id"] and i["name"] == name:
                return i
    raise AssertionError(f"{name} not on the public menu")


def test_seeded_menu_is_the_full_indian_cafe_menu():
    c, email, token = make_active_cafe()
    info = c.get(f"/api/public/{token}/info").json()
    cats = [c_["name"] for c_ in info["categories"]]
    for expected in ("Hot Coffee", "Cold Coffee & Shakes", "Chai & Hot Drinks",
                     "Juices & Coolers", "Snacks & Fries", "Sandwiches & Burgers",
                     "Maggi & Pasta", "Pizza", "Breakfast", "Desserts & Cakes"):
        assert expected in cats, cats
    total = len(info["items"])
    assert total >= 30, total
    cap = _menu_item(c, token, "Cappuccino")
    assert cap["price"] == 180
    chai = _menu_item(c, token, "Masala Chai")
    assert chai["price"] == 60


def test_public_order_creates_customer_and_owner_sees_it():
    c, email, token = make_active_cafe()
    cap = _menu_item(c, token, "Cappuccino")
    out = place_order(c, token, items=[{"item_id": cap["id"], "qty": 2}])
    assert out["order"]["id"]
    assert out["order"]["total"] == 360  # server-side total from menu prices
    assert out["customer"]["stamps"] == 0

    orders = c.get("/api/orders").json()["orders"]
    assert len(orders) == 1
    o = orders[0]
    assert o["id"] == out["order"]["id"]
    assert o["status"] == "NEW"
    assert o["customer"]["phone"] == "9811111111"
    assert o["items"][0]["name"] == "Cappuccino"
    assert o["items"][0]["qty"] == 2

    custs = c.get("/api/customers").json()["customers"]
    assert len(custs) == 1
    assert custs[0]["phone"] == "9811111111"
    assert custs[0]["visits"] == 0  # visits count completed (served) visits


def test_order_totals_are_server_side_not_client_claimed():
    c, email, token = make_active_cafe()
    cap = _menu_item(c, token, "Cappuccino")
    # Even a wildly wrong client-sent total is ignored.
    r = c.post(f"/api/public/{token}/order", json={
        "name": "Aarav", "phone": "9822222222", "table": "3", "total": 1,
        "items": [{"item_id": cap["id"], "qty": 1}],
    })
    assert r.status_code == 200, r.text
    assert r.json()["order"]["total"] == 180


def test_accept_with_prep_time_is_visible_on_customer_status():
    c, email, token = make_active_cafe()
    out = place_order(c, token)
    oid = out["order"]["id"]
    st = c.get(f"/api/public/{token}/order-status",
               params={"order_id": oid, "phone": "9811111111"}).json()
    assert st["order"]["status"] == "NEW"

    r = c.post(f"/api/orders/{oid}/status", json={"status": "ACCEPTED", "prep_minutes": 20})
    assert r.status_code == 200, r.text

    st = c.get(f"/api/public/{token}/order-status",
               params={"order_id": oid, "phone": "9811111111"}).json()
    assert st["order"]["status"] == "ACCEPTED"
    assert st["order"]["prep_minutes"] == 20
    assert st["order"]["ready_at"]
    assert 18 <= st["order"]["minutes_left"] <= 20

    # Owner delays by 5 minutes: the customer's screen moves too.
    r = c.post(f"/api/orders/{oid}/status",
               json={"status": "ACCEPTED", "add_minutes": 5})
    assert r.status_code == 200, r.text
    st2 = c.get(f"/api/public/{token}/order-status",
                params={"order_id": oid, "phone": "9811111111"}).json()
    assert st2["order"]["prep_minutes"] == 25
    assert st2["order"]["minutes_left"] > st["order"]["minutes_left"]


def test_status_cannot_go_backwards():
    c, email, token = make_active_cafe()
    out = place_order(c, token)
    oid = out["order"]["id"]
    serve_order(c, oid)
    r = c.post(f"/api/orders/{oid}/status", json={"status": "PREPARING"})
    assert r.status_code == 400
    # Wrong phone cannot snoop another customer's order status.
    r = c.get(f"/api/public/{token}/order-status",
              params={"order_id": oid, "phone": "9800000000"})
    assert r.status_code == 404


def test_serve_awards_exactly_one_stamp():
    c, email, token = make_active_cafe()
    out = place_order(c, token)
    serve_order(c, out["order"]["id"])
    card = c.get(f"/api/public/{token}/card", params={"phone": "9811111111"}).json()
    assert card["customer"]["stamps"] == 1
    assert card["customer"]["visits"] == 1
    # Re-serving / re-completing must never double-stamp.
    c.post(f"/api/orders/{out['order']['id']}/status", json={"status": "SERVED"})
    c.post(f"/api/orders/{out['order']['id']}/status", json={"status": "COMPLETED"})
    card = c.get(f"/api/public/{token}/card", params={"phone": "9811111111"}).json()
    assert card["customer"]["stamps"] == 1


def test_fifth_stamp_issues_reward_code_valid_7_days():
    c, email, token = make_active_cafe()
    last = None
    for _ in range(5):
        out = place_order(c, token)
        serve_order(c, out["order"]["id"])
        last = out
    card = c.get(f"/api/public/{token}/card", params={"phone": "9811111111"}).json()
    assert card["customer"]["stamps"] == 0  # card reset after the reward
    assert card["customer"]["visits"] == 5
    reward = card["customer"]["active_reward"]
    assert reward and reward["code"].startswith("CL-")
    assert reward["expires_on"] == (date.today() + timedelta(days=7)).isoformat()
    # The live order-status payload for the 5th order shows it too.
    st = c.get(f"/api/public/{token}/order-status",
               params={"order_id": last["order"]["id"], "phone": "9811111111"}).json()
    assert st["customer"]["active_reward"]["code"] == reward["code"]


def test_reward_redeem_works_exactly_once():
    c, email, token = make_active_cafe()
    for _ in range(5):
        out = place_order(c, token)
        serve_order(c, out["order"]["id"])
    code = c.get(f"/api/public/{token}/card",
                 params={"phone": "9811111111"}).json()["customer"]["active_reward"]["code"]
    r = c.post("/api/rewards/redeem", json={"code": code})
    assert r.status_code == 200, r.text
    assert r.json()["customer"]["name"] == "Aarav"
    r = c.post("/api/rewards/redeem", json={"code": code})
    assert r.status_code == 400  # second redemption refused
    r = c.post("/api/rewards/redeem", json={"code": "CL-NOPE99"})
    assert r.status_code == 404


def test_mark_paid_toggle_and_dashboard_revenue():
    c, email, token = make_active_cafe()
    out = place_order(c, token)
    serve_order(c, out["order"]["id"])
    dash = c.get("/api/dashboard").json()
    assert dash["orders_today"] == 1
    assert dash["revenue_today"] == 0  # not marked paid yet — counter only
    assert dash["orders_unpaid"] == 1

    r = c.post(f"/api/orders/{out['order']['id']}/paid", json={"paid": True})
    assert r.status_code == 200
    dash = c.get("/api/dashboard").json()
    assert dash["revenue_today"] == 180
    assert dash["orders_unpaid"] == 0
    # Toggle back off works too.
    c.post(f"/api/orders/{out['order']['id']}/paid", json={"paid": False})
    dash = c.get("/api/dashboard").json()
    assert dash["revenue_today"] == 0
