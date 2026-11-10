"""Subscription plan for using the CafeLoop Owner App itself.

Single source of truth: the public pricing page (/pricing) and the in-app
Plan & Billing screen both render from GET /api/plans, which serves this.

ONE plan only (Farhan's order, 2026-11-10): CafeLoop Pro — everything
included, no tiers. Yearly = 10× monthly (2 months free), the same
billing shape as his other products.
"""

SUBSCRIPTION_PLANS = [
    {
        "id": "pro",
        "name": "CafeLoop Pro",
        "monthly": 1499,
        "yearly": 14990,
        "member_limit": None,  # unlimited
        "badge": "Everything Included",
        "features": [
            "Unlimited tables & customers",
            "Table QR ordering — orders straight to the kitchen",
            "Automatic stamp cards (5th drink FREE)",
            "Automatic rewards with unique codes",
            "Come Back list with one-tap WhatsApp offers",
            "Live owner dashboard — orders, revenue, repeat %",
            "Menu manager with photos-by-emoji",
            "1 owner login",
        ],
    },
]


def get_subscription_plan(plan_id: str):
    return next((p for p in SUBSCRIPTION_PLANS if p["id"] == plan_id), None)
