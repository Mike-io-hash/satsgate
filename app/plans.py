from __future__ import annotations

from dataclasses import asdict, dataclass
from math import ceil


@dataclass(frozen=True)
class Plan:
    id: str
    title: str
    price_sats: int
    credits: int
    note: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# Recommended plans (tweak as needed):
# - Agents typically want: cheap trial + bigger packs to avoid paying invoices too often.
# - 1 credit (payment verification) = 1 successful /v1/paywall/verify (paid unlock). Credits do not expire.
PLANS: dict[str, Plan] = {
    "trial": Plan(
        id="trial",
        title="Trial",
        price_sats=1_000,
        credits=200,
        note="Low-friction entry for integration. ~5 sats per payment verification.",
    ),
    "starter": Plan(
        id="starter",
        title="Starter",
        price_sats=10_000,
        credits=2_500,
        note="Light production usage. ~4 sats per payment verification.",
    ),
    "growth": Plan(
        id="growth",
        title="Growth",
        price_sats=100_000,
        credits=30_000,
        note="Medium volume. ~3.33 sats per payment verification.",
    ),
    "scale": Plan(
        id="scale",
        title="Scale",
        price_sats=500_000,
        credits=200_000,
        note="High volume. ~2.5 sats per payment verification.",
    ),
    "hyper": Plan(
        id="hyper",
        title="Hyper",
        price_sats=1_000_000,
        credits=500_000,
        note="Very high volume. ~2 sats per payment verification.",
    ),
    "mega": Plan(
        id="mega",
        title="Mega",
        price_sats=10_000_000,
        credits=10_000_000,
        note="Extreme volume. 1 sat per payment verification.",
    ),
}


def list_plans() -> list[dict]:
    return [p.to_dict() for p in PLANS.values()]


def get_plan(plan_id: str) -> Plan:
    plan_id = (plan_id or "").strip().lower()
    if plan_id not in PLANS:
        raise KeyError(f"invalid plan: {plan_id}")
    return PLANS[plan_id]


def recommend_purchase(
    additional_credits_needed: int,
    *,
    max_topups: int = 3,
) -> dict | None:
    """Recommend what to buy to cover `additional_credits_needed`.

    - Supports buying multiples of the same plan (quantity).
    - Preference: minimize total sats.
    - If there are options with `quantity <= max_topups`, choose among those (reduces friction).

    Returns a dict:
      {plan_id, quantity, sats_total, credits_total, credits_over_need, plan}
    """

    additional_credits_needed = int(additional_credits_needed)
    if additional_credits_needed <= 0:
        return None

    max_topups = max(1, min(int(max_topups), 50))

    options: list[dict] = []
    for plan in PLANS.values():
        if int(plan.credits) <= 0:
            continue
        q = int(ceil(additional_credits_needed / float(plan.credits)))
        sats_total = int(plan.price_sats) * q
        credits_total = int(plan.credits) * q
        options.append(
            {
                "plan_id": plan.id,
                "quantity": q,
                "sats_total": sats_total,
                "credits_total": credits_total,
                "credits_over_need": credits_total - additional_credits_needed,
                "plan": plan.to_dict(),
            }
        )

    if not options:
        return None

    candidates = [o for o in options if o["quantity"] <= max_topups]
    if not candidates:
        candidates = options

    # Menor costo; tie-break: menos topups; luego menos overshoot
    candidates.sort(key=lambda o: (o["sats_total"], o["quantity"], o["credits_over_need"]))

    return candidates[0]
