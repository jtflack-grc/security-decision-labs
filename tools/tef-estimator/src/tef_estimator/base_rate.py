"""Base rates and floors, each on one population per scenario.

A scenario with a ``base_rate_lef`` block takes its base rate from loss events
per organization-year (LEF) on that population, divided by susceptibility:
US events per year (``n_us`` × under-reporting) × the tier's share of victims
÷ US firms in the tier. A block with ``share_of`` takes another scenario's
recipe and multiplies it by ``share`` (resolved by ``resolve_lef_spec``).
A scenario with a ``floor_lef`` block takes its floor
from it; otherwise the floor is IRIS's all-incident lower bound × the
scenario's share of incidents. One role per source: what sets the base rate
never sets the floor.
"""

from __future__ import annotations

from tef_estimator.data.common import GEO_MULTIPLIERS, REVENUE_BAND_DATA, Geography, PERTRange, RevenueBand
from tef_estimator.data.loader import load_reference, load_scenario

_IRIS_ALL_INCIDENT_FLOOR = load_reference("iris")["all_incident_lower_bound_2022"]


def resolve_lef_spec(spec: dict) -> dict:
    """A ``share_of`` block becomes the parent's recipe plus its own ``share``."""
    if "share_of" not in spec:
        return spec
    parent = load_scenario(spec["share_of"])["base_rate_lef"]
    return {**parent, **spec}


def _tier(spec: dict, band: RevenueBand) -> tuple[str, dict]:
    for name, tier in spec["tiers"].items():
        if band.value in tier["bands"]:
            return name, tier
    raise ValueError(f"no base-rate tier covers revenue band {band.value}")


def _band_gradient(tier: dict, band: RevenueBand) -> float:
    """IRIS all-incident revenue multiplier of the band relative to the tier's measured
    band (``revenue_gradient_from``); 1.0 for a flat tier."""
    ref = tier.get("revenue_gradient_from")
    if not ref:
        return 1.0
    return (REVENUE_BAND_DATA[band].all_incident_multiplier
            / REVENUE_BAND_DATA[RevenueBand(ref)].all_incident_multiplier)


def scenario_lef(scenario, band: RevenueBand, n_us: float | None = None) -> PERTRange | None:
    """LEF per organization-year for the band, or None for a consensus-TEF scenario.

    ``n_us`` replaces the bundled event count (live mode).
    """
    spec = getattr(scenario, "base_rate_lef", None)
    if not spec:
        return None
    _, tier = _tier(spec, band)
    events = (n_us if n_us is not None else spec["n_us"]) * tier["victim_share"] * _band_gradient(tier, band)
    share = spec.get("share", [1.0, 1.0, 1.0])
    return PERTRange(*(events * u * s / tier["us_firms"] for u, s in zip(spec["underreporting"], share)))


def lef_derivation(scenario, band: RevenueBand, n_us: float | None = None) -> str:
    spec = scenario.base_rate_lef
    name, tier = _tier(spec, band)
    n = n_us if n_us is not None else spec["n_us"]
    u = spec["underreporting"]
    lef = scenario_lef(scenario, band, n_us)
    share = (f"× share of {spec['share_of']} {spec['share'][0]:g} / {spec['share'][1]:g} / {spec['share'][2]:g} "
             if "share" in spec else "")
    g = _band_gradient(tier, band)
    gradient = (f"× IRIS revenue gradient {g:.2f} (vs {tier['revenue_gradient_from']}) "
                if g != 1.0 else "")
    return (f"LEF ({name}): {n:,.0f} US events/yr × under-reporting {u[0]:g} / {u[1]:g} / {u[2]:g} "
            f"{share}× victim share {tier['victim_share']:.3f} {gradient}÷ {tier['us_firms']:,} US firms "
            f"= {lef.low:.3g} / {lef.mode:.3g} / {lef.high:.3g} loss events per year")


def scenario_floor(scenario, band: RevenueBand) -> float:
    """Observed LEF lower bound for the band (0 where no source covers it)."""
    floors = getattr(scenario, "floor_lef", None)
    if floors:
        return floors.get("all", floors.get(band.value, 0.0))
    return _IRIS_ALL_INCIDENT_FLOOR[band.value] * scenario.overall_share


def geo_multiplier(scenario, geography: Geography) -> PERTRange:
    """Geography multiplier, relative to the base rate's own population.

    A base rate counted on one country already carries that country's level,
    so that country is 1.0 and the others scale by their ratio to it.
    """
    spec = getattr(scenario, "base_rate_lef", None)
    home = spec.get("geography") if spec else None
    if not home:
        return GEO_MULTIPLIERS[geography]
    if geography.value == home:
        return PERTRange(1.0, 1.0, 1.0)
    ref = GEO_MULTIPLIERS[Geography(home)].mode
    return PERTRange(*(x / ref for x in GEO_MULTIPLIERS[geography]))


def tier_concentration(scenario, band: RevenueBand) -> float:
    """How much more often the band's firms are hit than the average firm.

    The tier's share of victims ÷ its share of firms (1.0 without tiers). It puts
    population-average figures, such as the credential ceiling, on the tier.
    """
    spec = getattr(scenario, "base_rate_lef", None)
    if not spec:
        return 1.0
    _, tier = _tier(spec, band)
    all_firms = sum(t["us_firms"] for t in spec["tiers"].values())
    return tier["victim_share"] * _band_gradient(tier, band) / (tier["us_firms"] / all_firms)
