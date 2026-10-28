from __future__ import annotations

from tef_estimator.data.common import (
    PERTRange,
    RevenueBand,
    Sector,
    SECTOR_DATA,
)
from tef_estimator.base_rate import resolve_lef_spec
from tef_estimator.data.loader import load_scenario, normalized_proportions, pert_from_list


def _load_web_app_data() -> dict:
    scenario = load_scenario("web_app")

    vector_proportions = {
        k: PERTRange(*t) for k, t in normalized_proportions(scenario["vector_proportions"]).items()
    }

    base_rate = {
        k: PERTRange(*pert_from_list(v))
        for k, v in scenario["base_rate_triangulation"].items()
        if not k.startswith("_") and isinstance(v, list)
    }

    overall_share = scenario["web_app_overall_share"]["value"]

    sector_shares: dict[Sector, float | None] = {}
    for sector_key, val in scenario["web_app_sector_shares"].items():
        if sector_key.startswith("_"):
            continue
        sector_shares[Sector(sector_key)] = val

    revenue_shares: dict[RevenueBand, float] = {}
    for band_key, val in scenario["web_app_revenue_shares"].items():
        if band_key.startswith("_"):
            continue
        revenue_shares[RevenueBand(band_key)] = val

    revenue_prob_gte2: dict[RevenueBand, float | None] = {}
    for band_key, val in scenario["web_app_revenue_prob_gte2"].items():
        if band_key.startswith("_"):
            continue
        revenue_prob_gte2[RevenueBand(band_key)] = val

    cred_tempo_raw = scenario["credential_tempo"]
    credential_tempo = {
        k: PERTRange(*pert_from_list(v))
        for k, v in cred_tempo_raw.items()
        if not k.startswith("_") and isinstance(v, list)
    }

    expl_raw = scenario["exploitation_scanning"]
    exploitation_scanning: dict[str, PERTRange | float] = {}
    for k, v in expl_raw.items():
        if k.startswith("_"):
            continue
        if isinstance(v, list):
            exploitation_scanning[k] = PERTRange(*pert_from_list(v))
        elif v is not None:
            exploitation_scanning[k] = v

    output_templates = scenario["output_templates"]

    return {
        "vector_proportions": vector_proportions,
        "base_rate_triangulation": base_rate,
        "overall_share": overall_share,
        "sector_shares": sector_shares,
        "revenue_shares": revenue_shares,
        "revenue_prob_gte2": revenue_prob_gte2,
        "credential_tempo": credential_tempo,
        "exploitation_scanning": exploitation_scanning,
        "output_templates": output_templates,
        "base_rate_lef": resolve_lef_spec(scenario["base_rate_lef"]),
    }


_DATA = _load_web_app_data()


class WebAppScenario:

    @property
    def scenario_name(self) -> str:
        return "Web Application Exploitation"

    @property
    def scenario_slug(self) -> str:
        return "web_app"

    @property
    def active_vectors(self) -> list[str]:
        return ["exploitation", "credential", "phishing", "supply_chain"]

    @property
    def vector_proportions(self) -> dict[str, PERTRange]:
        return _DATA["vector_proportions"]

    @property
    def base_rate_triangulation(self) -> dict[str, PERTRange]:
        return _DATA["base_rate_triangulation"]

    @property
    def overall_share(self) -> float:
        return _DATA["overall_share"]

    @property
    def sector_shares(self) -> dict[Sector, float | None]:
        return _DATA["sector_shares"]

    @property
    def sector_loss_shares(self) -> dict[Sector, float | None]:
        return _DATA["sector_shares"]

    @property
    def revenue_shares(self) -> dict[RevenueBand, float]:
        return _DATA["revenue_shares"]

    @property
    def revenue_prob_gte2(self) -> dict[RevenueBand, float | None]:
        return _DATA["revenue_prob_gte2"]

    @property
    def credential_tempo(self) -> dict[str, PERTRange]:
        return _DATA["credential_tempo"]

    @property
    def base_rate_lef(self) -> dict:
        """US events, under-reporting and firms per revenue tier (base_rate.py)."""
        return _DATA["base_rate_lef"]

    @property
    def exploitation_scanning(self) -> dict[str, PERTRange | float]:
        return _DATA["exploitation_scanning"]

    @property
    def output_templates(self) -> dict[str, str]:
        return _DATA["output_templates"]

    def adjusted_sector_multiplier(self, sector: Sector) -> float:
        common_mult = SECTOR_DATA[sector].all_incident_multiplier
        share = self.sector_shares.get(sector)
        if share is not None:
            return common_mult * (share / self.overall_share)
        return common_mult

    def adjusted_sector_multiplier_range(self, sector: Sector) -> PERTRange:
        m = self.adjusted_sector_multiplier(sector)
        return PERTRange(low=max(0.1, m * 0.7), mode=m, high=m * 1.3)

    def adjusted_revenue_multiplier(self, band: RevenueBand) -> float:
        # The base rate is set per revenue tier (base_rate_lef), so revenue is
        # already in it; a multiplier on top would count it twice.
        return 1.0

    def adjusted_revenue_multiplier_range(self, band: RevenueBand) -> PERTRange:
        return PERTRange(1.0, 1.0, 1.0)
