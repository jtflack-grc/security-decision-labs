"""
TEF estimation engine -- the orchestrator.

Takes an OrganizationProfile, runs all four vector engines, applies
cross-vector dampening, performs validation checks, and produces
a TEFResult with full audit trail.
"""

from __future__ import annotations

import dataclasses
import functools
import math
from dataclasses import dataclass, field
from datetime import date

from tef_estimator.base_rate import lef_derivation, scenario_floor, scenario_lef
from tef_estimator.config import TEFConfig, get_bundled_susceptibility_prior, get_config
from tef_estimator.credibility import CredibilityBlender
from tef_estimator.data.common import (
    PERTRange,
    DampeningConfig,
    RevenueBand,
)
from tef_estimator.data.scenarios.base import ScenarioDefinition
from tef_estimator.data.scenarios.ransomware import RansomwareScenario
from tef_estimator.distributions import LognormalParams
from tef_estimator.profile import OrganizationProfile
from tef_estimator.result import TEFResult
from tef_estimator.triangulation import extract_anchors, triangulate
from tef_estimator.vectors import (
    CredentialVector,
    ExploitationVector,
    PhishingVector,
    SupplyChainVector,
    VectorEstimate,
)


def _version() -> str:
    from tef_estimator import __version__
    return __version__


@functools.cache
def _bundled_editions() -> tuple[str, ...]:
    """Bundled data files don't change within a process: read them once."""
    from tef_estimator.refresh.validators import bundled_editions
    return tuple(bundled_editions())


class TEFEngine:
    """Main estimation engine.

    Usage::

        profile = OrganizationProfile(
            sector=Sector.MANUFACTURING,
            revenue_band=RevenueBand.R_100M_1B,
            geography=Geography.US,
            remote_access=[RemoteAccessType.FORTINET],
            employee_count=2000,
        )
        engine = TEFEngine()
        result = engine.estimate(profile)
        print(result.full_report())
    """

    def __init__(
        self,
        scenario: ScenarioDefinition | None = None,
        dampening: DampeningConfig | None = None,
        base_rate_override: PERTRange | None = None,
        config: TEFConfig | None = None,
    ):
        self.config = config or get_config()
        self.scenario = scenario or RansomwareScenario()

        if dampening is not None:
            self.dampening = dampening
        else:
            dp = self.config.dampening
            self.dampening = DampeningConfig(
                factor_k=dp.factor_k,
                vector_k=dp.vector_k,
                max_composite=dp.max_composite,
            )

        self.base_rate_override = base_rate_override

        # Initialize vector engines
        self.exploitation = ExploitationVector(self.dampening, config=self.config)
        self.credential = CredentialVector(self.dampening, config=self.config)
        self.phishing = PhishingVector(self.dampening)
        self.supply_chain = SupplyChainVector(self.dampening)

    def _frozen_provenance(self) -> str:
        """One line naming the bundled editions, e.g. for "how current is this"."""
        parts = list(_bundled_editions())
        dshield = ((self.config.exploitation_ceiling_derivation or {})
                   .get("dshield_snapshot") or {}).get("date")
        if dshield:
            parts.append(f"DShield {dshield}")
        return (f"Inputs: frozen, bundled reference data (tef-estimator {_version()}): "
                + ", ".join(parts))

    def _susceptibility(self) -> PERTRange | None:
        """The scenario's susceptibility prior, unless the user changed the configured one."""
        scenario_prior = self.scenario.base_rate_triangulation.get("susceptibility_prior")
        cfg_prior = self.config.susceptibility_prior
        bundled = get_bundled_susceptibility_prior()
        user_set = any(abs(getattr(cfg_prior, k) - bundled[k]) > 1e-9 for k in ("low", "mode", "high"))
        if user_set or scenario_prior is None:
            return PERTRange(cfg_prior.low, cfg_prior.mode, cfg_prior.high)
        return scenario_prior

    def _live_n_us(self) -> float | None:
        live = (self.config.live_base_rate or {}).get(self.scenario.scenario_slug) or {}
        return live.get("n_us")

    def base_rate_for(self, band: RevenueBand) -> PERTRange:
        """Base rate (TEF) for a revenue band: LEF ÷ susceptibility on the scenario's
        population, or its consensus TEF where it has no LEF recipe."""
        if self.base_rate_override is not None:
            return self.base_rate_override
        prior = self._susceptibility()
        lef = scenario_lef(self.scenario, band, self._live_n_us())
        if lef is not None:
            return PERTRange(lef.low / prior.high, lef.mode / prior.mode, lef.high / prior.low)
        # Consensus TEF was derived with the scenario's prior: rescale to the one in use
        consensus = self.scenario.base_rate_triangulation["consensus"]
        scenario_prior = self.scenario.base_rate_triangulation.get("susceptibility_prior") or prior
        return PERTRange(
            low=consensus.low * (scenario_prior.high / prior.high),
            mode=consensus.mode * (scenario_prior.mode / prior.mode),
            high=consensus.high * (scenario_prior.low / prior.low),
        )

    def base_rate_derivation(self, band: RevenueBand, base_rate: PERTRange) -> list[str]:
        if self.base_rate_override is not None or getattr(self.scenario, "base_rate_lef", None) is None:
            return [f"Base rate (TEF): {base_rate.low:.3g} / {base_rate.mode:.3g} / {base_rate.high:.3g} per year"]
        prior = self._susceptibility()
        return [
            lef_derivation(self.scenario, band, self._live_n_us()),
            f"÷ susceptibility {prior.high:g} / {prior.mode:g} / {prior.low:g} "
            f"= base rate (TEF) {base_rate.low:.3g} / {base_rate.mode:.3g} / {base_rate.high:.3g} per year",
        ]

    def estimate(self, profile: OrganizationProfile) -> TEFResult:
        """Run the full TEF estimation for a given organization profile."""

        # Allow analyst override of base rate
        base_rate = self.base_rate_for(profile.revenue_band)
        if profile.custom_base_rate is not None:
            br = profile.custom_base_rate
            base_rate = PERTRange(br * 0.5, br, br * 2.0)

        # --- Run the scenario's active vector engines ---
        vector_engines = {
            "exploitation": self.exploitation,
            "credential": self.credential,
            "phishing": self.phishing,
            "supply_chain": self.supply_chain,
        }
        active = set(self.scenario.active_vectors)
        vectors: list[VectorEstimate] = [
            engine.estimate(profile, base_rate, self.scenario)
            for name, engine in vector_engines.items()
            if name in active
        ]

        # --- Bühlmann credibility blending (if telemetry provided) ---
        credibility_warnings, hardening_checks = self._apply_credibility(vectors, profile)

        # --- Compute aggregate with cross-vector dampening ---
        raw_total_median = sum(v.positioned_median for v in vectors)
        raw_total_low = sum(v.positioned_low for v in vectors)
        raw_total_high = sum(v.positioned_high for v in vectors)

        # Cross-vector dampening
        vk = self.dampening.vector_k
        total_median = raw_total_median * vk
        total_low = raw_total_low * vk
        total_high = raw_total_high * vk

        # --- Floor enforcement ---
        adjusted_sector = self.scenario.adjusted_sector_multiplier(profile.sector)
        total_floor = scenario_floor(self.scenario, profile.revenue_band) * adjusted_sector

        total_low = max(total_low, total_floor)
        total_median = max(total_median, total_floor)
        total_high = max(total_high, total_floor)

        # --- Ceiling ---
        total_ceiling = sum(v.ceiling for v in vectors)

        # --- Lognormal parameters ---
        # Centred on the positioned total. The vectors share one base rate, so their
        # uncertainty is largely common; Fenton-Wilkinson (which assumes independent
        # vectors) would put the median 1.35-1.72x above the headline TEF.
        lognormal = LognormalParams.from_median_and_range(
            median=total_median,
            low=total_low,
            high=total_high,
        )

        # --- Triangulation validation (consensus scenarios only) ---
        tri_result = None
        if "consensus" in self.scenario.base_rate_triangulation:
            anchors, consensus = extract_anchors(self.scenario.base_rate_triangulation)
            tri_result = triangulate(anchors, consensus)

        # --- Validation checks ---
        checks = self._validate(
            profile, vectors, total_median, total_floor, tri_result,
        )
        checks.extend(hardening_checks)

        # --- Warnings ---
        warnings = self._generate_warnings(profile, vectors, total_median, total_floor, credibility_warnings)

        # --- Dispersion (burstiness over time); an added output, never changes the rate ---
        dispersion = {
            "total": self.config.dispersion_for("scenarios", self.scenario.scenario_slug),
            "vectors": {v.telemetry_key: self.config.dispersion_for("vectors", v.telemetry_key)
                        for v in vectors},
        }

        return TEFResult(
            profile_summary=profile.summary(),
            estimate_date=date.today(),
            scenario_name=self.scenario.scenario_name,
            vectors=vectors,
            total_floor=total_floor,
            total_positioned_low=total_low,
            total_positioned_median=total_median,
            total_positioned_high=total_high,
            total_ceiling=total_ceiling,
            lognormal=lognormal,
            base_rate=base_rate,
            base_rate_derivation=self.base_rate_derivation(profile.revenue_band, base_rate),
            dampening=self.dampening,
            validation_checks=checks,
            warnings=warnings,
            dispersion=dispersion,
            input_provenance=list(self.config.input_provenance) or [self._frozen_provenance()],
            sentence_template=self.scenario.output_templates.get("one_sentence", ""),
            attempt_verb=self.scenario.output_templates.get("attempt_verb", ""),
        )

    def compare(
        self, profile_a: OrganizationProfile, profile_b: OrganizationProfile
    ) -> CompareResult:
        """Compare TEF estimates for two profiles."""
        result_a = self.estimate(profile_a)
        result_b = self.estimate(profile_b)

        vector_deltas = {}
        for va, vb in zip(result_a.vectors, result_b.vectors):
            vector_deltas[va.vector_name] = vb.positioned_median - va.positioned_median

        total_delta = result_b.total_positioned_median - result_a.total_positioned_median

        # Generate explanation
        explanation_parts = []
        for name, delta in sorted(vector_deltas.items(), key=lambda x: abs(x[1]), reverse=True):
            if abs(delta) < 1e-8:
                continue
            direction = "increases" if delta > 0 else "decreases"
            explanation_parts.append(
                f"{name} vector {direction} by {abs(delta):.5f} per year"
            )

        if not explanation_parts:
            explanation = "No change between profiles."
        else:
            direction = "increases" if total_delta > 0 else "decreases"
            explanation = (
                f"Total TEF {direction} by {abs(total_delta):.5f} per year. "
                + " ".join(explanation_parts)
            )

        return CompareResult(
            result_a=result_a,
            result_b=result_b,
            vector_deltas=vector_deltas,
            total_delta=total_delta,
            explanation=explanation,
        )

    def sensitivity(self, profile: OrganizationProfile) -> SensitivityResult:
        """Rank input parameters by contribution to output variance.

        Varies each parameter across its PERT range while holding others at mode.
        """
        from dataclasses import replace

        baseline = self.estimate(profile)
        entries = []

        # Base rate -- the dominant source of uncertainty
        # When custom_base_rate is set, sweep its implied range instead of
        # the scenario default, and clear it on the profile so the engine's
        # base_rate_override takes effect.
        if profile.custom_base_rate is not None:
            cbr = profile.custom_base_rate
            br = PERTRange(cbr * 0.5, cbr, cbr * 2.0)
            sweep_profile = replace(profile, custom_base_rate=None)
        else:
            br = self.base_rate_for(profile.revenue_band)
            sweep_profile = profile

        low_engine = TEFEngine(
            scenario=self.scenario, dampening=self.dampening,
            base_rate_override=PERTRange(br.low, br.low, br.low), config=self.config,
        )
        high_engine = TEFEngine(
            scenario=self.scenario, dampening=self.dampening,
            base_rate_override=PERTRange(br.high, br.high, br.high), config=self.config,
        )
        low_r = low_engine.estimate(sweep_profile)
        high_r = high_engine.estimate(sweep_profile)
        entries.append(SensitivityEntry(
            parameter="base_rate",
            pert_range=br,
            output_low=low_r.total_positioned_median,
            output_high=high_r.total_positioned_median,
            range_multiple=high_r.total_positioned_median / max(low_r.total_positioned_median, 1e-10),
        ))

        # Dampening k variations
        for k_name, k_range in [
            ("factor_k", PERTRange(0.50, 0.70, 1.0)),
            ("vector_k", PERTRange(0.70, 0.85, 1.0)),
        ]:
            low_damp = dataclasses.replace(self.dampening, **{k_name: k_range.low})
            high_damp = dataclasses.replace(self.dampening, **{k_name: k_range.high})
            low_eng = TEFEngine(scenario=self.scenario, dampening=low_damp, base_rate_override=br, config=self.config)
            high_eng = TEFEngine(scenario=self.scenario, dampening=high_damp, base_rate_override=br, config=self.config)
            low_r = low_eng.estimate(sweep_profile)
            high_r = high_eng.estimate(sweep_profile)
            entries.append(SensitivityEntry(
                parameter=k_name,
                pert_range=k_range,
                output_low=low_r.total_positioned_median,
                output_high=high_r.total_positioned_median,
                range_multiple=high_r.total_positioned_median / max(low_r.total_positioned_median, 1e-10),
            ))

        # Per-vector credibility k sweep (only with telemetry)
        if profile.telemetry is not None:
            _ksens = self.config.k_sensitivity or {}
            k_ranges = {name: PERTRange(*vals) for name, vals in _ksens.items()}
            for vec_name, k_range in k_ranges.items():
                obs = profile.telemetry.get(vec_name)
                if obs is None:
                    continue
                from tef_estimator.config import TEFConfig
                low_cfg = TEFConfig.from_dict(self.config.to_dict())
                setattr(low_cfg.credibility_k, vec_name, k_range.low)
                high_cfg = TEFConfig.from_dict(self.config.to_dict())
                setattr(high_cfg.credibility_k, vec_name, k_range.high)
                low_eng = TEFEngine(scenario=self.scenario, dampening=self.dampening,
                                    base_rate_override=br, config=low_cfg)
                high_eng = TEFEngine(scenario=self.scenario, dampening=self.dampening,
                                     base_rate_override=br, config=high_cfg)
                low_r = low_eng.estimate(sweep_profile)
                high_r = high_eng.estimate(sweep_profile)
                entries.append(SensitivityEntry(
                    parameter=f"credibility_k_{vec_name}",
                    pert_range=k_range,
                    output_low=low_r.total_positioned_median,
                    output_high=high_r.total_positioned_median,
                    # Higher k lowers the output, so rank by spread (max/min), not by high/low.
                    range_multiple=max(low_r.total_positioned_median, high_r.total_positioned_median)
                    / max(min(low_r.total_positioned_median, high_r.total_positioned_median), 1e-10),
                ))

        entries.sort(key=lambda x: x.range_multiple, reverse=True)

        caveats: list[str] = []
        if profile.telemetry is not None and not any(
            e.parameter.startswith("credibility_k_") for e in entries
        ):
            caveats.append(
                "Sensitivity analysis varies population-model parameters only. "
                "With telemetry present, credibility parameters (k, detection "
                "coverage) are additional sources of uncertainty not shown here. "
                "A future version may include these."
            )

        return SensitivityResult(
            baseline_median=baseline.total_positioned_median,
            entries=entries,
            caveats=caveats,
        )

    def _validate(
        self,
        profile: OrganizationProfile,
        vectors: list[VectorEstimate],
        total_median: float,
        total_floor: float,
        tri_result=None,
    ) -> list[str]:
        """Internal consistency checks."""
        checks = []

        if tri_result is not None:
            checks.extend(tri_result.validation)
            checks.append("")

        if total_median >= total_floor:
            checks.append(f"Floor <= Positioned: {total_floor:.5f} <= {total_median:.5f}")
        else:
            checks.append(f"FAIL: Positioned ({total_median:.5f}) < Floor ({total_floor:.5f})")

        # Per vector: the ceiling is a sanity check, a logical maximum; a median
        # above it means the positioning and the ceiling disagree (never capped)
        for v in vectors:
            if v.positioned_median <= v.ceiling:
                checks.append(f"{v.vector_name} median <= ceiling: "
                              f"{v.positioned_median:.5f} <= {v.ceiling:.5g}")
            else:
                checks.append(f"ABOVE CEILING: {v.vector_name} median {v.positioned_median:.5f} "
                              f"> ceiling {v.ceiling:.5g}")

        observed_lef = scenario_floor(self.scenario, profile.revenue_band)
        for susc in [0.05, 0.15, 0.30]:
            implied_lef = total_median * susc
            ratio = f"{implied_lef / observed_lef:.1f}x observed floor" if observed_lef > 0 else "no observed floor"
            checks.append(
                f"At susceptibility {susc:.0%}: implied LEF = {implied_lef:.5f} ({ratio})"
            )

        # Shares of the summed vectors (before cross-vector dampening), so they add to 100%
        raw_total = sum(v.positioned_median for v in vectors)
        if raw_total > 0:
            for v in vectors:
                pct = (v.positioned_median / raw_total) * 100
                checks.append(f"{v.vector_name} vector: {pct:.0f}% of total TEF")

        return checks

    def _generate_warnings(
        self,
        profile: OrganizationProfile,
        vectors: list[VectorEstimate],
        total_median: float,
        total_floor: float,
        credibility_warnings: list[str] | None = None,
    ) -> list[str]:
        """Generate contextual warnings."""
        warnings = list(credibility_warnings or [])

        if abs(total_median - total_floor) / max(total_floor, 1e-10) < 0.1:
            warnings.append(
                "Floor is binding: the observed LEF is more informative than "
                "the base-rate-plus-adjustments approach for this profile. The "
                "positioned estimate adds limited value beyond the empirical floor."
            )

        if profile.revenue_band.value in ("under_10m", "10m_100m"):
            warnings.append(
                "IRIS counts only publicly reported events, which under-counts small and "
                "mid-market firms: the observed floor is especially conservative for this cohort."
            )

        if profile.geography not in (profile.geography.US,):
            warnings.append(
                "IRIS data has a US disclosure bias. Floor is more conservative for "
                "non-US firms due to lower mandatory disclosure rates."
            )

        if profile.sector.value == "transportation":
            warnings.append(
                "Transportation shows an anomaly: low all-incident rate (0.78x) but "
                "84% ransomware loss share. This is a severity signal, not a frequency "
                "signal -- the vector decomposition may understate total risk for this sector."
            )

        warnings.append(
            f"Dampening coefficient k={self.dampening.factor_k:.2f}: "
            f"{self.dampening.factor_k_source}"
        )

        return warnings

    def _apply_credibility(
        self,
        vectors: list[VectorEstimate],
        profile: OrganizationProfile,
    ) -> tuple[list[str], list[str]]:
        """Apply Bühlmann credibility blending and Gamma-inspired band contraction.

        Returns (warnings, validation checks); a binding band-hardening limit
        produces both a warning and a validation-check entry.
        """
        warnings: list[str] = []
        checks: list[str] = []
        if profile.telemetry is None:
            return warnings, checks

        # Use this engine's k values (not the global config) so per-vector k sweeps take effect.
        blender = CredibilityBlender(vector_k=dataclasses.asdict(self.config.credibility_k))
        for v in vectors:
            obs = profile.telemetry.get(v.telemetry_key)
            if obs is None:
                continue

            blend = blender.blend(v.positioned_median, obs)
            v.prior_median = blend.prior
            v.observed_frequency = blend.adjusted_observed
            v.credibility_z = blend.credibility_z

            # Gamma-inspired posterior band contraction
            log_range = (math.log(max(v.positioned_high, 1e-10))
                         - math.log(max(v.positioned_low, 1e-10)))
            sigma_prior = log_range / (2 * 1.645)

            bh = self.config.band_hardening
            if sigma_prior > 0:
                cv_sq = math.exp(sigma_prior ** 2) - 1
                alpha_pert = 1.0 / cv_sq if cv_sq > 0 else 1e6
                # Pseudo-events = events actually detected (annualized_frequency is the raw detected
                # rate), so coverage acts on the width only through the count. The cap limits the
                # quarters counted; applying it to periods x coverage let lower coverage narrow the band more.
                periods = min(obs.observation_periods, bh.coverage_leverage_cap)
                if obs.observation_periods > bh.coverage_leverage_cap:
                    msg = (f"{v.vector_name}: coverage-leverage cap bound "
                           f"(observation periods {obs.observation_periods:g} → {bh.coverage_leverage_cap:g})")
                    warnings.append(msg)
                    checks.append(f"Band hardening: {msg}")
                n_events = obs.annualized_frequency * periods / 4.0
                alpha_post = alpha_pert + n_events

                if n_events > 10 * alpha_pert:
                    warnings.append(
                        f"Credibility warning for {v.vector_name}: "
                        f"pseudo-event count N={n_events:.1f} exceeds "
                        f"10× the prior shape α={alpha_pert:.2f}. "
                        f"The observed rate dominates the prior — "
                        f"band contraction may be overconfident."
                    )

                sigma_post = math.sqrt(math.log(1 + 1.0 / alpha_post))
                sigma_floor = bh.min_sigma_ratio * sigma_prior
                if sigma_post < sigma_floor:
                    msg = (f"{v.vector_name}: band floor bound "
                           f"(σ {sigma_post:.3f} → {sigma_floor:.3f}, "
                           f"{bh.min_sigma_ratio:.0%} of prior)")
                    warnings.append(msg)
                    checks.append(f"Band hardening: {msg}")
                sigma_post = max(sigma_post, sigma_floor)
            else:
                sigma_post = 0.0

            if blend.adjusted_observed > 50 * blend.prior:
                warnings.append(
                    f"Detection coverage warning for {v.vector_name}: "
                    f"adjusted observed rate ({blend.adjusted_observed:.1f}) is "
                    f"{blend.adjusted_observed / blend.prior:.0f}× the population "
                    f"prior ({blend.prior:.4f}). Driven by low detection coverage "
                    f"({obs.detection_coverage:.0%}). Small errors in detection "
                    f"coverage have large effects on the estimate."
                )

            mu_post = math.log(max(blend.blended, 1e-10))
            v.positioned_median = blend.blended
            v.positioned_low = math.exp(mu_post - 1.645 * sigma_post)
            v.positioned_high = math.exp(mu_post + 1.645 * sigma_post)
            v.enforce_bounds()

            if v.trace is not None:
                v.trace.add_step(
                    "Credibility blend", blend.blended, "Z=",
                    f"Z={blend.credibility_z:.3f}, obs={blend.adjusted_observed:.4f}",
                    blend.blended,
                )
                if sigma_prior > 0:
                    contraction = 1 - sigma_post / sigma_prior
                    v.trace.add_step(
                        "Band contraction", sigma_post, "σ→",
                        f"α_pert={alpha_pert:.2f}, N={n_events:.2f}, {contraction:.0%} narrower",
                        v.positioned_median,
                    )

        covered = [v.vector_name for v in vectors
                   if profile.telemetry.get(v.telemetry_key) is not None]
        if 0 < len(covered) < len(vectors):
            uncovered = [v.vector_name for v in vectors if v.vector_name not in covered]
            warnings.append(
                f"Partial telemetry: {len(covered)} of {len(vectors)} vectors have "
                f"observations ({', '.join(covered)}). Vectors without telemetry "
                f"({', '.join(uncovered)}) remain at population-model levels. "
                f"Vector share proportions reflect this asymmetry."
            )

        return warnings, checks


# ---------------------------------------------------------------------------
# Compare and Sensitivity result types
# ---------------------------------------------------------------------------

@dataclass
class CompareResult:
    """Result of comparing two organization profiles."""
    result_a: TEFResult
    result_b: TEFResult
    vector_deltas: dict[str, float]
    total_delta: float
    explanation: str

    def render_text(self) -> str:
        lines = [
            "PROFILE COMPARISON",
            "=" * 60,
            f"Profile A: {self.result_a.profile_summary}",
            f"Profile B: {self.result_b.profile_summary}",
            "",
            "VECTOR DELTAS:",
        ]
        for name, delta in self.vector_deltas.items():
            sign = "+" if delta >= 0 else ""
            lines.append(f"  {name:<15} {sign}{delta:.5f} per year")

        sign = "+" if self.total_delta >= 0 else ""
        lines.extend([
            "",
            f"  {'TOTAL':<15} {sign}{self.total_delta:.5f} per year",
            "",
            f"Explanation: {self.explanation}",
        ])
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "profile_a": self.result_a.profile_summary,
            "profile_b": self.result_b.profile_summary,
            "vector_deltas": self.vector_deltas,
            "total_delta": self.total_delta,
            "explanation": self.explanation,
            "result_a": self.result_a.to_dict(),
            "result_b": self.result_b.to_dict(),
        }


@dataclass
class SensitivityEntry:
    """One parameter's contribution to output variance."""
    parameter: str
    pert_range: PERTRange
    output_low: float
    output_high: float
    range_multiple: float


@dataclass
class SensitivityResult:
    """Ranked parameter contributions to output variance."""
    baseline_median: float
    entries: list[SensitivityEntry]
    caveats: list[str] = field(default_factory=list)

    @property
    def ranked(self) -> list[tuple[str, PERTRange, float]]:
        return [(e.parameter, e.pert_range, e.range_multiple) for e in self.entries]

    @property
    def tornado_data(self) -> list[dict]:
        """Data ready for a tornado chart."""
        return [
            {
                "parameter": e.parameter,
                "low": e.output_low,
                "high": e.output_high,
                "baseline": self.baseline_median,
                "range_multiple": e.range_multiple,
            }
            for e in self.entries
        ]

    def render_text(self) -> str:
        lines = [
            "SENSITIVITY ANALYSIS",
            "=" * 60,
            f"Baseline TEF: {self.baseline_median:.5f} per year",
            "",
            f"{'Parameter':<25} {'Low':<12} {'High':<12} {'Range':>8}",
            "-" * 60,
        ]
        for e in self.entries:
            lines.append(
                f"{e.parameter:<25} {e.output_low:.5f}    {e.output_high:.5f}    "
                f"{e.range_multiple:.1f}x"
            )
        if self.caveats:
            lines.append("")
            for caveat in self.caveats:
                lines.append(f"Note: {caveat}")
        return "\n".join(lines)
