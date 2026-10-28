"""
TEF estimation result -- the output of the engine.

Three-tier output structure:
  Tier 1 (summary): The slide -- positioned estimate, recurrence interval,
         vector bar, one sentence, peer percentile.
  Tier 2 (analysis): The analyst's workspace -- distributions, sensitivity,
         per-vector ranges.
  Tier 3 (audit): The challenge layer -- traces, validation, warnings,
         sources, base rate derivation.
"""

from __future__ import annotations

import math

from dataclasses import dataclass, field
from datetime import date

from tef_estimator.data.common import PERTRange, DampeningConfig
import numpy as np

from tef_estimator.distributions import DispersionParams, LognormalParams, sample_annual_counts
from tef_estimator.vectors.base import VectorEstimate


def recurrence_text(rate: float) -> str:
    """A rate in events per year, as plain words."""
    if rate <= 0:
        return "never"
    if rate >= 1:
        return f"about {rate:.1f} times a year"
    years = 1.0 / rate
    if years < 1.05:
        return "about once a year"
    return f"about once every {years:.1f} years" if years < 10 else f"about once every {years:.0f} years"


def ordinal(n: int) -> str:
    """71 -> '71st', 12 -> '12th'."""
    suffix = "th" if 10 <= n % 100 <= 20 else {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
    return f"{n}{suffix}"


@dataclass
class SummaryTier:
    """Tier 1 -- the slide."""
    positioned_median: float
    positioned_low: float
    positioned_high: float
    tef_text: str
    chance_at_least_one: float
    recurrence_years: float
    one_sentence: str
    peer_percentile: int | None
    peer_context: str | None
    vector_bar: list[dict[str, float | str]]


@dataclass
class AnalysisTier:
    """Tier 2 -- the analyst's workspace."""
    lognormal: LognormalParams
    pert: PERTRange
    vectors: list[VectorEstimate]


@dataclass
class AuditTier:
    """Tier 3 -- the challenge layer."""
    traces: list[dict]
    validation_checks: list[str]
    warnings: list[str]
    data_sources: list[str]
    base_rate: PERTRange
    dampening: DampeningConfig
    scenario_name: str


@dataclass
class TEFResult:
    """Complete TEF estimation output."""

    # --- Profile summary ---
    profile_summary: str
    estimate_date: date
    scenario_name: str

    # --- Vector decomposition ---
    vectors: list[VectorEstimate]

    # --- Aggregate positioned estimate ---
    total_floor: float
    total_positioned_low: float
    total_positioned_median: float
    total_positioned_high: float
    total_ceiling: float

    # --- Distribution parameters ---
    lognormal: LognormalParams

    # --- Base rate used, and how it was derived (one line per step) ---
    base_rate: PERTRange

    # --- Dampening config ---
    dampening: DampeningConfig

    # --- Audit trail ---
    validation_checks: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    # --- Peer percentile (set by peer.py after estimation) ---
    peer_percentile: int | None = None
    peer_context: str | None = None

    # --- Dispersion (burstiness over time), keyed "total" and "vectors" -> {key: params} ---
    dispersion: dict = field(default_factory=dict)

    # --- Where the inputs came from: frozen (bundled) or live (data date per input) ---
    input_provenance: list[str] = field(default_factory=list)

    base_rate_derivation: list[str] = field(default_factory=list)

    # --- The scenario's wording for the plain-language summary (output_templates) ---
    sentence_template: str = ""
    attempt_verb: str = ""

    @property
    def total_positioned_range(self) -> PERTRange:
        return PERTRange(self.total_positioned_low, self.total_positioned_median, self.total_positioned_high)

    @property
    def raw_vector_total(self) -> float:
        return sum(v.positioned_median for v in self.vectors)

    @property
    def tef_text(self) -> str:
        """TEF is a frequency: threat events per year, not a probability."""
        return f"{self.total_positioned_median:.2g} per year ({recurrence_text(self.total_positioned_median)})"

    @property
    def chance_at_least_one(self) -> float:
        """Probability of at least one threat event in a year (Poisson at the median rate)."""
        return 1.0 - math.exp(-self.total_positioned_median)

    @property
    def median_recurrence_years(self) -> float:
        if self.total_positioned_median > 0:
            return 1.0 / self.total_positioned_median
        return float("inf")

    @property
    def mean_recurrence_years(self) -> float:
        return self.median_recurrence_years

    # --- Three-tier access ---

    @property
    def summary(self) -> SummaryTier:
        total_median = self.total_positioned_median
        raw_total = self.raw_vector_total
        vector_bar = []
        if raw_total > 0:
            for v in self.vectors:
                vector_bar.append({
                    "vector": v.vector_name,
                    "share": v.positioned_median / raw_total,
                })

        return SummaryTier(
            positioned_median=total_median,
            positioned_low=self.total_positioned_low,
            positioned_high=self.total_positioned_high,
            tef_text=self.tef_text,
            chance_at_least_one=self.chance_at_least_one,
            recurrence_years=self.median_recurrence_years,
            one_sentence=self.plain_language_summary(),
            peer_percentile=self.peer_percentile,
            peer_context=self.peer_context,
            vector_bar=vector_bar,
        )

    @property
    def analysis(self) -> AnalysisTier:
        return AnalysisTier(
            lognormal=self.lognormal,
            pert=self.total_positioned_range,
            vectors=self.vectors,
        )

    @property
    def audit(self) -> AuditTier:
        all_sources = set()
        traces = []
        for v in self.vectors:
            all_sources.update(v.data_sources)
            if v.trace is not None:
                traces.append(v.trace.to_dict() if hasattr(v.trace, 'to_dict') else {})

        return AuditTier(
            traces=traces,
            validation_checks=self.validation_checks,
            warnings=self.warnings,
            data_sources=sorted(all_sources),
            base_rate=self.base_rate,
            dampening=self.dampening,
            scenario_name=self.scenario_name,
        )

    def plain_language_summary(self) -> str:
        """Board-ready plain language interpretation."""
        top_vector = ""
        raw_total = self.raw_vector_total
        if self.vectors and raw_total > 0:
            dominant = max(self.vectors, key=lambda v: v.positioned_median)
            share_pct = (dominant.positioned_median / raw_total) * 100
            driver = dominant.primary_drivers[0] if dominant.primary_drivers else dominant.vector_name
            top_vector = (
                f" The primary attack pathway is {dominant.vector_name.lower()}-based access "
                f"({share_pct:.0f}% of estimated frequency), driven by {driver.lower()}."
            )

        text = (
            f"{self._opening_sentence()}{top_vector} "
            f"This measures how often adversaries TRY -- not how often they succeed. "
            f"Success probability depends on your controls (assessed separately)."
        )
        if self.peer_percentile is not None:
            text += (
                f" This estimate is at the {ordinal(self.peer_percentile)} percentile "
                f"across all {self.peer_context or 'comparable'} organizations."
            )
        return text

    def _opening_sentence(self) -> str:
        """The scenario's own sentence (output_templates.one_sentence), else a generic one."""
        values = dict(
            attempt_verb=self.attempt_verb or "attempt to attack",
            recurrence=recurrence_text(self.total_positioned_median),
            low=recurrence_text(self.total_positioned_low),
            high=recurrence_text(self.total_positioned_high),
        )
        generic = ("Based on industry data, threat actors {attempt_verb} organizations "
                   "matching your profile {recurrence} (range: {low} to {high}).")
        try:
            sentence = (self.sentence_template or generic).format(**values)
        except (KeyError, IndexError, ValueError):  # a custom file with other placeholders
            sentence = generic.format(**values)
        return sentence.split(" This measures")[0]

    def vector_breakdown_text(self) -> str:
        """Formatted vector breakdown for console output."""
        lines = ["VECTOR BREAKDOWN:"]
        max_name_len = max(len(v.vector_name) for v in self.vectors)
        for v in self.vectors:
            lines.append(
                f"  {v.vector_name:<{max_name_len + 2}}"
                f"{v.positioned_low:.5f} - {v.positioned_high:.5f} events/year"
            )
            for driver in v.primary_drivers:
                lines.append(f"    -> {driver}")
        lines.append("")
        lines.append(
            f"  {'TOTAL':<{max_name_len + 2}}"
            f"{self.total_positioned_low:.5f} - {self.total_positioned_high:.5f} events/year"
        )
        lines.append(
            "  (cross-vector dampening applied -- vectors are not fully independent)"
        )
        return "\n".join(lines)

    def distribution_text(self) -> str:
        """Distribution parameters for Monte Carlo consumers."""
        ln = self.lognormal
        return (
            f"DISTRIBUTION PARAMETERS (for Monte Carlo):\n"
            f"  Recommended distribution: Lognormal\n"
            f"  mu (ln-space): {ln.mu:.3f}\n"
            f"  sigma (ln-space): {ln.sigma:.3f}\n"
            f"  5th percentile:  {ln.p5:.5f} events/year\n"
            f"  Median:          {ln.median:.5f} events/year\n"
            f"  95th percentile: {ln.p95:.5f} events/year\n"
            f"\n"
            f"  Alternative: PERT(min={self.total_positioned_low:.5f}, "
            f"mode={self.total_positioned_median:.5f}, "
            f"max={self.total_positioned_high:.5f})\n"
            f"\n"
            f"{self.fair_risk_engine_text()}"
        )

    def fair_risk_engine_inputs(self, basis: str = "detrended") -> dict:
        """TEF inputs for fair-risk-engine (FAIRInputs fields): this lognormal rate and the total dispersion.

        fair-risk-engine takes P10/P50/P90; they are read off this lognormal (the
        positioned low/high are about P5/P95). tef_dispersion is the total annual
        shape, None for Poisson. basis="raw" gives the trend-included shape, the
        sensitivity bound.
        """
        ln = self.lognormal
        d = self.total_dispersion
        if d is not None and basis == "raw":
            d = d.as_raw()
        return {
            "tef_model": "lognormal",
            "tef_p10": ln.p10,
            "tef_p50": ln.median,
            "tef_p90": ln.p90,
            "tef_dispersion": None if d is None else d.annual_shape,
        }

    def fair_risk_engine_text(self) -> str:
        inputs = self.fair_risk_engine_inputs()
        raw = self.fair_risk_engine_inputs(basis="raw")["tef_dispersion"]
        line = (f"  For fair-risk-engine: tef_model='lognormal', tef_p10={inputs['tef_p10']:.5g}, "
                f"tef_p50={inputs['tef_p50']:.5g}, tef_p90={inputs['tef_p90']:.5g}, "
                f"tef_dispersion={'None' if inputs['tef_dispersion'] is None else format(inputs['tef_dispersion'], 'g')}")
        if raw is not None and raw != inputs["tef_dispersion"]:
            line += f"\n  (trend-included sensitivity bound: tef_dispersion={raw:g})"
        if self.input_provenance:
            line += f"\n  ({self.input_provenance[0]})"
        return line

    @property
    def total_dispersion(self) -> DispersionParams | None:
        return self.dispersion.get("total") if self.dispersion else None

    @property
    def has_dispersion(self) -> bool:
        if not self.dispersion:
            return False
        entries = [self.dispersion.get("total"), *self.dispersion.get("vectors", {}).values()]
        return any(d is not None and not d.is_poisson for d in entries)

    def dispersion_text(self) -> str:
        """Burstiness of the rate over time, for Monte Carlo consumers."""
        lines = ["DISPERSION (rate burstiness over time; negative binomial counts):"]
        rows = [("Total", self.total_dispersion, self.total_positioned_median)]
        rows += [(v.vector_name, self.dispersion.get("vectors", {}).get(v.telemetry_key), v.positioned_median)
                 for v in self.vectors]
        for name, d, rate in rows:
            if d is None or d.is_poisson:
                lines.append(f"  {name}: Poisson (no public series to fit)")
            else:
                lines.append(
                    f"  {name}: monthly shape r={d.shape_r:g} ({d.basis}), shock lasts a {d.timescale} "
                    f"-> annual shape {d.annual_shape:g}; VMR at your rate = 1 + λ/(annual shape) = {d.vmr(rate):.4f}"
                )
        lines.append("  Effect on the annual loss tail is small at a few events a year; it grows with frequency.")
        return "\n".join(lines)

    def sample_annual_counts(self, size: int = 10_000, rng: np.random.Generator | None = None) -> np.ndarray:
        """Annual event counts: rate drawn from the TEF lognormal, then the dispersion shock, then Poisson."""
        if rng is None:
            rng = np.random.default_rng()
        rates = self.lognormal.sample(size=size, rng=rng)
        return sample_annual_counts(rates, self.total_dispersion, rng)

    @property
    def has_credibility_data(self) -> bool:
        return any(v.credibility_z is not None for v in self.vectors)

    def credibility_text(self) -> str:
        """Bühlmann credibility blending summary."""
        if not self.has_credibility_data:
            return ""

        blended_vectors = [v for v in self.vectors if v.credibility_z is not None]

        lines = ["CREDIBILITY ADJUSTMENT (org telemetry):"]
        max_name = max(len(v.vector_name) for v in blended_vectors)
        for v in blended_vectors:
            lines.append(
                f"  {v.vector_name:<{max_name + 2}}"
                f"Z={v.credibility_z:.2f}   "
                f"prior: {v.prior_median:.3g}/yr  "
                f"observed: {v.observed_frequency:.3g}/yr  "
                f"-> blended: {v.positioned_median:.3g}/yr"
            )

        prior_total = sum(v.prior_median for v in blended_vectors)
        blended_total = sum(v.positioned_median for v in blended_vectors)
        delta = blended_total - prior_total
        sign = "+" if delta >= 0 else ""
        lines.append(
            f"\n  Blended vectors shift: {sign}{delta:.3g} per year"
        )
        return "\n".join(lines)

    def full_report(self) -> str:
        """Complete text report -- Tier 3 full audit trail."""
        sep = "=" * 60
        sections = [
            f"\n{self.scenario_name.upper()} THREAT EVENT FREQUENCY ESTIMATE",
            sep,
            f"Estimate Date: {self.estimate_date.strftime('%B %Y')} (point-in-time; refresh quarterly)",
            f"Organization Profile: {self.profile_summary}",
            *self.input_provenance,
            "",
            self.plain_language_summary(),
            "",
            sep,
            self.vector_breakdown_text(),
            "",
            sep,
            self.distribution_text(),
        ]

        if self.has_dispersion:
            sections.extend(["", self.dispersion_text()])

        if self.has_credibility_data:
            sections.extend(["", sep, self.credibility_text()])

        # Calculation traces
        has_traces = any(v.trace is not None for v in self.vectors)
        if has_traces:
            sections.extend(["", sep, "CALCULATION TRACES:"])
            for v in self.vectors:
                if v.trace is not None and hasattr(v.trace, 'render_text'):
                    sections.extend(["", v.trace.render_text()])

        if self.validation_checks:
            sections.extend(["", sep, "VALIDATION CHECKS:"])
            for check in self.validation_checks:
                sections.append(f"  + {check}")

        if self.warnings:
            sections.extend(["", sep, "WARNINGS:"])
            for warn in self.warnings:
                sections.append(f"  ! {warn}")

        all_sources = set()
        for v in self.vectors:
            all_sources.update(v.data_sources)
        sections.extend(["", sep, "DATA SOURCES:"])
        for src in sorted(all_sources):
            sections.append(f"  * {src}")

        sections.extend([
            "", sep,
            "BASE RATE DERIVATION:",
            *(f"  {line}" for line in self.base_rate_derivation),
            f"  Dampening coefficient k={self.dampening.factor_k:.2f}: {self.dampening.factor_k_source}",
            "",
            "WHAT THIS ESTIMATE DOES NOT INCLUDE:",
            "  * Susceptibility (probability that an attempt succeeds)",
            "  * Loss magnitude (financial impact if it does)",
            "  * Control effectiveness (reduces susceptibility)",
            "  * Attack surface size effect (enters through susceptibility, not TEF)",
        ])

        return "\n".join(sections)

    def brief_report(self) -> str:
        """Tier 1 summary -- fits on one slide."""
        s = self.summary
        lines = [
            f"{self.scenario_name.upper()} TEF ESTIMATE",
            "=" * 40,
            f"TEF: {s.tef_text}",
            f"Chance of at least one attempt in a year: {s.chance_at_least_one:.0%}",
            "",
        ]
        if s.peer_percentile is not None:
            lines.append(f"Peer percentile: {ordinal(s.peer_percentile)} ({s.peer_context})")
            lines.append("")

        lines.append("VECTOR BREAKDOWN:")
        max_name = max(len(d["vector"]) for d in s.vector_bar) if s.vector_bar else 10
        for d in s.vector_bar:
            share = d["share"]
            bar = "#" * int(share * 40)
            lines.append(f"  {d['vector']:<{max_name + 2}} {share:>5.0%} {bar}")

        lines.extend(["", s.one_sentence])
        if self.input_provenance:
            lines.extend(["", self.input_provenance[0]])
        return "\n".join(lines)

    def to_markdown(self) -> str:
        """Markdown-formatted report suitable for file export."""
        s = self.summary
        lines = [
            f"# {self.scenario_name} TEF Estimate",
            "",
            f"**Date:** {self.estimate_date.strftime('%B %Y')} (point-in-time; refresh quarterly)",
            f"**Profile:** {self.profile_summary}",
            *[f"**{key}:**{rest}" if sep else line
              for line in self.input_provenance
              for key, sep, rest in [line.partition(":")]],
            "",
            "## Summary",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| TEF | {s.tef_text} |",
            f"| Range | {self.total_positioned_low:.2g} -- {self.total_positioned_high:.2g} per year |",
            f"| Chance of at least one attempt in a year | {s.chance_at_least_one:.0%} |",
        ]
        if s.peer_percentile is not None:
            lines.append(f"| Peer percentile | {ordinal(s.peer_percentile)} ({s.peer_context}) |")
        lines.append("")

        lines.extend([
            "## Vector Breakdown",
            "",
            "| Vector | Share | Range (per year) |",
            "|--------|------:|-------|",
        ])
        raw_total = self.raw_vector_total
        for v in self.vectors:
            share = v.positioned_median / raw_total if raw_total > 0 else 0
            lines.append(
                f"| {v.vector_name} | {share:.0%} | "
                f"{v.positioned_low:.2g} -- {v.positioned_high:.2g} |"
            )
        lines.append("")

        lines.extend([
            "## Distribution Parameters",
            "",
            "| Parameter | Value |",
            "|-----------|-------|",
            "| Distribution | Lognormal |",
            f"| mu (ln-space) | {self.lognormal.mu:.3f} |",
            f"| sigma (ln-space) | {self.lognormal.sigma:.3f} |",
            f"| 5th percentile | {self.lognormal.p5:.3g} per year |",
            f"| Median | {self.lognormal.median:.3g} per year |",
            f"| 95th percentile | {self.lognormal.p95:.3g} per year |",
            "",
        ])

        has_traces = any(v.trace is not None for v in self.vectors)
        if has_traces:
            lines.extend(["## Calculation Traces", ""])
            for v in self.vectors:
                if v.trace is not None and hasattr(v.trace, 'render_text'):
                    lines.extend([f"### {v.vector_name}", "", "```", v.trace.render_text(), "```", ""])

        if self.validation_checks:
            lines.extend(["## Validation Checks", ""])
            for check in self.validation_checks:
                if check.strip():
                    lines.append(f"- {check}")
            lines.append("")

        if self.warnings:
            lines.extend(["## Warnings", ""])
            for warn in self.warnings:
                lines.append(f"- {warn}")
            lines.append("")

        all_sources = set()
        for v in self.vectors:
            all_sources.update(v.data_sources)
        lines.extend(["## Data Sources", ""])
        for src in sorted(all_sources):
            lines.append(f"- {src}")
        lines.append("")

        lines.extend([
            "## Base Rate Derivation",
            "",
            *(f"- {line}" for line in self.base_rate_derivation),
            "",
            "---",
            "",
            s.one_sentence,
        ])

        return "\n".join(lines)

    def to_dict(self) -> dict:
        """JSON-serializable dict with all three tiers."""
        s = self.summary
        a = self.analysis
        au = self.audit

        return {
            "scenario": self.scenario_name.lower(),
            "profile": self.profile_summary,
            "estimate_date": self.estimate_date.isoformat(),
            "inputs": list(self.input_provenance),
            "summary": {
                "positioned_median": s.positioned_median,
                "positioned_low": s.positioned_low,
                "positioned_high": s.positioned_high,
                "tef_text": s.tef_text,
                "chance_at_least_one": s.chance_at_least_one,
                "recurrence_years": s.recurrence_years,
                "peer_percentile": s.peer_percentile,
                "peer_context": s.peer_context,
                "one_sentence": s.one_sentence,
                "vector_bar": s.vector_bar,
            },
            "analysis": {
                "lognormal": {
                    "mu": a.lognormal.mu,
                    "sigma": a.lognormal.sigma,
                    "p5": a.lognormal.p5,
                    "median": a.lognormal.median,
                    "p95": a.lognormal.p95,
                },
                "pert": {"min": a.pert.low, "mode": a.pert.mode, "max": a.pert.high},
                "vectors": [
                    {
                        "name": v.vector_name,
                        "floor": v.floor,
                        "positioned_low": v.positioned_low,
                        "positioned_median": v.positioned_median,
                        "positioned_high": v.positioned_high,
                        "ceiling": v.ceiling,
                        "primary_drivers": v.primary_drivers,
                    }
                    for v in a.vectors
                ],
                "credibility": [
                    {
                        "vector": v.vector_name,
                        "prior_median": v.prior_median,
                        "observed_frequency": v.observed_frequency,
                        "credibility_z": v.credibility_z,
                        "blended_median": v.positioned_median,
                    }
                    for v in a.vectors
                    if v.credibility_z is not None
                ] or None,
                "dispersion": {
                    "total": self.total_dispersion.to_dict(self.total_positioned_median)
                    if self.total_dispersion is not None else None,
                    "vectors": {
                        v.telemetry_key: self.dispersion["vectors"][v.telemetry_key].to_dict(v.positioned_median)
                        for v in self.vectors
                        if v.telemetry_key in self.dispersion.get("vectors", {})
                    },
                } if self.dispersion else None,
            },
            "audit": {
                "traces": au.traces,
                "validation_checks": au.validation_checks,
                "warnings": au.warnings,
                "data_sources": au.data_sources,
                "base_rate": {
                    "low": au.base_rate.low,
                    "mode": au.base_rate.mode,
                    "high": au.base_rate.high,
                },
                "dampening": {
                    "factor_k": au.dampening.factor_k,
                    "vector_k": au.dampening.vector_k,
                    "max_composite": au.dampening.max_composite,
                },
                "scenario_definition": {"name": au.scenario_name},
            },
        }
