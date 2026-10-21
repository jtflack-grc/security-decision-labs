"""
Bühlmann credibility blending for per-vector TEF estimation.

Blends population-level TEF priors with organization-specific telemetry
observations. Each vector has its own structural parameter k. The k values
are asserted (judgment), not fitted; see docs/technical-reference.md §8.3.

    blended = Z × adjusted_observed + (1 - Z) × prior
    Z = effective_n / (effective_n + k)
    effective_n = observation_periods × detection_coverage
    adjusted_observed = raw_observed / detection_coverage

The blend formula is equivalent to the Gamma-inspired posterior mean with
Gamma(α, β=k) prior. The engine uses this equivalence to motivate a
Gamma-inspired band contraction mechanism (see engine.py and
docs/technical-reference.md §8.6 for derivation and limitations).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from tef_estimator.config import get_config


def _get_credibility_k() -> dict[str, float]:
    ck = get_config().credibility_k
    return {
        "exploitation": ck.exploitation,
        "credential": ck.credential,
        "phishing": ck.phishing,
        "supply_chain": ck.supply_chain,
    }


@dataclass(frozen=True)
class VectorObservation:
    """Organization-specific telemetry for one attack vector.

    Attributes
    ----------
    vector : str
        Vector name matching engine output: "exploitation", "credential",
        "phishing", or "supply_chain".
    annualized_frequency : float
        Observed attempt rate annualized from the org's own data.
        This is the raw rate before detection coverage adjustment.
    observation_periods : int
        Number of observation periods (quarters) behind this number.
        More periods → higher credibility.
    detection_coverage : float
        Fraction of actual attempts the org would detect (0-1).
        Adjusts both the observation upward and the credibility downward.
    """
    vector: str
    annualized_frequency: float
    observation_periods: int
    detection_coverage: float = 1.0

    def __post_init__(self):
        if self.vector not in ("exploitation", "credential", "phishing", "supply_chain"):
            raise ValueError(
                f"vector must be one of exploitation/credential/phishing/supply_chain, "
                f"got '{self.vector}'"
            )
        if self.annualized_frequency < 0:
            raise ValueError(f"annualized_frequency must be >= 0, got {self.annualized_frequency}")
        if self.observation_periods < 1:
            raise ValueError(f"observation_periods must be >= 1, got {self.observation_periods}")
        if not 0 < self.detection_coverage <= 1.0:
            raise ValueError(
                f"detection_coverage must be in (0, 1], got {self.detection_coverage}"
            )


@dataclass
class OrgTelemetry:
    """Container for organization-specific vector observations."""
    observations: list[VectorObservation] | tuple[VectorObservation, ...] = field(default_factory=list)

    def __post_init__(self):
        vectors = [obs.vector for obs in self.observations]
        dupes = [v for v in vectors if vectors.count(v) > 1]
        if dupes:
            raise ValueError(
                f"Duplicate vector observations: {sorted(set(dupes))}. "
                f"Provide one observation per vector."
            )
        self.observations = tuple(self.observations)

    def get(self, vector_name: str) -> VectorObservation | None:
        for obs in self.observations:
            if obs.vector == vector_name:
                return obs
        return None


@dataclass(frozen=True)
class BlendResult:
    """Output of a single vector's credibility blending."""
    prior: float
    adjusted_observed: float
    credibility_z: float
    blended: float
    effective_n: float
    k: float


class CredibilityBlender:
    """Bühlmann credibility blender with per-vector structural parameters.

    k = σ²(process) / σ²(hypothetical means)

    Lower k → credibility grows faster with data (high-observability vectors).
    Higher k → credibility grows slowly (low-observability vectors).
    """

    def __init__(self, k_overrides: dict[str, float] | None = None):
        base_k = _get_credibility_k()
        self.vector_k = dict(base_k)
        if k_overrides:
            self.vector_k.update(k_overrides)

    def blend(self, prior: float, obs: VectorObservation) -> BlendResult:
        k = self.vector_k.get(obs.vector)
        if k is None:
            raise ValueError(f"No credibility k parameter for vector '{obs.vector}'")

        effective_n = obs.observation_periods * obs.detection_coverage
        z = effective_n / (effective_n + k)

        adjusted_observed = obs.annualized_frequency / obs.detection_coverage

        blended = z * adjusted_observed + (1 - z) * prior

        return BlendResult(
            prior=prior,
            adjusted_observed=adjusted_observed,
            credibility_z=z,
            blended=blended,
            effective_n=effective_n,
            k=k,
        )

    def blend_vectors(
        self,
        vector_priors: dict[str, float],
        telemetry: OrgTelemetry,
    ) -> dict[str, BlendResult]:
        results = {}
        for vector_name, prior in vector_priors.items():
            obs = telemetry.get(vector_name)
            if obs is not None:
                results[vector_name] = self.blend(prior, obs)
        return results
