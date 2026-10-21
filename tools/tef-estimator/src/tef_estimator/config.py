"""
Configuration loader for the TEF estimator.

Loads bundled defaults from config.yaml, then merges user overrides
from ~/.tef-estimator/config.yaml if present.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from tef_estimator.distributions import DispersionParams


_BUNDLED_CONFIG = Path(__file__).parent / "config.yaml"
_USER_CONFIG = Path.home() / ".tef-estimator" / "config.yaml"

_bundled_defaults: dict | None = None


def _get_bundled_defaults() -> dict:
    global _bundled_defaults
    if _bundled_defaults is None:
        with open(_BUNDLED_CONFIG) as f:
            _bundled_defaults = yaml.safe_load(f)
    return _bundled_defaults


@dataclass
class SusceptibilityPrior:
    low: float
    mode: float
    high: float


@dataclass
class DampeningParams:
    factor_k: float
    vector_k: float
    max_composite: float


@dataclass
class CredibilityKParams:
    exploitation: float
    credential: float
    phishing: float
    supply_chain: float


@dataclass
class BandHardeningParams:
    min_sigma_ratio: float
    coverage_leverage_cap: float


@dataclass
class ExploitationCeilingParams:
    edge_device: float
    edge_device_basis: str
    cloud_primary: float
    cloud_primary_basis: str
    default: float
    default_basis: str


@dataclass
class TEFConfig:
    susceptibility_prior: SusceptibilityPrior = field(
        default_factory=lambda: SusceptibilityPrior(
            **_get_bundled_defaults()["susceptibility_prior"]
        )
    )
    dampening: DampeningParams = field(
        default_factory=lambda: DampeningParams(
            **_get_bundled_defaults()["dampening"]
        )
    )
    credibility_k: CredibilityKParams = field(
        default_factory=lambda: CredibilityKParams(
            **{k: v for k, v in _get_bundled_defaults()["credibility_k"].items()
               if k in CredibilityKParams.__dataclass_fields__}
        )
    )
    band_hardening: BandHardeningParams = field(
        default_factory=lambda: BandHardeningParams(
            **_get_bundled_defaults().get("band_hardening", {"min_sigma_ratio": 0.25, "coverage_leverage_cap": 5.0})
        )
    )
    # Per-vector k-sensitivity sweep ranges [low, asserted, high]
    k_sensitivity: dict = field(
        default_factory=lambda: _get_bundled_defaults().get("k_sensitivity", {})
    )
    exploitation_ceilings: ExploitationCeilingParams = field(
        default_factory=lambda: ExploitationCeilingParams(
            **_get_bundled_defaults().get("exploitation_ceilings", {
                "edge_device": 1000.0, "edge_device_basis": "assumption",
                "cloud_primary": 0.01, "cloud_primary_basis": "assumption",
                "default": 0.1, "default_basis": "assumption",
            })
        )
    )
    revenue_per_employee: dict = field(
        default_factory=lambda: dict(_get_bundled_defaults().get("revenue_per_employee", {"other": 300}))
    )
    # Burstiness of the rate over time (see config.yaml "dispersion" and DispersionParams)
    dispersion: dict = field(
        default_factory=lambda: copy.deepcopy(_get_bundled_defaults().get("dispersion", {}))
    )

    def dispersion_for(self, kind: str, name: str) -> DispersionParams:
        """Dispersion for a vector (kind="vectors") or scenario total (kind="scenarios").

        Returns Poisson when no shape is configured.
        """
        if kind not in ("vectors", "scenarios"):
            raise ValueError(f"kind must be 'vectors' or 'scenarios', got {kind!r}")
        block = self.dispersion or {}
        entry = (block.get(kind) or {}).get(name)
        timescale = block.get("timescale", "month")
        basis = block.get("basis", "detrended")
        if not entry or entry.get("shape_r") is None:
            return DispersionParams(shape_r=None, timescale=timescale, basis=basis)
        params = DispersionParams(
            shape_r=entry["shape_r"],
            timescale=timescale,
            basis="detrended",
            source=entry.get("source", ""),
            raw_shape_r=entry.get("raw_shape_r"),
        )
        return params.as_raw() if basis == "raw" else params

    @classmethod
    def from_yaml(cls, path: str | Path) -> TEFConfig:
        """Load a config file; keys it leaves out fall back to the bundled defaults."""
        with open(path) as f:
            return cls.from_dict(yaml.safe_load(f) or {})

    @classmethod
    def from_dict(cls, d: dict) -> TEFConfig:
        defaults = _get_bundled_defaults()
        sp = {**defaults["susceptibility_prior"], **d.get("susceptibility_prior", {})}
        dp = {**defaults["dampening"], **d.get("dampening", {})}
        ck = {**defaults["credibility_k"], **d.get("credibility_k", {})}
        bh = {**defaults.get("band_hardening", {"min_sigma_ratio": 0.25, "coverage_leverage_cap": 5.0}), **d.get("band_hardening", {})}
        ec_defaults = {
            "edge_device": 1000.0, "edge_device_basis": "assumption",
            "cloud_primary": 0.01, "cloud_primary_basis": "assumption",
            "default": 0.1, "default_basis": "assumption",
        }
        ec = {**defaults.get("exploitation_ceilings", ec_defaults), **d.get("exploitation_ceilings", {})}
        rpe = {**defaults.get("revenue_per_employee", {"other": 300}), **d.get("revenue_per_employee", {})}
        cfg = cls()
        cfg.susceptibility_prior = SusceptibilityPrior(**sp)
        cfg.dampening = DampeningParams(**dp)
        cfg.credibility_k = CredibilityKParams(
            **{k: v for k, v in ck.items() if k in CredibilityKParams.__dataclass_fields__}
        )
        cfg.band_hardening = BandHardeningParams(**bh)
        cfg.k_sensitivity = {**defaults.get("k_sensitivity", {}), **d.get("k_sensitivity", {})}
        cfg.exploitation_ceilings = ExploitationCeilingParams(**ec)
        cfg.revenue_per_employee = rpe
        cfg.dispersion = _deep_merge(copy.deepcopy(defaults.get("dispersion", {})), d.get("dispersion", {}) or {})
        for kind in ("vectors", "scenarios"):  # validate every configured entry up front
            for name in (cfg.dispersion.get(kind) or {}):
                cfg.dispersion_for(kind, name)
        return cfg

    def to_dict(self) -> dict:
        return {
            "susceptibility_prior": {
                "low": self.susceptibility_prior.low,
                "mode": self.susceptibility_prior.mode,
                "high": self.susceptibility_prior.high,
            },
            "dampening": {
                "factor_k": self.dampening.factor_k,
                "vector_k": self.dampening.vector_k,
                "max_composite": self.dampening.max_composite,
            },
            "credibility_k": {
                "exploitation": self.credibility_k.exploitation,
                "credential": self.credibility_k.credential,
                "phishing": self.credibility_k.phishing,
                "supply_chain": self.credibility_k.supply_chain,
            },
            "band_hardening": {
                "min_sigma_ratio": self.band_hardening.min_sigma_ratio,
                "coverage_leverage_cap": self.band_hardening.coverage_leverage_cap,
            },
            "exploitation_ceilings": {
                "edge_device": self.exploitation_ceilings.edge_device,
                "edge_device_basis": self.exploitation_ceilings.edge_device_basis,
                "cloud_primary": self.exploitation_ceilings.cloud_primary,
                "cloud_primary_basis": self.exploitation_ceilings.cloud_primary_basis,
                "default": self.exploitation_ceilings.default,
                "default_basis": self.exploitation_ceilings.default_basis,
            },
            "revenue_per_employee": dict(self.revenue_per_employee),
            "k_sensitivity": copy.deepcopy(self.k_sensitivity),
            "dispersion": copy.deepcopy(self.dispersion),
        }


def _deep_merge(base: dict, overrides: dict) -> dict:
    merged = dict(base)
    for k, v in overrides.items():
        if k in merged and isinstance(merged[k], dict) and isinstance(v, dict):
            merged[k] = _deep_merge(merged[k], v)
        else:
            merged[k] = v
    return merged


def load_config(user_path: Path | None = None) -> TEFConfig:
    """Load config from bundled defaults, merged with user overrides."""
    base = dict(_get_bundled_defaults())

    user_file = user_path or _USER_CONFIG
    if user_file.exists():
        with open(user_file) as f:
            user = yaml.safe_load(f) or {}
        base = _deep_merge(base, user)

    return TEFConfig.from_dict(base)


_cached_config: TEFConfig | None = None


def get_config() -> TEFConfig:
    """Return the cached config, loading on first access."""
    global _cached_config
    if _cached_config is None:
        _cached_config = load_config()
    return _cached_config


def reset_config() -> None:
    """Clear cached config (for testing or after user edits)."""
    global _cached_config
    _cached_config = None
