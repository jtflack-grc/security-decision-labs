"""
Organization profile — the input to the TEF estimation engine.

6–9 inputs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from tef_estimator.config import get_config
from tef_estimator.data import (
    Geography,
    RemoteAccessType,
    RevenueBand,
    Sector,
)

_REVENUE_MIDPOINTS = {
    RevenueBand.UNDER_10M: 5_000,
    RevenueBand.R_10M_100M: 55_000,
    RevenueBand.R_100M_1B: 550_000,
    RevenueBand.R_1B_10B: 5_500_000,
    RevenueBand.R_10B_100B: 55_000_000,
    RevenueBand.OVER_100B: 200_000_000,
}

if TYPE_CHECKING:
    from tef_estimator.credibility import OrgTelemetry


@dataclass
class OrganizationProfile:
    """Everything the estimator needs to produce a TEF estimate.

    Required (minimum viable):
        sector, revenue_band, geography

    Strongly recommended:
        remote_access, employee_band, edge_vendors

    Optional:
        critical_infrastructure, supply_chain_provider, recent_ma
    """

    # --- Required ---
    sector: Sector
    revenue_band: RevenueBand
    geography: Geography

    # --- Strongly recommended ---
    remote_access: list[RemoteAccessType] = field(default_factory=lambda: [RemoteAccessType.NONE])
    employee_count: int | None = None
    edge_vendors: list[RemoteAccessType] = field(default_factory=list)

    # --- Optional profile flags ---
    critical_infrastructure: bool = False
    supply_chain_provider: bool = False
    recent_ma: bool = False

    # --- Override hooks for analysts ---
    custom_base_rate: float | None = None  # Override the triangulated base rate

    # --- Org-specific telemetry for Bühlmann credibility blending ---
    telemetry: OrgTelemetry | None = None

    def __post_init__(self):
        if self.employee_count is not None:
            if not isinstance(self.employee_count, int) or self.employee_count < 0:
                raise ValueError(
                    f"employee_count must be a non-negative integer, got {self.employee_count}"
                )
            if self.employee_count > 10_000_000:
                raise ValueError(
                    f"employee_count {self.employee_count:,} exceeds 10M — verify input"
                )
        if self.custom_base_rate is not None:
            if self.custom_base_rate <= 0:
                raise ValueError(
                    f"custom_base_rate must be positive (TEF, events per year), "
                    f"got {self.custom_base_rate}"
                )

    @property
    def has_vpn(self) -> bool:
        vpn_types = {
            RemoteAccessType.FORTINET,
            RemoteAccessType.PALO_ALTO,
            RemoteAccessType.CISCO,
            RemoteAccessType.SONICWALL,
            RemoteAccessType.CITRIX,
            RemoteAccessType.OTHER_VPN,
        }
        return bool(vpn_types & set(self.remote_access))

    @property
    def has_rdp(self) -> bool:
        return RemoteAccessType.RDP in self.remote_access

    @property
    def has_no_remote_access(self) -> bool:
        return self.remote_access == [RemoteAccessType.NONE]

    @property
    def has_vulnerable_vpn_vendor(self) -> bool:
        """Fortinet, Cisco, Palo Alto, SonicWall — extensive CVE history."""
        vuln_vendors = {
            RemoteAccessType.FORTINET,
            RemoteAccessType.PALO_ALTO,
            RemoteAccessType.CISCO,
            RemoteAccessType.SONICWALL,
        }
        return bool(vuln_vendors & set(self.remote_access))

    @property
    def employee_band_label(self) -> str:
        if self.employee_count is None:
            return "unknown"
        if self.employee_count < 50:
            return "<50"
        if self.employee_count < 500:
            return "50–500"
        if self.employee_count < 5_000:
            return "500–5,000"
        if self.employee_count < 50_000:
            return "5,000–50,000"
        return "50,000+"

    @property
    def has_large_email_footprint(self) -> bool:
        return self.employee_count is not None and self.employee_count >= 1000

    @property
    def is_cloud_primary(self) -> bool:
        """Cloud-primary with no edge devices — inferred from no VPN/RDP."""
        return self.has_no_remote_access and not self.edge_vendors

    def infer_employee_count(self, subsector: str | None = None) -> int | None:
        """Infer employee count from revenue band and sector RPE.

        Returns None if employee_count is already set.
        """
        if self.employee_count is not None:
            return None
        cfg = get_config()
        rpe_table = cfg.to_dict().get("revenue_per_employee", {})
        sector_key = self.sector.value
        rpe = None
        if subsector and subsector in rpe_table:
            rpe = rpe_table[subsector]
        if rpe is None:
            rpe = rpe_table.get(sector_key)
        if rpe is None:
            rpe = rpe_table.get("other", 300)
        midpoint = _REVENUE_MIDPOINTS.get(self.revenue_band)
        if midpoint is None or rpe <= 0:
            return None
        return max(1, round(midpoint / rpe))

    def summary(self) -> str:
        """Human-readable one-liner for output headers."""
        parts = [
            self.sector.value.replace("_", " ").title(),
            self.revenue_band.value.replace("_", "–").upper(),
            self.geography.value.replace("_", " ").title(),
        ]
        if self.has_vpn:
            vpn_names = [r.value for r in self.remote_access if r != RemoteAccessType.NONE]
            parts.append(f"VPN: {', '.join(vpn_names)}")
        if self.employee_count:
            parts.append(f"~{self.employee_count:,} employees")
        return " | ".join(parts)
