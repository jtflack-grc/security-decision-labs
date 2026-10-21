"""
NiceGUI web interface for the TEF estimator.

Three tabs:
  1. Estimate — point-in-time TEF estimation (existing)
  2. Telemetry — continuous monitoring dashboard
  3. Scenarios — custom scenario builder
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from nicegui import run, ui
import plotly.graph_objects as go

from tef_estimator import __version__
from tef_estimator.config import TEFConfig, SusceptibilityPrior, DampeningParams, CredibilityKParams
from tef_estimator.data.common import (
    DATA_VINTAGE,
    Geography,
    PERTRange,
    RemoteAccessType,
    RevenueBand,
    Sector,
)
from tef_estimator.data.loader import PEER_GRID_DIR
from tef_estimator.data.scenarios.bec import BECScenario
from tef_estimator.data.scenarios.exfiltration import ExfiltrationScenario
from tef_estimator.data.scenarios.web_app import WebAppScenario
from tef_estimator.data.scenarios.ransomware import RansomwareScenario
from tef_estimator.engine import TEFEngine
from tef_estimator.peer import compute_and_set_percentile, load_grid
from tef_estimator.profile import OrganizationProfile

log = logging.getLogger(__name__)

# --- Telemetry availability ---
try:
    from tef_estimator.telemetry.db import TelemetryDB
    from tef_estimator.telemetry.collectors import collect_all, get_all_collectors
    from tef_estimator.telemetry.scheduler import run_due_collections
    from tef_estimator.telemetry.integrator import run_integration
    from tef_estimator.telemetry.compare import compare, snapshot_baseline, load_baseline
    HAS_TELEMETRY = True
except ImportError:
    HAS_TELEMETRY = False

# --- Constants ---

BUILTIN_SCENARIOS = {
    "ransomware": RansomwareScenario,
    "bec": BECScenario,
    "exfiltration": ExfiltrationScenario,
    "web_app": WebAppScenario,
}

ACCENT = "#E74C3C"
BG_DARK = "#1a1a2e"
TEXT_MUTED = "#94a3b8"
SCENARIOS_DIR = Path.home() / ".tef-estimator" / "scenarios"


# --- Scenario discovery ---

def _discover_custom_scenarios() -> dict[str, Path]:
    if not SCENARIOS_DIR.exists():
        return {}
    found = {}
    for f in sorted(SCENARIOS_DIR.glob("*.json")):
        try:
            data = json.loads(f.read_text())
            slug = data.get("scenario_slug", f.stem)
            found[slug] = f
        except (json.JSONDecodeError, KeyError):
            continue
    return found


def _all_scenario_options() -> dict[str, str]:
    opts = {"ransomware": "Ransomware", "bec": "BEC", "exfiltration": "Data Exfiltration", "web_app": "Web App Exploitation"}
    for slug, path in _discover_custom_scenarios().items():
        try:
            data = json.loads(path.read_text())
            opts[slug] = data.get("scenario_name", slug.replace("_", " ").title())
        except Exception:
            opts[slug] = slug.replace("_", " ").title()
    return opts


def _load_scenario_for_engine(slug: str):
    if slug in BUILTIN_SCENARIOS:
        return BUILTIN_SCENARIOS[slug]()
    customs = _discover_custom_scenarios()
    if slug in customs:
        from tef_estimator.data.scenarios.custom import load_custom_scenario
        return load_custom_scenario(customs[slug])
    return RansomwareScenario()


# --- Helpers ---

def _display_name(enum_val: str) -> str:
    return enum_val.replace("_", " ").title()


def _enum_options(enum_cls) -> dict[str, str]:
    return {e.value: _display_name(e.value) for e in enum_cls}


def _run_estimate(state: dict, config_state: dict | None = None) -> dict | None:
    try:
        remote = state.get("remote_access", ["none"])
        if not remote:
            remote = ["none"]
        remote_enums = [RemoteAccessType(r) for r in remote]

        emp = state.get("employees")
        if emp is not None and emp != "":
            emp = int(emp)
        else:
            emp = None

        br = state.get("base_rate_override")
        if br is not None and br != "":
            br = float(br)
        else:
            br = None

        profile = OrganizationProfile(
            sector=Sector(state["sector"]),
            revenue_band=RevenueBand(state["revenue_band"]),
            geography=Geography(state["geography"]),
            remote_access=remote_enums,
            employee_count=emp,
            critical_infrastructure=state.get("critical_infra", False),
            supply_chain_provider=state.get("supply_chain", False),
            recent_ma=state.get("recent_ma", False),
            custom_base_rate=br,
        )

        cfg = None
        if config_state:
            cfg = TEFConfig(
                susceptibility_prior=SusceptibilityPrior(
                    low=config_state["susc_low"],
                    mode=config_state["susc_mode"],
                    high=config_state["susc_high"],
                ),
                dampening=DampeningParams(
                    factor_k=config_state["factor_k"],
                    vector_k=config_state["vector_k"],
                    max_composite=config_state["max_composite"],
                ),
                credibility_k=CredibilityKParams(
                    exploitation=config_state["cred_exploitation"],
                    credential=config_state["cred_credential"],
                    phishing=config_state["cred_phishing"],
                    supply_chain=config_state["cred_supply_chain"],
                ),
            )

        scenario = _load_scenario_for_engine(state.get("scenario", "ransomware"))
        engine = TEFEngine(scenario=scenario, config=cfg)
        result = engine.estimate(profile)

        grid_path = PEER_GRID_DIR / f"{scenario.scenario_slug}.json"
        grid = load_grid(grid_path)
        if grid is not None:
            compute_and_set_percentile(result, profile.revenue_band, grid)

        sens = engine.sensitivity(profile)

        return {
            "result": result,
            "sensitivity": sens,
            "profile": profile,
            "error": None,
        }
    except Exception as e:
        return {"result": None, "sensitivity": None, "profile": None, "error": str(e)}


# --- Chart builders ---

def _vector_bar_figure(result) -> go.Figure:
    s = result.summary
    vectors = s.vector_bar
    if not vectors:
        return go.Figure()

    names = [v["vector"] for v in vectors]
    shares = [v["share"] for v in vectors]
    colors = ["#E74C3C", "#3498DB", "#F39C12", "#2ECC71"]

    fig = go.Figure()
    for i, (name, share) in enumerate(zip(names, shares)):
        fig.add_trace(go.Bar(
            y=["TEF"], x=[share],
            name=f"{name} ({share:.0%})",
            orientation="h",
            marker_color=colors[i % len(colors)],
            text=f"{name}<br>{share:.0%}",
            textposition="inside",
            insidetextanchor="middle",
            hovertemplate=f"{name}: {share:.1%}<extra></extra>",
        ))

    fig.update_layout(
        barmode="stack", height=80,
        margin=dict(l=0, r=0, t=0, b=0),
        showlegend=False,
        xaxis=dict(visible=False, range=[0, 1]),
        yaxis=dict(visible=False),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="white", size=12),
    )
    return fig


def _tornado_figure(sensitivity) -> go.Figure:
    data = sensitivity.tornado_data
    baseline = sensitivity.baseline_median

    fig = go.Figure()
    params = [d["parameter"].replace("_", " ").title() for d in data]

    for i, d in enumerate(data):
        fig.add_trace(go.Bar(
            y=[params[i]], x=[d["low"] - baseline], base=[baseline],
            orientation="h", marker_color="#3498DB",
            name="Low" if i == 0 else None,
            showlegend=(i == 0),
            hovertemplate=f"Low: {d['low']:.5f}<extra></extra>",
        ))
        fig.add_trace(go.Bar(
            y=[params[i]], x=[d["high"] - baseline], base=[baseline],
            orientation="h", marker_color="#E74C3C",
            name="High" if i == 0 else None,
            showlegend=(i == 0),
            hovertemplate=f"High: {d['high']:.5f}<extra></extra>",
        ))

    fig.add_vline(x=baseline, line_dash="dash", line_color="white", line_width=1)

    fig.update_layout(
        barmode="overlay", height=180,
        margin=dict(l=0, r=20, t=30, b=20),
        title=dict(text=f"Sensitivity (baseline: {baseline:.4f})",
                   font=dict(size=13, color=TEXT_MUTED)),
        xaxis=dict(title="TEF", tickformat=".4f",
                   gridcolor="rgba(255,255,255,0.1)", color=TEXT_MUTED),
        yaxis=dict(color="white", autorange="reversed"),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="white"),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
    )
    return fig


def _history_figure(rows: list[tuple]) -> go.Figure:
    from collections import defaultdict
    series: dict[str, tuple[list, list]] = defaultdict(lambda: ([], []))
    for date, metric, value in rows:
        dates, values = series[metric]
        dates.append(date)
        values.append(value)

    fig = go.Figure()
    colors = ["#E74C3C", "#3498DB", "#F39C12", "#2ECC71", "#9B59B6", "#1ABC9C"]
    for i, (metric, (dates, values)) in enumerate(sorted(series.items())):
        short = metric.replace("_7d_avg", "").replace("unique_sources_", "").replace("daily_", "")
        fig.add_trace(go.Scatter(
            x=dates, y=values, mode="lines",
            name=short, line=dict(color=colors[i % len(colors)], width=2),
        ))

    fig.update_layout(
        height=300,
        margin=dict(l=40, r=20, t=10, b=40),
        xaxis=dict(color=TEXT_MUTED, gridcolor="rgba(255,255,255,0.05)"),
        yaxis=dict(color=TEXT_MUTED, gridcolor="rgba(255,255,255,0.05)"),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="white", size=11),
        legend=dict(font=dict(size=10)),
    )
    return fig


# ====================================================================
# Main App
# ====================================================================

class TEFEstimatorApp:
    def __init__(self):
        self.state = {
            "sector": Sector.MANUFACTURING.value,
            "revenue_band": RevenueBand.R_100M_1B.value,
            "geography": Geography.US.value,
            "remote_access": [RemoteAccessType.NONE.value],
            "employees": None,
            "critical_infra": False,
            "supply_chain": False,
            "recent_ma": False,
            "base_rate_override": None,
            "scenario": "ransomware",
            "compare_mode": False,
        }
        self.state_b = {
            "sector": Sector.FINANCIAL.value,
            "revenue_band": RevenueBand.R_100M_1B.value,
            "geography": Geography.US.value,
            "remote_access": [RemoteAccessType.NONE.value],
            "employees": None,
        }

        self.results_container = None
        self.compare_container = None
        self.compare_sidebar = None
        self.scenario_toggle = None

        # Telemetry state
        self.telem_db: TelemetryDB | None = None
        self.telem_health_container = None
        self.telem_signals_container = None
        self.telem_history_container = None
        self.telem_threshold = 0.20
        self.telem_source_select = None

        # Config state (loaded from config.yaml, overridable in UI)
        from tef_estimator.config import get_config
        cfg = get_config()
        self.config_state = {
            "susc_low": cfg.susceptibility_prior.low,
            "susc_mode": cfg.susceptibility_prior.mode,
            "susc_high": cfg.susceptibility_prior.high,
            "factor_k": cfg.dampening.factor_k,
            "vector_k": cfg.dampening.vector_k,
            "max_composite": cfg.dampening.max_composite,
            "cred_exploitation": cfg.credibility_k.exploitation,
            "cred_credential": cfg.credibility_k.credential,
            "cred_phishing": cfg.credibility_k.phishing,
            "cred_supply_chain": cfg.credibility_k.supply_chain,
        }

        # Scenario builder state
        self.scen_state = {
            "name": "My Custom Scenario",
            "slug": "my_custom",
            "exploitation": {"low": 0.10, "mode": 0.20, "high": 0.30},
            "credential": {"low": 0.30, "mode": 0.40, "high": 0.50},
            "phishing": {"low": 0.15, "mode": 0.25, "high": 0.35},
            "supply_chain": {"low": 0.05, "mode": 0.15, "high": 0.20},
            "base_rate": {"low": 0.005, "mode": 0.015, "high": 0.04},
            "overall_share": 0.10,
        }
        self.scen_sum_label = None
        self.scen_preview_container = None
        self.scen_list_container = None

    # ----------------------------------------------------------------
    # Build
    # ----------------------------------------------------------------

    def build(self):
        ui.dark_mode(True)

        ui.add_head_html("""
        <style>
            body { background: #0f172a !important; }
            .q-card { border: 1px solid #334155 !important; }
            .q-expansion-item { border: 1px solid #334155 !important; border-radius: 8px !important; }
            .q-tab-panel { padding: 0 !important; }
        </style>
        """)

        with ui.header().classes("bg-slate-900 border-b border-slate-700"):
            with ui.row().classes("w-full items-center justify-between px-4"):
                with ui.row().classes("items-center gap-3"):
                    ui.icon("shield", size="md").classes("text-red-500")
                    ui.label("TEF Estimator").classes("text-xl font-bold text-white")
                    ui.badge(f"v{__version__}", color="grey").classes("text-xs")

                self.tabs = ui.tabs().props("dense no-caps active-color=red indicator-color=red")
                with self.tabs:
                    self.tab_estimate = ui.tab("Estimate").props("no-caps")
                    self.tab_telemetry = ui.tab("Telemetry").props("no-caps")
                    self.tab_scenarios = ui.tab("Scenarios").props("no-caps")

        with ui.tab_panels(self.tabs, value=self.tab_estimate).classes(
            "w-full flex-1"
        ).style("background: #0f172a"):

            with ui.tab_panel(self.tab_estimate).classes("p-0"):
                self._build_estimate_tab()

            with ui.tab_panel(self.tab_telemetry).classes("p-0"):
                self._build_telemetry_tab()

            with ui.tab_panel(self.tab_scenarios).classes("p-0"):
                self._build_scenario_tab()

        with ui.footer().classes("bg-slate-900 border-t border-slate-700"):
            with ui.row().classes("w-full items-center justify-between px-4"):
                vintage_items = list(DATA_VINTAGE.items())[:3]
                vintage_text = " | ".join(str(v) for _, v in vintage_items)
                ui.label(f"Data: {vintage_text}").classes("text-xs text-slate-500")
                ui.label("Authors: Laura Voicu | Jack Jones").classes("text-xs text-slate-500")

        self._update_estimate()

    # ================================================================
    # ESTIMATE TAB
    # ================================================================

    def _build_estimate_tab(self):
        with ui.row().classes("w-full").style("min-height: calc(100vh - 160px)"):
            # Left sidebar
            with ui.column().classes(
                "w-80 p-4 bg-slate-900 border-r border-slate-700 shrink-0 overflow-y-auto"
            ).style("min-height: calc(100vh - 160px)"):
                self._build_sidebar(self.state, "Organization Profile")
                ui.separator().classes("bg-slate-700 my-3")

                # Scenario selector
                ui.label("Scenario").classes("text-sm text-slate-400")
                self.scenario_toggle = ui.select(
                    _all_scenario_options(),
                    value=self.state["scenario"],
                    on_change=lambda e: self._set_and_update(
                        self.state, "scenario", e.value
                    ),
                ).classes("w-full").props("dense outlined dark")

                ui.separator().classes("bg-slate-700 my-3")

                ui.switch(
                    "Compare Mode",
                    value=self.state["compare_mode"],
                    on_change=lambda e: self._toggle_compare(e.value),
                ).props("dense color=blue dark")

                ui.separator().classes("bg-slate-700 my-3")

                with ui.expansion("Advanced", icon="tune").classes("w-full").props("dense"):
                    ui.switch(
                        "Critical Infrastructure",
                        value=self.state["critical_infra"],
                        on_change=lambda e: self._set_and_update(
                            self.state, "critical_infra", e.value
                        ),
                    ).props("dense dark")
                    ui.switch(
                        "Supply Chain Provider",
                        value=self.state["supply_chain"],
                        on_change=lambda e: self._set_and_update(
                            self.state, "supply_chain", e.value
                        ),
                    ).props("dense dark")
                    ui.switch(
                        "Recent M&A (18 months)",
                        value=self.state["recent_ma"],
                        on_change=lambda e: self._set_and_update(
                            self.state, "recent_ma", e.value
                        ),
                    ).props("dense dark")
                    ui.number(
                        "Base Rate Override", value=None,
                        min=0.0001, max=1.0, step=0.001,
                        on_change=lambda e: self._set_and_update(
                            self.state, "base_rate_override", e.value
                        ),
                    ).classes("w-full").props("dense outlined dark hint='0.001 – 1.0'")

                with ui.expansion("Configuration", icon="settings").classes(
                    "w-full"
                ).props("dense"):
                    self._build_config_controls()

            # Compare sidebar
            self.compare_sidebar = ui.column().classes(
                "w-72 p-4 bg-slate-900/80 border-r border-slate-700 shrink-0 overflow-y-auto"
            ).style("min-height: calc(100vh - 160px)")
            self.compare_sidebar.set_visibility(self.state["compare_mode"])
            with self.compare_sidebar:
                self._build_sidebar(self.state_b, "Profile B (Compare)")

            # Main content
            with ui.column().classes("flex-1 p-6 gap-4 overflow-y-auto"):
                self.results_container = ui.column().classes("w-full gap-4")
                self.compare_container = ui.column().classes("w-full gap-4 mt-4")

    def _build_sidebar(self, target_state: dict, label: str = "Organization Profile"):
        ui.label(label).classes("text-lg font-bold text-white mb-2")

        ui.select(
            _enum_options(Sector), value=target_state["sector"], label="Sector",
            on_change=lambda e: self._set_and_update(target_state, "sector", e.value),
        ).classes("w-full").props("dense outlined dark")

        ui.select(
            _enum_options(RevenueBand), value=target_state["revenue_band"],
            label="Revenue Band",
            on_change=lambda e: self._set_and_update(target_state, "revenue_band", e.value),
        ).classes("w-full").props("dense outlined dark")

        ui.select(
            _enum_options(Geography), value=target_state["geography"], label="Geography",
            on_change=lambda e: self._set_and_update(target_state, "geography", e.value),
        ).classes("w-full").props("dense outlined dark")

        ui.select(
            _enum_options(RemoteAccessType),
            value=target_state.get("remote_access", ["none"]),
            label="Remote Access", multiple=True,
            on_change=lambda e: self._set_and_update(target_state, "remote_access", e.value),
        ).classes("w-full").props("dense outlined dark")

        ui.number(
            "Employee Count", value=target_state.get("employees"),
            min=0, max=10_000_000, step=100,
            on_change=lambda e: self._set_and_update(target_state, "employees", e.value),
        ).classes("w-full").props("dense outlined dark")

    def _build_config_controls(self):
        """Build configuration parameter controls in the sidebar."""

        def _cfg_update(key, value):
            self.config_state[key] = value
            self._update_estimate()

        ui.label("Susceptibility Prior").classes("text-xs text-slate-400 mt-1")
        with ui.row().classes("w-full gap-1"):
            ui.number(
                "Low", value=self.config_state["susc_low"],
                min=0.01, max=1.0, step=0.01, format="%.2f",
                on_change=lambda e: _cfg_update("susc_low", e.value),
            ).classes("flex-1").props("dense outlined dark")
            ui.number(
                "Mode", value=self.config_state["susc_mode"],
                min=0.01, max=1.0, step=0.01, format="%.2f",
                on_change=lambda e: _cfg_update("susc_mode", e.value),
            ).classes("flex-1").props("dense outlined dark")
            ui.number(
                "High", value=self.config_state["susc_high"],
                min=0.01, max=1.0, step=0.01, format="%.2f",
                on_change=lambda e: _cfg_update("susc_high", e.value),
            ).classes("flex-1").props("dense outlined dark")

        ui.label("Dampening").classes("text-xs text-slate-400 mt-2")
        ui.number(
            "Factor k (within-vector)", value=self.config_state["factor_k"],
            min=0.0, max=1.0, step=0.05, format="%.2f",
            on_change=lambda e: _cfg_update("factor_k", e.value),
        ).classes("w-full").props("dense outlined dark")
        ui.number(
            "Vector k (cross-vector)", value=self.config_state["vector_k"],
            min=0.0, max=1.0, step=0.05, format="%.2f",
            on_change=lambda e: _cfg_update("vector_k", e.value),
        ).classes("w-full").props("dense outlined dark")
        ui.number(
            "Max composite", value=self.config_state["max_composite"],
            min=1.0, max=20.0, step=0.5, format="%.1f",
            on_change=lambda e: _cfg_update("max_composite", e.value),
        ).classes("w-full").props("dense outlined dark")

        ui.label("Credibility k").classes("text-xs text-slate-400 mt-2")
        for vec in ["exploitation", "credential", "phishing", "supply_chain"]:
            key = f"cred_{vec}"
            ui.number(
                vec.replace("_", " ").title(),
                value=self.config_state[key],
                min=1.0, max=100.0, step=1.0, format="%.1f",
                on_change=lambda e, k=key: _cfg_update(k, e.value),
            ).classes("w-full").props("dense outlined dark")

    def _set_and_update(self, target: dict, key: str, value):
        target[key] = value
        self._update_estimate()

    def _toggle_compare(self, value: bool):
        self.state["compare_mode"] = value
        if self.compare_sidebar:
            self.compare_sidebar.set_visibility(value)
        self._update_estimate()

    def _update_estimate(self):
        self._render_results()

    def _render_results(self):
        if self.results_container is None:
            return

        self.results_container.clear()
        out = _run_estimate(self.state, self.config_state)

        if out is None or out["error"]:
            with self.results_container:
                ui.label(f"Error: {out['error'] if out else 'Unknown'}").classes(
                    "text-red-400 text-lg"
                )
            return

        result = out["result"]
        sens = out["sensitivity"]
        s = result.summary
        a = result.analysis

        with self.results_container:
            with ui.card().classes("w-full bg-slate-800 border-slate-700"):
                with ui.row().classes("w-full items-center justify-between"):
                    ui.label(f"{result.scenario_name} TEF Estimate").classes(
                        "text-xl font-bold text-white"
                    )
                    if s.peer_percentile is not None:
                        ui.badge(f"{s.peer_percentile}th percentile", color="blue").classes("text-sm")

                with ui.row().classes("w-full gap-8 mt-4"):
                    with ui.column().classes("items-center"):
                        ui.label(s.annual_probability_pct).classes(
                            "text-5xl font-bold"
                        ).style(f"color: {ACCENT}")
                        ui.label("Annual Probability").classes("text-sm text-slate-400")
                    with ui.column().classes("items-center"):
                        recur_text = (
                            f"~1 in {s.recurrence_years:.0f}"
                            if s.recurrence_years < 1e6 else "N/A"
                        )
                        ui.label(recur_text).classes("text-5xl font-bold text-blue-400")
                        ui.label("Year Recurrence").classes("text-sm text-slate-400")

                ui.separator().classes("bg-slate-700")
                ui.label("Vector Breakdown").classes("text-sm font-semibold text-slate-300 mt-2")
                ui.plotly(_vector_bar_figure(result)).classes("w-full h-20")

                with ui.row().classes("w-full gap-4 mt-2"):
                    raw_total = sum(v.positioned_median for v in result.vectors)
                    colors = ["#E74C3C", "#3498DB", "#F39C12", "#2ECC71"]
                    for i, v in enumerate(result.vectors):
                        with ui.column().classes("flex-1 items-center"):
                            ui.label(f"{v.positioned_median:.5f}").classes(
                                "text-sm font-mono"
                            ).style(f"color: {colors[i % len(colors)]}")
                            ui.label(v.vector_name).classes("text-xs text-slate-500")

            with ui.card().classes("w-full bg-slate-800/50 border-slate-700"):
                ui.label(s.one_sentence).classes("text-sm text-slate-300 italic")

            with ui.expansion("Analysis", icon="analytics").classes(
                "w-full bg-slate-800 border-slate-700"
            ).props("default-opened"):
                with ui.grid(columns=2).classes("w-full gap-4"):
                    with ui.card().classes("bg-slate-900 border-slate-700"):
                        ui.label("Distribution Parameters").classes(
                            "text-sm font-semibold text-slate-300"
                        )
                        ln = a.lognormal
                        for label, val in [
                            ("mu (ln-space)", f"{ln.mu:.3f}"),
                            ("sigma (ln-space)", f"{ln.sigma:.3f}"),
                            ("5th percentile", f"{ln.p5:.5f} ({ln.p5 * 100:.2f}%)"),
                            ("Median", f"{ln.median:.5f} ({ln.median * 100:.2f}%)"),
                            ("95th percentile", f"{ln.p95:.5f} ({ln.p95 * 100:.2f}%)"),
                        ]:
                            with ui.row().classes("justify-between w-full"):
                                ui.label(label).classes("text-xs text-slate-500")
                                ui.label(val).classes("text-xs font-mono text-white")
                        ui.label("For fair-risk-engine").classes("text-xs font-semibold text-slate-400 mt-3")
                        ui.label(result.fair_risk_engine_text().strip()).classes(
                            "text-xs font-mono text-white whitespace-pre-wrap break-all"
                        )

                    with ui.card().classes("bg-slate-900 border-slate-700"):
                        ui.label("Vector Priority").classes(
                            "text-sm font-semibold text-slate-300"
                        )
                        raw_total = sum(v.positioned_median for v in result.vectors)
                        ranked = sorted(result.vectors, key=lambda v: v.positioned_median, reverse=True)
                        for v in ranked:
                            ui.label(f"{v.vector_name}: {v.positioned_median / raw_total:.0%}").classes(
                                "text-sm text-white mt-1"
                            )
                            for driver in v.primary_drivers:
                                ui.label(f"  {driver}").classes("text-xs text-slate-400")

            if result.dispersion:
                with ui.expansion("Dispersion (burstiness over time)", icon="ssid_chart").classes(
                    "w-full bg-slate-800 border-slate-700"
                ):
                    ui.label(
                        "How much the rate is shaken in time by shared shocks (campaign waves, mass "
                        "exploitation). For simulating event counts: negative binomial instead of Poisson. "
                        "Never changes the TEF estimate."
                    ).classes("text-xs text-slate-400")
                    rows = [("Total", result.total_dispersion, result.total_positioned_median)]
                    rows += [(v.vector_name, result.dispersion.get("vectors", {}).get(v.telemetry_key),
                              v.positioned_median) for v in result.vectors]
                    with ui.grid(columns=5).classes("w-full gap-x-4 gap-y-1 mt-2"):
                        for head in ("", "Shape r (month)", "Annual shape", "VMR at your rate", "Basis"):
                            ui.label(head).classes("text-xs text-slate-500")
                        for name, d, rate in rows:
                            ui.label(name).classes("text-sm text-white")
                            if d is None or d.is_poisson:
                                ui.label("Poisson").classes("text-xs font-mono text-slate-400")
                                for _ in range(3):
                                    ui.label("—").classes("text-xs text-slate-500")
                                continue
                            ui.label(f"{d.shape_r:g}").classes("text-xs font-mono text-white").tooltip(d.source)
                            ui.label(f"{d.annual_shape:g}").classes("text-xs font-mono text-white")
                            ui.label(f"{d.vmr(rate):.4f}").classes("text-xs font-mono text-white")
                            ui.label(d.basis).classes("text-xs text-slate-400")
                    with ui.column().classes("gap-0 mt-2"):
                        for name, d, _ in rows:
                            if d is not None and not d.is_poisson:
                                ui.label(f"{name}: {d.source}").classes("text-xs text-slate-500")
                    td = result.total_dispersion
                    timescale = td.timescale if td is not None else "month"
                    ui.label(
                        f"Timescale: {timescale} "
                        f"({'independent monthly shocks, annual shape 12 r' if timescale == 'month' else 'one shock lasts the year, annual shape r'}). "
                        "Poisson where no public series supports a fit. Set in config.yaml → dispersion."
                    ).classes("text-xs text-slate-500 mt-2")

            if result.has_credibility_data:
                with ui.expansion("Credibility Adjustment", icon="tune").classes(
                    "w-full bg-slate-800 border-slate-700"
                ).props("default-opened"):
                    blended = [v for v in result.vectors if v.credibility_z is not None]
                    for v in blended:
                        with ui.row().classes("w-full justify-between items-center"):
                            ui.label(v.vector_name).classes("text-sm font-semibold text-white")
                            ui.label(f"Z={v.credibility_z:.2f}").classes(
                                "text-sm font-mono text-blue-400"
                            )
                        with ui.row().classes("w-full gap-6"):
                            ui.label(f"Prior: {v.prior_median * 100:.2f}%").classes(
                                "text-xs text-slate-400"
                            )
                            ui.label(f"Observed: {v.observed_frequency * 100:.2f}%").classes(
                                "text-xs text-slate-400"
                            )
                            ui.label(f"Blended: {v.positioned_median * 100:.2f}%").classes(
                                "text-xs font-semibold text-white"
                            )

            with ui.expansion("Sensitivity Analysis", icon="tune").classes(
                "w-full bg-slate-800 border-slate-700"
            ):
                ui.plotly(_tornado_figure(sens)).classes("w-full")
                with ui.row().classes("w-full gap-4 mt-2"):
                    for entry in sens.entries:
                        with ui.column().classes("flex-1"):
                            ui.label(entry.parameter.replace("_", " ").title()).classes(
                                "text-xs text-slate-400"
                            )
                            ui.label(
                                f"{entry.output_low:.5f} – {entry.output_high:.5f}"
                            ).classes("text-xs font-mono text-white")
                            ui.label(f"{entry.range_multiple:.1f}x range").classes(
                                "text-xs text-slate-500"
                            )
                if sens.caveats:
                    for caveat in sens.caveats:
                        ui.label(caveat).classes(
                            "text-xs text-amber-400 italic mt-2"
                        )

            with ui.expansion("Audit Trail", icon="fact_check").classes(
                "w-full bg-slate-800 border-slate-700"
            ):
                if result.validation_checks:
                    ui.label("Validation Checks").classes("text-xs font-semibold text-slate-400")
                    for check in result.validation_checks:
                        if check.strip():
                            ui.label(f"+ {check}").classes("text-xs font-mono text-slate-300")
                if result.warnings:
                    ui.label("Warnings").classes("text-xs font-semibold text-amber-400 mt-2")
                    for warn in result.warnings:
                        ui.label(f"! {warn}").classes("text-xs text-amber-300")

        # Compare
        if self.compare_container is not None:
            self.compare_container.clear()
        if self.state.get("compare_mode") and self.compare_container is not None:
            compare_state = {
                **self.state,
                "sector": self.state_b["sector"],
                "revenue_band": self.state_b["revenue_band"],
                "geography": self.state_b["geography"],
                "remote_access": self.state_b.get("remote_access", ["none"]),
                "employees": self.state_b.get("employees"),
            }
            out_b = _run_estimate(compare_state, self.config_state)

            if out_b and not out_b["error"]:
                result_b = out_b["result"]
                s_b = result_b.summary
                with self.compare_container:
                    with ui.card().classes("w-full bg-slate-800 border-slate-700"):
                        ui.label(f"Profile B — {result_b.scenario_name}").classes(
                            "text-lg font-bold text-white"
                        )
                        with ui.row().classes("w-full gap-8 mt-2"):
                            with ui.column().classes("items-center"):
                                ui.label(s_b.annual_probability_pct).classes(
                                    "text-3xl font-bold"
                                ).style(f"color: {ACCENT}")
                                ui.label("Annual Probability").classes("text-xs text-slate-400")
                            with ui.column().classes("items-center"):
                                recur_b = (
                                    f"~1 in {s_b.recurrence_years:.0f}"
                                    if s_b.recurrence_years < 1e6 else "N/A"
                                )
                                ui.label(recur_b).classes("text-3xl font-bold text-blue-400")
                                ui.label("Year Recurrence").classes("text-xs text-slate-400")

                        delta = result_b.total_positioned_median - result.total_positioned_median
                        delta_pct = delta * 100
                        sign = "+" if delta >= 0 else ""
                        color = "text-red-400" if delta > 0 else ("text-green-400" if delta < 0 else "text-slate-400")
                        ui.label(
                            f"Delta: {sign}{delta_pct:.2f}pp vs Profile A"
                        ).classes(f"text-sm font-semibold {color} mt-2")

                        ui.plotly(_vector_bar_figure(result_b)).classes("w-full h-20 mt-2")

    # ================================================================
    # TELEMETRY TAB
    # ================================================================

    def _build_telemetry_tab(self):
        with ui.column().classes("w-full p-6 gap-4"):
            if not HAS_TELEMETRY:
                with ui.card().classes("w-full bg-slate-800 border-slate-700"):
                    ui.label("Telemetry Not Installed").classes("text-xl font-bold text-amber-400")
                    ui.label(
                        "Install the telemetry extra to enable continuous monitoring:"
                    ).classes("text-sm text-slate-300 mt-2")
                    ui.code("pip install tef-estimator[telemetry]").classes("mt-2")
                return

            self._build_telemetry_content()

    def _build_telemetry_content(self):
        # Controls row
        with ui.card().classes("w-full bg-slate-800 border-slate-700"):
            with ui.row().classes("w-full items-center gap-4"):
                ui.label("Telemetry Monitoring").classes("text-xl font-bold text-white flex-1")
                ui.button("Initialize DB", icon="storage",
                          on_click=self._telem_init).props("flat color=blue dense")
                self.telem_source_select = ui.select(
                    {"all": "All Sources", "dshield": "DShield", "cisa_kev": "CISA KEV",
                     "ransomware_live": "Ransomware.live", "greynoise": "GreyNoise",
                     "annual_report_monitor": "Annual Reports",
                     "iris": "IRIS Reference", "vector_benchmarks": "Vector Benchmarks"},
                    value="all", label="Source",
                ).classes("w-48").props("dense outlined dark")
                ui.button("Collect", icon="download",
                          on_click=self._telem_collect).props("flat color=green dense")
                ui.button("Collect (Force)", icon="bolt",
                          on_click=self._telem_collect_force).props("flat color=orange dense")

        # Source health
        with ui.card().classes("w-full bg-slate-800 border-slate-700"):
            ui.label("Source Health").classes("text-sm font-semibold text-slate-300 mb-2")
            self.telem_health_container = ui.row().classes("w-full gap-3 flex-wrap")

        self._refresh_health()

        # Compare controls
        with ui.card().classes("w-full bg-slate-800 border-slate-700"):
            ui.label("Change Detection").classes("text-sm font-semibold text-slate-300 mb-2")
            with ui.row().classes("w-full items-center gap-4"):
                ui.label("Threshold:").classes("text-sm text-slate-400")
                ui.slider(
                    min=0.05, max=0.50, step=0.05, value=self.telem_threshold,
                    on_change=lambda e: setattr(self, "telem_threshold", e.value),
                ).classes("flex-1").props("label-always color=red")
                ui.button("Snapshot Baseline", icon="camera_alt",
                          on_click=self._telem_baseline).props("flat color=blue dense")
                ui.button("Compare Now", icon="compare_arrows",
                          on_click=self._telem_compare).props("flat color=red dense")

            self.telem_signals_container = ui.column().classes("w-full mt-2")

        # History
        with ui.card().classes("w-full bg-slate-800 border-slate-700"):
            with ui.row().classes("w-full items-center justify-between mb-2"):
                ui.label("Collection History (7-day rolling averages)").classes(
                    "text-sm font-semibold text-slate-300"
                )
                ui.button("Refresh", icon="refresh",
                          on_click=self._refresh_history).props("flat dense color=grey")
            self.telem_history_container = ui.column().classes("w-full")

        self._refresh_history()

    def _get_telem_db(self) -> TelemetryDB | None:
        if self.telem_db is None:
            self.telem_db = TelemetryDB()
        if not self.telem_db.db_path.exists():
            return None
        return self.telem_db

    async def _telem_init(self):
        db = TelemetryDB()
        await run.io_bound(db.initialize)
        self.telem_db = db
        ui.notify("Database initialized", type="positive")
        self._refresh_health()

    async def _telem_collect(self):
        db = self._get_telem_db()
        if db is None:
            ui.notify("Initialize the database first", type="warning")
            return
        ui.notify("Collecting...", type="info")
        source = self.telem_source_select.value if self.telem_source_select else "all"
        source_filter = None if source == "all" else source
        results = await run.io_bound(
            lambda: run_due_collections(db, source_filter=source_filter)
        )
        total = sum(r.get("records_inserted", 0) for r in results)
        ui.notify(f"Done: {total} records inserted", type="positive")
        self._refresh_health()
        self._refresh_history()

    async def _telem_collect_force(self):
        db = self._get_telem_db()
        if db is None:
            ui.notify("Initialize the database first", type="warning")
            return
        ui.notify("Force collecting all sources...", type="info")
        results = await run.io_bound(lambda: collect_all(db))
        total = sum(r.get("records_inserted", 0) for r in results)
        ui.notify(f"Done: {total} records inserted", type="positive")
        self._refresh_health()
        self._refresh_history()

    async def _telem_baseline(self):
        db = self._get_telem_db()
        if db is None:
            ui.notify("Initialize the database first", type="warning")
            return
        bl = await run.io_bound(lambda: snapshot_baseline(db))
        total = sum(len(v) for v in bl.values())
        ui.notify(f"Baseline saved: {total} metrics", type="positive")

    async def _telem_compare(self):
        db = self._get_telem_db()
        if db is None:
            ui.notify("Initialize the database first", type="warning")
            return
        result = await run.io_bound(lambda: compare(db, threshold=self.telem_threshold))

        if self.telem_signals_container:
            self.telem_signals_container.clear()
            with self.telem_signals_container:
                if not result.has_signals:
                    ui.label(
                        f"No signals detected ({result.metrics_checked} metrics checked, "
                        f"threshold={result.threshold:.0%})"
                    ).classes("text-sm text-green-400")
                else:
                    ui.label(
                        f"{len(result.signals)} signal(s) detected"
                    ).classes("text-sm font-semibold text-red-400 mb-2")

                    columns = [
                        {"name": "source", "label": "Source", "field": "source", "align": "left"},
                        {"name": "metric", "label": "Metric", "field": "metric", "align": "left"},
                        {"name": "baseline", "label": "Baseline", "field": "baseline", "align": "right"},
                        {"name": "current", "label": "Current", "field": "current", "align": "right"},
                        {"name": "change", "label": "Change", "field": "change", "align": "right"},
                        {"name": "direction", "label": "Dir", "field": "direction", "align": "center"},
                    ]
                    rows = [
                        {
                            "source": sig.source_id,
                            "metric": sig.metric_name.replace("_7d_avg", ""),
                            "baseline": f"{sig.baseline_value:.2f}",
                            "current": f"{sig.current_value:.2f}",
                            "change": f"{sig.pct_change:+.1%}",
                            "direction": sig.direction,
                        }
                        for sig in result.signals
                    ]
                    ui.table(columns=columns, rows=rows).classes(
                        "w-full"
                    ).props("dense flat dark")

    def _refresh_health(self):
        if self.telem_health_container is None:
            return
        self.telem_health_container.clear()

        db = self._get_telem_db()
        if db is None:
            with self.telem_health_container:
                ui.label("Database not initialized").classes("text-sm text-amber-400")
                ui.label("Click 'Initialize DB' to create the telemetry database.").classes(
                    "text-xs text-slate-500"
                )
            return

        try:
            conn = db.connect()
            health = db.get_source_health(conn)
            conn.close()
        except Exception:
            with self.telem_health_container:
                ui.label("Could not read database").classes("text-sm text-red-400")
            return

        with self.telem_health_container:
            for h in health:
                color = "bg-red-900/50 border-red-700" if h.staleness_flag else (
                    "bg-green-900/30 border-green-800" if h.last_success else
                    "bg-slate-900 border-slate-700"
                )
                with ui.card().classes(f"w-44 {color}").style("min-height: 90px"):
                    ui.label(h.source_id.replace("_", " ").upper()).classes(
                        "text-xs font-bold text-slate-300"
                    )
                    if h.last_success:
                        ts = h.last_success[:16].replace("T", " ")
                        ui.label(f"Last: {ts}").classes("text-xs text-green-400")
                    else:
                        ui.label("Never collected").classes("text-xs text-slate-500")
                    fails = h.consecutive_failures
                    if fails > 0:
                        ui.label(f"{fails} failures").classes("text-xs text-red-400")
                    if h.staleness_flag:
                        ui.label("STALE").classes("text-xs font-bold text-red-400")

    def _refresh_history(self):
        if self.telem_history_container is None:
            return
        self.telem_history_container.clear()

        db = self._get_telem_db()
        if db is None:
            with self.telem_history_container:
                ui.label("No data yet").classes("text-sm text-slate-500")
            return

        try:
            conn = db.connect()
            cursor = conn.cursor()
            cursor.execute(
                """SELECT series_date, metric_name, value
                   FROM time_series
                   WHERE metric_name LIKE '%_7d_avg'
                   ORDER BY series_date
                   LIMIT 2000"""
            )
            rows = cursor.fetchall()
            conn.close()
        except Exception:
            with self.telem_history_container:
                ui.label("No time series data").classes("text-sm text-slate-500")
            return

        with self.telem_history_container:
            if not rows:
                ui.label(
                    "No time series data yet. Run a collection and it will appear here."
                ).classes("text-sm text-slate-500")
            else:
                ui.plotly(_history_figure(rows)).classes("w-full")

    # ================================================================
    # SCENARIO BUILDER TAB
    # ================================================================

    def _build_scenario_tab(self):
        with ui.row().classes("w-full gap-4 p-6").style("min-height: calc(100vh - 160px)"):
            # Left: form
            with ui.column().classes("flex-1 gap-4"):
                with ui.card().classes("w-full bg-slate-800 border-slate-700"):
                    ui.label("Custom Scenario Builder").classes("text-xl font-bold text-white mb-4")

                    with ui.row().classes("w-full gap-4"):
                        ui.input(
                            "Scenario Name", value=self.scen_state["name"],
                            on_change=lambda e: self._scen_set("name", e.value),
                        ).classes("flex-1").props("dense outlined dark")
                        ui.input(
                            "Slug", value=self.scen_state["slug"],
                            on_change=lambda e: self._scen_set("slug", e.value),
                        ).classes("w-48").props("dense outlined dark")

                # Vector proportions
                with ui.card().classes("w-full bg-slate-800 border-slate-700"):
                    with ui.row().classes("w-full items-center justify-between"):
                        ui.label("Vector Proportions").classes("text-sm font-semibold text-slate-300")
                        self.scen_sum_label = ui.label("").classes("text-sm font-mono")
                    self._update_sum_label()

                    for vec in ["exploitation", "credential", "phishing", "supply_chain"]:
                        self._build_vector_row(vec)

                # Base rate
                with ui.card().classes("w-full bg-slate-800 border-slate-700"):
                    ui.label("Base Rate (annual probability)").classes(
                        "text-sm font-semibold text-slate-300 mb-2"
                    )
                    with ui.row().classes("w-full gap-4"):
                        for key, label in [("low", "Low"), ("mode", "Mode"), ("high", "High")]:
                            ui.number(
                                label, value=self.scen_state["base_rate"][key],
                                min=0.0001, max=1.0, step=0.001, format="%.4f",
                                on_change=lambda e, k=key: self._scen_set_nested(
                                    "base_rate", k, e.value
                                ),
                            ).classes("flex-1").props("dense outlined dark")

                # Overall share
                with ui.card().classes("w-full bg-slate-800 border-slate-700"):
                    ui.number(
                        "Overall Share of Incidents",
                        value=self.scen_state["overall_share"],
                        min=0.01, max=1.0, step=0.01, format="%.2f",
                        on_change=lambda e: self._scen_set("overall_share", e.value),
                    ).classes("w-64").props("dense outlined dark")

                # Actions
                with ui.card().classes("w-full bg-slate-800 border-slate-700"):
                    with ui.row().classes("w-full gap-4"):
                        ui.button("Save Scenario", icon="save",
                                  on_click=self._scen_save).props("color=green")
                        ui.button("Preview Estimate", icon="preview",
                                  on_click=self._scen_preview).props("color=blue")
                        ui.upload(
                            label="Load JSON", auto_upload=True,
                            on_upload=self._scen_upload,
                        ).classes("w-48").props("flat dense dark accept=.json")

                # Saved scenarios list
                with ui.card().classes("w-full bg-slate-800 border-slate-700"):
                    ui.label("Saved Scenarios").classes("text-sm font-semibold text-slate-300 mb-2")
                    self.scen_list_container = ui.column().classes("w-full gap-1")
                self._refresh_scenario_list()

            # Right: preview
            with ui.column().classes("w-96 gap-4"):
                with ui.card().classes("w-full bg-slate-800 border-slate-700 sticky top-4"):
                    ui.label("Preview").classes("text-sm font-semibold text-slate-300 mb-2")
                    self.scen_preview_container = ui.column().classes("w-full gap-2")
                    with self.scen_preview_container:
                        ui.label(
                            "Click 'Preview Estimate' to see what this scenario produces."
                        ).classes("text-sm text-slate-500")

    def _build_vector_row(self, vec: str):
        label = vec.replace("_", " ").title()
        colors = {
            "exploitation": "#E74C3C", "credential": "#3498DB",
            "phishing": "#F39C12", "supply_chain": "#2ECC71",
        }
        with ui.row().classes("w-full items-center gap-2 mt-2"):
            ui.label(label).classes("w-28 text-sm font-semibold").style(
                f"color: {colors.get(vec, 'white')}"
            )
            for key, lbl in [("low", "L"), ("mode", "M"), ("high", "H")]:
                ui.number(
                    lbl, value=self.scen_state[vec][key],
                    min=0.0, max=1.0, step=0.01, format="%.2f",
                    on_change=lambda e, v=vec, k=key: self._scen_set_nested(v, k, e.value),
                ).classes("w-24").props("dense outlined dark")

    def _scen_set(self, key: str, value):
        self.scen_state[key] = value

    def _scen_set_nested(self, parent: str, key: str, value):
        if value is not None:
            self.scen_state[parent][key] = value
            self._update_sum_label()

    def _update_sum_label(self):
        if self.scen_sum_label is None:
            return
        modes = sum(
            self.scen_state[v]["mode"]
            for v in ["exploitation", "credential", "phishing", "supply_chain"]
        )
        if 0.95 <= modes <= 1.05:
            self.scen_sum_label.text = f"Sum: {modes:.2f}"
            self.scen_sum_label.classes(replace="text-sm font-mono text-green-400")
        elif 0.85 <= modes <= 1.15:
            self.scen_sum_label.text = f"Sum: {modes:.2f} (acceptable)"
            self.scen_sum_label.classes(replace="text-sm font-mono text-amber-400")
        else:
            self.scen_sum_label.text = f"Sum: {modes:.2f} (should be ~1.0)"
            self.scen_sum_label.classes(replace="text-sm font-mono text-red-400")

    def _scen_to_dict(self) -> dict:
        s = self.scen_state
        return {
            "scenario_name": s["name"],
            "scenario_slug": s["slug"],
            "vector_proportions": {
                vec: [s[vec]["low"], s[vec]["mode"], s[vec]["high"]]
                for vec in ["exploitation", "credential", "phishing", "supply_chain"]
            },
            "base_rate": {
                "consensus": [s["base_rate"]["low"], s["base_rate"]["mode"], s["base_rate"]["high"]],
            },
            "overall_share": s["overall_share"],
        }

    def _scen_save(self):
        data = self._scen_to_dict()
        SCENARIOS_DIR.mkdir(parents=True, exist_ok=True)
        path = SCENARIOS_DIR / f"{data['scenario_slug']}.json"
        path.write_text(json.dumps(data, indent=2))
        ui.notify(f"Saved: {path.name}", type="positive")
        self._refresh_scenario_list()
        if self.scenario_toggle:
            self.scenario_toggle.options = _all_scenario_options()
            self.scenario_toggle.update()

    def _scen_preview(self):
        if self.scen_preview_container is None:
            return
        self.scen_preview_container.clear()

        data = self._scen_to_dict()
        try:
            from tef_estimator.data.scenarios.custom import CustomScenario
            scenario = CustomScenario(data)
            engine = TEFEngine(scenario=scenario)

            profile = OrganizationProfile(
                sector=Sector(self.state["sector"]),
                revenue_band=RevenueBand(self.state["revenue_band"]),
                geography=Geography(self.state["geography"]),
                remote_access=[RemoteAccessType.NONE],
            )
            result = engine.estimate(profile)
            s = result.summary

            with self.scen_preview_container:
                ui.label(f"{scenario.scenario_name}").classes("text-lg font-bold text-white")

                with ui.row().classes("w-full gap-6 mt-2"):
                    with ui.column().classes("items-center"):
                        ui.label(s.annual_probability_pct).classes(
                            "text-4xl font-bold"
                        ).style(f"color: {ACCENT}")
                        ui.label("Annual Probability").classes("text-xs text-slate-400")
                    with ui.column().classes("items-center"):
                        recur = (
                            f"~1 in {s.recurrence_years:.0f}"
                            if s.recurrence_years < 1e6 else "N/A"
                        )
                        ui.label(recur).classes("text-4xl font-bold text-blue-400")
                        ui.label("Year Recurrence").classes("text-xs text-slate-400")

                ui.plotly(_vector_bar_figure(result)).classes("w-full h-16 mt-2")

                ui.separator().classes("bg-slate-700 my-2")
                ui.label(s.one_sentence).classes("text-xs text-slate-400 italic")

                ui.label(
                    f"Using profile: {self.state['sector']} / {self.state['revenue_band']} / {self.state['geography']}"
                ).classes("text-xs text-slate-500 mt-2")

        except Exception as e:
            with self.scen_preview_container:
                ui.label(f"Error: {e}").classes("text-sm text-red-400")

    def _scen_upload(self, event):
        try:
            content = event.content.read().decode("utf-8")
            data = json.loads(content)
            self.scen_state["name"] = data.get("scenario_name", "")
            self.scen_state["slug"] = data.get("scenario_slug", "")
            vp = data.get("vector_proportions", {})
            for vec in ["exploitation", "credential", "phishing", "supply_chain"]:
                vals = vp.get(vec, [0.25, 0.25, 0.25])
                self.scen_state[vec] = {"low": vals[0], "mode": vals[1], "high": vals[2]}
            br = data.get("base_rate", {}).get("consensus", [0.005, 0.015, 0.04])
            self.scen_state["base_rate"] = {"low": br[0], "mode": br[1], "high": br[2]}
            self.scen_state["overall_share"] = data.get("overall_share", 0.10)
            ui.notify(f"Loaded: {data.get('scenario_name', 'Unknown')}", type="positive")
            ui.navigate.reload()
        except Exception as e:
            ui.notify(f"Load failed: {e}", type="negative")

    def _refresh_scenario_list(self):
        if self.scen_list_container is None:
            return
        self.scen_list_container.clear()

        customs = _discover_custom_scenarios()
        if not customs:
            with self.scen_list_container:
                ui.label("No saved scenarios yet").classes("text-sm text-slate-500")
            return

        with self.scen_list_container:
            for slug, path in customs.items():
                try:
                    data = json.loads(path.read_text())
                    name = data.get("scenario_name", slug)
                except Exception:
                    name = slug

                with ui.row().classes("w-full items-center justify-between"):
                    ui.label(f"{name} ({slug})").classes("text-sm text-white")
                    with ui.row().classes("gap-1"):
                        ui.button(
                            icon="play_arrow",
                            on_click=lambda s=slug: self._scen_use(s),
                        ).props("flat dense round color=blue size=sm").tooltip("Use in Estimate tab")
                        ui.button(
                            icon="delete",
                            on_click=lambda p=path: self._scen_delete(p),
                        ).props("flat dense round color=red size=sm").tooltip("Delete")

    def _scen_use(self, slug: str):
        self.state["scenario"] = slug
        if self.scenario_toggle:
            self.scenario_toggle.options = _all_scenario_options()
            self.scenario_toggle.value = slug
            self.scenario_toggle.update()
        ui.notify(f"Switched to scenario: {slug}", type="info")
        self.tabs.value = self.tab_estimate
        self._update_estimate()

    def _scen_delete(self, path: Path):
        path.unlink(missing_ok=True)
        ui.notify(f"Deleted: {path.name}", type="warning")
        self._refresh_scenario_list()
        if self.scenario_toggle:
            self.scenario_toggle.options = _all_scenario_options()
            self.scenario_toggle.update()


# ====================================================================
# Launch
# ====================================================================

def launch(port: int = 8080, reload: bool = False):
    @ui.page("/")
    def index():
        TEFEstimatorApp().build()

    ui.run(
        title="TEF Estimator",
        port=port,
        reload=reload,
        show=True,
        dark=True,
        favicon="🛡️",
    )
