"""Collector registry and bulk collection."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tef_estimator.telemetry.collectors.base import CollectionSummary
    from tef_estimator.telemetry.db import TelemetryDB


def get_all_collectors() -> list:
    from tef_estimator.telemetry.collectors.dshield import DShieldCollector
    from tef_estimator.telemetry.collectors.ransomware_live import RansomwareLiveCollector
    from tef_estimator.telemetry.collectors.cisa_kev import CISAKEVCollector
    from tef_estimator.telemetry.collectors.annual_report import AnnualReportCollector
    from tef_estimator.telemetry.collectors.iris_reference import IRISReferenceCollector
    from tef_estimator.telemetry.collectors.vector_benchmarks import VectorBenchmarksCollector

    return [
        DShieldCollector(),
        RansomwareLiveCollector(),
        CISAKEVCollector(),
        AnnualReportCollector(),
        IRISReferenceCollector(),
        VectorBenchmarksCollector(),
    ]


def collect_all(db: TelemetryDB, **kwargs) -> list[CollectionSummary]:
    """Run all collectors and return summaries."""
    results = []
    for collector in get_all_collectors():
        try:
            summary = collector.collect(db, **kwargs)
            results.append(summary)
        except Exception as e:
            results.append({
                "source": collector.SOURCE_ID,
                "status": "failed",
                "records_inserted": 0,
                "records_skipped": 0,
                "error": str(e),
            })
    return results
