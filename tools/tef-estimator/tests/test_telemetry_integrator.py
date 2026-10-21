"""Tests for tef_estimator.telemetry.integrator."""

from datetime import date, timedelta

import pytest

from tef_estimator.telemetry.db import TelemetryDB
from tef_estimator.telemetry.integrator import run_integration


def _recent_dates(n: int, offset: int = 5) -> list[str]:
    """Return n consecutive date strings ending `offset` days before today."""
    end = date.today() - timedelta(days=offset)
    return [(end - timedelta(days=n - 1 - i)).isoformat() for i in range(n)]


@pytest.fixture
def db_with_data():
    """In-memory DB pre-loaded with sample raw observations."""
    db = TelemetryDB(db_path=None)
    db.initialize()

    conn = db.connect()
    cursor = conn.cursor()
    ts = db.collection_timestamp()

    dates = _recent_dates(5)
    for i, d in enumerate(dates):
        db.insert_observation(
            cursor, "dshield", "scan_activity",
            d, "unique_sources_port_3389", float(100 + i * 10),
            "count", ts, f"hash_{i}",
        )

    db.insert_observation(
        cursor, "cisa_kev", "vulnerability_catalog",
        dates[0], "kev_CVE-2026-0001", 1.0,
        "binary", ts, "kevhash",
    )

    conn.commit()
    conn.close()
    return db


class TestIntegrator:
    def test_integration_runs(self, db_with_data):
        result = run_integration(db_with_data, lookback_days=30)
        assert result["status"] == "completed"
        assert result["sources_processed"] > 0
        assert result["total_inserted"] > 0

    def test_rolling_averages_created(self, db_with_data):
        run_integration(db_with_data, lookback_days=30)

        conn = db_with_data.connect()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT DISTINCT metric_name FROM time_series WHERE source_id = 'dshield'"
        )
        metrics = {row[0] for row in cursor.fetchall()}
        conn.close()

        assert "unique_sources_port_3389" in metrics
        assert "unique_sources_port_3389_7d_avg" in metrics
        assert "unique_sources_port_3389_30d_avg" in metrics

    def test_event_source_dedup(self, db_with_data):
        result = run_integration(db_with_data, lookback_days=30)

        per_source = {r["source"]: r for r in result["per_source"]}
        assert "cisa_kev" in per_source
        assert per_source["cisa_kev"]["inserted"] == 1

    def test_source_filter(self, db_with_data):
        result = run_integration(db_with_data, source_filter="dshield", lookback_days=30)
        assert result["sources_processed"] == 1
        assert result["per_source"][0]["source"] == "dshield"

    def test_gap_detection_and_interpolation(self):
        db = TelemetryDB(db_path=None)
        db.initialize()

        conn = db.connect()
        cursor = conn.cursor()
        ts = db.collection_timestamp()

        dates = _recent_dates(3)
        db.insert_observation(cursor, "dshield", "scan_activity",
                              dates[0], "test_metric", 100.0,
                              "count", ts, "h1")
        # Skip dates[1]
        db.insert_observation(cursor, "dshield", "scan_activity",
                              dates[2], "test_metric", 200.0,
                              "count", ts, "h2")
        conn.commit()
        conn.close()

        result = run_integration(db, lookback_days=30)
        assert result["total_gaps_found"] >= 1
        assert result["total_interpolated"] >= 1

        conn = db.connect()
        cursor = conn.cursor()
        cursor.execute(
            """SELECT value, interpolation_flag FROM time_series
               WHERE metric_name = 'test_metric' AND series_date = ?""",
            (dates[1],),
        )
        row = cursor.fetchone()
        conn.close()

        assert row is not None
        assert row[0] == 150.0  # (100 + 200) / 2
        assert row[1] == 1  # interpolation flag
