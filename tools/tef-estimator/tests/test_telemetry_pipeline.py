"""Telemetry pipeline: database, integration, scheduling, shift detection."""

import json
from datetime import date, datetime, timedelta, timezone

import pytest

from tef_estimator.telemetry.compare import (
    compare,
    load_baseline,
    snapshot_baseline,
)
from tef_estimator.telemetry.db import KNOWN_SOURCES, TelemetryDB
from tef_estimator.telemetry.integrator import run_integration
from tef_estimator.telemetry.scheduler import (
    is_due,
)

@pytest.fixture
def db():
    """In-memory telemetry database for testing."""
    tdb = TelemetryDB(db_path=None)
    tdb.initialize()
    return tdb


class TestTelemetryDB:
    def test_initialize_populates_source_health(self, db):
        conn = db.connect()
        health = db.get_source_health(conn)
        conn.close()

        source_ids = {h.source_id for h in health}
        for sid, _ in KNOWN_SOURCES:
            assert sid in source_ids

    def test_retired_source_hidden_from_health(self, db):
        # A database from an earlier release still has the GreyNoise row
        conn = db.connect()
        conn.execute("INSERT INTO source_health (source_id, notes) VALUES ('greynoise', 'GreyNoise Community')")
        conn.commit()
        health = db.get_source_health(conn)
        conn.close()

        assert "greynoise" not in {h.source_id for h in health}

    def test_insert_observation(self, db):
        conn = db.connect()
        cursor = conn.cursor()
        ts = db.collection_timestamp()

        inserted = db.insert_observation(
            cursor, "dshield", "scan_activity",
            "2026-06-13", "unique_sources_port_3389", 42.0,
            "count", ts, "abc123",
        )
        conn.commit()

        assert inserted is True

        cursor.execute("SELECT metric_value FROM raw_observations WHERE metric_name = ?",
                       ("unique_sources_port_3389",))
        row = cursor.fetchone()
        conn.close()
        assert row[0] == 42.0

    def test_insert_observation_dedup(self, db):
        conn = db.connect()
        cursor = conn.cursor()
        ts = db.collection_timestamp()

        db.insert_observation(cursor, "dshield", "scan", "2026-06-13",
                              "metric_a", 10.0, "count", ts, "h1")
        first = db.insert_observation(cursor, "dshield", "scan", "2026-06-13",
                                       "metric_a", 20.0, "count", ts, "h2")
        conn.commit()
        conn.close()

        assert first is False

    def test_update_source_health_success(self, db):
        conn = db.connect()
        db.update_source_health(conn, "dshield", True, "All good")

        health = db.get_source_health(conn)
        dshield = next(h for h in health if h.source_id == "dshield")
        conn.close()

        assert dshield.last_success is not None
        assert dshield.consecutive_failures == 0
        assert dshield.staleness_flag is False

    def test_update_source_health_failure_increments(self, db):
        conn = db.connect()
        db.update_source_health(conn, "dshield", False, "Timeout")
        db.update_source_health(conn, "dshield", False, "Timeout again")

        health = db.get_source_health(conn)
        dshield = next(h for h in health if h.source_id == "dshield")
        conn.close()

        assert dshield.consecutive_failures == 2


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

    def test_gap_detection_and_interpolation(self):
        db = TelemetryDB(db_path=None)
        db.initialize()

        conn = db.connect()
        cursor = conn.cursor()
        ts = db.collection_timestamp()

        dates = _recent_dates(3)
        db.insert_observation(cursor, "dshield", "scan_activity",
                              dates[0], "unique_sources_port_443", 100.0,
                              "count", ts, "h1")
        # Skip dates[1]
        db.insert_observation(cursor, "dshield", "scan_activity",
                              dates[2], "unique_sources_port_443", 200.0,
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
               WHERE metric_name = 'unique_sources_port_443' AND series_date = ?""",
            (dates[1],),
        )
        row = cursor.fetchone()
        conn.close()

        assert row is not None
        assert row[0] == 150.0  # (100 + 200) / 2
        assert row[1] == 1  # interpolation flag


class TestDerivedAdditions:
    def test_kev_additions_zero_filled(self):
        db = TelemetryDB(db_path=None)
        db.initialize()

        conn = db.connect()
        cursor = conn.cursor()
        ts = db.collection_timestamp()

        dates = _recent_dates(5)
        for d, cve in [(dates[0], "CVE-2026-0001"), (dates[0], "CVE-2026-0002"),
                       (dates[3], "CVE-2026-0003")]:
            db.insert_observation(cursor, "cisa_kev", "vulnerability_catalog",
                                  d, f"kev_{cve}", 1.0, "binary", ts, f"h{cve}")
        # The catalog total must not pollute the additions count
        db.insert_observation(cursor, "cisa_kev", "vulnerability_catalog",
                              dates[3], "total_kev_count", 1700.0,
                              "count", ts, "htot")
        conn.commit()
        conn.close()

        run_integration(db, lookback_days=30)

        conn = db.connect()
        cursor = conn.cursor()
        cursor.execute(
            """SELECT series_date, value, interpolation_flag FROM time_series
               WHERE metric_name = 'kev_additions' ORDER BY series_date"""
        )
        rows = {r[0]: (r[1], r[2]) for r in cursor.fetchall()}
        cursor.execute(
            """SELECT COUNT(*) FROM time_series
               WHERE metric_name = 'kev_additions_7d_avg'"""
        )
        avg_count = cursor.fetchone()[0]
        conn.close()

        assert rows[dates[0]] == (2.0, 0)
        assert rows[dates[3]] == (1.0, 0)
        # Quiet days are real zero observations, never interpolated
        assert rows[dates[1]] == (0.0, 0)
        assert rows[dates[2]] == (0.0, 0)
        assert rows[dates[4]] == (0.0, 0)
        assert avg_count > 0

    def _kev_db(self, rows, collected_days_ago=0):
        from datetime import datetime, timezone
        db = TelemetryDB(db_path=None)
        db.initialize()
        conn = db.connect()
        cursor = conn.cursor()
        ts = (datetime.now(timezone.utc) - timedelta(days=collected_days_ago)).isoformat()
        for d, cve in rows:
            db.insert_observation(cursor, "cisa_kev", "vulnerability_catalog",
                                  d, f"kev_{cve}", 1.0, "binary", ts, f"h{cve}")
        conn.commit()
        conn.close()
        return db

    def _series(self, db, metric):
        conn = db.connect()
        cursor = conn.cursor()
        cursor.execute("SELECT series_date, value FROM time_series WHERE metric_name = ?", (metric,))
        rows = dict(cursor.fetchall())
        conn.close()
        return rows

    def test_zero_fill_reaches_last_successful_collection(self):
        # An unchanged catalog adds no rows, but the day was still observed
        db = self._kev_db([(_recent_dates(1, offset=8)[0], "CVE-2026-0001")], collected_days_ago=6)
        conn = db.connect()
        db.update_source_health(conn, "cisa_kev", True, "No changes detected")
        conn.commit()
        conn.close()
        run_integration(db, lookback_days=30)
        today = date.today().isoformat()
        assert self._series(db, "kev_additions").get(today) == 0.0

    def test_averages_span_full_window_at_cutoff(self):
        cutoff = (date.today() - timedelta(days=10)).isoformat()
        db = self._kev_db([(cutoff, f"CVE-2026-{i:04d}") for i in range(7)])
        run_integration(db, lookback_days=10)
        # 7 additions over 7 days, not a 1-day window giving 7
        assert self._series(db, "kev_additions_7d_avg")[cutoff] == pytest.approx(1.0)


class TestMonitoredMetrics:
    def test_is_monitored(self):
        from tef_estimator.telemetry.integrator import is_monitored
        assert is_monitored("ransomware_live", "daily_victim_count_7d_avg")
        assert not is_monitored("ransomware_live", "group_census_lockbit_7d_avg")
        assert not is_monitored("ransomware_live", "daily_victim_count_by_attack_7d_avg")
        assert is_monitored("dshield", "unique_sources_port_3389_30d_avg")
        assert not is_monitored("dshield", "total_records_port_3389_7d_avg")
        assert not is_monitored("dshield", "unique_targets_port_3389_7d_avg")
        assert is_monitored("cisa_kev", "kev_additions_7d_avg")
        assert not is_monitored("cisa_kev", "kev_CVE-2026-0001")

    def test_ransomware_census_and_attack_series_not_integrated(self):
        db = TelemetryDB(db_path=None)
        db.initialize()
        conn = db.connect()
        cursor = conn.cursor()
        ts = db.collection_timestamp()
        for i, d in enumerate(_recent_dates(3)):
            for metric in ("daily_victim_count", "daily_victim_count_by_attack",
                           "group_census_lockbit"):
                db.insert_observation(cursor, "ransomware_live", "ransomware_activity",
                                      d, metric, float(10 + i), "count", ts, f"h{metric}{i}")
        conn.commit()
        conn.close()

        run_integration(db, source_filter="ransomware_live", lookback_days=30)

        conn = db.connect()
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT metric_name FROM time_series WHERE source_id = 'ransomware_live'")
        names = {r[0] for r in cursor.fetchall()}
        conn.close()
        assert "daily_victim_count_7d_avg" in names
        assert not any(n.startswith("group_census") for n in names)
        assert not any("by_attack" in n for n in names)


class TestIsDue:
    def test_never_run_is_due(self):
        due, reason = is_due("dshield", 1, {})
        assert due is True
        assert "never" in reason

    def test_force_is_due(self):
        state = {"dshield": {"last_success": datetime.now(timezone.utc).isoformat()}}
        due, reason = is_due("dshield", 1, state, force=True)
        assert due is True
        assert reason == "forced"

    def test_recent_not_due(self):
        now = datetime.now(timezone.utc).isoformat()
        state = {"dshield": {"last_success": now}}
        due, reason = is_due("dshield", 1, state)
        assert due is False

    def test_old_is_due(self):
        old = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
        state = {"dshield": {"last_success": old}}
        due, reason = is_due("dshield", 1, state)
        assert due is True

    def test_invalid_timestamp(self):
        state = {"dshield": {"last_success": "not-a-date"}}
        due, reason = is_due("dshield", 1, state)
        assert due is True
        assert "invalid" in reason


class TestCliCollectAndIntegrate:
    def test_force_without_source_uses_scheduler(self, monkeypatch, tmp_path):
        from typer.testing import CliRunner

        from tef_estimator.telemetry import cli, scheduler
        calls = {}

        def fake_run_due(db, **kw):
            calls.update(kw)
            return [{"source": "integrator", "status": "completed"}]

        monkeypatch.setattr(scheduler, "run_due_collections", fake_run_due)
        result = CliRunner().invoke(cli.app, ["collect", "--force", "--db-path", str(tmp_path / "t.db")])
        assert result.exit_code == 0, result.output
        assert calls == {"force": True, "source_filter": None}

    def test_integrate_builds_kev_series_without_downloads(self, tmp_path):
        from datetime import date, timedelta

        from typer.testing import CliRunner

        from tef_estimator.telemetry import cli
        from tef_estimator.telemetry.db import TelemetryDB
        path = tmp_path / "t.db"
        db = TelemetryDB(db_path=path)
        db.initialize()
        conn = db.connect()
        cursor = conn.cursor()
        day = (date.today() - timedelta(days=3)).isoformat()
        db.insert_observation(cursor, "cisa_kev", "vulnerability_catalog", day,
                              "kev_CVE-2026-0001", 1.0, "binary", db.collection_timestamp(), "h")
        conn.commit()
        conn.close()

        result = CliRunner().invoke(cli.app, ["integrate", "--db-path", str(path)])
        assert result.exit_code == 0, result.output
        conn = db.connect()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM time_series WHERE metric_name = 'kev_additions_7d_avg'")
        assert cursor.fetchone()[0] > 0
        conn.close()


@pytest.fixture
def db_with_timeseries():
    """DB with time_series data suitable for baseline/compare."""
    db = TelemetryDB(db_path=None)
    db.initialize()

    conn = db.connect()
    cursor = conn.cursor()

    for metric, value in [
        ("unique_sources_port_3389_7d_avg", 100.0),
        ("unique_sources_port_445_7d_avg", 50.0),
    ]:
        cursor.execute(
            """INSERT INTO time_series
               (source_id, series_date, event_type, metric_name, value, interpolation_flag)
               VALUES (?, ?, ?, ?, ?, ?)""",
            ("dshield", "2026-06-13", "scan_activity", metric, value, 0),
        )

    conn.commit()
    conn.close()
    return db


class TestCompare:
    def test_load_baseline_missing(self, tmp_path):
        bl = load_baseline(tmp_path)
        assert bl is None

    def test_compare_with_signal(self, db_with_timeseries, tmp_path):
        snapshot_baseline(db_with_timeseries, baseline_dir=tmp_path)

        # Now change a value in time_series
        conn = db_with_timeseries.connect()
        cursor = conn.cursor()
        cursor.execute(
            """UPDATE time_series SET value = 150.0
               WHERE metric_name = 'unique_sources_port_3389_7d_avg'"""
        )
        conn.commit()
        conn.close()

        result = compare(db_with_timeseries, threshold=0.20, baseline_dir=tmp_path)
        assert result.has_signals
        assert len(result.signals) == 1

        sig = result.signals[0]
        assert sig.source_id == "dshield"
        assert sig.baseline_value == 100.0
        assert sig.current_value == 150.0
        assert sig.direction == "up"
        assert abs(sig.pct_change - 0.50) < 0.01

    def test_compare_below_threshold(self, db_with_timeseries, tmp_path):
        snapshot_baseline(db_with_timeseries, baseline_dir=tmp_path)

        conn = db_with_timeseries.connect()
        cursor = conn.cursor()
        cursor.execute(
            """UPDATE time_series SET value = 110.0
               WHERE metric_name = 'unique_sources_port_3389_7d_avg'"""
        )
        conn.commit()
        conn.close()

        result = compare(db_with_timeseries, threshold=0.20, baseline_dir=tmp_path)
        assert not result.has_signals

def _set_metric(db, metric, value, source="dshield",
                event_type="scan_activity", date="2026-06-13"):
    conn = db.connect()
    cursor = conn.cursor()
    cursor.execute(
        """INSERT OR REPLACE INTO time_series
           (source_id, series_date, event_type, metric_name, value,
            interpolation_flag)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (source, date, event_type, metric, value, 0),
    )
    conn.commit()
    conn.close()


class TestBaselineKeyDiff:
    def test_new_metric_auto_baselined(self, db_with_timeseries, tmp_path):
        snapshot_baseline(db_with_timeseries, baseline_dir=tmp_path)
        _set_metric(db_with_timeseries, "kev_additions_7d_avg", 0.4,
                    source="cisa_kev", event_type="vulnerability_catalog")

        result = compare(db_with_timeseries, baseline_dir=tmp_path)
        assert result.new_metrics == ["cisa_kev/kev_additions_7d_avg"]
        assert not result.has_signals

        baseline = load_baseline(tmp_path)
        assert baseline["cisa_kev"]["kev_additions_7d_avg"] == 0.4

        # Second compare: the metric is known now, no longer new
        result = compare(db_with_timeseries, baseline_dir=tmp_path)
        assert result.new_metrics == []

    def test_missing_metric_reported(self, db_with_timeseries, tmp_path):
        snapshot_baseline(db_with_timeseries, baseline_dir=tmp_path)

        conn = db_with_timeseries.connect()
        cursor = conn.cursor()
        cursor.execute(
            """DELETE FROM time_series
               WHERE metric_name = 'unique_sources_port_445_7d_avg'"""
        )
        conn.commit()
        conn.close()

        result = compare(db_with_timeseries, baseline_dir=tmp_path)
        assert result.missing_metrics == ["dshield/unique_sources_port_445_7d_avg"]
        assert result.metrics_checked == 1


class TestSparseSeries:
    def test_large_pct_small_delta_no_signal(self, db_with_timeseries, tmp_path):
        _set_metric(db_with_timeseries, "kev_additions_7d_avg", 0.2,
                    source="cisa_kev", event_type="vulnerability_catalog")
        snapshot_baseline(db_with_timeseries, baseline_dir=tmp_path)

        # 0.2 -> 0.9 additions/day is +350%, but the absolute change (0.7)
        # is below the sparse floor: no signal, unlike a pct test
        _set_metric(db_with_timeseries, "kev_additions_7d_avg", 0.9,
                    source="cisa_kev", event_type="vulnerability_catalog")

        result = compare(db_with_timeseries, baseline_dir=tmp_path)
        assert not result.has_signals

    def test_delta_over_floor_signals(self, db_with_timeseries, tmp_path):
        _set_metric(db_with_timeseries, "kev_additions_7d_avg", 0.2,
                    source="cisa_kev", event_type="vulnerability_catalog")
        snapshot_baseline(db_with_timeseries, baseline_dir=tmp_path)

        _set_metric(db_with_timeseries, "kev_additions_7d_avg", 1.5,
                    source="cisa_kev", event_type="vulnerability_catalog")

        result = compare(db_with_timeseries, baseline_dir=tmp_path)
        sigs = [s for s in result.signals
                if s.metric_name == "kev_additions_7d_avg"]
        assert len(sigs) == 1
        assert sigs[0].test == "abs_delta"
        assert abs(sigs[0].abs_change - 1.3) < 1e-9
        assert sigs[0].direction == "up"


class TestLastCompleteDay:
    def test_current_day_left_out(self, tmp_path):
        db = TelemetryDB(db_path=None)
        db.initialize()
        _set_metric(db, "unique_sources_port_3389_7d_avg", 100.0, date="2026-10-23")
        snapshot_baseline(db, baseline_dir=tmp_path, as_of="2026-10-24")
        # Today's partial day drags its average down; it must not signal
        _set_metric(db, "unique_sources_port_3389_7d_avg", 60.0, date="2026-10-24")
        result = compare(db, baseline_dir=tmp_path, as_of="2026-10-24")
        assert not result.has_signals
        assert result.metrics_checked == 1
        # Once the day is complete it is compared
        result = compare(db, baseline_dir=tmp_path, as_of="2026-10-25")
        assert result.has_signals

    def test_baseline_never_takes_partial_day(self, tmp_path):
        db = TelemetryDB(db_path=None)
        db.initialize()
        _set_metric(db, "unique_sources_port_3389_7d_avg", 100.0, date="2026-10-23")
        _set_metric(db, "unique_sources_port_3389_7d_avg", 60.0, date="2026-10-24")
        baseline = snapshot_baseline(db, baseline_dir=tmp_path, as_of="2026-10-24")
        assert baseline["dshield"]["unique_sources_port_3389_7d_avg"] == 100.0

    def test_sources_collected_on_different_days_all_compared(self, tmp_path):
        db = TelemetryDB(db_path=None)
        db.initialize()
        _set_metric(db, "unique_sources_port_3389_7d_avg", 100.0, date="2026-10-23")
        _set_metric(db, "kev_additions_7d_avg", 1.2, source="cisa_kev",
                    event_type="vulnerability_catalog", date="2026-10-21")
        snapshot_baseline(db, baseline_dir=tmp_path, as_of="2026-10-24")
        result = compare(db, baseline_dir=tmp_path, as_of="2026-10-24")
        assert result.missing_metrics == []
        assert result.metrics_checked == 2

    def test_stale_source_reported_missing(self, tmp_path):
        db = TelemetryDB(db_path=None)
        db.initialize()
        _set_metric(db, "unique_sources_port_3389_7d_avg", 100.0, date="2026-10-23")
        _set_metric(db, "kev_additions_7d_avg", 1.2, source="cisa_kev",
                    event_type="vulnerability_catalog", date="2026-10-23")
        snapshot_baseline(db, baseline_dir=tmp_path, as_of="2026-10-24")
        # DShield keeps arriving; KEV stops after 10-23
        _set_metric(db, "unique_sources_port_3389_7d_avg", 101.0, date="2026-10-29")
        result = compare(db, baseline_dir=tmp_path, as_of="2026-10-30")
        assert result.missing_metrics == ["cisa_kev/kev_additions_7d_avg"]


class TestRetiredMetrics:
    def test_old_baseline_census_removed_not_missing(self, tmp_path):
        db = TelemetryDB(db_path=None)
        db.initialize()
        _set_metric(db, "daily_victim_count_7d_avg", 25.0, source="ransomware_live",
                    event_type="ransomware_activity", date="2026-10-23")
        (tmp_path / "telemetry_baseline.json").write_text(json.dumps({
            "ransomware_live": {"daily_victim_count_7d_avg": 25.0,
                                "group_census_lockbit_7d_avg": 300.0},
        }))
        result = compare(db, baseline_dir=tmp_path, as_of="2026-10-24")
        assert result.missing_metrics == []
        assert result.metrics_checked == 1
        assert load_baseline(tmp_path) == {"ransomware_live": {"daily_victim_count_7d_avg": 25.0}}


class TestSparseTrailingQuantile:
    def _series(self, db, values, start="2026-07-01"):
        from datetime import date, timedelta
        d0 = date.fromisoformat(start)
        for i, v in enumerate(values):
            _set_metric(db, "kev_additions_7d_avg", v, source="cisa_kev",
                        event_type="vulnerability_catalog", date=(d0 + timedelta(days=i)).isoformat())
        return (d0 + timedelta(days=len(values) - 1)).isoformat()

    def test_signals_above_own_trailing_p95(self, tmp_path):
        from datetime import date, timedelta
        db = TelemetryDB(db_path=None)
        db.initialize()
        last = self._series(db, [1.0 + 0.01 * (i % 10) for i in range(100)] + [1.8])
        as_of = (date.fromisoformat(last) + timedelta(days=1)).isoformat()
        snapshot_baseline(db, baseline_dir=tmp_path, as_of=as_of)
        r = compare(db, baseline_dir=tmp_path, as_of=as_of)
        sig = [s for s in r.signals if s.metric_name == "kev_additions_7d_avg"]
        assert len(sig) == 1 and sig[0].test == "above_trailing_p95"
        assert sig[0].current_value == 1.8

    def test_ordinary_value_does_not_signal(self, tmp_path):
        from datetime import date, timedelta
        db = TelemetryDB(db_path=None)
        db.initialize()
        last = self._series(db, [1.0 + 0.01 * (i % 10) for i in range(101)])
        as_of = (date.fromisoformat(last) + timedelta(days=1)).isoformat()
        snapshot_baseline(db, baseline_dir=tmp_path, as_of=as_of)
        r = compare(db, baseline_dir=tmp_path, as_of=as_of)
        assert not [s for s in r.signals if s.metric_name == "kev_additions_7d_avg"]
