"""Telemetry collectors: ransomware.live attack-date series and DShield."""

import json
from datetime import datetime, timedelta, timezone

import pytest

from tef_estimator.dispersion_fit import month_range, nb2_shape
from tef_estimator.telemetry.collectors import dshield, ransomware_live
from tef_estimator.telemetry.collectors.dshield import DShieldCollector, _date_chunks
from tef_estimator.telemetry.collectors.ransomware_live import (
    RansomwareLiveCollector,
    _attack_counts,
    _filter_and_aggregate,
    attack_months_to_fetch,
)
from tef_estimator.telemetry.db import TelemetryDB
from tef_estimator.telemetry.derive import live_dispersion_config

# ransomware.live victims per month by attack date, Jun 2025 - May 2026
# (8,279 victims from the notebook's monthly caches, deduplicated)
ATTACK_2025_06_TO_2026_05 = [541, 508, 527, 564, 776, 707, 756, 718, 783, 818, 787, 750]

NOW = datetime(2026, 10, 24, 10, 0, tzinfo=timezone.utc)


def _db():
    db = TelemetryDB(db_path=None)
    db.initialize()
    return db


def _value(db, metric, date):
    conn = db.connect()
    cursor = conn.cursor()
    cursor.execute(
        """SELECT metric_value FROM raw_observations
           WHERE source_id = 'ransomware_live' AND metric_name = ? AND observation_date = ?""",
        (metric, date),
    )
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None


class _Response:
    def __init__(self, payload):
        self.text = json.dumps(payload)
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


class _FakeAPI:
    """Routes the bulk file and the monthly endpoint; records requested URLs."""

    def __init__(self, bulk, months):
        self.bulk = bulk
        self.months = months
        self.urls = []

    def get(self, url, **kwargs):
        self.urls.append(url)
        if url == ransomware_live.VICTIMS_URL:
            return _Response(self.bulk)
        year, month = url.rstrip("/").split("/")[-2:]
        return _Response(self.months.get(f"{year}-{month}", []))

    def month_requests(self):
        return [u for u in self.urls if u != ransomware_live.VICTIMS_URL]


def _victim(attack, discovered, name="v", group="g"):
    return {"victim": name, "group": group, "attackdate": attack, "discovered": discovered}


class TestAttackCounts:
    def test_counts_by_attack_date(self):
        counts, with_attack = _attack_counts([
            _victim("2026-02-20", "2026-03-10 12:00:00", "a"),
            _victim("2026-02-20", "2026-03-10 13:00:00", "b"),
            _victim("2026-03-01", "2026-03-11", "c"),
        ])
        assert counts == {"2026-02-20": 2, "2026-03-01": 1}
        assert with_attack == 3

    def test_missing_attack_date_counts_on_discovery(self):
        counts, with_attack = _attack_counts([
            _victim(None, "2026-03-10", "a"),
            _victim("2026-03-02", "2026-03-10", "b"),
        ])
        assert counts == {"2026-03-10": 1, "2026-03-02": 1}
        assert with_attack == 1

    def test_same_post_in_two_month_files_counted_once(self):
        v = _victim("2026-02-27", "2026-03-02")
        counts, _ = _attack_counts([v, dict(v)])
        assert counts == {"2026-02-27": 1}

    def test_bulk_aggregation_by_discovery(self):
        daily, groups = _filter_and_aggregate([
            {"discovered": "2026-03-10T09:55:07+00:00", "group_name": "a"},
            {"discovered": "2026-03-10", "group_name": "a"},
        ])
        assert daily == {"2026-03-10": 2}
        assert groups == {"a": 2}


class TestMonthsToFetch:
    def test_window_plus_censored_current_and_lead(self):
        months, filling = attack_months_to_fetch(NOW)
        # 12-month window + 2 censored + current + 1 leading month
        assert len(months) == 16
        assert months[0] == "2025-07"
        assert months[-1] == "2026-10"
        assert filling == {"2026-08", "2026-09", "2026-10"}


class TestUpsert:
    def test_later_collection_wins(self):
        db = _db()
        conn = db.connect()
        cursor = conn.cursor()
        args = ("ransomware_live", "ransomware_activity", "2026-03-01",
                "daily_victim_count_by_attack")
        assert db.upsert_observation(cursor, *args, 10.0, "count", "2026-03-05T08:00", "h1")
        assert db.upsert_observation(cursor, *args, 14.0, "count", "2026-04-05T08:00", "h2")
        assert not db.upsert_observation(cursor, *args, 14.0, "count", "2026-04-06T08:00", "h3")
        conn.commit()
        conn.close()
        assert _value(db, "daily_victim_count_by_attack", "2026-03-01") == 14.0

    def test_insert_observation_still_ignores(self):
        db = _db()
        conn = db.connect()
        cursor = conn.cursor()
        args = ("cisa_kev", "vulnerability_catalog", "2026-03-01", "kev_CVE-2026-0001")
        assert db.insert_observation(cursor, *args, 1.0, "binary", "t1", "h1")
        assert not db.insert_observation(cursor, *args, 2.0, "binary", "t2", "h2")
        conn.close()


class TestCollector:
    def _collect(self, monkeypatch, api, db, cache, now=NOW, **kw):
        monkeypatch.setattr(ransomware_live.requests, "get", api.get)
        sleeps = []
        RansomwareLiveCollector().collect(db, now=now, cache_dir=cache,
                                          sleep=sleeps.append, **kw)
        return sleeps

    def test_first_run_fetches_all_months_rate_limited(self, monkeypatch, tmp_path):
        api = _FakeAPI(bulk=[], months={"2026-03": [_victim("2026-03-01", "2026-03-10")]})
        sleeps = self._collect(monkeypatch, api, _db(), tmp_path)
        assert len(api.month_requests()) == 16
        assert sleeps == [61] * 15
        assert (tmp_path / "rl_2026-03.json").exists()

    def test_second_run_same_day_uses_cache(self, monkeypatch, tmp_path):
        api = _FakeAPI(bulk=[], months={})
        db = _db()
        self._collect(monkeypatch, api, db, tmp_path)
        api.urls.clear()
        self._collect(monkeypatch, api, db, tmp_path, now=NOW + timedelta(hours=2))
        assert api.month_requests() == []

    def test_next_day_refetches_only_filling_months(self, monkeypatch, tmp_path):
        api = _FakeAPI(bulk=[], months={})
        db = _db()
        self._collect(monkeypatch, api, db, tmp_path)
        api.urls.clear()
        self._collect(monkeypatch, api, db, tmp_path, now=NOW + timedelta(hours=21))
        assert [u.split("victims/")[1] for u in api.month_requests()] == \
            ["2026/08", "2026/09", "2026/10"]

    def test_late_postings_grow_attack_day(self, monkeypatch, tmp_path):
        db = _db()
        early = [_victim("2026-09-01", "2026-09-10", "a")]
        api = _FakeAPI(bulk=[], months={"2026-09": early})
        self._collect(monkeypatch, api, db, tmp_path)
        assert _value(db, "daily_victim_count_by_attack", "2026-09-01") == 1.0

        api.months["2026-09"] = early + [_victim("2026-09-01", "2026-10-02", "b")]
        self._collect(monkeypatch, api, db, tmp_path, now=NOW + timedelta(hours=21))
        assert _value(db, "daily_victim_count_by_attack", "2026-09-01") == 2.0

    def test_failed_month_retried_once(self, monkeypatch, tmp_path):
        api = _FakeAPI(bulk=[], months={"2026-03": [_victim("2026-03-01", "2026-03-10")]})
        calls = {"n": 0}
        real_get = api.get

        def flaky(url, **kw):
            if url.endswith("2026/03"):
                calls["n"] += 1
                if calls["n"] == 1:
                    raise ransomware_live.requests.exceptions.ConnectionError("reset")
            return real_get(url, **kw)

        api.get = flaky
        db = _db()
        sleeps = self._collect(monkeypatch, api, db, tmp_path)
        assert calls["n"] == 2
        assert sleeps == [61] * 16
        assert _value(db, "daily_victim_count_by_attack", "2026-03-01") == 1.0

    def test_failed_month_days_not_written(self, monkeypatch, tmp_path):
        # A June victim listed in July's file must not stand in for June
        api = _FakeAPI(bulk=[], months={"2026-07": [_victim("2026-06-30", "2026-07-02", "late"),
                                                    _victim("2026-07-03", "2026-07-04", "jul")]})
        real_get = api.get

        def june_down(url, **kw):
            if url.endswith("2026/06"):
                raise ransomware_live.requests.exceptions.ConnectionError("down")
            return real_get(url, **kw)

        api.get = june_down
        db = _db()
        self._collect(monkeypatch, api, db, tmp_path)
        assert _value(db, "daily_victim_count_by_attack", "2026-06-30") is None
        assert _value(db, "daily_victim_count_by_attack", "2026-07-03") == 1.0

    def test_days_before_held_months_not_written(self, monkeypatch, tmp_path):
        db = _db()
        api = _FakeAPI(bulk=[], months={"2025-07": [_victim("2025-05-03", "2025-07-02")]})
        self._collect(monkeypatch, api, db, tmp_path)
        assert _value(db, "daily_victim_count_by_attack", "2025-05-03") is None

    def test_no_attack_dates_writes_no_attack_series(self, monkeypatch, tmp_path):
        db = _db()
        api = _FakeAPI(bulk=[], months={"2026-03": [{"victim": "v", "discovered": "2026-03-10"}]})
        self._collect(monkeypatch, api, db, tmp_path)
        assert _value(db, "daily_victim_count_by_attack", "2026-03-10") is None

    def test_bulk_unchanged_still_refreshes_attack_months(self, monkeypatch, tmp_path):
        db = TelemetryDB(db_path=tmp_path / "t.db")
        db.initialize()
        api = _FakeAPI(bulk=[{"discovered": "2026-10-20", "group_name": "a"}], months={})
        self._collect(monkeypatch, api, db, tmp_path / "cache")
        api.urls.clear()
        api.months["2026-10"] = [_victim("2026-10-05", "2026-10-21")]
        self._collect(monkeypatch, api, db, tmp_path / "cache", now=NOW + timedelta(hours=21))
        assert _value(db, "daily_victim_count_by_attack", "2026-10-05") == 1.0

    def test_force_refetches_filling_months_only(self, monkeypatch, tmp_path):
        # Settled months never change; force refetches the current and censored ones
        api = _FakeAPI(bulk=[], months={})
        db = _db()
        self._collect(monkeypatch, api, db, tmp_path)
        api.urls.clear()
        self._collect(monkeypatch, api, db, tmp_path, now=NOW + timedelta(hours=1), force=True)
        assert len(api.month_requests()) == 3

    def test_unreadable_cache_is_refetched(self, monkeypatch, tmp_path):
        api = _FakeAPI(bulk=[], months={"2026-01": [_victim("2026-01-05", "2026-01-20")]})
        db = _db()
        self._collect(monkeypatch, api, db, tmp_path)
        (tmp_path / "rl_2026-01.json").write_text('{"fetched_at": "2026-')  # interrupted write
        api.urls.clear()
        self._collect(monkeypatch, api, db, tmp_path, now=NOW + timedelta(hours=1))
        assert [u for u in api.month_requests() if u.endswith("2026/01")]
        assert _value(db, "daily_victim_count_by_attack", "2026-01-05") == 1.0

    def test_bulk_hash_saved_only_after_rows_committed(self, monkeypatch, tmp_path):
        db = TelemetryDB(db_path=tmp_path / "t.db")
        db.initialize()
        api = _FakeAPI(bulk=[{"discovered": "2026-10-20", "group_name": "a"}], months={})
        boom = RuntimeError("attack months failed")

        def fail(*a, **k):
            raise boom
        monkeypatch.setattr(RansomwareLiveCollector, "_collect_attack_dates", fail)
        with pytest.raises(RuntimeError):
            self._collect(monkeypatch, api, db, tmp_path / "cache")
        assert db.get_last_hash("ransomware_live") is None

    def test_bulk_force_bypasses_unchanged_payload(self, monkeypatch, tmp_path):
        db = TelemetryDB(db_path=tmp_path / "t.db")
        db.initialize()
        api = _FakeAPI(bulk=[{"discovered": "2026-10-20", "group_name": "a"}], months={})
        self._collect(monkeypatch, api, db, tmp_path / "cache")
        conn = db.connect()
        conn.execute("DELETE FROM raw_observations WHERE metric_name = 'daily_victim_count'")
        conn.commit()
        conn.close()
        self._collect(monkeypatch, api, db, tmp_path / "cache", force=True)
        assert _value(db, "daily_victim_count", "2026-10-20") == 1.0


class TestRansomwareLiveRefit:
    def _db_with_months(self, monthly, collected_on, days_held=None):
        """Spread each month's total over its days, as a real collection holds it."""
        from tef_estimator.telemetry.derive import _days_in_month
        db = _db()
        conn = db.connect()
        cursor = conn.cursor()
        for month, total in monthly.items():
            n = (days_held or {}).get(month, _days_in_month(month))
            base, extra = divmod(int(total), n)
            for day in range(1, n + 1):
                db.upsert_observation(cursor, "ransomware_live", "ransomware_activity",
                                      f"{month}-{day:02d}", "daily_victim_count_by_attack",
                                      float(base + (day <= extra)), "count",
                                      f"{collected_on}T08:00:00+00:00", "h")
        conn.commit()
        conn.close()
        return db

    def test_partial_month_in_window_falls_back(self):
        months = month_range("2025-06", "2026-07")
        totals = dict(zip(months, ATTACK_2025_06_TO_2026_05 + [400, 90]))
        totals["2026-03"] = 19
        db = self._db_with_months(totals, collected_on="2026-08-15",
                                  days_held={"2026-03": 15})
        cfg, fits = live_dispersion_config(db)
        rw = [f for f in fits if f.name == "ransomware"][0]
        assert rw.status == "fallback"
        assert "incomplete month(s) in window: 2026-03" in rw.reason
        assert cfg.dispersion["scenarios"]["ransomware"]["shape_r"] == 113.7

    def test_fit_on_attack_dates_with_censoring(self):
        months = month_range("2025-06", "2026-05")
        # Collected 2026-08-15: July is the last complete month, and the two
        # censored months (June, July) are still filling with late postings,
        # so the 12-month window ends in May 2026
        filled = dict(zip(months, ATTACK_2025_06_TO_2026_05))
        filled["2026-06"] = 400
        filled["2026-07"] = 90
        db = self._db_with_months(filled, collected_on="2026-08-15")

        _, fits = live_dispersion_config(db)
        rw = [f for f in fits if f.name == "ransomware"][0]
        assert rw.status == "fitted"
        assert rw.window == ("2025-06", "2026-05")
        assert rw.shape_r == round(nb2_shape(ATTACK_2025_06_TO_2026_05).shape_r, 1)
        assert rw.bundled_shape_r == 113.7

    def test_short_history_falls_back(self):
        months = month_range("2026-01", "2026-05")
        db = self._db_with_months(dict(zip(months, [700] * 5)), collected_on="2026-08-15")
        cfg, fits = live_dispersion_config(db)
        rw = [f for f in fits if f.name == "ransomware"][0]
        assert rw.status == "fallback"
        assert cfg.dispersion["scenarios"]["ransomware"]["shape_r"] == 113.7


DS_NOW = datetime(2026, 10, 24, 10, 0, tzinfo=timezone.utc)


class _FakeISC:
    """Returns one record per day of each requested range; records the ranges."""

    def __init__(self, sources=100, fail_ranges=()):
        self.calls = []
        self.sources = sources
        self.fail_ranges = set(fail_ranges)

    def __call__(self, port, start, end):
        self.calls.append((port, start, end))
        if (port, start) in self.fail_ranges:
            return None, None
        day = datetime.strptime(start, "%Y-%m-%d")
        last = datetime.strptime(end, "%Y-%m-%d")
        out = []
        while day <= last:
            out.append({"date": day.strftime("%Y-%m-%d"), "sources": self.sources,
                        "targets": 10, "records": 1000})
            day += timedelta(days=1)
        return out, f"h{start}"


def _ds_db():
    db = TelemetryDB(db_path=None)
    db.initialize()
    return db


def _ds_value(db, metric, date):
    conn = db.connect()
    cursor = conn.cursor()
    cursor.execute("""SELECT metric_value FROM raw_observations
                      WHERE source_id = 'dshield' AND metric_name = ? AND observation_date = ?""",
                   (metric, date))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None


def _run(monkeypatch, db, fake, **kw):
    monkeypatch.setattr(dshield, "fetch_port_history", fake)
    sleeps = []
    summary = DShieldCollector().collect(db, ports=[3389, 445], now=kw.pop("now", DS_NOW),
                                         sleep=sleeps.append, **kw)
    return summary, sleeps


def test_chunks_cover_range_without_overlap():
    chunks = _date_chunks(datetime(2026, 1, 1), datetime(2026, 4, 10), 30)
    assert chunks[0] == ("2026-01-01", "2026-01-30")
    assert chunks[-1][1] == "2026-04-10"
    assert all(a[1] < b[0] for a, b in zip(chunks, chunks[1:]))


def test_empty_db_backfills_history(monkeypatch):
    fake = _FakeISC()
    db = _ds_db()
    summary, sleeps = _run(monkeypatch, db, fake)
    starts = [c[1] for c in fake.calls if c[0] == 3389]
    assert starts[0] == (DS_NOW - timedelta(days=90)).strftime("%Y-%m-%d")
    assert len(starts) == 2  # 91 days in chunks of 90
    assert len(sleeps) == len(fake.calls) - 1 and set(sleeps) == {2}
    assert summary["status"] == "completed"
    assert _ds_value(db, "unique_sources_port_3389", "2026-10-01") == 100.0


def test_resumes_from_last_stored_day(monkeypatch):
    db = _ds_db()
    _run(monkeypatch, db, _FakeISC())
    fake = _FakeISC()
    _run(monkeypatch, db, fake, now=DS_NOW + timedelta(days=3))
    assert [c[1:] for c in fake.calls if c[0] == 3389] == [("2026-10-22", "2026-10-27")]


def test_partial_current_day_is_replaced(monkeypatch):
    db = _ds_db()
    _run(monkeypatch, db, _FakeISC(sources=40))
    assert _ds_value(db, "unique_sources_port_3389", "2026-10-24") == 40.0
    _run(monkeypatch, db, _FakeISC(sources=100), now=DS_NOW + timedelta(hours=12))
    assert _ds_value(db, "unique_sources_port_3389", "2026-10-24") == 100.0


def test_failed_chunk_marks_port_but_continues(monkeypatch):
    first_start = (DS_NOW - timedelta(days=90)).strftime("%Y-%m-%d")
    fake = _FakeISC(fail_ranges={(3389, first_start)})
    db = _ds_db()
    summary, _ = _run(monkeypatch, db, fake)
    assert summary["status"] == "completed"  # port 445 succeeded
    assert _ds_value(db, "unique_sources_port_3389", "2026-10-24") == 100.0
    assert _ds_value(db, "unique_sources_port_3389", first_start) is None


def test_port_with_no_data_retried_from_history_start(monkeypatch):
    first_start = (DS_NOW - timedelta(days=90)).strftime("%Y-%m-%d")
    db = _ds_db()
    _run(monkeypatch, db, _FakeISC(fail_ranges={(3389, first_start), (3389, "2026-10-24")}))
    fake = _FakeISC()
    _run(monkeypatch, db, fake, now=DS_NOW + timedelta(hours=12))
    assert [c[1] for c in fake.calls if c[0] == 3389][0] == first_start


def test_explicit_lookback_overrides(monkeypatch):
    fake = _FakeISC()
    _run(monkeypatch, _ds_db(), fake, lookback_days=7)
    assert [c[1:] for c in fake.calls if c[0] == 3389] == [("2026-10-17", "2026-10-24")]
