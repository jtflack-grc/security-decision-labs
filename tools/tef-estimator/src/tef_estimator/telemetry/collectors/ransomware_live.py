"""Ransomware.live victim telemetry collector.

Two feeds:
  - the bulk victims.json: daily victim counts by discovery date, and the
    group census. It carries no attack date.
  - the monthly API (v2/victims/YYYY/MM): victims by attack date, the series
    that times attacks (the dispersion shape describes when attacks happen;
    discovery dates add crawler and batch-posting timing). Months are cached;
    only months still filling with late postings are refetched.
"""

from __future__ import annotations

import json
import logging
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

from tef_estimator.config import get_config
from tef_estimator.dispersion_fit import month_range, shift_month
from tef_estimator.telemetry.collectors.base import CollectionSummary
from tef_estimator.telemetry.db import TelemetryDB

log = logging.getLogger(__name__)

SOURCE_ID = "ransomware_live"
EVENT_TYPE = "ransomware_activity"
VICTIMS_URL = "https://data.ransomware.live/victims.json"
MONTH_URL = "https://api.ransomware.live/v2/victims/{year}/{month:02d}"
REQUEST_TIMEOUT = 120


def _normalize_date(raw_date: str | None) -> str | None:
    if not raw_date:
        return None
    raw_date = raw_date.strip()

    if "T" in raw_date:
        try:
            return datetime.fromisoformat(raw_date).strftime("%Y-%m-%d")
        except ValueError:
            pass

    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(raw_date, fmt).strftime("%Y-%m-%d")
        except ValueError:
            continue

    return None


def _filter_and_aggregate(
    victims: list[dict],
) -> tuple[dict[str, int], dict[str, int]]:
    daily_counts: dict[str, int] = defaultdict(int)
    group_counts: dict[str, int] = defaultdict(int)

    for victim in victims:
        discovered = _normalize_date(victim.get("discovered"))
        if not discovered:
            continue

        daily_counts[discovered] += 1

        group_name = victim.get("group_name")
        if group_name:
            group_counts[group_name] += 1

    return dict(daily_counts), dict(group_counts)


def _dedup(victims: list[dict]) -> list[dict]:
    """One record per victim post (group, victim, discovery time); the last one wins."""
    return list({(v.get("group"), v.get("victim"), v.get("discovered")): v for v in victims}.values())


def _attack_counts(victims: list[dict]) -> tuple[dict[str, int], int]:
    """Daily counts by attack date over deduplicated victims.

    Victims without a disclosed attack date count on their discovery date,
    as ransomware.live itself does. Returns (counts, victims with an attack date).
    """
    counts: dict[str, int] = defaultdict(int)
    with_attack_date = 0
    for victim in _dedup(victims):
        attacked = _normalize_date(victim.get("attackdate"))
        day = attacked or _normalize_date(victim.get("discovered"))
        if day is None:
            continue
        if attacked:
            with_attack_date += 1
        counts[day] += 1
    return dict(counts), with_attack_date


def _attack_counts_by_country(victims: list[dict]) -> tuple[dict[str, int], dict[str, int]]:
    """Daily attack-date counts of US victims and of victims with a known country.

    Same deduplication and dating as ``_attack_counts``; the operational-tempo
    anchor allocates the unknown-country rest by the US share among the known.
    """
    us: dict[str, int] = defaultdict(int)
    known: dict[str, int] = defaultdict(int)
    for victim in _dedup(victims):
        day = (_normalize_date(victim.get("attackdate"))
               or _normalize_date(victim.get("discovered")))
        country = (victim.get("country") or "").strip().upper()
        if day is None or not country:
            continue
        known[day] += 1
        if country == "US":
            us[day] += 1
    return dict(us), dict(known)


def attack_months_to_fetch(now: datetime) -> tuple[list[str], set[str]]:
    """(all months to hold, months still filling) for the ransomware live refit."""
    series = get_config().dispersion["live"]["series"]["ransomware"]
    current = now.strftime("%Y-%m")
    censor = series.get("censor_months", 0)
    first = shift_month(current, -(series["window_months"] + censor + 1))
    filling = set(month_range(shift_month(current, -censor), current))
    return month_range(first, current), filling


def _read_month_cache(path: Path | None) -> dict | None:
    """A cached month, or None when absent or unreadable (it is then refetched)."""
    if path is None or not path.exists():
        return None
    try:
        cached = json.loads(path.read_text())
        datetime.fromisoformat(cached["fetched_at"])
        if not isinstance(cached["victims"], list):
            raise ValueError("victims is not a list")
        return cached
    except (ValueError, KeyError, TypeError) as e:
        log.warning("Unreadable cache %s (%s): refetching", path.name, e)
        return None


class RansomwareLiveCollector:
    SOURCE_ID = SOURCE_ID
    CADENCE_DAYS = 1

    def collect(self, db: TelemetryDB, **kwargs) -> CollectionSummary:
        collection_ts = db.collection_timestamp()
        force = bool(kwargs.get("force"))
        conn = db.connect()
        cursor = conn.cursor()
        inserted = skipped = 0
        notes: list[str] = []
        failed: list[str] = []

        bulk = self._collect_bulk(db, cursor, collection_ts, force)
        if bulk.get("error"):
            failed.append(f"bulk: {bulk['error']}")
        else:
            inserted += bulk["inserted"]
            skipped += bulk["skipped"]
            notes.append(bulk["note"])

        attack = self._collect_attack_dates(db, cursor, collection_ts, force, kwargs)
        inserted += attack["inserted"]
        skipped += attack["skipped"]
        notes.append(attack["note"])
        failed += [f"month {m}" for m in attack["failed_months"]]

        conn.commit()
        # Only once its rows are committed: a hash saved earlier would make
        # the next run skip bulk data that was never stored
        if bulk.get("hash"):
            db.save_hash(SOURCE_ID, bulk["hash"])
        ok = not bulk.get("error")
        db.update_source_health(conn, SOURCE_ID, ok, "; ".join(notes + failed))
        conn.close()

        log.info("Ransomware.live: %d inserted, %d skipped", inserted, skipped)
        summary: CollectionSummary = {
            "source": SOURCE_ID,
            "status": "completed" if ok else "failed",
            "records_inserted": inserted,
            "records_skipped": skipped,
            "collection_timestamp": collection_ts,
        }
        if not ok:
            summary["error"] = bulk["error"]
        return summary

    def _collect_bulk(self, db: TelemetryDB, cursor, collection_ts: str, force: bool) -> dict:
        log.info("Fetching ransomware.live victims...")
        try:
            response = requests.get(
                VICTIMS_URL,
                timeout=REQUEST_TIMEOUT,
                headers={"Accept": "application/json"},
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            log.error("Failed to fetch victims: %s", e)
            return {"error": str(e)}

        payload_hash = TelemetryDB.compute_hash(response.text)
        if payload_hash == db.get_last_hash(SOURCE_ID) and not force:
            log.info("No change in victims data (hash match)")
            return {"inserted": 0, "skipped": 0, "note": "bulk unchanged"}

        victims = response.json()
        if not isinstance(victims, list):
            log.error("Expected list, got %s", type(victims).__name__)
            return {"error": "Unexpected response format"}

        log.info("Processing %d victims...", len(victims))
        daily_counts, group_counts = _filter_and_aggregate(victims)
        inserted = skipped = 0

        # A day's count keeps changing until the day is over (collections run
        # mid-day): the latest collection wins.
        for date_str, count in sorted(daily_counts.items()):
            if db.upsert_observation(
                cursor, SOURCE_ID, EVENT_TYPE, date_str, "daily_victim_count",
                float(count), "count", collection_ts, payload_hash,
            ):
                inserted += 1
            else:
                skipped += 1

        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        for group_name, count in sorted(group_counts.items()):
            if db.insert_observation(
                cursor, SOURCE_ID, EVENT_TYPE, today, f"group_census_{group_name}",
                float(count), "count", collection_ts, payload_hash,
            ):
                inserted += 1
            else:
                skipped += 1

        return {
            "hash": payload_hash,
            "inserted": inserted,
            "skipped": skipped,
            "note": (f"bulk: {len(victims)} victims, {len(daily_counts)} dates, "
                     f"{len(group_counts)} groups"),
        }

    def _collect_attack_dates(self, db: TelemetryDB, cursor, collection_ts: str,
                              force: bool, kwargs: dict) -> dict:
        settings = get_config().telemetry_collectors["ransomware_live"]["attack_months"]
        now = kwargs.get("now") or datetime.now(timezone.utc)
        cache = kwargs.get("cache_dir") or db.cache_dir("ransomware_live_months")
        months, filling = attack_months_to_fetch(now)
        stale_before = now - timedelta(hours=settings["refetch_after_hours"])
        sleep = kwargs.get("sleep", time.sleep)

        records: list[dict] = []
        fetched: list[str] = []
        failed: list[str] = []
        held: set[str] = set()
        requested = False
        for month in months:
            path = Path(cache) / f"rl_{month}.json" if cache else None
            cached = _read_month_cache(path)
            if cached is not None:
                fetched_at = datetime.fromisoformat(cached["fetched_at"])
                # Settled months never change: force refetches only months still filling
                if month not in filling or (not force and fetched_at >= stale_before):
                    records += cached["victims"]
                    held.add(month)
                    continue

            year, mon = map(int, month.split("-"))
            victims, error = None, None
            for _attempt in range(1 + settings.get("retries", 0)):
                if requested:
                    sleep(settings["request_interval_seconds"])
                requested = True
                try:
                    response = requests.get(MONTH_URL.format(year=year, month=mon),
                                            timeout=REQUEST_TIMEOUT,
                                            headers={"Accept": "application/json"})
                    response.raise_for_status()
                    victims = response.json()
                    if not isinstance(victims, list):
                        raise ValueError(f"expected a list, got {type(victims).__name__}")
                    break
                except (requests.exceptions.RequestException, ValueError) as e:
                    victims, error = None, e
            if victims is None:
                log.error("Failed to fetch ransomware.live month %s: %s", month, error)
                failed.append(month)
                if cached is not None:
                    records += cached["victims"]
                    held.add(month)
                continue

            fetched.append(month)
            held.add(month)
            records += victims
            if path is not None:
                path.parent.mkdir(parents=True, exist_ok=True)
                # Written aside and renamed, so an interrupted write never leaves a partial file
                tmp = path.with_suffix(".tmp")
                tmp.write_text(json.dumps({"fetched_at": now.isoformat(), "victims": victims}))
                tmp.replace(path)

        counts, with_attack_date = _attack_counts(records)
        inserted = skipped = 0
        if records and not with_attack_date:
            log.error("No victim record from the monthly API carries an attack date — "
                      "the attack-date series is not written (field renamed upstream?)")
        else:
            # Only days of months held in full: a victim attack-dated in a month
            # whose own file is missing (before the held range, or a failed
            # fetch) is counted, but that day's count would be partial
            us_counts, known_counts = _attack_counts_by_country(records)
            for metric, series in (("daily_victim_count_by_attack", counts),
                                   ("daily_victim_count_by_attack_us", us_counts),
                                   ("daily_victim_count_by_attack_known_country", known_counts)):
                for date_str, count in sorted(series.items()):
                    if date_str[:7] not in held:
                        continue
                    if db.upsert_observation(
                        cursor, SOURCE_ID, EVENT_TYPE, date_str, metric,
                        float(count), "count", collection_ts, "monthly_api",
                    ):
                        inserted += 1
                    else:
                        skipped += 1

        note = (f"monthly API: {len(fetched)} months fetched, {len(months) - len(fetched) - len(failed)} "
                f"cached, {with_attack_date} of {len(records)} victims with an attack date")
        return {"inserted": inserted, "skipped": skipped, "note": note, "failed_months": failed}
