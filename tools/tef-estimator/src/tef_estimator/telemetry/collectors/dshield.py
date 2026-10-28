"""DShield port scan telemetry collector."""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timedelta, timezone

import requests

from tef_estimator.config import get_config
from tef_estimator.telemetry.collectors.base import CollectionSummary
from tef_estimator.telemetry.db import TelemetryDB

log = logging.getLogger(__name__)

DEFAULT_PORTS = [3389, 445, 443, 22, 23, 8080, 8443]
REQUEST_TIMEOUT = 30
USER_AGENT = "TEF-Telemetry-Agent/0.1 (research; FAIR-TEF-estimation)"

SOURCE_ID = "dshield"
EVENT_TYPE = "scan_activity"


def fetch_port_history(
    port: int, start_date: str, end_date: str,
) -> tuple[list | None, str | None]:
    url = (
        f"https://isc.sans.edu/api/porthistory/"
        f"{port}/{start_date}/{end_date}?json"
    )
    headers = {"User-Agent": USER_AGENT}

    try:
        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()

        raw_text = response.text
        payload_hash = TelemetryDB.compute_hash(raw_text)

        data = response.json()

        if isinstance(data, dict):
            if "data" in data and isinstance(data["data"], list):
                data = data["data"]
            else:
                numbered = {}
                for k, v in data.items():
                    if k.isdigit() and isinstance(v, dict):
                        numbered[int(k)] = v
                if numbered:
                    data = [numbered[k] for k in sorted(numbered.keys())]
                else:
                    log.warning("Port %d: unexpected dict response, keys=%s",
                                port, list(data.keys()))
                    return None, None

        if not isinstance(data, list):
            log.warning("Port %d: expected list, got %s", port, type(data).__name__)
            return None, None

        if len(data) == 0:
            log.info("Port %d: empty response", port)
            return [], payload_hash

        return data, payload_hash

    except requests.exceptions.Timeout:
        log.error("Port %d: timed out after %ds", port, REQUEST_TIMEOUT)
        return None, None
    except requests.exceptions.HTTPError as e:
        log.error("Port %d: HTTP error %d", port, e.response.status_code)
        return None, None
    except requests.exceptions.ConnectionError as e:
        log.error("Port %d: connection error: %s", port, e)
        return None, None
    except json.JSONDecodeError as e:
        log.error("Port %d: invalid JSON: %s", port, e)
        return None, None


def _collect_port(
    db: TelemetryDB,
    cursor,
    port: int,
    start_date: str,
    end_date: str,
    collection_ts: str,
) -> tuple[int, int, bool]:
    log.info("Fetching port %d (%s to %s)...", port, start_date, end_date)

    data, payload_hash = fetch_port_history(port, start_date, end_date)

    if data is None:
        return 0, 0, False
    if len(data) == 0:
        return 0, 0, True

    inserted = 0
    skipped = 0

    for record in data:
        obs_date = record.get("date")
        if not obs_date:
            skipped += 1
            continue

        obs_date = str(obs_date).strip()

        metrics = {
            f"unique_sources_port_{port}": record.get("sources"),
            f"unique_targets_port_{port}": record.get("targets"),
            f"total_records_port_{port}": record.get("records"),
        }

        for metric_name, raw_value in metrics.items():
            if raw_value is None:
                skipped += 1
                continue
            try:
                metric_value = float(raw_value)
            except (ValueError, TypeError):
                skipped += 1
                continue

            # The latest collection wins: the current day is partial until it ends
            was_inserted = db.upsert_observation(
                cursor, SOURCE_ID, EVENT_TYPE,
                obs_date, metric_name, metric_value,
                "count", collection_ts, payload_hash,
            )
            if was_inserted:
                inserted += 1
            else:
                skipped += 1

    log.info("Port %d: %d inserted, %d skipped", port, inserted, skipped)
    return inserted, skipped, True


def _resume_from(cursor, port: int, earliest: datetime, overlap_days: int) -> datetime:
    """First day to fetch: the last stored day minus the overlap (partial days),
    or ``earliest`` for a port with no data since then."""
    cursor.execute(
        """SELECT MAX(observation_date) FROM raw_observations
           WHERE source_id = ? AND metric_name = ? AND observation_date >= ?""",
        (SOURCE_ID, f"unique_sources_port_{port}", earliest.strftime("%Y-%m-%d")),
    )
    last = cursor.fetchone()[0]
    if last is None:
        return earliest
    last_day = datetime.strptime(last, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    return max(earliest, last_day - timedelta(days=overlap_days))


def _date_chunks(start: datetime, end: datetime, chunk_days: int) -> list[tuple[str, str]]:
    chunks = []
    cursor = start
    while cursor <= end:
        chunk_end = min(cursor + timedelta(days=chunk_days - 1), end)
        chunks.append((cursor.strftime("%Y-%m-%d"), chunk_end.strftime("%Y-%m-%d")))
        cursor = chunk_end + timedelta(days=1)
    return chunks


class DShieldCollector:
    SOURCE_ID = SOURCE_ID
    CADENCE_DAYS = 1

    def collect(
        self,
        db: TelemetryDB,
        *,
        ports: list[int] | None = None,
        lookback_days: int | None = None,
        **kwargs,
    ) -> CollectionSummary:
        """Fill each port's daily series up to today.

        From the last stored day minus an overlap (so partial days are
        replaced), or ``history_days`` back for a port with no data; an
        explicit ``lookback_days`` overrides this.
        """
        settings = get_config().telemetry_collectors["dshield"]
        history_days = settings["history_days"]
        chunk_days = settings["chunk_days"]
        overlap_days = settings["overlap_days"]
        delay = settings["request_delay_seconds"]
        sleep = kwargs.get("sleep", time.sleep)

        ports = ports or DEFAULT_PORTS
        now = kwargs.get("now") or datetime.now(timezone.utc)
        today = datetime(now.year, now.month, now.day, tzinfo=timezone.utc)
        earliest = today - timedelta(days=history_days)
        collection_ts = db.collection_timestamp()

        log.info("Starting DShield collection")

        conn = db.connect()
        cursor = conn.cursor()

        total_inserted = 0
        total_skipped = 0
        ports_succeeded = 0
        ports_failed = 0
        requests_made = 0

        for port in ports:
            if lookback_days is not None:
                start = today - timedelta(days=lookback_days)
            else:
                start = _resume_from(cursor, port, earliest, overlap_days)

            port_ok = True
            for chunk_start, chunk_end in _date_chunks(start, today, chunk_days):
                if requests_made:
                    sleep(delay)
                requests_made += 1
                inserted, skipped, success = _collect_port(
                    db, cursor, port, chunk_start, chunk_end, collection_ts,
                )
                total_inserted += inserted
                total_skipped += skipped
                port_ok = port_ok and success
                conn.commit()

            if port_ok:
                ports_succeeded += 1
            else:
                ports_failed += 1

        health_notes = (
            f"{ports_succeeded}/{len(ports)} ports succeeded, "
            f"{total_inserted} records inserted, "
            f"{total_skipped} skipped"
        )
        db.update_source_health(conn, SOURCE_ID, ports_succeeded > 0, health_notes)
        conn.close()

        return {
            "source": SOURCE_ID,
            "status": "completed" if ports_succeeded > 0 else "failed",
            "records_inserted": total_inserted,
            "records_skipped": total_skipped,
            "collection_timestamp": collection_ts,
        }
