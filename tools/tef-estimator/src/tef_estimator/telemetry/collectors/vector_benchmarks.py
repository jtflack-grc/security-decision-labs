"""Vector benchmarks collector — reads bundled initial_access_vectors.json."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from tef_estimator.telemetry.collectors.base import CollectionSummary
from tef_estimator.telemetry.db import TelemetryDB

log = logging.getLogger(__name__)

SOURCE_ID = "vector_benchmarks"
EVENT_TYPE = "reference_update"

_REFERENCE_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "data" / "reference" / "vectors" / "initial_access_vectors.json"
)


class VectorBenchmarksCollector:
    SOURCE_ID = SOURCE_ID
    CADENCE_DAYS = 7

    def collect(
        self,
        db: TelemetryDB,
        **kwargs,
    ) -> CollectionSummary:
        collection_ts = db.collection_timestamp()

        if not _REFERENCE_PATH.exists():
            log.error("Vector reference data not found: %s", _REFERENCE_PATH)
            return {
                "source": SOURCE_ID,
                "status": "failed",
                "records_inserted": 0,
                "records_skipped": 0,
                "error": f"File not found: {_REFERENCE_PATH}",
            }

        content = _REFERENCE_PATH.read_text()
        current_hash = db.compute_hash(content)
        last_hash = db.get_last_hash(SOURCE_ID)

        if current_hash == last_hash and not kwargs.get("force"):
            log.info("Vector data unchanged, skipping")
            conn = db.connect()
            db.update_source_health(conn, SOURCE_ID, True, "Data unchanged")
            conn.close()
            return {
                "source": SOURCE_ID,
                "status": "completed",
                "records_inserted": 0,
                "records_skipped": 0,
                "collection_timestamp": collection_ts,
            }

        data = json.loads(content)
        records = data.get("records", [])

        conn = db.connect()
        cursor = conn.cursor()
        inserted = 0

        for rec in records:
            rec_id = rec.get("id", "")
            value = rec.get("value")
            year_range = rec.get("year_range", "")

            if value is None:
                continue

            observation_date = _year_range_to_date(year_range)
            metric_name = _normalize_vector(rec_id)
            metric_type = rec.get("metric", "unknown")
            unit = "proportion" if metric_type.startswith("pct") else "count"

            was = db.insert_observation(
                cursor, SOURCE_ID, EVENT_TYPE, observation_date,
                metric_name, float(value),
                unit, collection_ts, current_hash,
            )
            if was:
                inserted += 1

        conn.commit()

        sources = data.get("_extraction_log", {}).get("sources", [])
        source_summary = f"{len(sources)} sources, {len(records)} records"
        db.update_source_health(
            conn, SOURCE_ID, True,
            f"Imported {inserted} metrics from {source_summary}",
        )
        conn.close()
        db.save_hash(SOURCE_ID, current_hash)

        return {
            "source": SOURCE_ID,
            "status": "completed",
            "records_inserted": inserted,
            "records_skipped": len(records) - inserted,
            "collection_timestamp": collection_ts,
        }


def _year_range_to_date(year_range: str) -> str:
    if not year_range:
        return "2025-01-01"
    parts = year_range.replace(" ", "").split("-")
    last_year = parts[-1]
    if len(last_year) == 4:
        return f"{last_year}-06-01"
    return f"{year_range}-01-01"


def _normalize_vector(vector: str) -> str:
    return (
        vector.lower()
        .replace(" ", "_")
        .replace("-", "_")
    )
