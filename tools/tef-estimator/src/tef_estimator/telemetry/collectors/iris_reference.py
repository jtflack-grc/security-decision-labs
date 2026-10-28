"""IRIS reference data collector — reads bundled extracted.json."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from tef_estimator.telemetry.collectors.base import CollectionSummary
from tef_estimator.telemetry.db import TelemetryDB

log = logging.getLogger(__name__)

SOURCE_ID = "iris"
EVENT_TYPE = "reference_update"

_REFERENCE_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "data" / "reference" / "iris" / "extracted.json"
)


class IRISReferenceCollector:
    SOURCE_ID = SOURCE_ID
    CADENCE_DAYS = 7

    def collect(
        self,
        db: TelemetryDB,
        **kwargs,
    ) -> CollectionSummary:
        collection_ts = db.collection_timestamp()

        if not _REFERENCE_PATH.exists():
            log.error("IRIS reference data not found: %s", _REFERENCE_PATH)
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
            log.info("IRIS data unchanged, skipping")
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
        extracted_date = data.get("_metadata", {}).get("extracted_date", "2026-01-01")

        conn = db.connect()
        cursor = conn.cursor()
        inserted = 0

        sector_mults = data.get("sector_multipliers", {})
        for sector, info in sector_mults.items():
            if sector.startswith("_"):
                continue
            if isinstance(info, dict) and "all_incident_multiplier" in info:
                was = db.insert_observation(
                    cursor, SOURCE_ID, EVENT_TYPE, extracted_date,
                    f"sector_multiplier_{sector}", info["all_incident_multiplier"],
                    "multiplier", collection_ts, current_hash,
                )
                if was:
                    inserted += 1

        rev_mults = data.get("revenue_band_multipliers", {})
        for band, info in rev_mults.items():
            if band.startswith("_"):
                continue
            if isinstance(info, dict) and "all_incident_multiplier" in info:
                was = db.insert_observation(
                    cursor, SOURCE_ID, EVENT_TYPE, extracted_date,
                    f"revenue_multiplier_{band}", info["all_incident_multiplier"],
                    "multiplier", collection_ts, current_hash,
                )
                if was:
                    inserted += 1

        floors = data.get("floor_anchors", {})
        for key in ("overall_lower_bound", "overall_upper_bound"):
            val = floors.get(key)
            if val is not None:
                was = db.insert_observation(
                    cursor, SOURCE_ID, EVENT_TYPE, extracted_date,
                    f"floor_{key}", float(val),
                    "probability", collection_ts, current_hash,
                )
                if was:
                    inserted += 1

        rw_share = data.get("ransomware_overall_share", {})
        if isinstance(rw_share, dict) and "value" in rw_share:
            was = db.insert_observation(
                cursor, SOURCE_ID, EVENT_TYPE, extracted_date,
                "ransomware_overall_share", float(rw_share["value"]),
                "proportion", collection_ts, current_hash,
            )
            if was:
                inserted += 1

        rw_sector = data.get("ransomware_sector_shares", {})
        for sector, val in rw_sector.items():
            if sector.startswith("_") or val is None:
                continue
            was = db.insert_observation(
                cursor, SOURCE_ID, EVENT_TYPE, extracted_date,
                f"ransomware_sector_share_{sector}", float(val),
                "proportion", collection_ts, current_hash,
            )
            if was:
                inserted += 1

        conn.commit()
        db.update_source_health(
            conn, SOURCE_ID, True,
            f"Imported {inserted} metrics from IRIS {data.get('_metadata', {}).get('vintage', 'unknown')}",
        )
        conn.close()
        db.save_hash(SOURCE_ID, current_hash)

        return {
            "source": SOURCE_ID,
            "status": "completed",
            "records_inserted": inserted,
            "records_skipped": 0,
            "collection_timestamp": collection_ts,
        }
