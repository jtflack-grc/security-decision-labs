"""CISA Known Exploited Vulnerabilities catalog collector."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import requests

from tef_estimator.telemetry.collectors.base import CollectionSummary
from tef_estimator.telemetry.db import TelemetryDB

log = logging.getLogger(__name__)

SOURCE_ID = "cisa_kev"
EVENT_TYPE = "vulnerability_catalog"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
REQUEST_TIMEOUT = 60


class CISAKEVCollector:
    SOURCE_ID = SOURCE_ID
    CADENCE_DAYS = 1

    def collect(self, db: TelemetryDB, **kwargs) -> CollectionSummary:
        collection_ts = db.collection_timestamp()
        log.info("Fetching CISA KEV catalog...")

        try:
            response = requests.get(KEV_URL, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            log.error("Failed to fetch KEV: %s", e)
            conn = db.connect()
            db.update_source_health(conn, SOURCE_ID, False, str(e))
            conn.close()
            return {
                "source": SOURCE_ID,
                "status": "failed",
                "records_inserted": 0,
                "records_skipped": 0,
                "error": str(e),
            }

        payload_hash = TelemetryDB.compute_hash(response.text)
        last_hash = db.get_last_hash(SOURCE_ID)

        if payload_hash == last_hash and not kwargs.get("force"):
            log.info("KEV catalog unchanged (hash match)")
            conn = db.connect()
            db.update_source_health(conn, SOURCE_ID, True, "No changes detected")
            conn.close()
            return {
                "source": SOURCE_ID,
                "status": "completed",
                "records_inserted": 0,
                "records_skipped": 0,
                "collection_timestamp": collection_ts,
            }

        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        catalog_version = data.get("catalogVersion", "unknown")

        log.info("KEV catalog v%s: %d vulnerabilities", catalog_version, len(vulnerabilities))

        conn = db.connect()
        cursor = conn.cursor()

        existing_metrics = db.get_existing_metric_names(cursor, SOURCE_ID)

        inserted = 0
        skipped = 0

        for vuln in vulnerabilities:
            cve_id = vuln.get("cveID")
            date_added = vuln.get("dateAdded")

            if not cve_id or not date_added:
                skipped += 1
                continue

            metric_name = f"kev_{cve_id}"
            if metric_name in existing_metrics:
                skipped += 1
                continue

            was_inserted = db.insert_observation(
                cursor, SOURCE_ID, EVENT_TYPE,
                date_added, metric_name, 1.0,
                "binary", collection_ts, payload_hash,
            )
            if was_inserted:
                inserted += 1
                existing_metrics.add(metric_name)
            else:
                skipped += 1

        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        db.insert_observation(
            cursor, SOURCE_ID, EVENT_TYPE,
            today, "total_kev_count", float(len(vulnerabilities)),
            "count", collection_ts, payload_hash,
        )

        conn.commit()
        db.save_hash(SOURCE_ID, payload_hash)

        health_notes = (
            f"Catalog v{catalog_version}: "
            f"{len(vulnerabilities)} total CVEs, "
            f"{inserted} new inserted"
        )
        db.update_source_health(conn, SOURCE_ID, True, health_notes)
        conn.close()

        log.info("CISA KEV: %d inserted, %d skipped", inserted, skipped)

        return {
            "source": SOURCE_ID,
            "status": "completed",
            "records_inserted": inserted,
            "records_skipped": skipped,
            "collection_timestamp": collection_ts,
        }
