"""SQLite persistence layer for telemetry observations."""

from __future__ import annotations

import hashlib
import logging
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)

DEFAULT_DB_DIR = Path.home() / ".tef-estimator"
DEFAULT_DB_PATH = DEFAULT_DB_DIR / "telemetry.db"

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS raw_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id TEXT NOT NULL,
    observation_date DATE NOT NULL,
    event_type TEXT NOT NULL,
    metric_name TEXT NOT NULL,
    metric_value REAL NOT NULL,
    unit TEXT NOT NULL,
    collection_timestamp DATETIME NOT NULL,
    raw_payload_hash TEXT,
    UNIQUE(source_id, observation_date, metric_name)
);

CREATE TABLE IF NOT EXISTS time_series (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id TEXT NOT NULL,
    series_date DATE NOT NULL,
    event_type TEXT NOT NULL,
    metric_name TEXT NOT NULL,
    value REAL NOT NULL,
    interpolation_flag BOOLEAN DEFAULT 0,
    UNIQUE(source_id, series_date, metric_name)
);

CREATE TABLE IF NOT EXISTS computed_statistics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_date DATE NOT NULL,
    scenario TEXT NOT NULL,
    metric_name TEXT NOT NULL,
    value REAL NOT NULL,
    lower_bound REAL,
    upper_bound REAL,
    confidence_level REAL,
    methodology_version TEXT
);

CREATE TABLE IF NOT EXISTS source_health (
    source_id TEXT PRIMARY KEY,
    last_success DATETIME,
    last_attempt DATETIME,
    consecutive_failures INTEGER DEFAULT 0,
    staleness_flag BOOLEAN DEFAULT 0,
    notes TEXT
);
"""

KNOWN_SOURCES = [
    ("dshield", "SANS ISC DShield"),
    ("cisa_kev", "CISA Known Exploited Vulnerabilities"),
    ("ransomware_live", "Ransomware.live"),
    ("annual_report_monitor", "Annual report edition monitor"),
    ("iris", "Cyentia IRIS reference data"),
    ("vector_benchmarks", "Initial access vector benchmarks (Verizon, Unit42, Mandiant, Beazley, CrowdStrike, IBM)"),
]


@dataclass(frozen=True)
class SourceHealth:
    source_id: str
    last_success: str | None
    last_attempt: str | None
    consecutive_failures: int
    staleness_flag: bool
    notes: str | None


_memory_db_counter = 0


class TelemetryDB:
    """Manages the telemetry SQLite database."""

    def __init__(self, db_path: Path | None = DEFAULT_DB_PATH) -> None:
        global _memory_db_counter
        self.db_path = db_path
        self._snapshots_dir: Path | None = None
        self._memory_uri: str | None = None
        self._memory_keepalive: sqlite3.Connection | None = None
        if db_path is None:
            _memory_db_counter += 1
            self._memory_uri = f"file:tef_mem_{_memory_db_counter}?mode=memory&cache=shared"
        else:
            self._snapshots_dir = db_path.parent / "snapshots"

    def cache_dir(self, name: str) -> Path | None:
        """A collector's download cache next to the DB; None for in-memory DBs."""
        if self._snapshots_dir is None:
            return None
        return self._snapshots_dir.parent / "cache" / name

    def initialize(self) -> None:
        """Create tables if they don't exist. Safe to call repeatedly."""
        if self.db_path is not None:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)

        if self._memory_uri is not None:
            self._memory_keepalive = sqlite3.connect(self._memory_uri, uri=True)

        conn = self.connect(_initializing=True)
        cursor = conn.cursor()
        cursor.executescript(SCHEMA_SQL)

        for source_id, notes in KNOWN_SOURCES:
            cursor.execute(
                "INSERT OR IGNORE INTO source_health (source_id, notes) VALUES (?, ?)",
                (source_id, notes),
            )

        conn.commit()
        conn.close()
        if self.db_path is not None:
            log.info("Database initialized at %s", self.db_path)

    def connect(self, _initializing: bool = False) -> sqlite3.Connection:
        """Return a connection to the database.

        For in-memory databases (db_path=None), uses a shared-cache named
        database so multiple connect()/close() cycles see the same data.
        """
        if self._memory_uri is not None:
            return sqlite3.connect(self._memory_uri, uri=True)

        if not _initializing and not self.db_path.exists():
            raise FileNotFoundError(
                f"Database not found at {self.db_path}. "
                "Run 'tef-estimator telemetry init' first."
            )
        conn = sqlite3.connect(str(self.db_path))
        if self.db_path.exists():
            conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def insert_observation(
        self,
        cursor: sqlite3.Cursor,
        source_id: str,
        event_type: str,
        observation_date: str,
        metric_name: str,
        metric_value: float,
        unit: str,
        collection_ts: str,
        payload_hash: str,
    ) -> bool:
        try:
            cursor.execute(
                """INSERT OR IGNORE INTO raw_observations
                (source_id, observation_date, event_type, metric_name,
                 metric_value, unit, collection_timestamp, raw_payload_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (source_id, observation_date, event_type, metric_name,
                 metric_value, unit, collection_ts, payload_hash),
            )
            return cursor.rowcount > 0
        except sqlite3.Error as e:
            log.error("Insert error for %s/%s on %s: %s",
                      source_id, metric_name, observation_date, e)
            return False

    def upsert_observation(
        self,
        cursor: sqlite3.Cursor,
        source_id: str,
        event_type: str,
        observation_date: str,
        metric_name: str,
        metric_value: float,
        unit: str,
        collection_ts: str,
        payload_hash: str,
    ) -> bool:
        """Insert, or replace the value when it changed; True if a row was written.

        For counts that keep growing after the date (late reporting, a partial
        current day), where the latest collection must win.
        """
        try:
            cursor.execute(
                """INSERT INTO raw_observations
                (source_id, observation_date, event_type, metric_name,
                 metric_value, unit, collection_timestamp, raw_payload_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(source_id, observation_date, metric_name) DO UPDATE SET
                    metric_value = excluded.metric_value,
                    collection_timestamp = excluded.collection_timestamp,
                    raw_payload_hash = excluded.raw_payload_hash
                WHERE raw_observations.metric_value != excluded.metric_value""",
                (source_id, observation_date, event_type, metric_name,
                 metric_value, unit, collection_ts, payload_hash),
            )
            return cursor.rowcount > 0
        except sqlite3.Error as e:
            log.error("Upsert error for %s/%s on %s: %s",
                      source_id, metric_name, observation_date, e)
            return False

    def update_source_health(
        self,
        conn: sqlite3.Connection,
        source_id: str,
        success: bool,
        notes: str | None = None,
    ) -> None:
        cursor = conn.cursor()
        now = datetime.now(timezone.utc).isoformat()
        if success:
            cursor.execute(
                """UPDATE source_health
                SET last_success = ?, last_attempt = ?,
                    consecutive_failures = 0, staleness_flag = 0, notes = ?
                WHERE source_id = ?""",
                (now, now, notes or "Collection successful", source_id),
            )
        else:
            cursor.execute(
                """UPDATE source_health
                SET last_attempt = ?,
                    consecutive_failures = consecutive_failures + 1,
                    staleness_flag = CASE
                        WHEN consecutive_failures >= 6 THEN 1
                        ELSE staleness_flag
                    END,
                    notes = ?
                WHERE source_id = ?""",
                (now, notes or "Collection failed", source_id),
            )
        conn.commit()

    def get_source_health(self, conn: sqlite3.Connection) -> list[SourceHealth]:
        cursor = conn.cursor()
        cursor.execute(
            """SELECT source_id, last_success, last_attempt,
                      consecutive_failures, staleness_flag, notes
               FROM source_health WHERE source_id IN ({})
               ORDER BY source_id""".format(",".join("?" * len(KNOWN_SOURCES))),
            [source_id for source_id, _ in KNOWN_SOURCES],
        )
        return [
            SourceHealth(
                source_id=row[0],
                last_success=row[1],
                last_attempt=row[2],
                consecutive_failures=row[3],
                staleness_flag=bool(row[4]),
                notes=row[5],
            )
            for row in cursor.fetchall()
        ]

    def get_existing_metric_names(
        self, cursor: sqlite3.Cursor, source_id: str,
    ) -> set[str]:
        cursor.execute(
            "SELECT DISTINCT metric_name FROM raw_observations WHERE source_id = ?",
            (source_id,),
        )
        return {row[0] for row in cursor.fetchall()}

    # --- Hash management ---

    def get_last_hash(self, source_id: str) -> str | None:
        if self._snapshots_dir is None:
            return None
        hash_file = self._snapshots_dir / f"{source_id}_last_hash.txt"
        if hash_file.exists():
            return hash_file.read_text().strip()
        return None

    def save_hash(self, source_id: str, hash_value: str) -> None:
        if self._snapshots_dir is None:
            return
        self._snapshots_dir.mkdir(parents=True, exist_ok=True)
        hash_file = self._snapshots_dir / f"{source_id}_last_hash.txt"
        hash_file.write_text(hash_value)

    @staticmethod
    def compute_hash(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    @staticmethod
    def collection_timestamp() -> str:
        return datetime.now(timezone.utc).isoformat()
