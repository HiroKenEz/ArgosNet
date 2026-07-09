"""Persistance SQLite : historique des alertes et registre des appareils connus.

Base légère (module ``sqlite3`` de la bibliothèque standard, aucune dépendance
supplémentaire). Le fichier est stocké dans ``~/.argosnet/argosnet.sqlite``.
Tous les accès se font depuis le thread GUI ; une seule connexion suffit.
"""
from __future__ import annotations

import os
import sqlite3
import time

from argosnet.core.detection.alert import Alert, Severity

DEFAULT_DB_DIR = os.path.join(os.path.expanduser("~"), ".argosnet")


class Database:
    def __init__(self, path: str | None = None) -> None:
        if path is None:
            os.makedirs(DEFAULT_DB_DIR, exist_ok=True)
            path = os.path.join(DEFAULT_DB_DIR, "argosnet.sqlite")
        self.path = path
        self._conn = sqlite3.connect(path)
        self._conn.row_factory = sqlite3.Row
        self._create_schema()

    def _create_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                ts            REAL,
                severity      INTEGER,
                category      TEXT,
                source        TEXT,
                packet_number INTEGER,
                detail        TEXT,
                created_at    REAL
            );
            CREATE TABLE IF NOT EXISTS devices (
                mac        TEXT PRIMARY KEY,
                ip         TEXT,
                vendor     TEXT,
                hostname   TEXT,
                first_seen REAL,
                last_seen  REAL
            );
            """
        )
        self._conn.commit()

    # ------------------------------------------------------------- alertes
    def save_alerts(self, alerts: list[Alert]) -> None:
        if not alerts:
            return
        now = time.time()
        self._conn.executemany(
            "INSERT INTO alerts (ts, severity, category, source, packet_number, detail, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                (a.timestamp, int(a.severity), a.category, a.source, a.packet_number, a.detail, now)
                for a in alerts
            ],
        )
        self._conn.commit()

    def load_recent_alerts(self, limit: int = 200) -> list[Alert]:
        """Charge les dernières alertes, en ordre chronologique (plus ancienne d'abord)."""
        rows = self._conn.execute(
            "SELECT * FROM (SELECT * FROM alerts ORDER BY id DESC LIMIT ?) ORDER BY id ASC",
            (limit,),
        ).fetchall()
        alerts: list[Alert] = []
        for row in rows:
            try:
                severity = Severity(row["severity"])
            except ValueError:
                severity = Severity.INFO
            alerts.append(
                Alert(
                    severity=severity,
                    category=row["category"],
                    source=row["source"],
                    detail=row["detail"],
                    timestamp=row["ts"] or 0.0,
                    packet_number=row["packet_number"],
                )
            )
        return alerts

    def clear_alerts(self) -> None:
        self._conn.execute("DELETE FROM alerts")
        self._conn.commit()

    # ------------------------------------------------------------ appareils
    def record_device(self, mac: str, ip: str = "", vendor: str = "", hostname: str = "") -> None:
        if not mac:
            return
        mac = mac.lower()
        now = time.time()
        self._conn.execute(
            """
            INSERT INTO devices (mac, ip, vendor, hostname, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(mac) DO UPDATE SET
                last_seen = excluded.last_seen,
                ip        = COALESCE(NULLIF(excluded.ip, ''), devices.ip),
                vendor    = COALESCE(NULLIF(excluded.vendor, ''), devices.vendor),
                hostname  = COALESCE(NULLIF(excluded.hostname, ''), devices.hostname)
            """,
            (mac, ip, vendor, hostname, now, now),
        )
        self._conn.commit()

    def known_macs(self) -> set[str]:
        rows = self._conn.execute("SELECT mac FROM devices").fetchall()
        return {row["mac"] for row in rows}

    def clear_devices(self) -> None:
        self._conn.execute("DELETE FROM devices")
        self._conn.commit()

    # ---------------------------------------------------------------- divers
    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass
