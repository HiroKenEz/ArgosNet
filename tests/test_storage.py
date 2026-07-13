"""Tests de la persistance SQLite (batching + appareils)."""
import os
import tempfile

from argosnet.core.detection.alert import Alert, Severity
from argosnet.core.storage import Database


def _fresh_db_path():
    path = os.path.join(tempfile.gettempdir(), "argos_test_storage.sqlite")
    if os.path.exists(path):
        os.remove(path)
    return path


def test_save_and_load_without_flush():
    # Les insertions sont visibles sur la même connexion avant même le commit (batching).
    db = Database(_fresh_db_path())
    db.save_alerts([Alert(Severity.CRITICAL, "ARP spoofing", "192.168.1.1", "détail", 1.0, 5)])
    loaded = db.load_recent_alerts()
    assert len(loaded) == 1
    assert loaded[0].severity == Severity.CRITICAL
    assert loaded[0].packet_number == 5
    db.flush()
    db.close()


def test_devices_upsert_and_known_macs():
    db = Database(_fresh_db_path())
    db.record_device("AA:BB:CC:DD:EE:FF", ip="192.168.1.5", vendor="Asus")
    db.record_device("aa:bb:cc:dd:ee:ff", hostname="pc")  # upsert, casse normalisée
    assert db.known_macs() == {"aa:bb:cc:dd:ee:ff"}
    db.clear_devices()
    assert db.known_macs() == set()
    db.close()


def test_clear_alerts():
    db = Database(_fresh_db_path())
    db.save_alerts([Alert(Severity.INFO, "Nouvel appareil", "aa:bb", "x", 1.0, 1)])
    db.clear_alerts()
    assert db.load_recent_alerts() == []
    db.close()
