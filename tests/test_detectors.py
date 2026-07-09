"""Tests du moteur de détection (mini-IDS)."""
from fixtures import build_attack_packets, build_sample_packets

from argosnet.core.detection.alert import Severity
from argosnet.core.detection.engine import DetectionEngine


def _categories(alerts):
    return {alert.category for alert in alerts}


def test_all_attack_types_detected():
    alerts = DetectionEngine().feed(build_attack_packets())
    cats = _categories(alerts)
    assert "ARP spoofing" in cats
    assert "Scan de ports" in cats
    assert "Balayage réseau" in cats
    assert "SYN flood" in cats
    assert "Identifiants en clair" in cats
    assert any("4444" in c for c in cats)          # signature Metasploit
    assert any("PowerShell" in c for c in cats)    # signature payload


def test_critical_alerts_present():
    alerts = DetectionEngine().feed(build_attack_packets())
    assert any(a.severity == Severity.CRITICAL for a in alerts)


def test_normal_traffic_has_no_critical():
    alerts = DetectionEngine().feed(build_sample_packets())
    assert all(a.severity != Severity.CRITICAL for a in alerts)


def test_reset_clears_state():
    engine = DetectionEngine()
    engine.feed(build_attack_packets())
    engine.reset()
    assert engine._counter == 0
    # Après reset, le trafic normal ne doit toujours pas déclencher de critique.
    assert all(a.severity != Severity.CRITICAL for a in engine.feed(build_sample_packets()))


def test_packet_numbers_assigned():
    alerts = DetectionEngine().feed(build_attack_packets())
    assert all(a.packet_number is not None for a in alerts)
