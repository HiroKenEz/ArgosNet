"""Test de la génération du rapport HTML."""
from argosnet.core.detection.alert import Alert, Severity
from argosnet.core.report import build_html_report
from argosnet.core.stats import Talker


def test_build_html_report_contains_sections_and_escapes():
    summary = {
        "total_packets": 10, "total_bytes": 2048, "duration": 5,
        "avg_pps": 2.0, "avg_bps": 400.0,
        "protocols": [("TCP", 7), ("DNS", 3)],
        "distinct_talkers": 4, "distinct_conversations": 3,
    }
    talkers = [Talker("192.168.1.10", 7, 1500)]
    conversations = [("192.168.1.10", "8.8.8.8", 3, 300)]
    alerts = [Alert(Severity.CRITICAL, "ARP spoofing", "192.168.1.1", "détail <b>x</b>", 1.0, 5)]
    devices = [{"mac": "aa:bb", "ip": "192.168.1.5", "vendor": "Asus",
                "hostname": "pc", "label": "Mon PC"}]

    report = build_html_report(
        summary=summary, top_talkers=talkers, conversations=conversations,
        alerts=alerts, devices=devices,
    )
    assert "<html" in report.lower()
    assert "Rapport ArgosNet" in report
    assert "192.168.1.10" in report
    assert "ARP spoofing" in report
    assert "Mon PC" in report
    assert "&lt;b&gt;" in report          # échappement HTML des champs
