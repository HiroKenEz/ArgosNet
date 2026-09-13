"""Test de la génération du rapport HTML."""
from argosnet.core.detection.alert import Alert, Severity
from argosnet.core.report import build_html_report
from argosnet.core.stats import Talker


def test_build_html_report_contains_sections_and_escapes():
    summary = {
        "total_packets": 10, "total_bytes": 2048, "duration": 5,
        "avg_pps": 2.0, "avg_bytes_per_s": 400.0,
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
    assert "Alertes (1)" in report        # nombre d'alertes incluses (#40)
    assert "2 000" in report              # plafond de la vue mentionné (#40)


def test_csv_safe_neutralizes_formulas():
    # Injection de formule via un champ réseau : préfixe apostrophe (#11).
    from argosnet.core.report import csv_safe

    assert csv_safe("=cmd|'/c calc'!A0") == "'=cmd|'/c calc'!A0"
    assert csv_safe("+1+1") == "'+1+1"
    assert csv_safe("-1") == "'-1"
    assert csv_safe("@evil") == "'@evil"
    assert csv_safe("\tcmd") == "'\tcmd"
    assert csv_safe("\ncmd") == "'\ncmd"
    assert csv_safe("domaine.evil.com") == "domaine.evil.com"
    assert csv_safe("") == ""
    assert csv_safe(123) == 123
    assert csv_safe(None) is None
