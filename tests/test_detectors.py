"""Tests du moteur de détection (mini-IDS)."""
import os

from fixtures import build_attack_packets, build_sample_packets
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from argosnet.core.detection.alert import Severity
from argosnet.core.detection.detectors import (
    BaselineAnomalyDetector,
    BeaconDetector,
    BlocklistDetector,
    DnsTunnelDetector,
    Ja3BlocklistDetector,
    PortKnockDetector,
    RogueDhcpDetector,
)
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


def test_dns_tunnel_detected():
    label = os.urandom(24).hex()  # 48 caractères hexadécimaux, haute entropie
    pkt = (
        Ether(src="02:00:00:00:00:01") / IP(src="192.168.1.10", dst="8.8.8.8")
        / UDP(sport=5000, dport=53) / DNS(rd=1, qd=DNSQR(qname=f"{label}.exfil.com"))
    )
    pkt.time = 1000.0
    alerts = DnsTunnelDetector().inspect(1, pkt)
    assert len(alerts) == 1
    assert alerts[0].category == "Tunneling DNS"


def test_beaconing_detected():
    det = BeaconDetector()
    alerts = []
    for i in range(5):  # 5 connexions à intervalle régulier de 10 s
        pkt = Ether(src="02:00:00:00:00:01") / IP(src="192.168.1.10", dst="5.6.7.8") / TCP(
            sport=40000 + i, dport=443, flags="S"
        )
        pkt.time = 1000.0 + i * 10
        alerts += det.inspect(i + 1, pkt)
    assert any(a.category == "Beaconing (C2 potentiel)" for a in alerts)


def test_rogue_dhcp_detected():
    det = RogueDhcpDetector()

    def offer(server_ip):
        return (
            Ether(src="02:00:00:00:00:01") / IP(src=server_ip, dst="255.255.255.255")
            / UDP(sport=67, dport=68) / BOOTP(op=2) / DHCP(options=[("message-type", "offer"), "end"])
        )

    assert det.inspect(1, offer("192.168.1.1")) == []          # 1er serveur : OK
    alerts = det.inspect(2, offer("192.168.1.66"))             # 2e serveur : rogue
    assert len(alerts) == 1
    assert alerts[0].severity == Severity.CRITICAL


def test_blocklist_detected():
    det = BlocklistDetector(blocklist={"203.0.113.66"})
    pkt = Ether() / IP(src="192.168.1.10", dst="203.0.113.66") / TCP(dport=443, flags="S")
    pkt.time = 1000.0
    alerts = det.inspect(1, pkt)
    assert len(alerts) == 1
    assert alerts[0].category == "Liste noire (threat intel)"


def test_port_knocking_detected():
    det = PortKnockDetector()
    alerts = []
    for i, port in enumerate([7000, 8000, 9000]):  # 3 ports hauts distincts, chacun une fois
        pkt = Ether(src="02:00:00:00:00:01") / IP(src="192.168.1.50", dst="192.168.1.1") / TCP(
            sport=40000 + i, dport=port, flags="S"
        )
        pkt.time = 1000.0 + i
        alerts += det.inspect(i + 1, pkt)
    assert any(a.category == "Port knocking" for a in alerts)


def test_port_knocking_ignores_repeated_port():
    det = PortKnockDetector()
    alerts = []
    for i in range(5):  # même port frappé plusieurs fois → pas une séquence de knock
        pkt = Ether(src="02:00:00:00:00:01") / IP(src="192.168.1.50", dst="192.168.1.1") / TCP(
            sport=40000 + i, dport=8080, flags="S"
        )
        pkt.time = 1000.0 + i
        alerts += det.inspect(i + 1, pkt)
    assert not any(a.category == "Port knocking" for a in alerts)


def test_ja3_blocklist_detected():
    from argosnet.core.ja3 import ja3_from_client_hello
    from test_ja3 import build_client_hello

    data = build_client_hello()
    _, digest = ja3_from_client_hello(data)
    pkt = (
        Ether(src="02:00:00:00:00:01") / IP(src="192.168.1.10", dst="1.2.3.4")
        / TCP(sport=44000, dport=443, flags="PA") / Raw(data)
    )
    pkt.time = 1000.0
    det = Ja3BlocklistDetector(blocklist={digest})
    alerts = det.inspect(1, pkt)
    assert len(alerts) == 1
    assert alerts[0].category == "Empreinte JA3 malveillante"
    assert alerts[0].severity == Severity.CRITICAL


def _ip_packet(src, t):
    pkt = Ether(src="02:00:00:00:00:01") / IP(src=src, dst="192.168.1.1") / TCP(dport=80, flags="S")
    pkt.time = t
    return pkt


def test_baseline_anomaly_detected():
    det = BaselineAnomalyDetector()
    n = 0
    # Apprentissage : trafic calme (1 paquet toutes les 5 s pendant 30 s).
    for k in range(6):
        n += 1
        assert det.inspect(n, _ip_packet("10.0.0.5", 1000.0 + k * 5)) == []
    # Après l'apprentissage : pic de 25 paquets en une seconde → anomalie.
    alerts = []
    for k in range(25):
        n += 1
        alerts += det.inspect(n, _ip_packet("10.0.0.5", 1031.0 + k * 0.01))
    assert any(a.category == "Anomalie de trafic" for a in alerts)


def test_baseline_no_alert_during_learning():
    det = BaselineAnomalyDetector()
    # Même un pic pendant l'apprentissage ne doit pas alerter.
    alerts = []
    for k in range(30):
        alerts += det.inspect(k + 1, _ip_packet("10.0.0.9", 1000.0 + k * 0.01))
    assert alerts == []


def test_rules_save_and_load_roundtrip(tmp_path):
    from argosnet.core.detection.detectors import load_rules, save_rules

    path = str(tmp_path / "rules.yaml")
    rules = [{"name": "Test", "dst_port": 1234, "severity": "critical", "message": "m"}]
    save_rules(rules, path)
    assert load_rules(path) == rules


def test_cleartext_creds_deduplicated():
    # Deux requêtes HTTP Basic sur la même connexion → une seule alerte (pas de spam).
    def http_basic(i):
        pkt = (
            Ether(src="02:aa:aa:aa:aa:aa", dst="02:bb:bb:bb:bb:bb")
            / IP(src="192.168.1.60", dst="1.2.3.4")
            / TCP(sport=52000 + i, dport=80, flags="PA")
            / Raw(b"GET / HTTP/1.1\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n")
        )
        pkt.time = 1000.0 + i
        return pkt

    alerts = DetectionEngine().feed([http_basic(0), http_basic(1)])
    creds = [a for a in alerts if a.category == "Identifiants en clair"]
    assert len(creds) == 1
