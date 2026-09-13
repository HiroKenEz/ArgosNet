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


def test_feed_with_explicit_start_number():
    # Le worker d'analyse fournit le numéro du 1er paquet du lot : la numérotation
    # des alertes reste alignée sur la liste de capture, hors du thread graphique.
    packets = build_attack_packets()
    alerts = DetectionEngine().feed(packets, start_number=1000)
    nums = [a.packet_number for a in alerts if a.packet_number is not None]
    assert nums
    assert min(nums) >= 1000
    assert max(nums) < 1000 + len(packets)


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


# --- Lot A (audit sept. 2026) : IPv6, port knocking, DNS, règles, baseline ---

def _ipv6_syn(src, dst, dport, t, sport=40000):
    from scapy.layers.inet6 import IPv6

    pkt = (
        Ether(src="02:00:00:00:00:01")
        / IPv6(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, flags="S")
    )
    pkt.time = t
    return pkt


def test_portscan_ipv6_detected():
    # 40 SYN IPv6 vers des ports distincts : 0 alerte avant correction (#22).
    from argosnet.core.detection.detectors import PortScanDetector

    det = PortScanDetector()
    alerts = []
    for i in range(40):
        alerts += det.inspect(i + 1, _ipv6_syn("2001:db8::10", "2001:db8::1", 1000 + i, 1000.0 + i * 0.05))
    assert any(a.category == "Scan de ports" for a in alerts)


def test_synflood_ipv6_detected():
    from argosnet.core.detection.detectors import SynFloodDetector

    det = SynFloodDetector()
    alerts = []
    for i in range(120):
        alerts += det.inspect(i + 1, _ipv6_syn(f"2001:db8::{i % 250 + 1}", "2001:db8::99", 80, 1000.0 + i * 0.01))
    assert any(a.category == "SYN flood" for a in alerts)


def test_blocklist_ipv6_detected():
    from scapy.layers.inet6 import IPv6

    from argosnet.core.detection.detectors import BlocklistDetector

    det = BlocklistDetector(blocklist={"2001:db8::66"})
    pkt = Ether() / IPv6(src="2001:db8::10", dst="2001:db8::66") / TCP(dport=443, flags="S")
    pkt.time = 1000.0
    alerts = det.inspect(1, pkt)
    assert len(alerts) == 1
    assert alerts[0].category == "Liste noire (threat intel)"


def test_host_sweep_message_uses_sweep_window(monkeypatch):
    # Le message doit citer HOSTSWEEP_WINDOW (copier-coller PORTSCAN_WINDOW avant, #32).
    import argosnet.core.detection.detectors as det_mod
    from argosnet.core.detection.detectors import HostSweepDetector

    monkeypatch.setattr(det_mod, "HOSTSWEEP_WINDOW", 7.0)
    det = HostSweepDetector()
    alerts = []
    for i in range(20):
        pkt = (
            Ether(src="02:00:00:00:00:01") / IP(src="192.168.1.50", dst=f"192.168.1.{100 + i}")
            / TCP(sport=45000, dport=80, flags="S")
        )
        pkt.time = 1000.0 + i * 0.05
        alerts += det.inspect(i + 1, pkt)
    assert alerts
    assert "7s" in alerts[0].detail


def test_host_sweep_counts_icmpv6_echo():
    from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6

    from argosnet.core.detection.detectors import HostSweepDetector

    det = HostSweepDetector()
    alerts = []
    for i in range(20):
        pkt = Ether(src="02:00:00:00:00:01") / IPv6(src="2001:db8::10", dst=f"2001:db8::{100 + i}") / ICMPv6EchoRequest()
        pkt.time = 1000.0 + i * 0.05
        alerts += det.inspect(i + 1, pkt)
    assert any(a.category == "Balayage réseau" for a in alerts)


def test_port_knock_with_retransmission_detected():
    # 7000,7000(retry SYN),8000,9000 → 1 alerte (0 avant, #23).
    det = PortKnockDetector()
    alerts = []
    for i, port in enumerate([7000, 7000, 8000, 9000]):
        pkt = Ether(src="02:00:00:00:00:01") / IP(src="192.168.1.50", dst="192.168.1.1") / TCP(
            sport=40000 + i, dport=port, flags="S"
        )
        pkt.time = 1000.0 + i
        alerts += det.inspect(i + 1, pkt)
    assert any(a.category == "Port knocking" for a in alerts)


def _dns_query_packet(qname, t=1000.0, src="192.168.1.10"):
    pkt = (
        Ether(src="02:00:00:00:00:01") / IP(src=src, dst="8.8.8.8")
        / UDP(sport=5000, dport=53) / DNS(rd=1, qd=DNSQR(qname=qname))
    )
    pkt.time = t
    return pkt


def test_dns_tunnel_co_uk_two_domains():
    # Deux exfils vers des domaines co.uk différents → 2 alertes (1 avant, #25).
    label1 = os.urandom(24).hex()
    label2 = os.urandom(24).hex()
    det = DnsTunnelDetector()
    alerts = det.inspect(1, _dns_query_packet(f"{label1}.evil.co.uk"))
    alerts += det.inspect(2, _dns_query_packet(f"{label2}.other.co.uk"))
    assert len(alerts) == 2
    assert all(a.category == "Tunneling DNS" for a in alerts)
    assert all(a.source == "192.168.1.10" for a in alerts)


def test_newdevice_reset_keeps_inventory():
    # Seedé puis reset() : une MAC connue ne doit pas re-alerter (#27).
    from argosnet.core.detection.detectors import NewDeviceDetector

    det = NewDeviceDetector(known_macs={"aa:bb:cc:00:00:01"})
    det.reset()
    pkt = Ether(src="aa:bb:cc:00:00:01", dst="ff:ff:ff:ff:ff:ff") / IP(src="192.168.1.10", dst="192.168.1.1")
    pkt.time = 1000.0
    assert det.inspect(1, pkt) == []


def test_invalid_rules_ignored_valid_kept(tmp_path):
    # contains non-chaîne + règle valide : la valide déclenche (AttributeError avant, #10).
    from argosnet.core.detection.detectors import SignatureDetector, load_rules

    path = str(tmp_path / "rules.yaml")
    import yaml

    with open(path, "w", encoding="utf-8") as handle:
        yaml.safe_dump(
            {"rules": [
                {"name": "Cassée", "contains": 12345, "severity": "warning", "message": "x"},
                {"name": "Bonne", "dst_port": 4444, "severity": "critical", "message": "m"},
            ]},
            handle,
        )
    rules = load_rules(path)
    assert [r["name"] for r in rules] == ["Bonne"]
    pkt = Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1, dport=4444, flags="S")
    pkt.time = 1000.0
    assert any(a.category == "Bonne" for a in SignatureDetector(rules).inspect(1, pkt))


def test_rules_string_returns_empty(tmp_path):
    # rules: "abc" → [] (['a','b','c'] avant, #10).
    from argosnet.core.detection.detectors import load_rules

    path = str(tmp_path / "rules.yaml")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write('rules: "abc"\n')
    assert load_rules(path) == []


def test_broken_rule_does_not_blind_others():
    # Une règle corrompue après chargement n'aveugle pas les autres (try par règle, #10).
    from argosnet.core.detection.detectors import SignatureDetector

    det = SignatureDetector(rules=[{"name": "Bonne", "dst_port": 4444, "severity": "critical", "message": "m"}])
    det.rules.append({"dst_port": object(), "contains": None, "name": "X", "severity": "warning", "message": "y"})
    pkt = Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1, dport=4444, flags="S")
    pkt.time = 1000.0
    assert any(a.category == "Bonne" for a in det.inspect(1, pkt))


def test_baseline_ignores_out_of_order_packet():
    # Paquet antérieur à _t0 (pcap désordonné) : ignoré, pas d'apprentissage (#24).
    det = BaselineAnomalyDetector()
    det.inspect(1, _ip_packet("10.0.0.5", 1000.0))
    assert det.inspect(2, _ip_packet("10.0.0.5", 900.0)) == []
    assert det.learn_counts.get("10.0.0.5", 0) == 1


def test_baseline_realert_after_delay():
    # 1 alerte, silence < 300 s, puis 2e alerte après le délai de ré-alerte (#24).
    import argosnet.core.detection.detectors as det_mod

    det = BaselineAnomalyDetector()
    n = 0
    for k in range(6):
        n += 1
        det.inspect(n, _ip_packet("10.0.0.5", 1000.0 + k * 5))
    burst = []
    for k in range(25):
        n += 1
        burst += det.inspect(n, _ip_packet("10.0.0.5", 1031.0 + k * 0.01))
    assert any(a.category == "Anomalie de trafic" for a in burst)
    soon = []
    for k in range(25):
        n += 1
        soon += det.inspect(n, _ip_packet("10.0.0.5", 1032.0 + k * 0.01))
    assert not any(a.category == "Anomalie de trafic" for a in soon)
    later = []
    base_t = 1032.0 + det_mod.BASELINE_REALERT_SECONDS + 1.0
    for k in range(25):
        n += 1
        later += det.inspect(n, _ip_packet("10.0.0.5", base_t + k * 0.01))
    assert any(a.category == "Anomalie de trafic" for a in later)


def test_cleartext_dedup_key_is_tuple():
    # La clé de dédoublonnage est le tuple (src, dst, kind), pas hash() (#41).
    from argosnet.core.detection.detectors import CleartextCredsDetector

    det = CleartextCredsDetector()
    pkt = (
        Ether() / IP(src="192.168.1.60", dst="1.2.3.4")
        / TCP(sport=52000, dport=80, flags="PA")
        / Raw(b"GET / HTTP/1.1\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n")
    )
    pkt.time = 1000.0
    assert len(det.inspect(1, pkt)) == 1
    assert ("192.168.1.60", "1.2.3.4", "http-basic") in det._alerted


def test_port_text_to_int():
    # Helper de l'éditeur de règles : ports valides 0–65535 (#10).
    from argosnet.core.detection.detectors import port_text_to_int

    assert port_text_to_int("443") == 443
    assert port_text_to_int("  80  ") == 80
    assert port_text_to_int("0") == 0
    assert port_text_to_int("65535") == 65535
    assert port_text_to_int("") is None
    assert port_text_to_int("abc") is None
    assert port_text_to_int("99999") is None
    assert port_text_to_int("-1") is None
