"""Constructeurs de paquets de test (partagés par les tests et les .pcap d'exemple).

Tous les paquets portent une adresse MAC source explicite afin d'être sérialisables
sans dépendre d'une interface réseau, et un horodatage (``.time``) pour les fenêtres
temporelles des détecteurs.
"""
from __future__ import annotations

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

M1 = "aa:bb:cc:00:00:01"
M2 = "aa:bb:cc:00:00:02"
GW = "de:ad:be:ef:00:01"
EVIL = "66:66:66:66:66:66"


def _stamp(packets, start=1000.0, step=0.05):
    for i, pkt in enumerate(packets):
        pkt.time = start + i * step
    return packets


def build_sample_packets():
    """Trafic normal varié (TCP, DNS, ARP, ICMP, IPv6)."""
    pkts = [
        Ether(src=M1, dst=GW) / IP(src="192.168.1.10", dst="192.168.1.1") / TCP(sport=51000, dport=443, flags="S"),
        Ether(src=GW, dst=M1) / IP(src="192.168.1.1", dst="192.168.1.10") / TCP(sport=443, dport=51000, flags="SA"),
        Ether(src=M1, dst=GW) / IP(src="192.168.1.10", dst="1.1.1.1") / TCP(sport=51000, dport=80, flags="PA") / Raw(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
        Ether(src=M1, dst=GW) / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=5000, dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com")),
        Ether(src=GW, dst=M1) / IP(src="8.8.8.8", dst="192.168.1.10") / UDP(sport=53, dport=5000) / DNS(qr=1, qd=DNSQR(qname="example.com"), an=DNSRR(rrname="example.com", rdata="93.184.216.34")),
        Ether(src=M1, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, psrc="192.168.1.10", pdst="192.168.1.1"),
        Ether(src=GW, dst=M1) / ARP(op=2, psrc="192.168.1.1", hwsrc=GW, pdst="192.168.1.10"),
        Ether(src=M1, dst=GW) / IP(src="192.168.1.10", dst="192.168.1.1") / ICMP(),
        Ether(src=M2, dst=M1) / IPv6(src="fe80::2", dst="fe80::1") / UDP(sport=1000, dport=2000),
    ]
    return _stamp(pkts)


def build_attack_packets():
    """Trafic malveillant couvrant chaque détecteur."""
    pkts = []
    # ARP spoofing (la passerelle change de MAC).
    pkts.append(Ether(src=GW, dst=M1) / ARP(op=2, psrc="192.168.1.1", hwsrc=GW, pdst="192.168.1.10"))
    pkts.append(Ether(src=EVIL, dst=M1) / ARP(op=2, psrc="192.168.1.1", hwsrc=EVIL, pdst="192.168.1.10"))
    # Scan de ports (1 source → 20 ports d'un même hôte).
    for port in range(1, 21):
        pkts.append(Ether(src="02:11:11:11:11:11", dst=GW) / IP(src="192.168.1.50", dst="192.168.1.1") / TCP(sport=40000 + port, dport=port, flags="S"))
    # Balayage réseau (1 source → 20 hôtes).
    for host in range(100, 120):
        pkts.append(Ether(src="02:22:22:22:22:22", dst=GW) / IP(src="192.168.1.51", dst=f"192.168.1.{host}") / TCP(sport=45000, dport=80, flags="S"))
    # SYN flood (120 SYN vers une cible).
    for i in range(120):
        pkts.append(Ether(src="02:33:33:33:33:33", dst=GW) / IP(src=f"10.0.0.{i % 250}", dst="192.168.1.200") / TCP(sport=50000 + i, dport=80, flags="S"))
    # Identifiants HTTP en clair.
    pkts.append(Ether(src="02:44:44:44:44:44", dst=GW) / IP(src="192.168.1.60", dst="1.2.3.4") / TCP(sport=52000, dport=80, flags="PA") / Raw(b"GET / HTTP/1.1\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n"))
    # Signature : port Metasploit 4444.
    pkts.append(Ether(src="02:55:55:55:55:55", dst=GW) / IP(src="192.168.1.61", dst="5.6.7.8") / TCP(sport=53000, dport=4444, flags="S"))
    # Signature : PowerShell encodé dans la charge utile.
    pkts.append(Ether(src="02:77:77:77:77:77", dst=GW) / IP(src="192.168.1.62", dst="9.9.9.9") / TCP(sport=54000, dport=8080, flags="PA") / Raw(b"powershell -enc ZQBjAGgAbwA="))
    return _stamp(pkts, step=0.01)
