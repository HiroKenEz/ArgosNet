"""Tests du moteur de dissection."""
from fixtures import build_sample_packets
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from argosnet.core.dissect import (
    hexdump,
    layer_tree,
    packet_length,
    summarize,
    tcp_flags_str,
)


def _client_hello(sni: bytes) -> bytes:
    """Construit les octets d'un ClientHello TLS minimal avec extension SNI."""
    sni_entry = b"\x00" + len(sni).to_bytes(2, "big") + sni      # name_type + name_len + name
    sni_list = len(sni_entry).to_bytes(2, "big") + sni_entry     # server_name_list_length + entrée
    ext = b"\x00\x00" + len(sni_list).to_bytes(2, "big") + sni_list  # type + longueur + données
    body = (
        b"\x03\x03" + b"\x00" * 32 + b"\x00"                     # version + aléa + session id len
        + b"\x00\x02\x00\x2f" + b"\x01\x00"                      # cipher suites + compression
        + len(ext).to_bytes(2, "big") + ext                     # extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def test_protocols():
    protos = [summarize(p).protocol for p in build_sample_packets()]
    assert protos[0] == "TCP"
    assert "DNS" in protos
    assert "ARP" in protos
    assert "ICMP" in protos


def test_tcp_flags():
    assert tcp_flags_str(0x02) == "SYN"
    assert tcp_flags_str(0x12) == "SYN, ACK"


def test_endpoints_and_info():
    pkts = build_sample_packets()
    summary = summarize(pkts[0])
    assert summary.src == "192.168.1.10"
    assert summary.dst == "192.168.1.1"
    assert "443" in summary.info


def test_ipv6_endpoints():
    pkts = build_sample_packets()
    summary = summarize(pkts[8])
    assert summary.src == "fe80::2"
    assert summary.dst == "fe80::1"


def test_layer_tree():
    tree = layer_tree(build_sample_packets()[3])  # DNS
    names = [name for name, _ in tree]
    assert {"Ethernet", "IP", "UDP", "DNS"}.issubset(set(names))


def test_hexdump_and_length():
    pkt = build_sample_packets()[0]
    assert packet_length(pkt) > 0
    assert "0000" in hexdump(pkt)


def test_http_decoder():
    pkt = (
        Ether(src="02:00:00:00:00:01") / IP(src="192.168.1.10", dst="1.2.3.4")
        / TCP(sport=50000, dport=80, flags="PA")
        / Raw(b"GET /index.html HTTP/1.1\r\nHost: example.org\r\n\r\n")
    )
    s = summarize(pkt)
    assert s.protocol == "HTTP"
    assert "GET /index.html" in s.info
    assert "example.org" in s.info


def test_tls_sni_decoder():
    pkt = (
        Ether(src="02:00:00:00:00:01") / IP(src="192.168.1.10", dst="1.2.3.4")
        / TCP(sport=50000, dport=443, flags="PA")
        / Raw(_client_hello(b"example.com"))
    )
    s = summarize(pkt)
    assert s.protocol == "TLS"
    assert "example.com" in s.info


def test_dhcp_decoder():
    pkt = (
        Ether(src="02:00:00:00:00:01") / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67) / BOOTP() / DHCP(options=[("message-type", "discover"), "end"])
    )
    s = summarize(pkt)
    assert s.protocol == "DHCP"
    assert "Discover" in s.info
