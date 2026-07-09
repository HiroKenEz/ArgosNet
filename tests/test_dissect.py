"""Tests du moteur de dissection."""
from fixtures import build_sample_packets

from argosnet.core.dissect import (
    hexdump,
    layer_tree,
    packet_length,
    summarize,
    tcp_flags_str,
)


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
