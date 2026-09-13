"""Tests du filtre d'affichage."""
from types import SimpleNamespace

from fixtures import build_sample_packets

from argosnet.core.dissect import summarize
from argosnet.core.display_filter import compile_filter


def _records():
    return [SimpleNamespace(summary=summarize(p), packet=p) for p in build_sample_packets()]


def _count(expr):
    pred = compile_filter(expr)
    return sum(1 for record in _records() if pred(record))


def test_empty_matches_all():
    assert _count("") == len(_records())


def test_protocol_term():
    assert _count("dns") == 2


def test_ip_addr():
    assert _count("ip.addr==8.8.8.8") == 2


def test_ip_addr_is_exact_not_substring():
    # « ip.addr==192.168.1.1 » ne doit PAS matcher 192.168.1.10 (bug de sous-chaîne).
    # 5 paquets contiennent exactement 192.168.1.1 ; les 3 qui n'ont que .10 sont exclus.
    assert _count("ip.addr==192.168.1.1") == 5


def test_tcp_port():
    assert _count("tcp.port==443") == 2


def test_and_combination():
    assert _count("arp and 192.168.1.1") == 2


def test_negation():
    total = len(_records())
    tcp = sum(1 for r in _records() if r.summary.protocol == "TCP")
    assert _count("proto!=tcp") == total - tcp


def test_icmp_matches_icmpv6():
    # Le filtre nu « icmp » trouve aussi le ping6 (#30).
    from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6
    from scapy.layers.l2 import Ether

    pkt = Ether(src="02:00:00:00:00:01") / IPv6(src="fe80::2", dst="fe80::1") / ICMPv6EchoRequest()
    record = SimpleNamespace(summary=summarize(pkt), packet=pkt)
    assert record.summary.protocol == "ICMPv6"
    assert compile_filter("icmp")(record) is True
    assert compile_filter("icmpv6")(record) is True
    assert compile_filter("tcp")(record) is False
