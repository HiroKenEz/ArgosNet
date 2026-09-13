"""Test du réassemblage de flux TCP (Follow Stream)."""
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from argosnet.core.follow import follow_tcp_stream


def _seg(sport, dport, src, dst, data, t):
    pkt = Ether(src="02:00:00:00:00:01") / IP(src=src, dst=dst) / TCP(
        sport=sport, dport=dport, flags="PA"
    ) / Raw(data)
    pkt.time = t
    return pkt


def _seg_seq(sport, dport, src, dst, seq, data, t):
    pkt = Ether(src="02:00:00:00:00:01") / IP(src=src, dst=dst) / TCP(
        sport=sport, dport=dport, flags="PA", seq=seq
    ) / Raw(data)
    pkt.time = t
    return pkt


def test_follow_reassembles_both_directions_in_order():
    c2s = _seg(50000, 80, "192.168.1.10", "1.2.3.4", b"GET / HTTP/1.1\r\n", 1.0)
    s2c = _seg(80, 50000, "1.2.3.4", "192.168.1.10", b"HTTP/1.1 200 OK\r\n", 2.0)
    noise = _seg(50001, 80, "192.168.1.99", "9.9.9.9", b"noise", 1.5)

    stream = follow_tcp_stream([c2s, noise, s2c], c2s)
    assert stream is not None
    assert len(stream.segments) == 2                 # le paquet « noise » est exclu
    assert stream.segments[0][0] is True             # a→b (requête) en premier (temps)
    assert b"GET" in stream.segments[0][1]
    assert stream.segments[1][0] is False            # b→a (réponse) ensuite
    assert b"200 OK" in stream.segments[1][1]
    assert stream.total_bytes() == len(b"GET / HTTP/1.1\r\n") + len(b"HTTP/1.1 200 OK\r\n")


def test_follow_ignores_retransmission():
    # Même seq retransmis (2× HELLO) → une seule copie (#19).
    ref = _seg_seq(50000, 80, "192.168.1.10", "1.2.3.4", 0, b"HELLO", 1.0)
    retry = _seg_seq(50000, 80, "192.168.1.10", "1.2.3.4", 0, b"HELLO", 2.0)
    stream = follow_tcp_stream([ref, retry], ref)
    assert stream is not None
    assert stream.segments == [(True, b"HELLO")]


def test_follow_reorders_out_of_order_segments():
    # Arrivée 0, 10, 5 → contenu dans l'ordre des seq (#19).
    ref = _seg_seq(50000, 80, "192.168.1.10", "1.2.3.4", 0, b"AAAAA", 1.0)
    later = _seg_seq(50000, 80, "192.168.1.10", "1.2.3.4", 10, b"CCCCC", 2.0)
    middle = _seg_seq(50000, 80, "192.168.1.10", "1.2.3.4", 5, b"BBBBB", 3.0)
    stream = follow_tcp_stream([ref, later, middle], ref)
    assert stream is not None
    assert b"".join(data for _, data in stream.segments) == b"AAAAABBBBBCCCCC"


def test_follow_ipv6_stream():
    # Flux IPv6 : réassemblé (None avant, #20).
    from scapy.layers.inet6 import IPv6

    def seg6(sport, dport, data, t):
        pkt = Ether(src="02:00:00:00:00:01") / IPv6(src="2001:db8::10", dst="2001:db8::1") / TCP(
            sport=sport, dport=dport, flags="PA"
        ) / Raw(data)
        pkt.time = t
        return pkt

    ref = seg6(50000, 80, b"ping6", 1.0)
    stream = follow_tcp_stream([ref], ref)
    assert stream is not None
    assert stream.segments == [(True, b"ping6")]
    assert stream.endpoint_a == "2001:db8::10:50000"


def test_follow_truncated_when_over_caps(monkeypatch):
    # Plafonds : flux coupé → truncated=True (#14).
    import argosnet.core.follow as follow_mod

    monkeypatch.setattr(follow_mod, "MAX_SEGMENTS", 3)
    pkts = [
        _seg_seq(50000, 80, "192.168.1.10", "1.2.3.4", i * 10, b"x" * 10, 1.0 + i)
        for i in range(10)
    ]
    stream = follow_tcp_stream(pkts, pkts[0])
    assert stream is not None
    assert stream.truncated is True
    assert len(stream.segments) <= 3


def test_follow_late_earlier_seq_not_dropped():
    # WORLD seq=1005 à t=1.0 puis HELLO seq=1000 à t=1.5 : les deux conservés,
    # dans l'ordre des seq (relecture PR #42 : next_seq = plus petite seq).
    world = _seg_seq(50000, 80, "192.168.1.10", "1.2.3.4", 1005, b"WORLD", 1.0)
    hello = _seg_seq(50000, 80, "192.168.1.10", "1.2.3.4", 1000, b"HELLO", 1.5)
    stream = follow_tcp_stream([world, hello], world)
    assert stream is not None
    assert [(d, b) for d, b in stream.segments] == [(True, b"HELLO"), (True, b"WORLD")]


def test_follow_syn_sets_next_seq():
    # SYN seq=5000 : un segment périmé (seq=4000) est ignoré, la suite gardée.
    from scapy.layers.inet import IP as _IP
    from scapy.layers.inet import TCP as _TCP
    from scapy.layers.l2 import Ether as _Ether

    def _syn(t):
        pkt = _Ether(src="02:00:00:00:00:01") / _IP(src="192.168.1.10", dst="1.2.3.4") / _TCP(
            sport=50000, dport=80, flags="S", seq=5000
        )
        pkt.time = t
        return pkt

    syn = _syn(0.5)
    stale = _seg_seq(50000, 80, "192.168.1.10", "1.2.3.4", 4000, b"STALE", 1.0)
    late = _seg_seq(50000, 80, "192.168.1.10", "1.2.3.4", 6000, b"LATE", 2.0)
    stream = follow_tcp_stream([syn, stale, late], syn)
    assert stream is not None
    assert [(d, b) for d, b in stream.segments] == [(True, b"LATE")]
