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
