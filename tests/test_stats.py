"""Tests du moteur de statistiques."""
from fixtures import build_sample_packets
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from argosnet.core.stats import THROUGHPUT_WINDOW, StatsEngine


def _engine():
    engine = StatsEngine()
    engine.add_packets(build_sample_packets())
    return engine


def test_totals():
    engine = _engine()
    assert engine.total_packets == 9
    assert engine.total_bytes > 0


def test_protocol_breakdown():
    breakdown = dict(_engine().protocol_breakdown())
    assert breakdown.get("TCP") == 3


def test_top_talkers():
    talkers = _engine().top_talkers(5)
    assert talkers[0].address == "192.168.1.10"


def test_throughput_sums_to_total():
    _seconds, pps, _kbps = _engine().throughput_series()
    assert sum(pps) == 9


def test_reset():
    engine = _engine()
    engine.reset()
    assert engine.total_packets == 0
    assert engine.proto_counts == {}


def test_throughput_window_bounds_series():
    # Deux paquets très éloignés dans le temps : la fenêtre glissante purge le premier,
    # mais le total cumulé n'est pas affecté.
    def pkt(t):
        p = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(
            src="10.0.0.1", dst="10.0.0.2"
        ) / TCP()
        p.time = t
        return p

    engine = StatsEngine()
    engine.add_packets([pkt(1000.0), pkt(1000.0 + THROUGHPUT_WINDOW + 500)])
    seconds, pps, _kbps = engine.throughput_series()
    assert engine.total_packets == 2      # total non affecté par la purge
    assert 0 not in seconds               # la première seconde a été purgée
    assert sum(pps) == 1                  # seul le paquet récent reste dans la fenêtre
