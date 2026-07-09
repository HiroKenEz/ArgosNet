"""Tests du moteur de statistiques."""
from fixtures import build_sample_packets

from argosnet.core.stats import StatsEngine


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
