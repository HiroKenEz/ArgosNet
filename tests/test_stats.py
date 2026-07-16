"""Tests du moteur de statistiques."""
import threading

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
    # p1/p2 = TCP (SYN/SYN-ACK sans charge utile) ; p3 = HTTP (décodeur enrichi).
    assert breakdown.get("TCP") == 2
    assert breakdown.get("HTTP") == 1


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


def test_summary():
    s = _engine().summary()
    assert s["total_packets"] == 9
    assert dict(s["protocols"]).get("TCP") == 2
    assert s["duration"] >= 1
    assert s["distinct_talkers"] > 0


def test_throughput_by_protocol():
    seconds, series = _engine().throughput_by_protocol(5)
    # Les protocoles retournés sont ceux du top ; TCP y figure (2 paquets).
    assert "TCP" in series
    # Chaque série a la même longueur que l'axe des secondes.
    assert all(len(values) == len(seconds) for values in series.values())
    # La somme sur toutes les courbes vaut le nombre de paquets des protocoles du top.
    top = {name for name, _ in _engine().proto_counts.most_common(5)}
    expected = sum(_engine().proto_counts[name] for name in top)
    assert sum(sum(v) for v in series.values()) == expected


def test_throughput_by_protocol_empty():
    seconds, series = StatsEngine().throughput_by_protocol()
    assert seconds == []
    assert series == {}


def test_concurrent_add_and_read():
    # Le worker d'analyse alimente le moteur pendant que la GUI lit les agrégats :
    # les lectures itèrent sur les compteurs et doivent rester sûres sous verrou.
    engine = StatsEngine()
    packets = build_sample_packets()
    rounds = 150
    errors: list = []

    def writer():
        try:
            for _ in range(rounds):
                engine.add_packets(packets)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    def reader():
        try:
            for _ in range(rounds):
                engine.top_talkers(5)
                engine.top_conversations(5)
                engine.protocol_breakdown()
                engine.distinct_protocols()
                engine.throughput_series()
                engine.throughput_by_protocol()
                engine.summary()
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=writer), threading.Thread(target=reader)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert not errors, errors
    assert engine.total_packets == rounds * len(packets)


def test_reset_keeps_engine_usable():
    # reset() vide les compteurs sans recréer le verrou : le moteur reste utilisable.
    engine = _engine()
    engine.reset()
    assert engine.total_packets == 0
    engine.add_packets(build_sample_packets())
    assert engine.total_packets == 9


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
