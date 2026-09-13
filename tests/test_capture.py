"""Tests du contrôleur de capture (tampon borné, drain partiel, compteur de pertes)."""
from argosnet.core.capture import CaptureController


class _Pkt:
    def __init__(self, i):
        self.i = i


def _feed(controller, n):
    for i in range(n):
        controller._on_packet(_Pkt(i))


def test_drain_max_items_keeps_remainder():
    # drain(3) sur 7 paquets → 3 puis 4 (#1+#2).
    controller = CaptureController(max_buffer=100)
    _feed(controller, 7)
    first = controller.drain(3)
    assert [p.i for p in first] == [0, 1, 2]
    rest = controller.drain()
    assert [p.i for p in rest] == [3, 4, 5, 6]


def test_drain_without_limit_empties_buffer():
    controller = CaptureController(max_buffer=100)
    _feed(controller, 5)
    assert len(controller.drain()) == 5
    assert controller.drain() == []


def test_reset_dropped():
    # Tampon plein → pertes comptées, remises à zéro (#38).
    controller = CaptureController(max_buffer=2)
    _feed(controller, 5)
    assert controller.dropped_count() == 3
    controller.reset_dropped()
    assert controller.dropped_count() == 0


def test_start_clears_buffer_and_resets_dropped(monkeypatch):
    # Une nouvelle capture repart d'un tampon vide (#3, relecture PR #42).
    import scapy.sendrecv

    class FakeSniffer:
        def __init__(self, *args, **kwargs):
            self.running = False

        def start(self):
            pass

        def stop(self):
            pass

    monkeypatch.setattr(scapy.sendrecv, "AsyncSniffer", FakeSniffer)
    controller = CaptureController(max_buffer=2)
    _feed(controller, 5)
    controller.start()
    try:
        assert controller.drain() == []
        assert controller.dropped_count() == 0
    finally:
        controller.stop()
