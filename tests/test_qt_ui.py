"""Régressions UI/threads — relecture PR #42 (requiert Qt : sautées en CI)."""
import os
import time

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication, QMessageBox


@pytest.fixture(scope="module")
def app():
    yield QApplication.instance() or QApplication([])


def _patch_dialogs(monkeypatch, answers=None):
    """Neutralise les boîtes modales (bloquantes en offscreen) et enregistre les appels."""
    calls = []
    answers = answers or {}

    def _info(*args, **kwargs):
        calls.append("information")
        return QMessageBox.StandardButton.Ok

    def _warn(*args, **kwargs):
        calls.append("warning")
        return QMessageBox.StandardButton.Ok

    def _crit(*args, **kwargs):
        calls.append("critical")
        return QMessageBox.StandardButton.Ok

    def _question(*args, **kwargs):
        calls.append("question")
        return answers.get("question", QMessageBox.StandardButton.Yes)

    monkeypatch.setattr(QMessageBox, "information", _info)
    monkeypatch.setattr(QMessageBox, "warning", _warn)
    monkeypatch.setattr(QMessageBox, "critical", _crit)
    monkeypatch.setattr(QMessageBox, "question", _question)
    return calls


def _pump(app, cond, timeout=15.0):
    end = time.time() + timeout
    while time.time() < end:
        app.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return False


def _tiny_pcap(path, n=3):
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    from scapy.utils import wrpcap

    pkts = []
    for i in range(n):
        pkt = Ether(src="02:00:00:00:00:01") / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(
            sport=1000 + i, dport=80, flags="S"
        )
        pkt.time = 1000.0 + i
        pkts.append(pkt)
    wrpcap(str(path), pkts)
    return str(path)


def test_finished_loader_cleared(app, tmp_path, monkeypatch):
    """#1 : après finished, _loader vaut None ; un 2e chargement fonctionne."""
    _patch_dialogs(monkeypatch)
    from argosnet.ui.capture_view import CaptureView

    view = CaptureView()
    view.load_pcap(_tiny_pcap(tmp_path / "a.pcap"))
    assert _pump(app, lambda: view._model.rowCount() >= 3)
    assert _pump(app, lambda: view._progress.isHidden())
    assert view._loader is None
    # 2e chargement : ne doit pas lever « C++ object already deleted ».
    view.load_pcap(_tiny_pcap(tmp_path / "b.pcap"))
    assert _pump(app, lambda: view._model.rowCount() >= 6)


def test_cancel_after_finished_does_not_raise(app, tmp_path, monkeypatch):
    """#1 : cancel_pcap_load (closeEvent) après finished ne lève pas."""
    _patch_dialogs(monkeypatch)
    from argosnet.ui.capture_view import CaptureView

    view = CaptureView()
    view.load_pcap(_tiny_pcap(tmp_path / "c.pcap"))
    assert _pump(app, lambda: view._model.rowCount() >= 3)
    assert _pump(app, lambda: view._progress.isHidden())
    view.cancel_pcap_load()  # ne doit pas lever


def test_stop_capture_drains_everything(app, monkeypatch):
    """#3 : _stop_capture vide tout le tampon (pas de résidus au scan suivant)."""
    _patch_dialogs(monkeypatch)
    import argosnet.ui.capture_view as cv_mod
    from fixtures import build_sample_packets

    monkeypatch.setattr(cv_mod, "DRAIN_MAX_ITEMS", 3)
    from argosnet.ui.capture_view import CaptureView

    view = CaptureView()
    for pkt in build_sample_packets():
        view._controller._on_packet(pkt)
    view._stop_capture()
    assert view._model.rowCount() == 9
    assert view._controller.drain() == []


def test_pcap_refused_when_view_full(app, monkeypatch):
    """#5 : chargement refusé quand la vue est au plafond (aucun loader créé)."""
    calls = _patch_dialogs(monkeypatch)
    import argosnet.ui.capture_view as cv_mod

    monkeypatch.setattr(cv_mod, "MAX_PACKETS_IN_VIEW", 5)
    from argosnet.core.dissect import PacketSummary
    from argosnet.ui.capture_view import CaptureView
    from argosnet.ui.packet_model import PacketRecord

    view = CaptureView()
    view._model.append_records([
        PacketRecord(number=i + 1, time=float(i),
                     summary=PacketSummary(src="a", dst="b", protocol="TCP", length=60, info="x"),
                     packet=None)
        for i in range(5)
    ])
    before = view._loader
    view.load_pcap("/nexiste/pas.pcap")
    assert view._loader is before
    assert "information" in calls


def test_pcap_loader_limited_to_remaining_capacity(app, tmp_path, monkeypatch):
    """#5 : le loader est borné à la capacité restante de la vue."""
    _patch_dialogs(monkeypatch)
    import argosnet.ui.capture_view as cv_mod

    monkeypatch.setattr(cv_mod, "MAX_PACKETS_IN_VIEW", 5)
    from argosnet.core.dissect import PacketSummary
    from argosnet.ui.capture_view import CaptureView
    from argosnet.ui.packet_model import PacketRecord

    view = CaptureView()
    view._model.append_records([
        PacketRecord(number=i + 1, time=float(i),
                     summary=PacketSummary(src="a", dst="b", protocol="TCP", length=60, info="x"),
                     packet=None)
        for i in range(2)
    ])
    view.load_pcap(_tiny_pcap(tmp_path / "d.pcap", n=1))
    loader = view._loader
    assert loader is not None
    assert loader._max_packets == 3
    assert _pump(app, lambda: view._model.rowCount() >= 3)


def test_worker_ignores_stale_generation(app):
    """#4 : un lot d'ancienne génération est abandonné avant stats.add_packets."""
    from fixtures import build_sample_packets

    from argosnet.core.analysis import AnalysisWorker
    from argosnet.core.detection.engine import DetectionEngine
    from argosnet.core.stats import StatsEngine

    pkt = build_sample_packets()[0]
    worker = AnalysisWorker(StatsEngine(), DetectionEngine(detectors=[]))
    worker._process(999, 1, [pkt])  # génération périmée
    assert worker._stats.total_packets == 0
    worker._process(worker.generation, 1, [pkt])  # génération courante
    assert worker._stats.total_packets == 1


def test_periodic_scan_skips_when_confirmation_needed(app, monkeypatch):
    """#6 : pas de scan ni popup en périodique si confirmation requise."""
    calls = _patch_dialogs(monkeypatch)
    import argosnet.ui.scan_view as sv_mod

    started = []

    class _Sig:
        def connect(self, *args):
            pass

    class FakeThread:
        def __init__(self, *args):
            self.host_found = _Sig()
            self.finished_scan = _Sig()
            self.error = _Sig()

        def isRunning(self):
            return False

        def start(self):
            started.append(True)

    monkeypatch.setattr(sv_mod, "HostDiscoveryThread", FakeThread)
    from argosnet.ui.scan_view import ScanView

    view = ScanView()
    view._target_edit.setText("192.168.1.0/23")  # > 256 adresses → confirmation requise
    view._periodic_scan()
    assert started == []
    assert "question" not in calls
    assert "192.168.0.0/23" in view._status.text()  # réseau normalisé cité dans la raison
