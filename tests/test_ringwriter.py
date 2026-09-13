"""Tests de la capture en anneau (fichiers .pcap rotatifs)."""
import os

import pytest
from fixtures import build_sample_packets
from scapy.utils import rdpcap

from argosnet.core.capture import RingWriter


def _packets(n):
    """Répète les paquets d'exemple pour en obtenir ``n``."""
    base = build_sample_packets()
    out = []
    while len(out) < n:
        out.extend(base)
    return out[:n]


def test_ring_rotation_and_cap(tmp_path):
    rw = RingWriter(str(tmp_path), prefix="test", max_files=2, max_packets=3)
    for pkt in _packets(9):
        rw.write(pkt)
    rw.close()

    kept = rw.files()
    assert len(kept) == 2  # quota de fichiers respecté
    on_disk = sorted(p.name for p in tmp_path.glob("*.pcap"))
    assert on_disk == ["test-0002.pcap", "test-0003.pcap"]  # les plus anciens purgés
    for path in kept:
        assert len(rdpcap(path)) == 3  # fichiers .pcap valides et complets


def test_ring_last_file_partial(tmp_path):
    rw = RingWriter(str(tmp_path), prefix="p", max_files=5, max_packets=4)
    for pkt in _packets(6):
        rw.write(pkt)
    rw.close()

    files = rw.files()
    assert len(files) == 2
    assert len(rdpcap(files[0])) == 4  # premier fichier plein
    assert len(rdpcap(files[1])) == 2  # second partiellement rempli, flush à la fermeture


def test_ring_validates_args(tmp_path):
    with pytest.raises(ValueError):
        RingWriter(str(tmp_path), max_files=0)
    with pytest.raises(ValueError):
        RingWriter(str(tmp_path), max_packets=0)


def test_ring_resumes_after_previous_session(tmp_path):
    # Une nouvelle session reprend après 0002 (pas d'écrasement) et le quota
    # s'applique aussi aux fichiers existants.
    rw1 = RingWriter(str(tmp_path), prefix="test", max_files=2, max_packets=2)
    for pkt in _packets(3):
        rw1.write(pkt)
    rw1.close()

    rw2 = RingWriter(str(tmp_path), prefix="test", max_files=2, max_packets=2)
    assert [os.path.basename(p) for p in rw2.files()] == ["test-0001.pcap", "test-0002.pcap"]
    for pkt in _packets(4):
        rw2.write(pkt)
    rw2.close()

    on_disk = sorted(p.name for p in tmp_path.glob("*.pcap"))
    assert on_disk == ["test-0003.pcap", "test-0004.pcap"]
