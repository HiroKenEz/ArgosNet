"""Capture de paquets en arrière-plan (Scapy AsyncSniffer).

Le sniffer tourne dans son propre thread natif et empile les paquets dans un tampon
protégé par un verrou. L'interface graphique vient les récupérer par lots via
:meth:`CaptureController.drain`, appelée périodiquement par un ``QTimer``. Ce schéma
producteur/consommateur évite d'émettre un signal Qt par paquet (coûteux à haut débit)
et garde la GUI fluide.
"""
from __future__ import annotations

import os
import threading
from collections import deque
from typing import Any, Optional


class RingWriter:
    """Écrit les paquets dans des fichiers ``.pcap`` rotatifs (monitoring continu).

    Le fichier courant est clôturé et remplacé dès qu'il atteint ``max_packets``
    paquets. Au plus ``max_files`` fichiers sont conservés sur le disque : au-delà,
    le plus ancien est supprimé. L'espace occupé est donc borné, ce qui permet une
    surveillance 24/7 sans saturer le disque.
    """

    def __init__(
        self,
        directory: str,
        prefix: str = "argosnet",
        max_files: int = 5,
        max_packets: int = 10_000,
    ) -> None:
        if max_files < 1:
            raise ValueError("max_files doit être >= 1")
        if max_packets < 1:
            raise ValueError("max_packets doit être >= 1")
        self.directory = directory
        self.prefix = prefix
        self.max_files = max_files
        self.max_packets = max_packets
        self._files: deque[str] = deque()
        self._writer: Any = None
        self._index = 0
        self._count = 0
        os.makedirs(directory, exist_ok=True)

    def _rotate(self) -> None:
        self._close_writer()
        from scapy.utils import PcapWriter

        self._index += 1
        path = os.path.join(self.directory, f"{self.prefix}-{self._index:04d}.pcap")
        self._writer = PcapWriter(path, append=False, sync=False)
        self._files.append(path)
        self._count = 0
        # Fenêtre glissante : supprime les fichiers les plus anciens hors quota.
        while len(self._files) > self.max_files:
            old = self._files.popleft()
            try:
                os.remove(old)
            except OSError:
                pass

    def write(self, packet: Any) -> None:
        if self._writer is None or self._count >= self.max_packets:
            self._rotate()
        self._writer.write(packet)
        self._count += 1

    def _close_writer(self) -> None:
        if self._writer is not None:
            try:
                self._writer.close()
            except Exception:
                pass
            self._writer = None

    def close(self) -> None:
        self._close_writer()

    def files(self) -> list[str]:
        """Fichiers .pcap actuellement conservés, du plus ancien au plus récent."""
        return list(self._files)


class CaptureController:
    """Pilote la capture et met les paquets en file d'attente pour la GUI."""

    def __init__(self, max_buffer: int = 100_000) -> None:
        self._sniffer: Any = None
        self._buffer: deque = deque(maxlen=max_buffer)
        self._lock = threading.Lock()
        self._dropped = 0  # paquets perdus (tampon plein, GUI trop lente à drainer)
        self._ring: Optional[RingWriter] = None

    # ---------------------------------------------------------------- cycle
    def start(
        self,
        iface: Any = None,
        bpf_filter: Optional[str] = None,
        ring: Optional["RingWriter"] = None,
    ) -> None:
        """Démarre la capture sur ``iface`` avec un éventuel filtre BPF.

        ``iface`` peut être un objet interface Scapy ou un nom ; ``None`` laisse
        Scapy choisir l'interface par défaut. Si ``ring`` est fourni, chaque paquet
        est aussi écrit dans la capture en anneau (fichiers .pcap rotatifs). Lève une
        exception si la capture ne peut pas démarrer (Npcap absent, privilèges
        insuffisants, filtre invalide).
        """
        if self.is_running():
            return
        from scapy.sendrecv import AsyncSniffer

        self._ring = ring
        self._sniffer = AsyncSniffer(
            iface=iface,
            filter=(bpf_filter or None),
            prn=self._on_packet,
            store=False,
        )
        self._sniffer.start()

    def stop(self) -> None:
        sniffer = self._sniffer
        self._sniffer = None
        if sniffer is not None:
            try:
                if getattr(sniffer, "running", False):
                    sniffer.stop()
            except Exception:
                pass
        # Le thread du sniffer est arrêté : plus aucun ``_on_packet`` ne tourne, on peut
        # clôturer sans risque la capture en anneau (flush du dernier fichier .pcap).
        ring = self._ring
        self._ring = None
        if ring is not None:
            ring.close()

    def is_running(self) -> bool:
        return self._sniffer is not None and bool(getattr(self._sniffer, "running", False))

    # ------------------------------------------------------- producteur/conso
    def _on_packet(self, packet: Any) -> None:
        # Appelé depuis le thread du sniffer : on empile simplement.
        with self._lock:
            if self._buffer.maxlen is not None and len(self._buffer) >= self._buffer.maxlen:
                # Le tampon est plein : append va évincer le plus ancien → paquet perdu.
                self._dropped += 1
            self._buffer.append(packet)
        # Écriture disque hors du verrou du tampon pour ne pas ralentir ``drain``.
        # Seul le thread du sniffer touche le writer, et ``stop`` attend son arrêt
        # avant de clôturer : pas de course.
        ring = self._ring
        if ring is not None:
            try:
                ring.write(packet)
            except Exception:
                pass

    def dropped_count(self) -> int:
        return self._dropped

    def drain(self) -> list[Any]:
        """Récupère et vide les paquets accumulés depuis le dernier appel."""
        with self._lock:
            if not self._buffer:
                return []
            items = list(self._buffer)
            self._buffer.clear()
        return items
