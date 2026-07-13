"""Capture de paquets en arrière-plan (Scapy AsyncSniffer).

Le sniffer tourne dans son propre thread natif et empile les paquets dans un tampon
protégé par un verrou. L'interface graphique vient les récupérer par lots via
:meth:`CaptureController.drain`, appelée périodiquement par un ``QTimer``. Ce schéma
producteur/consommateur évite d'émettre un signal Qt par paquet (coûteux à haut débit)
et garde la GUI fluide.
"""
from __future__ import annotations

import threading
from collections import deque
from typing import Any, Optional


class CaptureController:
    """Pilote la capture et met les paquets en file d'attente pour la GUI."""

    def __init__(self, max_buffer: int = 100_000) -> None:
        self._sniffer: Any = None
        self._buffer: deque = deque(maxlen=max_buffer)
        self._lock = threading.Lock()
        self._dropped = 0  # paquets perdus (tampon plein, GUI trop lente à drainer)

    # ---------------------------------------------------------------- cycle
    def start(self, iface: Any = None, bpf_filter: Optional[str] = None) -> None:
        """Démarre la capture sur ``iface`` avec un éventuel filtre BPF.

        ``iface`` peut être un objet interface Scapy ou un nom ; ``None`` laisse
        Scapy choisir l'interface par défaut. Lève une exception si la capture ne
        peut pas démarrer (Npcap absent, privilèges insuffisants, filtre invalide).
        """
        if self.is_running():
            return
        from scapy.sendrecv import AsyncSniffer

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
