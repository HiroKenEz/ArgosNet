"""Worker d'analyse : statistiques et détection **hors du thread graphique**.

À haut débit, agréger les statistiques et passer chaque paquet dans les détecteurs
coûte cher. Faire ce travail dans le thread graphique le fait saccader. Ce worker
consomme les lots de paquets dans son propre thread et ne renvoie à l'interface que
les alertes, via un signal Qt (connexion automatiquement mise en file d'attente).

L'interface, elle, lit les agrégats du :class:`~argosnet.core.stats.StatsEngine`
partagé depuis son ``QTimer`` : le moteur est thread-safe (verrou interne).

Chaque lot porte le **numéro de son premier paquet** : la numérotation des alertes
reste alignée sur la liste de capture sans dépendre de l'ordonnancement des threads.
"""
from __future__ import annotations

import threading
from collections import deque
from typing import Any

from PySide6.QtCore import QThread, Signal

from argosnet.core.detection.engine import DetectionEngine
from argosnet.core.stats import StatsEngine

WAIT_TIMEOUT = 0.2  # s — réveil périodique pour vérifier la demande d'arrêt


class AnalysisWorker(QThread):
    """Consomme les lots de paquets et émet les alertes détectées."""

    alerts_ready = Signal(list)  # list[Alert]

    def __init__(self, stats: StatsEngine, detection: DetectionEngine) -> None:
        super().__init__()
        self._stats = stats
        self._detection = detection
        self._queue: deque[tuple[int, list]] = deque()
        self._cond = threading.Condition()
        self._detection_lock = threading.RLock()
        self._running = True

    # ------------------------------------------------------------- entrée
    def submit(self, start_number: int, packets: list) -> None:
        """Met un lot en file d'attente (appelé depuis le thread graphique)."""
        if not packets:
            return
        with self._cond:
            self._queue.append((start_number, list(packets)))
            self._cond.notify()

    def pending_batches(self) -> int:
        with self._cond:
            return len(self._queue)

    # ------------------------------------------------------------- contrôle
    def reset(self) -> None:
        """Vide la file et réinitialise statistiques et détecteurs."""
        with self._cond:
            self._queue.clear()
        self._stats.reset()
        with self._detection_lock:
            self._detection.reset()

    def stop(self) -> None:
        """Demande l'arrêt et attend la fin du thread."""
        with self._cond:
            self._running = False
            self._cond.notify_all()
        self.wait(2000)

    # ------------------------------------------------------------- boucle
    def run(self) -> None:
        while True:
            with self._cond:
                while self._running and not self._queue:
                    self._cond.wait(WAIT_TIMEOUT)
                if not self._running and not self._queue:
                    return
                start_number, packets = self._queue.popleft()

            self._process(start_number, packets)

    def _process(self, start_number: int, packets: list[Any]) -> None:
        try:
            self._stats.add_packets(packets)
            with self._detection_lock:
                alerts = self._detection.feed(packets, start_number=start_number)
        except Exception:
            # L'analyse ne doit jamais tuer le thread : on abandonne ce lot.
            return
        if alerts:
            self.alerts_ready.emit(alerts)
