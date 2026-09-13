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

# Lots en attente au maximum : quand le worker décroche durablement, les lots
# excédentaires sont abandonnés et comptés (pas d'OOM), et l'interface l'affiche.
MAX_PENDING_BATCHES = 50


class AnalysisWorker(QThread):
    """Consomme les lots de paquets et émet les alertes détectées."""

    alerts_ready = Signal(int, list)  # (génération, alertes)

    def __init__(self, stats: StatsEngine, detection: DetectionEngine) -> None:
        super().__init__()
        self._stats = stats
        self._detection = detection
        self._queue: deque[tuple[int, list]] = deque()
        self._cond = threading.Condition()
        self._detection_lock = threading.RLock()
        self._process_lock = threading.Lock()
        self._running = True
        self._generation = 0
        self._dropped_packets = 0

    @property
    def generation(self) -> int:
        """Génération courante (incrémentée par :meth:`reset`)."""
        with self._cond:
            return self._generation

    # ------------------------------------------------------------- entrée
    def submit(self, start_number: int, packets: list) -> None:
        """Met un lot en file d'attente (appelé depuis le thread graphique)."""
        if not packets:
            return
        with self._cond:
            if len(self._queue) >= MAX_PENDING_BATCHES:
                self._dropped_packets += len(packets)
                return
            self._queue.append((start_number, packets))
            self._cond.notify()

    def pending_batches(self) -> int:
        with self._cond:
            return len(self._queue)

    def dropped_packets(self) -> int:
        """Paquets abandonnés (file pleine) depuis le dernier :meth:`reset`."""
        with self._cond:
            return self._dropped_packets

    # ------------------------------------------------------------- contrôle
    def reset(self) -> None:
        """Vide la file et réinitialise statistiques et détecteurs.

        La génération est incrémentée : les alertes d'un lot dépilé avant
        l'effacement (ancienne génération) sont ignorées par l'interface. On attend
        la fin du lot en cours avant de remettre à zéro (plus de stats fantômes).
        """
        with self._cond:
            self._queue.clear()
            self._generation += 1
            self._dropped_packets = 0
        with self._process_lock:
            pass  # attend la fin du lot en cours, sans rien faire d'autre
        self._stats.reset()
        with self._detection_lock:
            self._detection.reset()

    def stop(self) -> None:
        """Demande l'arrêt et attend la fin du thread (file vidée d'abord)."""
        with self._cond:
            self._queue.clear()
            self._running = False
            self._cond.notify_all()
        # Sans timeout : un lot est borné, le thread termine toujours. On ne
        # détruit plus jamais un QThread encore en cours à la fermeture.
        self.wait()

    # ------------------------------------------------------------- boucle
    def run(self) -> None:
        while True:
            with self._cond:
                while self._running and not self._queue:
                    self._cond.wait(WAIT_TIMEOUT)
                if not self._running and not self._queue:
                    return
                start_number, packets = self._queue.popleft()
                generation = self._generation

            self._process(generation, start_number, packets)

    def _process(self, generation: int, start_number: int, packets: list[Any]) -> None:
        with self._process_lock:
            try:
                self._stats.add_packets(packets)
                with self._detection_lock:
                    alerts = self._detection.feed(packets, start_number=start_number)
            except Exception:
                # L'analyse ne doit jamais tuer le thread : on abandonne ce lot.
                return
            if alerts:
                self.alerts_ready.emit(generation, alerts)
