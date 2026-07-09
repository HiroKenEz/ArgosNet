"""Moteur de détection : oriente chaque paquet vers tous les détecteurs.

Le moteur maintient son propre compteur de paquets, aligné sur la numérotation de
la liste de capture (les deux consomment le même flux dans le même ordre), afin que
les alertes puissent référencer le numéro de paquet concerné.
"""
from __future__ import annotations

from typing import Any

from argosnet.core.detection.alert import Alert
from argosnet.core.detection.detectors import Detector, default_detectors


class DetectionEngine:
    def __init__(self, detectors: list[Detector] | None = None) -> None:
        self.detectors: list[Detector] = detectors if detectors is not None else default_detectors()
        self._counter = 0

    def feed(self, packets) -> list[Alert]:
        """Analyse un lot de paquets et renvoie les alertes déclenchées."""
        alerts: list[Alert] = []
        for pkt in packets:
            self._counter += 1
            for detector in self.detectors:
                try:
                    alerts.extend(detector.inspect(self._counter, pkt))
                except Exception:
                    # Un détecteur défaillant ne doit pas interrompre les autres.
                    continue
        return alerts

    def reset(self) -> None:
        self._counter = 0
        for detector in self.detectors:
            detector.reset()
