"""Onglet « Carte » : cartographie graphique du réseau.

Construit un graphe nœud-lien à partir des conversations observées : chaque nœud est
un hôte (IP), chaque arête un échange de trafic. Les hôtes du réseau local et les hôtes
externes sont colorés différemment. Alimenté par ``packets_added`` et rafraîchi par un
``QTimer``, comme le dashboard.
"""
from __future__ import annotations

import math

import numpy as np
import pyqtgraph as pg
from PySide6.QtCore import QTimer
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QHBoxLayout, QLabel, QVBoxLayout, QWidget

from argosnet.core.geoip import is_external
from argosnet.core.i18n import tr
from argosnet.core.stats import StatsEngine

REFRESH_MS = 1500
MAX_NODES = 30
MAX_EDGES = 60

LOCAL_COLOR = "#3fbf6f"    # hôtes du réseau local
EXTERNAL_COLOR = "#e0973b"  # hôtes externes


def is_local(ip: str) -> bool:
    """Hôte non public (réseau local, CGN, réservé…).

    Délègue à ``core/geoip`` pour une classification unique et complète dans toute
    l'application (évite une seconde définition divergente).
    """
    return not is_external(ip)


class NetworkMapView(QWidget):
    def __init__(self, stats: StatsEngine) -> None:
        super().__init__()
        self._stats = stats  # moteur partagé, alimenté par le worker d'analyse
        self._last_total = -1

        pg.setConfigOptions(antialias=True, background=None, foreground="#888")
        self._build_ui()

        self._timer = QTimer(self)
        self._timer.setInterval(REFRESH_MS)
        self._timer.timeout.connect(self._refresh)
        self._timer.start()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)

        legend = QHBoxLayout()
        legend.addWidget(self._legend_dot(LOCAL_COLOR, tr("Hôte local")))
        legend.addWidget(self._legend_dot(EXTERNAL_COLOR, tr("Hôte externe")))
        legend.addStretch(1)
        self._info = QLabel(tr("En attente de trafic…"))
        self._info.setStyleSheet("color: gray;")
        legend.addWidget(self._info)
        root.addLayout(legend)

        self._plot = pg.PlotWidget()
        self._plot.hideAxis("bottom")
        self._plot.hideAxis("left")
        self._plot.setAspectLocked(True)
        self._plot.setMenuEnabled(False)
        self._graph = pg.GraphItem()
        self._plot.addItem(self._graph)
        self._labels: list[pg.TextItem] = []
        root.addWidget(self._plot, 1)

    @staticmethod
    def _legend_dot(color: str, text: str) -> QLabel:
        label = QLabel(f"● {text}")
        label.setStyleSheet(f"color: {color};")
        return label

    def reset(self) -> None:
        """Vide l'affichage — les statistiques partagées sont remises à zéro en amont."""
        self._last_total = -1
        self._clear_graph()
        self._info.setText(tr("En attente de trafic…"))

    # -------------------------------------------------------------- rendu
    def _clear_graph(self) -> None:
        self._graph.setData(pos=np.empty((0, 2)), adj=np.empty((0, 2), dtype=int))
        for label in self._labels:
            self._plot.removeItem(label)
        self._labels = []

    def _refresh(self) -> None:
        total = self._stats.total_packets
        if total == self._last_total:
            return
        self._last_total = total

        nodes = [t.address for t in self._stats.top_talkers(MAX_NODES)]
        if not nodes:
            self._clear_graph()
            return
        index = {ip: i for i, ip in enumerate(nodes)}

        # Positions : disposition circulaire.
        n = len(nodes)
        pos = np.array(
            [[math.cos(2 * math.pi * i / n), math.sin(2 * math.pi * i / n)] for i in range(n)],
            dtype=float,
        )

        # Arêtes : conversations dont les deux extrémités sont des nœuds affichés.
        adj = []
        for a, b, _pk, _by in self._stats.top_conversations(MAX_EDGES):
            if a in index and b in index:
                adj.append([index[a], index[b]])
        adj_arr = np.array(adj, dtype=int) if adj else np.empty((0, 2), dtype=int)

        brushes = [pg.mkBrush(LOCAL_COLOR if is_local(ip) else EXTERNAL_COLOR) for ip in nodes]

        self._graph.setData(
            pos=pos,
            adj=adj_arr,
            size=16,
            symbol="o",
            symbolBrush=brushes,
            symbolPen=pg.mkPen("#222"),
            pen=pg.mkPen(QColor(140, 140, 140, 120), width=1),
            pxMode=True,
        )

        # Étiquettes IP (gérées manuellement pour rester compatibles toutes versions).
        for label in self._labels:
            self._plot.removeItem(label)
        self._labels = []
        for ip, (x, y) in zip(nodes, pos):
            text = pg.TextItem(ip, color="#bbb", anchor=(0.5, 1.4))
            text.setPos(x, y)
            self._plot.addItem(text)
            self._labels.append(text)

        self._info.setText(
            tr("{nodes} hôte(s), {edges} lien(s) affichés").format(nodes=n, edges=len(adj))
        )
