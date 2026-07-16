"""Onglet « Dashboard » : statistiques et visualisation temps réel.

Alimenté par le signal ``packets_added`` de la vue de capture. Les graphes sont
rafraîchis périodiquement (et non à chaque paquet) par un ``QTimer``.
"""
from __future__ import annotations

import pyqtgraph as pg
from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from argosnet.core.i18n import tr
from argosnet.core.stats import StatsEngine

REFRESH_MS = 1000
IO_COLORS = ["#3b7dd8", "#d9534f", "#5cb85c", "#f0ad4e", "#9b59b6", "#1abc9c"]


def format_bytes(num: float) -> str:
    for unit in ("o", "Ko", "Mo", "Go"):
        if num < 1024 or unit == "Go":
            return f"{num:.0f} {unit}" if unit == "o" else f"{num:.1f} {unit}"
        num /= 1024
    return f"{num:.1f} Go"


class StatTile(QFrame):
    """Petite tuile « valeur + libellé »."""

    def __init__(self, caption: str) -> None:
        super().__init__()
        self.setFrameShape(QFrame.Shape.StyledPanel)
        layout = QVBoxLayout(self)
        self._value = QLabel("—")
        self._value.setStyleSheet("font-size: 22px; font-weight: bold;")
        self._value.setAlignment(Qt.AlignmentFlag.AlignCenter)
        cap = QLabel(caption)
        cap.setStyleSheet("color: gray;")
        cap.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._value)
        layout.addWidget(cap)

    def set_value(self, text: str) -> None:
        self._value.setText(text)


class DashboardView(QWidget):
    def __init__(self, stats: StatsEngine) -> None:
        super().__init__()
        self._stats = stats  # moteur partagé, alimenté par le worker d'analyse
        self._last_total = -1

        # Fond transparent → suit le thème de la fenêtre ; gris moyen visible
        # aussi bien sur fond clair que sombre.
        pg.setConfigOptions(antialias=True, background=None, foreground="#888")
        self._build_ui()

        self._timer = QTimer(self)
        self._timer.setInterval(REFRESH_MS)
        self._timer.timeout.connect(self._refresh)
        self._timer.start()

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        root = QVBoxLayout(self)

        tiles = QHBoxLayout()
        self._tile_packets = StatTile(tr("Paquets"))
        self._tile_bytes = StatTile(tr("Volume total"))
        self._tile_rate = StatTile(tr("Débit moyen"))
        self._tile_protos = StatTile(tr("Protocoles"))
        for tile in (self._tile_packets, self._tile_bytes, self._tile_rate, self._tile_protos):
            tiles.addWidget(tile)
        root.addLayout(tiles)

        # Courbe de débit (paquets/s).
        self._tput_plot = pg.PlotWidget(title=tr("Débit (paquets/s)"))
        self._tput_plot.setLabel("bottom", tr("temps"), units="s")
        self._tput_plot.setLabel("left", tr("paquets/s"))
        self._tput_plot.showGrid(x=True, y=True, alpha=0.2)
        self._tput_curve = self._tput_plot.plot(
            pen=pg.mkPen("#3b7dd8", width=2), fillLevel=0, brush=(59, 125, 216, 60)
        )
        root.addWidget(self._tput_plot, 2)

        # IO Graph : une courbe de débit par protocole (façon Wireshark).
        self._io_plot = pg.PlotWidget(title=tr("Débit par protocole (paquets/s)"))
        self._io_plot.setLabel("bottom", tr("temps"), units="s")
        self._io_plot.setLabel("left", tr("paquets/s"))
        self._io_plot.showGrid(x=True, y=True, alpha=0.2)
        self._io_plot.addLegend(offset=(10, 10))
        self._io_curves: dict[str, pg.PlotDataItem] = {}
        root.addWidget(self._io_plot, 2)

        # Bas : répartition protocoles | top talkers.
        split = QSplitter(Qt.Orientation.Horizontal)

        self._proto_plot = pg.PlotWidget(title=tr("Répartition par protocole"))
        self._proto_plot.setLabel("left", tr("paquets"))
        self._proto_plot.showGrid(y=True, alpha=0.2)
        self._proto_bar: pg.BarGraphItem | None = None
        split.addWidget(self._proto_plot)

        talkers_box = QWidget()
        tb_layout = QVBoxLayout(talkers_box)
        tb_layout.addWidget(QLabel(tr("Top talkers (par volume)")))
        self._talkers = QTableWidget(0, 3)
        self._talkers.setHorizontalHeaderLabels([tr("Adresse"), tr("Paquets"), tr("Volume")])
        self._talkers.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._talkers.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        tb_layout.addWidget(self._talkers)
        split.addWidget(talkers_box)
        split.setSizes([520, 520])

        root.addWidget(split, 3)

    def reset(self) -> None:
        """Vide l'affichage — les statistiques partagées sont remises à zéro en amont."""
        self._last_total = -1
        self._refresh(force=True)

    # ------------------------------------------------------------- rendu
    def _refresh(self, force: bool = False) -> None:
        total = self._stats.total_packets
        if not force and total == self._last_total:
            return
        self._last_total = total

        self._tile_packets.set_value(f"{total:,}".replace(",", " "))
        self._tile_bytes.set_value(format_bytes(self._stats.total_bytes))
        self._tile_protos.set_value(str(self._stats.distinct_protocols()))

        seconds, pps, _kbps = self._stats.throughput_series()
        if seconds:
            self._tput_curve.setData(seconds, pps)
            duration = max(1, seconds[-1] + 1)
            self._tile_rate.set_value(tr("{rate} p/s").format(rate=f"{total / duration:.1f}"))
        else:
            self._tput_curve.setData([], [])
            self._tile_rate.set_value("—")

        self._refresh_io_graph()
        self._refresh_protocols()
        self._refresh_talkers()

    def _refresh_io_graph(self) -> None:
        seconds, series = self._stats.throughput_by_protocol(len(IO_COLORS))
        # Retire les courbes des protocoles qui ne sont plus dans le top.
        for proto in list(self._io_curves):
            if proto not in series:
                self._io_plot.removeItem(self._io_curves.pop(proto))
        for index, (proto, values) in enumerate(series.items()):
            curve = self._io_curves.get(proto)
            if curve is None:
                color = IO_COLORS[index % len(IO_COLORS)]
                curve = self._io_plot.plot(pen=pg.mkPen(color, width=2), name=proto)
                self._io_curves[proto] = curve
            curve.setData(seconds, values)

    def _refresh_protocols(self) -> None:
        breakdown = self._stats.protocol_breakdown()
        if self._proto_bar is not None:
            self._proto_plot.removeItem(self._proto_bar)
            self._proto_bar = None
        if not breakdown:
            return
        names = [name for name, _ in breakdown]
        counts = [count for _, count in breakdown]
        xs = list(range(len(names)))
        self._proto_bar = pg.BarGraphItem(
            x=xs, height=counts, width=0.6, brush="#3b7dd8"
        )
        self._proto_plot.addItem(self._proto_bar)
        axis = self._proto_plot.getAxis("bottom")
        axis.setTicks([list(zip(xs, names))])

    def _refresh_talkers(self) -> None:
        talkers = self._stats.top_talkers(12)
        self._talkers.setRowCount(len(talkers))
        for row, talker in enumerate(talkers):
            self._talkers.setItem(row, 0, QTableWidgetItem(talker.address))
            self._talkers.setItem(row, 1, QTableWidgetItem(str(talker.packets)))
            self._talkers.setItem(row, 2, QTableWidgetItem(format_bytes(talker.bytes)))
