"""Onglet « Conversations » : paires d'hôtes et volumes échangés (à la Wireshark).

Alimenté par ``packets_added`` et rafraîchi périodiquement, comme le dashboard.
"""
from __future__ import annotations

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QHeaderView,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from argosnet.core.geoip import classify_ip, describe, is_external
from argosnet.core.i18n import tr
from argosnet.core.stats import StatsEngine
from argosnet.ui.dashboard_view import format_bytes

REFRESH_MS = 1000
COLUMNS = ["Hôte A", "Hôte B", "Paquets", "Volume", "Zone"]


class ConversationsView(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self._stats = StatsEngine()
        self._last_total = -1
        self._zone_cache: dict[str, str] = {}  # IP -> zone (évite de recalculer)
        self._build_ui()

        self._timer = QTimer(self)
        self._timer.setInterval(REFRESH_MS)
        self._timer.timeout.connect(self._refresh)
        self._timer.start()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        self._info = QLabel(tr("Conversations entre hôtes (triées par volume)."))
        self._info.setStyleSheet("color: gray;")
        root.addWidget(self._info)
        self._table = QTableWidget(0, len(COLUMNS))
        self._table.setHorizontalHeaderLabels([tr(c) for c in COLUMNS])
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        header = self._table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        root.addWidget(self._table)

    # ------------------------------------------------------------- ingestion
    def on_packets(self, packets: list) -> None:
        self._stats.add_packets(packets)

    def reset(self) -> None:
        self._stats.reset()
        self._last_total = -1
        self._zone_cache.clear()
        self._table.setRowCount(0)

    def _zone_for(self, a: str, b: str) -> str:
        """Zone de la conversation : l'hôte externe s'il y en a un, sinon « local »."""
        external = a if is_external(a) else (b if is_external(b) else None)
        if external is None:
            # Deux hôtes non publics : catégorie de A (privé, CGN…) ou « local ».
            cat = classify_ip(a)
            return tr("local") if cat == "privé" else cat
        if external not in self._zone_cache:
            self._zone_cache[external] = describe(external)
        return self._zone_cache[external]

    # ------------------------------------------------------------- rendu
    def _refresh(self) -> None:
        if self._stats.total_packets == self._last_total:
            return
        self._last_total = self._stats.total_packets
        conversations = self._stats.top_conversations(200)
        self._table.setRowCount(len(conversations))
        for row, (a, b, packets, byte_count) in enumerate(conversations):
            self._table.setItem(row, 0, QTableWidgetItem(a))
            self._table.setItem(row, 1, QTableWidgetItem(b))
            pkt_item = QTableWidgetItem(str(packets))
            pkt_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            self._table.setItem(row, 2, pkt_item)
            vol_item = QTableWidgetItem(format_bytes(byte_count))
            vol_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            self._table.setItem(row, 3, vol_item)
            self._table.setItem(row, 4, QTableWidgetItem(self._zone_for(a, b)))
        self._info.setText(
            tr("{count} conversation(s) — triées par volume.").format(count=len(conversations))
        )
