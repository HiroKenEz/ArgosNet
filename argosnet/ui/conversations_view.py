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

from argosnet.core.stats import StatsEngine
from argosnet.ui.dashboard_view import format_bytes

REFRESH_MS = 1000
COLUMNS = ["Hôte A", "Hôte B", "Paquets", "Volume"]


class ConversationsView(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self._stats = StatsEngine()
        self._last_total = -1
        self._build_ui()

        self._timer = QTimer(self)
        self._timer.setInterval(REFRESH_MS)
        self._timer.timeout.connect(self._refresh)
        self._timer.start()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        self._info = QLabel("Conversations entre hôtes (triées par volume).")
        self._info.setStyleSheet("color: gray;")
        root.addWidget(self._info)
        self._table = QTableWidget(0, len(COLUMNS))
        self._table.setHorizontalHeaderLabels(COLUMNS)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        header = self._table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        root.addWidget(self._table)

    # ------------------------------------------------------------- ingestion
    def on_packets(self, packets: list) -> None:
        self._stats.add_packets(packets)

    def reset(self) -> None:
        self._stats.reset()
        self._last_total = -1
        self._table.setRowCount(0)

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
        self._info.setText(f"{len(conversations)} conversation(s) — triées par volume.")
