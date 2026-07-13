"""Onglet « Appareils » : inventaire persistant du réseau (base SQLite).

Affiche les appareils connus (MAC, IP, constructeur, nom d'hôte, vu le/dernier) et permet
d'attribuer un **libellé personnalisé** à chacun (colonne éditable, sauvegardée en base).
"""
from __future__ import annotations

import time

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

COLUMNS = ["MAC", "IP", "Constructeur", "Nom d'hôte", "Libellé", "Vu le", "Dernier"]
LABEL_COL = 4


def _fmt_time(ts) -> str:
    if not ts:
        return "—"
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))


class DevicesView(QWidget):
    def __init__(self, db) -> None:
        super().__init__()
        self._db = db
        self._building = False
        self._build_ui()
        self.refresh()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        bar = QHBoxLayout()
        self._info = QLabel("Appareils connus.")
        self._info.setStyleSheet("font-weight: bold;")
        bar.addWidget(self._info)
        bar.addStretch(1)
        hint = QLabel("Double-cliquez la colonne « Libellé » pour nommer un appareil.")
        hint.setStyleSheet("color: gray;")
        bar.addWidget(hint)
        refresh_btn = QPushButton("Rafraîchir")
        refresh_btn.clicked.connect(self.refresh)
        bar.addWidget(refresh_btn)
        root.addLayout(bar)

        self._table = QTableWidget(0, len(COLUMNS))
        self._table.setHorizontalHeaderLabels(COLUMNS)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(
            QTableWidget.EditTrigger.DoubleClicked | QTableWidget.EditTrigger.EditKeyPressed
        )
        header = self._table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(LABEL_COL, QHeaderView.ResizeMode.Stretch)
        self._table.itemChanged.connect(self._on_item_changed)
        root.addWidget(self._table)

    # ------------------------------------------------------------------ API
    def refresh(self) -> None:
        devices = self._db.list_devices()
        self._building = True
        self._table.setRowCount(len(devices))
        for row, dev in enumerate(devices):
            self._table.setItem(row, 0, self._readonly(dev.get("mac", "")))
            self._table.setItem(row, 1, self._readonly(dev.get("ip") or "—"))
            self._table.setItem(row, 2, self._readonly(dev.get("vendor") or "—"))
            self._table.setItem(row, 3, self._readonly(dev.get("hostname") or "—"))
            label_item = QTableWidgetItem(dev.get("label") or "")
            label_item.setData(Qt.ItemDataRole.UserRole, dev.get("mac", ""))
            self._table.setItem(row, LABEL_COL, label_item)
            self._table.setItem(row, 5, self._readonly(_fmt_time(dev.get("first_seen"))))
            self._table.setItem(row, 6, self._readonly(_fmt_time(dev.get("last_seen"))))
        self._building = False
        self._info.setText(f"{len(devices)} appareil(s) connu(s)")

    # ------------------------------------------------------------- interne
    @staticmethod
    def _readonly(text: str) -> QTableWidgetItem:
        item = QTableWidgetItem(text)
        item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
        return item

    def _on_item_changed(self, item: QTableWidgetItem) -> None:
        if self._building or item.column() != LABEL_COL:
            return
        mac = item.data(Qt.ItemDataRole.UserRole)
        if mac:
            self._db.set_device_label(mac, item.text())
