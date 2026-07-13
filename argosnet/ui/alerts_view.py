"""Onglet « Alertes » : panneau des menaces détectées.

Reçoit les alertes du :class:`~argosnet.core.detection.engine.DetectionEngine` (via
la fenêtre principale) et les affiche, les plus récentes en haut, colorées par gravité.
"""
from __future__ import annotations

import csv
import time

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from argosnet.core.detection.alert import Alert, Severity

COLUMNS = ["Heure", "Gravité", "Catégorie", "Source", "N° paquet", "Détail"]

# Nombre maximum d'alertes affichées (les plus anciennes sont retirées de la vue ;
# l'historique complet reste consultable dans la base SQLite).
MAX_DISPLAY_ALERTS = 2000


class AlertsView(QWidget):
    # (total, nombre de critiques) — permet de mettre à jour le libellé de l'onglet.
    counts_changed = Signal(int, int)

    def __init__(self) -> None:
        super().__init__()
        self._total = 0
        self._critical = 0
        self._alerts: list[Alert] = []
        self._build_ui()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)

        bar = QHBoxLayout()
        self._summary = QLabel("Aucune alerte.")
        self._summary.setStyleSheet("font-weight: bold;")
        bar.addWidget(self._summary)
        bar.addStretch(1)
        export_btn = QPushButton("Exporter (CSV)…")
        export_btn.clicked.connect(self.export_csv_dialog)
        bar.addWidget(export_btn)
        clear_btn = QPushButton("Effacer les alertes")
        clear_btn.clicked.connect(self.reset)
        bar.addWidget(clear_btn)
        root.addLayout(bar)

        self._table = QTableWidget(0, len(COLUMNS))
        self._table.setHorizontalHeaderLabels(COLUMNS)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setWordWrap(True)
        header = self._table.horizontalHeader()
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        for col in (0, 1, 2, 3, 4):
            header.setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        root.addWidget(self._table)

    # ------------------------------------------------------------- API
    def add_alerts(self, alerts: list[Alert]) -> None:
        for alert in alerts:
            self._insert_alert(alert)
            self._alerts.append(alert)
        self._trim()
        if alerts:
            self._update_summary()

    def _trim(self) -> None:
        """Borne l'affichage : retire les alertes les plus anciennes au-delà du plafond."""
        overflow = len(self._alerts) - MAX_DISPLAY_ALERTS
        if overflow > 0:
            del self._alerts[:overflow]
            for _ in range(overflow):  # les plus anciennes sont en bas de la table
                self._table.removeRow(self._table.rowCount() - 1)

    def reset(self) -> None:
        self._table.setRowCount(0)
        self._alerts.clear()
        self._total = 0
        self._critical = 0
        self._update_summary()

    def export_csv_dialog(self) -> None:
        if not self._alerts:
            QMessageBox.information(self, "Rien à exporter", "Aucune alerte à exporter.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Exporter les alertes", "alertes.csv", "CSV (*.csv)"
        )
        if path:
            self.export_csv(path)

    def export_csv(self, path: str) -> None:
        """Écrit toutes les alertes dans un fichier CSV (UTF-8 avec BOM pour Excel)."""
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as handle:
                writer = csv.writer(handle, delimiter=";")
                writer.writerow(["Horodatage", "Gravité", "Catégorie", "Source", "N° paquet", "Détail"])
                for alert in self._alerts:
                    hhmmss = (
                        time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(alert.timestamp))
                        if alert.timestamp
                        else ""
                    )
                    writer.writerow(
                        [hhmmss, alert.severity.label, alert.category, alert.source,
                         alert.packet_number or "", alert.detail]
                    )
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Export impossible", f"Échec de l'écriture :\n{exc}")

    # ------------------------------------------------------------- interne
    def _insert_alert(self, alert: Alert) -> None:
        self._table.insertRow(0)  # les plus récentes en haut
        hhmmss = time.strftime("%H:%M:%S", time.localtime(alert.timestamp)) if alert.timestamp else "—"
        values = [
            hhmmss,
            alert.severity.label,
            alert.category,
            alert.source,
            str(alert.packet_number) if alert.packet_number else "—",
            alert.detail,
        ]
        brush = QBrush(QColor(alert.severity.color))
        dark_text = QBrush(QColor("#1a1a1a"))  # lisible sur fond coloré, quel que soit le thème
        for col, text in enumerate(values):
            item = QTableWidgetItem(text)
            item.setBackground(brush)
            item.setForeground(dark_text)
            if col == 1:
                item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(0, col, item)

        self._total += 1
        if alert.severity == Severity.CRITICAL:
            self._critical += 1

    def _update_summary(self) -> None:
        if self._total == 0:
            self._summary.setText("Aucune alerte.")
        else:
            self._summary.setText(
                f"{self._total} alerte(s) — dont {self._critical} critique(s)."
            )
        self.counts_changed.emit(self._total, self._critical)
