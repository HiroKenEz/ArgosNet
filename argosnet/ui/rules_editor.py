"""Éditeur de règles de détection (mini-IDS), enregistrées dans ~/.argosnet/rules.yaml."""
from __future__ import annotations

from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

COLUMNS = ["Nom", "Port dest.", "Contient", "Gravité", "Message"]
SEVERITIES = ("info", "warning", "critical")


class RulesEditorDialog(QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Règles de détection (mini-IDS)")
        self.resize(780, 460)
        layout = QVBoxLayout(self)

        info = QLabel(
            "Chaque règle peut cibler un <b>port de destination</b> et/ou une "
            "<b>sous-chaîne</b> dans la charge utile. Gravité : info, warning ou critical. "
            "Enregistré dans <code>~/.argosnet/rules.yaml</code>."
        )
        info.setWordWrap(True)
        info.setStyleSheet("color: gray;")
        layout.addWidget(info)

        self._table = QTableWidget(0, len(COLUMNS))
        self._table.setHorizontalHeaderLabels(COLUMNS)
        header = self._table.horizontalHeader()
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self._table)

        bar = QHBoxLayout()
        add_btn = QPushButton("Ajouter")
        add_btn.clicked.connect(lambda: self._append({"severity": "warning"}))
        rem_btn = QPushButton("Supprimer la ligne")
        rem_btn.clicked.connect(self._remove_row)
        bar.addWidget(add_btn)
        bar.addWidget(rem_btn)
        bar.addStretch(1)
        save_btn = QPushButton("Enregistrer")
        save_btn.clicked.connect(self._save)
        cancel_btn = QPushButton("Annuler")
        cancel_btn.clicked.connect(self.reject)
        bar.addWidget(save_btn)
        bar.addWidget(cancel_btn)
        layout.addLayout(bar)

        self._load()

    def _load(self) -> None:
        from argosnet.core.detection.detectors import load_rules
        for rule in load_rules():
            self._append(rule)

    def _append(self, rule: dict) -> None:
        row = self._table.rowCount()
        self._table.insertRow(row)
        port = rule.get("dst_port")
        values = [
            str(rule.get("name", "")),
            "" if port is None else str(port),
            str(rule.get("contains", "") or ""),
            str(rule.get("severity", "warning")),
            str(rule.get("message", "")),
        ]
        for col, text in enumerate(values):
            self._table.setItem(row, col, QTableWidgetItem(text))

    def _remove_row(self) -> None:
        row = self._table.currentRow()
        if row >= 0:
            self._table.removeRow(row)

    def _collect(self) -> list[dict]:
        rules: list[dict] = []
        for row in range(self._table.rowCount()):
            def cell(col: int) -> str:
                item = self._table.item(row, col)
                return item.text().strip() if item else ""

            name, port, contains, severity, message = (cell(c) for c in range(5))
            if not (name or port or contains):
                continue  # ligne vide
            rule: dict = {"name": name or "Règle"}
            if port.isdigit():
                rule["dst_port"] = int(port)
            if contains:
                rule["contains"] = contains
            rule["severity"] = severity.lower() if severity.lower() in SEVERITIES else "warning"
            rule["message"] = message
            rules.append(rule)
        return rules

    def _save(self) -> None:
        from argosnet.core.detection.detectors import save_rules
        try:
            save_rules(self._collect())
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Enregistrement impossible", str(exc))
            return
        self.accept()
