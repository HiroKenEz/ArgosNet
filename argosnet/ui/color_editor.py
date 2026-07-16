"""Dialogue de personnalisation des couleurs de protocole (persistées)."""
from __future__ import annotations

from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QColorDialog,
    QDialog,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from argosnet.core.i18n import tr
from argosnet.ui.packet_model import (
    DEFAULT_PROTO_COLORS,
    PROTO_COLORS,
    apply_proto_colors,
    save_proto_colors,
)


class ColorEditorDialog(QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("Couleurs des protocoles"))
        self.resize(340, 480)
        self._pending = {proto: color.name() for proto, color in PROTO_COLORS.items()}
        self._buttons: dict[str, QPushButton] = {}

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(tr("Cliquez une couleur pour la modifier.")))

        grid = QGridLayout()
        for row, proto in enumerate(PROTO_COLORS):
            grid.addWidget(QLabel(proto), row, 0)
            button = QPushButton()
            self._paint(button, QColor(self._pending[proto]))
            button.clicked.connect(lambda _checked=False, p=proto: self._pick(p))
            self._buttons[proto] = button
            grid.addWidget(button, row, 1)
        container = QWidget()
        container.setLayout(grid)
        scroll = QScrollArea()
        scroll.setWidget(container)
        scroll.setWidgetResizable(True)
        layout.addWidget(scroll, 1)

        bar = QHBoxLayout()
        reset_btn = QPushButton(tr("Réinitialiser"))
        reset_btn.clicked.connect(self._reset)
        bar.addWidget(reset_btn)
        bar.addStretch(1)
        ok_btn = QPushButton(tr("OK"))
        ok_btn.clicked.connect(self._accept)
        cancel_btn = QPushButton(tr("Annuler"))
        cancel_btn.clicked.connect(self.reject)
        bar.addWidget(ok_btn)
        bar.addWidget(cancel_btn)
        layout.addLayout(bar)

    @staticmethod
    def _paint(button: QPushButton, color: QColor) -> None:
        button.setStyleSheet(f"background: {color.name()}; color: #111;")
        button.setText(color.name())

    def _pick(self, proto: str) -> None:
        color = QColorDialog.getColor(
            QColor(self._pending[proto]), self, tr("Couleur — {proto}").format(proto=proto)
        )
        if color.isValid():
            self._pending[proto] = color.name()
            self._paint(self._buttons[proto], color)

    def _reset(self) -> None:
        for proto, hex_color in DEFAULT_PROTO_COLORS.items():
            self._pending[proto] = hex_color
            if proto in self._buttons:
                self._paint(self._buttons[proto], QColor(hex_color))

    def _accept(self) -> None:
        apply_proto_colors(self._pending)
        save_proto_colors()
        self.accept()
