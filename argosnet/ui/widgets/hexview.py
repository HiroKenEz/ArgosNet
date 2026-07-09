"""Vue hexadécimale simple (offset | octets | ASCII), en police à chasse fixe."""
from __future__ import annotations

from PySide6.QtGui import QFont
from PySide6.QtWidgets import QPlainTextEdit


class HexView(QPlainTextEdit):
    def __init__(self) -> None:
        super().__init__()
        self.setReadOnly(True)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        font = QFont("Consolas")
        font.setStyleHint(QFont.StyleHint.Monospace)
        font.setPointSize(10)
        self.setFont(font)
        self.setPlaceholderText("Sélectionnez un paquet pour afficher son contenu hexadécimal.")

    def show_dump(self, dump: str) -> None:
        self.setPlainText(dump)

    def clear_dump(self) -> None:
        self.clear()
