"""Boîte de dialogue « Suivre le flux TCP » : affiche le flux réassemblé, coloré par sens."""
from __future__ import annotations

from PySide6.QtGui import QColor, QFont, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
)

from argosnet.core.i18n import tr

CLIENT_COLOR = "#3b7dd8"   # a → b
SERVER_COLOR = "#d9534f"   # b → a


class FollowStreamDialog(QDialog):
    def __init__(self, stream, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(
            tr("Suivre le flux TCP — {a} ↔ {b}").format(
                a=stream.endpoint_a, b=stream.endpoint_b
            )
        )
        self.resize(820, 600)
        layout = QVBoxLayout(self)

        legend = QLabel(
            f"<span style='color:{CLIENT_COLOR}'>■</span> {stream.endpoint_a} → {stream.endpoint_b}"
            f"    <span style='color:{SERVER_COLOR}'>■</span> {stream.endpoint_b} → {stream.endpoint_a}"
            f"    ({stream.total_bytes()} {tr('octets')})"
        )
        layout.addWidget(legend)

        self._view = QTextEdit()
        self._view.setReadOnly(True)
        self._view.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        font = QFont("Consolas")
        font.setStyleHint(QFont.StyleHint.Monospace)
        font.setPointSize(10)
        self._view.setFont(font)
        layout.addWidget(self._view, 1)

        self._render(stream)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        copy_btn = QPushButton(tr("Copier"))
        copy_btn.clicked.connect(lambda: QApplication.clipboard().setText(self._view.toPlainText()))
        close_btn = QPushButton(tr("Fermer"))
        close_btn.clicked.connect(self.accept)
        buttons.addWidget(copy_btn)
        buttons.addWidget(close_btn)
        layout.addLayout(buttons)

    def _render(self, stream) -> None:
        client_fmt = QTextCharFormat()
        client_fmt.setForeground(QColor(CLIENT_COLOR))
        server_fmt = QTextCharFormat()
        server_fmt.setForeground(QColor(SERVER_COLOR))
        cursor = self._view.textCursor()
        for a_to_b, data in stream.segments:
            cursor.insertText(data.decode("utf-8", "replace"), client_fmt if a_to_b else server_fmt)
        self._view.moveCursor(QTextCursor.MoveOperation.Start)
