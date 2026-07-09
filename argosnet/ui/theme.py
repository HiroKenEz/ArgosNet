"""Thèmes clair / sombre pour ArgosNet.

Utilise le style « Fusion » (rendu identique sur toutes les plateformes) et une
palette Qt. Les graphes pyqtgraph sont configurés avec un fond transparent, ils
suivent donc automatiquement le thème de la fenêtre.
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QApplication


def apply_theme(app: QApplication, dark: bool) -> None:
    app.setStyle("Fusion")
    app.setPalette(_dark_palette() if dark else app.style().standardPalette())


def _dark_palette() -> QPalette:
    pal = QPalette()
    window = QColor(45, 45, 48)
    base = QColor(30, 30, 32)
    text = QColor(220, 220, 220)
    disabled = QColor(120, 120, 120)
    highlight = QColor(59, 125, 216)

    pal.setColor(QPalette.ColorRole.Window, window)
    pal.setColor(QPalette.ColorRole.WindowText, text)
    pal.setColor(QPalette.ColorRole.Base, base)
    pal.setColor(QPalette.ColorRole.AlternateBase, window)
    pal.setColor(QPalette.ColorRole.ToolTipBase, window)
    pal.setColor(QPalette.ColorRole.ToolTipText, text)
    pal.setColor(QPalette.ColorRole.Text, text)
    pal.setColor(QPalette.ColorRole.Button, QColor(53, 53, 55))
    pal.setColor(QPalette.ColorRole.ButtonText, text)
    pal.setColor(QPalette.ColorRole.BrightText, Qt.GlobalColor.red)
    pal.setColor(QPalette.ColorRole.Link, QColor(90, 150, 240))
    pal.setColor(QPalette.ColorRole.Highlight, highlight)
    pal.setColor(QPalette.ColorRole.HighlightedText, Qt.GlobalColor.white)
    pal.setColor(QPalette.ColorRole.PlaceholderText, disabled)

    for group in (QPalette.ColorGroup.Disabled,):
        pal.setColor(group, QPalette.ColorRole.Text, disabled)
        pal.setColor(group, QPalette.ColorRole.ButtonText, disabled)
        pal.setColor(group, QPalette.ColorRole.WindowText, disabled)
    return pal
