"""Point d'entrée d'ArgosNet.

Usage :
    python -m argosnet.main
    python -m argosnet.main --selftest   # vérification à froid (pour l'.exe empaqueté)
"""
from __future__ import annotations

import os
import sys


def _selftest() -> int:
    """Démarrage à froid sans interaction : vérifie que tout est bien empaqueté."""
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication

    from argosnet.core.detection.detectors import load_rules
    from argosnet.ui.main_window import MainWindow

    app = QApplication([])  # noqa: F841 (doit exister avant tout widget)
    window = MainWindow()
    tabs = [window.tabs.tabText(i) for i in range(window.tabs.count())]
    rules = load_rules()

    ok = len(tabs) >= 5 and len(rules) > 0
    print("ArgosNet self-test :", "OK" if ok else "ÉCHEC")
    print("  onglets    :", tabs)
    print("  règles IDS :", len(rules))
    print("  interfaces :", len(window._interfaces))
    return 0 if ok else 1


def main() -> int:
    if "--selftest" in sys.argv:
        return _selftest()

    from PySide6.QtWidgets import QApplication, QMessageBox

    from PySide6.QtGui import QIcon

    from argosnet import __app_name__
    from argosnet.core.environment import environment_warnings
    from argosnet.core.i18n import load_language
    from argosnet.core.resources import app_icon_path
    from argosnet.ui.main_window import MainWindow
    from argosnet.ui.theme import apply_theme

    load_language()  # applique la langue persistée avant de construire l'interface

    app = QApplication(sys.argv)
    app.setApplicationName(__app_name__)
    app.setWindowIcon(QIcon(app_icon_path()))
    apply_theme(app, dark=True)  # thème sombre par défaut (basculable dans le menu Affichage)

    window = MainWindow()
    window.show()

    # Avertissements non bloquants sur l'environnement (Npcap, privilèges).
    warnings = environment_warnings()
    if warnings:
        QMessageBox.warning(
            window,
            f"{__app_name__} — vérification de l'environnement",
            "\n\n".join(warnings),
        )

    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
