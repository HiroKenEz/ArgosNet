"""Fenêtre principale d'ArgosNet.

Compose les onglets (Interfaces, Capture, Scan, Dashboard, Carte, Alertes) et joue le
rôle de racine d'assemblage : le flux de paquets de la vue de capture est distribué au
dashboard, à la carte réseau et au moteur de détection, dont les alertes sont affichées
et persistées en base SQLite.
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QHeaderView,
    QLabel,
    QMainWindow,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from argosnet import __app_name__, __version__
from argosnet.core.interfaces import NetIface, list_interfaces
from argosnet.core.detection.detectors import NewDeviceDetector
from argosnet.core.detection.engine import DetectionEngine
from argosnet.core.storage import Database
from argosnet.ui.alerts_view import AlertsView
from argosnet.ui.capture_view import CaptureView
from argosnet.ui.dashboard_view import DashboardView
from argosnet.ui.network_map_view import NetworkMapView
from argosnet.ui.scan_view import ScanView


class MainWindow(QMainWindow):
    """Fenêtre principale à onglets."""

    def __init__(self, db_path: str | None = None) -> None:
        super().__init__()
        self.setWindowTitle(f"{__app_name__} {__version__} — Analyseur réseau local")
        self.resize(1200, 750)

        self._interfaces: list[NetIface] = list_interfaces()

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self._db = Database(db_path)

        self.capture_view = CaptureView()
        self.scan_view = ScanView()
        self.dashboard_view = DashboardView()
        self.network_map_view = NetworkMapView()
        self.alerts_view = AlertsView()
        self._detection = DetectionEngine()

        # Les appareils déjà connus (base) ne redéclenchent pas d'alerte « nouvel appareil ».
        self._seed_known_devices()

        # Le flux de paquets alimente dashboard, carte réseau et moteur de détection ;
        # l'effacement réinitialise dashboard et carte (l'historique persiste en base).
        self.capture_view.packets_added.connect(self.dashboard_view.on_packets)
        self.capture_view.packets_added.connect(self.network_map_view.on_packets)
        self.capture_view.packets_added.connect(self._run_detection)
        self.capture_view.cleared.connect(self.dashboard_view.reset)
        self.capture_view.cleared.connect(self.network_map_view.reset)
        self.capture_view.cleared.connect(self._reset_detection)
        self.scan_view.device_found.connect(self._db.record_device)
        self.alerts_view.counts_changed.connect(self._update_alert_tab)

        self.tabs.addTab(self._build_interfaces_tab(), "Interfaces")
        self.tabs.addTab(self.capture_view, "Capture")
        self.tabs.addTab(self.scan_view, "Scan")
        self.tabs.addTab(self.dashboard_view, "Dashboard")
        self.tabs.addTab(self.network_map_view, "Carte")
        self._alerts_tab_index = self.tabs.addTab(self.alerts_view, "Alertes")

        self._build_menu()

        # Rejoue l'historique des alertes persistées.
        self.alerts_view.add_alerts(self._db.load_recent_alerts())

        self.statusBar().showMessage(
            f"{len(self._interfaces)} interface(s) réseau détectée(s)"
        )

    def _seed_known_devices(self) -> None:
        known = self._db.known_macs()
        for detector in self._detection.detectors:
            if isinstance(detector, NewDeviceDetector):
                detector.known = set(known)

    # ------------------------------------------------------------------ helpers
    def _build_menu(self) -> None:
        file_menu = self.menuBar().addMenu("&Fichier")

        open_action = file_menu.addAction("Ouvrir une capture .pcap…")
        open_action.triggered.connect(self._open_capture)

        save_action = file_menu.addAction("Enregistrer la capture…")
        save_action.triggered.connect(self.capture_view.save_pcap_dialog)

        file_menu.addSeparator()
        quit_action = file_menu.addAction("Quitter")
        quit_action.triggered.connect(self.close)

        view_menu = self.menuBar().addMenu("&Affichage")
        self._dark_action = view_menu.addAction("Thème sombre")
        self._dark_action.setCheckable(True)
        self._dark_action.setChecked(True)
        self._dark_action.toggled.connect(self._toggle_theme)

        history_menu = self.menuBar().addMenu("&Historique")
        clear_alerts = history_menu.addAction("Effacer l'historique des alertes")
        clear_alerts.triggered.connect(self._clear_alert_history)
        forget_devices = history_menu.addAction("Oublier les appareils connus")
        forget_devices.triggered.connect(self._forget_devices)

    def _clear_alert_history(self) -> None:
        self._db.clear_alerts()
        self.alerts_view.reset()
        self.statusBar().showMessage("Historique des alertes effacé.", 4000)

    def _forget_devices(self) -> None:
        self._db.clear_devices()
        self._seed_known_devices()
        self.statusBar().showMessage("Appareils connus oubliés.", 4000)

    def closeEvent(self, event) -> None:  # noqa: N802
        self.capture_view.stop_capture_if_running()
        self._db.close()
        super().closeEvent(event)

    def _toggle_theme(self, dark: bool) -> None:
        from PySide6.QtWidgets import QApplication

        from argosnet.ui.theme import apply_theme
        apply_theme(QApplication.instance(), dark)

    def _open_capture(self) -> None:
        self.tabs.setCurrentWidget(self.capture_view)
        self.capture_view.open_pcap_dialog()

    # ---------------------------------------------------------------- détection
    def _run_detection(self, packets: list) -> None:
        alerts = self._detection.feed(packets)
        if not alerts:
            return
        self.alerts_view.add_alerts(alerts)
        self._db.save_alerts(alerts)
        # Enregistre les appareils nouvellement découverts (source = MAC).
        for alert in alerts:
            if alert.category == "Nouvel appareil":
                self._db.record_device(alert.source)
        critical = sum(1 for a in alerts if a.severity.name == "CRITICAL")
        if critical:
            self.statusBar().showMessage(
                f"⚠️ {critical} alerte(s) critique(s) détectée(s)", 5000
            )

    def _reset_detection(self) -> None:
        self._detection.reset()
        self.alerts_view.reset()

    def _update_alert_tab(self, total: int, critical: int) -> None:
        label = "Alertes" if total == 0 else f"Alertes ({total})"
        self.tabs.setTabText(self._alerts_tab_index, label)

    @staticmethod
    def _placeholder(text: str) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        label = QLabel(text)
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        label.setStyleSheet("color: gray; font-size: 15px;")
        layout.addWidget(label)
        return widget

    def _build_interfaces_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.addWidget(QLabel("Interfaces réseau détectées :"))

        columns = ["Description", "Nom technique", "Adresse IP", "Adresse MAC", "Capture"]
        table = QTableWidget(len(self._interfaces), len(columns))
        table.setHorizontalHeaderLabels(columns)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)

        for row, iface in enumerate(self._interfaces):
            table.setItem(row, 0, QTableWidgetItem(iface.description))
            table.setItem(row, 1, QTableWidgetItem(iface.name))
            table.setItem(row, 2, QTableWidgetItem(iface.ip or "—"))
            table.setItem(row, 3, QTableWidgetItem(iface.mac or "—"))
            status = "✓ prête" if iface.capturable else "Npcap requis"
            table.setItem(row, 4, QTableWidgetItem(status))

        header = table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(table)

        if not self._interfaces:
            layout.addWidget(
                QLabel(
                    "Aucune interface détectée. Vérifiez que Npcap est installé "
                    "et que l'application est lancée en administrateur."
                )
            )
        elif not any(iface.capturable for iface in self._interfaces):
            note = QLabel(
                "ℹ️ Interfaces listées via l'API Windows. Installez Npcap pour activer "
                "la capture de paquets."
            )
            note.setStyleSheet("color: #b06a00;")
            layout.addWidget(note)
        return widget
