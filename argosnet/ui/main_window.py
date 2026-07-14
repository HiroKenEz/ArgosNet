"""Fenêtre principale d'ArgosNet.

Compose les onglets (Interfaces, Capture, Scan, Dashboard, Carte, Alertes) et joue le
rôle de racine d'assemblage : le flux de paquets de la vue de capture est distribué au
dashboard, à la carte réseau et au moteur de détection, dont les alertes sont affichées
et persistées en base SQLite.
"""
from __future__ import annotations

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QApplication,
    QHeaderView,
    QLabel,
    QMainWindow,
    QMessageBox,
    QStyle,
    QSystemTrayIcon,
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
from argosnet.ui.conversations_view import ConversationsView
from argosnet.ui.dashboard_view import DashboardView
from argosnet.ui.devices_view import DevicesView
from argosnet.ui.network_map_view import NetworkMapView
from argosnet.ui.scan_view import ScanView


class MainWindow(QMainWindow):
    """Fenêtre principale à onglets."""

    def __init__(self, db_path: str | None = None) -> None:
        super().__init__()
        self.setWindowTitle(f"{__app_name__} {__version__} — Analyseur réseau local")
        self.resize(1200, 750)

        from argosnet.ui.packet_model import load_proto_colors
        load_proto_colors()  # couleurs de protocole personnalisées (si définies)

        self._interfaces: list[NetIface] = list_interfaces()

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self._db = Database(db_path)

        self.capture_view = CaptureView()
        self.scan_view = ScanView()
        self.dashboard_view = DashboardView()
        self.network_map_view = NetworkMapView()
        self.conversations_view = ConversationsView()
        self.devices_view = DevicesView(self._db)
        self.alerts_view = AlertsView()
        self._detection = DetectionEngine()

        # Les appareils déjà connus (base) ne redéclenchent pas d'alerte « nouvel appareil ».
        self._seed_known_devices()

        # Le flux de paquets alimente dashboard, carte réseau et moteur de détection ;
        # l'effacement réinitialise dashboard et carte (l'historique persiste en base).
        self.capture_view.packets_added.connect(self.dashboard_view.on_packets)
        self.capture_view.packets_added.connect(self.network_map_view.on_packets)
        self.capture_view.packets_added.connect(self.conversations_view.on_packets)
        self.capture_view.packets_added.connect(self._run_detection)
        self.capture_view.cleared.connect(self.dashboard_view.reset)
        self.capture_view.cleared.connect(self.network_map_view.reset)
        self.capture_view.cleared.connect(self.conversations_view.reset)
        self.capture_view.cleared.connect(self._reset_detection)
        self.scan_view.device_found.connect(self._db.record_device)
        self.scan_view.device_found.connect(lambda *a: self.devices_view.refresh())
        self.alerts_view.counts_changed.connect(self._update_alert_tab)
        self.alerts_view.jump_to_packet.connect(self._jump_to_packet)

        self.tabs.addTab(self._build_interfaces_tab(), "Interfaces")
        self.tabs.addTab(self.capture_view, "Capture")
        self.tabs.addTab(self.scan_view, "Scan")
        self.tabs.addTab(self.devices_view, "Appareils")
        self.tabs.addTab(self.dashboard_view, "Dashboard")
        self.tabs.addTab(self.conversations_view, "Conversations")
        self.tabs.addTab(self.network_map_view, "Carte")
        self._alerts_tab_index = self.tabs.addTab(self.alerts_view, "Alertes")
        self.tabs.currentChanged.connect(self._on_tab_changed)

        self._setup_notifications()
        self._build_menu()

        # Validation périodique des écritures SQLite (batching, cf. audit R2).
        self._flush_timer = QTimer(self)
        self._flush_timer.setInterval(3000)
        self._flush_timer.timeout.connect(self._db.flush)
        self._flush_timer.start()

        # Rejoue l'historique des alertes persistées.
        self.alerts_view.add_alerts(self._db.load_recent_alerts())

        self.statusBar().showMessage(
            f"{len(self._interfaces)} interface(s) réseau détectée(s)"
        )

    def _setup_notifications(self) -> None:
        self._tray = None
        if QSystemTrayIcon.isSystemTrayAvailable():
            icon = self.style().standardIcon(QStyle.StandardPixmap.SP_MessageBoxWarning)
            self._tray = QSystemTrayIcon(icon, self)
            self._tray.setToolTip("ArgosNet")
            self._tray.show()

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

        report_action = file_menu.addAction("Exporter un rapport HTML…")
        report_action.triggered.connect(self._export_report)

        file_menu.addSeparator()
        quit_action = file_menu.addAction("Quitter")
        quit_action.triggered.connect(self.close)

        view_menu = self.menuBar().addMenu("&Affichage")
        self._dark_action = view_menu.addAction("Thème sombre")
        self._dark_action.setCheckable(True)
        self._dark_action.setChecked(True)
        self._dark_action.toggled.connect(self._toggle_theme)
        self._notify_action = view_menu.addAction("Notifications d'alerte critique")
        self._notify_action.setCheckable(True)
        self._notify_action.setChecked(True)
        colors_action = view_menu.addAction("Couleurs des protocoles…")
        colors_action.triggered.connect(self._edit_colors)

        detect_menu = self.menuBar().addMenu("&Détection")
        rules_action = detect_menu.addAction("Éditer les règles IDS…")
        rules_action.triggered.connect(self._edit_rules)

        stats_menu = self.menuBar().addMenu("&Statistiques")
        summary_action = stats_menu.addAction("Résumé de la capture…")
        summary_action.triggered.connect(self._show_summary)

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
        self._db.flush()
        self._db.close()
        if self._tray is not None:
            self._tray.hide()
        super().closeEvent(event)

    def _edit_rules(self) -> None:
        from argosnet.ui.rules_editor import RulesEditorDialog

        if RulesEditorDialog(self).exec():
            self._reload_rules()
            self.statusBar().showMessage("Règles de détection rechargées.", 4000)

    def _reload_rules(self) -> None:
        from argosnet.core.detection.detectors import SignatureDetector, load_rules

        rules = load_rules()
        for detector in self._detection.detectors:
            if isinstance(detector, SignatureDetector):
                detector.rules = rules

    def _edit_colors(self) -> None:
        from argosnet.ui.color_editor import ColorEditorDialog

        if ColorEditorDialog(self).exec():
            self.capture_view._model.refresh_colors()

    def _export_report(self) -> None:
        from PySide6.QtCore import QUrl
        from PySide6.QtGui import QDesktopServices
        from PySide6.QtWidgets import QFileDialog

        from argosnet.core.report import build_html_report

        path, _ = QFileDialog.getSaveFileName(
            self, "Exporter un rapport", "rapport_argosnet.html", "HTML (*.html)"
        )
        if not path:
            return
        stats = self.dashboard_view._stats
        report = build_html_report(
            summary=stats.summary(),
            top_talkers=stats.top_talkers(20),
            conversations=stats.top_conversations(50),
            alerts=self.alerts_view._alerts,
            devices=self._db.list_devices(),
        )
        try:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(report)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Export impossible", str(exc))
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(path))
        self.statusBar().showMessage(f"Rapport exporté : {path}", 5000)

    def _on_tab_changed(self, _index: int) -> None:
        # Rafraîchit l'inventaire quand on ouvre son onglet (données en base).
        if self.tabs.currentWidget() is self.devices_view:
            self.devices_view.refresh()

    def _jump_to_packet(self, number: int) -> None:
        """Depuis une alerte : bascule sur la capture et sélectionne le paquet."""
        self.tabs.setCurrentWidget(self.capture_view)
        self.capture_view.select_packet_number(number)

    def _show_summary(self) -> None:
        from argosnet.ui.dashboard_view import format_bytes

        s = self.dashboard_view._stats.summary()
        if s["total_packets"] == 0:
            QMessageBox.information(self, "Résumé de la capture", "Aucun paquet capturé.")
            return
        total = s["total_packets"]
        lines = [
            f"Paquets           : {total:,}".replace(",", " "),
            f"Volume            : {format_bytes(s['total_bytes'])}",
            f"Durée             : {s['duration']} s",
            f"Débit moyen       : {s['avg_pps']:.1f} paquets/s  ({format_bytes(s['avg_bps'])}/s)",
            f"Hôtes distincts   : {s['distinct_talkers']}",
            f"Conversations     : {s['distinct_conversations']}",
            "",
            "Répartition par protocole :",
        ]
        for name, count in s["protocols"]:
            pct = 100 * count / total if total else 0
            lines.append(f"    {name:<10} {count:>8}   ({pct:.1f} %)")
        QMessageBox.information(self, "Résumé de la capture", "\n".join(lines))

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
        new_device = False
        for alert in alerts:
            if alert.category == "Nouvel appareil":
                self._db.record_device(alert.source)
                new_device = True
        if new_device:
            self.devices_view.refresh()
        criticals = [a for a in alerts if a.severity.name == "CRITICAL"]
        if criticals:
            self.statusBar().showMessage(
                f"⚠️ {len(criticals)} alerte(s) critique(s) détectée(s)", 5000
            )
            self._notify_critical(criticals)

    def _notify_critical(self, criticals: list) -> None:
        if not self._notify_action.isChecked():
            return
        QApplication.beep()
        if self._tray is not None:
            first = criticals[0]
            body = f"{first.category} — {first.source}"
            if len(criticals) > 1:
                body += f"  (+{len(criticals) - 1} autre(s))"
            self._tray.showMessage(
                "ArgosNet — alerte critique",
                body,
                QSystemTrayIcon.MessageIcon.Critical,
                6000,
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
