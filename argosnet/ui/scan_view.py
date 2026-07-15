"""Onglet « Scan » : découverte d'hôtes et scan de ports.

Les scans nécessitent Npcap + privilèges administrateur. Sans eux, un message
d'erreur clair est affiché plutôt que de planter.
"""
from __future__ import annotations

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from argosnet.core.i18n import tr
from argosnet.core.interfaces import NetIface, list_interfaces
from argosnet.core.scanner import (
    HostDiscoveryThread,
    HostInfo,
    PortScanThread,
    default_target,
)

COLUMNS = ["IP", "MAC", "Constructeur", "Nom d'hôte", "Ports ouverts"]
SCHEDULE_DEFAULT_MIN = 10   # intervalle par défaut du scan périodique (minutes)


class ScanView(QWidget):
    # (mac, ip, constructeur, nom d'hôte) — pour l'enregistrement en base.
    device_found = Signal(str, str, str, str)

    def __init__(self) -> None:
        super().__init__()
        self._interfaces: list[NetIface] = list_interfaces()
        self._row_by_ip: dict[str, int] = {}
        self._discovery: HostDiscoveryThread | None = None
        self._portscan: PortScanThread | None = None
        self._schedule_timer = QTimer(self)
        self._schedule_timer.timeout.connect(self._periodic_scan)
        self._build_ui()

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        root = QVBoxLayout(self)

        bar = QHBoxLayout()
        bar.addWidget(QLabel(tr("Interface :")))
        self._iface_combo = QComboBox()
        self._iface_combo.setMinimumWidth(300)
        for iface in self._interfaces:
            suffix = "" if iface.capturable else "  (Npcap requis)"
            self._iface_combo.addItem(iface.label + suffix, iface)
        self._iface_combo.currentIndexChanged.connect(self._sync_target)
        bar.addWidget(self._iface_combo)

        bar.addWidget(QLabel(tr("Cible :")))
        self._target_edit = QLineEdit()
        self._target_edit.setPlaceholderText("ex. 192.168.1.0/24")
        bar.addWidget(self._target_edit, 1)

        self._discover_btn = QPushButton(tr("Découvrir les hôtes"))
        self._discover_btn.clicked.connect(self._start_discovery)
        bar.addWidget(self._discover_btn)

        self._portscan_btn = QPushButton(tr("Scanner les ports de l'hôte sélectionné"))
        self._portscan_btn.clicked.connect(self._start_portscan)
        bar.addWidget(self._portscan_btn)
        root.addLayout(bar)

        # Barre de planification : relance périodique de la découverte d'hôtes.
        sched_bar = QHBoxLayout()
        self._schedule_check = QCheckBox(tr("Scan périodique"))
        self._schedule_check.setToolTip(
            tr("Relance automatiquement la découverte d'hôtes à intervalle régulier.")
        )
        self._schedule_check.toggled.connect(self._toggle_schedule)
        sched_bar.addWidget(self._schedule_check)
        self._interval_spin = QSpinBox()
        self._interval_spin.setRange(1, 1440)
        self._interval_spin.setValue(SCHEDULE_DEFAULT_MIN)
        self._interval_spin.valueChanged.connect(self._interval_changed)
        sched_bar.addWidget(self._interval_spin)
        sched_bar.addWidget(QLabel(tr("min")))
        sched_bar.addStretch(1)
        root.addLayout(sched_bar)

        self._status = QLabel(tr("Prêt."))
        self._status.setStyleSheet("color: gray;")
        root.addWidget(self._status)

        self._table = QTableWidget(0, len(COLUMNS))
        self._table.setHorizontalHeaderLabels([tr(c) for c in COLUMNS])
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        header = self._table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        root.addWidget(self._table)

        self._sync_target()

    def _sync_target(self) -> None:
        iface = self._iface_combo.currentData()
        if iface is not None and not self._target_edit.text().strip():
            self._target_edit.setText(default_target(iface.ip))
        elif iface is not None:
            # Met à jour uniquement si le champ correspond encore à un /24 auto.
            current = self._target_edit.text().strip()
            if current.endswith("/24"):
                self._target_edit.setText(default_target(iface.ip) or current)

    # --------------------------------------------------------- découverte
    def _selected_iface_arg(self):
        iface: NetIface | None = self._iface_combo.currentData()
        if iface is None:
            return None
        return iface.raw if (iface.capturable and iface.raw is not None) else iface.name

    def _start_discovery(self) -> None:
        target = self._target_edit.text().strip()
        if not target:
            QMessageBox.information(self, "Cible manquante", "Indiquez un sous-réseau (ex. 192.168.1.0/24).")
            return
        self._table.setRowCount(0)
        self._row_by_ip.clear()
        self._discover_btn.setEnabled(False)
        self._status.setText(f"Balayage ARP de {target}…")

        self._discovery = HostDiscoveryThread(target, self._selected_iface_arg())
        self._discovery.host_found.connect(self._add_host)
        self._discovery.finished_scan.connect(self._discovery_done)
        self._discovery.error.connect(self._scan_error)
        self._discovery.start()

    def _add_host(self, host: HostInfo) -> None:
        row = self._table.rowCount()
        self._table.insertRow(row)
        self._row_by_ip[host.ip] = row
        values = [host.ip, host.mac, host.vendor or "—", host.hostname or "—",
                  ", ".join(map(str, host.open_ports)) if host.open_ports else "—"]
        for col, text in enumerate(values):
            self._table.setItem(row, col, QTableWidgetItem(text))
        self.device_found.emit(host.mac, host.ip, host.vendor, host.hostname)

    def _discovery_done(self, count: int) -> None:
        self._discover_btn.setEnabled(True)
        self._status.setText(f"Découverte terminée : {count} hôte(s) trouvé(s).")

    # --------------------------------------------------------- planification
    def _toggle_schedule(self, enabled: bool) -> None:
        if enabled:
            self._schedule_timer.start(self._interval_spin.value() * 60_000)
            self._status.setText(
                tr("Planifié : scan toutes les {minutes} min.").format(
                    minutes=self._interval_spin.value()
                )
            )
            self._periodic_scan()  # premier scan immédiat
        else:
            self._schedule_timer.stop()

    def _interval_changed(self, minutes: int) -> None:
        if self._schedule_timer.isActive():
            self._schedule_timer.start(minutes * 60_000)

    def _periodic_scan(self) -> None:
        # Ne lance pas de nouveau balayage si l'un est déjà en cours (anti-chevauchement).
        if self._discovery is not None and self._discovery.isRunning():
            return
        # Cible absente : on saute ce tour sans ouvrir de dialogue modal.
        if not self._target_edit.text().strip():
            return
        self._start_discovery()

    # --------------------------------------------------------- scan de ports
    def _start_portscan(self) -> None:
        row = self._table.currentRow()
        if row < 0:
            QMessageBox.information(self, "Aucun hôte", "Sélectionnez un hôte dans la liste.")
            return
        ip = self._table.item(row, 0).text()
        self._portscan_btn.setEnabled(False)
        self._status.setText(f"Scan des ports de {ip}…")

        self._portscan = PortScanThread(ip, iface=self._selected_iface_arg())
        self._portscan.result.connect(self._portscan_done)
        self._portscan.error.connect(self._scan_error)
        self._portscan.start()

    def _portscan_done(self, ip: str, open_ports: list) -> None:
        self._portscan_btn.setEnabled(True)
        row = self._row_by_ip.get(ip)
        if row is not None:
            text = ", ".join(map(str, open_ports)) if open_ports else "aucun"
            self._table.setItem(row, 4, QTableWidgetItem(text))
        self._status.setText(f"Scan de {ip} terminé : {len(open_ports)} port(s) ouvert(s).")

    # ------------------------------------------------------------- erreurs
    def _scan_error(self, message: str) -> None:
        self._discover_btn.setEnabled(True)
        self._portscan_btn.setEnabled(True)
        self._status.setText("Échec du scan.")
        QMessageBox.critical(self, "Scan impossible", message)
