"""Onglet « Scan » : découverte d'hôtes et scan de ports.

Les scans nécessitent Npcap + privilèges administrateur. Sans eux, un message
d'erreur clair est affiché plutôt que de planter.
"""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from argosnet.core.interfaces import NetIface, list_interfaces
from argosnet.core.scanner import (
    HostDiscoveryThread,
    HostInfo,
    PortScanThread,
    default_target,
)

COLUMNS = ["IP", "MAC", "Constructeur", "Nom d'hôte", "Ports ouverts"]


class ScanView(QWidget):
    # (mac, ip, constructeur, nom d'hôte) — pour l'enregistrement en base.
    device_found = Signal(str, str, str, str)

    def __init__(self) -> None:
        super().__init__()
        self._interfaces: list[NetIface] = list_interfaces()
        self._row_by_ip: dict[str, int] = {}
        self._discovery: HostDiscoveryThread | None = None
        self._portscan: PortScanThread | None = None
        self._build_ui()

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        root = QVBoxLayout(self)

        bar = QHBoxLayout()
        bar.addWidget(QLabel("Interface :"))
        self._iface_combo = QComboBox()
        self._iface_combo.setMinimumWidth(300)
        for iface in self._interfaces:
            suffix = "" if iface.capturable else "  (Npcap requis)"
            self._iface_combo.addItem(iface.label + suffix, iface)
        self._iface_combo.currentIndexChanged.connect(self._sync_target)
        bar.addWidget(self._iface_combo)

        bar.addWidget(QLabel("Cible :"))
        self._target_edit = QLineEdit()
        self._target_edit.setPlaceholderText("ex. 192.168.1.0/24")
        bar.addWidget(self._target_edit, 1)

        self._discover_btn = QPushButton("Découvrir les hôtes")
        self._discover_btn.clicked.connect(self._start_discovery)
        bar.addWidget(self._discover_btn)

        self._portscan_btn = QPushButton("Scanner les ports de l'hôte sélectionné")
        self._portscan_btn.clicked.connect(self._start_portscan)
        bar.addWidget(self._portscan_btn)
        root.addLayout(bar)

        self._status = QLabel("Prêt.")
        self._status.setStyleSheet("color: gray;")
        root.addWidget(self._status)

        self._table = QTableWidget(0, len(COLUMNS))
        self._table.setHorizontalHeaderLabels(COLUMNS)
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
