"""Onglet « Capture » : le cœur type Wireshark.

Assemble le sélecteur d'interface, les filtres (capture BPF + affichage), la liste de
paquets, le volet de détail par couches et la vue hexadécimale. La capture réelle est
déléguée à :class:`argosnet.core.capture.CaptureController`.
"""
from __future__ import annotations

from PySide6.QtCore import QModelIndex, QSortFilterProxyModel, Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableView,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from argosnet.core.capture import CaptureController
from argosnet.core.display_filter import compile_filter
from argosnet.core.dissect import hexdump, layer_tree
from argosnet.core.interfaces import NetIface, list_interfaces
from argosnet.ui.packet_model import PacketTableModel, make_record
from argosnet.ui.widgets.hexview import HexView

DRAIN_INTERVAL_MS = 250  # cadence de récupération des paquets depuis le sniffer


class PacketFilterProxy(QSortFilterProxyModel):
    """Applique un filtre d'affichage sur le modèle de paquets."""

    def __init__(self) -> None:
        super().__init__()
        self._predicate = compile_filter("")

    def set_filter(self, expr: str) -> None:
        self._predicate = compile_filter(expr)
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:  # noqa: N802
        model = self.sourceModel()
        record = model.record_at(source_row) if model else None
        if record is None:
            return True
        try:
            return bool(self._predicate(record))
        except Exception:
            return True


class CaptureView(QWidget):
    """Widget principal de capture/analyse de paquets."""

    # Diffuse les nouveaux paquets bruts aux autres moteurs (stats, détection).
    packets_added = Signal(list)
    # Émis quand la liste est vidée (réinitialisation des moteurs dérivés).
    cleared = Signal()

    def __init__(self) -> None:
        super().__init__()
        self._controller = CaptureController()

        self._model = PacketTableModel()
        self._proxy = PacketFilterProxy()
        self._proxy.setSourceModel(self._model)

        self._timer = QTimer(self)
        self._timer.setInterval(DRAIN_INTERVAL_MS)
        self._timer.timeout.connect(self._drain)

        self._build_ui()
        self._reload_interfaces()

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        root = QVBoxLayout(self)

        # Barre 1 : interface + filtre de capture + start/stop.
        bar1 = QHBoxLayout()
        bar1.addWidget(QLabel("Interface :"))
        self._iface_combo = QComboBox()
        self._iface_combo.setMinimumWidth(320)
        bar1.addWidget(self._iface_combo)
        bar1.addWidget(QLabel("Filtre capture (BPF) :"))
        self._bpf_edit = QLineEdit()
        self._bpf_edit.setPlaceholderText("ex. tcp port 443, host 192.168.1.1…")
        bar1.addWidget(self._bpf_edit, 1)
        self._start_btn = QPushButton("▶ Démarrer")
        self._stop_btn = QPushButton("■ Arrêter")
        self._stop_btn.setEnabled(False)
        self._start_btn.clicked.connect(self._start_capture)
        self._stop_btn.clicked.connect(self._stop_capture)
        bar1.addWidget(self._start_btn)
        bar1.addWidget(self._stop_btn)
        root.addLayout(bar1)

        # Barre 2 : filtre d'affichage + compteur + effacer.
        bar2 = QHBoxLayout()
        bar2.addWidget(QLabel("Filtre d'affichage :"))
        self._filter_edit = QLineEdit()
        self._filter_edit.setPlaceholderText("ex. dns, ip.addr==192.168.1.1, tcp.port==443…")
        self._filter_edit.textChanged.connect(self._apply_filter)
        bar2.addWidget(self._filter_edit, 1)
        self._count_label = QLabel("0 paquet")
        bar2.addWidget(self._count_label)
        open_btn = QPushButton("Ouvrir .pcap…")
        open_btn.clicked.connect(self.open_pcap_dialog)
        bar2.addWidget(open_btn)
        save_btn = QPushButton("Enregistrer .pcap…")
        save_btn.clicked.connect(self.save_pcap_dialog)
        bar2.addWidget(save_btn)
        clear_btn = QPushButton("Effacer")
        clear_btn.clicked.connect(self._clear)
        bar2.addWidget(clear_btn)
        root.addLayout(bar2)

        # Zone centrale : liste (haut) / détail + hexa (bas).
        vsplit = QSplitter(Qt.Orientation.Vertical)

        self._table = QTableView()
        self._table.setModel(self._proxy)
        self._table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        self._table.setAlternatingRowColors(False)
        self._table.verticalHeader().setVisible(False)
        header = self._table.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self._table.selectionModel().currentRowChanged.connect(self._on_row_changed)
        vsplit.addWidget(self._table)

        hsplit = QSplitter(Qt.Orientation.Horizontal)
        self._detail = QTreeWidget()
        self._detail.setHeaderLabels(["Champ", "Valeur"])
        self._detail.setColumnWidth(0, 220)
        hsplit.addWidget(self._detail)
        self._hex = HexView()
        hsplit.addWidget(self._hex)
        hsplit.setSizes([520, 520])
        vsplit.addWidget(hsplit)
        vsplit.setSizes([420, 300])

        root.addWidget(vsplit, 1)
        self._set_default_columns()

    def _set_default_columns(self) -> None:
        widths = [60, 110, 170, 170, 90, 70]  # la dernière (Info) s'étire
        for col, width in enumerate(widths):
            self._table.setColumnWidth(col, width)

    def _reload_interfaces(self) -> None:
        self._iface_combo.clear()
        interfaces: list[NetIface] = list_interfaces()
        # Priorité aux interfaces réellement capturables et disposant d'une IP.
        interfaces.sort(key=lambda i: (not i.capturable, i.ip is None))
        for iface in interfaces:
            suffix = "" if iface.capturable else "  (Npcap requis)"
            self._iface_combo.addItem(iface.label + suffix, iface)

    # ------------------------------------------------------------- capture
    def _selected_iface(self) -> NetIface | None:
        return self._iface_combo.currentData()

    def _start_capture(self) -> None:
        iface = self._selected_iface()
        iface_arg = None
        if iface is not None:
            iface_arg = iface.raw if (iface.capturable and iface.raw is not None) else iface.name
        try:
            self._controller.start(iface_arg, self._bpf_edit.text().strip() or None)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(
                self,
                "Capture impossible",
                f"Impossible de démarrer la capture.\n\n{exc}\n\n"
                "Vérifiez que Npcap est installé et que l'application est lancée "
                "en administrateur.",
            )
            return
        self._timer.start()
        self._start_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self._iface_combo.setEnabled(False)
        self._bpf_edit.setEnabled(False)

    def stop_capture_if_running(self) -> None:
        """Arrête proprement la capture (appelé à la fermeture de l'application)."""
        if self._controller.is_running():
            self._stop_capture()

    def _stop_capture(self) -> None:
        self._controller.stop()
        self._timer.stop()
        self._drain()  # récupère les derniers paquets en attente
        self._start_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._iface_combo.setEnabled(True)
        self._bpf_edit.setEnabled(True)

    def _drain(self) -> None:
        packets = self._controller.drain()
        if not packets:
            return
        base = self._model.next_number()
        records = [make_record(base + i, pkt) for i, pkt in enumerate(packets)]
        self._model.append_records(records)
        self._update_count()
        self.packets_added.emit(packets)

    # ---------------------------------------------------------- import/export
    def open_pcap_dialog(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Ouvrir une capture", "", "Captures (*.pcap *.pcapng *.cap);;Tous (*.*)"
        )
        if path:
            self.load_pcap(path)

    def load_pcap(self, path: str) -> None:
        """Charge un fichier .pcap dans la liste (même chemin qu'une capture live)."""
        try:
            from scapy.utils import rdpcap
            packets = list(rdpcap(path))
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Lecture impossible", f"Fichier illisible :\n{exc}")
            return
        base = self._model.next_number()
        records = [make_record(base + i, pkt) for i, pkt in enumerate(packets)]
        self._model.append_records(records)
        self._update_count()
        if packets:
            self.packets_added.emit(packets)

    def save_pcap_dialog(self) -> None:
        if self._model.rowCount() == 0:
            QMessageBox.information(self, "Rien à enregistrer", "Aucun paquet à exporter.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Enregistrer la capture", "capture.pcap", "Captures (*.pcap)"
        )
        if not path:
            return
        try:
            from scapy.utils import wrpcap
            wrpcap(path, self._model.all_packets())
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Écriture impossible", f"Échec de l'enregistrement :\n{exc}")

    # -------------------------------------------------------------- filtre
    def _apply_filter(self, text: str) -> None:
        self._proxy.set_filter(text)
        self._update_count()

    def _clear(self) -> None:
        self._model.clear()
        self._detail.clear()
        self._hex.clear_dump()
        self._update_count()
        self.cleared.emit()

    def _update_count(self) -> None:
        total = self._model.rowCount()
        shown = self._proxy.rowCount()
        if shown == total:
            self._count_label.setText(f"{total} paquet(s)")
        else:
            self._count_label.setText(f"{shown} / {total} paquet(s)")

    # ------------------------------------------------------- sélection/détail
    def _on_row_changed(self, current: QModelIndex, _previous: QModelIndex) -> None:
        if not current.isValid():
            return
        source_index = self._proxy.mapToSource(current)
        record = self._model.record_at(source_index.row())
        if record is None:
            return
        self._populate_detail(record.packet)
        self._hex.show_dump(hexdump(record.packet))

    def _populate_detail(self, packet) -> None:
        self._detail.clear()
        for layer_name, fields in layer_tree(packet):
            top = QTreeWidgetItem([layer_name, ""])
            font = top.font(0)
            font.setBold(True)
            top.setFont(0, font)
            for field_name, value in fields:
                top.addChild(QTreeWidgetItem([field_name, value]))
            self._detail.addTopLevelItem(top)
            top.setExpanded(True)
