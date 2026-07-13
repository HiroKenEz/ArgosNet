"""Onglet « Capture » : le cœur type Wireshark.

Assemble le sélecteur d'interface, les filtres (capture BPF + affichage), la liste de
paquets, le volet de détail par couches et la vue hexadécimale. La capture réelle est
déléguée à :class:`argosnet.core.capture.CaptureController`.
"""
from __future__ import annotations

import json
import os

from PySide6.QtCore import (
    QModelIndex,
    QSortFilterProxyModel,
    QStringListModel,
    Qt,
    QThread,
    QTimer,
    Signal,
)
from PySide6.QtGui import QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QCompleter,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QProgressDialog,
    QPushButton,
    QSplitter,
    QTableView,
    QToolButton,
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

def _has_tcp(packet) -> bool:
    try:
        from scapy.layers.inet import TCP
        return packet.haslayer(TCP)
    except Exception:
        return False


FILTERS_PATH = os.path.join(os.path.expanduser("~"), ".argosnet", "filters.json")
BUILTIN_FILTERS = [
    "dns", "arp", "icmp", "proto==tcp", "proto==udp",
    "tcp.port==443", "tcp.port==80", "udp.port==53",
    "ip.addr==", "ip.src==", "ip.dst==",
]

DRAIN_INTERVAL_MS = 250   # cadence de récupération des paquets depuis le sniffer
FILTER_DEBOUNCE_MS = 200  # délai avant application du filtre d'affichage après frappe


class PcapLoader(QThread):
    """Lit un .pcap de façon incrémentale et construit les enregistrements hors GUI.

    La lecture (``PcapReader``) et la dissection (``make_record``) se font dans ce thread ;
    les enregistrements sont émis **par lots** pour peupler la liste progressivement et
    afficher une progression, sans geler l'interface sur les fichiers volumineux.
    """

    chunk = Signal(list)     # list[PacketRecord]
    progress = Signal(int)   # nombre total de paquets lus
    failed = Signal(str)

    CHUNK = 5000

    def __init__(self, path: str, base_number: int) -> None:
        super().__init__()
        self._path = path
        self._base = base_number

    def run(self) -> None:
        try:
            from scapy.utils import PcapReader
            count = 0
            batch: list = []
            with PcapReader(self._path) as reader:
                for pkt in reader:
                    batch.append(make_record(self._base + count, pkt))
                    count += 1
                    if len(batch) >= self.CHUNK:
                        self.chunk.emit(batch)
                        self.progress.emit(count)
                        batch = []
            if batch:
                self.chunk.emit(batch)
                self.progress.emit(count)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))


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

        # Anti-rebond du filtre d'affichage : n'applique le filtre qu'après une
        # courte pause de frappe, pour ne pas réévaluer tous les paquets à chaque touche.
        self._filter_timer = QTimer(self)
        self._filter_timer.setSingleShot(True)
        self._filter_timer.setInterval(FILTER_DEBOUNCE_MS)
        self._filter_timer.timeout.connect(self._apply_filter)

        self._favorites, self._history = self._load_filters()
        self._build_ui()
        self._reload_interfaces()
        self._refresh_completer()

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
        self._filter_edit.textChanged.connect(lambda _t: self._filter_timer.start())
        self._filter_completer = QCompleter(self)
        self._filter_completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self._completer_model = QStringListModel(self)
        self._filter_completer.setModel(self._completer_model)
        self._filter_edit.setCompleter(self._filter_completer)
        bar2.addWidget(self._filter_edit, 1)
        self._fav_btn = QToolButton()
        self._fav_btn.setText("★")
        self._fav_btn.setToolTip("Filtres favoris et récents")
        self._fav_btn.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        fav_menu = QMenu(self._fav_btn)
        fav_menu.aboutToShow.connect(self._build_favorites_menu)
        self._fav_btn.setMenu(fav_menu)
        bar2.addWidget(self._fav_btn)
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

        # Barre de recherche (Ctrl+F), masquée par défaut.
        root.addWidget(self._build_find_bar())
        find_shortcut = QShortcut(QKeySequence.StandardKey.Find, self)
        find_shortcut.activated.connect(self._toggle_find)

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
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._show_context_menu)
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
        """Charge un fichier .pcap en arrière-plan, par lots (ne gèle pas la GUI)."""
        self._loader = PcapLoader(path, self._model.next_number())
        self._progress = QProgressDialog("Lecture de la capture…", None, 0, 0, self)
        self._progress.setWindowTitle("Chargement")
        self._progress.setWindowModality(Qt.WindowModality.WindowModal)
        self._progress.setCancelButton(None)
        self._progress.setMinimumDuration(0)
        self._loader.chunk.connect(self._on_pcap_chunk)
        self._loader.progress.connect(
            lambda n: self._progress.setLabelText(f"Lecture de la capture…  {n} paquets")
        )
        self._loader.failed.connect(self._on_pcap_failed)
        self._loader.finished.connect(self._progress.close)
        self._loader.start()
        self._progress.show()

    def _on_pcap_chunk(self, records: list) -> None:
        self._model.append_records(records)
        self._update_count()
        if records:
            self.packets_added.emit([r.packet for r in records])

    def _on_pcap_failed(self, message: str) -> None:
        if hasattr(self, "_progress"):
            self._progress.close()
        QMessageBox.critical(self, "Lecture impossible", f"Fichier illisible :\n{message}")

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
    def _apply_filter(self) -> None:
        text = self._filter_edit.text().strip()
        self._proxy.set_filter(text)
        self._add_history(text)
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
        text = f"{total} paquet(s)" if shown == total else f"{shown} / {total} paquet(s)"
        dropped = self._controller.dropped_count()
        if dropped:
            text += f"   ⚠ {dropped} perdu(s)"
        self._count_label.setText(text)

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

    # ------------------------------------------------------- recherche (Ctrl+F)
    def _build_find_bar(self) -> QWidget:
        self._find_bar = QWidget()
        layout = QHBoxLayout(self._find_bar)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(QLabel("Rechercher :"))
        self._find_edit = QLineEdit()
        self._find_edit.setPlaceholderText("texte dans source, destination, protocole ou info…")
        self._find_edit.returnPressed.connect(self._find_next)
        layout.addWidget(self._find_edit, 1)
        prev_btn = QPushButton("Précédent")
        prev_btn.clicked.connect(self._find_prev)
        next_btn = QPushButton("Suivant")
        next_btn.clicked.connect(self._find_next)
        close_btn = QPushButton("✕")
        close_btn.setFixedWidth(30)
        close_btn.clicked.connect(self._hide_find)
        for btn in (prev_btn, next_btn, close_btn):
            layout.addWidget(btn)
        esc = QShortcut(QKeySequence("Escape"), self._find_edit)
        esc.activated.connect(self._hide_find)
        self._find_bar.setVisible(False)
        return self._find_bar

    def _toggle_find(self) -> None:
        self._find_bar.setVisible(not self._find_bar.isVisible())
        if self._find_bar.isVisible():
            self._find_edit.setFocus()
            self._find_edit.selectAll()

    def _hide_find(self) -> None:
        self._find_bar.setVisible(False)
        self._table.setFocus()

    def _find_next(self) -> None:
        self._find(1)

    def _find_prev(self) -> None:
        self._find(-1)

    def _find(self, direction: int) -> None:
        text = self._find_edit.text().strip().lower()
        rows = self._proxy.rowCount()
        if not text or rows == 0:
            return
        cur = self._table.currentIndex().row()
        i = (cur + direction) % rows if cur >= 0 else 0
        for _ in range(rows):
            source = self._proxy.mapToSource(self._proxy.index(i, 0))
            record = self._model.record_at(source.row())
            if record and self._row_matches(record, text):
                idx = self._proxy.index(i, 0)
                self._table.setCurrentIndex(idx)
                self._table.scrollTo(idx)
                return
            i = (i + direction) % rows

    @staticmethod
    def _row_matches(record, text: str) -> bool:
        s = record.summary
        return (
            text in str(record.number)
            or text in s.src.lower()
            or text in s.dst.lower()
            or text in s.protocol.lower()
            or text in s.info.lower()
        )

    # --------------------------------------------------- menu contextuel paquet
    def _show_context_menu(self, pos) -> None:
        index = self._table.indexAt(pos)
        if not index.isValid():
            return
        record = self._model.record_at(self._proxy.mapToSource(index).row())
        if record is None:
            return
        s = record.summary
        menu = QMenu(self)
        if s.src and s.src != "—":
            menu.addAction(f"Filtrer la source  {s.src}", lambda: self._set_filter(f"ip.src=={s.src}"))
            menu.addAction(f"Filtrer l'adresse  {s.src}", lambda: self._set_filter(f"ip.addr=={s.src}"))
        if s.dst and s.dst != "—":
            menu.addAction(f"Filtrer la destination  {s.dst}", lambda: self._set_filter(f"ip.dst=={s.dst}"))
        menu.addAction(f"Filtrer le protocole  {s.protocol}",
                       lambda: self._set_filter(f"proto=={s.protocol.lower()}"))
        if _has_tcp(record.packet):
            menu.addSeparator()
            menu.addAction("Suivre le flux TCP", lambda: self._follow_stream(record.packet))
        menu.addSeparator()
        menu.addAction("Copier la ligne", lambda: self._copy_to_clipboard(self._row_text(record)))
        menu.addAction("Copier l'info", lambda: self._copy_to_clipboard(s.info))
        menu.exec(self._table.viewport().mapToGlobal(pos))

    def _follow_stream(self, packet) -> None:
        from argosnet.core.follow import follow_tcp_stream
        from argosnet.ui.widgets.follow_dialog import FollowStreamDialog

        stream = follow_tcp_stream(self._model.all_packets(), packet)
        if stream is None or not stream.segments:
            QMessageBox.information(
                self, "Suivre le flux",
                "Aucune donnée applicative à réassembler pour ce flux TCP.",
            )
            return
        FollowStreamDialog(stream, self).exec()

    def _set_filter(self, expr: str) -> None:
        self._filter_edit.setText(expr)
        self._filter_timer.stop()
        self._apply_filter()

    @staticmethod
    def _row_text(record) -> str:
        s = record.summary
        return f"{record.number}\t{s.src}\t{s.dst}\t{s.protocol}\t{s.length}\t{s.info}"

    @staticmethod
    def _copy_to_clipboard(text: str) -> None:
        QApplication.clipboard().setText(text)

    # ------------------------------------------------ saut vers un paquet (alerte)
    def select_packet_number(self, number: int) -> None:
        """Sélectionne le paquet portant ce numéro (retire le filtre s'il le masque)."""
        row = self._model.row_for_number(number)
        if row is None:
            return
        source_index = self._model.index(row, 0)
        proxy_index = self._proxy.mapFromSource(source_index)
        if not proxy_index.isValid():  # masqué par le filtre → on l'enlève
            self._filter_edit.clear()
            self._filter_timer.stop()
            self._apply_filter()
            proxy_index = self._proxy.mapFromSource(source_index)
        if proxy_index.isValid():
            self._table.setCurrentIndex(proxy_index)
            self._table.scrollTo(proxy_index)
            self._table.setFocus()

    # ---------------------------------------------------- filtres favoris/récents
    def _load_filters(self) -> tuple[list, list]:
        try:
            with open(FILTERS_PATH, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            return list(data.get("favorites", [])), list(data.get("history", []))
        except Exception:
            return [], []

    def _save_filters(self) -> None:
        try:
            os.makedirs(os.path.dirname(FILTERS_PATH), exist_ok=True)
            with open(FILTERS_PATH, "w", encoding="utf-8") as handle:
                json.dump(
                    {"favorites": self._favorites, "history": self._history},
                    handle, ensure_ascii=False, indent=2,
                )
        except Exception:
            pass

    def _add_history(self, expr: str) -> None:
        if not expr:
            return
        if expr in self._history:
            self._history.remove(expr)
        self._history.insert(0, expr)
        del self._history[20:]
        self._save_filters()
        self._refresh_completer()

    def _refresh_completer(self) -> None:
        suggestions: list[str] = []
        for item in self._favorites + self._history + BUILTIN_FILTERS:
            if item and item not in suggestions:
                suggestions.append(item)
        self._completer_model.setStringList(suggestions)

    def _build_favorites_menu(self) -> None:
        menu = self._fav_btn.menu()
        menu.clear()
        save = menu.addAction("★ Enregistrer le filtre actuel comme favori")
        save.setEnabled(bool(self._filter_edit.text().strip()))
        save.triggered.connect(self._save_current_favorite)
        if self._favorites:
            menu.addSeparator()
            header = menu.addAction("Favoris")
            header.setEnabled(False)
            for expr in self._favorites:
                menu.addAction("  " + expr, lambda checked=False, e=expr: self._set_filter(e))
        if self._history:
            menu.addSeparator()
            header = menu.addAction("Récents")
            header.setEnabled(False)
            for expr in self._history[:10]:
                menu.addAction("  " + expr, lambda checked=False, e=expr: self._set_filter(e))

    def _save_current_favorite(self) -> None:
        expr = self._filter_edit.text().strip()
        if expr and expr not in self._favorites:
            self._favorites.insert(0, expr)
            del self._favorites[20:]
            self._save_filters()
            self._refresh_completer()
