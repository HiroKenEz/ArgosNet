"""Modèle de table Qt pour la liste des paquets.

Utilise ``QAbstractTableModel`` (pattern modèle/vue) afin d'afficher des dizaines de
milliers de paquets sans créer un widget par cellule. Les paquets sont ajoutés par
lots (voir :meth:`PacketTableModel.append_records`) pour limiter le coût GUI.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PySide6.QtGui import QColor

from argosnet.core.dissect import PacketSummary, summarize

COLUMNS = ["N°", "Temps", "Source", "Destination", "Protocole", "Long.", "Info"]

# Coloration douce par protocole (façon Wireshark), lisible sur fond clair.
DEFAULT_PROTO_COLORS: dict[str, str] = {
    "TCP": "#e7e6ff",
    "UDP": "#e2f0ff",
    "DNS": "#d8f5e3",
    "mDNS": "#d8f5ea",
    "DHCP": "#e6f7d0",
    "ARP": "#fbf3d0",
    "ICMP": "#ffe0e0",
    "HTTP": "#d5f0d5",
    "TLS": "#efe0ff",
    "IPv6": "#eef0f2",
    "IP": "#f2f2f2",
    "Ethernet": "#f6f6f6",
}

# Couleurs courantes (modifiables par l'utilisateur), sous forme de QColor.
PROTO_COLORS: dict[str, QColor] = {k: QColor(v) for k, v in DEFAULT_PROTO_COLORS.items()}

COLORS_PATH = os.path.join(os.path.expanduser("~"), ".argosnet", "colors.json")


def apply_proto_colors(mapping: dict[str, str]) -> None:
    """Applique un dictionnaire {protocole: '#hex'} sur les couleurs courantes."""
    for proto, hex_color in mapping.items():
        PROTO_COLORS[proto] = QColor(hex_color)


def reset_proto_colors() -> None:
    apply_proto_colors(DEFAULT_PROTO_COLORS)


def load_proto_colors() -> None:
    """Charge les couleurs personnalisées depuis ~/.argosnet/colors.json (si présent)."""
    try:
        with open(COLORS_PATH, "r", encoding="utf-8") as handle:
            apply_proto_colors(json.load(handle))
    except Exception:
        pass


def save_proto_colors() -> None:
    try:
        os.makedirs(os.path.dirname(COLORS_PATH), exist_ok=True)
        data = {proto: color.name() for proto, color in PROTO_COLORS.items()}
        with open(COLORS_PATH, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)
    except Exception:
        pass


@dataclass
class PacketRecord:
    """Un paquet capturé + son résumé pré-calculé."""

    number: int
    time: float
    summary: PacketSummary
    packet: Any


class PacketTableModel(QAbstractTableModel):
    def __init__(self) -> None:
        super().__init__()
        self._records: list[PacketRecord] = []
        self._t0: float | None = None  # horodatage du premier paquet (temps relatif)

    # ----------------------------------------------------------- API publique
    def append_records(self, records: list[PacketRecord]) -> None:
        if not records:
            return
        start = len(self._records)
        self.beginInsertRows(QModelIndex(), start, start + len(records) - 1)
        self._records.extend(records)
        if self._t0 is None and self._records:
            self._t0 = self._records[0].time
        self.endInsertRows()

    def clear(self) -> None:
        self.beginResetModel()
        self._records.clear()
        self._t0 = None
        self.endResetModel()

    def record_at(self, row: int) -> PacketRecord | None:
        if 0 <= row < len(self._records):
            return self._records[row]
        return None

    def all_packets(self) -> list[Any]:
        """Liste des paquets Scapy bruts (pour l'export .pcap)."""
        return [record.packet for record in self._records]

    def refresh_colors(self) -> None:
        """Repeint la table après une modification des couleurs de protocole."""
        if self._records:
            self.dataChanged.emit(
                self.index(0, 0),
                self.index(len(self._records) - 1, len(COLUMNS) - 1),
                [Qt.ItemDataRole.BackgroundRole, Qt.ItemDataRole.ForegroundRole],
            )

    def row_for_number(self, number: int) -> int | None:
        """Ligne (index source) correspondant au numéro de paquet donné."""
        if not self._records:
            return None
        # Les numéros sont séquentiels : accès direct, avec repli linéaire.
        idx = number - self._records[0].number
        if 0 <= idx < len(self._records) and self._records[idx].number == number:
            return idx
        for i, record in enumerate(self._records):
            if record.number == number:
                return i
        return None

    def next_number(self) -> int:
        return len(self._records) + 1

    # --------------------------------------------------- surcharges Qt requises
    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._records)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(COLUMNS)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole):  # noqa: N802
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if orientation == Qt.Orientation.Horizontal:
            return COLUMNS[section]
        return None

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        record = self._records[index.row()]
        col = index.column()

        if role == Qt.ItemDataRole.DisplayRole:
            return self._cell_text(record, col)
        if role == Qt.ItemDataRole.BackgroundRole:
            return PROTO_COLORS.get(record.summary.protocol)
        if role == Qt.ItemDataRole.ForegroundRole:
            # Texte foncé forcé sur les cellules colorées : lisible en thème clair
            # comme en thème sombre (fond pastel constant).
            if record.summary.protocol in PROTO_COLORS:
                return QColor("#1a1a1a")
            return None
        if role == Qt.ItemDataRole.TextAlignmentRole and col in (0, 1, 5):
            return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        return None

    # ------------------------------------------------------------- formatage
    def _cell_text(self, record: PacketRecord, col: int) -> str:
        s = record.summary
        if col == 0:
            return str(record.number)
        if col == 1:
            rel = record.time - (self._t0 or record.time)
            return f"{rel:.6f}"
        if col == 2:
            return s.src
        if col == 3:
            return s.dst
        if col == 4:
            return s.protocol
        if col == 5:
            return str(s.length)
        if col == 6:
            return s.info
        return ""


def make_record(number: int, packet: Any) -> PacketRecord:
    """Construit un ``PacketRecord`` à partir d'un paquet Scapy."""
    return PacketRecord(
        number=number,
        time=float(getattr(packet, "time", 0.0) or 0.0),
        summary=summarize(packet),
        packet=packet,
    )
