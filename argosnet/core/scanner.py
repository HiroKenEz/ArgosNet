"""Scan réseau : découverte d'hôtes (ARP) et scan de ports (TCP SYN).

Les deux opérations tournent dans des ``QThread`` distincts pour ne pas geler la GUI.
Elles nécessitent Npcap et des privilèges administrateur (capture/envoi bruts).
"""
from __future__ import annotations

import socket
from dataclasses import dataclass, field
from typing import Any

from PySide6.QtCore import QThread, Signal

from argosnet.core.oui import lookup_vendor

# Ports courants sondés lors d'un scan de ports.
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 161, 389, 443, 445, 465,
    587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
]


@dataclass
class HostInfo:
    ip: str
    mac: str
    vendor: str = ""
    hostname: str = ""
    open_ports: list[int] = field(default_factory=list)


def default_target(ip: str | None) -> str:
    """Déduit un sous-réseau /24 à partir d'une adresse IPv4 d'interface."""
    if not ip:
        return ""
    parts = ip.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return ""


def resolve_hostname(ip: str) -> str:
    """Résolution inverse best-effort (peut échouer silencieusement)."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


class HostDiscoveryThread(QThread):
    """Découvre les hôtes actifs d'un sous-réseau par balayage ARP."""

    host_found = Signal(object)   # HostInfo
    finished_scan = Signal(int)   # nombre d'hôtes trouvés
    error = Signal(str)

    def __init__(self, target: str, iface: Any = None) -> None:
        super().__init__()
        self._target = target
        self._iface = iface

    def run(self) -> None:
        try:
            from scapy.layers.l2 import ARP, Ether
            from scapy.sendrecv import srp
        except Exception as exc:  # noqa: BLE001
            self.error.emit(f"Scapy indisponible : {exc}")
            return

        try:
            answered, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self._target),
                timeout=3,
                iface=self._iface,
                verbose=0,
            )
        except Exception as exc:  # noqa: BLE001
            self.error.emit(
                f"Échec du balayage ARP : {exc}\n"
                "Vérifiez Npcap, les privilèges administrateur et la cible."
            )
            return

        count = 0
        for _sent, received in answered:
            ip = received.psrc
            mac = received.hwsrc
            host = HostInfo(
                ip=ip,
                mac=mac,
                vendor=lookup_vendor(mac),
                hostname=resolve_hostname(ip),
            )
            self.host_found.emit(host)
            count += 1
        self.finished_scan.emit(count)


class PortScanThread(QThread):
    """Scanne les ports TCP courants d'un hôte via un scan SYN."""

    result = Signal(str, list)    # (ip, ports ouverts)
    error = Signal(str)

    def __init__(self, ip: str, ports: list[int] | None = None, iface: Any = None) -> None:
        super().__init__()
        self._ip = ip
        self._ports = ports or COMMON_PORTS
        self._iface = iface

    def run(self) -> None:
        try:
            from scapy.layers.inet import IP, TCP
            from scapy.sendrecv import sr
        except Exception as exc:  # noqa: BLE001
            self.error.emit(f"Scapy indisponible : {exc}")
            return

        try:
            answered, _ = sr(
                IP(dst=self._ip) / TCP(dport=self._ports, flags="S"),
                timeout=3,
                iface=self._iface,
                verbose=0,
            )
        except Exception as exc:  # noqa: BLE001
            self.error.emit(f"Échec du scan de ports : {exc}")
            return

        open_ports: list[int] = []
        for sent, received in answered:
            if received.haslayer(TCP) and int(received.getlayer(TCP).flags) == 0x12:
                open_ports.append(int(sent.getlayer(TCP).dport))
        self.result.emit(self._ip, sorted(set(open_ports)))
