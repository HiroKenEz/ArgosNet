"""Détecteurs individuels du mini-IDS.

Chaque détecteur est un objet à état : il reçoit les paquets un par un via
``inspect(number, pkt)`` et renvoie la liste d'alertes déclenchées. L'état interne
(fenêtres glissantes, tables d'apprentissage) est réinitialisé par ``reset()``.
"""
from __future__ import annotations

import os
from collections import defaultdict, deque
from typing import Any

from argosnet.core.detection.alert import Alert, Severity

try:
    from scapy.layers.l2 import ARP, Ether
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.packet import Raw
    _SCAPY_OK = True
except Exception:  # pragma: no cover
    _SCAPY_OK = False


# Seuils par défaut (ajustables). Fenêtres en secondes.
PORTSCAN_WINDOW = 5.0
PORTSCAN_PORTS = 15        # ports distincts sur une même cible → scan de ports
HOSTSWEEP_HOSTS = 15       # hôtes distincts balayés → balayage réseau
SYNFLOOD_WINDOW = 3.0
SYNFLOOD_COUNT = 100       # SYN vers une même cible dans la fenêtre → flood

SYN = 0x02
ACK = 0x10


def _pkt_time(pkt: Any) -> float:
    return float(getattr(pkt, "time", 0.0) or 0.0)


class Detector:
    """Interface commune des détecteurs."""

    def inspect(self, number: int, pkt: Any) -> list[Alert]:
        raise NotImplementedError

    def reset(self) -> None:
        self.__init__()  # type: ignore[misc]


class ArpSpoofDetector(Detector):
    """Détecte les incohérences IP↔MAC dans les réponses ARP (MITM classique)."""

    def __init__(self) -> None:
        self.ip_to_mac: dict[str, str] = {}
        self._alerted: set[tuple[str, str, str]] = set()

    def inspect(self, number: int, pkt: Any) -> list[Alert]:
        if not pkt.haslayer(ARP):
            return []
        arp = pkt.getlayer(ARP)
        if int(arp.op) != 2:  # on ne s'intéresse qu'aux « is-at » (réponses)
            return []
        ip, mac = arp.psrc, (arp.hwsrc or "").lower()
        if not ip or not mac:
            return []
        known = self.ip_to_mac.get(ip)
        if known and known != mac:
            key = (ip, known, mac)
            if key not in self._alerted:
                self._alerted.add(key)
                self.ip_to_mac[ip] = mac
                return [
                    Alert(
                        severity=Severity.CRITICAL,
                        category="ARP spoofing",
                        source=ip,
                        detail=(
                            f"L'adresse {ip} est maintenant annoncée par {mac} "
                            f"alors qu'elle était associée à {known}. "
                            "Possible attaque de l'homme du milieu (MITM)."
                        ),
                        timestamp=_pkt_time(pkt),
                        packet_number=number,
                    )
                ]
        else:
            self.ip_to_mac[ip] = mac
        return []


class PortScanDetector(Detector):
    """Repère un scan de ports (beaucoup de ports SYN sur une même cible)."""

    def __init__(self) -> None:
        # src -> deque[(time, dst, dport)]
        self.events: dict[str, deque] = defaultdict(deque)
        self._alerted: set[str] = set()

    def inspect(self, number: int, pkt: Any) -> list[Alert]:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return []
        tcp = pkt.getlayer(TCP)
        flags = int(tcp.flags)
        if not (flags & SYN) or (flags & ACK):  # SYN pur (pas SYN/ACK)
            return []
        src = pkt.getlayer(IP).src
        dst = pkt.getlayer(IP).dst
        now = _pkt_time(pkt)

        window = self.events[src]
        window.append((now, dst, int(tcp.dport)))
        while window and now - window[0][0] > PORTSCAN_WINDOW:
            window.popleft()

        ports_by_host: dict[str, set] = defaultdict(set)
        for _, d, p in window:
            ports_by_host[d].add(p)
        for host, ports in ports_by_host.items():
            if len(ports) >= PORTSCAN_PORTS and (src, host) not in self._alerted:
                self._alerted.add((src, host))  # type: ignore[arg-type]
                return [
                    Alert(
                        severity=Severity.WARNING,
                        category="Scan de ports",
                        source=src,
                        detail=(
                            f"{src} a sondé {len(ports)} ports différents sur {host} "
                            f"en moins de {PORTSCAN_WINDOW:.0f}s (scan TCP SYN)."
                        ),
                        timestamp=now,
                        packet_number=number,
                    )
                ]
        return []


class HostSweepDetector(Detector):
    """Repère un balayage réseau (une source qui sonde beaucoup d'hôtes)."""

    def __init__(self) -> None:
        self.events: dict[str, deque] = defaultdict(deque)
        self._alerted: set[str] = set()

    def inspect(self, number: int, pkt: Any) -> list[Alert]:
        src = dst = None
        now = _pkt_time(pkt)
        if pkt.haslayer(ARP) and int(pkt.getlayer(ARP).op) == 1:
            arp = pkt.getlayer(ARP)
            src, dst = arp.psrc, arp.pdst
        elif pkt.haslayer(IP) and pkt.haslayer(ICMP) and int(pkt.getlayer(ICMP).type) == 8:
            ip = pkt.getlayer(IP)
            src, dst = ip.src, ip.dst
        elif pkt.haslayer(IP) and pkt.haslayer(TCP):
            tcp = pkt.getlayer(TCP)
            if (int(tcp.flags) & SYN) and not (int(tcp.flags) & ACK):
                ip = pkt.getlayer(IP)
                src, dst = ip.src, ip.dst
        if not src or not dst:
            return []

        window = self.events[src]
        window.append((now, dst))
        while window and now - window[0][0] > PORTSCAN_WINDOW:
            window.popleft()
        hosts = {d for _, d in window}
        if len(hosts) >= HOSTSWEEP_HOSTS and src not in self._alerted:
            self._alerted.add(src)
            return [
                Alert(
                    severity=Severity.WARNING,
                    category="Balayage réseau",
                    source=src,
                    detail=(
                        f"{src} a contacté {len(hosts)} hôtes différents "
                        f"en moins de {PORTSCAN_WINDOW:.0f}s (découverte/scan réseau)."
                    ),
                    timestamp=now,
                    packet_number=number,
                )
            ]
        return []


class SynFloodDetector(Detector):
    """Repère un afflux massif de SYN vers une même cible (déni de service)."""

    def __init__(self) -> None:
        self.events: dict[str, deque] = defaultdict(deque)
        self._alerted: set[str] = set()

    def inspect(self, number: int, pkt: Any) -> list[Alert]:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return []
        tcp = pkt.getlayer(TCP)
        if not (int(tcp.flags) & SYN) or (int(tcp.flags) & ACK):
            return []
        dst = pkt.getlayer(IP).dst
        now = _pkt_time(pkt)
        window = self.events[dst]
        window.append(now)
        while window and now - window[0] > SYNFLOOD_WINDOW:
            window.popleft()
        if len(window) >= SYNFLOOD_COUNT and dst not in self._alerted:
            self._alerted.add(dst)
            return [
                Alert(
                    severity=Severity.CRITICAL,
                    category="SYN flood",
                    source=dst,
                    detail=(
                        f"{len(window)} paquets SYN reçus par {dst} en "
                        f"{SYNFLOOD_WINDOW:.0f}s. Possible déni de service (SYN flood)."
                    ),
                    timestamp=now,
                    packet_number=number,
                )
            ]
        return []


class NewDeviceDetector(Detector):
    """Signale l'apparition d'un nouvel appareil (MAC jamais vue)."""

    def __init__(self, known_macs: set[str] | None = None) -> None:
        self.known: set[str] = set(known_macs or set())

    def inspect(self, number: int, pkt: Any) -> list[Alert]:
        if not pkt.haslayer(Ether):
            return []
        mac = (pkt.getlayer(Ether).src or "").lower()
        if not mac or mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            return []
        # Ignore les adresses multicast (bit de poids faible du 1er octet).
        try:
            if int(mac.split(":")[0], 16) & 0x01:
                return []
        except ValueError:
            return []
        if mac in self.known:
            return []
        self.known.add(mac)
        return [
            Alert(
                severity=Severity.INFO,
                category="Nouvel appareil",
                source=mac,
                detail=f"Nouvel appareil détecté sur le réseau (MAC {mac}).",
                timestamp=_pkt_time(pkt),
                packet_number=number,
            )
        ]

    def reset(self) -> None:
        self.known = set()


class CleartextCredsDetector(Detector):
    """Repère des identifiants transmis en clair (HTTP Basic, FTP, Telnet)."""

    def __init__(self) -> None:
        self._alerted: set[int] = set()

    def inspect(self, number: int, pkt: Any) -> list[Alert]:
        if not pkt.haslayer(Raw):
            return []
        try:
            payload = bytes(pkt.getlayer(Raw).load)
        except Exception:
            return []
        low = payload.lower()
        reason = None
        if b"authorization: basic " in low:
            reason = "En-tête HTTP « Authorization: Basic » (identifiants encodés en base64)."
        elif low.startswith(b"user ") or b"\nuser " in low:
            if pkt.haslayer(TCP) and int(pkt.getlayer(TCP).dport) in (21, 23):
                reason = "Commande FTP/Telnet USER en clair."
        elif low.startswith(b"pass ") or b"\npass " in low:
            if pkt.haslayer(TCP) and int(pkt.getlayer(TCP).dport) in (21, 23):
                reason = "Commande FTP/Telnet PASS (mot de passe en clair)."
        if reason is None:
            return []
        src = pkt.getlayer(IP).src if pkt.haslayer(IP) else "?"
        return [
            Alert(
                severity=Severity.WARNING,
                category="Identifiants en clair",
                source=src,
                detail=reason + " Le trafic n'est pas chiffré.",
                timestamp=_pkt_time(pkt),
                packet_number=number,
            )
        ]

    def reset(self) -> None:
        self._alerted = set()


class SignatureDetector(Detector):
    """Détecteur générique piloté par des règles (rules.yaml).

    Chaque règle peut cibler un ``dst_port`` et/ou une sous-chaîne ``contains``
    dans la charge utile, avec un ``severity`` et un ``message``.
    """

    def __init__(self, rules: list[dict] | None = None) -> None:
        self.rules = rules if rules is not None else load_rules()
        self._alerted: set[tuple] = set()

    def inspect(self, number: int, pkt: Any) -> list[Alert]:
        dport = None
        if pkt.haslayer(TCP):
            dport = int(pkt.getlayer(TCP).dport)
        elif pkt.haslayer(UDP):
            dport = int(pkt.getlayer(UDP).dport)
        payload = b""
        if pkt.haslayer(Raw):
            try:
                payload = bytes(pkt.getlayer(Raw).load).lower()
            except Exception:
                payload = b""

        alerts: list[Alert] = []
        for rule in self.rules:
            rule_port = rule.get("dst_port")
            rule_contains = rule.get("contains")
            if rule_port is not None and dport != int(rule_port):
                continue
            if rule_contains and rule_contains.lower().encode() not in payload:
                continue
            if rule_port is None and not rule_contains:
                continue  # règle vide, ignorée

            src = pkt.getlayer(IP).src if pkt.haslayer(IP) else "?"
            key = (rule.get("name"), src, dport)
            if key in self._alerted:
                continue
            self._alerted.add(key)
            alerts.append(
                Alert(
                    severity=_severity_from_str(rule.get("severity", "warning")),
                    category=rule.get("name", "Règle de signature"),
                    source=src,
                    detail=rule.get("message", "Correspondance de signature."),
                    timestamp=_pkt_time(pkt),
                    packet_number=number,
                )
            )
        return alerts

    def reset(self) -> None:
        self._alerted = set()


def _severity_from_str(value: str) -> Severity:
    return {
        "info": Severity.INFO,
        "warning": Severity.WARNING,
        "critical": Severity.CRITICAL,
    }.get(str(value).lower(), Severity.WARNING)


def load_rules(path: str | None = None) -> list[dict]:
    """Charge les règles de signature depuis un fichier YAML."""
    if path is None:
        path = os.path.join(os.path.dirname(__file__), "rules.yaml")
    try:
        import yaml
        with open(path, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
        return list(data.get("rules", []))
    except Exception:
        return []


def default_detectors() -> list[Detector]:
    """Instancie l'ensemble des détecteurs par défaut."""
    return [
        ArpSpoofDetector(),
        PortScanDetector(),
        HostSweepDetector(),
        SynFloodDetector(),
        NewDeviceDetector(),
        CleartextCredsDetector(),
        SignatureDetector(),
    ]
