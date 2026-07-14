"""Détecteurs individuels du mini-IDS.

Chaque détecteur est un objet à état : il reçoit les paquets un par un via
``inspect(number, pkt)`` et renvoie la liste d'alertes déclenchées. L'état interne
(fenêtres glissantes, tables d'apprentissage) est réinitialisé par ``reset()``.
"""
from __future__ import annotations

import math
import os
from collections import Counter, defaultdict, deque
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
HOSTSWEEP_WINDOW = 5.0
HOSTSWEEP_HOSTS = 15       # hôtes distincts balayés → balayage réseau
SYNFLOOD_WINDOW = 3.0
SYNFLOOD_COUNT = 100       # SYN vers une même cible dans la fenêtre → flood

# Détections avancées.
DNS_TUNNEL_LABEL_LEN = 35  # longueur mini d'un label sous-domaine « encodé »
DNS_TUNNEL_ENTROPY = 3.5   # entropie mini (bits/caractère) pour juger un label aléatoire
BEACON_MIN_EVENTS = 5      # nb mini de connexions pour juger d'une périodicité
BEACON_MAX_JITTER = 0.15   # coefficient de variation maxi des intervalles (régularité)
BEACON_MIN_INTERVAL = 1.0
BEACON_MAX_INTERVAL = 3600.0

# Port knocking : courte séquence de SYN vers des ports hauts distincts d'une même
# cible, depuis une même source, dans une fenêtre brève. Volontairement borné en
# nombre de ports pour rester distinct d'un scan (voir PORTSCAN_PORTS).
PORTKNOCK_WINDOW = 10.0
PORTKNOCK_MIN_PORTS = 3
PORTKNOCK_MAX_PORTS = 7
PORTKNOCK_MIN_PORT = 1024   # les « coups » visent des ports hauts/inhabituels

SYN = 0x02
ACK = 0x10

# Purge périodique des fenêtres glissantes : évite que les dictionnaires d'état
# accumulent une clé par IP vue « à vie » lors d'une capture longue durée.
CLEANUP_EVERY = 2000


def _pkt_time(pkt: Any) -> float:
    return float(getattr(pkt, "time", 0.0) or 0.0)


def _prune_events(events: dict, now: float, window: float, time_of) -> None:
    """Vide les entrées expirées et supprime les clés dont la fenêtre est vide."""
    stale = []
    for key, dq in events.items():
        while dq and now - time_of(dq[0]) > window:
            dq.popleft()
        if not dq:
            stale.append(key)
    for key in stale:
        del events[key]


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
        self._n = 0

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

        self._n += 1
        if self._n % CLEANUP_EVERY == 0:
            _prune_events(self.events, now, PORTSCAN_WINDOW, lambda e: e[0])

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
        self._n = 0

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

        self._n += 1
        if self._n % CLEANUP_EVERY == 0:
            _prune_events(self.events, now, HOSTSWEEP_WINDOW, lambda e: e[0])

        window = self.events[src]
        window.append((now, dst))
        while window and now - window[0][0] > HOSTSWEEP_WINDOW:
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
        self._n = 0

    def inspect(self, number: int, pkt: Any) -> list[Alert]:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return []
        tcp = pkt.getlayer(TCP)
        if not (int(tcp.flags) & SYN) or (int(tcp.flags) & ACK):
            return []
        dst = pkt.getlayer(IP).dst
        now = _pkt_time(pkt)

        self._n += 1
        if self._n % CLEANUP_EVERY == 0:
            _prune_events(self.events, now, SYNFLOOD_WINDOW, lambda e: e)

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
        reason = kind = None
        if b"authorization: basic " in low:
            reason = "En-tête HTTP « Authorization: Basic » (identifiants encodés en base64)."
            kind = "http-basic"
        elif low.startswith(b"user ") or b"\nuser " in low:
            if pkt.haslayer(TCP) and int(pkt.getlayer(TCP).dport) in (21, 23):
                reason, kind = "Commande FTP/Telnet USER en clair.", "ftp-user"
        elif low.startswith(b"pass ") or b"\npass " in low:
            if pkt.haslayer(TCP) and int(pkt.getlayer(TCP).dport) in (21, 23):
                reason, kind = "Commande FTP/Telnet PASS (mot de passe en clair).", "ftp-pass"
        if reason is None:
            return []
        src = pkt.getlayer(IP).src if pkt.haslayer(IP) else "?"
        dst = pkt.getlayer(IP).dst if pkt.haslayer(IP) else "?"
        # Une seule alerte par (source, destination, type) : évite le spam sur une
        # session répétant le même en-tête d'authentification.
        key = hash((src, dst, kind))
        if key in self._alerted:
            return []
        self._alerted.add(key)
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


def _entropy(text: str) -> float:
    """Entropie de Shannon (bits par caractère) d'une chaîne."""
    if not text:
        return 0.0
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in Counter(text).values())


def _dns_query_name(pkt) -> str | None:
    """Nom de domaine d'une requête DNS (None si ce n'est pas une requête DNS)."""
    try:
        from scapy.layers.dns import DNS
    except Exception:
        return None
    if not pkt.haslayer(DNS):
        return None
    dns = pkt.getlayer(DNS)
    if int(getattr(dns, "qr", 0)) != 0:  # 0 = requête
        return None
    qd = dns.qd
    if not qd:
        return None
    try:
        entry = qd[0]
    except (TypeError, IndexError, KeyError):
        entry = qd
    try:
        return entry.qname.decode(errors="replace").rstrip(".")
    except Exception:
        return None


class DnsTunnelDetector(Detector):
    """Détecte l'exfiltration via DNS : sous-domaines longs et à haute entropie."""

    def __init__(self) -> None:
        self._alerted: set[str] = set()

    def inspect(self, number: int, pkt: Any) -> list[Alert]:
        qname = _dns_query_name(pkt)
        if not qname:
            return []
        labels = qname.split(".")
        if len(labels) < 3:
            return []
        registered = ".".join(labels[-2:])
        sub_labels = labels[:-2]
        longest = max(sub_labels, key=len) if sub_labels else ""
        if len(longest) >= DNS_TUNNEL_LABEL_LEN and _entropy(longest) >= DNS_TUNNEL_ENTROPY:
            if registered in self._alerted:
                return []
            self._alerted.add(registered)
            return [
                Alert(
                    severity=Severity.WARNING,
                    category="Tunneling DNS",
                    source=registered,
                    detail=(
                        f"Requête DNS avec un sous-domaine long et aléatoire vers « {registered} » "
                        "— possible exfiltration de données via DNS."
                    ),
                    timestamp=_pkt_time(pkt),
                    packet_number=number,
                )
            ]
        return []

    def reset(self) -> None:
        self._alerted = set()


class BeaconDetector(Detector):
    """Détecte un trafic périodique régulier (possible balise de commande C2)."""

    def __init__(self) -> None:
        self.events: dict = defaultdict(lambda: deque(maxlen=12))
        self._alerted: set = set()
        self._n = 0

    def inspect(self, number: int, pkt: Any) -> list[Alert]:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return []
        tcp = pkt.getlayer(TCP)
        if not (int(tcp.flags) & SYN) or (int(tcp.flags) & ACK):
            return []
        ip = pkt.getlayer(IP)
        key = (ip.src, ip.dst, int(tcp.dport))
        now = _pkt_time(pkt)

        self._n += 1
        if self._n % CLEANUP_EVERY == 0:
            for k in [k for k, dq in self.events.items()
                      if dq and now - dq[-1] > BEACON_MAX_INTERVAL * 3]:
                del self.events[k]

        times = self.events[key]
        times.append(now)
        if key in self._alerted or len(times) < BEACON_MIN_EVENTS:
            return []
        intervals = [b - a for a, b in zip(times, list(times)[1:])]
        mean = sum(intervals) / len(intervals)
        if not (BEACON_MIN_INTERVAL <= mean <= BEACON_MAX_INTERVAL):
            return []
        variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
        cv = (variance ** 0.5) / mean if mean else 1.0
        if cv <= BEACON_MAX_JITTER:
            self._alerted.add(key)
            return [
                Alert(
                    severity=Severity.WARNING,
                    category="Beaconing (C2 potentiel)",
                    source=ip.src,
                    detail=(
                        f"{ip.src} contacte {ip.dst}:{int(tcp.dport)} à intervalle très régulier "
                        f"(~{mean:.0f}s) — comportement de balise de commande (C2)."
                    ),
                    timestamp=now,
                    packet_number=number,
                )
            ]
        return []

    def reset(self) -> None:
        self.__init__()


class RogueDhcpDetector(Detector):
    """Signale un second serveur DHCP répondant sur le réseau (possible serveur rogue)."""

    def __init__(self) -> None:
        self.servers: set[str] = set()
        self._alerted: set[str] = set()

    def inspect(self, number: int, pkt: Any) -> list[Alert]:
        try:
            from scapy.layers.dhcp import BOOTP
        except Exception:
            return []
        if not (pkt.haslayer(BOOTP) and pkt.haslayer(IP)):
            return []
        if int(pkt.getlayer(BOOTP).op) != 2:  # BOOTREPLY = réponse d'un serveur
            return []
        server = pkt.getlayer(IP).src
        already_known = server in self.servers
        self.servers.add(server)
        if not already_known and len(self.servers) > 1 and server not in self._alerted:
            self._alerted.add(server)
            return [
                Alert(
                    severity=Severity.CRITICAL,
                    category="Serveur DHCP rogue",
                    source=server,
                    detail=(
                        f"Un second serveur DHCP répond sur le réseau ({server}). "
                        "Possible serveur DHCP pirate (attaque de l'homme du milieu)."
                    ),
                    timestamp=_pkt_time(pkt),
                    packet_number=number,
                )
            ]
        return []

    def reset(self) -> None:
        self.__init__()


BUNDLED_BLOCKLIST = os.path.join(os.path.dirname(__file__), "blocklist.txt")
USER_BLOCKLIST = os.path.join(os.path.expanduser("~"), ".argosnet", "blocklist.txt")


def load_blocklist(paths: list[str] | None = None) -> set[str]:
    """Charge une liste noire d'IP (fichier livré + fichier utilisateur)."""
    if paths is None:
        paths = [BUNDLED_BLOCKLIST, USER_BLOCKLIST]
    ips: set[str] = set()
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                for line in handle:
                    entry = line.split("#", 1)[0].strip()
                    if entry:
                        ips.add(entry)
        except Exception:
            continue
    return ips


class BlocklistDetector(Detector):
    """Alerte sur toute communication avec une IP de la liste noire (threat intel)."""

    def __init__(self, blocklist: set[str] | None = None) -> None:
        self.blocklist = blocklist if blocklist is not None else load_blocklist()
        self._alerted: set[str] = set()

    def inspect(self, number: int, pkt: Any) -> list[Alert]:
        if not self.blocklist or not pkt.haslayer(IP):
            return []
        ip = pkt.getlayer(IP)
        for addr in (ip.src, ip.dst):
            if addr in self.blocklist and addr not in self._alerted:
                self._alerted.add(addr)
                return [
                    Alert(
                        severity=Severity.CRITICAL,
                        category="Liste noire (threat intel)",
                        source=addr,
                        detail=(
                            f"Communication avec {addr}, présent sur la liste noire "
                            "d'adresses malveillantes."
                        ),
                        timestamp=_pkt_time(pkt),
                        packet_number=number,
                    )
                ]
        return []

    def reset(self) -> None:
        self._alerted = set()


class PortKnockDetector(Detector):
    """Repère une séquence de *port knocking* (ouverture furtive d'un service).

    Le port knocking consiste à frapper, dans un ordre précis, une courte suite de
    ports fermés pour déclencher l'ouverture d'un accès (souvent une backdoor). On
    signale une source qui envoie, vers une même cible et en peu de temps, des SYN
    sur ``PORTKNOCK_MIN_PORTS``..``PORTKNOCK_MAX_PORTS`` ports hauts **distincts**
    (chacun frappé une seule fois). La borne haute la distingue d'un scan de ports.
    """

    def __init__(self) -> None:
        # (src, dst) -> deque[(time, dport)]
        self.events: dict[tuple[str, str], deque] = defaultdict(deque)
        self._alerted: set[tuple[str, str]] = set()
        self._n = 0

    def inspect(self, number: int, pkt: Any) -> list[Alert]:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return []
        tcp = pkt.getlayer(TCP)
        if not (int(tcp.flags) & SYN) or (int(tcp.flags) & ACK):  # SYN pur
            return []
        dport = int(tcp.dport)
        if dport < PORTKNOCK_MIN_PORT:
            return []
        ip = pkt.getlayer(IP)
        src, dst = ip.src, ip.dst
        now = _pkt_time(pkt)

        self._n += 1
        if self._n % CLEANUP_EVERY == 0:
            _prune_events(self.events, now, PORTKNOCK_WINDOW, lambda e: e[0])

        window = self.events[(src, dst)]
        window.append((now, dport))
        while window and now - window[0][0] > PORTKNOCK_WINDOW:
            window.popleft()

        ports = [p for _, p in window]
        distinct = set(ports)
        # Séquence courte de ports distincts, chacun frappé une seule fois.
        if (
            (src, dst) not in self._alerted
            and PORTKNOCK_MIN_PORTS <= len(distinct) <= PORTKNOCK_MAX_PORTS
            and len(ports) == len(distinct)
        ):
            self._alerted.add((src, dst))
            sequence = " → ".join(str(p) for _, p in window)
            return [
                Alert(
                    severity=Severity.WARNING,
                    category="Port knocking",
                    source=src,
                    detail=(
                        f"{src} a frappé une séquence de {len(distinct)} ports hauts sur {dst} "
                        f"({sequence}) en moins de {PORTKNOCK_WINDOW:.0f}s — possible port knocking "
                        "(ouverture furtive d'un accès)."
                    ),
                    timestamp=now,
                    packet_number=number,
                )
            ]
        return []

    def reset(self) -> None:
        self.__init__()


BUNDLED_JA3_BLOCKLIST = os.path.join(os.path.dirname(__file__), "ja3_blocklist.txt")
USER_JA3_BLOCKLIST = os.path.join(os.path.expanduser("~"), ".argosnet", "ja3_blocklist.txt")


def load_ja3_blocklist(paths: list[str] | None = None) -> set[str]:
    """Charge une liste noire d'empreintes JA3 (fichier livré + fichier utilisateur)."""
    if paths is None:
        paths = [BUNDLED_JA3_BLOCKLIST, USER_JA3_BLOCKLIST]
    hashes: set[str] = set()
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                for line in handle:
                    entry = line.split("#", 1)[0].strip().lower()
                    if entry:
                        hashes.add(entry)
        except Exception:
            continue
    return hashes


class Ja3BlocklistDetector(Detector):
    """Alerte quand un ClientHello TLS présente une empreinte JA3 sur liste noire.

    JA3 identifie le client TLS indépendamment de l'IP : on repère ainsi un outil ou
    un malware connu même s'il change d'adresse ou de domaine (threat intel).
    """

    def __init__(self, blocklist: set[str] | None = None) -> None:
        self.blocklist = blocklist if blocklist is not None else load_ja3_blocklist()
        self._alerted: set[tuple[str, str]] = set()

    def inspect(self, number: int, pkt: Any) -> list[Alert]:
        if not self.blocklist or not pkt.haslayer(Raw):
            return []
        try:
            payload = bytes(pkt.getlayer(Raw).load)
        except Exception:
            return []
        if len(payload) < 6 or payload[0] != 0x16:  # enregistrement TLS handshake
            return []
        from argosnet.core.ja3 import ja3_from_client_hello

        result = ja3_from_client_hello(payload)
        if not result:
            return []
        digest = result[1].lower()
        if digest not in self.blocklist:
            return []
        src = pkt.getlayer(IP).src if pkt.haslayer(IP) else "?"
        key = (src, digest)
        if key in self._alerted:
            return []
        self._alerted.add(key)
        return [
            Alert(
                severity=Severity.CRITICAL,
                category="Empreinte JA3 malveillante",
                source=src,
                detail=(
                    f"Client TLS de {src} avec l'empreinte JA3 {digest}, connue comme "
                    "malveillante (liste noire JA3)."
                ),
                timestamp=_pkt_time(pkt),
                packet_number=number,
            )
        ]

    def reset(self) -> None:
        self._alerted = set()


def _severity_from_str(value: str) -> Severity:
    return {
        "info": Severity.INFO,
        "warning": Severity.WARNING,
        "critical": Severity.CRITICAL,
    }.get(str(value).lower(), Severity.WARNING)


USER_RULES_PATH = os.path.join(os.path.expanduser("~"), ".argosnet", "rules.yaml")


def bundled_rules_path() -> str:
    """Chemin des règles livrées avec l'application (lecture seule)."""
    return os.path.join(os.path.dirname(__file__), "rules.yaml")


def load_rules(path: str | None = None) -> list[dict]:
    """Charge les règles de signature depuis un fichier YAML.

    Sans chemin, privilégie les règles **utilisateur** (``~/.argosnet/rules.yaml``,
    éditables dans l'UI) et retombe sur les règles livrées avec l'application.
    """
    if path is None:
        path = USER_RULES_PATH if os.path.exists(USER_RULES_PATH) else bundled_rules_path()
    try:
        import yaml
        with open(path, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
        return list(data.get("rules", []))
    except Exception:
        return []


def save_rules(rules: list[dict], path: str = USER_RULES_PATH) -> None:
    """Enregistre les règles dans le fichier utilisateur (YAML)."""
    import yaml
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        yaml.safe_dump({"rules": rules}, handle, allow_unicode=True, sort_keys=False)


def default_detectors() -> list[Detector]:
    """Instancie l'ensemble des détecteurs par défaut."""
    return [
        ArpSpoofDetector(),
        PortScanDetector(),
        HostSweepDetector(),
        SynFloodDetector(),
        NewDeviceDetector(),
        CleartextCredsDetector(),
        DnsTunnelDetector(),
        BeaconDetector(),
        RogueDhcpDetector(),
        PortKnockDetector(),
        BlocklistDetector(),
        Ja3BlocklistDetector(),
        SignatureDetector(),
    ]
