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
    from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6
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

# Détection d'anomalies par apprentissage : on mesure le débit « normal » de chaque
# source pendant une fenêtre d'apprentissage, puis on signale les pics anormaux.
BASELINE_LEARN_SECONDS = 30.0   # durée d'apprentissage (secondes de trafic observé)
BASELINE_MIN_RATE = 20          # plancher : pas d'alerte sous ce pic (paquets/s)
BASELINE_FACTOR = 5.0           # multiple de la moyenne apprise déclenchant l'anomalie
BASELINE_REALERT_SECONDS = 300.0  # délai avant de réalerte une même source

SYN = 0x02
ACK = 0x10

# Purge périodique des fenêtres glissantes : évite que les dictionnaires d'état
# accumulent une clé par IP vue « à vie » lors d'une capture longue durée.
CLEANUP_EVERY = 2000

# Plafond des tables indexées par une adresse que l'attaquant contrôle
# (``ArpSpoof.ip_to_mac``, ``Baseline.learn_counts/baseline``) : au-delà, on
# n'apprend plus de nouvelles clés, sans lever d'erreur (anti-exhaustion mémoire).
MAX_TRACKED_KEYS = 50_000


def _bounded_add(mapping: dict, key: Any, value: Any) -> None:
    """Associe ``key -> value`` si la clé existe déjà ou si le plafond n'est pas atteint."""
    if key in mapping or len(mapping) < MAX_TRACKED_KEYS:
        mapping[key] = value


def _ip_layer(pkt: Any) -> Any | None:
    """Couche réseau (IPv4 ou IPv6) d'un paquet, ou ``None`` si absente."""
    if pkt.haslayer(IP):
        return pkt.getlayer(IP)
    if pkt.haslayer(IPv6):
        return pkt.getlayer(IPv6)
    return None


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
            _bounded_add(self.ip_to_mac, ip, mac)
        return []


class PortScanDetector(Detector):
    """Repère un scan de ports (beaucoup de ports SYN sur une même cible)."""

    def __init__(self) -> None:
        # src -> deque[(time, dst, dport)]
        self.events: dict[str, deque] = defaultdict(deque)
        self._alerted: set[str] = set()
        self._n = 0

    def inspect(self, number: int, pkt: Any) -> list[Alert]:
        if not pkt.haslayer(TCP):
            return []
        ip = _ip_layer(pkt)
        if ip is None:
            return []
        tcp = pkt.getlayer(TCP)
        flags = int(tcp.flags)
        if not (flags & SYN) or (flags & ACK):  # SYN pur (pas SYN/ACK)
            return []
        src, dst = ip.src, ip.dst
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
        elif pkt.haslayer(ICMPv6EchoRequest):
            ip = _ip_layer(pkt)
            if ip is not None:
                src, dst = ip.src, ip.dst
        elif pkt.haslayer(ICMP) and int(pkt.getlayer(ICMP).type) == 8:
            ip = _ip_layer(pkt)
            if ip is not None:
                src, dst = ip.src, ip.dst
        elif pkt.haslayer(TCP):
            ip = _ip_layer(pkt)
            if ip is not None:
                tcp = pkt.getlayer(TCP)
                if (int(tcp.flags) & SYN) and not (int(tcp.flags) & ACK):
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
                        f"en moins de {HOSTSWEEP_WINDOW:.0f}s (découverte/scan réseau)."
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
        if not pkt.haslayer(TCP):
            return []
        ip = _ip_layer(pkt)
        if ip is None:
            return []
        tcp = pkt.getlayer(TCP)
        if not (int(tcp.flags) & SYN) or (int(tcp.flags) & ACK):
            return []
        dst = ip.dst
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
        # L'inventaire n'est pas un état d'exécution : il survit à « Effacer ».
        # « Oublier les appareils connus » réassigne explicitement ``known``
        # (voir ``MainWindow._seed_known_devices``).
        pass


class CleartextCredsDetector(Detector):
    """Repère des identifiants transmis en clair (HTTP Basic, FTP, Telnet)."""

    def __init__(self) -> None:
        self._alerted: set[tuple] = set()

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
        layer = _ip_layer(pkt)
        src = layer.src if layer is not None else "?"
        dst = layer.dst if layer is not None else "?"
        # Une seule alerte par (source, destination, type) : évite le spam sur une
        # session répétant le même en-tête d'authentification.
        key = (src, dst, kind)
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
    dans la charge utile, avec un ``severity`` et un ``message``. Les règles
    invalides sont ignorées au chargement (voir :func:`_sanitize_rule`) et chaque
    règle est évaluée dans son propre ``try`` : une règle cassée n'aveugle plus
    les autres.
    """

    def __init__(self, rules: list[dict] | None = None) -> None:
        raw = rules if rules is not None else load_rules()
        self.rules = [r for r in (_sanitize_rule(entry) for entry in raw) if r is not None]
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
            try:
                alert = self._match_rule(rule, number, pkt, dport, payload)
            except Exception:
                continue  # une règle cassée n'aveugle pas les autres
            if alert is not None:
                alerts.append(alert)
        return alerts

    def _match_rule(self, rule: dict, number: int, pkt: Any, dport: int | None, payload: bytes) -> Alert | None:
        """Évalue une règle (déjà assainie) contre un paquet."""
        rule_port = rule.get("dst_port")
        rule_contains = rule.get("contains")
        if rule_port is not None and dport != int(rule_port):
            return None
        if rule_contains and rule_contains.lower().encode() not in payload:
            return None
        if rule_port is None and not rule_contains:
            return None  # règle vide, ignorée

        layer = _ip_layer(pkt)
        src = layer.src if layer is not None else "?"
        key = (rule.get("name"), src, dport)
        if key in self._alerted:
            return None
        self._alerted.add(key)
        return Alert(
            severity=_severity_from_str(rule.get("severity", "warning")),
            category=rule.get("name", "Règle de signature"),
            source=src,
            detail=rule.get("message", "Correspondance de signature."),
            timestamp=_pkt_time(pkt),
            packet_number=number,
        )

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


# Suffixes de second niveau courants (co.uk, com.au…) : le domaine enregistré
# prend alors 3 labels au lieu de 2, sans dépendance externe.
_SECOND_LEVEL_SUFFIXES = frozenset({"co", "com", "net", "org", "gov", "ac", "edu"})


def _registered_domain(labels: list[str]) -> str:
    """Domaine enregistré d'un nom découpé en labels (gestion co.uk & co)."""
    if (
        len(labels) >= 3
        and labels[-2].lower() in _SECOND_LEVEL_SUFFIXES
        and len(labels[-1]) == 2
    ):
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


class DnsTunnelDetector(Detector):
    """Détecte l'exfiltration via DNS : sous-domaines longs et à haute entropie."""

    def __init__(self) -> None:
        self._alerted: set[tuple] = set()

    def inspect(self, number: int, pkt: Any) -> list[Alert]:
        qname = _dns_query_name(pkt)
        if not qname:
            return []
        labels = qname.split(".")
        if len(labels) < 3:
            return []
        registered = _registered_domain(labels)
        sub_labels = labels[: -len(registered.split("."))]
        longest = max(sub_labels, key=len) if sub_labels else ""
        if len(longest) >= DNS_TUNNEL_LABEL_LEN and _entropy(longest) >= DNS_TUNNEL_ENTROPY:
            layer = _ip_layer(pkt)
            client = layer.src if layer is not None else "?"
            key = (client, registered.lower())
            if key in self._alerted:
                return []
            self._alerted.add(key)
            return [
                Alert(
                    severity=Severity.WARNING,
                    category="Tunneling DNS",
                    source=client,
                    detail=(
                        f"Requête DNS de {client} avec un sous-domaine long et aléatoire "
                        f"vers « {registered} » — possible exfiltration de données via DNS."
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
        if not pkt.haslayer(TCP):
            return []
        ip = _ip_layer(pkt)
        if ip is None:
            return []
        tcp = pkt.getlayer(TCP)
        if not (int(tcp.flags) & SYN) or (int(tcp.flags) & ACK):
            return []
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
            seen = ", ".join(sorted(self.servers))
            return [
                Alert(
                    severity=Severity.CRITICAL,
                    category="Serveur DHCP rogue",
                    source=server,
                    detail=(
                        f"Un second serveur DHCP répond sur le réseau ({server}). "
                        f"Serveurs vus : {seen}. Le premier serveur vu n'est pas "
                        "forcément le légitime : vérifiez quel serveur est autorisé "
                        "(possible serveur DHCP pirate, attaque de l'homme du milieu)."
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
        if not self.blocklist:
            return []
        ip = _ip_layer(pkt)
        if ip is None:
            return []
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
        if not pkt.haslayer(TCP):
            return []
        ip = _ip_layer(pkt)
        if ip is None:
            return []
        tcp = pkt.getlayer(TCP)
        if not (int(tcp.flags) & SYN) or (int(tcp.flags) & ACK):  # SYN pur
            return []
        dport = int(tcp.dport)
        if dport < PORTKNOCK_MIN_PORT:
            return []
        src, dst = ip.src, ip.dst
        now = _pkt_time(pkt)

        self._n += 1
        if self._n % CLEANUP_EVERY == 0:
            _prune_events(self.events, now, PORTKNOCK_WINDOW, lambda e: e[0])

        window = self.events[(src, dst)]
        window.append((now, dport))
        while window and now - window[0][0] > PORTKNOCK_WINDOW:
            window.popleft()

        # Les retransmissions SYN répètent le même port : on dédoublonne les coups
        # consécutifs avant d'exiger des ports distincts (sinon un retry annule tout).
        sequence = [p for _, p in window]
        deduped = [p for i, p in enumerate(sequence) if i == 0 or p != sequence[i - 1]]
        distinct = set(deduped)
        if (
            (src, dst) not in self._alerted
            and PORTKNOCK_MIN_PORTS <= len(distinct) <= PORTKNOCK_MAX_PORTS
            and len(deduped) == len(distinct)
        ):
            self._alerted.add((src, dst))
            shown = " → ".join(str(p) for p in deduped)
            return [
                Alert(
                    severity=Severity.WARNING,
                    category="Port knocking",
                    source=src,
                    detail=(
                        f"{src} a frappé une séquence de {len(distinct)} ports hauts sur {dst} "
                        f"({shown}) en moins de {PORTKNOCK_WINDOW:.0f}s — possible port knocking "
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
        layer = _ip_layer(pkt)
        src = layer.src if layer is not None else "?"
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


class BaselineAnomalyDetector(Detector):
    """Apprend le débit normal par source, puis signale les pics anormaux.

    Pendant les ``BASELINE_LEARN_SECONDS`` premières secondes de trafic observé, on
    mesure le débit moyen (paquets/s) de chaque source. Ensuite, toute source dont le
    débit instantané (fenêtre glissante d'une seconde) dépasse ``BASELINE_FACTOR`` fois
    sa moyenne apprise — et un plancher ``BASELINE_MIN_RATE`` — est signalée. Approche
    heuristique : le pic est jugé relativement au comportement habituel de la source.

    Limites assumées : un pic **pendant** l'apprentissage fausse la moyenne apprise
    (empoisonnement) et peut aveugler la détection pour cette source ; les paquets
    antérieurs au début observé (pcap désordonné) sont ignorés. Une source réalerte
    au plus toutes les ``BASELINE_REALERT_SECONDS`` secondes.
    """

    def __init__(self) -> None:
        self.events: dict[str, deque] = defaultdict(deque)  # src -> temps (fenêtre 1 s)
        self.learn_counts: dict[str, int] = defaultdict(int)
        self.baseline: dict[str, float] = {}                # src -> débit moyen appris
        self._last_alert: dict[str, float] = {}             # src -> temps de la dernière alerte
        self._t0: float | None = None
        self._n = 0

    def inspect(self, number: int, pkt: Any) -> list[Alert]:
        layer = _ip_layer(pkt)
        if layer is None:
            return []
        src = layer.src
        now = _pkt_time(pkt)
        if self._t0 is None:
            self._t0 = now
        elapsed = now - self._t0
        if elapsed < 0:
            return []  # paquet hors-ordre (pcap désordonné) : ignoré

        self._n += 1
        if self._n % CLEANUP_EVERY == 0:
            _prune_events(self.events, now, 1.0, lambda t: t)

        window = self.events[src]
        window.append(now)
        while window and now - window[0] > 1.0:
            window.popleft()
        rate = len(window)

        if elapsed < BASELINE_LEARN_SECONDS:
            # Phase d'apprentissage : on compte, on n'alerte pas.
            _bounded_add(self.learn_counts, src, self.learn_counts.get(src, 0) + 1)
            return []

        base = self.baseline.get(src)
        if base is None:
            base = self.learn_counts.get(src, 0) / BASELINE_LEARN_SECONDS
            _bounded_add(self.baseline, src, base)
        threshold = max(BASELINE_MIN_RATE, BASELINE_FACTOR * base)
        if rate >= threshold:
            last = self._last_alert.get(src)
            if last is None or now - last >= BASELINE_REALERT_SECONDS:
                self._last_alert[src] = now
                return [
                    Alert(
                        severity=Severity.WARNING,
                        category="Anomalie de trafic",
                        source=src,
                        detail=(
                            f"{src} émet {rate} paquets/s, très au-dessus de son débit habituel "
                            f"(~{base:.1f}/s appris) — pic de trafic anormal."
                        ),
                        timestamp=now,
                        packet_number=number,
                    )
                ]
        return []

    def reset(self) -> None:
        self.__init__()


def _severity_from_str(value: str) -> Severity:
    return {
        "info": Severity.INFO,
        "warning": Severity.WARNING,
        "critical": Severity.CRITICAL,
    }.get(str(value).lower(), Severity.WARNING)


_VALID_SEVERITIES = ("info", "warning", "critical")
_MAX_CONTAINS_LEN = 512


def _sanitize_rule(rule: Any) -> dict | None:
    """Normalise une règle IDS, ou ``None`` si elle est invalide (ignorée, sans lever).

    Valide : ``rules`` = liste de dicts ; ``dst_port`` entier 0–65535 ou absent ;
    ``contains`` chaîne non vide ≤ 512 caractères ou absent ; au moins l'un des
    deux présent ; ``severity`` ∈ info/warning/critical (sinon warning) ;
    ``name``/``message`` convertis en chaînes.
    """
    if not isinstance(rule, dict):
        return None
    port = rule.get("dst_port")
    if port is None:
        port_int = None
    elif isinstance(port, bool):
        return None
    elif isinstance(port, int):
        port_int = port
    elif isinstance(port, str) and port.strip().isdigit():
        port_int = int(port.strip())
    else:
        return None
    if port_int is not None and not 0 <= port_int <= 65535:
        return None
    contains = rule.get("contains")
    if contains is not None:
        if not isinstance(contains, str) or not contains.strip() or len(contains) > _MAX_CONTAINS_LEN:
            return None
    if port_int is None and not contains:
        return None  # règle vide, ignorée
    severity = str(rule.get("severity", "warning")).lower()
    if severity not in _VALID_SEVERITIES:
        severity = "warning"
    clean: dict = {
        "name": str(rule.get("name") or "Règle de signature"),
        "severity": severity,
        "message": str(rule.get("message") or "Correspondance de signature."),
    }
    if port_int is not None:
        clean["dst_port"] = port_int
    if contains:
        clean["contains"] = contains
    return clean


def port_text_to_int(text: str) -> int | None:
    """Convertit un port saisi dans l'éditeur de règles, ou ``None`` si invalide."""
    text = (text or "").strip()
    if not text.isdigit():
        return None
    value = int(text)
    return value if 0 <= value <= 65535 else None


USER_RULES_PATH = os.path.join(os.path.expanduser("~"), ".argosnet", "rules.yaml")


def bundled_rules_path() -> str:
    """Chemin des règles livrées avec l'application (lecture seule)."""
    return os.path.join(os.path.dirname(__file__), "rules.yaml")


def load_rules(path: str | None = None) -> list[dict]:
    """Charge les règles de signature depuis un fichier YAML.

    Sans chemin, privilégie les règles **utilisateur** (``~/.argosnet/rules.yaml``,
    éditables dans l'UI) et retombe sur les règles livrées avec l'application.
    Les règles invalides sont ignorées silencieusement (jamais d'exception).
    """
    if path is None:
        path = USER_RULES_PATH if os.path.exists(USER_RULES_PATH) else bundled_rules_path()
    try:
        import yaml
        with open(path, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
        if not isinstance(data, dict):
            return []
        raw = data.get("rules", [])
        if not isinstance(raw, list):
            return []
        return [r for r in (_sanitize_rule(entry) for entry in raw) if r is not None]
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
        BaselineAnomalyDetector(),
        SignatureDetector(),
    ]
