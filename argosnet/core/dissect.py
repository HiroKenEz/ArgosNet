"""Dissection de paquets Scapy.

Trois usages, tous découplés de l'interface graphique :

* :func:`summarize`   → champs de la liste (source, destination, protocole, info) ;
* :func:`layer_tree`  → arbre déroulant des couches pour le volet de détail ;
* :func:`hexdump`     → vidage hexadécimal pour la vue hexa.
"""
from __future__ import annotations

from dataclasses import dataclass

# Imports Scapy réalisés paresseusement : on veut pouvoir importer ce module même
# si Scapy n'est pas installé (pour les tests d'interface, par exemple).
try:
    from scapy.packet import NoPayload, Packet, Raw
    from scapy.layers.l2 import ARP, Ether
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.dns import DNS
    _SCAPY_OK = True
except Exception:  # pragma: no cover - dépend de l'environnement
    _SCAPY_OK = False


# Drapeaux TCP dans l'ordre d'affichage habituel de Wireshark.
_TCP_FLAGS = [
    ("F", 0x01, "FIN"),
    ("S", 0x02, "SYN"),
    ("R", 0x04, "RST"),
    ("P", 0x08, "PSH"),
    ("A", 0x10, "ACK"),
    ("U", 0x20, "URG"),
    ("E", 0x40, "ECE"),
    ("C", 0x80, "CWR"),
]


@dataclass
class PacketSummary:
    """Résumé d'un paquet pour la liste (une ligne = un paquet)."""

    src: str
    dst: str
    protocol: str
    length: int
    info: str


def tcp_flags_str(flag_value: int) -> str:
    """Rend une chaîne compacte de drapeaux TCP, ex. « SYN, ACK »."""
    names = [name for _, bit, name in _TCP_FLAGS if flag_value & bit]
    return ", ".join(names) if names else "—"


def _highest_protocol(pkt) -> str:
    """Nom du protocole le plus « parlant » présent dans le paquet."""
    # Ordre de priorité : applicatif > réseau > liaison.
    for layer_cls, label in (
        (DNS, "DNS"),
        (ARP, "ARP"),
        (ICMP, "ICMP"),
    ):
        if pkt.haslayer(layer_cls):
            return label
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(IPv6):
        return "IPv6"
    if pkt.haslayer(IP):
        return "IP"
    if pkt.haslayer(Ether):
        return "Ethernet"
    return pkt.__class__.__name__


def _endpoints(pkt) -> tuple[str, str]:
    """Adresses source et destination les plus significatives."""
    if pkt.haslayer(IP):
        ip = pkt.getlayer(IP)
        return ip.src, ip.dst
    if pkt.haslayer(IPv6):
        ip6 = pkt.getlayer(IPv6)
        return ip6.src, ip6.dst
    if pkt.haslayer(ARP):
        arp = pkt.getlayer(ARP)
        return arp.psrc, arp.pdst
    if pkt.haslayer(Ether):
        eth = pkt.getlayer(Ether)
        return eth.src, eth.dst
    return "—", "—"


def _info(pkt, protocol: str) -> str:
    """Ligne d'information façon Wireshark, selon le protocole dominant."""
    try:
        if protocol == "DNS" and pkt.haslayer(DNS):
            return _dns_info(pkt.getlayer(DNS))
        if protocol == "ARP" and pkt.haslayer(ARP):
            return _arp_info(pkt.getlayer(ARP))
        if protocol == "ICMP" and pkt.haslayer(ICMP):
            icmp = pkt.getlayer(ICMP)
            return f"ICMP type={icmp.type} code={icmp.code}"
        if protocol == "TCP" and pkt.haslayer(TCP):
            tcp = pkt.getlayer(TCP)
            payload_len = len(tcp.payload) if not isinstance(tcp.payload, NoPayload) else 0
            return (
                f"{tcp.sport} → {tcp.dport}  [{tcp_flags_str(int(tcp.flags))}]  "
                f"Seq={tcp.seq} Ack={tcp.ack} Len={payload_len}"
            )
        if protocol == "UDP" and pkt.haslayer(UDP):
            udp = pkt.getlayer(UDP)
            payload_len = len(udp.payload) if not isinstance(udp.payload, NoPayload) else 0
            return f"{udp.sport} → {udp.dport}  Len={payload_len}"
    except Exception:
        pass
    # Repli : le résumé natif de Scapy.
    try:
        return pkt.summary()
    except Exception:
        return protocol


def _dns_qname(dns) -> str:
    """Nom de la première question DNS, quel que soit le format Scapy (qd/qd[0])."""
    qd = dns.qd
    if not qd:
        return "?"
    try:
        entry = qd[0]
    except (TypeError, IndexError, KeyError):
        entry = qd
    try:
        return entry.qname.decode(errors="replace")
    except Exception:
        return str(getattr(entry, "qname", "?"))


def _dns_info(dns) -> str:
    try:
        if dns.qr == 0:  # requête
            return f"Requête DNS : {_dns_qname(dns)}"
        # réponse
        answers = []
        for i in range(dns.ancount or 0):
            rr = dns.an[i]
            answers.append(str(getattr(rr, "rdata", "")))
        return (
            f"Réponse DNS : {_dns_qname(dns)} → "
            f"{', '.join(answers) if answers else '(vide)'}"
        )
    except Exception:
        return "DNS"


def _arp_info(arp) -> str:
    try:
        if arp.op == 1:  # who-has
            return f"Qui a {arp.pdst} ? Dis-le à {arp.psrc}"
        if arp.op == 2:  # is-at
            return f"{arp.psrc} est à {arp.hwsrc}"
    except Exception:
        pass
    return "ARP"


def packet_length(pkt) -> int:
    """Longueur du paquet sur le fil, sans jamais forcer une reconstruction.

    Pour un paquet capturé, ``pkt.original`` contient les octets bruts : on les
    mesure directement. On ne retombe sur ``len(pkt)`` (qui reconstruit le paquet)
    que pour les paquets forgés en mémoire.
    """
    raw = getattr(pkt, "original", None)
    if raw:
        return len(raw)
    try:
        return len(pkt)
    except Exception:
        return 0


def summarize(pkt) -> PacketSummary:
    """Produit le résumé d'un paquet pour la liste."""
    protocol = _highest_protocol(pkt)
    src, dst = _endpoints(pkt)
    return PacketSummary(
        src=src,
        dst=dst,
        protocol=protocol,
        length=packet_length(pkt),
        info=_info(pkt, protocol),
    )


def layer_tree(pkt) -> list[tuple[str, list[tuple[str, str]]]]:
    """Décompose le paquet en couches et champs pour le volet de détail.

    Retourne une liste ``[(nom_couche, [(champ, valeur), ...]), ...]``.
    """
    result: list[tuple[str, list[tuple[str, str]]]] = []
    layer = pkt
    while layer is not None and not isinstance(layer, NoPayload):
        fields: list[tuple[str, str]] = []
        for field_desc in getattr(layer, "fields_desc", []):
            name = field_desc.name
            try:
                value = layer.getfieldval(name)
                value_repr = layer.get_field(name).i2repr(layer, value)
            except Exception:
                value_repr = repr(getattr(layer, name, ""))
            fields.append((name, value_repr))
        result.append((layer.name, fields))
        layer = layer.payload if layer.payload is not None else None
    return result


def hexdump(pkt) -> str:
    """Vidage hexadécimal du paquet (offset | hex | ASCII)."""
    try:
        from scapy.utils import hexdump as scapy_hexdump
        return scapy_hexdump(pkt, dump=True)
    except Exception:
        return _fallback_hexdump(bytes(pkt))


def _fallback_hexdump(data: bytes, width: int = 16) -> str:
    lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset : offset + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset:04x}  {hex_part:<{width * 3}}  {ascii_part}")
    return "\n".join(lines)
