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


HTTP_METHODS = (
    b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ",
    b"OPTIONS ", b"PATCH ", b"TRACE ", b"CONNECT ",
)


def _raw_payload(pkt) -> bytes:
    """Charge utile applicative brute (couche Raw), ou b'' si absente."""
    if pkt.haslayer(Raw):
        try:
            return bytes(pkt.getlayer(Raw).load)
        except Exception:
            return b""
    return b""


def _is_http(payload: bytes) -> bool:
    return payload.startswith(HTTP_METHODS) or payload.startswith(b"HTTP/")


def _is_tls(payload: bytes) -> bool:
    # Enregistrement TLS : type ∈ {change_cipher, alert, handshake, app_data}, version majeure 3.
    return len(payload) >= 3 and payload[0] in (0x14, 0x15, 0x16, 0x17) and payload[1] == 0x03


def _has_dhcp(pkt) -> bool:
    try:
        from scapy.layers.dhcp import DHCP
        return pkt.haslayer(DHCP)
    except Exception:
        return False


def _udp_ports(pkt) -> tuple[int, int]:
    udp = pkt.getlayer(UDP)
    return int(udp.sport), int(udp.dport)


def _highest_protocol(pkt) -> str:
    """Nom du protocole le plus « parlant » présent dans le paquet."""
    # Ordre de priorité : applicatif > réseau > liaison.
    if pkt.haslayer(DNS):
        if pkt.haslayer(UDP) and 5353 in _udp_ports(pkt):
            return "mDNS"
        return "DNS"
    if pkt.haslayer(ARP):
        return "ARP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    if _has_dhcp(pkt):
        return "DHCP"
    if pkt.haslayer(TCP):
        payload = _raw_payload(pkt)
        if payload:
            if _is_http(payload):
                return "HTTP"
            if _is_tls(payload):
                return "TLS"
        return "TCP"
    if pkt.haslayer(UDP):
        if 5353 in _udp_ports(pkt):
            return "mDNS"
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
        if protocol == "HTTP":
            return _http_info(_raw_payload(pkt))
        if protocol == "TLS":
            return _tls_info(_raw_payload(pkt))
        if protocol == "DHCP":
            return _dhcp_info(pkt)
        if protocol == "mDNS":
            return _dns_info(pkt.getlayer(DNS)) if pkt.haslayer(DNS) else "mDNS"
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


def _http_info(payload: bytes) -> str:
    """Première ligne HTTP (requête ou statut) + en-tête Host éventuel."""
    if not payload:
        return "HTTP"
    first = payload.split(b"\r\n", 1)[0].decode("latin-1", "replace").strip()
    host = ""
    for line in payload.split(b"\r\n")[1:]:
        if line[:5].lower() == b"host:":
            host = line[5:].strip().decode("latin-1", "replace")
            break
        if not line:  # fin des en-têtes
            break
    if host and payload.startswith(HTTP_METHODS):
        return f"HTTP  {first}   (Host: {host})"
    return f"HTTP  {first}"


def _tls_sni(data: bytes) -> str | None:
    """Extrait le SNI d'un ClientHello TLS (retourne None si absent/illisible)."""
    try:
        pos = 5  # saute l'en-tête d'enregistrement TLS
        if data[pos] != 0x01:  # doit être un ClientHello
            return None
        pos += 4                 # type handshake (1) + longueur (3)
        pos += 2                 # version client
        pos += 32                # aléa
        pos += 1 + data[pos]     # session id
        pos += 2 + int.from_bytes(data[pos:pos + 2], "big")  # cipher suites
        pos += 1 + data[pos]     # méthodes de compression
        ext_total = int.from_bytes(data[pos:pos + 2], "big")
        pos += 2
        end = min(pos + ext_total, len(data))
        while pos + 4 <= end:
            ext_type = int.from_bytes(data[pos:pos + 2], "big")
            ext_len = int.from_bytes(data[pos + 2:pos + 4], "big")
            pos += 4
            if ext_type == 0x0000:  # server_name
                p = pos + 2 + 1  # longueur de liste (2) + type de nom (1)
                name_len = int.from_bytes(data[p:p + 2], "big")
                p += 2
                return data[p:p + name_len].decode("latin-1", "replace")
            pos += ext_len
    except Exception:
        return None
    return None


def _tls_info(payload: bytes) -> str:
    if not payload:
        return "TLS"
    content_type = payload[0]
    if content_type == 0x16 and len(payload) > 5:  # handshake
        if payload[5] == 0x01:
            sni = _tls_sni(payload)
            return "TLS  Client Hello" + (f"   (SNI: {sni})" if sni else "")
        if payload[5] == 0x02:
            return "TLS  Server Hello"
        return "TLS  Handshake"
    if content_type == 0x17:
        return "TLS  Application Data"
    if content_type == 0x15:
        return "TLS  Alert"
    return "TLS"


def _dhcp_info(pkt) -> str:
    try:
        from scapy.layers.dhcp import DHCP
        dhcp = pkt.getlayer(DHCP)
        names = {
            1: "Discover", 2: "Offer", 3: "Request", 4: "Decline",
            5: "ACK", 6: "NAK", 7: "Release", 8: "Inform",
        }
        for opt in dhcp.options:
            if isinstance(opt, tuple) and opt[0] == "message-type":
                value = opt[1]
                # Sur le fil : entier (1-8). Construit symboliquement : chaîne (« discover »).
                if isinstance(value, int):
                    return "DHCP  " + names.get(value, str(value))
                return "DHCP  " + str(value).capitalize()
    except Exception:
        pass
    return "DHCP"


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
