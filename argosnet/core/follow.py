"""Réassemblage de flux TCP (« Follow Stream »).

À partir de la liste des paquets capturés et d'un paquet de référence, reconstitue la
conversation TCP correspondante (même 4-uplet, les deux sens), ordonnée dans le temps,
et concatène les charges utiles par direction.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class TcpStream:
    endpoint_a: str                       # « ip:port » du côté « a » (référence)
    endpoint_b: str
    segments: list                        # list[tuple[bool, bytes]] : (a_vers_b, données)

    def total_bytes(self) -> int:
        return sum(len(data) for _, data in self.segments)


def follow_tcp_stream(packets, ref) -> TcpStream | None:
    """Réassemble le flux TCP auquel appartient ``ref`` parmi ``packets``."""
    try:
        from scapy.layers.inet import IP, TCP
        from scapy.packet import Raw
    except Exception:
        return None
    if not (ref.haslayer(IP) and ref.haslayer(TCP)):
        return None

    rip, rtcp = ref.getlayer(IP), ref.getlayer(TCP)
    a = (rip.src, int(rtcp.sport))
    b = (rip.dst, int(rtcp.dport))
    key = frozenset((a, b))

    matched: list[tuple[float, bool, bytes]] = []
    for pkt in packets:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            continue
        ip, tcp = pkt.getlayer(IP), pkt.getlayer(TCP)
        src = (ip.src, int(tcp.sport))
        dst = (ip.dst, int(tcp.dport))
        if frozenset((src, dst)) != key:
            continue
        try:
            data = bytes(pkt.getlayer(Raw).load)
        except Exception:
            continue
        if not data:
            continue
        matched.append((float(getattr(pkt, "time", 0.0) or 0.0), src == a, data))

    matched.sort(key=lambda item: item[0])
    segments = [(a_to_b, data) for _, a_to_b, data in matched]
    return TcpStream(f"{a[0]}:{a[1]}", f"{b[0]}:{b[1]}", segments)
