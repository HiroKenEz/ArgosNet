"""Réassemblage de flux TCP (« Follow Stream »).

À partir de la liste des paquets capturés et d'un paquet de référence, reconstitue la
conversation TCP correspondante (même 4-uplet, les deux sens) et concatène les charges
utiles par direction.

Le réassemblage suit les numéros de séquence TCP (arithmétique modulo 2³²), pas
l'ordre d'arrivée : les retransmissions sont ignorées, les chevauchements rognés et
les trous mis en attente puis vidés dans l'ordre quand ils se comblent (ou à la fin).
L'entrelacement des deux sens suit l'ordre d'arrivée des paquets.
"""
from __future__ import annotations

from dataclasses import dataclass

# Plafonds anti-exhaustion (un pcap piégé ne doit pas figer l'interface).
MAX_SEGMENTS = 50_000       # segments collectés au maximum
MAX_STREAM_BYTES = 20 * 1024 * 1024  # octets de charge utile au maximum

_MOD = 2 ** 32
_HALF_MOD = 2 ** 31
_TCP_SYN = 0x02


def _seq_before(a: int, b: int) -> bool:
    """``a`` strictement avant ``b``, en arithmétique modulo 2³²."""
    return a != b and (b - a) % _MOD < _HALF_MOD


def _seq_le(a: int, b: int) -> bool:
    """``a`` avant ou égal à ``b``, en arithmétique modulo 2³²."""
    return a == b or _seq_before(a, b)


def _mod_min(seqs: list[int]) -> int:
    """Plus petite séquence (comparaison modulo 2³²), pour des seq proches."""
    best = seqs[0]
    for seq in seqs[1:]:
        if _seq_before(seq, best):
            best = seq
    return best


@dataclass
class TcpStream:
    endpoint_a: str                       # « ip:port » du côté « a » (référence)
    endpoint_b: str
    segments: list                        # list[tuple[bool, bytes]] : (a_vers_b, données)
    truncated: bool = False               # True si les plafonds ont coupé le flux

    def total_bytes(self) -> int:
        return sum(len(data) for _, data in self.segments)


class _DirectionBuffer:
    """Réassemble un sens du flux dans l'ordre des numéros de séquence."""

    def __init__(self, next_seq: int | None = None) -> None:
        self.next_seq = next_seq
        self.pending: dict[int, bytes] = {}

    def feed(self, seq: int, data: bytes) -> list[bytes]:
        """Absorbe un segment, retourne les morceaux devenus livrables (dans l'ordre)."""
        out: list[bytes] = []
        if self.next_seq is None:
            self.next_seq = seq
        assert self.next_seq is not None
        end = (seq + len(data)) % _MOD
        if seq != self.next_seq and _seq_le(end, self.next_seq):
            return out  # segment entièrement déjà vu (retransmission)
        if seq != self.next_seq and _seq_before(seq, self.next_seq):
            skip = (self.next_seq - seq) % _MOD  # chevauchement en tête : rogne
            data = data[skip:]
            seq = self.next_seq
        if seq == self.next_seq:
            out.append(data)
            self.next_seq = (seq + len(data)) % _MOD
            while self.next_seq in self.pending:  # vide la file devenue contiguë
                chunk = self.pending.pop(self.next_seq)
                out.append(chunk)
                self.next_seq = (self.next_seq + len(chunk)) % _MOD
        elif seq not in self.pending:
            self.pending[seq] = data  # trou : mise en attente
        return out

    def flush(self) -> list[bytes]:
        """Vide la file d'attente dans l'ordre des séquences (trous non comblés)."""
        out: list[bytes] = []
        if self.next_seq is None:
            return out  # aucun segment dans ce sens
        for seq in sorted(self.pending, key=lambda s: (s - self.next_seq) % _MOD):
            data = self.pending[seq]
            end = (seq + len(data)) % _MOD
            if seq != self.next_seq and _seq_le(end, self.next_seq):
                continue
            if _seq_before(seq, self.next_seq):
                skip = (self.next_seq - seq) % _MOD
                data = data[skip:]
                seq = self.next_seq
            out.append(data)
            self.next_seq = (seq + len(data)) % _MOD
        self.pending.clear()
        return out


def _net_addrs(pkt) -> tuple[str, str] | None:
    """Adresses (src, dst) IPv4 ou IPv6 d'un paquet, ou None."""
    try:
        from scapy.layers.inet import IP
        from scapy.layers.inet6 import IPv6
    except Exception:
        return None
    if pkt.haslayer(IP):
        ip = pkt.getlayer(IP)
        return ip.src, ip.dst
    if pkt.haslayer(IPv6):
        ip6 = pkt.getlayer(IPv6)
        return ip6.src, ip6.dst
    return None


def follow_tcp_stream(packets, ref) -> TcpStream | None:
    """Réassemble le flux TCP auquel appartient ``ref`` parmi ``packets``."""
    try:
        from scapy.layers.inet import TCP
        from scapy.packet import Raw
    except Exception:
        return None
    if not ref.haslayer(TCP):
        return None
    ref_addrs = _net_addrs(ref)
    if ref_addrs is None:
        return None

    rtcp = ref.getlayer(TCP)
    a = (ref_addrs[0], int(rtcp.sport))
    b = (ref_addrs[1], int(rtcp.dport))
    key = frozenset((a, b))

    collected: list[tuple[float, int, int, bool, bytes]] = []  # (temps, ordre, seq, a→b, données)
    seqs: dict[bool, list[int]] = {True: [], False: []}
    first_syn: dict[bool, tuple[float, int]] = {}  # sens -> (temps, seq du 1er SYN)
    total = 0
    truncated = False
    for order, pkt in enumerate(packets):
        if not pkt.haslayer(TCP):
            continue
        addrs = _net_addrs(pkt)
        if addrs is None:
            continue
        tcp = pkt.getlayer(TCP)
        src = (addrs[0], int(tcp.sport))
        dst = (addrs[1], int(tcp.dport))
        if frozenset((src, dst)) != key:
            continue
        direction = src == a
        moment = float(getattr(pkt, "time", 0.0) or 0.0)
        flags = int(tcp.flags)
        if flags & _TCP_SYN:
            seq = int(tcp.seq) % _MOD
            if direction not in first_syn or moment < first_syn[direction][0]:
                first_syn[direction] = (moment, seq)
        if not pkt.haslayer(Raw):
            continue
        try:
            data = bytes(pkt.getlayer(Raw).load)
        except Exception:
            continue
        if not data:
            continue
        if len(collected) >= MAX_SEGMENTS or total >= MAX_STREAM_BYTES:
            truncated = True
            break
        # Un SYN consomme un numéro de séquence : sa charge utile démarre à seq+1.
        eff_seq = (int(tcp.seq) + (1 if flags & _TCP_SYN else 0)) % _MOD
        collected.append((moment, order, eff_seq, direction, data))
        seqs[direction].append(eff_seq)
        total += len(data)

    collected.sort(key=lambda item: (item[0], item[1]))
    # Point de départ par sens : seq+1 du premier SYN si présent, sinon la plus
    # petite seq collectée (comparaison modulo 2³²). Un segment de seq inférieure
    # arrivé après le premier n'est ainsi plus jeté comme une retransmission.
    buffers = {}
    for direction in (True, False):
        if direction in first_syn:
            initial: int | None = (first_syn[direction][1] + 1) % _MOD
        elif seqs[direction]:
            initial = _mod_min(seqs[direction])
        else:
            initial = None
        buffers[direction] = _DirectionBuffer(initial)
    segments: list[tuple[bool, bytes]] = []
    for _, _, seq, a_to_b, data in collected:
        for chunk in buffers[a_to_b].feed(seq, data):
            segments.append((a_to_b, chunk))
    for direction in (True, False):
        for chunk in buffers[direction].flush():
            segments.append((direction, chunk))
    stream = TcpStream(f"{a[0]}:{a[1]}", f"{b[0]}:{b[1]}", segments)
    stream.truncated = truncated
    return stream
