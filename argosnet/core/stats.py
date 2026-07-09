"""Moteur de statistiques : compteurs alimentés par le flux de paquets.

Découplé de l'interface : le dashboard vient lire les agrégats et rafraîchit ses
graphes via un ``QTimer``. Le débit est binné à la seconde (horodatage du paquet)
pour tracer une courbe temporelle aussi bien en direct que sur un .pcap chargé.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass

from argosnet.core.dissect import _endpoints, _highest_protocol, packet_length


@dataclass
class Talker:
    address: str
    packets: int
    bytes: int


class StatsEngine:
    def __init__(self) -> None:
        self.total_packets = 0
        self.total_bytes = 0
        self.proto_counts: Counter[str] = Counter()
        self.talker_packets: Counter[str] = Counter()
        self.talker_bytes: Counter[str] = Counter()
        self.conv_packets: Counter[tuple[str, str]] = Counter()
        self.conv_bytes: Counter[tuple[str, str]] = Counter()
        self.per_second_packets: dict[int, int] = defaultdict(int)
        self.per_second_bytes: dict[int, int] = defaultdict(int)
        self._t0: float | None = None

    # ------------------------------------------------------------- ingestion
    def add_packet(self, packet) -> None:
        length = packet_length(packet)
        self.total_packets += 1
        self.total_bytes += length

        proto = _highest_protocol(packet)
        self.proto_counts[proto] += 1

        src, dst = _endpoints(packet)
        for endpoint in (src, dst):
            if endpoint and endpoint != "—":
                self.talker_packets[endpoint] += 1
                self.talker_bytes[endpoint] += length

        if src != "—" and dst != "—":
            key = (src, dst) if src <= dst else (dst, src)
            self.conv_packets[key] += 1
            self.conv_bytes[key] += length

        ts = float(getattr(packet, "time", 0.0) or 0.0)
        if self._t0 is None:
            self._t0 = ts
        bucket = int(ts - self._t0) if self._t0 is not None else 0
        self.per_second_packets[bucket] += 1
        self.per_second_bytes[bucket] += length

    def add_packets(self, packets) -> None:
        for packet in packets:
            self.add_packet(packet)

    def reset(self) -> None:
        self.__init__()

    # ------------------------------------------------------------- lectures
    def protocol_breakdown(self) -> list[tuple[str, int]]:
        return self.proto_counts.most_common()

    def top_talkers(self, limit: int = 10) -> list[Talker]:
        return [
            Talker(addr, self.talker_packets[addr], byte_count)
            for addr, byte_count in self.talker_bytes.most_common(limit)
        ]

    def top_conversations(self, limit: int = 10) -> list[tuple[str, str, int, int]]:
        return [
            (a, b, self.conv_packets[(a, b)], byte_count)
            for (a, b), byte_count in self.conv_bytes.most_common(limit)
        ]

    def throughput_series(self) -> tuple[list[int], list[int], list[float]]:
        """Retourne (secondes, paquets/s, Ko/s) sur toute la durée observée."""
        if not self.per_second_packets:
            return [], [], []
        last = max(self.per_second_packets)
        seconds = list(range(0, last + 1))
        pps = [self.per_second_packets.get(s, 0) for s in seconds]
        kbps = [self.per_second_bytes.get(s, 0) / 1024.0 for s in seconds]
        return seconds, pps, kbps
