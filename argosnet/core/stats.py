"""Moteur de statistiques : compteurs alimentés par le flux de paquets.

Découplé de l'interface : le dashboard vient lire les agrégats et rafraîchit ses
graphes via un ``QTimer``. Le débit est binné à la seconde (horodatage du paquet)
pour tracer une courbe temporelle aussi bien en direct que sur un .pcap chargé.

**Thread-safe** : l'alimentation se fait depuis le thread d'analyse tandis que
l'interface lit les agrégats depuis le thread graphique. Un verrou réentrant protège
donc aussi bien les écritures que les lectures (qui itèrent sur les compteurs).
"""
from __future__ import annotations

import threading
from collections import Counter, defaultdict
from dataclasses import dataclass

from argosnet.core.dissect import _endpoints, _highest_protocol, packet_length

# Durée (en secondes) conservée pour la courbe de débit. Borne la mémoire et le coût
# de reconstruction de la série sur une capture live de longue durée (jusqu'à 1 h).
THROUGHPUT_WINDOW = 3600


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
        self.per_second_proto: dict[int, dict] = defaultdict(lambda: defaultdict(int))
        self._t0: float | None = None
        self._max_bucket: int = 0
        self._lock = threading.RLock()

    # ------------------------------------------------------------- ingestion
    def add_packet(self, packet) -> None:
        with self._lock:
            self._add_packet(packet)

    def add_packets(self, packets) -> None:
        with self._lock:
            for packet in packets:
                self._add_packet(packet)

    def _add_packet(self, packet) -> None:
        """Corps de l'ingestion — appelé verrou déjà tenu."""
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
        self.per_second_proto[bucket][proto] += 1

        # Purge des secondes trop anciennes (fenêtre glissante) quand le temps avance.
        if bucket > self._max_bucket:
            self._max_bucket = bucket
            cutoff = bucket - THROUGHPUT_WINDOW
            if cutoff > 0:
                for old in [b for b in self.per_second_packets if b < cutoff]:
                    del self.per_second_packets[old]
                    self.per_second_bytes.pop(old, None)
                    self.per_second_proto.pop(old, None)

    def reset(self) -> None:
        """Remet tous les compteurs à zéro (sans recréer le verrou)."""
        with self._lock:
            self.total_packets = 0
            self.total_bytes = 0
            self.proto_counts.clear()
            self.talker_packets.clear()
            self.talker_bytes.clear()
            self.conv_packets.clear()
            self.conv_bytes.clear()
            self.per_second_packets.clear()
            self.per_second_bytes.clear()
            self.per_second_proto.clear()
            self._t0 = None
            self._max_bucket = 0

    # ------------------------------------------------------------- lectures
    def protocol_breakdown(self) -> list[tuple[str, int]]:
        with self._lock:
            return self.proto_counts.most_common()

    def distinct_protocols(self) -> int:
        with self._lock:
            return len(self.proto_counts)

    def top_talkers(self, limit: int = 10) -> list[Talker]:
        with self._lock:
            return [
                Talker(addr, self.talker_packets[addr], byte_count)
                for addr, byte_count in self.talker_bytes.most_common(limit)
            ]

    def top_conversations(self, limit: int = 10) -> list[tuple[str, str, int, int]]:
        with self._lock:
            return [
                (a, b, self.conv_packets[(a, b)], byte_count)
                for (a, b), byte_count in self.conv_bytes.most_common(limit)
            ]

    def duration(self) -> int:
        """Durée observée, en secondes (0 si aucune donnée)."""
        with self._lock:
            return self._max_bucket + 1 if self._t0 is not None else 0

    def summary(self) -> dict:
        """Résumé synthétique de la capture (pour l'affichage « Résumé »)."""
        with self._lock:
            dur = self.duration()
            return {
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "duration": dur,
                "avg_pps": (self.total_packets / dur) if dur else 0.0,
                "avg_bps": (self.total_bytes / dur) if dur else 0.0,
                "protocols": self.protocol_breakdown(),
                "distinct_talkers": len(self.talker_bytes),
                "distinct_conversations": len(self.conv_bytes),
            }

    def throughput_series(self) -> tuple[list[int], list[int], list[float]]:
        """Retourne (secondes, paquets/s, Ko/s) sur la fenêtre glissante conservée."""
        with self._lock:
            if not self.per_second_packets:
                return [], [], []
            last = max(self.per_second_packets)
            first = max(min(self.per_second_packets), last - THROUGHPUT_WINDOW + 1)
            seconds = list(range(first, last + 1))
            pps = [self.per_second_packets.get(s, 0) for s in seconds]
            kbps = [self.per_second_bytes.get(s, 0) / 1024.0 for s in seconds]
            return seconds, pps, kbps

    def throughput_by_protocol(self, top_n: int = 5) -> tuple[list[int], dict[str, list[int]]]:
        """Retourne (secondes, {protocole: paquets/s}) pour les ``top_n`` protocoles."""
        with self._lock:
            if not self.per_second_proto:
                return [], {}
            top_protocols = [name for name, _ in self.proto_counts.most_common(top_n)]
            buckets = self.per_second_proto
            last = max(buckets)
            first = max(min(buckets), last - THROUGHPUT_WINDOW + 1)
            seconds = list(range(first, last + 1))
            series = {
                proto: [buckets.get(s, {}).get(proto, 0) for s in seconds]
                for proto in top_protocols
            }
            return seconds, series
