"""Modèle d'alerte de détection."""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class Severity(IntEnum):
    """Niveau de gravité (l'ordre numérique sert au tri décroissant)."""

    INFO = 1
    WARNING = 2
    CRITICAL = 3

    @property
    def label(self) -> str:
        return {
            Severity.INFO: "Info",
            Severity.WARNING: "Avertissement",
            Severity.CRITICAL: "Critique",
        }[self]

    @property
    def color(self) -> str:
        return {
            Severity.INFO: "#e2f0ff",
            Severity.WARNING: "#fff0d0",
            Severity.CRITICAL: "#ffdcdc",
        }[self]


@dataclass
class Alert:
    """Une alerte émise par un détecteur."""

    severity: Severity
    category: str          # ex. « ARP spoofing »
    source: str            # IP ou MAC à l'origine
    detail: str            # description lisible
    timestamp: float = 0.0
    packet_number: int | None = None
