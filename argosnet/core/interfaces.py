"""Découverte des interfaces réseau disponibles (via Scapy).

Fournit une couche d'abstraction légère au-dessus de Scapy pour que le reste de
l'application n'ait pas à connaître les détails de la plateforme.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class NetIface:
    """Représente une interface réseau exploitable pour la capture."""

    name: str                       # nom technique utilisé par Scapy
    description: str                # libellé lisible (ex. « Intel Wi-Fi 6 »)
    ip: str | None = None
    mac: str | None = None
    index: int | None = None
    # True si l'interface peut réellement être capturée (Npcap présent).
    capturable: bool = True
    # Objet interface Scapy brut (réutilisé tel quel pour lancer la capture).
    raw: Any = field(default=None, repr=False, compare=False)

    @property
    def label(self) -> str:
        """Libellé affichable dans les sélecteurs de l'interface graphique."""
        base = self.description or self.name
        return f"{base}  —  {self.ip}" if self.ip else base


def _first_ipv4(ips: list[str] | None) -> str | None:
    """Extrait la première adresse IPv4 exploitable d'une liste d'adresses."""
    for addr in ips or []:
        if ":" not in addr and not addr.startswith("169.254.") and addr != "0.0.0.0":
            return addr
    # À défaut d'IPv4 « propre », renvoie la première adresse non lien-local.
    for addr in ips or []:
        if ":" not in addr:
            return addr
    return None


_cache: list[NetIface] | None = None


def list_interfaces(refresh: bool = False) -> list[NetIface]:
    """Retourne la liste des interfaces réseau (mise en cache pour la session).

    - Si Npcap est présent, renvoie les interfaces réellement capturables
      (``get_working_ifaces``), avec l'objet Scapy prêt pour la capture.
    - Sinon, se replie sur l'énumération Windows (``get_windows_if_list``) pour
      rester informatif : ces entrées sont marquées ``capturable=False``.
    - Renvoie une liste vide si Scapy n'est pas disponible du tout.

    L'énumération Scapy est coûteuse : le résultat est mémorisé et une **copie** est
    renvoyée à chaque appel (les appelants peuvent trier sans effet de bord).
    Passer ``refresh=True`` pour forcer une nouvelle énumération.
    """
    global _cache
    if _cache is None or refresh:
        _cache = _compute_interfaces()
    return list(_cache)


def _compute_interfaces() -> list[NetIface]:
    capturable = _list_capturable_interfaces()
    if capturable:
        return capturable
    return _list_windows_interfaces()


def _list_capturable_interfaces() -> list[NetIface]:
    try:
        from scapy.interfaces import get_working_ifaces
        ifaces = get_working_ifaces()
    except Exception:
        return []

    result: list[NetIface] = []
    for iface in ifaces:
        ip = getattr(iface, "ip", None)
        if ip in ("0.0.0.0", ""):
            ip = None
        result.append(
            NetIface(
                name=getattr(iface, "name", str(iface)),
                description=getattr(iface, "description", "") or getattr(iface, "name", ""),
                ip=ip,
                mac=getattr(iface, "mac", None) or None,
                index=getattr(iface, "index", None),
                capturable=True,
                raw=iface,
            )
        )
    return result


def _list_windows_interfaces() -> list[NetIface]:
    """Repli informatif via l'API Windows (utilisable sans Npcap)."""
    try:
        from scapy.arch.windows import get_windows_if_list
        entries = get_windows_if_list()
    except Exception:
        return []

    result: list[NetIface] = []
    for entry in entries:
        result.append(
            NetIface(
                name=entry.get("name") or entry.get("guid") or "",
                description=entry.get("description") or entry.get("name") or "",
                ip=_first_ipv4(entry.get("ips")),
                mac=(entry.get("mac") or None),
                index=entry.get("index"),
                capturable=False,
                raw=None,
            )
        )
    return result
