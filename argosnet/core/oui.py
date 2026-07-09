"""Résolution du constructeur à partir d'une adresse MAC (base OUI).

S'appuie sur ``mac-vendor-lookup`` (base locale). En l'absence de base téléchargée
ou en cas d'erreur, renvoie une chaîne vide plutôt que de bloquer ou de lever :
la résolution du constructeur reste une information « best effort ».
"""
from __future__ import annotations

_lookup = None
_unavailable = False


def lookup_vendor(mac: str) -> str:
    """Renvoie le nom du constructeur pour une MAC, ou '' si inconnu/indisponible."""
    global _lookup, _unavailable
    if _unavailable or not mac:
        return ""
    try:
        from mac_vendor_lookup import MacLookup
        if _lookup is None:
            _lookup = MacLookup()
        return _lookup.lookup(mac)
    except Exception:
        # Base absente (jamais mise à jour) ou MAC invalide : on abandonne
        # silencieusement pour ne pas ralentir les scans suivants.
        return ""


def update_vendor_db() -> bool:
    """Télécharge/rafraîchit la base OUI (nécessite un accès réseau).

    Renvoie True en cas de succès. À appeler explicitement (ex. depuis un menu).
    """
    global _lookup, _unavailable
    try:
        from mac_vendor_lookup import MacLookup
        if _lookup is None:
            _lookup = MacLookup()
        _lookup.update_vendors()
        _unavailable = False
        return True
    except Exception:
        return False
