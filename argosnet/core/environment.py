"""Vérifications d'environnement : privilèges administrateur et pilote Npcap.

Ces contrôles ne bloquent pas le démarrage : ils permettent d'afficher un
avertissement clair à l'utilisateur quand la capture risque d'échouer.
"""
from __future__ import annotations

import ctypes
import os
import sys


def is_admin() -> bool:
    """Indique si le processus dispose des privilèges administrateur."""
    if sys.platform != "win32":
        try:
            return os.geteuid() == 0  # type: ignore[attr-defined]
        except AttributeError:
            return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def npcap_installed() -> bool:
    """Détecte la présence du pilote Npcap (indispensable à la capture sous Windows)."""
    if sys.platform != "win32":
        return True  # libpcap est supposé présent sur les autres plateformes

    windir = os.environ.get("WINDIR", r"C:\Windows")
    candidates = [
        os.path.join(windir, "System32", "Npcap", "wpcap.dll"),
        os.path.join(windir, "System32", "wpcap.dll"),
        os.path.join(windir, "SysWOW64", "Npcap", "wpcap.dll"),
    ]
    return any(os.path.exists(path) for path in candidates)


def environment_warnings() -> list[str]:
    """Retourne la liste des avertissements d'environnement à présenter à l'utilisateur."""
    from argosnet.core.i18n import tr

    warnings: list[str] = []
    if not npcap_installed():
        warnings.append(tr(
            "Npcap ne semble pas installé : la capture de paquets sera indisponible.\n"
            "Installez-le depuis https://npcap.com en cochant "
            "« Install Npcap in WinPcap API-compatible Mode »."
        ))
    if not is_admin():
        warnings.append(tr(
            "L'application n'est pas lancée en administrateur.\n"
            "La capture brute et le scan de ports nécessitent des privilèges élevés."
        ))
    return warnings
