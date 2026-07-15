"""Localisation des ressources embarquées (icône…), en source comme en build gelé.

En exécution normale, les ressources sont lues depuis le paquet ``argosnet``. Une
fois l'application empaquetée (PyInstaller ou Nuitka ``--standalone``), les fichiers
de données sont déposés à côté de l'exécutable : on essaie donc plusieurs racines et
on renvoie le premier chemin existant.
"""
from __future__ import annotations

import os
import sys


def _candidate_roots() -> list[str]:
    roots: list[str] = []
    # Build gelé : dossier de l'exécutable (PyInstaller pose aussi ``_MEIPASS``).
    if getattr(sys, "frozen", False):
        roots.append(os.path.dirname(sys.executable))
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            roots.append(meipass)
    # Source : racine du paquet ``argosnet`` (ce fichier est dans argosnet/core/).
    roots.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return roots


def resource_path(*parts: str) -> str:
    """Chemin absolu d'une ressource ``argosnet/<parts>`` (existant si possible).

    ``parts`` est relatif au paquet ``argosnet`` (ex. ``resource_path("resources",
    "argosnet.ico")``). Retourne le premier candidat existant, ou le chemin en
    source par défaut (même s'il n'existe pas, pour un message d'erreur lisible).
    """
    rel = os.path.join("argosnet", *parts)
    for root in _candidate_roots():
        candidate = os.path.join(root, rel)
        if os.path.exists(candidate):
            return candidate
    # Repli : chemin relatif au paquet, sans le préfixe « argosnet ».
    pkg_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(pkg_root, *parts)


def app_icon_path() -> str:
    """Chemin de l'icône de l'application (``.ico``)."""
    return resource_path("resources", "argosnet.ico")
