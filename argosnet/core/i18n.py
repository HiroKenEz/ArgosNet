"""Internationalisation légère (français par défaut, anglais en option).

Le code source est écrit en français : la chaîne française sert donc de **clé**.
:func:`tr` renvoie sa traduction dans la langue courante, ou la chaîne d'origine si
aucune traduction n'existe (repli sûr). La langue est persistée dans
``~/.argosnet/config.json`` et appliquée au démarrage ; un changement en cours de
session invite à redémarrer pour reconstruire l'interface.

Ce module ne dépend pas de Qt : il est testable hors interface graphique.
"""
from __future__ import annotations

import json
import os

CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".argosnet", "config.json")
SUPPORTED = ("fr", "en")
_DEFAULT = "fr"

_current = _DEFAULT

# Traductions français → anglais. La clé est la chaîne française telle qu'écrite dans
# l'interface. Les entrées absentes retombent sur le français (pas de texte manquant).
_EN: dict[str, str] = {
    # Fenêtre / onglets
    "Analyseur réseau local": "Local network analyzer",
    "Interfaces": "Interfaces",
    "Capture": "Capture",
    "Scan": "Scan",
    "Appareils": "Devices",
    "Dashboard": "Dashboard",
    "Conversations": "Conversations",
    "Carte": "Map",
    "Alertes": "Alerts",
    "{count} interface(s) réseau détectée(s)": "{count} network interface(s) detected",
    # Menus
    "&Fichier": "&File",
    "&Affichage": "&View",
    "&Détection": "&Detection",
    "&Statistiques": "&Statistics",
    "&Historique": "&History",
    "Langue": "Language",
    "Français": "French",
    "English": "English",
    # Actions du menu
    "Ouvrir une capture .pcap…": "Open a .pcap capture…",
    "Enregistrer la capture…": "Save capture…",
    "Exporter un rapport (HTML/PDF)…": "Export a report (HTML/PDF)…",
    "Quitter": "Quit",
    "Thème sombre": "Dark theme",
    "Notifications d'alerte critique": "Critical alert notifications",
    "Couleurs des protocoles…": "Protocol colors…",
    "Éditer les règles IDS…": "Edit IDS rules…",
    "Résumé de la capture…": "Capture summary…",
    "Effacer l'historique des alertes": "Clear alert history",
    "Oublier les appareils connus": "Forget known devices",
    # Messages / dialogues
    "Historique des alertes effacé.": "Alert history cleared.",
    "Appareils connus oubliés.": "Known devices forgotten.",
    "Règles de détection rechargées.": "Detection rules reloaded.",
    "Rapport exporté : {path}": "Report exported: {path}",
    "Exporter un rapport": "Export a report",
    "Export impossible": "Export failed",
    "Redémarrez ArgosNet pour appliquer la nouvelle langue.":
        "Restart ArgosNet to apply the new language.",
    # Barre de capture
    "Interface :": "Interface:",
    "Filtre capture (BPF) :": "Capture filter (BPF):",
    "Anneau": "Ring",
    "▶ Démarrer": "▶ Start",
    "■ Arrêter": "■ Stop",
    "Filtre d'affichage :": "Display filter:",
    "Ouvrir .pcap…": "Open .pcap…",
    "Enregistrer .pcap…": "Save .pcap…",
    "Effacer": "Clear",
    "Rechercher :": "Search:",
    "Précédent": "Previous",
    "Suivant": "Next",
    # Onglet Scan
    "Cible :": "Target:",
    "Découvrir les hôtes": "Discover hosts",
    "Scanner les ports de l'hôte sélectionné": "Scan ports of selected host",
    "Prêt.": "Ready.",
    "Scan périodique": "Periodic scan",
    "min": "min",
    "IP": "IP",
    "MAC": "MAC",
    "Constructeur": "Vendor",
    "Nom d'hôte": "Hostname",
    "Ports ouverts": "Open ports",
    "Planifié : scan toutes les {minutes} min.": "Scheduled: scan every {minutes} min.",
    "Relance automatiquement la découverte d'hôtes à intervalle régulier.":
        "Automatically re-runs host discovery at a regular interval.",
    # Onglet Conversations
    "Hôte A": "Host A",
    "Hôte B": "Host B",
    "Paquets": "Packets",
    "Volume": "Volume",
    "Zone": "Zone",
    "local": "local",
    "Conversations entre hôtes (triées par volume).":
        "Host conversations (sorted by volume).",
    "{count} conversation(s) — triées par volume.":
        "{count} conversation(s) — sorted by volume.",
}

_CATALOG: dict[str, dict[str, str]] = {"en": _EN}


def available_languages() -> tuple[str, ...]:
    return SUPPORTED


def get_language() -> str:
    return _current


def set_language(lang: str) -> None:
    """Fixe la langue courante (retombe sur le défaut si non supportée)."""
    global _current
    _current = lang if lang in SUPPORTED else _DEFAULT


def tr(text: str) -> str:
    """Traduit ``text`` dans la langue courante, ou le renvoie tel quel."""
    if _current == _DEFAULT:
        return text
    return _CATALOG.get(_current, {}).get(text, text)


def load_language(path: str | None = None) -> str:
    """Lit la langue persistée et l'active. Retourne la langue effective."""
    path = path or CONFIG_PATH
    lang = _DEFAULT
    try:
        with open(path, "r", encoding="utf-8") as handle:
            lang = json.load(handle).get("language", _DEFAULT)
    except Exception:
        lang = _DEFAULT
    set_language(lang)
    return get_language()


def save_language(lang: str, path: str | None = None) -> None:
    """Active et persiste la langue choisie (fusionnée dans le fichier de config)."""
    path = path or CONFIG_PATH
    set_language(lang)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        data: dict = {}
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except Exception:
            data = {}
        data["language"] = get_language()
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2)
    except Exception:
        pass
