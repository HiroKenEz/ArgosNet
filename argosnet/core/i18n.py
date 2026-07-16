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
    # Gravité (alertes)
    "Info": "Info",
    "Avertissement": "Warning",
    "Critique": "Critical",
    # Liste de paquets
    "N°": "No.",
    "Temps": "Time",
    "Source": "Source",
    "Destination": "Destination",
    "Protocole": "Protocol",
    "Long.": "Len.",
    "Champ": "Field",
    "Valeur": "Value",
    # Dashboard
    "Volume total": "Total volume",
    "Débit moyen": "Average rate",
    "Protocoles": "Protocols",
    "Débit (paquets/s)": "Rate (packets/s)",
    "temps": "time",
    "paquets/s": "packets/s",
    "paquets": "packets",
    "Débit par protocole (paquets/s)": "Rate per protocol (packets/s)",
    "Répartition par protocole": "Protocol breakdown",
    "Top talkers (par volume)": "Top talkers (by volume)",
    "Adresse": "Address",
    "{rate} p/s": "{rate} pkt/s",
    # Alertes
    "Heure": "Time",
    "Gravité": "Severity",
    "Catégorie": "Category",
    "N° paquet": "Packet no.",
    "Détail": "Detail",
    "Horodatage": "Timestamp",
    "Aucune alerte.": "No alerts.",
    "Exporter (CSV)…": "Export (CSV)…",
    "Effacer les alertes": "Clear alerts",
    "Double-cliquez une alerte pour voir le paquet concerné.":
        "Double-click an alert to view the related packet.",
    "Rien à exporter": "Nothing to export",
    "Aucune alerte à exporter.": "No alert to export.",
    "Exporter les alertes": "Export alerts",
    "Échec de l'écriture :\n{error}": "Write failed:\n{error}",
    "{total} alerte(s) — dont {critical} critique(s).":
        "{total} alert(s) — including {critical} critical.",
    # Appareils
    "Libellé": "Label",
    "Vu le": "First seen",
    "Dernier": "Last seen",
    "Appareils connus.": "Known devices.",
    "Double-cliquez la colonne « Libellé » pour nommer un appareil.":
        "Double-click the “Label” column to name a device.",
    "Rafraîchir": "Refresh",
    "{count} appareil(s) connu(s)": "{count} known device(s)",
    # Carte
    "Hôte local": "Local host",
    "Hôte externe": "External host",
    "En attente de trafic…": "Waiting for traffic…",
    "{nodes} hôte(s), {edges} lien(s) affichés": "{nodes} host(s), {edges} link(s) shown",
    # Scan (statuts / dialogues)
    "Cible manquante": "Missing target",
    "Indiquez un sous-réseau (ex. 192.168.1.0/24).": "Enter a subnet (e.g. 192.168.1.0/24).",
    "Balayage ARP de {target}…": "ARP sweep of {target}…",
    "Découverte terminée : {count} hôte(s) trouvé(s).":
        "Discovery complete: {count} host(s) found.",
    "Aucun hôte": "No host",
    "Sélectionnez un hôte dans la liste.": "Select a host from the list.",
    "Scan des ports de {ip}…": "Scanning ports of {ip}…",
    "Scan de {ip} terminé : {count} port(s) ouvert(s).":
        "Scan of {ip} complete: {count} open port(s).",
    "Échec du scan.": "Scan failed.",
    "Scan impossible": "Scan failed",
    # Éditeur de règles
    "Règles de détection (mini-IDS)": "Detection rules (mini-IDS)",
    "Chaque règle peut cibler un <b>port de destination</b> et/ou une "
    "<b>sous-chaîne</b> dans la charge utile. Gravité : info, warning ou critical. "
    "Enregistré dans <code>~/.argosnet/rules.yaml</code>.":
        "Each rule can target a <b>destination port</b> and/or a <b>substring</b> "
        "in the payload. Severity: info, warning or critical. "
        "Saved in <code>~/.argosnet/rules.yaml</code>.",
    "Nom": "Name",
    "Port dest.": "Dst port",
    "Contient": "Contains",
    "Message": "Message",
    "Ajouter": "Add",
    "Supprimer la ligne": "Delete row",
    "Enregistrer": "Save",
    "Annuler": "Cancel",
    "Enregistrement impossible": "Save failed",
    # Éditeur de couleurs
    "Couleurs des protocoles": "Protocol colors",
    "Cliquez une couleur pour la modifier.": "Click a color to change it.",
    "Réinitialiser": "Reset",
    "OK": "OK",
    "Couleur — {proto}": "Color — {proto}",
    # Onglet Interfaces
    "Interfaces réseau détectées :": "Detected network interfaces:",
    "Description": "Description",
    "Nom technique": "Technical name",
    "Adresse IP": "IP address",
    "Adresse MAC": "MAC address",
    "✓ prête": "✓ ready",
    "Npcap requis": "Npcap required",
    "Aucune interface détectée. Vérifiez que Npcap est installé "
    "et que l'application est lancée en administrateur.":
        "No interface detected. Check that Npcap is installed and that the "
        "application is running as administrator.",
    "ℹ️ Interfaces listées via l'API Windows. Installez Npcap pour activer "
    "la capture de paquets.":
        "ℹ️ Interfaces listed via the Windows API. Install Npcap to enable "
        "packet capture.",
    # Résumé de la capture
    "Résumé de la capture": "Capture summary",
    "Aucun paquet capturé.": "No packet captured.",
    "Durée": "Duration",
    "Hôtes distincts": "Distinct hosts",
    "Répartition par protocole :": "Protocol breakdown:",
    # Notifications
    "⚠️ {count} alerte(s) critique(s) détectée(s)": "⚠️ {count} critical alert(s) detected",
    "ArgosNet — alerte critique": "ArgosNet — critical alert",
    "  (+{count} autre(s))": "  (+{count} more)",
    # Capture (dialogues, menu, progression)
    "Capture en anneau : écrit le trafic dans des fichiers .pcap rotatifs\n"
    "({files} fichiers × {packets} paquets max) sous\n{dir}\n"
    "Idéal pour une surveillance continue sans saturer le disque.":
        "Ring capture: writes traffic to rotating .pcap files\n"
        "({files} files × {packets} packets max) under\n{dir}\n"
        "Ideal for continuous monitoring without filling the disk.",
    "Filtres favoris et récents": "Favorite and recent filters",
    "{count} paquet(s)": "{count} packet(s)",
    "{shown} / {total} paquet(s)": "{shown} / {total} packet(s)",
    "   ⚠ {count} perdu(s)": "   ⚠ {count} dropped",
    "texte dans source, destination, protocole ou info…":
        "text in source, destination, protocol or info…",
    "Capture en anneau impossible": "Ring capture failed",
    "Impossible de préparer le dossier d'anneau :\n{error}":
        "Cannot prepare the ring folder:\n{error}",
    "Capture impossible": "Capture failed",
    "Impossible de démarrer la capture.\n\n{error}\n\n"
    "Vérifiez que Npcap est installé et que l'application est lancée "
    "en administrateur.":
        "Cannot start capture.\n\n{error}\n\n"
        "Check that Npcap is installed and that the application is running "
        "as administrator.",
    "Ouvrir une capture": "Open a capture",
    "Captures (*.pcap *.pcapng *.cap);;Tous (*.*)":
        "Captures (*.pcap *.pcapng *.cap);;All (*.*)",
    "Lecture de la capture…": "Reading the capture…",
    "Chargement": "Loading",
    "Lecture de la capture…  {count} paquets": "Reading the capture…  {count} packets",
    "Lecture impossible": "Read failed",
    "Fichier illisible :\n{message}": "Unreadable file:\n{message}",
    "Rien à enregistrer": "Nothing to save",
    "Aucun paquet à exporter.": "No packet to export.",
    "Enregistrer la capture": "Save capture",
    "Captures (*.pcap)": "Captures (*.pcap)",
    "Écriture impossible": "Write failed",
    "Échec de l'enregistrement :\n{error}": "Save failed:\n{error}",
    "Filtrer la source  {addr}": "Filter source  {addr}",
    "Filtrer l'adresse  {addr}": "Filter address  {addr}",
    "Filtrer la destination  {addr}": "Filter destination  {addr}",
    "Filtrer le protocole  {proto}": "Filter protocol  {proto}",
    "Suivre le flux TCP": "Follow TCP stream",
    "Copier la ligne": "Copy row",
    "Copier l'info": "Copy info",
    "Suivre le flux": "Follow stream",
    "Aucune donnée applicative à réassembler pour ce flux TCP.":
        "No application data to reassemble for this TCP stream.",
    "★ Enregistrer le filtre actuel comme favori": "★ Save current filter as favorite",
    "Favoris": "Favorites",
    "Récents": "Recent",
    # Follow Stream
    "Suivre le flux TCP — {a} ↔ {b}": "Follow TCP stream — {a} ↔ {b}",
    "octets": "bytes",
    "Copier": "Copy",
    "Fermer": "Close",
    # Environnement (démarrage)
    "vérification de l'environnement": "environment check",
    "Npcap ne semble pas installé : la capture de paquets sera indisponible.\n"
    "Installez-le depuis https://npcap.com en cochant "
    "« Install Npcap in WinPcap API-compatible Mode ».":
        "Npcap does not seem to be installed: packet capture will be unavailable.\n"
        "Install it from https://npcap.com, checking "
        "“Install Npcap in WinPcap API-compatible Mode”.",
    "L'application n'est pas lancée en administrateur.\n"
    "La capture brute et le scan de ports nécessitent des privilèges élevés.":
        "The application is not running as administrator.\n"
        "Raw capture and port scanning require elevated privileges.",
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
