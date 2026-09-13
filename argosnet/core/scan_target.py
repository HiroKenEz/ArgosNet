"""Validation de la cible de découverte réseau (sans Qt, testable).

Une cible trop large transforme le poste en canon à broadcast (flood ARP, détection
IDS garantie) : on refuse les cibles dangereuses et on exige une confirmation pour
les balayages de plus de 256 adresses ou hors réseau privé.
"""
from __future__ import annotations

import ipaddress

# Préfixe minimal accepté (/16) : en dessous, le balayage est refusé.
MIN_PREFIXLEN = 16
# Au-delà de 256 adresses (préfixe plus court que /24), confirmation obligatoire.
CONFIRM_PREFIXLEN = 24


def check_target(text: str) -> tuple:
    """Valide une cible saisie dans l'onglet Scan.

    Retourne ``(réseau, erreur, besoin_confirmation)`` : ``réseau`` est un
    ``IPv4Network`` normalisé (ou None), ``erreur`` un message (clé ``tr``) ou
    None, ``besoin_confirmation`` exige un ``QMessageBox.question`` côté UI.
    """
    text = (text or "").strip()
    if not text:
        return None, "Indiquez un sous-réseau (ex. 192.168.1.0/24).", False
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None, (
            "Cible invalide : utilisez une adresse IPv4 ou un sous-réseau CIDR "
            "(ex. 192.168.1.0/24)."
        ), False
    if not isinstance(network, ipaddress.IPv4Network):
        return None, (
            "Cible invalide : utilisez une adresse IPv4 ou un sous-réseau CIDR "
            "(ex. 192.168.1.0/24)."
        ), False
    if (
        network.network_address.is_unspecified
        or network.network_address.is_loopback
        or network.is_multicast
        or network.prefixlen < MIN_PREFIXLEN
    ):
        return None, (
            "Cible refusée : 0.0.0.0, loopback, multicast et préfixes < /16 "
            "sont interdits."
        ), False
    need_confirm = network.prefixlen < CONFIRM_PREFIXLEN or not network.is_private
    return network, None, need_confirm
