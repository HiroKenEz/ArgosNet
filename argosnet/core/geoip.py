"""Classification et géolocalisation (best-effort) des adresses IP.

La **classification** (privée, publique, réservée…) est calculée hors-ligne avec la
bibliothèque standard : elle fonctionne toujours. La **géolocalisation** pays/ASN est
optionnelle : elle n'est active que si la bibliothèque ``geoip2`` est installée *et*
qu'une base MaxMind GeoLite2 est présente sous ``~/.argosnet/`` (fichiers
``GeoLite2-Country.mmdb`` / ``GeoLite2-ASN.mmdb``). Sans ces éléments, seules les
catégories hors-ligne sont renvoyées — aucune requête réseau n'est jamais faite.
"""
from __future__ import annotations

import ipaddress
import os

_CONF_DIR = os.path.join(os.path.expanduser("~"), ".argosnet")
COUNTRY_DB = os.path.join(_CONF_DIR, "GeoLite2-Country.mmdb")
ASN_DB = os.path.join(_CONF_DIR, "GeoLite2-ASN.mmdb")

_CGN = ipaddress.ip_network("100.64.0.0/10")  # NAT de fournisseur (RFC 6598)


def classify_ip(ip: str) -> str:
    """Catégorie hors-ligne d'une IP : public, privé, loopback, CGN, multicast…"""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "?"
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "lien-local"
    if addr.is_multicast:
        return "multicast"
    if isinstance(addr, ipaddress.IPv4Address) and addr in _CGN:
        return "CGN"
    if addr.is_private:
        return "privé"
    if addr.is_reserved or addr.is_unspecified:
        return "réservé"
    return "public"


def is_external(ip: str) -> bool:
    """Vrai si l'IP est publique (routable sur Internet)."""
    return classify_ip(ip) == "public"


# --- Géolocalisation optionnelle (MaxMind GeoLite2 via geoip2) ----------------
_country_reader = None
_asn_reader = None
_tried = False


def _readers():
    """Ouvre (une seule fois) les bases MaxMind si disponibles ; sinon (None, None)."""
    global _country_reader, _asn_reader, _tried
    if _tried:
        return _country_reader, _asn_reader
    _tried = True
    try:
        import geoip2.database  # type: ignore
    except Exception:
        return None, None
    if os.path.exists(COUNTRY_DB):
        try:
            _country_reader = geoip2.database.Reader(COUNTRY_DB)
        except Exception:
            _country_reader = None
    if os.path.exists(ASN_DB):
        try:
            _asn_reader = geoip2.database.Reader(ASN_DB)
        except Exception:
            _asn_reader = None
    return _country_reader, _asn_reader


def geo_available() -> bool:
    """Vrai si au moins une base MaxMind est chargée."""
    country, asn = _readers()
    return country is not None or asn is not None


def lookup(ip: str) -> str:
    """Pays/ASN best-effort d'une IP publique, ou '' si indisponible."""
    if not is_external(ip):
        return ""
    country_reader, asn_reader = _readers()
    parts: list[str] = []
    if country_reader is not None:
        try:
            code = country_reader.country(ip).country.iso_code
            if code:
                parts.append(code)
        except Exception:
            pass
    if asn_reader is not None:
        try:
            resp = asn_reader.asn(ip)
            org = resp.autonomous_system_organization or ""
            parts.append(f"AS{resp.autonomous_system_number} {org}".strip())
        except Exception:
            pass
    return " · ".join(parts)


def describe(ip: str) -> str:
    """Résumé lisible : catégorie hors-ligne, enrichie du pays/ASN si disponible."""
    base = classify_ip(ip)
    extra = lookup(ip)
    return f"{base} · {extra}" if extra else base
