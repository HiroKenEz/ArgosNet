"""Empreinte **JA3** d'un ClientHello TLS.

JA3 identifie un client TLS (navigateur, malware, outil…) indépendamment de l'IP
ou du SNI. On concatène, dans l'ordre du ClientHello :

    version,ciphers,extensions,courbes_elliptiques,formats_de_points

(valeurs décimales séparées par des tirets, champs séparés par des virgules) puis on
prend le MD5 de cette chaîne. Les valeurs *GREASE* (RFC 8701) sont exclues pour ne pas
perturber l'empreinte. Réf. https://github.com/salesforce/ja3

Le ClientHello est parsé « à la main » par décalages d'octets : aucune dépendance à la
couche TLS de Scapy (souvent absente), et cela fonctionne hors-ligne.
"""
from __future__ import annotations

import hashlib

# Valeurs GREASE (RFC 8701) : 0x0a0a, 0x1a1a, … 0xfafa (les deux octets égaux, forme 0x?a).
_GREASE = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
}


def _u16(data: bytes, pos: int) -> int:
    return int.from_bytes(data[pos:pos + 2], "big")


def ja3_from_client_hello(data: bytes) -> tuple[str, str] | None:
    """Retourne ``(chaîne_ja3, md5_ja3)`` pour un enregistrement TLS ClientHello.

    Renvoie ``None`` si ``data`` n'est pas un ClientHello exploitable.
    """
    try:
        if len(data) < 6 or data[0] != 0x16:   # enregistrement de type handshake
            return None
        pos = 5                                # saute l'en-tête d'enregistrement (5 o)
        if data[pos] != 0x01:                  # message ClientHello
            return None
        pos += 4                               # type handshake (1) + longueur (3)
        version = _u16(data, pos)
        pos += 2
        pos += 32                              # aléa client
        pos += 1 + data[pos]                   # session id (longueur + contenu)

        # Suites de chiffrement.
        cs_len = _u16(data, pos)
        pos += 2
        ciphers = [
            c for i in range(0, cs_len - 1, 2)
            if (c := _u16(data, pos + i)) not in _GREASE
        ]
        pos += cs_len

        # Méthodes de compression.
        pos += 1 + data[pos]

        # Extensions (facultatives).
        extensions: list[int] = []
        curves: list[int] = []
        point_formats: list[int] = []
        if pos + 2 <= len(data):
            ext_total = _u16(data, pos)
            pos += 2
            end = min(pos + ext_total, len(data))
            while pos + 4 <= end:
                ext_type = _u16(data, pos)
                ext_len = _u16(data, pos + 2)
                pos += 4
                body = data[pos:pos + ext_len]
                if ext_type not in _GREASE:
                    extensions.append(ext_type)
                if ext_type == 0x000a and len(body) >= 2:      # supported_groups (courbes)
                    n = _u16(body, 0)
                    curves = [
                        g for i in range(0, n - 1, 2)
                        if (g := _u16(body, 2 + i)) not in _GREASE
                    ]
                elif ext_type == 0x000b and len(body) >= 1:    # ec_point_formats
                    n = body[0]
                    point_formats = list(body[1:1 + n])
                pos += ext_len

        ja3 = "{},{},{},{},{}".format(
            version,
            "-".join(map(str, ciphers)),
            "-".join(map(str, extensions)),
            "-".join(map(str, curves)),
            "-".join(map(str, point_formats)),
        )
        return ja3, hashlib.md5(ja3.encode()).hexdigest()
    except Exception:
        return None
