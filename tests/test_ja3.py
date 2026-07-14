"""Tests du calcul d'empreinte JA3 (ClientHello TLS)."""
import hashlib
import struct

from argosnet.core.ja3 import ja3_from_client_hello


def build_client_hello() -> bytes:
    """ClientHello déterministe : 2 suites, extensions GREASE + courbes + points."""

    def ext(ext_type: int, body: bytes) -> bytes:
        return struct.pack(">HH", ext_type, len(body)) + body

    grease = ext(0x0A0A, b"")  # extension GREASE : doit être exclue
    groups_body = struct.pack(">H", 4) + struct.pack(">HH", 0x001D, 0x0017)  # courbes 29, 23
    supported_groups = ext(0x000A, groups_body)
    ec_point = ext(0x000B, bytes([1, 0x00]))  # 1 format de point : 0
    extensions = grease + supported_groups + ec_point

    ciphers = struct.pack(">HH", 0xC02B, 0x009C)  # 49195, 156
    body = (
        struct.pack(">H", 0x0303)                       # version client (TLS 1.2 = 771)
        + b"\x00" * 32                                   # aléa
        + b"\x00"                                        # session id (longueur 0)
        + struct.pack(">H", len(ciphers)) + ciphers      # suites de chiffrement
        + b"\x01\x00"                                    # compression : 1 méthode (0)
        + struct.pack(">H", len(extensions)) + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


def test_ja3_string_and_hash():
    ja3, digest = ja3_from_client_hello(build_client_hello())
    # version,ciphers,extensions(GREASE exclue),courbes,formats_de_points
    assert ja3 == "771,49195-156,10-11,29-23,0"
    assert digest == hashlib.md5(ja3.encode()).hexdigest()


def test_ja3_rejects_non_client_hello():
    assert ja3_from_client_hello(b"\x17\x03\x03\x00\x10rubbish") is None
    assert ja3_from_client_hello(b"") is None
