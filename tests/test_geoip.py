"""Tests de la classification IP (cœur GeoIP, hors-ligne, sans MaxMind)."""
from argosnet.core.geoip import classify_ip, describe, is_external, lookup


def test_classify_private():
    assert classify_ip("192.168.1.10") == "privé"
    assert classify_ip("10.0.0.5") == "privé"
    assert classify_ip("172.16.5.5") == "privé"


def test_classify_public():
    assert classify_ip("8.8.8.8") == "public"
    assert classify_ip("1.1.1.1") == "public"


def test_classify_special():
    assert classify_ip("127.0.0.1") == "loopback"
    assert classify_ip("169.254.1.1") == "lien-local"
    assert classify_ip("224.0.0.1") == "multicast"
    assert classify_ip("100.64.0.1") == "CGN"
    assert classify_ip("pas une IP") == "?"


def test_is_external():
    assert is_external("8.8.8.8") is True
    assert is_external("192.168.1.1") is False


def test_lookup_without_data_is_empty():
    # Sans base MaxMind (ni geoip2), l'enrichissement est vide et describe() se limite
    # à la catégorie hors-ligne.
    assert lookup("8.8.8.8") == ""
    assert lookup("192.168.1.1") == ""
    assert describe("192.168.1.1") == "privé"
    assert describe("8.8.8.8") == "public"


def test_ipv6_classification():
    assert classify_ip("::1") == "loopback"
    assert classify_ip("2001:4860:4860::8888") == "public"
