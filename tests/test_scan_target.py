"""Tests de la validation de cible de scan (sans Qt)."""
from argosnet.core.scan_target import check_target


def test_valid_private_24_no_confirm():
    network, error, need_confirm = check_target("192.168.1.0/24")
    assert error is None
    assert need_confirm is False
    assert str(network) == "192.168.1.0/24"


def test_single_ip_normalized():
    network, error, need_confirm = check_target("192.168.1.5")
    assert error is None
    assert str(network) == "192.168.1.5/32"
    assert need_confirm is False


def test_empty_and_garbage_rejected():
    for text in ("", "   ", "n'importe quoi", "2001:db8::/32", "999.1.1.0/24"):
        network, error, need_confirm = check_target(text)
        assert network is None
        assert error
        assert need_confirm is False


def test_dangerous_targets_refused():
    for text in ("0.0.0.0/0", "0.0.0.0/8", "127.0.0.0/8", "224.0.0.0/4", "10.0.0.0/8"):
        network, error, need_confirm = check_target(text)
        assert network is None
        assert error
        assert need_confirm is False


def test_large_or_public_needs_confirm():
    _, _, wide = check_target("192.168.0.0/16")
    assert wide is True
    _, _, mid = check_target("192.168.1.0/23")
    assert mid is True
    _, _, public = check_target("8.8.8.0/24")
    assert public is True
