"""Tests de la résolution constructeur (base OUI, best-effort)."""
from argosnet.core import oui


def teardown_function(_):
    # Réinitialise l'état global du module entre les tests.
    oui._unavailable = False
    oui._lookup = None


def test_empty_mac_returns_empty():
    assert oui.lookup_vendor("") == ""


def test_short_circuit_when_unavailable():
    # Une fois la base marquée indisponible, on ne retente rien : retour immédiat.
    oui._unavailable = True
    assert oui.lookup_vendor("aa:bb:cc:dd:ee:ff") == ""


def test_lookup_never_raises():
    # Quel que soit l'état de la base (présente, absente, biblio manquante),
    # lookup_vendor renvoie toujours une chaîne sans lever d'exception.
    result = oui.lookup_vendor("aa:bb:cc:dd:ee:ff")
    assert isinstance(result, str)


def test_lookup_without_cache_makes_no_network_call(monkeypatch):
    # Sans base locale : "" immédiat, sans appel à update_vendors (#13).
    import sys
    from types import SimpleNamespace

    calls: list = []

    class FakeLookup:
        def find_vendors_list(self):
            return None  # pas de base locale

        def update_vendors(self):
            calls.append("update")
            raise AssertionError("aucun accès réseau implicite")

        def lookup(self, mac):
            calls.append("lookup")
            return "X"

    monkeypatch.setitem(
        sys.modules, "mac_vendor_lookup", SimpleNamespace(MacLookup=FakeLookup)
    )
    assert oui.lookup_vendor("aa:bb:cc:dd:ee:ff") == ""
    assert calls == []
