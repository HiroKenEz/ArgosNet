"""Test du service d'interfaces (mise en cache + copie défensive)."""
from argosnet.core.interfaces import list_interfaces


def test_returns_a_defensive_copy():
    a = list_interfaces()
    b = list_interfaces()
    assert isinstance(a, list)
    # Chaque appel renvoie une copie : trier/muter l'une n'affecte pas le cache.
    assert a is not b
