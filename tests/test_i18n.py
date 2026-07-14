"""Tests de l'internationalisation (cœur i18n, sans Qt)."""
import json

from argosnet.core import i18n


def teardown_function(_):
    # Évite que l'état global de langue ne fuite vers les autres tests.
    i18n.set_language("fr")


def test_default_is_french_passthrough():
    i18n.set_language("fr")
    assert i18n.get_language() == "fr"
    assert i18n.tr("Capture") == "Capture"
    assert i18n.tr("Quitter") == "Quitter"


def test_english_translation():
    i18n.set_language("en")
    assert i18n.tr("Quitter") == "Quit"
    assert i18n.tr("Carte") == "Map"


def test_templated_string():
    i18n.set_language("en")
    msg = i18n.tr("{count} interface(s) réseau détectée(s)").format(count=3)
    assert msg == "3 network interface(s) detected"


def test_unknown_key_falls_back():
    i18n.set_language("en")
    assert i18n.tr("chaîne inconnue xyz") == "chaîne inconnue xyz"


def test_unsupported_language_defaults_to_french():
    i18n.set_language("de")
    assert i18n.get_language() == "fr"


def test_save_and_load_roundtrip(tmp_path):
    path = str(tmp_path / "config.json")
    i18n.save_language("en", path)
    i18n.set_language("fr")
    assert i18n.load_language(path) == "en"
    data = json.loads((tmp_path / "config.json").read_text(encoding="utf-8"))
    assert data["language"] == "en"


def test_load_missing_file_defaults_french(tmp_path):
    assert i18n.load_language(str(tmp_path / "nope.json")) == "fr"
