"""Filtre d'affichage léger (sur les paquets déjà disséqués).

Grammaire volontairement simple et tolérante :

* terme nu           → nom de protocole, ou sous-chaîne dans source/destination/info
  (``dns``, ``192.168``, ``443``)
* ``champ op valeur`` → ``op`` ∈ ``==``, ``=``, ``!=``
  champs pris en charge : ``ip.addr``, ``ip.src``, ``ip.dst``,
  ``tcp.port``, ``udp.port``, ``port``, ``proto`` / ``protocol``
* plusieurs conditions séparées par ``and`` sont combinées (ET logique)

Retourne un prédicat ``callable(record) -> bool`` réutilisable par le proxy Qt.
"""
from __future__ import annotations

import re
from typing import Callable

# Un « record » est un argosnet.ui.packet_model.PacketRecord, mais on ne l'importe
# pas ici pour éviter une dépendance de la logique cœur vers l'UI.
Predicate = Callable[[object], bool]

_FIELD_RE = re.compile(
    r"^(ip\.addr|ip\.src|ip\.dst|tcp\.port|udp\.port|port|proto|protocol)"
    r"\s*(==|=|!=)\s*(.+)$"
)


def compile_filter(expr: str) -> Predicate:
    """Compile une expression de filtre en prédicat."""
    expr = (expr or "").strip()
    if not expr:
        return lambda record: True

    parts = re.split(r"\s+and\s+", expr, flags=re.IGNORECASE)
    predicates = [_compile_single(part.strip()) for part in parts if part.strip()]
    if not predicates:
        return lambda record: True
    if len(predicates) == 1:
        return predicates[0]
    return lambda record: all(pred(record) for pred in predicates)


def _compile_single(term: str) -> Predicate:
    match = _FIELD_RE.match(term.lower())
    if match:
        field, op, value = match.group(1), match.group(2), match.group(3).strip()
        negate = op == "!="

        def field_pred(record, field=field, value=value, negate=negate):
            result = _eval_field(record, field, value)
            return (not result) if negate else result

        return field_pred

    # Terme nu : protocole exact, ou sous-chaîne dans les adresses / l'info.
    needle = term.lower()

    def bare_pred(record, needle=needle):
        s = record.summary
        return (
            needle == s.protocol.lower()
            or needle in s.src.lower()
            or needle in s.dst.lower()
            or needle in s.info.lower()
        )

    return bare_pred


def _eval_field(record, field: str, value: str) -> bool:
    s = record.summary
    if field in ("proto", "protocol"):
        return s.protocol.lower() == value
    if field == "ip.addr":
        return value in s.src.lower() or value in s.dst.lower()
    if field == "ip.src":
        return value in s.src.lower()
    if field == "ip.dst":
        return value in s.dst.lower()
    if field in ("tcp.port", "udp.port", "port"):
        return _matches_port(record, field, value)
    return False


def _matches_port(record, field: str, value: str) -> bool:
    try:
        from scapy.layers.inet import TCP, UDP
    except Exception:
        return False
    layers = []
    if field in ("tcp.port", "port"):
        layers.append(TCP)
    if field in ("udp.port", "port"):
        layers.append(UDP)
    pkt = record.packet
    for layer_cls in layers:
        if pkt.haslayer(layer_cls):
            layer = pkt.getlayer(layer_cls)
            if str(layer.sport) == value or str(layer.dport) == value:
                return True
    return False
