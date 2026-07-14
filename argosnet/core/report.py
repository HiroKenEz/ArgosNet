"""Génération d'un rapport HTML autonome (résumé, protocoles, talkers, alertes, appareils)."""
from __future__ import annotations

import html
import time

_CSS = """
body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; color: #222; }
h1 { margin-bottom: 0; }
p.meta { color: #888; margin-top: 4px; }
h2 { border-bottom: 2px solid #3b7dd8; padding-bottom: 4px; margin-top: 28px; }
table { border-collapse: collapse; width: 100%; margin-top: 8px; }
th, td { border: 1px solid #ddd; padding: 6px 10px; text-align: left; font-size: 14px; }
th { background: #f2f5fa; }
table.kv th { width: 220px; }
"""


def _human_bytes(num: float) -> str:
    for unit in ("o", "Ko", "Mo", "Go"):
        if num < 1024 or unit == "Go":
            return f"{num:.0f} {unit}" if unit == "o" else f"{num:.1f} {unit}"
        num /= 1024
    return f"{num:.1f} Go"


def build_html_report(*, summary, top_talkers, conversations, alerts, devices) -> str:
    esc = html.escape
    total = summary.get("total_packets", 0)
    out: list[str] = [
        "<!doctype html><html lang='fr'><head><meta charset='utf-8'>",
        "<title>Rapport ArgosNet</title><style>", _CSS, "</style></head><body>",
        "<h1>Rapport ArgosNet</h1>",
        f"<p class='meta'>Généré le {time.strftime('%Y-%m-%d %H:%M:%S')}</p>",
        "<h2>Résumé</h2><table class='kv'>",
        f"<tr><th>Paquets</th><td>{total}</td></tr>",
        f"<tr><th>Volume total</th><td>{_human_bytes(summary.get('total_bytes', 0))}</td></tr>",
        f"<tr><th>Durée</th><td>{summary.get('duration', 0)} s</td></tr>",
        f"<tr><th>Débit moyen</th><td>{summary.get('avg_pps', 0):.1f} paquets/s</td></tr>",
        f"<tr><th>Hôtes distincts</th><td>{summary.get('distinct_talkers', 0)}</td></tr>",
        f"<tr><th>Conversations</th><td>{summary.get('distinct_conversations', 0)}</td></tr>",
        "</table>",
        "<h2>Protocoles</h2><table><tr><th>Protocole</th><th>Paquets</th><th>Part</th></tr>",
    ]
    for name, count in summary.get("protocols", []):
        pct = 100 * count / total if total else 0
        out.append(f"<tr><td>{esc(name)}</td><td>{count}</td><td>{pct:.1f} %</td></tr>")
    out.append("</table>")

    out.append("<h2>Top talkers</h2><table><tr><th>Adresse</th><th>Paquets</th><th>Volume</th></tr>")
    for talker in top_talkers:
        out.append(
            f"<tr><td>{esc(talker.address)}</td><td>{talker.packets}</td>"
            f"<td>{_human_bytes(talker.bytes)}</td></tr>"
        )
    out.append("</table>")

    out.append(
        "<h2>Conversations</h2><table>"
        "<tr><th>Hôte A</th><th>Hôte B</th><th>Paquets</th><th>Volume</th></tr>"
    )
    for a, b, packets, byte_count in conversations:
        out.append(
            f"<tr><td>{esc(a)}</td><td>{esc(b)}</td><td>{packets}</td>"
            f"<td>{_human_bytes(byte_count)}</td></tr>"
        )
    out.append("</table>")

    out.append(
        f"<h2>Alertes ({len(alerts)})</h2><table>"
        "<tr><th>Heure</th><th>Gravité</th><th>Catégorie</th><th>Source</th><th>Détail</th></tr>"
    )
    for alert in alerts:
        when = time.strftime("%H:%M:%S", time.localtime(alert.timestamp)) if alert.timestamp else ""
        out.append(
            f"<tr style='background:{alert.severity.color}'>"
            f"<td>{when}</td><td>{alert.severity.label}</td><td>{esc(alert.category)}</td>"
            f"<td>{esc(alert.source)}</td><td>{esc(alert.detail)}</td></tr>"
        )
    out.append("</table>")

    if devices:
        out.append(
            "<h2>Appareils</h2><table>"
            "<tr><th>MAC</th><th>IP</th><th>Constructeur</th><th>Nom d'hôte</th><th>Libellé</th></tr>"
        )
        for dev in devices:
            out.append(
                f"<tr><td>{esc(dev.get('mac', ''))}</td><td>{esc(dev.get('ip') or '')}</td>"
                f"<td>{esc(dev.get('vendor') or '')}</td><td>{esc(dev.get('hostname') or '')}</td>"
                f"<td>{esc(dev.get('label') or '')}</td></tr>"
            )
        out.append("</table>")

    out.append("</body></html>")
    return "\n".join(out)
