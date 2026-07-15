"""Génère l'icône d'ArgosNet : ``argosnet/resources/argosnet.ico`` (+ ``docs/icon.png``).

Le motif — un œil stylisé sur fond dégradé, clin d'œil à **Argos Panoptès**, le
gardien aux cent yeux — est dessiné vectoriellement avec Qt à chaque taille (net même
en 16 px). Les images sont ensuite empaquetées dans un conteneur ``.ico`` (payloads PNG,
compatibles Windows Vista+). Exécuter une fois pour régénérer l'asset :

    python tools/make_icon.py
"""
from __future__ import annotations

import os
import struct
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QBuffer, QPointF, QRectF, Qt
from PySide6.QtGui import (
    QBrush,
    QColor,
    QImage,
    QLinearGradient,
    QPainter,
    QPen,
    QRadialGradient,
)

SIZES = [16, 24, 32, 48, 64, 128, 256]
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _draw(painter: QPainter, s: float) -> None:
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

    # Fond arrondi, dégradé bleu nuit → sarcelle (accent de l'app : #3b7dd8).
    bg = QLinearGradient(0, 0, 0, s)
    bg.setColorAt(0.0, QColor("#12233f"))
    bg.setColorAt(1.0, QColor("#0c3b46"))
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(QBrush(bg))
    radius = 0.20 * s
    painter.drawRoundedRect(QRectF(0, 0, s, s), radius, radius)

    cx, cy = 0.5 * s, 0.5 * s

    # Anneau « radar » discret autour de l'œil.
    ring = QPen(QColor(59, 125, 216, 90))
    ring.setWidthF(max(1.0, 0.02 * s))
    painter.setPen(ring)
    painter.setBrush(Qt.BrushStyle.NoBrush)
    painter.drawEllipse(QPointF(cx, cy), 0.40 * s, 0.40 * s)

    # Blanc de l'œil (amande).
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(QColor("#eef4fb"))
    eye = QRectF(cx - 0.34 * s, cy - 0.22 * s, 0.68 * s, 0.44 * s)
    painter.drawEllipse(eye)

    # Iris (dégradé radial bleu).
    iris = QRadialGradient(QPointF(cx, cy), 0.20 * s)
    iris.setColorAt(0.0, QColor("#5aa0f2"))
    iris.setColorAt(1.0, QColor("#2f6fd0"))
    painter.setBrush(QBrush(iris))
    painter.drawEllipse(QPointF(cx, cy), 0.185 * s, 0.185 * s)

    # Pupille + reflet.
    painter.setBrush(QColor("#0b1830"))
    painter.drawEllipse(QPointF(cx, cy), 0.085 * s, 0.085 * s)
    painter.setBrush(QColor(255, 255, 255, 230))
    painter.drawEllipse(QPointF(cx - 0.055 * s, cy - 0.055 * s), 0.030 * s, 0.030 * s)


def _png_bytes(size: int) -> bytes:
    img = QImage(size, size, QImage.Format.Format_ARGB32)
    img.fill(Qt.GlobalColor.transparent)
    painter = QPainter(img)
    _draw(painter, float(size))
    painter.end()

    buffer = QBuffer()
    buffer.open(QBuffer.OpenModeFlag.ReadWrite)
    img.save(buffer, "PNG")
    payload = bytes(buffer.data())
    buffer.close()
    return payload


def _build_ico(pngs: list[tuple[int, bytes]], out_path: str) -> None:
    count = len(pngs)
    header = struct.pack("<HHH", 0, 1, count)  # réservé, type=1 (icône), nombre d'images
    offset = 6 + count * 16
    entries = b""
    data = b""
    for size, png in pngs:
        dim = 0 if size >= 256 else size  # 0 code « 256 » dans le format ICO
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(png), offset)
        data += png
        offset += len(png)
    with open(out_path, "wb") as handle:
        handle.write(header + entries + data)


def main() -> int:
    from PySide6.QtWidgets import QApplication

    QApplication(sys.argv[:1])
    pngs = [(size, _png_bytes(size)) for size in SIZES]

    res_dir = os.path.join(ROOT, "argosnet", "resources")
    docs_dir = os.path.join(ROOT, "docs")
    os.makedirs(res_dir, exist_ok=True)
    os.makedirs(docs_dir, exist_ok=True)

    ico_path = os.path.join(res_dir, "argosnet.ico")
    _build_ico(pngs, ico_path)
    with open(os.path.join(docs_dir, "icon.png"), "wb") as handle:
        handle.write(dict(pngs)[256])

    print("Icône générée :", ico_path, f"({os.path.getsize(ico_path)} o, {len(SIZES)} tailles)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
