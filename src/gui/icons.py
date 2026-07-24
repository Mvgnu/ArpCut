"""SVG icon set — crisp, modern line icons rendered to theme-colored pixmaps.

Replaces the old base64 PNG blobs in ``assets.py``. Every icon is a small SVG
body (24x24 viewBox, stroke-based) recolored on demand and rendered at any size
at full device-pixel resolution, so they stay sharp on Retina and adapt to the
active theme. ``app_logo()`` builds a bespoke ArpCut mark.
"""
from __future__ import annotations

from functools import lru_cache

from PySide6.QtCore import QRectF, Qt, QSize
from PySide6.QtGui import QIcon, QImage, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer

# Feather-style stroke bodies (no <svg> wrapper, no color — injected below).
_BODIES: dict[str, str] = {
    'scan':      '<circle cx="12" cy="12" r="2"/><path d="M16.24 7.76a6 6 0 0 1 0 8.49m-8.48 0a6 6 0 0 1 0-8.49m11.31-2.82a10 10 0 0 1 0 14.14m-14.14 0a10 10 0 0 1 0-14.14"/>',
    'deepscan':  '<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/>',
    'cut':       '<path d="M18.36 6.64a9 9 0 1 1-12.73 0"/><line x1="12" y1="2" x2="12" y2="12"/>',
    'restore':   '<polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/>',
    'killall':   '<polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>',
    'lag':       '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>',
    'full':      '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    'oneway':    '<circle cx="12" cy="12" r="10"/><polyline points="12 8 16 12 12 16"/><line x1="8" y1="12" x2="16" y2="12"/>',
    'port':      '<line x1="4" y1="9" x2="20" y2="9"/><line x1="4" y1="15" x2="20" y2="15"/><line x1="10" y1="3" x2="8" y2="21"/><line x1="16" y1="3" x2="14" y2="21"/>',
    'host':      '<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
    'traffic':   '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>',
    'settings':  '<line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/><line x1="1" y1="14" x2="7" y2="14"/><line x1="9" y1="8" x2="15" y2="8"/><line x1="17" y1="16" x2="23" y2="16"/>',
    'info':      '<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>',
    'search':    '<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>',
    'copy':      '<rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',
    'close':     '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>',
    'minus':     '<line x1="5" y1="12" x2="19" y2="12"/>',
    'plus':      '<line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>',
    'chevron-right': '<polyline points="9 18 15 12 9 6"/>',
    'chevron-down':  '<polyline points="6 9 12 15 18 9"/>',
    'router':    '<rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/>',
    'monitor':   '<rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>',
    'device':    '<rect x="5" y="2" width="14" height="20" rx="2" ry="2"/><line x1="12" y1="18" x2="12.01" y2="18"/>',
    'more':      '<circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/><circle cx="5" cy="12" r="1"/>',
    'refresh':   '<polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>',
    'moon':      '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>',
    'sun':       '<circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>',
    'wifi':      '<path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/>',
    'lock':      '<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
    'alert':     '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
    'check':     '<polyline points="20 6 9 17 4 12"/>',
    'shield-check': '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/>',
    'globe-lock': '<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
    'external':  '<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/>',
    'github':    '<path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"/>',
}

_STROKE_W: dict[str, float] = {'more': 3.0}  # dots need a fatter stroke


@lru_cache(maxsize=512)
def _render(name: str, color: str, size: int, ratio: int, stroke: float) -> QPixmap:
    body = _BODIES.get(name, _BODIES['device'])
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" '
        f'fill="none" stroke="{color}" stroke-width="{stroke}" '
        f'stroke-linecap="round" stroke-linejoin="round">{body}</svg>'
    ).encode()
    r = QSvgRenderer(svg)
    img = QImage(size * ratio, size * ratio, QImage.Format_ARGB32)
    img.fill(Qt.transparent)
    img.setDevicePixelRatio(ratio)
    p = QPainter(img)
    p.setRenderHint(QPainter.Antialiasing)
    r.render(p, QRectF(0, 0, size, size))
    p.end()
    return QPixmap.fromImage(img)


def pixmap(name: str, color: str, size: int = 20, stroke: float = None) -> QPixmap:
    stroke = stroke if stroke is not None else _STROKE_W.get(name, 2.0)
    return _render(name, color, size, 2, stroke)


def icon(name: str, color: str, size: int = 20, stroke: float = None) -> QIcon:
    ic = QIcon()
    ic.addPixmap(pixmap(name, color, size, stroke))
    return ic


def app_logo(size: int = 128) -> QPixmap:
    """Bespoke ArpCut mark: a network node with a severed link, on a rounded tile."""
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128">
      <defs>
        <linearGradient id="bg" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stop-color="#2A2E3C"/><stop offset="1" stop-color="#14161E"/>
        </linearGradient>
        <linearGradient id="ac" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stop-color="#0A84FF"/><stop offset="1" stop-color="#5AC8FA"/>
        </linearGradient>
      </defs>
      <rect x="6" y="6" width="116" height="116" rx="28" fill="url(#bg)"/>
      <rect x="6.5" y="6.5" width="115" height="115" rx="27.5" fill="none" stroke="#FFFFFF" stroke-opacity="0.10"/>
      <g fill="none" stroke="url(#ac)" stroke-width="6" stroke-linecap="round">
        <path d="M40 44 L58 60"/>
        <path d="M70 68 L88 84"/>
      </g>
      <g fill="none" stroke="#FF453A" stroke-width="6" stroke-linecap="round">
        <path d="M76 46 L60 62"/><path d="M52 70 L68 54" stroke-opacity="0"/>
      </g>
      <circle cx="36" cy="40" r="10" fill="url(#ac)"/>
      <circle cx="92" cy="88" r="10" fill="url(#ac)"/>
      <circle cx="64" cy="64" r="7" fill="#FF453A"/>
    </svg>'''.encode()
    r = QSvgRenderer(svg)
    img = QImage(size, size, QImage.Format_ARGB32)
    img.fill(Qt.transparent)
    p = QPainter(img)
    p.setRenderHint(QPainter.Antialiasing)
    r.render(p, QRectF(0, 0, size, size))
    p.end()
    return QPixmap.fromImage(img)


def app_icon(size: int = 128) -> QIcon:
    ic = QIcon()
    ic.addPixmap(app_logo(size))
    return ic


def device_glyph(dev_type: str) -> str:
    return {'Me': 'monitor', 'Router': 'router'}.get(dev_type, 'device')
