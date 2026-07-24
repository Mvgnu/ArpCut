"""Centralized theme — one palette + one stylesheet for the whole UI.

Everything visual lives here: the frosted-glass color tokens, the accent colors
(macOS system palette), and the global Qt stylesheet driven by **role/tone
properties** rather than per-widget inline colors. That single source lets
``retheme()`` repaint the entire live widget tree on a light/dark switch — no
relaunch, no stranded captured colors.

``THEME`` is a proxy that always forwards to the *current* theme, so
``from gui.theme import THEME`` reads stay correct across a switch.
"""
from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtGui import QColor, QFont, QPalette


@dataclass(frozen=True)
class Theme:
    """Resolved design tokens. Colors are CSS strings for QSS; ``qcolor()``
    turns any token into a ``QColor`` for hand-painting."""

    name: str
    window: str
    window_rgba: tuple
    sheen: str
    surface: str
    surface_hover: str
    surface_active: str
    border: str
    border_strong: str
    text: str
    text_muted: str
    text_faint: str
    on_accent: str
    accent: str
    danger: str
    good: str
    warn: str
    purple: str
    accent_tint: str
    danger_tint: str
    good_tint: str
    warn_tint: str
    purple_tint: str
    shadow_rgba: tuple

    def qcolor(self, css: str) -> QColor:
        css = css.strip()
        if css.startswith('rgba'):
            r, g, b, a = (x.strip() for x in css[css.index('(') + 1:css.index(')')].split(','))
            return QColor(int(r), int(g), int(b), round(float(a) * 255))
        return QColor(css)


# Near-opaque bases: a hint of glass, but content stays readable over any wallpaper.
DARK = Theme(
    name='dark',
    window='rgba(24, 26, 34, 0.96)',
    window_rgba=(24, 26, 34, 245),
    sheen='rgba(255, 255, 255, 0.05)',
    surface='rgba(255, 255, 255, 0.055)',
    surface_hover='rgba(255, 255, 255, 0.09)',
    surface_active='rgba(255, 255, 255, 0.14)',
    border='rgba(255, 255, 255, 0.10)',
    border_strong='rgba(255, 255, 255, 0.18)',
    text='#F3F5F9',
    text_muted='#A2ABBB',
    text_faint='#6B7383',
    on_accent='#FFFFFF',
    accent='#0A84FF',
    danger='#FF453A',
    good='#32D74B',
    warn='#FF9F0A',
    purple='#BF5AF2',
    accent_tint='rgba(10, 132, 255, 0.20)',
    danger_tint='rgba(255, 69, 58, 0.20)',
    good_tint='rgba(50, 215, 75, 0.20)',
    warn_tint='rgba(255, 159, 10, 0.18)',
    purple_tint='rgba(191, 90, 242, 0.20)',
    shadow_rgba=(0, 0, 0, 160),
)

LIGHT = Theme(
    name='light',
    window='rgba(243, 244, 247, 0.975)',
    window_rgba=(243, 244, 247, 249),
    sheen='rgba(255, 255, 255, 0.65)',
    surface='rgba(0, 0, 0, 0.045)',
    surface_hover='rgba(0, 0, 0, 0.075)',
    surface_active='rgba(0, 0, 0, 0.11)',
    border='rgba(0, 0, 0, 0.11)',
    border_strong='rgba(0, 0, 0, 0.20)',
    text='#14161C',
    text_muted='#525B6A',
    text_faint='#828B99',
    on_accent='#FFFFFF',
    accent='#0071E3',
    danger='#D8332A',
    good='#1DA83E',
    warn='#B4740A',
    purple='#8E33C7',
    accent_tint='rgba(0, 113, 227, 0.14)',
    danger_tint='rgba(216, 51, 42, 0.14)',
    good_tint='rgba(29, 168, 62, 0.14)',
    warn_tint='rgba(180, 116, 10, 0.16)',
    purple_tint='rgba(142, 51, 199, 0.14)',
    shadow_rgba=(0, 0, 0, 55),
)


class _ActiveTheme:
    """Proxy forwarding every attribute to the *current* theme, so captured
    ``from gui.theme import THEME`` references stay live across a switch."""
    __slots__ = ()
    _current: Theme = DARK

    def __getattr__(self, name):
        return getattr(_ActiveTheme._current, name)


THEME = _ActiveTheme()


def set_theme(dark: bool) -> Theme:
    _ActiveTheme._current = DARK if dark else LIGHT
    return _ActiveTheme._current


def current() -> Theme:
    return _ActiveTheme._current


def font(size: int = 13, weight: int = QFont.Normal) -> QFont:
    f = QFont('SF Pro Text')
    if not f.exactMatch():
        f = QFont('.AppleSystemUIFont')
    f.setPointSize(size)
    f.setWeight(weight)  # type: ignore[arg-type]
    return f


def qss(t: Theme = None) -> str:
    """The single global stylesheet. All text/containers style by role/tone
    property, so a re-apply repaints everything."""
    t = t or current()
    return f"""
    * {{
        color: {t.text};
        font-family: "SF Pro Text", ".AppleSystemUIFont", "Helvetica Neue";
        font-size: 13px;
        outline: none;
    }}
    QWidget#GlassRoot, QWidget#GlassDialogRoot {{ background: transparent; }}
    QToolTip {{
        background: {t.qcolor(t.window).name()}; color: {t.text};
        border: 1px solid {t.border_strong}; border-radius: 6px; padding: 5px 8px;
    }}

    /* ---- text roles (theme-following, no inline colors) ---- */
    QLabel[role="title"]    {{ color: {t.text}; font-size: 14px; font-weight: 600; }}
    QLabel[role="subtitle"] {{ color: {t.text_muted}; font-size: 12px; }}
    QLabel[role="body"]     {{ color: {t.text}; }}
    QLabel[role="muted"]    {{ color: {t.text_muted}; }}
    QLabel[role="faint"]    {{ color: {t.text_faint}; }}
    QLabel[role="caption"]  {{ color: {t.text_muted}; font-size: 12px; }}
    QLabel[role="section"]  {{ color: {t.text_faint}; font-size: 11px; font-weight: 700; }}
    QLabel[role="value"]    {{ color: {t.text}; font-weight: 600; }}
    QLabel[role="tag"]      {{ color: {t.text_faint}; font-size: 10px; font-weight: 700; }}
    QLabel[role="titlebar"] {{ color: {t.text}; font-size: 13px; font-weight: 600; }}
    QLabel[role="hero"]     {{ color: {t.text}; font-size: 22px; font-weight: 700; }}
    QLabel[role="ok"]       {{ color: {t.good}; font-weight: 600; }}
    QLabel[role="bad"]      {{ color: {t.warn}; font-weight: 600; }}

    /* ---- status line (color by level) ---- */
    QLabel#StatusLine {{ color: {t.text_muted}; }}
    QLabel#StatusLine[level="danger"] {{ color: {t.danger}; }}
    QLabel#StatusLine[level="good"]   {{ color: {t.good}; }}
    QLabel#StatusLine[level="warn"]   {{ color: {t.warn}; }}
    QLabel#StatusLine[level="accent"] {{ color: {t.accent}; }}

    /* ---- panels / rows / separators ---- */
    QWidget[glass="panel"] {{
        background: {t.surface}; border: 1px solid {t.border}; border-radius: 12px;
    }}
    QFrame[role="hline"] {{ background: {t.border}; border: none; max-height: 1px; min-height: 1px; }}
    QFrame#DeviceRow {{
        background: {t.surface}; border: 1px solid {t.border}; border-radius: 12px;
    }}
    QFrame#DeviceRow:hover {{ background: {t.surface_hover}; }}
    QFrame#DeviceRow[selected="true"] {{ background: {t.accent_tint}; border: 1px solid {t.accent}; }}

    /* ---- banner (info/warn/danger tone) ---- */
    QFrame#Banner[tone="warn"]   {{ background: {t.warn_tint}; border: 1px solid {t.warn}; border-radius: 12px; }}
    QFrame#Banner[tone="danger"] {{ background: {t.danger_tint}; border: 1px solid {t.danger}; border-radius: 12px; }}
    QFrame#Banner[tone="good"]   {{ background: {t.good_tint}; border: 1px solid {t.good}; border-radius: 12px; }}
    QFrame#Banner QLabel[role="banner"] {{ color: {t.text}; font-weight: 600; }}
    QFrame#Banner QLabel[role="bannerIcon"] {{ background: transparent; }}

    /* ---- chips (tone-tinted badges) ---- */
    QLabel[chip="danger"] {{ background: {t.danger_tint}; color: {t.danger}; }}
    QLabel[chip="warn"]   {{ background: {t.warn_tint}; color: {t.warn}; }}
    QLabel[chip="good"]   {{ background: {t.good_tint}; color: {t.good}; }}
    QLabel[chip="accent"] {{ background: {t.accent_tint}; color: {t.accent}; }}
    QLabel[chip="purple"] {{ background: {t.purple_tint}; color: {t.purple}; }}
    QLabel[chip] {{ border-radius: 6px; padding: 2px 7px; font-size: 10px; font-weight: 700; }}

    /* ---- segmented control ---- */
    QFrame[seg="true"] {{ background: {t.surface}; border: 1px solid {t.border}; border-radius: 9px; }}
    QFrame[seg="true"] QPushButton {{
        background: transparent; border: none; border-radius: 7px; padding: 6px 12px; color: {t.text_muted};
    }}
    QFrame[seg="true"] QPushButton:checked {{ background: {t.surface_active}; color: {t.text}; font-weight: 600; }}

    /* ---- scrollbars ---- */
    QScrollArea, QScrollArea > QWidget > QWidget {{ background: transparent; border: none; }}
    QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
    QScrollBar::handle:vertical {{ background: {t.border_strong}; border-radius: 5px; min-height: 32px; }}
    QScrollBar::handle:vertical:hover {{ background: {t.text_faint}; }}
    QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; }}
    QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}
    QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
    QScrollBar::handle:horizontal {{ background: {t.border_strong}; border-radius: 5px; min-width: 32px; }}

    /* ---- buttons ---- */
    QPushButton {{
        background: {t.surface}; border: 1px solid {t.border}; border-radius: 8px;
        padding: 7px 14px; color: {t.text};
    }}
    QPushButton:hover {{ background: {t.surface_hover}; border-color: {t.border_strong}; }}
    QPushButton:pressed {{ background: {t.surface_active}; }}
    QPushButton:disabled {{ color: {t.text_faint}; background: transparent; border-color: {t.border}; }}
    QPushButton[accent="primary"] {{ background: {t.accent}; border: none; color: {t.on_accent}; font-weight: 600; }}
    QPushButton[accent="danger"]  {{ background: {t.danger}; border: none; color: {t.on_accent}; font-weight: 600; }}
    QPushButton[accent="good"]    {{ background: {t.good}; border: none; color: {t.on_accent}; font-weight: 600; }}

    /* ---- progress ---- */
    QProgressBar#ScanBar {{ background: transparent; border: none; }}
    QProgressBar#ScanBar::chunk {{ background: {t.accent}; border-radius: 2px; }}

    /* ---- inputs ---- */
    QLineEdit, QSpinBox, QComboBox {{
        background: {t.surface}; border: 1px solid {t.border}; border-radius: 8px;
        padding: 6px 10px; selection-background-color: {t.accent}; selection-color: {t.on_accent};
    }}
    QLineEdit:focus, QSpinBox:focus, QComboBox:focus {{ border-color: {t.accent}; }}
    QComboBox::drop-down {{ border: none; width: 22px; }}
    QComboBox QAbstractItemView {{
        background: {t.qcolor(t.window).name()}; border: 1px solid {t.border_strong};
        border-radius: 8px; selection-background-color: {t.accent_tint}; padding: 4px;
    }}
    QSpinBox::up-button, QSpinBox::down-button {{ width: 0; height: 0; }}

    QCheckBox {{ spacing: 8px; background: transparent; }}
    QCheckBox::indicator {{
        width: 18px; height: 18px; border-radius: 6px;
        border: 1px solid {t.border_strong}; background: {t.surface};
    }}
    QCheckBox::indicator:checked {{ background: {t.accent}; border-color: {t.accent}; }}

    /* ---- tables ---- */
    QTableWidget, QTableView, QTreeWidget, QListWidget {{
        background: transparent; border: none; gridline-color: {t.border};
        selection-background-color: {t.accent_tint}; selection-color: {t.text};
        color: {t.text};
    }}
    QHeaderView {{ background: transparent; }}
    QHeaderView::section {{
        background: {t.surface}; color: {t.text_muted}; border: none;
        border-bottom: 1px solid {t.border}; padding: 6px 8px; font-weight: 600;
    }}
    QTableCornerButton::section {{ background: {t.surface}; border: none; }}
    QTableWidget::item, QTreeWidget::item {{ padding: 4px 6px; }}
    QLabel {{ background: transparent; }}
    """


def apply(app, dark: bool = True) -> Theme:
    """Set the active theme and paint it across the whole application."""
    t = set_theme(dark)
    app.setFont(font(13))
    app.setStyleSheet(qss(t))
    pal = QPalette()
    pal.setColor(QPalette.Window, t.qcolor(t.window))
    pal.setColor(QPalette.WindowText, t.qcolor(t.text))
    pal.setColor(QPalette.Text, t.qcolor(t.text))
    pal.setColor(QPalette.Base, t.qcolor(t.surface))
    pal.setColor(QPalette.Highlight, t.qcolor(t.accent))
    pal.setColor(QPalette.HighlightedText, t.qcolor(t.on_accent))
    app.setPalette(pal)
    return t


def retheme(app, dark: bool) -> Theme:
    """Switch theme and repaint the entire live widget tree — no relaunch.

    Re-applies the global QSS, then walks every widget: re-polishes it (so
    ``[role]`` / ``[tone]`` / ``[selected]`` selectors re-evaluate), calls its
    optional ``on_theme_changed`` hook (for icon recolors), and repaints it (for
    custom-painted glass/badges/toggles that read ``THEME`` live)."""
    t = apply(app, dark)
    for w in app.allWidgets():
        style = w.style()
        style.unpolish(w)
        style.polish(w)
        hook = getattr(w, 'on_theme_changed', None)
        if callable(hook):
            try:
                hook()
            except Exception:  # noqa: BLE001 — never let one widget break the walk
                pass
        w.update()
    return t
