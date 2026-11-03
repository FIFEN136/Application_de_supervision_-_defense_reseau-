"""
Procus Secure — Feuille de style Qt
Style « noir et or » : fond noir chaud uni, accents dorés, texte blanc (contraste ≥ 15:1), police Public Sans
(licence SIL OFL, fournie dans assets/fonts). Si les fichiers de la police Marianne sont déposés dans assets/fonts par
une administration autorisée à l'utiliser, elle est utilisée en priorité.

Palette :
  BG_MAIN    #0E0E0C   fond principal (noir chaud)
  BG_SIDEBAR #080807   barre latérale
  BG_CARD    #1B1A15   cartes / panneaux
  BG_ROW     #14130F   lignes alternées tableau
  BG_INPUT   #12110E   champs de saisie
  BORDER     #3A3524   séparateurs (or sombre)
  ACCENT     #D4AF37   or
  CYAN       #E6C766   or clair (liens, puces actives)
  GREEN      #27AE60   en ligne
  RED        #ef5b4b   hors ligne / critique
  TEXT_PRI   #FFFFFF   texte principal
  TEXT_SEC   #D6D1C4   texte secondaire (lisible)
"""

import os


def preferred_family() -> str:
    """Marianne si ses fichiers ont été fournis, sinon Public Sans."""
    from PyQt6.QtGui import QFontDatabase
    return "Marianne" if "Marianne" in set(QFontDatabase.families()) else "Public Sans"


def load_fonts() -> list[str]:
    """Charge toutes les polices .ttf/.otf de assets/fonts. À appeler une fois, après la création de QApplication."""
    from PyQt6.QtGui import QFontDatabase
    folder = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "assets", "fonts")
    loaded = []
    if os.path.isdir(folder):
        for name in sorted(os.listdir(folder)):
            if name.lower().endswith((".ttf", ".otf")) and QFontDatabase.addApplicationFont(os.path.join(folder, name)) >= 0:
                loaded.append(name)
    return loaded


COLOR = {
    "bg_main":    "#0e0e0c",
    "bg_sidebar": "#080807",
    "bg_card":    "#1b1a15",
    "bg_row":     "#14130f",
    "bg_input":   "#12110e",
    "border":     "#3a3524",
    "accent":     "#d4af37",
    "cyan":       "#e6c766",
    "green":      "#27AE60",
    "red":        "#ef5b4b",
    "yellow":     "#D4AC0D",
    "purple":     "#8E44AD",
    "text_pri":   "#ffffff",
    "text_sec":   "#d6d1c4",
    "hover":      "#2a2515",
}

def alpha(color: str, hex_alpha: str | int) -> str:
    """'#RRGGBB' + alpha (hex '22' ou 0-255) → 'rgba(r,g,b,a)'.
    Qt lit '#RRGGBBAA' comme '#AARRGGBB' : ne jamais suffixer l'alpha à une couleur hex."""
    a = int(hex_alpha, 16) if isinstance(hex_alpha, str) else int(hex_alpha)
    c = color.lstrip("#")
    return f"rgba({int(c[0:2], 16)}, {int(c[2:4], 16)}, {int(c[4:6], 16)}, {a / 255:.2f})"


SEVERITY_COLORS = {
    "disaster":    "#8E44AD",
    "high":        "#ef5b4b",
    "average":     "#F08A24",
    "warning":     "#D4AC0D",
    "information": "#e6c766",
    "resolved":    "#27AE60",
}

STATUS_COLORS = {
    "online":      "#27AE60",
    "offline":     "#ef5b4b",
    "unreachable": "#F08A24",
    "unknown":     "#d6d1c4",
}

MAIN_QSS = """
/* ── Globals ── */
QWidget {
    background-color: #0e0e0c;
    color: #ffffff;
    font-family: "Marianne", "Public Sans", "Segoe UI", sans-serif;
    font-size: 9pt;
}

QLabel { background: transparent; }

QMainWindow { background-color: #0e0e0c; }

/* ── Scrollbars ── */
QScrollBar:vertical {
    background: #080807;
    width: 7px;
    margin: 0;
}
QScrollBar::handle:vertical {
    background: #3a3524;
    border-radius: 3px;
    min-height: 24px;
}
QScrollBar::handle:vertical:hover { background: #5a4f2e; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }

QScrollBar:horizontal {
    background: #080807;
    height: 7px;
}
QScrollBar::handle:horizontal {
    background: #3a3524;
    border-radius: 3px;
}
QScrollBar::handle:horizontal:hover { background: #5a4f2e; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }

/* ── Tables ── */
QTableWidget, QTableView {
    background-color: #1b1a15;
    border: 1px solid #3a3524;
    border-radius: 4px;
    gridline-color: #3a3524;
    selection-background-color: #2a2515;
    alternate-background-color: #14130f;
    outline: none;
}
QTableWidget::item, QTableView::item {
    padding: 4px 8px;
    border: none;
}
QTableWidget::item:selected, QTableView::item:selected {
    background-color: #2a2515;
    color: #ffffff;
}
QHeaderView::section {
    background-color: #080807;
    color: #d6d1c4;
    padding: 5px 10px;
    border: none;
    border-right: 1px solid #3a3524;
    border-bottom: 2px solid #d4af37;
    font-weight: 700;
    font-size: 8pt;
    letter-spacing: 0.3px;
}

/* ── Boutons ── */
QPushButton {
    background-color: #1b1a15;
    color: #ffffff;
    border: 1px solid #3a3524;
    border-radius: 3px;
    padding: 4px 12px;
    font-weight: 500;
}
QPushButton:hover {
    background-color: #2a2515;
    border-color: #5a4f2e;
}
QPushButton:pressed { background-color: #080807; }
QPushButton:disabled {
    color: #5a4f2e;
    background-color: #0e0e0c;
    border-color: #3a3524;
}

QPushButton#btn_primary {
    background-color: #d4af37;
    color: #ffffff;
    border: none;
    font-weight: 700;
}
QPushButton#btn_primary:hover { background-color: #b8962e; }
QPushButton#btn_primary:pressed { background-color: #9a7b24; }

QPushButton#btn_danger {
    background-color: transparent;
    color: #ef5b4b;
    border: 1px solid #ef5b4b;
    border-radius: 3px;
}
QPushButton#btn_danger:hover { background-color: #ef5b4b; color: #fff; }

QPushButton#btn_success {
    background-color: transparent;
    color: #27AE60;
    border: 1px solid #27AE60;
    border-radius: 3px;
}
QPushButton#btn_success:hover { background-color: #27AE60; color: #0e0e0c; }

/* ── Inputs ── */
QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox, QDoubleSpinBox, QComboBox {
    background-color: #12110e;
    border: 1px solid #3a3524;
    border-radius: 3px;
    color: #ffffff;
    padding: 4px 8px;
    selection-background-color: #d4af37;
    selection-color: #ffffff;
}
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus,
QSpinBox:focus, QComboBox:focus {
    border-color: #d4af37;
}

QComboBox::drop-down { border: none; width: 18px; }
QComboBox::down-arrow {
    image: none;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 5px solid #d6d1c4;
    margin-right: 6px;
}
QComboBox QAbstractItemView {
    background-color: #12110e;
    border: 1px solid #3a3524;
    selection-background-color: #2a2515;
    outline: none;
}

/* ── Labels ── */
QLabel { background: transparent; }

/* ── Group box ── */
QGroupBox {
    background-color: #1b1a15;
    border: 1px solid #3a3524;
    border-radius: 4px;
    margin-top: 12px;
    padding: 10px;
    font-weight: 700;
    color: #d6d1c4;
    font-size: 8pt;
    letter-spacing: 0.5px;
}
QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 10px;
    top: -6px;
    padding: 0 4px;
    background-color: #1b1a15;
}

/* ── Tabs ── */
QTabWidget::pane {
    background-color: #1b1a15;
    border: 1px solid #3a3524;
    border-top: none;
    border-radius: 0 0 4px 4px;
}
QTabBar::tab {
    background-color: #080807;
    color: #d6d1c4;
    padding: 7px 18px;
    border: 1px solid #3a3524;
    border-bottom: none;
    margin-right: 2px;
    border-radius: 3px 3px 0 0;
    font-size: 8pt;
}
QTabBar::tab:selected {
    background-color: #1b1a15;
    color: #ffffff;
    border-bottom: 2px solid #d4af37;
}
QTabBar::tab:hover:!selected { background-color: #14130f; }

/* ── Progress bars ── */
QProgressBar {
    background-color: #3a3524;
    border: none;
    border-radius: 3px;
    height: 7px;
    text-align: center;
    font-size: 7pt;
    color: transparent;
}
QProgressBar::chunk { background-color: #27AE60; border-radius: 3px; }
QProgressBar[value_critical="true"]::chunk { background-color: #ef5b4b; }
QProgressBar[value_warning="true"]::chunk  { background-color: #d4af37; }

/* ── Checkboxes ── */
QCheckBox { spacing: 8px; color: #ffffff; }
QCheckBox::indicator {
    width: 14px; height: 14px;
    border-radius: 2px;
    border: 1px solid #3a3524;
    background-color: #12110e;
}
QCheckBox::indicator:checked { background-color: #d4af37; border-color: #d4af37; }

/* ── Splitter ── */
QSplitter::handle { background-color: #3a3524; }
QSplitter::handle:horizontal { width: 1px; }
QSplitter::handle:vertical   { height: 1px; }

/* ── Status bar ── */
QStatusBar {
    background-color: #080807;
    color: #d6d1c4;
    border-top: 1px solid #3a3524;
    font-size: 8pt;
}

/* ── Tool tips ── */
QToolTip {
    background-color: #1b1a15;
    color: #ffffff;
    border: 1px solid #3a3524;
    border-radius: 3px;
    padding: 4px 8px;
    font-size: 8pt;
}

/* ── Dialog ── */
QDialog { background-color: #0e0e0c; }
QDialogButtonBox QPushButton { min-width: 80px; }

/* ── Message box ── */
QMessageBox { background-color: #0e0e0c; }
QMessageBox QLabel { color: #ffffff; }

/* ── Frame card ── */
QFrame#card_frame {
    background-color: #1b1a15;
    border: 1px solid #3a3524;
    border-radius: 4px;
    padding: 10px;
}
"""


def get_severity_badge_style(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity, "#d6d1c4")
    return (
        f"background-color: {alpha(color, '28')}; "
        f"color: {color}; "
        "border-radius: 3px; "
        "padding: 2px 8px; "
        "font-size: 8pt; "
        "font-weight: 700;"
    )


def get_status_dot_style(status: str) -> str:
    color = STATUS_COLORS.get(status, "#d6d1c4")
    return (
        f"background-color: {color}; "
        "border-radius: 5px; "
        "min-width: 10px; min-height: 10px; "
        "max-width: 10px; max-height: 10px;"
    )
