"""
Procus Secure — Feuille de style Qt
Style inspiré de Zabbix : fond sombre bleu-gris, orange vif, police DejaVu/Segoe UI

Palette Zabbix-like :
  BG_MAIN    #1F2D40   fond principal (bleu nuit)
  BG_SIDEBAR #172334   barre latérale (bleu sombre)
  BG_CARD    #253347   cartes / panneaux
  BG_ROW     #1E2B3C   lignes alternées tableau
  BG_INPUT   #1A2538   champs de saisie
  BORDER     #2E4260   séparateurs
  ACCENT     #E45516   orange Zabbix
  CYAN       #1DC6DC   info / bande passante
  GREEN      #27AE60   en ligne
  RED        #C0392B   critique
  YELLOW     #D4AC0D   average
  PURPLE     #8E44AD   disaster
  TEXT_PRI   #D9E5F0   texte principal
  TEXT_SEC   #7A9BBE   texte secondaire
"""

COLOR = {
    "bg_main":    "#1F2D40",
    "bg_sidebar": "#172334",
    "bg_card":    "#253347",
    "bg_row":     "#1E2B3C",
    "bg_input":   "#1A2538",
    "border":     "#2E4260",
    "accent":     "#E45516",
    "cyan":       "#1DC6DC",
    "green":      "#27AE60",
    "red":        "#C0392B",
    "yellow":     "#D4AC0D",
    "purple":     "#8E44AD",
    "text_pri":   "#D9E5F0",
    "text_sec":   "#7A9BBE",
    "hover":      "#1E3050",
}

SEVERITY_COLORS = {
    "disaster":    "#8E44AD",
    "high":        "#C0392B",
    "average":     "#E45516",
    "warning":     "#D4AC0D",
    "information": "#1DC6DC",
    "resolved":    "#27AE60",
}

STATUS_COLORS = {
    "online":      "#27AE60",
    "offline":     "#C0392B",
    "unreachable": "#E45516",
    "unknown":     "#7A9BBE",
}

MAIN_QSS = """
/* ── Globals ── */
QWidget {
    background-color: #1F2D40;
    color: #D9E5F0;
    font-family: "DejaVu Sans", "Segoe UI", sans-serif;
    font-size: 9pt;
}

QMainWindow { background-color: #1F2D40; }

/* ── Scrollbars ── */
QScrollBar:vertical {
    background: #172334;
    width: 7px;
    margin: 0;
}
QScrollBar::handle:vertical {
    background: #2E4260;
    border-radius: 3px;
    min-height: 24px;
}
QScrollBar::handle:vertical:hover { background: #3D5A80; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }

QScrollBar:horizontal {
    background: #172334;
    height: 7px;
}
QScrollBar::handle:horizontal {
    background: #2E4260;
    border-radius: 3px;
}
QScrollBar::handle:horizontal:hover { background: #3D5A80; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }

/* ── Tables ── */
QTableWidget, QTableView {
    background-color: #253347;
    border: 1px solid #2E4260;
    border-radius: 4px;
    gridline-color: #2E4260;
    selection-background-color: #1E3050;
    alternate-background-color: #1E2B3C;
    outline: none;
}
QTableWidget::item, QTableView::item {
    padding: 4px 8px;
    border: none;
}
QTableWidget::item:selected, QTableView::item:selected {
    background-color: #1E3050;
    color: #D9E5F0;
}
QHeaderView::section {
    background-color: #172334;
    color: #7A9BBE;
    padding: 5px 10px;
    border: none;
    border-right: 1px solid #2E4260;
    border-bottom: 2px solid #E45516;
    font-weight: 700;
    font-size: 8pt;
    letter-spacing: 0.3px;
}

/* ── Boutons ── */
QPushButton {
    background-color: #253347;
    color: #D9E5F0;
    border: 1px solid #2E4260;
    border-radius: 3px;
    padding: 4px 12px;
    font-weight: 500;
}
QPushButton:hover {
    background-color: #1E3050;
    border-color: #3D5A80;
}
QPushButton:pressed { background-color: #172334; }
QPushButton:disabled {
    color: #3D5A80;
    background-color: #1F2D40;
    border-color: #2E4260;
}

QPushButton#btn_primary {
    background-color: #E45516;
    color: #ffffff;
    border: none;
    font-weight: 700;
}
QPushButton#btn_primary:hover { background-color: #C94B12; }
QPushButton#btn_primary:pressed { background-color: #A83E0F; }

QPushButton#btn_danger {
    background-color: transparent;
    color: #C0392B;
    border: 1px solid #C0392B;
    border-radius: 3px;
}
QPushButton#btn_danger:hover { background-color: #C0392B; color: #fff; }

QPushButton#btn_success {
    background-color: transparent;
    color: #27AE60;
    border: 1px solid #27AE60;
    border-radius: 3px;
}
QPushButton#btn_success:hover { background-color: #27AE60; color: #1F2D40; }

/* ── Inputs ── */
QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox, QDoubleSpinBox, QComboBox {
    background-color: #1A2538;
    border: 1px solid #2E4260;
    border-radius: 3px;
    color: #D9E5F0;
    padding: 4px 8px;
    selection-background-color: #E45516;
    selection-color: #ffffff;
}
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus,
QSpinBox:focus, QComboBox:focus {
    border-color: #E45516;
}

QComboBox::drop-down { border: none; width: 18px; }
QComboBox::down-arrow {
    image: none;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 5px solid #7A9BBE;
    margin-right: 6px;
}
QComboBox QAbstractItemView {
    background-color: #1A2538;
    border: 1px solid #2E4260;
    selection-background-color: #1E3050;
    outline: none;
}

/* ── Labels ── */
QLabel { background: transparent; }

/* ── Group box ── */
QGroupBox {
    background-color: #253347;
    border: 1px solid #2E4260;
    border-radius: 4px;
    margin-top: 12px;
    padding: 10px;
    font-weight: 700;
    color: #7A9BBE;
    font-size: 8pt;
    letter-spacing: 0.5px;
}
QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 10px;
    top: -6px;
    padding: 0 4px;
    background-color: #253347;
}

/* ── Tabs ── */
QTabWidget::pane {
    background-color: #253347;
    border: 1px solid #2E4260;
    border-top: none;
    border-radius: 0 0 4px 4px;
}
QTabBar::tab {
    background-color: #172334;
    color: #7A9BBE;
    padding: 7px 18px;
    border: 1px solid #2E4260;
    border-bottom: none;
    margin-right: 2px;
    border-radius: 3px 3px 0 0;
    font-size: 8pt;
}
QTabBar::tab:selected {
    background-color: #253347;
    color: #D9E5F0;
    border-bottom: 2px solid #E45516;
}
QTabBar::tab:hover:!selected { background-color: #1E2B3C; }

/* ── Progress bars ── */
QProgressBar {
    background-color: #2E4260;
    border: none;
    border-radius: 3px;
    height: 7px;
    text-align: center;
    font-size: 7pt;
    color: transparent;
}
QProgressBar::chunk { background-color: #27AE60; border-radius: 3px; }
QProgressBar[value_critical="true"]::chunk { background-color: #C0392B; }
QProgressBar[value_warning="true"]::chunk  { background-color: #E45516; }

/* ── Checkboxes ── */
QCheckBox { spacing: 8px; color: #D9E5F0; }
QCheckBox::indicator {
    width: 14px; height: 14px;
    border-radius: 2px;
    border: 1px solid #2E4260;
    background-color: #1A2538;
}
QCheckBox::indicator:checked { background-color: #E45516; border-color: #E45516; }

/* ── Splitter ── */
QSplitter::handle { background-color: #2E4260; }
QSplitter::handle:horizontal { width: 1px; }
QSplitter::handle:vertical   { height: 1px; }

/* ── Status bar ── */
QStatusBar {
    background-color: #172334;
    color: #7A9BBE;
    border-top: 1px solid #2E4260;
    font-size: 8pt;
}

/* ── Tool tips ── */
QToolTip {
    background-color: #253347;
    color: #D9E5F0;
    border: 1px solid #2E4260;
    border-radius: 3px;
    padding: 4px 8px;
    font-size: 8pt;
}

/* ── Dialog ── */
QDialog { background-color: #1F2D40; }
QDialogButtonBox QPushButton { min-width: 80px; }

/* ── Message box ── */
QMessageBox { background-color: #1F2D40; }
QMessageBox QLabel { color: #D9E5F0; }

/* ── Frame card ── */
QFrame#card_frame {
    background-color: #253347;
    border: 1px solid #2E4260;
    border-radius: 4px;
    padding: 10px;
}
"""


def get_severity_badge_style(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity, "#7A9BBE")
    return (
        f"background-color: {color}28; "
        f"color: {color}; "
        "border-radius: 3px; "
        "padding: 2px 8px; "
        "font-size: 8pt; "
        "font-weight: 700;"
    )


def get_status_dot_style(status: str) -> str:
    color = STATUS_COLORS.get(status, "#7A9BBE")
    return (
        f"background-color: {color}; "
        "border-radius: 5px; "
        "min-width: 10px; min-height: 10px; "
        "max-width: 10px; max-height: 10px;"
    )
