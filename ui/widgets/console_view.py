"""
HSR — Console live (journal en temps réel)
Procus Tech

Terminal sombre avec logs colorés par niveau.
Reçoit les signaux log_message(level, message) des workers.
"""
from datetime import datetime
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QPlainTextEdit, QComboBox
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QTextCharFormat, QColor, QTextCursor

from ui.styles import COLOR


LOG_COLORS = {
    "DEBUG":    "#8B9CB0",
    "INFO":     "#00D4FF",
    "SUCCESS":  "#2ECC71",
    "WARNING":  "#F39C12",
    "AVERAGE":  "#F39C12",
    "ERROR":    "#E74C3C",
    "HIGH":     "#E74C3C",
    "CRITICAL": "#9B59B6",
    "DISASTER": "#9B59B6",
}


class ConsoleView(QWidget):

    def __init__(self, parent=None):
        super().__init__(parent)
        self._max_lines = 2000
        self._paused = False
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(10)

        # ── En-tête ──
        hdr = QHBoxLayout()
        title = QLabel("Console")
        title.setStyleSheet(f"font-size: 14pt; font-weight: 700; color: {COLOR['text_pri']};")
        hdr.addWidget(title)
        hdr.addStretch()

        self._filter_combo = QComboBox()
        self._filter_combo.addItems(["Tous", "INFO", "WARNING", "ERROR", "CRITICAL"])
        self._filter_combo.setFixedWidth(120)
        hdr.addWidget(QLabel("Filtre :"))
        hdr.addWidget(self._filter_combo)

        btn_pause = QPushButton("⏸ Pause")
        btn_pause.setCheckable(True)
        btn_pause.toggled.connect(self._toggle_pause)
        hdr.addWidget(btn_pause)

        btn_clear = QPushButton("🗑 Effacer")
        btn_clear.clicked.connect(self._clear)
        hdr.addWidget(btn_clear)

        btn_export = QPushButton("💾 Exporter")
        btn_export.clicked.connect(self._export)
        hdr.addWidget(btn_export)

        layout.addLayout(hdr)

        # ── Zone texte ──
        self._console = QPlainTextEdit()
        self._console.setReadOnly(True)
        self._console.setMaximumBlockCount(self._max_lines)
        self._console.setFont(QFont("Cascadia Code, Consolas, Courier New", 9))
        self._console.setStyleSheet(f"""
            QPlainTextEdit {{
                background-color: #0D1117;
                color: {COLOR['text_pri']};
                border: 1px solid {COLOR['border']};
                border-radius: 6px;
                padding: 8px;
                selection-background-color: #2A3040;
            }}
        """)
        layout.addWidget(self._console)

        # ── Pied ──
        foot = QHBoxLayout()
        self._lbl_count = QLabel("0 lignes")
        self._lbl_count.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 8pt;")
        self._lbl_status = QLabel("● En attente")
        self._lbl_status.setStyleSheet(f"color: {COLOR['green']}; font-size: 8pt;")
        foot.addWidget(self._lbl_status)
        foot.addStretch()
        foot.addWidget(self._lbl_count)
        layout.addLayout(foot)

        self.append_log("INFO", "Console démarrée — HSR Procus Tech")

    # ─────────────────────────────────────────

    def append_log(self, level: str, message: str):
        if self._paused:
            return

        # Filtre UI
        f = self._filter_combo.currentText()
        if f != "Tous":
            if f == "ERROR"    and level not in ("ERROR", "CRITICAL", "DISASTER", "HIGH"):
                return
            if f == "WARNING"  and level not in ("WARNING", "AVERAGE", "ERROR", "CRITICAL", "DISASTER", "HIGH"):
                return
            if f == "INFO"     and level not in ("INFO", "SUCCESS"):
                return
            if f == "CRITICAL" and level not in ("CRITICAL", "DISASTER"):
                return

        ts   = datetime.now().strftime("%H:%M:%S")
        color = LOG_COLORS.get(level.upper(), "#E8EAED")

        cursor = self._console.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)

        # Timestamp
        fmt_ts = QTextCharFormat()
        fmt_ts.setForeground(QColor("#4D5566"))
        cursor.setCharFormat(fmt_ts)
        cursor.insertText(f"[{ts}] ")

        # Level badge
        fmt_lvl = QTextCharFormat()
        fmt_lvl.setForeground(QColor(color))
        fmt_lvl.setFontWeight(700)
        cursor.setCharFormat(fmt_lvl)
        cursor.insertText(f"[{level:<8}] ")

        # Message
        fmt_msg = QTextCharFormat()
        fmt_msg.setForeground(QColor("#C8CDD6"))
        cursor.setCharFormat(fmt_msg)
        cursor.insertText(message + "\n")

        self._console.setTextCursor(cursor)
        self._console.ensureCursorVisible()

        count = self._console.document().blockCount()
        self._lbl_count.setText(f"{count} ligne(s)")

    def _toggle_pause(self, paused: bool):
        self._paused = paused
        self._lbl_status.setText("⏸ Pause" if paused else "● Actif")
        self._lbl_status.setStyleSheet(f"color: {COLOR['accent'] if paused else COLOR['green']}; font-size: 8pt;")

    def _clear(self):
        self._console.clear()
        self.append_log("INFO", "Console effacée.")

    def _export(self):
        from PyQt6.QtWidgets import QFileDialog
        path, _ = QFileDialog.getSaveFileName(self, "Exporter console", "console_hsr.txt", "Texte (*.txt)")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self._console.toPlainText())
            self.append_log("SUCCESS", f"Console exportée : {path}")
