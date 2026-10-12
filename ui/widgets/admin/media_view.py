"""
HSR — Administration : Types de médias (notifications)
Procus Tech

Tableau des canaux de notification + bouton Tester
"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
    QMessageBox
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont

from ui.styles import COLOR


MEDIA_ICONS = {
    "email":     "✉",
    "slack":     "💬",
    "sms":       "📱",
    "pagerduty": "🔔",
    "webhook":   "🌐",
}


class MediaView(QWidget):

    def __init__(self, db=None, security=None, parent=None):
        super().__init__(parent)
        self.db = db
        self.security = security
        self._build_ui()
        self.refresh()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)

        hdr = QHBoxLayout()
        title = QLabel("Administration — Médias")
        title.setStyleSheet(f"font-size: 14pt; font-weight: 700; color: {COLOR['text_pri']};")
        hdr.addWidget(title)
        hdr.addStretch()
        btn_ref = QPushButton("⟳  Actualiser")
        btn_ref.clicked.connect(self.refresh)
        hdr.addWidget(btn_ref)
        layout.addLayout(hdr)

        desc = QLabel(
            "Les médias sont les canaux d'envoi des notifications (email, Slack, SMS…). "
            "Configurez les paramètres SMTP/API dans les paramètres système."
        )
        desc.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 8pt;")
        desc.setWordWrap(True)
        layout.addWidget(desc)

        cols = ["", "Nom", "Type", "Description", "Adresse / Webhook", "Statut", "Actions"]
        self._table = QTableWidget(0, len(cols))
        self._table.setHorizontalHeaderLabels(cols)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self._table.verticalHeader().setVisible(False)
        self._table.setAlternatingRowColors(True)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setColumnWidth(0, 32)
        self._table.setColumnWidth(1, 150)
        self._table.setColumnWidth(2, 100)
        self._table.setColumnWidth(4, 200)
        self._table.setColumnWidth(5, 80)
        self._table.setColumnWidth(6, 120)
        layout.addWidget(self._table)

    def refresh(self):
        if not self.db:
            return
        media_types = self.db.get_media_types()
        self._table.setRowCount(0)

        for mt in media_types:
            row = self._table.rowCount()
            self._table.insertRow(row)
            self._table.setRowHeight(row, 38)

            mtype = mt.get("type", "").lower()
            icon_item = QTableWidgetItem(MEDIA_ICONS.get(mtype, "⚙"))
            icon_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            icon_item.setFont(QFont("Segoe UI", 12))
            self._table.setItem(row, 0, icon_item)

            self._table.setItem(row, 1, QTableWidgetItem(mt.get("name", "")))
            self._table.setItem(row, 2, QTableWidgetItem(mt.get("type", "")))
            self._table.setItem(row, 3, QTableWidgetItem(mt.get("description", "") or ""))
            self._table.setItem(row, 4, QTableWidgetItem(mt.get("smtp_host", "") or mt.get("webhook_url", "") or "—"))

            active = mt.get("active", 1)
            status_item = QTableWidgetItem("Actif" if active else "Inactif")
            status_item.setForeground(QColor(COLOR["green"] if active else COLOR["red"]))
            self._table.setItem(row, 5, status_item)

            # Bouton Tester
            btn_w = QWidget()
            btn_lay = QHBoxLayout(btn_w)
            btn_lay.setContentsMargins(4, 4, 4, 4)
            btn_test = QPushButton("▷ Tester")
            btn_test.setFixedHeight(24)
            btn_test.setStyleSheet(f"background:transparent;color:{COLOR['cyan']};border:1px solid {COLOR['cyan']};border-radius:3px;padding:1px 6px;font-size:7pt;")
            mt_name = mt.get("name", "")
            btn_test.clicked.connect(lambda ch, n=mt_name: self._test_media(n))
            btn_lay.addWidget(btn_test)
            btn_lay.addStretch()
            self._table.setCellWidget(row, 6, btn_w)

    def _test_media(self, name: str):
        QMessageBox.information(
            self, "Test média",
            f"Test envoyé via « {name} ».\n"
            "(Fonctionnalité disponible après configuration des paramètres SMTP/API.)"
        )


