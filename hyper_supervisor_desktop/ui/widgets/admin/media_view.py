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
from ui.icons import icon_button
from ui.icons import ICONS, _svg_icon


MEDIA_DESCRIPTIONS = {
    "email":   "Alertes par e-mail via un serveur SMTP (STARTTLS / SSL)",
    "webhook": "Alertes POST JSON vers une URL (Slack, Teams, SIEM…)",
    "sms":     "Alertes SMS (passerelle non intégrée dans cette version)",
}


def _media_icon_key(mt: dict) -> str:
    name = (mt.get("name") or "").lower()
    mtype = (mt.get("type") or "").lower()
    if "slack" in name:
        return "media_slack"
    if "pagerduty" in name:
        return "media_pagerduty"
    return {"email": "media_email", "sms": "media_sms"}.get(mtype, "media_webhook")


SUPPORTED_TYPES = ("email", "webhook")


def media_summary(mt: dict) -> tuple[str, str]:
    """(adresse affichée, état) d'après config_json — jamais de secret en clair."""
    import json
    from urllib.parse import urlparse
    mtype = (mt.get("type") or "").lower()
    if mtype not in SUPPORTED_TYPES:
        return "—", "Non pris en charge"
    try:
        cfg = json.loads(mt.get("config_json") or "{}")
    except Exception:
        cfg = {}
    if mtype == "email":
        host = (cfg.get("smtp_host") or "").strip()
        if not host:
            return "—", "Non configuré"
        to = (cfg.get("smtp_to") or "").strip()
        return f"{host}:{cfg.get('smtp_port', 587)}" + (f" → {to}" if to else ""), "Configuré"
    raw = cfg.get("webhook_url") or ""
    if not raw:
        return "—", "Non configuré"
    try:                                   # l'URL est chiffrée en base : on n'affiche que « chiffrée »
        from core.security import CryptoHelper
        url = CryptoHelper.decrypt(raw)
        netloc = urlparse(url).netloc
        return (netloc + "/•••" if netloc else "URL chiffrée"), "Configuré"
    except Exception:
        return "URL chiffrée", "Configuré"


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
        btn_ref = icon_button("act_refresh", "Actualiser")
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
        self._table.setColumnWidth(4, 260)
        self._table.setColumnWidth(5, 150)
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
            icon_w = QLabel()
            icon_w.setAlignment(Qt.AlignmentFlag.AlignCenter)
            icon_w.setStyleSheet("background: transparent;")
            icon_w.setPixmap(_svg_icon(ICONS[_media_icon_key(mt)], size=16, color=COLOR["cyan"]))
            self._table.setCellWidget(row, 0, icon_w)

            self._table.setItem(row, 1, QTableWidgetItem(mt.get("name", "")))
            self._table.setItem(row, 2, QTableWidgetItem(mt.get("type", "")))
            self._table.setItem(row, 3, QTableWidgetItem(
                mt.get("description") or MEDIA_DESCRIPTIONS.get(mtype, "")))
            addr, state = media_summary(mt)
            self._table.setItem(row, 4, QTableWidgetItem(addr))

            active = mt.get("active", 1)
            if not active:
                label, color = "Inactif", COLOR["red"]
            elif state == "Configuré":
                label, color = "Actif · configuré", COLOR["green"]
            else:
                label, color = f"Actif · {state.lower()}", COLOR["accent"]
            status_item = QTableWidgetItem(label)
            status_item.setForeground(QColor(color))
            self._table.setItem(row, 5, status_item)

            # Bouton Tester
            btn_w = QWidget()
            btn_lay = QHBoxLayout(btn_w)
            btn_lay.setContentsMargins(4, 4, 4, 4)
            btn_test = icon_button("act_zap", "Tester")
            btn_test.setFixedHeight(24)
            btn_test.setStyleSheet(f"background:transparent;color:{COLOR['cyan']};border:1px solid {COLOR['cyan']};border-radius:3px;padding:1px 6px;font-size:7pt;")
            mt_name = mt.get("name", "")
            btn_test.clicked.connect(lambda ch, n=mt_name: self._test_media(n))
            btn_lay.addWidget(btn_test)
            btn_lay.addStretch()
            self._table.setCellWidget(row, 6, btn_w)

    def _test_media(self, name: str):
        """Envoie réellement un événement de test via le média choisi (hors thread UI)."""
        if self.security:
            try:
                self.security.require_permission("can_manage_config")
            except PermissionError as e:
                QMessageBox.warning(self, "Accès refusé", str(e))
                return
        if not self.db:
            return
        from core.notifier import NotifierManager
        from ui.async_call import run_blocking
        mgr = NotifierManager(self.db)
        res, err = run_blocking(lambda: mgr.test_media(name))
        ok, msg = (False, str(err)) if err is not None else res
        box = QMessageBox.information if ok else QMessageBox.warning
        box(self, "Test média", f"{name} : {'réussi' if ok else 'échec'}\n\n{msg}")
