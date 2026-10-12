"""
HSR — Vue Problèmes
Procus Tech

Identique à la maquette :
  Colonnes : Sévérité | Depuis | Durée | Hôte | Groupe | Problème | Occur. | Tags | Acquitté | Actions
  Filtres par sévérité (tous / sinistre / grave / moyen / avertissement / info)
  Bouton Acquitter par ligne
"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget,
    QTableWidgetItem, QPushButton, QComboBox, QLineEdit,
    QHeaderView, QFrame, QSizePolicy, QAbstractItemView
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor, QFont

from ui.styles import COLOR, SEVERITY_COLORS, get_severity_badge_style


class ProblemsView(QWidget):

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

        # ── Titre + filtres ──
        hdr = QHBoxLayout()
        title = QLabel("Problèmes actifs")
        title.setStyleSheet(f"font-size: 14pt; font-weight: 700; color: {COLOR['text_pri']};")
        hdr.addWidget(title)
        hdr.addStretch()

        self._filter_sev = QComboBox()
        self._filter_sev.addItems(["Toutes sévérités", "disaster", "high", "average", "warning", "information"])
        self._filter_sev.setFixedWidth(160)
        self._filter_sev.currentIndexChanged.connect(self.refresh)
        hdr.addWidget(self._filter_sev)

        self._search = QLineEdit()
        self._search.setPlaceholderText("Rechercher...")
        self._search.setFixedWidth(200)
        self._search.textChanged.connect(self._apply_filter)
        hdr.addWidget(self._search)

        btn_refresh = QPushButton("⟳  Actualiser")
        btn_refresh.clicked.connect(self.refresh)
        hdr.addWidget(btn_refresh)
        layout.addLayout(hdr)

        # ── Barre sévérité ──
        sev_row = QHBoxLayout()
        sev_row.setSpacing(8)
        self._sev_btns: dict[str, QPushButton] = {}
        sev_labels = [
            ("all",         "Tous",          "#8B9CB0"),
            ("disaster",    "Sinistre",      SEVERITY_COLORS["disaster"]),
            ("high",        "Grave",         SEVERITY_COLORS["high"]),
            ("average",     "Moyen",         SEVERITY_COLORS["average"]),
            ("warning",     "Avertissement", SEVERITY_COLORS["warning"]),
            ("information", "Information",   SEVERITY_COLORS["information"]),
        ]
        for key, label, color in sev_labels:
            btn = QPushButton(label)
            btn.setCheckable(True)
            btn.setFixedHeight(28)
            btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {color}22;
                    color: {color};
                    border: 1px solid {color}66;
                    border-radius: 4px;
                    padding: 2px 10px;
                    font-size: 8pt;
                    font-weight: 600;
                }}
                QPushButton:checked {{
                    background-color: {color};
                    color: #1A1D23;
                }}
            """)
            btn.clicked.connect(lambda ch, k=key: self._filter_by_severity(k))
            sev_row.addWidget(btn)
            self._sev_btns[key] = btn
        self._sev_btns["all"].setChecked(True)
        sev_row.addStretch()
        layout.addLayout(sev_row)

        # ── Tableau ──
        cols = ["Sévérité", "Depuis", "Durée", "Hôte", "Groupe", "Problème", "Occur.", "Tags", "Acquitté", "Actions"]
        self._table = QTableWidget(0, len(cols))
        self._table.setHorizontalHeaderLabels(cols)
        self._table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(7, QHeaderView.ResizeMode.ResizeToContents)
        self._table.verticalHeader().setVisible(False)
        self._table.setAlternatingRowColors(True)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setColumnWidth(0, 100)
        self._table.setColumnWidth(1, 130)
        self._table.setColumnWidth(2, 80)
        self._table.setColumnWidth(3, 130)
        self._table.setColumnWidth(4, 100)
        self._table.setColumnWidth(6, 60)
        self._table.setColumnWidth(8, 80)
        self._table.setColumnWidth(9, 120)
        layout.addWidget(self._table)

        # ── Pied ──
        foot = QHBoxLayout()
        self._lbl_count = QLabel()
        self._lbl_count.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 8pt;")
        btn_ack_all = QPushButton("Tout acquitter")
        btn_ack_all.setObjectName("btn_success")
        btn_ack_all.clicked.connect(self._acknowledge_all)
        foot.addWidget(self._lbl_count)
        foot.addStretch()
        foot.addWidget(btn_ack_all)
        layout.addLayout(foot)

        self._current_severity = "all"

    # ─────────────────────────────────────────

    def _filter_by_severity(self, key: str):
        self._current_severity = key
        for k, b in self._sev_btns.items():
            b.setChecked(k == key)
        self.refresh()

    def _apply_filter(self):
        txt = self._search.text().lower()
        for row in range(self._table.rowCount()):
            show = False
            for col in range(self._table.columnCount() - 1):
                item = self._table.item(row, col)
                if item and txt in item.text().lower():
                    show = True
                    break
            self._table.setRowHidden(row, not show)

    def refresh(self):
        if not self.db:
            return
        sev = None if self._current_severity == "all" else self._current_severity
        events = self.db.get_events(severity=sev, limit=500)
        self._populate(events)

    def _populate(self, events: list):
        self._table.setRowCount(0)
        from datetime import datetime

        for evt in events:
            row = self._table.rowCount()
            self._table.insertRow(row)
            self._table.setRowHeight(row, 36)

            sev = evt.get("severity", "information")
            color = SEVERITY_COLORS.get(sev, "#8B9CB0")

            # Sévérité
            sev_item = QTableWidgetItem(sev.upper())
            sev_item.setForeground(QColor(color))
            sev_item.setFont(QFont("Segoe UI", 8, QFont.Weight.Bold))
            sev_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(row, 0, sev_item)

            # Depuis
            occurred = evt.get("occurred_at", "")
            self._table.setItem(row, 1, QTableWidgetItem(str(occurred)[:16]))

            # Durée (calculé si pas résolu)
            resolved = evt.get("resolved_at")
            if resolved:
                dur = "Résolu"
            else:
                try:
                    dt_start = datetime.fromisoformat(str(occurred))
                    delta = datetime.now() - dt_start
                    hours = int(delta.total_seconds() // 3600)
                    mins  = int((delta.total_seconds() % 3600) // 60)
                    dur = f"{hours}h {mins}m" if hours > 0 else f"{mins}m"
                except Exception:
                    dur = "—"
            self._table.setItem(row, 2, QTableWidgetItem(dur))

            self._table.setItem(row, 3, QTableWidgetItem(evt.get("host_name", "")))
            self._table.setItem(row, 4, QTableWidgetItem(evt.get("group_name", "")))
            self._table.setItem(row, 5, QTableWidgetItem(evt.get("description", "")))
            self._table.setItem(row, 6, QTableWidgetItem("1"))  # occurrences (MVP)

            # Tags
            import json
            try:
                tags = json.loads(evt.get("tags", "[]") or "[]")
                tags_str = ", ".join(tags) if tags else ""
            except Exception:
                tags_str = ""
            self._table.setItem(row, 7, QTableWidgetItem(tags_str))

            # Acquitté
            acked = evt.get("acknowledged", 0)
            ack_item = QTableWidgetItem("✔" if acked else "")
            ack_item.setForeground(QColor(COLOR["green"]))
            ack_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(row, 8, ack_item)

            # Bouton acquitter
            if not acked:
                btn = QPushButton("Acquitter")
                btn.setStyleSheet(f"""
                    QPushButton {{
                        background: transparent;
                        color: {COLOR['accent']};
                        border: 1px solid {COLOR['accent']};
                        border-radius: 4px;
                        padding: 2px 8px;
                        font-size: 7pt;
                    }}
                    QPushButton:hover {{
                        background: {COLOR['accent']};
                        color: #1A1D23;
                    }}
                """)
                evt_id = evt.get("id")
                btn.clicked.connect(lambda ch, eid=evt_id: self._acknowledge(eid))
                self._table.setCellWidget(row, 9, btn)
            else:
                resolved_item = QTableWidgetItem("Acquitté")
                resolved_item.setForeground(QColor(COLOR["green"]))
                self._table.setItem(row, 9, resolved_item)

        self._lbl_count.setText(f"{self._table.rowCount()} problème(s)")

    def _acknowledge(self, event_id: int):
        if not self.db:
            return
        if self.security:
            user = self.security.get_current_user()
            username = user.get("login", "unknown") if user else "unknown"
        else:
            username = "unknown"
        self.db.acknowledge_event(event_id, username)
        self.refresh()

    def _acknowledge_all(self):
        if not self.db:
            return
        if self.security:
            user = self.security.get_current_user()
            username = user.get("login", "unknown") if user else "unknown"
        else:
            username = "unknown"
        events = self.db.get_events(limit=1000)
        for evt in events:
            if not evt.get("acknowledged"):
                self.db.acknowledge_event(evt["id"], username)
        self.refresh()
