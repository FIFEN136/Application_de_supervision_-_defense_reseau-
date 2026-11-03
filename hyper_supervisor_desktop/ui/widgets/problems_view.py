"""
HSR — Vue Problèmes
Procus Tech

Colonnes : Sévérité | Depuis | Durée | Hôte | Groupe | Problème | Occur. | Tags | Acquitté | Actions
Filtres par sévérité + pagination LIMIT/OFFSET
"""
import json
from datetime import datetime

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget,
    QTableWidgetItem, QPushButton, QComboBox, QLineEdit,
    QHeaderView, QAbstractItemView
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont

from ui.icons import icon_button, next_button, svg_icon
from ui.styles import COLOR, SEVERITY_COLORS, alpha

PAGE_SIZE = 100


class ProblemsView(QWidget):

    def __init__(self, db=None, security=None, parent=None):
        super().__init__(parent)
        self.db = db
        self.security = security
        self._page = 0           # page courante (0-indexed)
        self._total = 0          # nombre total de lignes
        self._current_severity = "all"
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
        self._filter_sev.currentIndexChanged.connect(self._on_combobox_changed)
        hdr.addWidget(self._filter_sev)

        self._search = QLineEdit()
        self._search.setPlaceholderText("Rechercher...")
        self._search.setFixedWidth(200)
        self._search.textChanged.connect(self._apply_filter)
        hdr.addWidget(self._search)

        btn_refresh = icon_button("act_refresh", "Actualiser")
        btn_refresh.clicked.connect(self.refresh)
        hdr.addWidget(btn_refresh)
        layout.addLayout(hdr)

        # ── Barre sévérité ──
        sev_row = QHBoxLayout()
        sev_row.setSpacing(8)
        self._sev_btns: dict[str, QPushButton] = {}
        sev_labels = [
            ("all",         "Tous",          "#c4bfae"),
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
                    background-color: {alpha(color, '22')};
                    color: {color};
                    border: 1px solid {alpha(color, '66')};
                    border-radius: 4px;
                    padding: 2px 10px;
                    font-size: 8pt;
                    font-weight: 600;
                }}
                QPushButton:checked {{
                    background-color: {color};
                    color: #0b0b0a;
                }}
            """)
            btn.clicked.connect(lambda ch, k=key: self._filter_by_severity(k))
            sev_row.addWidget(btn)
            self._sev_btns[key] = btn
        self._sev_btns["all"].setChecked(True)
        sev_row.addStretch()
        layout.addLayout(sev_row)

        # ── Tableau ──
        cols = ["Sévérité", "Depuis", "Durée", "Hôte", "Groupe",
                "Problème", "Occur.", "Tags", "Acquitté", "Actions"]
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

        # ── Pied : pagination + acquitter tout ──
        foot = QHBoxLayout()
        self._lbl_count = QLabel()
        self._lbl_count.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 8pt;")
        foot.addWidget(self._lbl_count)
        foot.addStretch()

        # Pagination
        self._btn_prev = icon_button("act_prev", "Précédent")
        self._btn_prev.setFixedWidth(110)
        self._btn_prev.clicked.connect(self._prev_page)
        self._btn_prev.setEnabled(False)
        foot.addWidget(self._btn_prev)

        self._lbl_page = QLabel("Page 1 / 1")
        self._lbl_page.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 8pt; padding: 0 8px;")
        self._lbl_page.setAlignment(Qt.AlignmentFlag.AlignCenter)
        foot.addWidget(self._lbl_page)

        self._btn_next = next_button("Suivant")
        self._btn_next.setFixedWidth(110)
        self._btn_next.clicked.connect(self._next_page)
        self._btn_next.setEnabled(False)
        foot.addWidget(self._btn_next)

        foot.addSpacing(16)

        btn_ack_all = QPushButton("Tout acquitter")
        btn_ack_all.setObjectName("btn_success")
        btn_ack_all.clicked.connect(self._acknowledge_all)
        foot.addWidget(btn_ack_all)
        layout.addLayout(foot)

    # ─────────────────────────────────────────
    # Navigation pagination
    # ─────────────────────────────────────────

    def _prev_page(self):
        if self._page > 0:
            self._page -= 1
            self._load_page()

    def _next_page(self):
        max_page = max(0, (self._total - 1) // PAGE_SIZE)
        if self._page < max_page:
            self._page += 1
            self._load_page()

    def _update_pagination_controls(self):
        max_page = max(0, (self._total - 1) // PAGE_SIZE) if self._total > 0 else 0
        self._lbl_page.setText(f"Page {self._page + 1} / {max_page + 1}")
        self._btn_prev.setEnabled(self._page > 0)
        self._btn_next.setEnabled(self._page < max_page)

    # ─────────────────────────────────────────
    # Filtres
    # ─────────────────────────────────────────

    def _on_combobox_changed(self):
        idx = self._filter_sev.currentIndex()
        sev = None if idx == 0 else self._filter_sev.currentText()
        self._current_severity = sev or "all"
        self._page = 0
        self._load_page()

    def _filter_by_severity(self, key: str):
        self._current_severity = key
        for k, b in self._sev_btns.items():
            b.setChecked(k == key)
        # Sync combobox silently
        self._filter_sev.blockSignals(True)
        if key == "all":
            self._filter_sev.setCurrentIndex(0)
        else:
            items = [self._filter_sev.itemText(i)
                     for i in range(self._filter_sev.count())]
            try:
                self._filter_sev.setCurrentIndex(items.index(key))
            except ValueError:
                self._filter_sev.setCurrentIndex(0)
        self._filter_sev.blockSignals(False)
        self._page = 0
        self._load_page()

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

    # ─────────────────────────────────────────
    # Chargement
    # ─────────────────────────────────────────

    def refresh(self):
        if not self.db:
            return
        self._page = 0
        self._load_page()

    def _load_page(self):
        if not self.db:
            return
        sev = None if self._current_severity == "all" else self._current_severity
        self._total = self.db.count_events(severity=sev)
        offset = self._page * PAGE_SIZE
        events = self.db.get_events(severity=sev, limit=PAGE_SIZE, offset=offset)
        self._populate(events)
        self._update_pagination_controls()

    def _populate(self, events: list):
        self._table.setRowCount(0)

        for evt in events:
            row = self._table.rowCount()
            self._table.insertRow(row)
            self._table.setRowHeight(row, 36)

            sev = evt.get("severity", "information")
            color = SEVERITY_COLORS.get(sev, "#c4bfae")

            # Sévérité
            sev_item = QTableWidgetItem(sev.upper())
            sev_item.setForeground(QColor(color))
            sev_item.setFont(QFont("Segoe UI", 8, QFont.Weight.Bold))
            sev_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(row, 0, sev_item)

            # Depuis
            occurred = evt.get("occurred_at", "")
            self._table.setItem(row, 1, QTableWidgetItem(str(occurred)[:16]))

            # Durée
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
            self._table.setItem(row, 6, QTableWidgetItem("1"))

            # Tags
            try:
                tags = json.loads(evt.get("tags", "[]") or "[]")
                tags_str = ", ".join(tags) if tags else ""
            except Exception:
                tags_str = ""
            self._table.setItem(row, 7, QTableWidgetItem(tags_str))

            # Acquitté
            acked = evt.get("acknowledged", 0)
            ack_item = QTableWidgetItem("")
            if acked:
                ack_item.setIcon(svg_icon("act_check", COLOR["green"]))
                ack_item.setToolTip("Acquitté")
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
                        color: #0b0b0a;
                    }}
                """)
                evt_id = evt.get("id")
                btn.clicked.connect(lambda ch, eid=evt_id: self._acknowledge(eid))
                self._table.setCellWidget(row, 9, btn)
            else:
                resolved_item = QTableWidgetItem("Acquitté")
                resolved_item.setForeground(QColor(COLOR["green"]))
                self._table.setItem(row, 9, resolved_item)

        shown = self._table.rowCount()
        start = self._page * PAGE_SIZE + 1 if self._total > 0 else 0
        end = min(self._page * PAGE_SIZE + shown, self._total)
        self._lbl_count.setText(
            f"{start}–{end} sur {self._total} problème(s)"
            if self._total > 0 else "0 problème"
        )

    # ─────────────────────────────────────────
    # Actions
    # ─────────────────────────────────────────

    def _acknowledge(self, event_id: int):
        if not self.db:
            return
        username = self._get_username()
        self.db.acknowledge_event(event_id, username)
        self._load_page()

    def _acknowledge_all(self):
        if not self.db:
            return
        username = self._get_username()
        # Acquitter toutes les pages, pas seulement la page affichée
        sev = None if self._current_severity == "all" else self._current_severity
        total = self.db.count_events(severity=sev)
        offset = 0
        while offset < total:
            batch = self.db.get_events(severity=sev, limit=500, offset=offset)
            for evt in batch:
                if not evt.get("acknowledged"):
                    self.db.acknowledge_event(evt["id"], username)
            offset += 500
        self._page = 0
        self._load_page()

    def _get_username(self) -> str:
        if self.security:
            user = self.security.get_current_user()
            return user.get("login", "unknown") if user else "unknown"
        return "unknown"
