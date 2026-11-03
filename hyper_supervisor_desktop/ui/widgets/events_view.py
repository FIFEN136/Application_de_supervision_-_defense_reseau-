"""
HSR — Historique des événements
Procus Tech

Tableau complet + pagination LIMIT/OFFSET + Export CSV
"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget,
    QTableWidgetItem, QPushButton, QComboBox, QHeaderView,
    QAbstractItemView, QFileDialog
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont

from ui.styles import COLOR, SEVERITY_COLORS
from ui.icons import icon_button, next_button, svg_icon

PAGE_SIZE = 150


class EventsView(QWidget):

    def __init__(self, db=None, parent=None):
        super().__init__(parent)
        self.db = db
        self._page = 0
        self._total = 0
        self._current_severity = None
        self._build_ui()
        self.refresh()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)

        hdr = QHBoxLayout()
        title = QLabel("Événements")
        title.setStyleSheet(f"font-size: 14pt; font-weight: 700; color: {COLOR['text_pri']};")
        hdr.addWidget(title)
        hdr.addStretch()

        self._filter_sev = QComboBox()
        self._filter_sev.addItems(["Toutes sévérités", "disaster", "high", "average", "warning", "information"])
        self._filter_sev.setFixedWidth(160)
        self._filter_sev.currentIndexChanged.connect(self._on_filter_changed)
        hdr.addWidget(self._filter_sev)

        btn_refresh = icon_button("act_refresh", "Actualiser")
        btn_refresh.clicked.connect(self.refresh)
        hdr.addWidget(btn_refresh)

        btn_export = icon_button("act_export", "Export CSV")
        btn_export.clicked.connect(self._export_csv)
        hdr.addWidget(btn_export)

        layout.addLayout(hdr)

        cols = ["ID", "Sévérité", "Type", "Hôte", "Groupe",
                "Description", "Port", "Avant", "Après", "Date", "Acquitté"]
        self._table = QTableWidget(0, len(cols))
        self._table.setHorizontalHeaderLabels(cols)
        self._table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self._table.verticalHeader().setVisible(False)
        self._table.setAlternatingRowColors(True)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setColumnWidth(0, 50)
        self._table.setColumnWidth(1, 100)
        self._table.setColumnWidth(2, 110)
        self._table.setColumnWidth(3, 130)
        self._table.setColumnWidth(4, 100)
        self._table.setColumnWidth(6, 60)
        self._table.setColumnWidth(7, 80)
        self._table.setColumnWidth(8, 80)
        self._table.setColumnWidth(9, 140)
        self._table.setColumnWidth(10, 80)
        layout.addWidget(self._table)

        # ── Pied : compteur + pagination ──
        foot = QHBoxLayout()
        self._lbl_count = QLabel()
        self._lbl_count.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 8pt;")
        foot.addWidget(self._lbl_count)
        foot.addStretch()

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

        layout.addLayout(foot)

    # ─────────────────────────────────────────
    # Pagination
    # ─────────────────────────────────────────

    def _prev_page(self):
        if self._page > 0:
            self._page -= 1
            self._load_page()

    def _next_page(self):
        max_page = max(0, (self._total - 1) // PAGE_SIZE) if self._total > 0 else 0
        if self._page < max_page:
            self._page += 1
            self._load_page()

    def _update_pagination_controls(self):
        max_page = max(0, (self._total - 1) // PAGE_SIZE) if self._total > 0 else 0
        self._lbl_page.setText(f"Page {self._page + 1} / {max_page + 1}")
        self._btn_prev.setEnabled(self._page > 0)
        self._btn_next.setEnabled(self._page < max_page)

    # ─────────────────────────────────────────
    # Filtre
    # ─────────────────────────────────────────

    def _on_filter_changed(self):
        idx = self._filter_sev.currentIndex()
        self._current_severity = None if idx == 0 else self._filter_sev.currentText()
        self._page = 0
        self._load_page()

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
        sev = self._current_severity
        self._total = self.db.count_events(severity=sev)
        offset = self._page * PAGE_SIZE
        events = self.db.get_events(severity=sev, limit=PAGE_SIZE, offset=offset)
        self._table.setRowCount(0)

        for evt in events:
            row = self._table.rowCount()
            self._table.insertRow(row)
            self._table.setRowHeight(row, 30)

            sev_val = evt.get("severity", "")
            color = SEVERITY_COLORS.get(sev_val, "#c4bfae")

            self._table.setItem(row, 0, QTableWidgetItem(str(evt.get("id", ""))))

            sev_item = QTableWidgetItem(sev_val.upper())
            sev_item.setForeground(QColor(color))
            sev_item.setFont(QFont("Segoe UI", 8, QFont.Weight.Bold))
            self._table.setItem(row, 1, sev_item)

            self._table.setItem(row, 2,  QTableWidgetItem(evt.get("event_type", "")))
            self._table.setItem(row, 3,  QTableWidgetItem(evt.get("host_name", "")))
            self._table.setItem(row, 4,  QTableWidgetItem(evt.get("group_name", "")))
            self._table.setItem(row, 5,  QTableWidgetItem(evt.get("description", "")))
            self._table.setItem(row, 6,  QTableWidgetItem(str(evt.get("port", "") or "")))
            self._table.setItem(row, 7,  QTableWidgetItem(evt.get("state_before", "") or ""))
            self._table.setItem(row, 8,  QTableWidgetItem(evt.get("state_after", "") or ""))
            self._table.setItem(row, 9,  QTableWidgetItem(str(evt.get("occurred_at", ""))[:16]))

            ack_item = QTableWidgetItem("")
            if evt.get("acknowledged"):
                ack_item.setIcon(svg_icon("act_check", COLOR["green"]))
                ack_item.setToolTip("Acquitté")
            ack_item.setForeground(QColor(COLOR["green"]))
            ack_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(row, 10, ack_item)

        shown = self._table.rowCount()
        start = self._page * PAGE_SIZE + 1 if self._total > 0 else 0
        end = min(self._page * PAGE_SIZE + shown, self._total)
        self._lbl_count.setText(
            f"{start}–{end} sur {self._total} événement(s)"
            if self._total > 0 else "0 événement"
        )
        self._update_pagination_controls()

    # ─────────────────────────────────────────
    # Export CSV (toutes les lignes, pas seulement la page)
    # ─────────────────────────────────────────

    def _export_csv(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Exporter événements", "evenements_hsr.csv", "CSV (*.csv)"
        )
        if not path:
            return
        import csv
        sev = self._current_severity
        total = self.db.count_events(severity=sev) if self.db else 0
        headers = [self._table.horizontalHeaderItem(c).text()
                   for c in range(self._table.columnCount())]
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f, delimiter=";")
            writer.writerow(headers)
            offset = 0
            while offset < total:
                batch = self.db.get_events(severity=sev, limit=500, offset=offset)
                for evt in batch:
                    sev_val = evt.get("severity", "")
                    writer.writerow([
                        evt.get("id", ""),
                        sev_val.upper(),
                        evt.get("event_type", ""),
                        evt.get("host_name", ""),
                        evt.get("group_name", ""),
                        evt.get("description", ""),
                        evt.get("port", "") or "",
                        evt.get("state_before", "") or "",
                        evt.get("state_after", "") or "",
                        str(evt.get("occurred_at", ""))[:16],
                        "Oui" if evt.get("acknowledged") else "",
                    ])
                offset += 500
