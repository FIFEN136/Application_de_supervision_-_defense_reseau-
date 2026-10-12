"""
HSR — Historique des événements
Procus Tech

Tableau complet + bouton Export CSV
"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget,
    QTableWidgetItem, QPushButton, QComboBox, QHeaderView,
    QAbstractItemView, QFileDialog
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont

from ui.styles import COLOR, SEVERITY_COLORS


class EventsView(QWidget):

    def __init__(self, db=None, parent=None):
        super().__init__(parent)
        self.db = db
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
        self._filter_sev.currentIndexChanged.connect(self.refresh)
        hdr.addWidget(self._filter_sev)

        btn_refresh = QPushButton("⟳  Actualiser")
        btn_refresh.clicked.connect(self.refresh)
        hdr.addWidget(btn_refresh)

        btn_export = QPushButton("💾  Export CSV")
        btn_export.clicked.connect(self._export_csv)
        hdr.addWidget(btn_export)

        layout.addLayout(hdr)

        cols = ["ID", "Sévérité", "Type", "Hôte", "Groupe", "Description", "Port", "Avant", "Après", "Date", "Acquitté"]
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

        foot = QHBoxLayout()
        self._lbl_count = QLabel()
        self._lbl_count.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 8pt;")
        foot.addWidget(self._lbl_count)
        foot.addStretch()
        layout.addLayout(foot)

    def refresh(self):
        if not self.db:
            return
        idx = self._filter_sev.currentIndex()
        sev = None if idx == 0 else self._filter_sev.currentText()
        events = self.db.get_events(severity=sev, limit=1000)
        self._table.setRowCount(0)

        for evt in events:
            row = self._table.rowCount()
            self._table.insertRow(row)
            self._table.setRowHeight(row, 30)

            sev_val = evt.get("severity", "")
            color = SEVERITY_COLORS.get(sev_val, "#8B9CB0")

            self._table.setItem(row, 0, QTableWidgetItem(str(evt.get("id", ""))))

            sev_item = QTableWidgetItem(sev_val.upper())
            sev_item.setForeground(QColor(color))
            sev_item.setFont(QFont("Segoe UI", 8, QFont.Weight.Bold))
            self._table.setItem(row, 1, sev_item)

            self._table.setItem(row, 2,  QTableWidgetItem(evt.get("event_type", "")))
            self._table.setItem(row, 3,  QTableWidgetItem(evt.get("host_name", "")))
            self._table.setItem(row, 4,  QTableWidgetItem(evt.get("group_name", "")))
            self._table.setItem(row, 5,  QTableWidgetItem(evt.get("description", "")))
            self._table.setItem(row, 6,  QTableWidgetItem(str(evt.get("port", "") or ""))
)
            self._table.setItem(row, 7,  QTableWidgetItem(evt.get("state_before", "") or ""))
            self._table.setItem(row, 8,  QTableWidgetItem(evt.get("state_after", "") or ""))
            self._table.setItem(row, 9,  QTableWidgetItem(str(evt.get("occurred_at", ""))[:16]))

            acked = "✔" if evt.get("acknowledged") else ""
            ack_item = QTableWidgetItem(acked)
            ack_item.setForeground(QColor(COLOR["green"]))
            ack_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(row, 10, ack_item)

        self._lbl_count.setText(f"{self._table.rowCount()} événement(s)")

    def _export_csv(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Exporter événements", "evenements_hsr.csv", "CSV (*.csv)"
        )
        if not path:
            return
        import csv
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f, delimiter=";")
            headers = [self._table.horizontalHeaderItem(c).text()
                       for c in range(self._table.columnCount())]
            writer.writerow(headers)
            for row in range(self._table.rowCount()):
                line = []
                for col in range(self._table.columnCount()):
                    item = self._table.item(row, col)
                    line.append(item.text() if item else "")
                writer.writerow(line)
