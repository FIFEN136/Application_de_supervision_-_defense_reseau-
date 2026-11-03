"""
HSR — Administration : Templates de supervision
Procus Tech
"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView
)
from ui.styles import COLOR
from ui.icons import icon_button


class TemplatesView(QWidget):

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
        title = QLabel("Administration — Templates")
        title.setStyleSheet(f"font-size: 14pt; font-weight: 700; color: {COLOR['text_pri']};")
        hdr.addWidget(title)
        hdr.addStretch()
        btn_ref = icon_button("act_refresh", "Actualiser")
        btn_ref.clicked.connect(self.refresh)
        hdr.addWidget(btn_ref)
        layout.addLayout(hdr)

        cols = ["ID", "Nom", "Type d'équipement", "Ports surveillés", "OIDs SNMP", "Description"]
        self._table = QTableWidget(0, len(cols))
        self._table.setHorizontalHeaderLabels(cols)
        self._table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self._table.verticalHeader().setVisible(False)
        self._table.setAlternatingRowColors(True)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setColumnWidth(0, 40)
        self._table.setColumnWidth(1, 160)
        self._table.setColumnWidth(2, 140)
        self._table.setColumnWidth(3, 140)
        self._table.setColumnWidth(4, 120)
        layout.addWidget(self._table)

    def refresh(self):
        if not self.db:
            return
        templates = self.db.get_templates()
        self._table.setRowCount(0)
        for t in templates:
            row = self._table.rowCount()
            self._table.insertRow(row)
            self._table.setRowHeight(row, 36)
            self._table.setItem(row, 0, QTableWidgetItem(str(t.get("id", ""))))
            self._table.setItem(row, 1, QTableWidgetItem(t.get("name", "")))
            self._table.setItem(row, 2, QTableWidgetItem(t.get("device_type", "")))
            self._table.setItem(row, 3, QTableWidgetItem(t.get("default_ports", "") or ""))
            self._table.setItem(row, 4, QTableWidgetItem(t.get("snmp_oids", "") or ""))
            self._table.setItem(row, 5, QTableWidgetItem(t.get("description", "") or ""))
