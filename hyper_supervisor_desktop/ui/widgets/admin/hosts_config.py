"""
HSR — Administration : Hôtes
Procus Tech

Gestion CRUD des équipements supervisés.
"""
from database.crypto_db import INTEGRITY_ERRORS
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
    QDialog, QFormLayout, QLineEdit, QComboBox, QDialogButtonBox,
    QMessageBox, QFrame
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor

from ui.styles import COLOR, STATUS_COLORS
from ui.icons import icon_button


class HostDialog(QDialog):
    """Dialogue ajout / modification d'un hôte."""

    def __init__(self, db=None, host: dict = None, parent=None):
        super().__init__(parent)
        self.db = db
        self._host = host
        self.setWindowTitle("Ajouter un hôte" if host is None else "Modifier l'hôte")
        self.setMinimumWidth(420)
        self.setModal(True)
        self._build()

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(16)

        form = QFormLayout()
        form.setSpacing(10)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        self._f_name      = QLineEdit()
        self._f_ip        = QLineEdit()
        self._f_community = QLineEdit("public")
        self._f_location  = QLineEdit()
        self._f_type      = QComboBox()
        self._f_type.addItems(["router", "switch", "firewall", "server", "workstation", "ap", "unknown"])
        self._f_group     = QComboBox()
        self._f_group.addItem("Aucun groupe", None)
        if self.db:
            for g in self.db.get_host_groups():
                self._f_group.addItem(g["name"], g["id"])

        form.addRow("Nom *",            self._f_name)
        form.addRow("Adresse IP *",     self._f_ip)
        form.addRow("Communauté SNMP",  self._f_community)
        form.addRow("Type",             self._f_type)
        form.addRow("Groupe",           self._f_group)
        form.addRow("Localisation",     self._f_location)

        layout.addLayout(form)

        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btns.accepted.connect(self._validate)
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)

        if self._host:
            self._f_name.setText(self._host.get("name", ""))
            self._f_ip.setText(self._host.get("ip_address", ""))
            self._f_community.setText(self._host.get("snmp_community", "public"))
            self._f_location.setText(self._host.get("location", ""))
            idx = self._f_type.findText(self._host.get("device_type", "unknown"))
            if idx >= 0:
                self._f_type.setCurrentIndex(idx)

    def _validate(self):
        from core.security import InputValidator
        try:
            InputValidator.name(self._f_name.text())
            InputValidator.ip_address(self._f_ip.text())
            InputValidator.snmp_community(self._f_community.text())
        except ValueError as e:
            QMessageBox.warning(self, "Saisie invalide", str(e))
            return
        self.accept()

    def get_data(self) -> dict:
        return {
            "name":           self._f_name.text().strip(),
            "ip_address":     self._f_ip.text().strip(),
            "snmp_community": self._f_community.text().strip() or "public",
            "device_type":    self._f_type.currentText(),
            "group_id":       self._f_group.currentData(),
            "location":       self._f_location.text().strip(),
        }


class HostsConfigView(QWidget):

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
        title = QLabel("Administration — Hôtes")
        title.setStyleSheet(f"font-size: 14pt; font-weight: 700; color: {COLOR['text_pri']};")
        hdr.addWidget(title)
        hdr.addStretch()

        btn_add = QPushButton("+ Ajouter un hôte")
        btn_add.setObjectName("btn_primary")
        btn_add.clicked.connect(self._add_host)
        hdr.addWidget(btn_add)

        btn_refresh = icon_button("act_refresh", "Actualiser")
        btn_refresh.clicked.connect(self.refresh)
        hdr.addWidget(btn_refresh)
        layout.addLayout(hdr)

        cols = ["ID", "Nom", "IP", "Type", "Groupe", "Statut", "Localisation", "Dernier contrôle", "Actions"]
        self._table = QTableWidget(0, len(cols))
        self._table.setHorizontalHeaderLabels(cols)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        self._table.verticalHeader().setVisible(False)
        self._table.setAlternatingRowColors(True)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setColumnWidth(0, 40)
        self._table.setColumnWidth(2, 110)
        self._table.setColumnWidth(3, 90)
        self._table.setColumnWidth(4, 110)
        self._table.setColumnWidth(5, 90)
        self._table.setColumnWidth(7, 140)
        self._table.setColumnWidth(8, 160)
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
        hosts = self.db.get_all_hosts()
        self._table.setRowCount(0)

        for host in hosts:
            row = self._table.rowCount()
            self._table.insertRow(row)
            self._table.setRowHeight(row, 36)

            self._table.setItem(row, 0, QTableWidgetItem(str(host.get("id", ""))))
            self._table.setItem(row, 1, QTableWidgetItem(host.get("name", "")))
            self._table.setItem(row, 2, QTableWidgetItem(host.get("ip_address", "")))
            self._table.setItem(row, 3, QTableWidgetItem(host.get("device_type", "")))
            self._table.setItem(row, 4, QTableWidgetItem(host.get("group_name", "") or ""))

            status = host.get("status", "unknown")
            status_item = QTableWidgetItem(status.capitalize())
            status_item.setForeground(QColor(STATUS_COLORS.get(status, "#c4bfae")))
            self._table.setItem(row, 5, status_item)

            self._table.setItem(row, 6, QTableWidgetItem(host.get("location", "")))
            self._table.setItem(row, 7, QTableWidgetItem(str(host.get("last_check", "—"))[:16]))

            # Boutons actions
            btn_w = QWidget()
            btn_lay = QHBoxLayout(btn_w)
            btn_lay.setContentsMargins(4, 4, 4, 4)
            btn_lay.setSpacing(4)

            btn_edit = icon_button("act_edit", "Modifier")
            btn_edit.setFixedHeight(24)
            btn_edit.setStyleSheet(f"""
                QPushButton {{
                    background: transparent; color: {COLOR['cyan']};
                    border: 1px solid {COLOR['cyan']}; border-radius: 3px;
                    padding: 1px 6px; font-size: 7pt;
                }}
                QPushButton:hover {{ background: {COLOR['cyan']}; color: #0b0b0a; }}
            """)
            host_copy = dict(host)
            btn_edit.clicked.connect(lambda ch, h=host_copy: self._edit_host(h))

            btn_del = icon_button("act_delete", "")
            btn_del.setFixedHeight(24)
            btn_del.setFixedWidth(28)
            btn_del.setStyleSheet(f"""
                QPushButton {{
                    background: transparent; color: {COLOR['red']};
                    border: 1px solid {COLOR['red']}; border-radius: 3px;
                    padding: 1px 4px; font-size: 8pt;
                }}
                QPushButton:hover {{ background: {COLOR['red']}; color: #fff; }}
            """)
            hid = host.get("id")
            btn_del.clicked.connect(lambda ch, hid_=hid: self._delete_host(hid_))

            btn_lay.addWidget(btn_edit)
            btn_lay.addWidget(btn_del)
            btn_lay.addStretch()
            self._table.setCellWidget(row, 8, btn_w)

        self._lbl_count.setText(f"{self._table.rowCount()} hôte(s)")

    def _add_host(self):
        if self.security:
            try:
                self.security.require_permission("can_add_host")
            except PermissionError as e:
                QMessageBox.warning(self, "Accès refusé", str(e))
                return
        dlg = HostDialog(db=self.db, parent=self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            data = dlg.get_data()
            import sqlite3
            try:
                self.db.add_host(
                    name=data["name"], ip=data["ip_address"],
                    group_id=data["group_id"], device_type=data["device_type"],
                    location=data["location"], snmp_community=data["snmp_community"]
                )
            except INTEGRITY_ERRORS:
                QMessageBox.warning(self, "Doublon", "Un hôte avec ce nom ou cette adresse IP existe déjà.")
                return
            self.refresh()

    def _edit_host(self, host: dict):
        if self.security:
            try:
                self.security.require_permission("can_edit_host")
            except PermissionError as e:
                QMessageBox.warning(self, "Accès refusé", str(e))
                return
        dlg = HostDialog(db=self.db, host=host, parent=self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            data = dlg.get_data()
            # Chiffrer la communauté SNMP avant mise à jour
            encrypted_community = self.db._encrypt_community(data["snmp_community"])
            import sqlite3
            try:
              self.db.execute("""
                UPDATE hosts SET name=?, ip_address=?, snmp_community=?, device_type=?,
                                 group_id=?, location=?, snmp_enabled=1,
                                 updated_at=datetime('now')
                WHERE id=?
            """, (data["name"], data["ip_address"], encrypted_community,
                  data["device_type"], data["group_id"], data["location"], host["id"]))
            except INTEGRITY_ERRORS:
                QMessageBox.warning(self, "Doublon", "Un hôte avec ce nom ou cette adresse IP existe déjà.")
                return
            self.refresh()

    def _delete_host(self, host_id: int):
        if self.security:
            try:
                self.security.require_permission("can_delete_host")
            except PermissionError as e:
                QMessageBox.warning(self, "Accès refusé", str(e))
                return
        reply = QMessageBox.question(
            self, "Confirmation",
            "Supprimer cet hôte et toutes ses données ?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.db.execute("DELETE FROM hosts WHERE id=?", (host_id,))
            self.refresh()
