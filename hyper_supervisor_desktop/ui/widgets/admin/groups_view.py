"""
HSR — Administration : Groupes d'hôtes
Procus Tech
"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
    QDialog, QFormLayout, QLineEdit, QDialogButtonBox, QMessageBox
)
from database.crypto_db import INTEGRITY_ERRORS
from PyQt6.QtCore import Qt
from ui.styles import COLOR
from ui.icons import icon_button


class GroupDialog(QDialog):
    def __init__(self, group: dict = None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Groupe d'hôtes")
        self.setMinimumWidth(340)
        self.setModal(True)
        layout = QVBoxLayout(self)
        form = QFormLayout()
        self._f_name = QLineEdit()
        self._f_desc = QLineEdit()
        form.addRow("Nom *", self._f_name)
        form.addRow("Description", self._f_desc)
        layout.addLayout(form)
        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btns.accepted.connect(self._validate)
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)
        if group:
            self._f_name.setText(group.get("name", ""))
            self._f_desc.setText(group.get("description", ""))

    def _validate(self):
        if not self._f_name.text().strip():
            QMessageBox.warning(self, "Requis", "Le nom est obligatoire.")
            return
        self.accept()

    def get_data(self) -> dict:
        return {
            "name":        self._f_name.text().strip(),
            "description": self._f_desc.text().strip(),
        }


class GroupsView(QWidget):

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
        title = QLabel("Administration — Groupes")
        title.setStyleSheet(f"font-size: 14pt; font-weight: 700; color: {COLOR['text_pri']};")
        hdr.addWidget(title)
        hdr.addStretch()
        btn_add = QPushButton("+ Ajouter")
        btn_add.setObjectName("btn_primary")
        btn_add.clicked.connect(self._add)
        hdr.addWidget(btn_add)
        btn_ref = icon_button("act_refresh", "Actualiser")
        btn_ref.clicked.connect(self.refresh)
        hdr.addWidget(btn_ref)
        layout.addLayout(hdr)

        cols = ["ID", "Nom", "Description", "Hôtes", "Problèmes", "Actions"]
        self._table = QTableWidget(0, len(cols))
        self._table.setHorizontalHeaderLabels(cols)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self._table.verticalHeader().setVisible(False)
        self._table.setAlternatingRowColors(True)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setColumnWidth(0, 40)
        self._table.setColumnWidth(3, 70)
        self._table.setColumnWidth(4, 80)
        self._table.setColumnWidth(5, 150)
        layout.addWidget(self._table)

    def refresh(self):
        if not self.db:
            return
        groups = self.db.get_host_groups()
        self._table.setRowCount(0)
        for g in groups:
            row = self._table.rowCount()
            self._table.insertRow(row)
            self._table.setRowHeight(row, 36)
            self._table.setItem(row, 0, QTableWidgetItem(str(g.get("id", ""))))
            self._table.setItem(row, 1, QTableWidgetItem(g.get("name", "")))
            self._table.setItem(row, 2, QTableWidgetItem(g.get("description", "") or ""))
            self._table.setItem(row, 3, QTableWidgetItem(str(g.get("host_count", 0))))
            self._table.setItem(row, 4, QTableWidgetItem(str(g.get("problem_count", 0))))

            btn_w = QWidget()
            btn_lay = QHBoxLayout(btn_w)
            btn_lay.setContentsMargins(4, 4, 4, 4)
            btn_lay.setSpacing(4)

            btn_edit = icon_button("act_edit", "Modifier")
            btn_edit.setFixedHeight(24)
            btn_edit.setStyleSheet(f"background:transparent;color:{COLOR['cyan']};border:1px solid {COLOR['cyan']};border-radius:3px;padding:1px 6px;font-size:7pt;")
            gc = dict(g)
            btn_edit.clicked.connect(lambda ch, gp=gc: self._edit(gp))

            btn_del = icon_button("act_delete", "")
            btn_del.setFixedSize(28, 24)
            btn_del.setStyleSheet(f"background:transparent;color:{COLOR['red']};border:1px solid {COLOR['red']};border-radius:3px;padding:1px 4px;font-size:8pt;")
            gid = g.get("id")
            btn_del.clicked.connect(lambda ch, gid_=gid: self._delete(gid_))

            btn_lay.addWidget(btn_edit)
            btn_lay.addWidget(btn_del)
            btn_lay.addStretch()
            self._table.setCellWidget(row, 5, btn_w)

    def _check(self) -> bool:
        if self.security:
            try:
                self.security.require_permission("can_manage_config")
            except PermissionError as e:
                QMessageBox.warning(self, "Accès refusé", str(e))
                return False
        return True

    def _save(self, sql: str, params: tuple) -> bool:
        import sqlite3
        try:
            self.db.execute(sql, params)
            return True
        except INTEGRITY_ERRORS:
            QMessageBox.warning(self, "Doublon", "Un groupe portant ce nom existe déjà.")
            return False

    def _add(self):
        if not self._check():
            return
        dlg = GroupDialog(parent=self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            d = dlg.get_data()
            if self._save("INSERT INTO host_groups (name, description) VALUES (?, ?)",
                          (d["name"], d["description"])):
                self.refresh()

    def _edit(self, group: dict):
        if not self._check():
            return
        dlg = GroupDialog(group=group, parent=self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            d = dlg.get_data()
            if self._save("UPDATE host_groups SET name=?, description=? WHERE id=?",
                          (d["name"], d["description"], group["id"])):
                self.refresh()

    def _delete(self, gid: int):
        if not self._check():
            return
        row = self.db.fetchone("SELECT COUNT(*) AS n FROM hosts WHERE group_id=?", (gid,))
        n = (row or {}).get("n", 0) if isinstance(row, dict) else (row[0] if row else 0)
        if n:
            QMessageBox.warning(
                self, "Suppression impossible",
                f"Ce groupe contient {n} hôte(s). Déplacez-les ou supprimez-les d'abord.")
            return
        reply = QMessageBox.question(self, "Confirmation", "Supprimer ce groupe ?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            try:
                self.db.execute("DELETE FROM host_groups WHERE id=?", (gid,))
            except Exception as e:
                QMessageBox.warning(self, "Erreur", str(e))
            self.refresh()
