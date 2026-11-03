"""
HSR — Administration : Utilisateurs
Procus Tech

Identique à la maquette :
  Colonnes : Login | Nom complet | Rôle (badge) | Groupes | Dernière connexion | Statut | Actions (Modifier/Désactiver)
"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
    QDialog, QFormLayout, QLineEdit, QComboBox, QDialogButtonBox,
    QMessageBox, QCheckBox
)
from database.crypto_db import INTEGRITY_ERRORS
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont

from ui.styles import COLOR
from ui.icons import icon_button


ROLE_COLORS = {
    "super-admin": COLOR["red"],
    "operator":    COLOR["accent"],
    "read-only":   COLOR["text_sec"],
}


class UserDialog(QDialog):
    def __init__(self, db=None, user: dict = None, parent=None):
        super().__init__(parent)
        self.db = db
        self._user = user
        self._is_edit = user is not None
        self.setWindowTitle("Modifier l'utilisateur" if self._is_edit else "Nouvel utilisateur")
        self.setMinimumWidth(400)
        self.setModal(True)
        self._build()

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(14)

        form = QFormLayout()
        form.setSpacing(10)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        self._f_login     = QLineEdit()
        self._f_fullname  = QLineEdit()
        self._f_role      = QComboBox()
        self._f_role.addItems(["super-admin", "operator", "read-only"])
        self._f_password  = QLineEdit()
        self._f_password.setEchoMode(QLineEdit.EchoMode.Password)
        self._f_password.setPlaceholderText("Laisser vide pour ne pas changer" if self._is_edit else "")

        form.addRow("Login *",       self._f_login)
        form.addRow("Nom complet",   self._f_fullname)
        form.addRow("Rôle",          self._f_role)
        form.addRow("Mot de passe",  self._f_password)

        layout.addLayout(form)

        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btns.accepted.connect(self._validate)
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)

        if self._user:
            self._f_login.setText(self._user.get("login", ""))
            self._f_login.setReadOnly(True)
            self._f_fullname.setText(self._user.get("full_name", ""))
            idx = self._f_role.findText(self._user.get("role", "read-only"))
            if idx >= 0:
                self._f_role.setCurrentIndex(idx)

    def _validate(self):
        from core.security import InputValidator
        try:
            InputValidator.login(self._f_login.text())
        except ValueError as e:
            QMessageBox.warning(self, "Login invalide", str(e))
            return
        if not self._is_edit and not self._f_password.text():
            QMessageBox.warning(self, "Requis", "Le mot de passe est obligatoire pour un nouvel utilisateur.")
            return
        if self._f_password.text() and len(self._f_password.text()) < 6:
            QMessageBox.warning(self, "Mot de passe trop court",
                                "Le mot de passe doit contenir au moins 6 caractères.")
            return
        self.accept()

    def get_data(self) -> dict:
        return {
            "login":     self._f_login.text().strip(),
            "full_name": self._f_fullname.text().strip(),
            "role":      self._f_role.currentText(),
            "password":  self._f_password.text(),
        }


class UsersView(QWidget):

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
        title = QLabel("Administration — Utilisateurs")
        title.setStyleSheet(f"font-size: 14pt; font-weight: 700; color: {COLOR['text_pri']};")
        hdr.addWidget(title)
        hdr.addStretch()

        btn_add = QPushButton("+ Ajouter")
        btn_add.setObjectName("btn_primary")
        btn_add.clicked.connect(self._add_user)
        hdr.addWidget(btn_add)

        btn_ref = icon_button("act_refresh", "Actualiser")
        btn_ref.clicked.connect(self.refresh)
        hdr.addWidget(btn_ref)
        layout.addLayout(hdr)

        cols = ["Login", "Nom complet", "Rôle", "Groupes", "Dernière connexion", "Statut", "Actions"]
        self._table = QTableWidget(0, len(cols))
        self._table.setHorizontalHeaderLabels(cols)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._table.verticalHeader().setVisible(False)
        self._table.setAlternatingRowColors(True)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setColumnWidth(0, 120)
        self._table.setColumnWidth(2, 100)
        self._table.setColumnWidth(3, 120)
        self._table.setColumnWidth(4, 140)
        self._table.setColumnWidth(5, 80)
        self._table.setColumnWidth(6, 160)
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
        users = self.db.get_users()
        self._table.setRowCount(0)

        for user in users:
            row = self._table.rowCount()
            self._table.insertRow(row)
            self._table.setRowHeight(row, 38)

            self._table.setItem(row, 0, QTableWidgetItem(user.get("login", "")))
            self._table.setItem(row, 1, QTableWidgetItem(user.get("full_name", "") or ""))

            # Rôle avec badge coloré
            role = user.get("role", "read-only")
            role_color = ROLE_COLORS.get(role, "#c4bfae")
            role_item = QTableWidgetItem(role)
            role_item.setForeground(QColor(role_color))
            role_item.setFont(QFont("Segoe UI", 8, QFont.Weight.Bold))
            self._table.setItem(row, 2, role_item)

            self._table.setItem(row, 3, QTableWidgetItem(user.get("group_name", "") or ""))
            self._table.setItem(row, 4, QTableWidgetItem(str(user.get("last_login", "—"))[:16]))

            active = user.get("active", 1)
            status_item = QTableWidgetItem("Actif" if active else "Inactif")
            status_item.setForeground(QColor(COLOR["green"] if active else COLOR["red"]))
            self._table.setItem(row, 5, status_item)

            # Boutons
            btn_w = QWidget()
            btn_lay = QHBoxLayout(btn_w)
            btn_lay.setContentsMargins(4, 4, 4, 4)
            btn_lay.setSpacing(4)

            btn_edit = icon_button("act_edit", "Modifier")
            btn_edit.setFixedHeight(24)
            btn_edit.setStyleSheet(f"background:transparent;color:{COLOR['cyan']};border:1px solid {COLOR['cyan']};border-radius:3px;padding:1px 6px;font-size:7pt;")
            uc = dict(user)
            btn_edit.clicked.connect(lambda ch, u=uc: self._edit_user(u))

            lbl_toggle = "Désactiver" if active else "Activer"
            btn_toggle = QPushButton(lbl_toggle)
            btn_toggle.setFixedHeight(24)
            tc = COLOR["accent"] if active else COLOR["green"]
            btn_toggle.setStyleSheet(f"background:transparent;color:{tc};border:1px solid {tc};border-radius:3px;padding:1px 6px;font-size:7pt;")
            uid = user.get("id")
            new_active = 0 if active else 1
            btn_toggle.clicked.connect(lambda ch, uid_=uid, a=new_active: self._toggle_active(uid_, a))

            btn_lay.addWidget(btn_edit)
            btn_lay.addWidget(btn_toggle)
            btn_lay.addStretch()
            self._table.setCellWidget(row, 6, btn_w)

        self._lbl_count.setText(f"{self._table.rowCount()} utilisateur(s)")

    def _guard(self) -> bool:
        if self.security:
            try:
                self.security.require_permission("can_manage_users")
            except PermissionError as e:
                QMessageBox.warning(self, "Accès refusé", str(e))
                return False
        return True

    def _other_active_admins(self, exclude_id: int) -> int:
        return len([u for u in self.db.get_users()
                    if u["role"] == "super-admin" and u["active"] and u["id"] != exclude_id])

    def _add_user(self):
        if self.security:
            try:
                self.security.require_permission("can_manage_users")
            except PermissionError as e:
                QMessageBox.warning(self, "Accès refusé", str(e))
                return
        dlg = UserDialog(db=self.db, parent=self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            d = dlg.get_data()
            from core.security import SecurityManager
            pwd_hash = SecurityManager.hash_password(d["password"])
            import sqlite3
            try:
                self.db.execute("""
                    INSERT INTO users (login, full_name, role, password_hash, active)
                    VALUES (?, ?, ?, ?, 1)
                """, (d["login"], d["full_name"], d["role"], pwd_hash))
            except INTEGRITY_ERRORS:
                QMessageBox.warning(self, "Doublon", f"Le login « {d['login']} » existe déjà.")
                return
            self.refresh()

    def _edit_user(self, user: dict):
        if not self._guard():
            return
        dlg = UserDialog(db=self.db, user=user, parent=self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            d = dlg.get_data()
            if user.get("role") == "super-admin" and d["role"] != "super-admin" \
                    and self._other_active_admins(user["id"]) == 0:
                QMessageBox.warning(self, "Refusé", "Impossible de retirer le dernier super-admin actif.")
                return
            if d["password"]:
                from core.security import SecurityManager
                pwd_hash = SecurityManager.hash_password(d["password"])
                self.db.execute(
                    "UPDATE users SET full_name=?, role=?, password_hash=? WHERE id=?",
                    (d["full_name"], d["role"], pwd_hash, user["id"])
                )
            else:
                self.db.execute(
                    "UPDATE users SET full_name=?, role=? WHERE id=?",
                    (d["full_name"], d["role"], user["id"])
                )
            self.refresh()

    def _toggle_active(self, user_id: int, new_state: int):
        if not self._guard():
            return
        if not new_state:
            cur = (self.security.get_current_user() or {}) if self.security else {}
            target = next((u for u in self.db.get_users() if u["id"] == user_id), None)
            if target and cur.get("login") == target["login"]:
                QMessageBox.warning(self, "Refusé", "Vous ne pouvez pas désactiver votre propre compte.")
                return
            if target and target["role"] == "super-admin" and self._other_active_admins(user_id) == 0:
                QMessageBox.warning(self, "Refusé", "Impossible de désactiver le dernier super-admin actif.")
                return
        self.db.execute("UPDATE users SET active=? WHERE id=?", (new_state, user_id))
        self.refresh()
