#!/usr/bin/env python3
"""
Procus Secure — Network Supervision
Procus Tech | Protéger · Surveiller · Contrôler

Point d'entrée principal de l'application desktop.
"""
import os
import sys
from pathlib import Path

os.environ.setdefault("QT_AUTO_SCREEN_SCALE_FACTOR", "1")

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QPixmap
from PyQt6.QtWidgets import (
    QApplication,
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
)

from database.db_manager import DatabaseManager
from core.security import SecurityManager


# ─────────────────────────────────────────────────────────────────
# Styles de la fenêtre de connexion — cohérent Procus Secure
# ─────────────────────────────────────────────────────────────────

LOGIN_QSS = """
QDialog {
    background-color: #1F2D40;
}
QWidget {
    background-color: #1F2D40;
    color: #D9E5F0;
    font-family: "DejaVu Sans", "Segoe UI", sans-serif;
    font-size: 9pt;
}
QLineEdit {
    background-color: #1A2538;
    border: 1px solid #2E4260;
    border-radius: 4px;
    color: #D9E5F0;
    padding: 9px 12px;
    font-size: 9.5pt;
}
QLineEdit:focus {
    border-color: #E45516;
}
QPushButton#btn_login {
    background-color: #E45516;
    color: #ffffff;
    border: none;
    border-radius: 4px;
    padding: 10px;
    font-size: 9.5pt;
    font-weight: 700;
}
QPushButton#btn_login:hover  { background-color: #C94B12; }
QPushButton#btn_login:pressed { background-color: #A83E0F; }
"""


# ─────────────────────────────────────────────────────────────────
# Icône SVG login (shield Procus)
# ─────────────────────────────────────────────────────────────────

def _render_shield(size: int = 56, color: str = "#E45516") -> QPixmap:
    """Rendu du bouclier Procus en SVG inline."""
    try:
        from PyQt6.QtCore import QByteArray
        from PyQt6.QtGui import QImage, QPainter
        from PyQt6.QtSvg import QSvgRenderer

        svg = (
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"'
            f' width="{size}" height="{size}" fill="none"'
            f' stroke="{color}" stroke-width="1.6"'
            f' stroke-linecap="round" stroke-linejoin="round">'
            f'<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>'
            f'</svg>'
        )
        renderer = QSvgRenderer(QByteArray(svg.encode()))
        img = QImage(size, size, QImage.Format.Format_ARGB32)
        img.fill(0)
        painter = QPainter(img)
        renderer.render(painter)
        painter.end()
        return QPixmap.fromImage(img)
    except (RuntimeError, TypeError, ValueError):
        pix = QPixmap(size, size)
        pix.fill(Qt.GlobalColor.transparent)
        return pix


# ─────────────────────────────────────────────────────────────────
# Écran de connexion — Procus Secure
# ─────────────────────────────────────────────────────────────────

class LoginDialog(QDialog):
    """Fenêtre d'authentification Procus Secure."""

    def __init__(self, security: SecurityManager, session_expired: bool = False,
                 parent=None):
        super().__init__(parent)
        self.security = security
        self._user: dict | None = None
        self._session_expired = session_expired

        self.setWindowTitle("Procus Secure — Connexion")
        self.setFixedSize(420, 500)
        self.setModal(True)
        self.setStyleSheet(LOGIN_QSS)
        # Empêcher la fermeture via la croix sans authentification
        self.setWindowFlag(Qt.WindowType.WindowCloseButtonHint, False)
        self._build()

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(44, 44, 44, 36)
        layout.setSpacing(0)

        # ── Header : logo + nom ──
        hdr = QHBoxLayout()
        hdr.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hdr.setSpacing(14)

        # Logo Procus (image ou shield SVG)
        logo_path = Path(__file__).parent / "assets" / "logo_procus.jpg"
        logo_lbl = QLabel()
        logo_lbl.setFixedSize(52, 52)
        logo_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        if logo_path.exists():
            pix = QPixmap(str(logo_path)).scaled(
                52, 52,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation
            )
            logo_lbl.setPixmap(pix)
            logo_lbl.setStyleSheet("border-radius: 8px; background: transparent;")
        else:
            logo_lbl.setPixmap(_render_shield(52, "#E45516"))
            logo_lbl.setStyleSheet("background: transparent;")

        name_col = QVBoxLayout()
        name_col.setSpacing(2)
        lbl_name = QLabel("Procus Secure")
        lbl_name.setStyleSheet(
            "font-size: 15pt; font-weight: 800; color: #D9E5F0; "
            "letter-spacing: 0.5px; background: transparent;"
        )
        lbl_sub = QLabel("SUPERVISION RÉSEAU")
        lbl_sub.setStyleSheet(
            "font-size: 7pt; font-weight: 700; color: #E45516; "
            "letter-spacing: 2px; background: transparent;"
        )
        name_col.addWidget(lbl_name)
        name_col.addWidget(lbl_sub)

        hdr.addWidget(logo_lbl)
        hdr.addLayout(name_col)
        layout.addLayout(hdr)
        layout.addSpacing(24)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setFixedHeight(1)
        sep.setStyleSheet("background: #2E4260; border: none;")
        layout.addWidget(sep)
        layout.addSpacing(24)

        # ── Avertissement expiration de session ──
        if self._session_expired:
            warn = QLabel("⏱  Session expirée — veuillez vous reconnecter")
            warn.setAlignment(Qt.AlignmentFlag.AlignCenter)
            warn.setStyleSheet(
                "color: #D4AC0D; font-size: 8pt; font-weight: 600; "
                "background: #D4AC0D18; border: 1px solid #D4AC0D44; "
                "border-radius: 4px; padding: 6px;"
            )
            layout.addWidget(warn)
            layout.addSpacing(14)

        # ── Champs ──
        lbl_login = QLabel("IDENTIFIANT")
        lbl_login.setStyleSheet("color: #7A9BBE; font-size: 7.5pt; font-weight: 700; "
                                "letter-spacing: 0.8px; background: transparent;")
        self._f_login = QLineEdit()
        self._f_login.setPlaceholderText("admin")
        self._f_login.setFixedHeight(40)
        layout.addWidget(lbl_login)
        layout.addSpacing(4)
        layout.addWidget(self._f_login)
        layout.addSpacing(14)

        lbl_pwd = QLabel("MOT DE PASSE")
        lbl_pwd.setStyleSheet("color: #7A9BBE; font-size: 7.5pt; font-weight: 700; "
                              "letter-spacing: 0.8px; background: transparent;")
        self._f_pwd = QLineEdit()
        self._f_pwd.setEchoMode(QLineEdit.EchoMode.Password)
        self._f_pwd.setPlaceholderText("••••••••")
        self._f_pwd.setFixedHeight(40)
        self._f_pwd.returnPressed.connect(self._try_login)
        layout.addWidget(lbl_pwd)
        layout.addSpacing(4)
        layout.addWidget(self._f_pwd)
        layout.addSpacing(8)

        # Message d'erreur
        self._lbl_error = QLabel()
        self._lbl_error.setStyleSheet(
            "color: #C0392B; font-size: 8pt; background: #C0392B14; "
            "border: 1px solid #C0392B44; border-radius: 3px; padding: 5px;"
        )
        self._lbl_error.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._lbl_error.hide()
        layout.addWidget(self._lbl_error)
        layout.addSpacing(18)

        # Bouton connexion
        btn = QPushButton("Se connecter")
        btn.setObjectName("btn_login")
        btn.setFixedHeight(44)
        btn.clicked.connect(self._try_login)
        layout.addWidget(btn)

        layout.addStretch()

        hint = QLabel("Connexion par défaut : admin / admin")
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hint.setStyleSheet("color: #3D5A80; font-size: 7pt; background: transparent;")
        layout.addWidget(hint)

    def _try_login(self):
        login = self._f_login.text().strip()
        password = self._f_pwd.text()

        # Validation basique
        if not login or not password:
            self._show_error("Identifiant et mot de passe requis.")
            return
        if len(login) > 64 or len(password) > 256:
            self._show_error("Identifiants invalides.")
            return

        user = self.security.authenticate(login, password)
        if user:
            self._user = user
            self.accept()
        else:
            self._show_error("Identifiants incorrects. Réessayez.")
            self._f_pwd.clear()
            self._f_pwd.setFocus()

    def _show_error(self, msg: str):
        self._lbl_error.setText(msg)
        self._lbl_error.show()

    def get_user(self) -> dict | None:
        return self._user

    def keyPressEvent(self, event):
        """Bloquer Escape pour ne pas fermer la dialog sans authentification."""
        if event.key() == Qt.Key.Key_Escape:
            return
        super().keyPressEvent(event)


# ─────────────────────────────────────────────────────────────────
# Gestion du cycle de vie : fenêtre principale + re-login
# ─────────────────────────────────────────────────────────────────

class AppController:
    """
    Orchestre le cycle fenêtre principale ↔ LoginDialog.
    Écoute session_expired et réaffiche LoginDialog proprement.
    """

    def __init__(self, app: QApplication, db: DatabaseManager,
                 security: SecurityManager):
        self.app      = app
        self.db       = db
        self.security = security
        self._window  = None

    def run(self):
        """Premier login + boucle d'événements Qt."""
        if not self._show_login(session_expired=False):
            sys.exit(0)
        self._open_main_window()
        sys.exit(self.app.exec())

    def _show_login(self, session_expired: bool = False) -> bool:
        """Affiche LoginDialog ; retourne True si authentifié."""
        dlg = LoginDialog(self.security, session_expired=session_expired)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return False
        self._current_user = dlg.get_user()
        return True

    def _open_main_window(self):
        from ui.main_window import MainWindow
        self._window = MainWindow(db=self.db, security=self.security)
        self._window.set_current_user(self._current_user)
        # ── Point 6 : session_expired → re-login ──
        self._window.session_expired.connect(self._on_session_expired)
        self._window.show()

    def _on_session_expired(self):
        """Session expirée : masque la fenêtre principale, réaffiche login."""
        from loguru import logger
        logger.info("[APP] Session expirée — verrouillage de l'interface.")
        if self._window:
            self._window.hide()

        if self._show_login(session_expired=True):
            self._window.set_current_user(self._current_user)
            self._window.show()
        else:
            # L'utilisateur a fermé le login sans s'authentifier → quitter
            self.app.quit()


# ─────────────────────────────────────────────────────────────────
# Point d'entrée
# ─────────────────────────────────────────────────────────────────

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Procus Secure")
    app.setOrganizationName("Procus Tech")
    app.setApplicationVersion("1.0.0")

    font = QFont("DejaVu Sans", 9)
    app.setFont(font)

    # ── Base de données ──
    db = DatabaseManager()
    db.initialize()

    # ── Sécurité ──
    security = SecurityManager(db)
    security.verify_db_integrity()

    # ── Lancement ──
    controller = AppController(app, db, security)
    controller.run()


if __name__ == "__main__":
    main()
