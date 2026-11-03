#!/usr/bin/env python3
"""
Procus Secure — Network Supervision
Procus Tech | Protéger · Surveiller · Contrôler

Point d'entrée principal de l'application desktop.
"""
import sys
import os
from pathlib import Path

os.environ.setdefault("QT_AUTO_SCREEN_SCALE_FACTOR", "1")

from PyQt6.QtWidgets import (
    QApplication, QDialog, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QFrame, QMessageBox, QWidget
)
from PyQt6.QtCore import Qt, QTimer, QMetaObject
from PyQt6.QtGui import QFont, QPixmap

from database.db_manager import DatabaseManager
from core.security import SecurityManager


# ─────────────────────────────────────────────────────────────────
# Styles de la fenêtre de connexion — cohérent Procus Secure
# ─────────────────────────────────────────────────────────────────

LOGIN_QSS = """
QDialog {
    background-color: #0e0e0c;
}
QWidget {
    background-color: #0e0e0c;
    color: #ffffff;
    font-family: "Marianne", "Public Sans", "Segoe UI", sans-serif;
    font-size: 9pt;
}
QLineEdit {
    background-color: #12110e;
    border: 1px solid #3a3524;
    border-radius: 4px;
    color: #ffffff;
    padding: 9px 12px;
    font-size: 9.5pt;
}
QLineEdit:focus {
    border-color: #d4af37;
}
QPushButton#btn_login {
    background-color: #d4af37;
    color: #ffffff;
    border: none;
    border-radius: 4px;
    padding: 10px;
    font-size: 9.5pt;
    font-weight: 700;
}
QPushButton#btn_login:hover  { background-color: #b8962e; }
QPushButton#btn_login:pressed { background-color: #9a7b24; }
"""


# ─────────────────────────────────────────────────────────────────
# Icône SVG login (shield Procus)
# ─────────────────────────────────────────────────────────────────

def _render_shield(size: int = 56, color: str = "#d4af37") -> QPixmap:
    """Rendu du bouclier Procus en SVG inline."""
    try:
        from PyQt6.QtSvg import QSvgRenderer
        from PyQt6.QtCore import QByteArray
        from PyQt6.QtGui import QImage, QPainter
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
        p = QPainter(img)
        renderer.render(p)
        p.end()
        return QPixmap.fromImage(img)
    except Exception:
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
            logo_lbl.setPixmap(_render_shield(52, "#d4af37"))
            logo_lbl.setStyleSheet("background: transparent;")

        name_col = QVBoxLayout()
        name_col.setSpacing(2)
        lbl_name = QLabel("Procus Secure")
        lbl_name.setStyleSheet(
            "font-size: 15pt; font-weight: 800; color: #ffffff; "
            "letter-spacing: 0.5px; background: transparent;"
        )
        lbl_sub = QLabel("SUPERVISION RÉSEAU")
        lbl_sub.setStyleSheet(
            "font-size: 7pt; font-weight: 700; color: #d4af37; "
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
        sep.setStyleSheet("background: #3a3524; border: none;")
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
        lbl_login.setStyleSheet("color: #d6d1c4; font-size: 7.5pt; font-weight: 700; "
                                "letter-spacing: 0.8px; background: transparent;")
        self._f_login = QLineEdit()
        self._f_login.setPlaceholderText("admin")
        self._f_login.setFixedHeight(40)
        layout.addWidget(lbl_login)
        layout.addSpacing(4)
        layout.addWidget(self._f_login)
        layout.addSpacing(14)

        lbl_pwd = QLabel("MOT DE PASSE")
        lbl_pwd.setStyleSheet("color: #d6d1c4; font-size: 7.5pt; font-weight: 700; "
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
            "color: #ef5b4b; font-size: 8pt; background: #C0392B14; "
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

        if self._admin_has_default_password():
            hint = QLabel("Première connexion : admin / admin — changez ce mot de passe.")
            hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
            hint.setStyleSheet("color: #D4AC0D; font-size: 7pt; background: transparent;")
            layout.addWidget(hint)

    def _admin_has_default_password(self) -> bool:
        """Vrai tant que le compte admin utilise encore le mot de passe d'usine."""
        try:
            row = self.security.db.fetchone("SELECT password_hash FROM users WHERE login='admin'")
            return bool(row) and self.security.verify_password("admin", row["password_hash"])
        except Exception:
            return False

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

        remaining = self.security.lockout_remaining(login)
        if remaining > 0:
            self._show_error(f"Trop de tentatives. Réessayez dans {remaining} s.")
            self._f_pwd.clear()
            return

        user = self.security.authenticate(login, password)
        if user:
            self._user = user
            self.accept()
        else:
            remaining = self.security.lockout_remaining(login)
            if remaining > 0:
                self._show_error(f"Compte verrouillé {remaining} s après trop d'échecs.")
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
# Écran de changement de mot de passe obligatoire (première connexion)
# ─────────────────────────────────────────────────────────────────

class ChangePasswordDialog(QDialog):
    """Forcer le changement du mot de passe au premier lancement (password_changed=0)."""

    def __init__(self, user: dict, security: SecurityManager, parent=None):
        super().__init__(parent)
        self.user = user
        self.security = security
        self._success = False

        self.setWindowTitle("Procus Secure — Changement de mot de passe")
        self.setFixedSize(480, 380)
        self.setModal(True)
        self.setStyleSheet(LOGIN_QSS)
        self.setWindowFlag(Qt.WindowType.WindowCloseButtonHint, False)
        self._build()

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(44, 44, 44, 36)
        layout.setSpacing(0)

        # ── Header ──
        title = QLabel("⚠  Changement de mot de passe obligatoire")
        title.setStyleSheet(
            "font-size: 12pt; font-weight: 700; color: #ffffff; "
            "letter-spacing: 0.5px; background: transparent;"
        )
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        layout.addSpacing(12)

        hint = QLabel(
            "Le compte « admin » utilise encore le mot de passe d'usine.\n"
            "Vous devez le changer maintenant pour continuer."
        )
        hint.setStyleSheet(
            "color: #D4AC0D; font-size: 8.5pt; font-weight: 500; "
            "background: transparent; line-height: 140%;"
        )
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hint.setWordWrap(True)
        layout.addWidget(hint)
        layout.addSpacing(20)

        # ── Mot de passe actuel ──
        lbl_current = QLabel("MOT DE PASSE ACTUEL")
        lbl_current.setStyleSheet(
            "color: #d6d1c4; font-size: 7.5pt; font-weight: 700; "
            "letter-spacing: 0.8px; background: transparent;"
        )
        self._f_current = QLineEdit()
        self._f_current.setEchoMode(QLineEdit.EchoMode.Password)
        self._f_current.setPlaceholderText("admin")
        self._f_current.setFixedHeight(40)
        layout.addWidget(lbl_current)
        layout.addSpacing(4)
        layout.addWidget(self._f_current)
        layout.addSpacing(12)

        # ── Nouveau mot de passe ──
        lbl_new = QLabel("NOUVEAU MOT DE PASSE")
        lbl_new.setStyleSheet(
            "color: #d6d1c4; font-size: 7.5pt; font-weight: 700; "
            "letter-spacing: 0.8px; background: transparent;"
        )
        self._f_new = QLineEdit()
        self._f_new.setEchoMode(QLineEdit.EchoMode.Password)
        self._f_new.setPlaceholderText("••••••••")
        self._f_new.setFixedHeight(40)
        layout.addWidget(lbl_new)
        layout.addSpacing(4)
        layout.addWidget(self._f_new)
        layout.addSpacing(12)

        # ── Confirmation ──
        lbl_confirm = QLabel("CONFIRMER")
        lbl_confirm.setStyleSheet(
            "color: #d6d1c4; font-size: 7.5pt; font-weight: 700; "
            "letter-spacing: 0.8px; background: transparent;"
        )
        self._f_confirm = QLineEdit()
        self._f_confirm.setEchoMode(QLineEdit.EchoMode.Password)
        self._f_confirm.setPlaceholderText("••••••••")
        self._f_confirm.setFixedHeight(40)
        self._f_confirm.returnPressed.connect(self._try_change)
        layout.addWidget(lbl_confirm)
        layout.addSpacing(4)
        layout.addWidget(self._f_confirm)
        layout.addSpacing(12)

        # ── Message d'erreur ──
        self._lbl_error = QLabel()
        self._lbl_error.setStyleSheet(
            "color: #ef5b4b; font-size: 8pt; background: #C0392B14; "
            "border: 1px solid #C0392B44; border-radius: 3px; padding: 5px;"
        )
        self._lbl_error.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._lbl_error.hide()
        layout.addWidget(self._lbl_error)
        layout.addSpacing(12)

        # ── Bouton ──
        btn = QPushButton("Changer et continuer")
        btn.setObjectName("btn_login")
        btn.setFixedHeight(44)
        btn.clicked.connect(self._try_change)
        layout.addWidget(btn)
        layout.addStretch()

    def _try_change(self):
        current = self._f_current.text()
        new_pwd = self._f_new.text()
        confirm = self._f_confirm.text()

        # Validations
        if not current or not new_pwd or not confirm:
            self._show_error("Tous les champs sont obligatoires.")
            return

        if len(new_pwd) < 8:
            self._show_error("Le nouveau mot de passe doit contenir au moins 8 caractères.")
            return

        if new_pwd != confirm:
            self._show_error("Les deux mots de passe ne correspondent pas.")
            return

        # Vérifier que le mot de passe actuel est correct
        if not self.security.verify_password(current, self.user.get("password_hash", "")):
            self._show_error("Le mot de passe actuel est incorrect.")
            self._f_current.clear()
            self._f_current.setFocus()
            return

        if new_pwd == current or new_pwd.lower() == "admin":
            self._show_error("Choisissez un mot de passe différent de l'ancien et de « admin ».")
            return

        # Changer le mot de passe en base (même hachage que le reste de l'application)
        try:
            self.security.db.execute(
                "UPDATE users SET password_hash = ?, password_changed = 1 WHERE login = ?",
                (self.security.hash_password(new_pwd), self.user["login"])
            )
            try:
                self.security.db.write_audit(
                    username=self.user["login"], action="PASSWORD_CHANGED",
                    detail="Changement obligatoire du mot de passe d'usine",
                    user_id=self.user.get("id"))
            except Exception:
                pass
            self._success = True
            self.accept()
        except Exception as e:
            self._show_error(f"Erreur lors du changement : {e}")

    def _show_error(self, msg: str):
        self._lbl_error.setText(msg)
        self._lbl_error.show()

    def is_success(self) -> bool:
        return self._success

    def keyPressEvent(self, event):
        """Bloquer Escape."""
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

        # ── Première connexion : le mot de passe d'usine doit être changé avant d'entrer ──
        if self._must_change_password(self._current_user):
            change_dlg = ChangePasswordDialog(self._current_user, self.security)
            if change_dlg.exec() != QDialog.DialogCode.Accepted:
                sys.exit(0)
            self._current_user = self.db.fetchone(
                "SELECT * FROM users WHERE login = ?", (self._current_user["login"],)) or self._current_user

        self._open_main_window()
        if getattr(self, "_integrity_ok", True) is False:
            QMessageBox.warning(
                self._window, "Journal d'audit",
                "⚠ Des entrées du journal d'audit ne correspondent pas à leur signature HMAC.\n"
                "Le journal a pu être altéré (ou la clé HMAC a changé).\n"
                "Consultez les logs pour le détail."
            )
        self.app.aboutToQuit.connect(self._stop_workers)   # arrêt propre des QThread
        sys.exit(self.app.exec())

    def _must_change_password(self, user: dict | None) -> bool:
        """Vrai si le compte utilise encore le mot de passe d'usine « admin » (les anciennes bases où il a
        déjà été changé ne sont pas concernées)."""
        if not user or user.get("password_changed"):
            return False
        try:
            return self.security.verify_password("admin", user.get("password_hash", ""))
        except Exception:
            return False

    def _show_login(self, session_expired: bool = False) -> bool:
        """Affiche LoginDialog ; retourne True si authentifié."""
        dlg = LoginDialog(self.security, session_expired=session_expired)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return False
        self._current_user = dlg.get_user()
        return True

    def _open_main_window(self):
        from PyQt6.QtCore import QThread
        from ui.main_window import MainWindow
        from core.scanner import ScannerWorker
        from core.monitor import MonitorWorker
        from core.network_setup import NetworkSetupWorker

        # ── Écran de chargement animé (n'empêche jamais le démarrage s'il échoue) ──
        splash = None
        if not os.environ.get("PROCUS_NO_SPLASH"):
            try:
                from ui.splash import SplashScreen
                splash = SplashScreen()
                splash.start()
                splash.set_progress(4, "Initialisation des systèmes de sécurité…")
            except Exception:
                splash = None
        step = (lambda pct, txt: splash.set_progress(pct, txt)) if splash else (lambda pct, txt: None)

        self._window = MainWindow(db=self.db, security=self.security, progress=step)
        step(52, "Chargement de la supervision…")
        self._window.set_current_user(self._current_user)
        # ── Point 6 : session_expired → re-login ──
        self._window.session_expired.connect(self._on_session_expired)

        step(60, "Démarrage des moteurs d'analyse…")
        # ── Points 2–4 : ScannerWorker dans son propre QThread ──
        self._scanner_thread = QThread()
        self._scanner_worker = ScannerWorker(
            db_manager=self.db, security=self.security
        )
        self._scanner_worker.moveToThread(self._scanner_thread)
        self._scanner_thread.start()
        self._window.connect_scanner_worker(self._scanner_worker)

        # ── Point 3 : MonitorWorker dans son propre QThread ──
        self._monitor_thread = QThread()
        self._monitor_worker = MonitorWorker(db_manager=self.db)
        self._monitor_worker.moveToThread(self._monitor_thread)
        self._monitor_thread.start()
        self._window.connect_monitor_worker(self._monitor_worker)

        step(74, "Surveillance des équipements…")
        # ── Connexion automatique au réseau de la machine ──
        #    enregistre la machine + la passerelle, découvre le sous-réseau, puis
        #    déclenche immédiatement un premier scan + une première collecte.
        self._net_thread = QThread()
        self._net_worker = NetworkSetupWorker(db=self.db)
        self._net_worker.moveToThread(self._net_thread)
        self._net_thread.start()
        self._window.connect_network_setup(self._net_worker)
        QMetaObject.invokeMethod(self._net_worker, "run", Qt.ConnectionType.QueuedConnection)

        # ── Pipeline d'automatisation (corrélation, priorisation, validation humaine) ──
        from core.automation import AutomationWorker
        self._auto_thread = QThread()
        self._auto_worker = AutomationWorker(db=self.db, security=self.security)
        self._auto_worker.moveToThread(self._auto_thread)
        self._auto_thread.start()
        self._window.connect_automation_worker(self._auto_worker)
        self._window.start_defense()          # défense active : services selon les réglages

        step(88, "Connexion sécurisée au réseau…")
        self._window.show()
        step(96, "Affichage du tableau de bord…")
        QApplication.processEvents()          # la fenêtre se peint derrière l'écran de chargement
        if splash:
            splash.finish("Prêt")

    def _stop_workers(self):
        """Arrête proprement tous les workers et leurs threads."""
        try:
            if getattr(self, "_window", None) and hasattr(self._window, "defense"):
                self._window.defense.stop()
        except Exception:
            pass
        for w in ("_scanner_worker", "_monitor_worker"):
            worker = getattr(self, w, None)
            if worker and hasattr(worker, "request_stop"):
                worker.request_stop()            # le cycle en cours s'arrête entre deux hôtes
        for attr in ("_scanner_thread", "_monitor_thread", "_net_thread", "_auto_thread"):
            thread = getattr(self, attr, None)
            if thread and thread.isRunning():
                thread.quit()
                thread.wait(8000)

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
            self._stop_workers()
            self.app.quit()


# ─────────────────────────────────────────────────────────────────
# Point d'entrée
# ─────────────────────────────────────────────────────────────────

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Procus Secure")
    app.setOrganizationName("Procus Tech")
    app.setApplicationVersion("1.0.0")

    from ui.styles import load_fonts, preferred_family
    load_fonts()
    font = QFont(preferred_family(), 9)
    app.setFont(font)
    from ui.winstyle import DarkTitleFilter
    app._dark_titles = DarkTitleFilter(app)              # barre de titre sombre (Windows) sur toutes les fenêtres et dialogues
    app.installEventFilter(app._dark_titles)

    # ── Journal applicatif (fichier tournant, secrets masqués) ──
    from core.logging_setup import setup_logging
    setup_logging()

    # ── Base de données ──
    db = DatabaseManager()
    db.initialize()

    # ── Sécurité ──
    security = SecurityManager(db)
    integrity_ok = security.verify_db_integrity()
    db.purge_old_data(days=30)          # rétention : 30 jours de métriques / états de ports

    # ── Lancement ──
    controller = AppController(app, db, security)
    controller._integrity_ok = integrity_ok
    controller.run()


if __name__ == "__main__":
    main()
