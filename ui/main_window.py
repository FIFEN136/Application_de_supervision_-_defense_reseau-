"""
Procus Secure — Fenêtre principale
Navigation sidebar + QStackedWidget + SchedulerThread automatique
"""
import os
from pathlib import Path

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
    QLabel, QPushButton, QFrame, QStackedWidget,
    QStatusBar, QSizePolicy
)
from PyQt6.QtCore import Qt, QTimer, QThread, QObject, pyqtSignal
from PyQt6.QtGui import QFont, QPixmap, QImage, QPainter

from ui.styles import COLOR, MAIN_QSS


# ─────────────────────────────────────────────────────────────────
# Icônes SVG monochromes — style cybersécurité pro
# ─────────────────────────────────────────────────────────────────

# Chaque icône est un SVG 16×16, trait monochrome, currentColor via fill/stroke
# En Qt on injecte la couleur dans le SVG avant de le passer à QLabel via QPixmap

def _svg_icon(svg_body: str, size: int = 16, color: str = "#7A9BBE") -> QPixmap:
    """
    Rendu d'un SVG inline en QPixmap coloré.
    Utilise QSvgRenderer (PyQt6.QtSvg) — inclus dans PyQt6 standard.
    """
    try:
        from PyQt6.QtSvg import QSvgRenderer
        from PyQt6.QtCore import QByteArray
        svg_str = (
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" '
            f'width="{size}" height="{size}" fill="none" '
            f'stroke="{color}" stroke-width="1.8" '
            f'stroke-linecap="round" stroke-linejoin="round">'
            f'{svg_body}</svg>'
        )
        renderer = QSvgRenderer(QByteArray(svg_str.encode("utf-8")))
        img = QImage(size, size, QImage.Format.Format_ARGB32)
        img.fill(0)
        painter = QPainter(img)
        renderer.render(painter)
        painter.end()
        return QPixmap.fromImage(img)
    except Exception:
        # Fallback : pixmap vide si QtSvg non disponible
        pix = QPixmap(size, size)
        pix.fill(Qt.GlobalColor.transparent)
        return pix


# Bibliothèque SVG paths (Feather Icons / Lucide style)
ICONS = {
    # Tableau de bord
    "dashboard": '<rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/>',
    # Problèmes / alertes
    "problems":  '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
    # Hôtes / serveurs
    "hosts":     '<rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/>',
    # Dernières données
    "latest":    '<line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/>',
    # Console / terminal
    "console":   '<polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>',
    # Carte réseau / topologie
    "topology":  '<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
    # Métriques / graphiques
    "metrics":   '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>',
    # Événements / notifications
    "events":    '<path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/>',
    # Rapports
    "reports":   '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/>',
    # Templates / configuration
    "templates": '<circle cx="12" cy="12" r="3"/><path d="M19.07 4.93a10 10 0 0 1 0 14.14M4.93 4.93a10 10 0 0 0 0 14.14"/>',
    # Médias / alerting
    "media":     '<path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07A19.5 19.5 0 0 1 4.15 13a19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 3.07 2h3a2 2 0 0 1 2 1.72c.127.96.361 1.903.7 2.81a2 2 0 0 1-.45 2.11L7.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45c.907.339 1.85.573 2.81.7A2 2 0 0 1 21 16.92z"/>',
    # Administration / shield
    "admin":     '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    # Hôtes (sous-menu)
    "admin_hosts": '<circle cx="12" cy="8" r="4"/><path d="M20 21a8 8 0 1 0-16 0"/>',
    # Groupes (sous-menu)
    "admin_groups": '<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>',
    # Utilisateurs (sous-menu)
    "admin_users": '<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',
    # Utilisateur (avatar bas)
    "user_avatar": '<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',
}


# ─────────────────────────────────────────────────────────────────
# Scheduler : lance scans + monitoring en boucle en arrière-plan
# ─────────────────────────────────────────────────────────────────

class SchedulerWorker(QObject):
    """Lance périodiquement les scans et collectes SNMP."""
    trigger_scan    = pyqtSignal()
    trigger_monitor = pyqtSignal()
    log_message     = pyqtSignal(str, str)

    def __init__(self, db=None, scan_interval_s=300, snmp_interval_s=60, parent=None):
        super().__init__(parent)
        self.db = db
        self._scan_interval  = scan_interval_s   # 5 min par défaut
        self._snmp_interval  = snmp_interval_s   # 1 min par défaut
        self._scan_timer  = None
        self._snmp_timer  = None

    def start_timers(self):
        self._scan_timer = QTimer()
        self._scan_timer.setInterval(self._scan_interval * 1000)
        self._scan_timer.timeout.connect(self._do_scan)
        self._scan_timer.start()

        self._snmp_timer = QTimer()
        self._snmp_timer.setInterval(self._snmp_interval * 1000)
        self._snmp_timer.timeout.connect(self._do_monitor)
        self._snmp_timer.start()

        self.log_message.emit("INFO",
            f"[Scheduler] Scans toutes les {self._scan_interval}s, "
            f"SNMP toutes les {self._snmp_interval}s")

    def _do_scan(self):
        self.log_message.emit("INFO", "[Scheduler] Déclenchement scan automatique")
        self.trigger_scan.emit()

    def _do_monitor(self):
        self.log_message.emit("INFO", "[Scheduler] Collecte SNMP automatique")
        self.trigger_monitor.emit()

    def stop(self):
        if self._scan_timer:  self._scan_timer.stop()
        if self._snmp_timer:  self._snmp_timer.stop()


# ─────────────────────────────────────────────────────────────────
# Bouton de navigation latérale — icônes SVG monochromes
# ─────────────────────────────────────────────────────────────────

class NavButton(QPushButton):
    """Bouton sidebar avec icône SVG monochrome + label + badge."""

    def __init__(self, icon_key: str, label: str, indent: bool = False, parent=None):
        super().__init__(parent)
        self.setCheckable(True)
        self.setFixedHeight(36)
        self._icon_key = icon_key
        self._indent   = indent

        layout = QHBoxLayout(self)
        layout.setContentsMargins(16 if not indent else 34, 0, 10, 0)
        layout.setSpacing(10)

        # Icône SVG
        self._icon_lbl = QLabel()
        self._icon_lbl.setFixedSize(16, 16)
        self._icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._icon_lbl.setStyleSheet("background: transparent;")

        # Texte
        self._text_lbl = QLabel(label)
        self._text_lbl.setStyleSheet("background: transparent; font-size: 8.5pt;")

        # Badge nombre
        self._badge = QLabel()
        self._badge.setFixedSize(22, 16)
        self._badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._badge.setStyleSheet(
            f"background-color: {COLOR['red']}; color: white; border-radius: 8px; "
            "font-size: 7pt; font-weight: bold;"
        )
        self._badge.hide()

        layout.addWidget(self._icon_lbl)
        layout.addWidget(self._text_lbl, 1)
        layout.addWidget(self._badge)

        self._apply_icon(COLOR["text_sec"])
        self._update_style(False)
        self.toggled.connect(self._update_style)

    def _apply_icon(self, color: str):
        svg_body = ICONS.get(self._icon_key, "")
        if svg_body:
            pix = _svg_icon(svg_body, size=16, color=color)
            self._icon_lbl.setPixmap(pix)

    def set_badge(self, count: int):
        if count > 0:
            self._badge.setText(str(count) if count < 100 else "99+")
            self._badge.show()
        else:
            self._badge.hide()

    def _update_style(self, checked: bool):
        if checked:
            self._apply_icon(COLOR["accent"])
            self._text_lbl.setStyleSheet(
                f"background: transparent; font-size: 8.5pt; "
                f"color: {COLOR['accent']}; font-weight: 700;"
            )
            self.setStyleSheet(f"""
                NavButton {{
                    background-color: {COLOR['accent']}18;
                    border: none;
                    border-left: 3px solid {COLOR['accent']};
                    border-radius: 0;
                }}
            """)
        else:
            self._apply_icon(COLOR["text_sec"])
            self._text_lbl.setStyleSheet(
                f"background: transparent; font-size: 8.5pt; "
                f"color: {COLOR['text_sec']}; font-weight: 400;"
            )
            self.setStyleSheet(f"""
                NavButton {{
                    background-color: transparent;
                    border: none;
                    border-left: 3px solid transparent;
                    border-radius: 0;
                }}
                NavButton:hover {{
                    background-color: {COLOR['hover']};
                }}
            """)


class NavSection(QLabel):
    """Séparateur de section dans la sidebar."""
    def __init__(self, text: str, parent=None):
        super().__init__(text.upper(), parent)
        self.setFixedHeight(28)
        self.setStyleSheet(f"""
            color: {COLOR['text_sec']};
            font-size: 6.5pt;
            font-weight: 700;
            letter-spacing: 1.2px;
            padding-left: 16px;
            padding-top: 8px;
            background: transparent;
        """)


# ─────────────────────────────────────────────────────────────────
# Fenêtre principale
# ─────────────────────────────────────────────────────────────────

class MainWindow(QMainWindow):

    # Émis quand la session expire (30 min d'inactivité)
    session_expired = pyqtSignal()

    def __init__(self, db=None, security=None, parent=None):
        super().__init__(parent)
        self.db = db
        self.security = security

        self.setWindowTitle("Procus Secure — Network Supervision")
        self.setMinimumSize(1280, 720)
        self.resize(1440, 900)
        self.setStyleSheet(MAIN_QSS)

        self._build_ui()
        self._connect_nav()
        self._start_scheduler()

        # Refresh badge/statut toutes les 15 s
        self._status_timer = QTimer(self)
        self._status_timer.timeout.connect(self._refresh_status)
        self._status_timer.start(15_000)

        # Session timeout 30 min
        self._session_timer = QTimer(self)
        self._session_timer.setInterval(30 * 60 * 1000)
        self._session_timer.timeout.connect(self._on_session_timeout)
        self._session_timer.start()
        self.installEventFilter(self)

        self._nav_buttons["dashboard"].setChecked(True)

    # ─────────────────────────────────────────
    # Construction UI
    # ─────────────────────────────────────────

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self._sidebar = self._build_sidebar()
        root.addWidget(self._sidebar)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.VLine)
        sep.setStyleSheet(f"color: {COLOR['border']}; background: {COLOR['border']}; max-width: 1px;")
        root.addWidget(sep)

        self._stack = QStackedWidget()
        self._stack.setStyleSheet(f"background-color: {COLOR['bg_main']};")
        root.addWidget(self._stack, 1)

        # Status bar
        sb = QStatusBar()
        sb.setFixedHeight(22)
        self.setStatusBar(sb)
        self._lbl_user    = QLabel()
        self._lbl_version = QLabel("Procus Secure v1.0")
        self._lbl_db_ok   = QLabel("  DB OK")
        self._lbl_db_ok.setStyleSheet(f"color: {COLOR['green']}; font-weight: 600;")
        sb.addWidget(self._lbl_user)
        sb.addPermanentWidget(self._lbl_db_ok)
        sb.addPermanentWidget(self._lbl_version)

        self._load_views()

    def _build_sidebar(self) -> QWidget:
        sidebar = QWidget()
        sidebar.setFixedWidth(230)
        sidebar.setStyleSheet(f"background-color: {COLOR['bg_sidebar']};")

        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ── Header : Logo Procus + nom app côte à côte ──
        header = QWidget()
        header.setFixedHeight(72)
        header.setStyleSheet(
            f"background-color: {COLOR['bg_sidebar']}; "
            f"border-bottom: 1px solid {COLOR['border']};"
        )
        h_lay = QHBoxLayout(header)
        h_lay.setContentsMargins(14, 0, 14, 0)
        h_lay.setSpacing(12)

        # Logo Procus — image ou fallback shield SVG
        logo_path = Path(__file__).parent.parent / "assets" / "logo_procus.jpg"
        logo_lbl = QLabel()
        logo_lbl.setFixedSize(40, 40)
        logo_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        if logo_path.exists():
            pix = QPixmap(str(logo_path)).scaled(
                40, 40,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation
            )
            logo_lbl.setPixmap(pix)
            logo_lbl.setStyleSheet("background: transparent; border-radius: 6px;")
        else:
            # Fallback shield SVG monochrome accent
            pix_fb = _svg_icon(ICONS["admin"], size=36, color=COLOR["accent"])
            logo_lbl.setPixmap(pix_fb)
            logo_lbl.setStyleSheet("background: transparent;")

        # Texte app
        name_col = QVBoxLayout()
        name_col.setSpacing(2)
        name_col.setContentsMargins(0, 0, 0, 0)

        lbl_name = QLabel("Procus Secure")
        lbl_name.setStyleSheet(
            f"font-size: 10pt; font-weight: 800; "
            f"color: {COLOR['text_pri']}; letter-spacing: 0.5px; "
            "background: transparent;"
        )
        lbl_sub = QLabel("SUPERVISION RÉSEAU")
        lbl_sub.setStyleSheet(
            f"font-size: 6pt; font-weight: 700; "
            f"color: {COLOR['accent']}; letter-spacing: 1.5px; "
            "background: transparent;"
        )
        name_col.addWidget(lbl_name)
        name_col.addWidget(lbl_sub)

        h_lay.addWidget(logo_lbl)
        h_lay.addLayout(name_col, 1)
        layout.addWidget(header)

        layout.addSpacing(6)

        # ── Navigation ──
        self._nav_buttons: dict[str, NavButton] = {}
        self._nav_group: list[NavButton] = []

        def add_btn(key: str, label: str, indent: bool = False):
            btn = NavButton(key, label, indent=indent)
            self._nav_buttons[key] = btn
            self._nav_group.append(btn)
            layout.addWidget(btn)
            return btn

        add_btn("dashboard", "Tableau de bord")
        add_btn("problems",  "Problèmes")

        layout.addWidget(NavSection("Supervision"))
        add_btn("hosts",    "Hôtes")
        add_btn("latest",   "Dernières données")
        add_btn("console",  "Console")
        add_btn("topology", "Carte réseau")
        add_btn("metrics",  "Métriques")
        add_btn("events",   "Événements")

        layout.addWidget(NavSection("Rapports"))
        add_btn("reports",  "Rapports")

        layout.addWidget(NavSection("Configuration"))
        add_btn("templates",    "Templates")
        add_btn("media",        "Médias")
        add_btn("admin",        "Administration")
        add_btn("admin_hosts",  "Hôtes",        indent=True)
        add_btn("admin_groups", "Groupes",       indent=True)
        add_btn("admin_users",  "Utilisateurs",  indent=True)

        layout.addStretch()

        # ── Pied de sidebar : utilisateur connecté ──
        sep_bot = QFrame()
        sep_bot.setFrameShape(QFrame.Shape.HLine)
        sep_bot.setFixedHeight(1)
        sep_bot.setStyleSheet(f"background: {COLOR['border']}; border: none;")
        layout.addWidget(sep_bot)

        self._user_widget = QWidget()
        self._user_widget.setFixedHeight(56)
        self._user_widget.setStyleSheet(f"background-color: {COLOR['bg_sidebar']};")
        u_lay = QHBoxLayout(self._user_widget)
        u_lay.setContentsMargins(14, 8, 14, 8)
        u_lay.setSpacing(10)

        # Avatar SVG monochrome
        self._avatar_lbl = QLabel()
        self._avatar_lbl.setFixedSize(28, 28)
        self._avatar_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._avatar_lbl.setStyleSheet(
            f"background-color: {COLOR['bg_card']}; border-radius: 14px;"
        )
        pix_user = _svg_icon(ICONS["user_avatar"], size=16, color=COLOR["text_sec"])
        self._avatar_lbl.setPixmap(pix_user)

        self._lbl_sidebar_user = QLabel("—")
        self._lbl_sidebar_user.setStyleSheet(
            f"color: {COLOR['text_pri']}; font-weight: 700; font-size: 8pt; background: transparent;"
        )
        self._lbl_sidebar_role = QLabel("—")
        self._lbl_sidebar_role.setStyleSheet(
            f"color: {COLOR['accent']}; font-size: 7pt; font-weight: 600; background: transparent;"
        )
        u_col = QVBoxLayout()
        u_col.setSpacing(1)
        u_col.setContentsMargins(0, 0, 0, 0)
        u_col.addWidget(self._lbl_sidebar_user)
        u_col.addWidget(self._lbl_sidebar_role)
        u_lay.addWidget(self._avatar_lbl)
        u_lay.addLayout(u_col, 1)
        layout.addWidget(self._user_widget)

        return sidebar

    def _load_views(self):
        from ui.widgets.dashboard_view       import DashboardView
        from ui.widgets.problems_view        import ProblemsView
        from ui.widgets.hosts_view           import HostsView
        from ui.widgets.latest_data_view     import LatestDataView
        from ui.widgets.console_view         import ConsoleView
        from ui.widgets.topology_view        import TopologyView
        from ui.widgets.metrics_view         import MetricsView
        from ui.widgets.events_view          import EventsView
        from ui.widgets.reports_view         import ReportsView
        from ui.widgets.admin.hosts_config   import HostsConfigView
        from ui.widgets.admin.groups_view    import GroupsView
        from ui.widgets.admin.templates_view import TemplatesView
        from ui.widgets.admin.users_view     import UsersView
        from ui.widgets.admin.media_view     import MediaView

        self._views = {
            "dashboard":    DashboardView(db=self.db),
            "problems":     ProblemsView(db=self.db, security=self.security),
            "hosts":        HostsView(db=self.db, security=self.security),
            "latest":       LatestDataView(db=self.db),
            "console":      ConsoleView(),
            "topology":     TopologyView(db=self.db),
            "metrics":      MetricsView(db=self.db),
            "events":       EventsView(db=self.db),
            "reports":      ReportsView(db=self.db),
            "admin":        QWidget(),
            "admin_hosts":  HostsConfigView(db=self.db, security=self.security),
            "admin_groups": GroupsView(db=self.db, security=self.security),
            "templates":    TemplatesView(db=self.db, security=self.security),
            "admin_users":  UsersView(db=self.db, security=self.security),
            "media":        MediaView(db=self.db, security=self.security),
        }

        for view in self._views.values():
            self._stack.addWidget(view)

    # ─────────────────────────────────────────
    # Scheduler automatique (point critique #2)
    # ─────────────────────────────────────────

    def _start_scheduler(self):
        """Démarre le scheduler de scans/monitoring automatiques."""
        self._sched_thread = QThread(self)
        self._scheduler = SchedulerWorker(
            db=self.db,
            scan_interval_s=300,   # scan TCP toutes les 5 min
            snmp_interval_s=60,    # SNMP toutes les 1 min
        )
        self._scheduler.moveToThread(self._sched_thread)
        self._sched_thread.started.connect(self._scheduler.start_timers)

        # Log console
        console = self._views.get("console") if hasattr(self, "_views") else None
        if console and hasattr(console, "append_log"):
            self._scheduler.log_message.connect(console.append_log)

        self._sched_thread.start()

    # ─────────────────────────────────────────
    # Navigation
    # ─────────────────────────────────────────

    def _connect_nav(self):
        for key, btn in self._nav_buttons.items():
            btn.clicked.connect(lambda checked, k=key: self._navigate(k))

    def _navigate(self, key: str):
        # Réinitialiser le timeout d'inactivité
        self._session_timer.start()

        for k, b in self._nav_buttons.items():
            b.blockSignals(True)
            b.setChecked(k == key)
            b.blockSignals(False)

        if key == "admin":
            key = "admin_hosts"
            self._nav_buttons["admin_hosts"].setChecked(True)

        view = self._views.get(key)
        if view:
            self._stack.setCurrentWidget(view)
            if hasattr(view, "refresh"):
                view.refresh()

    # ─────────────────────────────────────────
    # Session timeout
    # ─────────────────────────────────────────

    def eventFilter(self, obj, event):
        from PyQt6.QtCore import QEvent
        if event.type() in (
            QEvent.Type.MouseButtonPress, QEvent.Type.KeyPress,
            QEvent.Type.MouseMove
        ):
            self._session_timer.start()
        return super().eventFilter(obj, event)

    def _on_session_timeout(self):
        self._session_timer.stop()
        self.session_expired.emit()

    # ─────────────────────────────────────────
    # Refresh statut
    # ─────────────────────────────────────────

    def _refresh_status(self):
        if self.db:
            try:
                count = self.db.get_active_problems_count()
                self._nav_buttons["problems"].set_badge(count)
            except Exception:
                pass

        user = self.security.get_current_user() if self.security else None
        if user:
            name = user.get("full_name") or user.get("login", "—")
            role = user.get("role", "—")
            self._lbl_sidebar_user.setText(name)
            self._lbl_sidebar_role.setText(role)
            self._lbl_user.setText(f"  {name}  |  {role}")

    def set_current_user(self, user: dict):
        if self.security:
            self.security.set_current_user(user)
        self._refresh_status()

    # ─────────────────────────────────────────
    # Connexion workers scan/monitor
    # ─────────────────────────────────────────

    def connect_scanner_worker(self, worker):
        """Connecte un ScannerWorker — appelé depuis main.py."""
        self._scanner_worker = worker
        console = self._views.get("console")
        if console and hasattr(console, "append_log"):
            worker.log_message.connect(console.append_log)

        hosts_view = self._views.get("hosts")
        if hosts_view and hasattr(hosts_view, "on_scan_result"):
            worker.result_ready.connect(hosts_view.on_scan_result)

        # Point critique #4 — change_detected → add_event en DB
        if hosts_view and hasattr(hosts_view, "on_change_detected"):
            worker.change_detected.connect(hosts_view.on_change_detected)

        # Scheduler déclenche le scan auto sur tous les hôtes
        if hasattr(self, "_scheduler") and hosts_view and hasattr(hosts_view, "trigger_all_scans"):
            self._scheduler.trigger_scan.connect(hosts_view.trigger_all_scans)

    def connect_monitor_worker(self, worker):
        """Connecte un MonitorWorker — appelé depuis main.py."""
        self._monitor_worker = worker
        console = self._views.get("console")
        if console and hasattr(console, "append_log"):
            worker.log_message.connect(console.append_log)

        dashboard = self._views.get("dashboard")
        if dashboard and hasattr(dashboard, "on_metrics"):
            worker.metrics_ready.connect(dashboard.on_metrics)

        # Point critique #3 — persistance métriques en DB
        if self.db and hasattr(worker, "metrics_ready"):
            worker.metrics_ready.connect(self._persist_metrics)

    def _persist_metrics(self, data: dict):
        """Sauvegarde les métriques collectées en DB (point critique #3)."""
        if not self.db:
            return
        host_id  = data.get("host_id")
        hostname = data.get("host", "")
        if not host_id:
            return
        try:
            pairs = [
                ("cpu_util",      data.get("cpu"),      "%"),
                ("mem_used",      data.get("memory"),   "%"),
                ("if_in_octets",  data.get("if_in"),    "Mbps"),
                ("if_out_octets", data.get("if_out"),   "Mbps"),
            ]
            for metric_name, value, unit in pairs:
                if value is not None:
                    self.db.execute(
                        """INSERT INTO metrics
                           (host_id, metric_name, value, unit)
                           VALUES (?, ?, ?, ?)""",
                        (host_id, metric_name, float(value), unit)
                    )
        except Exception as e:
            pass  # silencieux pour ne pas bloquer l'UI

    def closeEvent(self, event):
        if hasattr(self, "_sched_thread"):
            self._scheduler.stop()
            self._sched_thread.quit()
            self._sched_thread.wait(2000)
        super().closeEvent(event)
