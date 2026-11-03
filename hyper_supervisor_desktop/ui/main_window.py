"""
Procus Secure — Fenêtre principale
Navigation sidebar + QStackedWidget + SchedulerThread automatique
"""
import os
from pathlib import Path

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
    QLabel, QPushButton, QFrame, QStackedWidget,
    QStatusBar, QSizePolicy, QScrollArea
)
from PyQt6.QtCore import Qt, QTimer, QThread, QObject, pyqtSignal, pyqtSlot, QMetaObject
from PyQt6.QtGui import QFont, QPixmap, QImage, QPainter

from ui.styles import COLOR, MAIN_QSS, alpha


# ─────────────────────────────────────────────────────────────────
# Icônes SVG monochromes — style cybersécurité pro
# ─────────────────────────────────────────────────────────────────

# Chaque icône est un SVG 16×16, trait monochrome, currentColor via fill/stroke
# En Qt on injecte la couleur dans le SVG avant de le passer à QLabel via QPixmap

from ui.icons import ICONS, _svg_icon  # noqa: F401  (partagé avec le tableau de bord)


# ─────────────────────────────────────────────────────────────────
# Scheduler : lance scans + monitoring en boucle en arrière-plan
# ─────────────────────────────────────────────────────────────────

class SchedulerWorker(QObject):
    """Lance périodiquement les scans et collectes SNMP."""
    trigger_scan    = pyqtSignal()
    trigger_monitor = pyqtSignal()
    trigger_discovery = pyqtSignal()
    trigger_pipeline  = pyqtSignal()
    trigger_presence  = pyqtSignal()
    log_message     = pyqtSignal(str, str)

    def __init__(self, db=None, scan_interval_s=300, snmp_interval_s=60, parent=None):
        super().__init__(parent)
        self.db = db
        self._scan_interval  = scan_interval_s   # 5 min par défaut
        self._snmp_interval  = snmp_interval_s   # 1 min par défaut
        self._scan_timer  = None
        self._snmp_timer  = None
        self._scan_busy_since = None      # cycles non empilés : on n'en relance pas un tant que
        self._snmp_busy_since = None      # le précédent n'est pas terminé

    @pyqtSlot()
    def start_timers(self):
        self._scan_timer = QTimer(self)
        self._scan_timer.setInterval(self._scan_interval * 1000)
        self._scan_timer.timeout.connect(self._do_scan)
        self._scan_timer.start()

        self._snmp_timer = QTimer(self)
        self._snmp_timer.setInterval(self._snmp_interval * 1000)
        self._snmp_timer.timeout.connect(self._do_monitor)
        self._snmp_timer.start()

        # Redécouverte périodique des réseaux saisis (nouveaux équipements)
        self._disc_timer = QTimer(self)
        try:
            disc_s = max(60, int(self.db.get_setting("discovery_interval", "600"))) if self.db else 600
        except (TypeError, ValueError):
            disc_s = 600
        self._disc_timer.setInterval(disc_s * 1000)
        self._disc_timer.timeout.connect(self.trigger_discovery.emit)
        self._disc_timer.start()

        # Pipeline d'automatisation (corrélation, priorisation, actions à valider, rapport périodique)
        self._pipe_timer = QTimer(self)
        try:
            pipe_s = max(30, int(self.db.get_setting("pipeline_interval", "120"))) if self.db else 120
        except (TypeError, ValueError):
            pipe_s = 120
        self._pipe_timer.setInterval(pipe_s * 1000)
        self._pipe_timer.timeout.connect(self.trigger_pipeline.emit)
        self._pipe_timer.start()

        # Présence rapide : un appareil muet depuis 30 s est signalé hors ligne
        self._presence_timer = QTimer(self)
        self._presence_timer.setInterval(5000)
        self._presence_timer.timeout.connect(self.trigger_presence.emit)
        self._presence_timer.start()

        self.log_message.emit("INFO",
            f"[Scheduler] Scans toutes les {self._scan_interval}s, "
            f"SNMP toutes les {self._snmp_interval}s")

    @pyqtSlot()
    def run_now(self):
        """Premier cycle immédiat (scan + collecte) sans attendre les intervalles."""
        self._do_monitor()
        self._do_scan()

    def _is_busy(self, since, interval_s):
        """Un cycle bloqué depuis plus de 10 intervalles est considéré comme perdu (sécurité)."""
        import time
        return since is not None and (time.monotonic() - since) < interval_s * 10

    def _do_scan(self):
        import time
        if self._is_busy(self._scan_busy_since, self._scan_interval):
            self.log_message.emit("INFO", "[Scheduler] Scan précédent encore en cours — ignoré")
            return
        self._scan_busy_since = time.monotonic()
        self.log_message.emit("INFO", "[Scheduler] Déclenchement scan automatique")
        self.trigger_scan.emit()

    def _do_monitor(self):
        import time
        if self._is_busy(self._snmp_busy_since, self._snmp_interval):
            self.log_message.emit("INFO", "[Scheduler] Collecte précédente encore en cours — ignorée")
            return
        self._snmp_busy_since = time.monotonic()
        self.log_message.emit("INFO", "[Scheduler] Collecte automatique (métriques)")
        self.trigger_monitor.emit()

    @pyqtSlot()
    def scan_finished(self):
        self._scan_busy_since = None

    @pyqtSlot(int)
    def monitor_finished(self, _n=0):
        self._snmp_busy_since = None

    @pyqtSlot(int, int)
    def set_intervals(self, scan_s: int, snmp_s: int):
        """Met à jour les intervalles à chaud (depuis SettingsView)."""
        self._scan_interval = scan_s
        self._snmp_interval = snmp_s
        if self._scan_timer:
            self._scan_timer.setInterval(scan_s * 1000)
        if self._snmp_timer:
            self._snmp_timer.setInterval(snmp_s * 1000)
        self.log_message.emit(
            "INFO", f"[Scheduler] Intervalles mis à jour : scan={scan_s}s, SNMP={snmp_s}s"
        )

    @pyqtSlot()
    def stop(self):
        if self._scan_timer:  self._scan_timer.stop()
        if self._snmp_timer:  self._snmp_timer.stop()
        if getattr(self, "_disc_timer", None):  self._disc_timer.stop()
        if getattr(self, "_pipe_timer", None):  self._pipe_timer.stop()
        if getattr(self, "_presence_timer", None):  self._presence_timer.stop()


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
                    background-color: {alpha(COLOR['accent'], '18')};
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

    def __init__(self, db=None, security=None, parent=None, progress=None):
        super().__init__(parent)
        self.db = db
        self.security = security
        self._progress_cb = progress         # callable(pct, texte) — écran de démarrage

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

        # Session timeout (réglage « session_timeout », 30 min par défaut)
        self._session_timer = QTimer(self)
        self._session_minutes = 30
        self._session_timer.setInterval(self._session_minutes * 60 * 1000)
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

        # ── Navigation (zone défilante : l'en-tête et le pied restent fixes même sur petit écran) ──
        nav_host = QWidget()
        nav_host.setStyleSheet(f"background-color: {COLOR['bg_sidebar']};")
        nav_lay = QVBoxLayout(nav_host)
        nav_lay.setContentsMargins(0, 0, 0, 0)
        nav_lay.setSpacing(0)
        nav_scroll = QScrollArea()
        nav_scroll.setWidgetResizable(True)
        nav_scroll.setFrameShape(QFrame.Shape.NoFrame)
        nav_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        nav_scroll.setStyleSheet(
            "QScrollArea { background: transparent; border: none; }"
            "QScrollBar:vertical { width: 6px; background: transparent; }"
            f"QScrollBar::handle:vertical {{ background: {COLOR['border']}; border-radius: 3px; min-height: 24px; }}"
            "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }")
        nav_scroll.setWidget(nav_host)
        layout.addWidget(nav_scroll, 1)
        self._nav_buttons: dict[str, NavButton] = {}
        self._nav_group: list[NavButton] = []

        def add_btn(key: str, label: str, indent: bool = False):
            btn = NavButton(key, label, indent=indent)
            self._nav_buttons[key] = btn
            self._nav_group.append(btn)
            nav_lay.addWidget(btn)
            return btn

        add_btn("dashboard", "Tableau de bord")
        add_btn("problems",  "Problèmes")
        add_btn("incidents", "Incidents")

        nav_lay.addWidget(NavSection("Supervision"))
        add_btn("hosts",    "Hôtes")
        add_btn("latest",   "Dernières données")
        add_btn("console",  "Console")
        add_btn("topology", "Carte réseau")
        add_btn("metrics",  "Métriques")
        add_btn("events",   "Événements")
        add_btn("defense",  "Défense active")
        add_btn("netsec",   "Sécurité réseau")

        nav_lay.addWidget(NavSection("Rapports"))
        add_btn("reports",  "Rapports")

        nav_lay.addWidget(NavSection("Configuration"))
        add_btn("templates",    "Templates")
        add_btn("media",        "Médias")
        add_btn("settings",     "Paramètres")
        add_btn("admin",        "Administration")
        add_btn("admin_hosts",  "Hôtes",        indent=True)
        add_btn("admin_groups", "Groupes",       indent=True)
        add_btn("admin_users",  "Utilisateurs",  indent=True)

        nav_lay.addStretch()

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

    def _report(self, pct: int, text: str):
        """Progression du démarrage (écran de chargement) — sans effet si aucun écran n'est branché."""
        cb = getattr(self, "_progress_cb", None)
        if cb:
            try:
                cb(pct, text)
            except Exception:
                pass

    def _load_views(self):
        from ui.widgets.dashboard_view       import DashboardView
        from ui.widgets.problems_view        import ProblemsView
        from ui.widgets.hosts_view           import HostsView
        from ui.widgets.incidents_view       import IncidentsView
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
        from ui.widgets.settings_view        import SettingsView
        from ui.widgets.defense_view         import DefenseView
        from ui.widgets.security_view        import SecurityView
        from core.defense                    import DefenseManager
        self.defense = DefenseManager(self.db, self.security)

        factories = [
            ("dashboard",    lambda: DashboardView(db=self.db)),
            ("problems",     lambda: ProblemsView(db=self.db, security=self.security)),
            ("incidents",    lambda: IncidentsView(db=self.db, security=self.security)),
            ("hosts",        lambda: HostsView(db=self.db, security=self.security)),
            ("latest",       lambda: LatestDataView(db=self.db)),
            ("console",      lambda: ConsoleView()),
            ("topology",     lambda: TopologyView(db=self.db, security=self.security)),
            ("metrics",      lambda: MetricsView(db=self.db)),
            ("events",       lambda: EventsView(db=self.db)),
            ("reports",      lambda: ReportsView(db=self.db)),
            ("defense",      lambda: DefenseView(db=self.db, security=self.security, manager=self.defense)),
            ("netsec",       lambda: SecurityView(db=self.db, security=self.security, manager=self.defense)),
            ("settings",     lambda: SettingsView(db=self.db, security=self.security,
                                                  scheduler=None)),   # scheduler branché après _start_scheduler
            ("admin",        lambda: QWidget()),
            ("admin_hosts",  lambda: HostsConfigView(db=self.db, security=self.security)),
            ("admin_groups", lambda: GroupsView(db=self.db, security=self.security)),
            ("templates",    lambda: TemplatesView(db=self.db, security=self.security)),
            ("admin_users",  lambda: UsersView(db=self.db, security=self.security)),
            ("media",        lambda: MediaView(db=self.db, security=self.security)),
        ]
        self._views = {}
        for i, (key, make) in enumerate(factories, 1):
            self._views[key] = make()
            self._report(8 + int(42 * i / len(factories)), "Chargement de l'interface…")

        for view in self._views.values():
            self._stack.addWidget(view)

    # ─────────────────────────────────────────
    # Scheduler automatique (point critique #2)
    # ─────────────────────────────────────────

    def _start_scheduler(self):
        """Démarre le scheduler de scans/monitoring automatiques."""
        # Lire les intervalles depuis la DB si disponible
        scan_s = 300
        snmp_s = 60
        if self.db:
            try:
                scan_s = int(self.db.get_setting("scan_interval", "300"))
                snmp_s = int(self.db.get_setting("snmp_interval", "60"))
            except Exception:
                pass

        self._sched_thread = QThread(self)
        self._scheduler = SchedulerWorker(
            db=self.db,
            scan_interval_s=scan_s,
            snmp_interval_s=snmp_s,
        )
        self._scheduler.moveToThread(self._sched_thread)
        self._sched_thread.started.connect(self._scheduler.start_timers)

        # Log console
        console = self._views.get("console") if hasattr(self, "_views") else None
        if console and hasattr(console, "append_log"):
            self._scheduler.log_message.connect(console.append_log)

        self._sched_thread.start()

        # Donner la référence du scheduler à SettingsView
        settings_view = self._views.get("settings")
        if settings_view and hasattr(settings_view, "set_scheduler"):
            settings_view.set_scheduler(self._scheduler)

        # Notifier worker (point 9)
        from core.notifier import NotifierWorker
        self._notifier_thread = QThread(self)
        self._notifier_worker = NotifierWorker(db=self.db)
        self._notifier_worker.moveToThread(self._notifier_thread)
        self._notifier_thread.start()
        self._notifier_worker.notification_sent.connect(self._on_notification_sent)
        self._notifier_worker.notification_failed.connect(self._on_notification_failed)

    @pyqtSlot(str)
    def _on_notification_sent(self, channel: str):
        console = self._views.get("console")
        if console:
            console.append_log("INFO", f"[Notif] Envoyé via {channel}")

    @pyqtSlot(str, str)
    def _on_notification_failed(self, channel: str, error: str):
        console = self._views.get("console")
        if console:
            console.append_log("WARNING", f"[Notif] Échec {channel}: {error}")

    # ─────────────────────────────────────────
    # Navigation
    # ─────────────────────────────────────────

    def _connect_nav(self):
        for key, btn in self._nav_buttons.items():
            btn.clicked.connect(lambda checked, k=key: self._navigate(k))

    def _navigate(self, key: str):
        # Réinitialiser le timeout d'inactivité
        self._session_timer.start()

        def _sync_nav(active: str):
            for k, b in self._nav_buttons.items():
                b.blockSignals(True)
                b.setChecked(k == active)
                b.blockSignals(False)
                b._update_style(b.isChecked())      # signaux bloqués : le style doit être rafraîchi à la main

        _sync_nav(key)
        if key == "admin":
            key = "admin_hosts"
            _sync_nav("admin_hosts")

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

    def _sync_session_timeout(self):
        """Applique le délai d'inactivité saisi dans Paramètres (min. 1 minute)."""
        if not self.db:
            return
        try:
            minutes = max(1, int(self.db.get_setting("session_timeout", "30")))
        except (TypeError, ValueError):
            minutes = 30
        if minutes != self._session_minutes:
            self._session_minutes = minutes
            self._session_timer.setInterval(minutes * 60 * 1000)
            self._session_timer.start()

    def _refresh_status(self):
        self._sync_session_timeout()
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
        """Connecte le ScannerWorker (vit dans son QThread) à l'UI, au scheduler et aux notifications."""
        self._scanner_worker = worker
        console = self._views.get("console")
        if console and hasattr(console, "append_log"):
            worker.log_message.connect(console.append_log)

        hosts_view = self._views.get("hosts")
        if hosts_view:
            worker.scan_complete.connect(hosts_view.on_scan_complete)    # rafraîchit après chaque hôte
            worker.change_detected.connect(hosts_view.on_change_detected)
            hosts_view.scan_requested.connect(worker.request_scan)       # bouton « Scan »

        # Scan automatique : scheduler → ScannerWorker.scan_all (tous les hôtes, en série)
        if hasattr(self, "_scheduler"):
            self._scheduler.trigger_scan.connect(worker.scan_all)
            worker.cycle_done.connect(self._scheduler.scan_finished)

        # Notifications (SMTP / Webhook / Slack) sur chaque changement détecté
        if hasattr(self, "_notifier_worker"):
            worker.change_detected.connect(self._notifier_worker.on_change_detected)

    def connect_monitor_worker(self, worker):
        """Connecte le MonitorWorker : collecte automatique, dashboard, notifications d'alerte."""
        self._monitor_worker = worker
        console = self._views.get("console")
        if console and hasattr(console, "append_log"):
            worker.log_message.connect(console.append_log)

        dashboard = self._views.get("dashboard")
        if dashboard:
            worker.metrics_ready.connect(dashboard.on_metrics)
        hosts_view = self._views.get("hosts")
        if hosts_view:
            worker.cycle_done.connect(hosts_view.on_cycle_done)

        # Collecte automatique : scheduler → MonitorWorker.collect_all
        if hasattr(self, "_scheduler"):
            self._scheduler.trigger_monitor.connect(worker.collect_all)
            self._scheduler.trigger_presence.connect(worker.presence_tick)
            worker.cycle_done.connect(self._scheduler.monitor_finished)

        # Alertes (seuils CPU/RAM, hôte hors ligne) → notifications
        if hasattr(self, "_notifier_worker"):
            worker.alert_triggered.connect(self._notifier_worker.on_change_detected)

    def connect_network_setup(self, worker):
        """Connecte le NetworkSetupWorker : découverte, puis premier cycle scan + collecte."""
        self._net_worker = worker
        console = self._views.get("console")
        if console and hasattr(console, "append_log"):
            worker.log_message.connect(console.append_log)
        hosts_view = self._views.get("hosts")
        if hosts_view:
            hosts_view.discover_requested.connect(worker.discover)
            worker.finished.connect(hosts_view.on_discovery_finished)
        if hasattr(self, "_scheduler"):
            worker.finished.connect(self._on_network_ready)
            self._scheduler.trigger_discovery.connect(worker.rediscover_due)
        topo = self._views.get("topology")
        if topo and hasattr(topo, "network_scan_requested"):
            topo.network_scan_requested.connect(worker.discover_network)
            worker.network_discovered.connect(topo.on_network_discovered)
        worker.network_discovered.connect(self._on_network_discovered)
        if hasattr(self, "_notifier_worker"):
            worker.new_device.connect(self._notifier_worker.on_change_detected)

    def start_defense(self):
        """Défense active (honeypots, ARP/DHCP, agents, syslog, FIM) : alertes → notifications + console, puis démarrage."""
        d = self.defense
        if hasattr(self, "_notifier_worker"):
            d.alert.connect(self._notifier_worker.on_change_detected)
        console = self._views.get("console")
        if console and hasattr(console, "append_log"):
            d.log_message.connect(console.append_log)
        d.start()

    def connect_automation_worker(self, worker):
        """Pipeline d'automatisation : planification, vue Incidents, notifications des incidents P1/P2."""
        self._auto_worker = worker
        console = self._views.get("console")
        if console and hasattr(console, "append_log"):
            worker.log_message.connect(console.append_log)
        inc = self._views.get("incidents")
        if inc:
            inc.run_requested.connect(worker.run_pipeline)
            worker.pipeline_done.connect(inc.on_pipeline_done)
        if hasattr(self, "_scheduler"):
            self._scheduler.trigger_pipeline.connect(worker.run_pipeline)
        worker.pipeline_done.connect(self._on_pipeline_done)
        if hasattr(self, "_notifier_worker"):
            worker.incident_alert.connect(self._on_incident_alert)

    @pyqtSlot(dict)
    def _on_pipeline_done(self, result: dict):
        s = result.get("steps", {})
        n = s.get("5_correlation", {}).get("incidents_opened", 0)
        w = s.get("8_validation_humaine", {}).get("waiting_for_human", 0)
        btn = self._nav_buttons.get("incidents")
        if btn is not None and hasattr(btn, "setToolTip"):
            btn.setToolTip(f"{w} action(s) en attente de validation")
        if n:
            inc = self._views.get("incidents")
            if inc:
                inc.refresh()

    @pyqtSlot(dict)
    def _on_incident_alert(self, info: dict):
        if hasattr(self, "_notifier_worker"):
            self._notifier_worker.on_change_detected({
                "host_id": info.get("host_id"), "host_name": info.get("host"), "severity": info.get("severity"),
                "event_type": "incident", "port": None,
                "description": f"[{info.get('priority_label')}] {info.get('title')}",
                "state_before": "", "state_after": f"{info.get('event_count')} événement(s)"})

    @pyqtSlot(int, int, int)
    def _on_network_discovered(self, network_id: int, added: int, total: int):
        """Nouveaux équipements → statut/métriques immédiats (sans attendre le prochain cycle)."""
        if added and hasattr(self, "_scheduler"):
            QMetaObject.invokeMethod(self._scheduler, "run_now", Qt.ConnectionType.QueuedConnection)
        dash = self._views.get("dashboard")
        if dash:
            dash.refresh()

    @pyqtSlot(int)
    def _on_network_ready(self, added: int):
        """Réseau enregistré → premier cycle immédiat (sans attendre les intervalles)."""
        if hasattr(self, "_scheduler"):
            QMetaObject.invokeMethod(self._scheduler, "run_now", Qt.ConnectionType.QueuedConnection)
        dash = self._views.get("dashboard")
        if dash:
            dash.refresh()

    def closeEvent(self, event):
        if hasattr(self, "defense"):
            self.defense.stop()
        if hasattr(self, "_sched_thread"):
            if self._sched_thread.isRunning():
                QMetaObject.invokeMethod(self._scheduler, "stop",
                                         Qt.ConnectionType.BlockingQueuedConnection)
            self._sched_thread.quit()
            self._sched_thread.wait(2000)
        if hasattr(self, "_notifier_thread"):
            self._notifier_thread.quit()
            self._notifier_thread.wait(1000)
        super().closeEvent(event)
