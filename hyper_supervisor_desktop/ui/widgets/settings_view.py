"""
Procus Secure — Vue Paramètres système
Procus Tech

Onglets :
  1. Supervision   — intervalles, seuils, communauté SNMP par défaut
  2. Notifications SMTP — serveur mail, destinataires, test
  3. Webhooks      — URL, secret HMAC, test Slack/Teams
  4. Sauvegarde    — export/import base SQLite
"""
import shutil
from pathlib import Path

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QScrollArea, QFormLayout, QLineEdit, QSpinBox, QTabWidget, QGroupBox, QCheckBox, QComboBox,
    QMessageBox, QFileDialog, QFrame
)
from PyQt6.QtCore import Qt, pyqtSignal

from ui.styles import COLOR, alpha
from ui.icons import icon_button


class SettingsView(QWidget):
    _box_done = pyqtSignal(bool, str)

    def __init__(self, db=None, security=None, scheduler=None, parent=None):
        super().__init__(parent)
        self.db        = db
        self.security  = security
        self.scheduler = scheduler
        self._build_ui()
        self._load_settings()

    # ─────────────────────────────────────────
    # Construction
    # ─────────────────────────────────────────

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)

        # Titre
        hdr = QHBoxLayout()
        title = QLabel("Paramètres système")
        title.setStyleSheet(f"font-size: 14pt; font-weight: 700; color: {COLOR['text_pri']};")
        hdr.addWidget(title)
        hdr.addStretch()
        layout.addLayout(hdr)

        # Tabs
        self._tabs = QTabWidget()
        self._tabs.setStyleSheet(f"""
            QTabWidget::pane {{
                border: 1px solid {COLOR['border']};
                background: {COLOR['bg_card']};
                border-radius: 4px;
            }}
            QTabBar::tab {{
                background: {COLOR['bg_sidebar']};
                color: {COLOR['text_sec']};
                padding: 8px 18px;
                border: 1px solid {COLOR['border']};
                border-bottom: none;
                margin-right: 2px;
                font-size: 8.5pt;
            }}
            QTabBar::tab:selected {{
                background: {COLOR['bg_card']};
                color: {COLOR['text_pri']};
                border-bottom: 2px solid {COLOR['accent']};
                font-weight: 700;
            }}
            QTabBar::tab:hover {{
                background: {COLOR['hover']};
                color: {COLOR['text_pri']};
            }}
        """)

        self._tabs.addTab(self._build_tab_supervision(),   "Supervision")
        self._tabs.addTab(self._build_tab_smtp(),          "Notifications SMTP")
        self._tabs.addTab(self._build_tab_webhooks(),      "Webhooks")
        self._tabs.addTab(self._build_tab_backup(),        "Sauvegarde")
        self._tabs.addTab(self._build_tab_automation(),    "Automatisation")
        layout.addWidget(self._tabs)

    def _form_style(self) -> str:
        return f"""
            QLineEdit, QSpinBox {{
                background: {COLOR['bg_main']};
                border: 1px solid {COLOR['border']};
                color: {COLOR['text_pri']};
                padding: 5px 8px;
                border-radius: 3px;
                font-size: 9pt;
            }}
            QLineEdit:focus, QSpinBox:focus {{
                border-color: {COLOR['accent']};
            }}
            QLabel {{
                color: {COLOR['text_sec']};
                font-size: 8.5pt;
            }}
        """

    def _save_btn(self, text: str = "Sauvegarder") -> QPushButton:
        btn = icon_button("act_save", text)
        btn.setObjectName("btn_primary")
        btn.setFixedHeight(36)
        return btn

    # ─────────────────────────────────────────
    # Onglet 1 — Supervision
    # ─────────────────────────────────────────

    def _build_tab_supervision(self) -> QWidget:
        w = QWidget()
        w.setStyleSheet(self._form_style())
        layout = QVBoxLayout(w)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)

        # Intervalles
        grp_intervals = QGroupBox("Intervalles de supervision")
        grp_intervals.setStyleSheet(f"""
            QGroupBox {{ color: {COLOR['text_pri']}; font-weight: 700; font-size: 9pt;
                         border: 1px solid {COLOR['border']}; border-radius: 4px;
                         margin-top: 16px; padding-top: 14px; }}
            QGroupBox::title {{ subcontrol-origin: margin; left: 10px; padding: 0 4px; }}
        """)
        form1 = QFormLayout(grp_intervals)
        form1.setSpacing(10)
        form1.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        self._scan_interval = QSpinBox()
        self._scan_interval.setRange(60, 3600)
        self._scan_interval.setSuffix(" s")
        self._scan_interval.setValue(300)

        self._snmp_interval = QSpinBox()
        self._snmp_interval.setRange(30, 600)
        self._snmp_interval.setSuffix(" s")
        self._snmp_interval.setValue(60)

        self._session_timeout = QSpinBox()
        self._session_timeout.setRange(5, 120)
        self._session_timeout.setSuffix(" min")
        self._session_timeout.setValue(30)

        form1.addRow("Intervalle scan TCP :", self._scan_interval)
        form1.addRow("Intervalle SNMP :", self._snmp_interval)
        form1.addRow("Timeout session :", self._session_timeout)
        layout.addWidget(grp_intervals)

        # Seuils
        grp_thresh = QGroupBox("Seuils d'alerte")
        grp_thresh.setStyleSheet(grp_intervals.styleSheet())
        form2 = QFormLayout(grp_thresh)
        form2.setSpacing(10)
        form2.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        self._cpu_threshold = QSpinBox()
        self._cpu_threshold.setRange(50, 100)
        self._cpu_threshold.setSuffix(" %")
        self._cpu_threshold.setValue(80)

        self._ram_threshold = QSpinBox()
        self._ram_threshold.setRange(50, 100)
        self._ram_threshold.setSuffix(" %")
        self._ram_threshold.setValue(85)

        self._snmp_community = QLineEdit("public")
        self._snmp_community.setPlaceholderText("Communauté SNMP par défaut")

        self._presence_grace = QSpinBox()
        self._presence_grace.setRange(10, 600)
        self._presence_grace.setSuffix(" s")
        self._presence_grace.setValue(30)
        self._presence_grace.setToolTip("Un appareil sans aucune réponse pendant ce délai passe en rouge (hors ligne) sur la carte.")
        form2.addRow("Hors ligne après (silence) :", self._presence_grace)
        form2.addRow("Seuil CPU :", self._cpu_threshold)
        form2.addRow("Seuil RAM :", self._ram_threshold)
        form2.addRow("Communauté SNMP défaut :", self._snmp_community)
        layout.addWidget(grp_thresh)

        # Box Internet (facultatif)
        grp_box = QGroupBox("Connexion à la box (facultatif)")
        grp_box.setStyleSheet(grp_intervals.styleSheet())
        fb = QFormLayout(grp_box)
        fb.setSpacing(10)
        fb.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        self._box_enabled = QCheckBox("Lire la liste des appareils sur ma box (Wi-Fi / Ethernet, bande, signal, port)")
        self._box_addr = QLineEdit()
        self._box_addr.setPlaceholderText("Adresse de la box, souvent 192.168.1.254")
        self._box_pwd = QLineEdit()
        self._box_pwd.setEchoMode(QLineEdit.EchoMode.Password)
        self._box_pwd.setPlaceholderText("Mot de passe de la box (laissez vide pour garder l'actuel)")
        for field in (self._box_addr, self._box_pwd):
            field.setMinimumHeight(34)
        fb.setVerticalSpacing(12)
        fb.addRow(self._box_enabled)
        fb.addRow("Adresse de la box :", self._box_addr)
        fb.addRow("Mot de passe :", self._box_pwd)
        box_hint = QLabel("Sans cette option, tout reste automatique (informations déduites). Avec elle, la box donne les vraies valeurs. "
                          "Lecture seule, réseau local uniquement, mot de passe chiffré.")
        box_hint.setWordWrap(True)
        box_hint.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 7.5pt;")
        fb.addRow(box_hint)
        self._box_result = QLabel("")
        self._box_result.setWordWrap(True)
        self._box_result.setMinimumHeight(24)
        self._box_result.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        btn_box_test = icon_button("act_zap", "Tester la connexion à la box")
        btn_box_test.setMinimumHeight(38); btn_box_test.setMinimumWidth(220)
        btn_box_test.clicked.connect(self._test_box)
        btn_box_save = icon_button("act_save", "Enregistrer la box")
        btn_box_save.setMinimumHeight(38); btn_box_save.setMinimumWidth(220)
        btn_box_save.clicked.connect(self._save_box)
        row_box = QHBoxLayout()
        row_box.addWidget(btn_box_save)
        row_box.addWidget(btn_box_test)
        row_box.addStretch()
        fb.addRow(row_box)
        fb.addRow(self._box_result)
        grp_box.setMinimumHeight(260)
        self._btn_box_test = btn_box_test
        self._box_done.connect(self._on_box_result)
        layout.addWidget(grp_box)

        # Bouton
        btn_save = self._save_btn()
        btn_save.clicked.connect(self._save_supervision)
        layout.addWidget(btn_save)
        layout.addStretch()
        scroll = QScrollArea()                       # rien n'est écrasé quand la fenêtre est petite
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(w)
        return scroll

    # ─────────────────────────────────────────
    # Onglet 2 — SMTP
    # ─────────────────────────────────────────

    def _build_tab_smtp(self) -> QWidget:
        w = QWidget()
        w.setStyleSheet(self._form_style())
        layout = QVBoxLayout(w)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)

        grp = QGroupBox("Serveur SMTP")
        grp.setStyleSheet(f"""
            QGroupBox {{ color: {COLOR['text_pri']}; font-weight: 700; font-size: 9pt;
                         border: 1px solid {COLOR['border']}; border-radius: 4px;
                         margin-top: 16px; padding-top: 14px; }}
            QGroupBox::title {{ subcontrol-origin: margin; left: 10px; padding: 0 4px; }}
        """)
        form = QFormLayout(grp)
        form.setSpacing(10)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        self._smtp_host = QLineEdit()
        self._smtp_host.setPlaceholderText("smtp.exemple.com")

        self._smtp_port = QSpinBox()
        self._smtp_port.setRange(1, 65535)
        self._smtp_port.setValue(587)

        self._smtp_user = QLineEdit()
        self._smtp_user.setPlaceholderText("notifications@exemple.com")

        self._smtp_password = QLineEdit()
        self._smtp_password.setEchoMode(QLineEdit.EchoMode.Password)
        self._smtp_password.setPlaceholderText("Mot de passe SMTP")

        self._smtp_from = QLineEdit()
        self._smtp_from.setPlaceholderText("Procus Secure <noreply@exemple.com>")

        self._smtp_to = QLineEdit()
        self._smtp_to.setPlaceholderText("admin@exemple.com, noc@exemple.com")

        from core import mailer as _ml
        self._mail_mode = QComboBox()
        self._mail_mode.addItem("Via un serveur SMTP (Gmail, Outlook, OVH, serveur de l'entreprise…)", "relay")
        self._mail_mode.addItem("Envoi direct par Procus Secure (aucun compte à créer)", "direct")
        self._smtp_preset = QComboBox()
        self._smtp_preset.addItem("— Choisir mon fournisseur —", "")
        for _n in _ml.PRESETS:
            self._smtp_preset.addItem(_n, _n)
        self._smtp_preset.addItem("Autre / serveur de l'entreprise", "")
        self._smtp_security = QComboBox()
        for _k, _v in _ml.SECURITY_CHOICES.items():
            self._smtp_security.addItem(_v, _k)
        self._smtp_verify = QCheckBox("Vérifier le certificat du serveur (recommandé)")
        self._smtp_verify.setChecked(True)
        self._mail_help = QLabel("")
        self._mail_help.setWordWrap(True)
        self._mail_help.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 8pt;")
        self._mail_mode.currentIndexChanged.connect(self._on_mail_mode)
        self._smtp_preset.currentIndexChanged.connect(self._on_preset)
        form.addRow("Mode d'envoi :", self._mail_mode)
        form.addRow("Fournisseur :", self._smtp_preset)
        form.addRow("Serveur SMTP :", self._smtp_host)
        form.addRow("Port :", self._smtp_port)
        form.addRow("Sécurité :", self._smtp_security)
        form.addRow("", self._smtp_verify)
        form.addRow("Utilisateur :", self._smtp_user)
        form.addRow("Mot de passe :", self._smtp_password)
        form.addRow("Expéditeur :", self._smtp_from)
        form.addRow("Destinataires :", self._smtp_to)
        form.addRow("", self._mail_help)
        layout.addWidget(grp)
        self._queue_lbl = QLabel("")
        self._queue_lbl.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 8pt;")
        layout.addWidget(self._queue_lbl)

        hint = QLabel("Port 587 = STARTTLS · Port 465 = SSL/TLS · Le serveur est un nom d'hôte (ex : smtp.gmail.com), pas une adresse e-mail. Gmail : utilisez un mot de passe d'application.")
        hint.setWordWrap(True)
        hint.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 7.5pt; font-style: italic;")
        layout.addWidget(hint)

        btns = QHBoxLayout()
        btn_save = self._save_btn()
        btn_save.clicked.connect(self._save_smtp)
        btn_test = icon_button("act_mail", "Envoyer un email test")
        btn_test.setFixedHeight(36)
        btn_test.setStyleSheet(f"background:transparent;color:{COLOR['cyan']};border:1px solid {COLOR['cyan']};border-radius:4px;padding:2px 14px;font-size:9pt;")
        btn_test.clicked.connect(self._test_smtp)
        btn_diag = icon_button("act_search", "Diagnostiquer (pas à pas)")
        btn_diag.setFixedHeight(36)
        btn_diag.setStyleSheet(btn_test.styleSheet())
        btn_diag.clicked.connect(self._diagnose_smtp)
        btn_retry = icon_button("act_refresh", "Renvoyer les e-mails en attente")
        btn_retry.setFixedHeight(36)
        btn_retry.setStyleSheet(btn_test.styleSheet())
        btn_retry.clicked.connect(self._retry_outbox)
        btns.addWidget(btn_save)
        btns.addWidget(btn_test)
        btns.addWidget(btn_diag)
        btns.addWidget(btn_retry)
        btns.addStretch()
        layout.addLayout(btns)
        layout.addStretch()
        self._on_mail_mode()
        return w

    # ─────────────────────────────────────────
    # Onglet 3 — Webhooks
    # ─────────────────────────────────────────

    def _build_tab_webhooks(self) -> QWidget:
        w = QWidget()
        w.setStyleSheet(self._form_style())
        layout = QVBoxLayout(w)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)

        grp = QGroupBox("Webhook (Slack / Teams / générique)")
        grp.setStyleSheet(f"""
            QGroupBox {{ color: {COLOR['text_pri']}; font-weight: 700; font-size: 9pt;
                         border: 1px solid {COLOR['border']}; border-radius: 4px;
                         margin-top: 16px; padding-top: 14px; }}
            QGroupBox::title {{ subcontrol-origin: margin; left: 10px; padding: 0 4px; }}
        """)
        form = QFormLayout(grp)
        form.setSpacing(10)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        self._webhook_url = QLineEdit()
        self._webhook_url.setPlaceholderText("https://hooks.slack.com/services/...")

        self._webhook_secret = QLineEdit()
        self._webhook_secret.setPlaceholderText("Secret HMAC (optionnel)")

        form.addRow("URL Webhook :", self._webhook_url)
        form.addRow("Secret HMAC :", self._webhook_secret)
        self._webhook_allow = QLineEdit()
        self._webhook_allow.setPlaceholderText("Vide = adresses internes interdites (recommandé). Ex : 192.168.1.50, 10.0.0.0/24")
        form.addRow("Hôtes internes autorisés :", self._webhook_allow)
        layout.addWidget(grp)

        hint = QLabel(
            "Pour Slack : créez une Incoming Webhook App et collez l'URL.\n"
            "Pour Teams : utilisez l'URL du connecteur Webhook entrant.\n"
            "Le secret HMAC signe la requête avec X-Hub-Signature-256."
        )
        hint.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 7.5pt;")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        btns = QHBoxLayout()
        btn_save = self._save_btn()
        btn_save.clicked.connect(self._save_webhooks)
        btn_test = icon_button("act_zap", "Tester le webhook")
        btn_test.setFixedHeight(36)
        btn_test.setStyleSheet(f"background:transparent;color:{COLOR['cyan']};border:1px solid {COLOR['cyan']};border-radius:4px;padding:2px 14px;font-size:9pt;")
        btn_test.clicked.connect(self._test_webhook)
        btns.addWidget(btn_save)
        btns.addWidget(btn_test)
        btns.addStretch()
        layout.addLayout(btns)
        layout.addStretch()
        return w

    # ─────────────────────────────────────────
    # Onglet 4 — Sauvegarde
    # ─────────────────────────────────────────

    def _build_tab_backup(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)

        grp = QGroupBox("Base de données SQLite")
        grp.setStyleSheet(f"""
            QGroupBox {{ color: {COLOR['text_pri']}; font-weight: 700; font-size: 9pt;
                         border: 1px solid {COLOR['border']}; border-radius: 4px;
                         margin-top: 16px; padding-top: 14px; }}
            QGroupBox::title {{ subcontrol-origin: margin; left: 10px; padding: 0 4px; }}
        """)
        grp_layout = QVBoxLayout(grp)
        grp_layout.setSpacing(12)

        # Chemin DB
        self._lbl_db_path = QLabel("—")
        self._lbl_db_path.setStyleSheet(
            f"color: {COLOR['cyan']}; font-size: 8pt; font-family: monospace; "
            f"background: {COLOR['bg_main']}; padding: 6px 10px; border-radius: 4px;"
        )
        self._lbl_db_path.setWordWrap(True)
        grp_layout.addWidget(QLabel("Chemin de la base :"))
        grp_layout.addWidget(self._lbl_db_path)

        # Dernière sauvegarde
        self._lbl_last_backup = QLabel("Aucune sauvegarde effectuée dans cette session.")
        self._lbl_last_backup.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 8pt;")
        grp_layout.addWidget(self._lbl_last_backup)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet(f"background: {COLOR['border']}; border: none;")
        sep.setFixedHeight(1)
        grp_layout.addWidget(sep)

        # Boutons
        btn_export = icon_button("act_export", "Exporter la base de données")
        btn_export.setObjectName("btn_primary")
        btn_export.setFixedHeight(38)
        btn_export.clicked.connect(self._export_db)

        btn_import = icon_button("act_import", "Importer / Restaurer une sauvegarde")
        btn_import.setFixedHeight(38)
        btn_import.setStyleSheet(
            f"background:transparent;color:{COLOR['red']};border:1px solid {COLOR['red']};"
            f"border-radius:4px;padding:2px 14px;font-size:9pt;"
        )
        btn_import.clicked.connect(self._import_db)

        grp_layout.addWidget(btn_export)
        grp_layout.addWidget(btn_import)
        layout.addWidget(grp)

        warn = QLabel(
            "Attention : l'importation remplace la base actuelle. "
            "Un redémarrage de l'application est nécessaire après restauration."
        )
        warn.setStyleSheet(
            f"color: {COLOR['red']}; font-size: 8pt; background: {alpha(COLOR['red'], '11')}; "
            f"border: 1px solid {alpha(COLOR['red'], '44')}; border-radius: 4px; padding: 8px;"
        )
        warn.setWordWrap(True)
        layout.addWidget(warn)
        layout.addStretch()
        return w

    # ─────────────────────────────────────────
    # Chargement / Sauvegarde
    # ─────────────────────────────────────────

    def _load_settings(self):
        if not self.db:
            return
        try:
            s = self.db.get_all_settings()
        except Exception:
            s = {}

        self._scan_interval.setValue(int(s.get("scan_interval", 300)))
        self._snmp_interval.setValue(int(s.get("snmp_interval", 60)))
        self._session_timeout.setValue(int(s.get("session_timeout", 30)))
        self._cpu_threshold.setValue(int(s.get("cpu_threshold", 80)))
        self._ram_threshold.setValue(int(s.get("ram_threshold", 85)))
        self._snmp_community.setText(s.get("default_snmp_community", "public"))
        self._presence_grace.setValue(int(s.get("presence_grace_s", 30) or 30))
        try:
            from core import box_reader
            bs = box_reader.settings(self.db)
            self._box_enabled.setChecked(bs["enabled"])
            self._box_addr.setText(bs["address"])
            self._box_pwd.clear()
            self._box_pwd.setPlaceholderText("Mot de passe enregistré (laissez vide pour le garder)" if bs["password"]
                                             else "Mot de passe de la box")
        except Exception:
            pass

        self._smtp_host.setText(s.get("smtp_host", ""))
        self._smtp_port.setValue(int(s.get("smtp_port", 587)))
        self._smtp_user.setText(s.get("smtp_user", ""))
        self._smtp_from.setText(s.get("smtp_from", ""))
        self._smtp_to.setText(s.get("smtp_to", ""))
        i = self._mail_mode.findData(s.get("mail_mode", "relay")); self._mail_mode.setCurrentIndex(max(0, i))
        i = self._smtp_security.findData(s.get("smtp_security", "auto")); self._smtp_security.setCurrentIndex(max(0, i))
        self._smtp_verify.setChecked(s.get("smtp_verify_tls", "1") not in ("0", "false"))
        self._refresh_queue_label()

        self._webhook_allow.setText(s.get("webhook_allow_internal", ""))
        # Déchiffrer les secrets avant affichage dans les champs
        try:
            from core.security import CryptoHelper
            raw_pwd = s.get("smtp_password", "")
            self._smtp_password.setText(CryptoHelper.decrypt(raw_pwd) if raw_pwd else "")
            raw_secret = s.get("webhook_secret", "")
            self._webhook_secret.setText(CryptoHelper.decrypt(raw_secret) if raw_secret else "")
        except Exception:
            self._smtp_password.setText("")
            self._webhook_secret.setText(s.get("webhook_secret", ""))

        try:
            from core.security import CryptoHelper as _CH
            self._webhook_url.setText(_CH.decrypt(s.get("webhook_url", "")))
        except Exception:
            self._webhook_url.setText("")

        # Chemin DB
        if hasattr(self.db, "db_path"):
            mode = getattr(self.db, "mode", "plain")
            etat = {"sqlcipher": "chiffrée (AES-256, SQLCipher)", "file": "chiffrée (AES-256-GCM)",
                    "plain": "NON chiffrée (secrets protégés champ par champ)"}.get(mode, mode)
            self._lbl_db_path.setText(f"{self.db.db_path}\nBase de données : {etat}")

    def _build_tab_automation(self) -> QWidget:
        """Pipeline d'automatisation : fréquence, règles de priorité, rapport périodique."""
        import json
        from core.automation import DEFAULT_RULES
        w = QWidget()
        w.setStyleSheet(self._form_style())
        lay = QVBoxLayout(w)
        lay.setContentsMargins(20, 16, 20, 16)
        info = QLabel("HSR corrèle les événements, calcule une priorité et PROPOSE des actions. Aucune action "
                      "perturbatrice (isoler, bloquer, modifier, patcher) n'est exécutée sans votre validation "
                      "(Incidents → Validation humaine).")
        info.setWordWrap(True)
        lay.addWidget(info)
        form = QFormLayout()
        self._auto_interval = QSpinBox(); self._auto_interval.setRange(30, 3600); self._auto_interval.setSuffix(" s")
        self._auto_window = QSpinBox(); self._auto_window.setRange(1, 1440); self._auto_window.setSuffix(" min")
        self._auto_report_on = QCheckBox("Générer un rapport périodique automatiquement")
        self._auto_report_h = QSpinBox(); self._auto_report_h.setRange(1, 720); self._auto_report_h.setSuffix(" h")
        self._auto_report_dir = QLineEdit(); self._auto_report_dir.setPlaceholderText("Dossier des rapports (par défaut ~/.procus_hsr/reports)")
        self._auto_crit = QSpinBox(); self._auto_crit.setRange(0, 20)
        form.addRow("Fréquence du pipeline", self._auto_interval)
        form.addRow("Fenêtre de corrélation", self._auto_window)
        form.addRow("Poids de la criticité", self._auto_crit)
        form.addRow(self._auto_report_on)
        form.addRow("Rapport toutes les", self._auto_report_h)
        form.addRow("Dossier", self._auto_report_dir)
        lay.addLayout(form)
        btn = self._save_btn()
        btn.clicked.connect(self._save_automation)
        lay.addWidget(btn)
        lay.addStretch()
        if self.db:
            r = json.loads(json.dumps(DEFAULT_RULES))
            try:
                r.update(json.loads(self.db.get_setting("auto_rules", "") or "{}"))
            except ValueError:
                pass
            self._auto_interval.setValue(int(self.db.get_setting("pipeline_interval", "120") or 120))
            self._auto_window.setValue(int(r.get("correlation_window_min", 60)))
            self._auto_crit.setValue(int(r.get("crit_weight", 6)))
            self._auto_report_on.setChecked(self.db.get_setting("auto_report_enabled", "1") == "1")
            self._auto_report_h.setValue(int(float(self.db.get_setting("auto_report_interval_h", "24") or 24)))
            self._auto_report_dir.setText(self.db.get_setting("report_dir", ""))
        return w

    def _save_automation(self):
        if not self.db:
            return
        import json
        try:
            custom = json.loads(self.db.get_setting("auto_rules", "") or "{}")
        except ValueError:
            custom = {}
        custom["correlation_window_min"] = self._auto_window.value()
        custom["crit_weight"] = self._auto_crit.value()
        self.db.set_setting("auto_rules", json.dumps(custom))
        self.db.set_setting("pipeline_interval", str(self._auto_interval.value()))
        self.db.set_setting("auto_report_enabled", "1" if self._auto_report_on.isChecked() else "0")
        self.db.set_setting("auto_report_interval_h", str(self._auto_report_h.value()))
        self.db.set_setting("report_dir", self._auto_report_dir.text().strip())
        QMessageBox.information(self, "Automatisation", "Réglages enregistrés (la fréquence s'applique au prochain démarrage).")

    # ── box (facultatif) ──
    def _save_box(self):
        if not self.db:
            return
        from core import box_reader
        try:
            box_reader.save_settings(self.db, self._box_enabled.isChecked(), self._box_addr.text(), self._box_pwd.text())
        except box_reader.BoxError as e:
            QMessageBox.warning(self, "Box", str(e))
            return
        self._box_pwd.clear()
        self._box_result.setText("Enregistré. Les appareils seront relus toutes les 2 minutes." if self._box_enabled.isChecked()
                                 else "Enregistré. La lecture de la box est désactivée.")

    def _test_box(self):
        from core import box_reader
        addr, pwd = self._box_addr.text(), self._box_pwd.text()
        if not pwd and self.db:
            pwd = box_reader.settings(self.db)["password"]
        self._btn_box_test.setEnabled(False)
        self._box_result.setText("Test en cours…")
        import threading
        threading.Thread(target=lambda: self._box_done.emit(*box_reader.test_connection(addr, pwd)), daemon=True).start()

    def _on_box_result(self, ok: bool, msg: str):
        self._btn_box_test.setEnabled(True)
        self._box_result.setText(("Réussi : " if ok else "Échec : ") + msg)

    def _save_supervision(self):
        if not self.db:
            return
        self.db.set_setting("scan_interval",          str(self._scan_interval.value()))
        self.db.set_setting("snmp_interval",          str(self._snmp_interval.value()))
        self.db.set_setting("session_timeout",        str(self._session_timeout.value()))
        self.db.set_setting("cpu_threshold",          str(self._cpu_threshold.value()))
        self.db.set_setting("ram_threshold",          str(self._ram_threshold.value()))
        self.db.set_setting("default_snmp_community", self._snmp_community.text().strip())
        self.db.set_setting("presence_grace_s",       str(self._presence_grace.value()))

        # Mise à jour immédiate des intervalles du scheduler
        if self.scheduler and hasattr(self.scheduler, "set_intervals"):
            from PyQt6.QtCore import QMetaObject, Qt, Q_ARG
            # Le scheduler vit dans son propre QThread → appel mis en file (thread-safe)
            QMetaObject.invokeMethod(
                self.scheduler, "set_intervals", Qt.ConnectionType.QueuedConnection,
                Q_ARG(int, self._scan_interval.value()),
                Q_ARG(int, self._snmp_interval.value()),
            )

        QMessageBox.information(self, "Paramètres sauvegardés",
                                "Intervalles de supervision mis à jour.")

    def _save_smtp(self):
        host = self._smtp_host.text().strip()
        if host and ("@" in host or "://" in host or " " in host):
            QMessageBox.warning(self, "Serveur SMTP invalide",
                                "« Serveur SMTP » doit être un nom d'hôte (ex : smtp.gmail.com), "
                                "pas une adresse e-mail.")
            return
        if not self.db:
            return
        self.db.set_setting("smtp_host", self._smtp_host.text().strip())
        self.db.set_setting("smtp_port", str(self._smtp_port.value()))
        self.db.set_setting("smtp_user", self._smtp_user.text().strip())
        self.db.set_setting("smtp_from", self._smtp_from.text().strip())
        self.db.set_setting("smtp_to",   self._smtp_to.text().strip())
        self.db.set_setting("mail_mode", self._mail_mode.currentData())
        self.db.set_setting("smtp_security", self._smtp_security.currentData())
        self.db.set_setting("smtp_verify_tls", "1" if self._smtp_verify.isChecked() else "0")

        # Chiffrer le mot de passe avant stockage
        pwd = self._smtp_password.text()
        if pwd:
            try:
                from core.security import CryptoHelper
                self.db.set_setting("smtp_password", CryptoHelper.encrypt(pwd))
            except Exception:
                self.db.set_setting("smtp_password", pwd)

        # Mettre à jour le config_json du média Email SMTP en DB
        self._sync_smtp_media()
        QMessageBox.information(self, "Paramètres SMTP sauvegardés",
                                "Configuration SMTP enregistrée.")

    def _smtp_fields(self, encrypted_pwd: str) -> dict:
        return {
            "mail_mode":     self._mail_mode.currentData(),
            "smtp_host":     self._smtp_host.text().strip(),
            "smtp_port":     self._smtp_port.value(),
            "smtp_security": self._smtp_security.currentData(),
            "smtp_verify_tls": self._smtp_verify.isChecked(),
            "smtp_user":     self._smtp_user.text().strip(),
            "smtp_password": encrypted_pwd,
            "smtp_from":     self._smtp_from.text().strip(),
            "smtp_to":       self._smtp_to.text().strip(),
        }

    def _on_mail_mode(self, *_):
        direct = self._mail_mode.currentData() == "direct"
        for w in (self._smtp_preset, self._smtp_host, self._smtp_port, self._smtp_security, self._smtp_verify,
                  self._smtp_user, self._smtp_password):
            w.setEnabled(not direct)
        self._mail_help.setText(
            "Procus Secure remet lui-même le message au serveur de messagerie du destinataire (port 25). Aucun compte à créer, "
            "mais beaucoup de fournisseurs d'accès bloquent ce port et le message peut arriver dans les indésirables : "
            "utilisez « Diagnostiquer » pour vérifier." if direct else
            "Choisissez votre fournisseur : le serveur, le port et la sécurité se remplissent tout seuls. Utilisez « Diagnostiquer » "
            "en cas de problème : il vous dit en français quelle étape échoue.")

    def _on_preset(self, *_):
        from core import mailer as _ml
        p = _ml.PRESETS.get(self._smtp_preset.currentData() or "")
        if not p:
            return
        self._smtp_host.setText(p["host"])
        self._smtp_port.setValue(p["port"])
        i = self._smtp_security.findData(p["security"]); self._smtp_security.setCurrentIndex(max(0, i))
        self._mail_help.setText(p["help"])

    def _refresh_queue_label(self):
        try:
            from core.mailer import Outbox
            n = Outbox(self.db).count_pending()
            self._queue_lbl.setText(f"{n} e-mail(s) d'alerte en attente de renvoi automatique." if n else
                                    "Aucun e-mail en attente : les alertes qui n'ont pas pu partir sont renvoyées automatiquement.")
        except Exception:
            pass

    @staticmethod
    def _encrypt_for_test(pwd: str) -> str:
        try:
            from core.security import CryptoHelper
            return CryptoHelper.encrypt(pwd) if pwd else ""
        except Exception:
            return pwd

    def _diagnose_smtp(self):
        import json
        from core import mailer as _ml
        from core.notifier import NotifierManager
        from ui.async_call import run_blocking
        cfg = NotifierManager._load_config(json.dumps(self._smtp_fields(self._encrypt_for_test(self._smtp_password.text()))))
        steps, err = run_blocking(lambda: _ml.diagnose(cfg))
        if err is not None:
            QMessageBox.warning(self, "Diagnostic", f"{type(err).__name__} : {err}")
            return
        lines = []
        for st in steps:
            lines.append(f"{'OK' if st['ok'] else 'ÉCHEC'} — {st['step']}" + (f" — {st['detail']}" if st["detail"] else ""))
            if not st["ok"] and st["advice"]:
                lines.append(f"      → {st['advice']}")
        ok = all(st["ok"] for st in steps)
        (QMessageBox.information if ok else QMessageBox.warning)(
            self, "Diagnostic e-mail", "\n".join(lines) + ("\n\nTout est en ordre." if ok else ""))

    def _retry_outbox(self):
        from core.notifier import NotifierManager
        from ui.async_call import run_blocking
        res, err = run_blocking(lambda: NotifierManager(db=self.db).flush_outbox(force=True))
        self._refresh_queue_label()
        if err is not None:
            QMessageBox.warning(self, "E-mails en attente", f"{type(err).__name__} : {err}")
        else:
            QMessageBox.information(self, "E-mails en attente",
                                    f"Envoyés : {res['sent']} · abandonnés : {res['failed']} · encore en attente : {res['kept']}.")

    def _sync_smtp_media(self):
        """Synchronise les paramètres SMTP dans la table media_types."""
        if not self.db:
            return
        import json
        try:
            from core.security import CryptoHelper
            encrypted_pwd = CryptoHelper.encrypt(self._smtp_password.text()) if self._smtp_password.text() else self.db.get_setting("smtp_password", "")
        except Exception:
            encrypted_pwd = self._smtp_password.text()

        config = self._smtp_fields(encrypted_pwd)
        # Mise à jour du premier média de type email
        media = self.db.fetchone("SELECT id FROM media_types WHERE type='email' LIMIT 1")
        if media:
            self.db.update_media_config(media["id"], json.dumps(config))

    def _encrypt_secret(self, value: str):
        """Chiffre un secret ; retourne None (et prévient l'utilisateur) si le chiffrement échoue,
        pour ne JAMAIS stocker un secret en clair."""
        if not value:
            return ""
        from core.security import CryptoHelper
        token = CryptoHelper.encrypt(value)
        if token == value:      # CryptoHelper a replié sur le clair → refus
            QMessageBox.critical(self, "Chiffrement indisponible",
                                 "Impossible de chiffrer le secret : enregistrement annulé.")
            return None
        return token

    def _save_webhooks(self):
        if not self.db:
            return
        url    = self._encrypt_secret(self._webhook_url.text().strip())
        secret = self._encrypt_secret(self._webhook_secret.text().strip())
        if url is None or secret is None:
            return
        self.db.set_setting("webhook_url",    url)
        self.db.set_setting("webhook_secret", secret)
        self.db.set_setting("webhook_allow_internal", self._webhook_allow.text().strip())

        # Sync média Slack/webhook
        self._sync_webhook_media()
        QMessageBox.information(self, "Webhook sauvegardé",
                                "Configuration webhook enregistrée (chiffrée).")

    def _sync_webhook_media(self):
        if not self.db:
            return
        import json
        config = {
            "webhook_url":    self.db.get_setting("webhook_url", ""),       # déjà chiffrés
            "webhook_secret": self.db.get_setting("webhook_secret", ""),
        }
        # Mise à jour du premier média Slack ou webhook
        media = self.db.fetchone(
            "SELECT id FROM media_types WHERE type='webhook' AND active=1 LIMIT 1"
        )
        if media:
            self.db.update_media_config(media["id"], json.dumps(config))

    # ─────────────────────────────────────────
    # Tests
    # ─────────────────────────────────────────

    def _test_smtp(self):
        """Teste l'envoi SMTP avec les paramètres saisis ; affiche la cause réelle d'un échec."""
        from core.notifier import NotifierManager, validate_smtp_settings
        from ui.async_call import run_blocking
        import json
        problem = validate_smtp_settings(self._smtp_host.text(), self._smtp_port.value(),
                                         self._smtp_to.text(), self._mail_mode.currentData())
        if problem:
            QMessageBox.warning(self, "Test SMTP", f"{problem}")
            return
        try:
            from core.security import CryptoHelper
            encrypted_pwd = CryptoHelper.encrypt(self._smtp_password.text()) if self._smtp_password.text() else ""
        except Exception:
            encrypted_pwd = self._smtp_password.text()

        config = self._smtp_fields(encrypted_pwd)
        test_event = {
            "host_name": "test-host", "severity": "high",
            "event_type": "test", "description": "Test de notification Procus Secure.",
            "port": 22, "state_before": "closed", "state_after": "open",
        }
        mgr = NotifierManager(db=self.db)
        cfg = mgr._load_config(json.dumps(config))
        res, err = run_blocking(lambda: mgr._send_email_ex(test_event, cfg, "Test SMTP"))
        if err is not None:
            ok, detail = False, f"{type(err).__name__} : {err}"
        else:
            ok, detail = res
        if ok:
            QMessageBox.information(self, "Test SMTP", f"{detail}")
        else:
            QMessageBox.warning(self, "Test SMTP", f"Échec de l'envoi.\n\n{detail}")

    def _test_webhook(self):
        """Teste l'envoi Webhook avec les paramètres saisis."""
        from core.notifier import NotifierManager
        import json

        url    = self._webhook_url.text().strip()
        secret = self._webhook_secret.text().strip()

        if not url:
            QMessageBox.warning(self, "Webhook", "URL webhook vide.")
            return

        config = {"webhook_url": url, "webhook_secret": secret}
        test_event = {
            "host_name": "test-host", "severity": "high",
            "event_type": "test", "description": "Test de notification Procus Secure.",
            "port": 443, "state_before": "closed", "state_after": "open",
        }
        mgr = NotifierManager(db=self.db)
        name = "Slack Test" if "slack" in url.lower() or "hooks.slack" in url else "Webhook Test"
        if "slack" in name.lower():
            ok = mgr._send_slack(test_event, config, name)
        else:
            ok = mgr._send_webhook(test_event, config, name)

        if ok:
            QMessageBox.information(self, "Test Webhook", "Webhook de test envoyé avec succès !")
        else:
            QMessageBox.warning(self, "Test Webhook",
                                "Échec. Vérifiez l'URL et consultez les logs.")

    # ─────────────────────────────────────────
    # Sauvegarde / Restauration DB
    # ─────────────────────────────────────────

    def _export_db(self):
        if not self.db:
            QMessageBox.warning(self, "Export", "Aucune base de données ouverte.")
            return

        from datetime import datetime
        default_name = f"procus_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        path, _ = QFileDialog.getSaveFileName(
            self, "Exporter la base de données",
            default_name,
            "Base SQLite (*.db);;Tous les fichiers (*)"
        )
        if not path:
            return

        try:
            self.db.backup_to(path)      # sauvegarde cohérente (compatible WAL)
            self._lbl_last_backup.setText(
                f"Dernière sauvegarde : {datetime.now().strftime('%d/%m/%Y %H:%M:%S')} → {path}"
            )
            self._lbl_last_backup.setStyleSheet(f"color: {COLOR['green']}; font-size: 8pt;")
            QMessageBox.information(
                self, "Export réussi",
                f"Base de données exportée avec succès :\n{path}"
            )
        except Exception as e:
            QMessageBox.critical(self, "Erreur export", f"Erreur lors de l'export :\n{e}")

    def _import_db(self):
        if not self.db:
            QMessageBox.warning(self, "Import", "Aucune base de données ouverte.")
            return

        path, _ = QFileDialog.getOpenFileName(
            self, "Sélectionner une sauvegarde",
            "",
            "Base SQLite (*.db);;Tous les fichiers (*)"
        )
        if not path:
            return

        ok, msg = self.db.validate_backup(path, getattr(self.db, '_key_hex', None))
        if not ok:
            QMessageBox.critical(self, "Sauvegarde invalide", f"{msg}")
            return

        reply = QMessageBox.warning(
            self, "Confirmation restauration",
            f"Remplacer la base de données actuelle par :\n\n{path}\n\n"
            "Une sauvegarde de sécurité de la base actuelle sera créée automatiquement.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        try:
            safety = self.db.restore_from(path)
            self._load_settings()
            QMessageBox.information(
                self, "Restauration réussie",
                "Base de données restaurée à chaud (aucun redémarrage nécessaire).\n\n"
                f"Sauvegarde de sécurité de l'ancienne base :\n{safety}\n\n"
                "Reconnectez-vous si votre compte n'existe pas dans cette sauvegarde."
            )
        except Exception as e:
            QMessageBox.critical(self, "Erreur import", f"Erreur lors de la restauration :\n{e}")

    def set_scheduler(self, scheduler):
        """Reçoit la référence du scheduler après démarrage (depuis main_window)."""
        self.scheduler = scheduler

    def refresh(self):
        self._load_settings()
