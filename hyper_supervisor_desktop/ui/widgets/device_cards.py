"""
Carte réseau — éléments d'interface partagés : barre flottante (Rafraîchir · Carte · Liste · Détails), filtres de connexion,
cartes d'appareils (vue Liste compacte et vue Détails complète), fenêtre de modification des informations.
Tout est écrit pour un public non informaticien : phrases courtes, aucune abréviation sans explication.
"""
from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFormLayout, QFrame, QGridLayout, QHBoxLayout, QLabel, QLineEdit,
                             QPushButton, QScrollArea, QSpinBox, QVBoxLayout, QWidget, QGraphicsDropShadowEffect)
from PyQt6.QtGui import QColor

from ui.icons import icon_button
from ui.styles import COLOR

FILTERS = [("all", "Tous"), ("wifi", "Wi-Fi"), ("ethernet", "Ethernet")]
FILTER_ICONS = {"wifi": "dev_ap", "ethernet": "dev_switch", "access": "dev_firewall"}
STATUS_TXT = {"online": "En ligne", "offline": "Hors ligne", "unreachable": "Injoignable", "degraded": "Dégradé", "unknown": "Inconnu"}
STATUS_COL = {"online": COLOR["green"], "offline": COLOR["red"], "unreachable": COLOR["accent"], "degraded": COLOR["yellow"]}
TYPE_FR = {"router": "Routeur / box", "ap": "Borne Wi-Fi", "switch": "Commutateur", "firewall": "Pare-feu", "server": "Serveur",
           "workstation": "Ordinateur", "printer": "Imprimante", "mobile": "Téléphone / tablette", "iot": "Objet connecté",
           "tv": "TV / média", "camera": "Caméra", "unknown": "Appareil"}
ROLE_FR = {"server": "Serveur", "workstation": "Poste de travail", "network": "Réseau", "printer": "Imprimante", "camera": "Caméra",
           "iot": "Objet connecté", "mobile": "Mobile", "guest": "Invité", "admin": "Administration", "unknown": "Non classé"}


def dash(v) -> str:
    return "—" if v in (None, "", []) else str(v)


def conn_badge_text(info: dict) -> str:
    c = info["conn"]
    if c["type"] == "unknown":
        return "Connexion inconnue"
    txt = c["label"] + (" (probable)" if c["probable"] else "")
    if c["detail"] and c["type"] == "ethernet":
        txt = c["detail"]
    return txt


class FilterChips(QWidget):
    changed = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)
        self._btns: dict[str, QPushButton] = {}
        for key, label in FILTERS:
            b = QPushButton(label)
            b.setCheckable(True)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            if key in FILTER_ICONS:
                from PyQt6.QtGui import QIcon
                from ui.icons import ICONS, _svg_icon
                b.setIcon(QIcon(_svg_icon(ICONS[FILTER_ICONS[key]], 16, COLOR["cyan"])))
            b.clicked.connect(lambda _=False, k=key: self.set_filter(k))
            self._btns[key] = b
            lay.addWidget(b)
        lay.addStretch()
        self.current = "all"
        self.set_filter("all", emit=False)

    def set_filter(self, key: str, emit: bool = True):
        self.current = key
        for k, b in self._btns.items():
            b.setChecked(k == key)
            b.setStyleSheet(
                f"QPushButton {{ border: 1px solid {COLOR['cyan']}; border-radius: 13px; padding: 4px 14px; font-weight: 600;"
                f" color: {'#1a1400' if k == key else COLOR['cyan']}; background: {COLOR['cyan'] if k == key else 'transparent'}; }}"
                f"QPushButton:hover {{ background: {COLOR['cyan'] if k == key else COLOR['hover']}; }}")
        if emit:
            self.changed.emit(key)


class FloatingBar(QFrame):
    """Barre de tâches flottante : Rafraîchir · Carte · Liste · Détails."""
    refresh_clicked = pyqtSignal()
    mode_changed = pyqtSignal(str)

    MODES = [("map", "Carte"), ("list", "Liste"), ("details", "Détails")]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("floating_bar")
        self.setStyleSheet(f"#floating_bar {{ background: {COLOR['bg_sidebar']}; border: 1px solid {COLOR['border']}; border-radius: 16px; }}"
                           f"#floating_bar QPushButton {{ border-radius: 8px; padding: 8px 18px; font-weight: 600; "
                           f"border: 1px solid {COLOR['border']}; background: {COLOR['bg_card']}; color: {COLOR['text_pri']}; }}"
                           f"#floating_bar QPushButton:hover {{ background: {COLOR['hover']}; }}")
        sh = QGraphicsDropShadowEffect(self)
        sh.setBlurRadius(24)
        sh.setOffset(0, 4)
        sh.setColor(QColor(0, 0, 0, 160))
        self.setGraphicsEffect(sh)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(12, 10, 12, 10)
        lay.setSpacing(8)
        self.btn_refresh = icon_button("act_refresh", "Rafraîchir")
        self.btn_refresh.setToolTip("Relit tous les appareils et leur état")
        self.btn_refresh.clicked.connect(self.refresh_clicked.emit)
        lay.addWidget(self.btn_refresh)
        lay.addSpacing(10)
        self.buttons: dict[str, QPushButton] = {}
        for key, label in self.MODES:
            b = QPushButton(label)
            b.setCheckable(True)
            b.clicked.connect(lambda _=False, k=key: self.set_mode(k))
            self.buttons[key] = b
            lay.addWidget(b)
        self.mode = "map"
        self.set_mode("map", emit=False)

    def set_mode(self, mode: str, emit: bool = True):
        self.mode = mode
        for k, b in self.buttons.items():
            b.setChecked(k == mode)
            if k == mode:
                b.setStyleSheet(f"background: {COLOR['cyan']}; color: #1a1400; border: 1px solid {COLOR['cyan']};")
            else:
                b.setStyleSheet("")
        if emit:
            self.mode_changed.emit(mode)


class DeviceCard(QFrame):
    """Carte d'un appareil. mode « list » : nom, type de connexion, état. mode « details » : toutes les informations + actions."""
    clicked = pyqtSignal(int)
    action = pyqtSignal(str, int)          # ("ping" | "scan" | "access" | "edit" | "approve", host_id)

    def __init__(self, info: dict, mode: str = "list", extra: str = "", parent=None):
        super().__init__(parent)
        self.info, self.mode = info, mode
        self._missing: list[str] = []
        inactive = not info["active"]
        self.setObjectName("dev_card")
        bg = "#3a362a" if inactive and mode == "list" else COLOR["bg_card"]
        self.setStyleSheet(f"#dev_card {{ background: {bg}; border: 1px solid {COLOR['border']}; border-radius: 10px; }}"
                           f"#dev_card QLabel {{ background: transparent; border: none; }}")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(6)
        head = QHBoxLayout()
        from ui.icons import device_pixmap
        ico = QLabel()
        ico.setPixmap(device_pixmap(info["device_type"], 26, STATUS_COL.get(info["status"], COLOR["text_sec"])))
        ico.setFixedSize(30, 30)
        head.addWidget(ico)
        name = QLabel(info["name"] or info["ip"])
        name.setStyleSheet(f"font-size: 11pt; font-weight: 700; color: {COLOR['text_pri']};")
        name.setWordWrap(True)
        head.addWidget(name, 1)
        if mode == "details":
            ed = icon_button("act_edit", "")
            ed.setToolTip("Modifier les informations de cet appareil")
            ed.setFixedSize(30, 28)
            ed.clicked.connect(lambda: self.action.emit("edit", info["id"]))
            head.addWidget(ed)
        lay.addLayout(head)
        if mode == "list":
            self._build_list(lay, info, extra)
        else:
            self._build_details(lay, info)

    def mousePressEvent(self, e):
        super().mousePressEvent(e)
        self.clicked.emit(self.info["id"])

    # ── vue Liste ──
    def _build_list(self, lay, info, extra):
        if extra:
            lbl = QLabel(extra)
            lbl.setStyleSheet(f"color: {COLOR['cyan']}; font-weight: 600;")
            lay.addWidget(lbl)
            return
        ip = QLabel(info["ip"] + (f"  ·  {info['vendor']}" if info["vendor"] else ""))
        ip.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 8pt;")
        lay.addWidget(ip)
        row = QHBoxLayout()
        from ui.icons import dot_label
        row.addWidget(dot_label(STATUS_COL.get(info["status"], COLOR["text_sec"])))
        st = QLabel(STATUS_TXT.get(info["status"], info["status"]))
        st.setStyleSheet(f"color: {STATUS_COL.get(info['status'], COLOR['text_sec'])}; font-weight: 600;")
        row.addWidget(st)
        row.addStretch()
        badge = QLabel(conn_badge_text(info))
        badge.setStyleSheet(f"background: {COLOR['bg_row']}; border-radius: 10px; padding: 3px 10px; color: {COLOR['text_pri']};")
        row.addWidget(badge)
        lay.addLayout(row)
        if info["rx_fmt"] and info["active"]:
            r = QLabel(f"↓ {info['rx_fmt']}   ↑ {info['tx_fmt']}")
            r.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 8pt;")
            lay.addWidget(r)

    # ── vue Détails ──
    def _section(self, lay, title):
        t = QLabel(title)
        t.setStyleSheet(f"font-size: 10pt; font-weight: 700; color: {COLOR['cyan']}; margin-top: 6px;")
        lay.addWidget(t)

    def _row(self, lay, key, val, missing: str = ""):
        """Une ligne n'est affichée que si l'information est réelle ; sinon son nom est noté dans « Non disponible »."""
        if val in (None, "", []):
            if missing:
                self._missing.append(missing)
            return
        r = QHBoxLayout()
        k = QLabel(key)
        k.setStyleSheet(f"color: {COLOR['text_sec']};")
        v = QLabel(str(val))
        v.setStyleSheet(f"color: {COLOR['text_pri']}; font-weight: 600;")
        v.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        v.setWordWrap(True)
        v.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        r.addWidget(k)
        r.addWidget(v, 1)
        lay.addLayout(r)

    def _build_details(self, lay, i):
        c = i["conn"]
        self._section(lay, "Informations sur l'appareil")
        self._row(lay, "Type", TYPE_FR.get(i["device_type"], "Appareil"))
        self._row(lay, "Fabricant", i["vendor"], "fabricant")
        self._row(lay, "Nom sur le réseau", i["dns_name"])
        self._row(lay, "Modèle", i["model"], "modèle")
        self._row(lay, "Système", i["os"], "système")
        self._row(lay, "Rôle", ROLE_FR.get(i["role"] or "", None))
        self._row(lay, "État", STATUS_TXT.get(i["status"], i["status"]))
        self._section(lay, "Connexion")
        self._row(lay, "Mode", conn_badge_text(i) if c["type"] != "unknown" else None, "mode de connexion")
        if c["source_label"]:
            self._row(lay, "Information", c["source_label"])
        self._row(lay, "Qualité", i["quality"], "qualité")
        self._row(lay, "Temps de réponse", f"{i['latency_ms']:.0f} ms" if i["latency_ms"] is not None else None)
        self._row(lay, "Réseau", i["network"])
        self._row(lay, "Joint via", i["reach"])
        if c["type"] == "wifi":
            self._row(lay, "Bande Wi-Fi", f"{i['band']} GHz" if i["band"] else None, "bande Wi-Fi")
            self._row(lay, "Signal (RSSI)", f"{i['rssi']} dBm" if i["rssi"] is not None else None, "signal Wi-Fi")
        self._row(lay, "Vitesse de la liaison", f"{i['link_mbps']} Mb/s" if i["link_mbps"] else None, "vitesse de la liaison")
        self._row(lay, "Débit reçu / envoyé", f"↓ {i['rx_fmt']}  ↑ {i['tx_fmt']}" if i["rx_fmt"] else None)
        self._row(lay, "Pic sur 24 h", f"↓ {i['peak_rx_fmt'] or '—'}  ↑ {i['peak_tx_fmt'] or '—'}" if (i["peak_rx_fmt"] or i["peak_tx_fmt"]) else None)
        self._section(lay, "Adresses")
        self._row(lay, "IPv4", i["ip"])
        self._row(lay, "IPv6", i["ipv6"])
        self._row(lay, "MAC", i["mac"])
        self._section(lay, "Présence")
        self._row(lay, "Première connexion", i["first_seen"])
        self._row(lay, "Dernière vue", i["last_seen"])
        if i["cpu"] is not None or i["ram"] is not None:
            self._section(lay, "Charge de l'appareil")
            self._row(lay, "Processeur", f"{i['cpu']:.0f} %" if i["cpu"] is not None else None)
            self._row(lay, "Mémoire", f"{i['ram']:.0f} %" if i["ram"] is not None else None)
            self._row(lay, "Disque", f"{i['disk']:.0f} %" if i["disk"] is not None else None)
        self._section(lay, "Sécurité")
        self._row(lay, "Référentiel", "Attendu" if i["approved"] else "Inconnu : à vérifier")
        self._row(lay, "Connexion coupée", "Oui" if i["blocked"] else "Non")
        self._row(lay, "Services ouverts", ", ".join(i["open_ports"]) if i["open_ports"] else None)
        if i.get("admin_url"):
            self._row(lay, "Page d'administration", i["admin_url"])
        self._row(lay, "Supervision", " · ".join(x for x, ok in (("Agent", i["agent"]), ("SNMP", i["snmp"])) if ok) or "Ping seulement")
        self._row(lay, "Groupe / lieu", " · ".join(x for x in (i["group"], i["location"]) if x) or None)
        self._row(lay, "Responsable", i["owner"])
        if self._missing:
            self._section(lay, "Non disponible pour l'instant")
            n = QLabel("Cet appareil ne les annonce pas : " + ", ".join(self._missing) + ".\n"
                       "Pour les obtenir : activez la lecture de la box (Paramètres), installez l'agent Procus sur cet appareil, "
                       "ou saisissez-les avec le bouton « Modifier ».")
            n.setWordWrap(True)
            n.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 9pt;")
            lay.addWidget(n)
        self._section(lay, "Actions")
        for key, label, ico in (("access", "Autoriser / bloquer cet appareil", "act_shield"), ("scan", "Faire un scan réseau", "act_search"),
                                ("ping", "Faire un ping", "act_activity"), ("connect", "Se connecter à cet équipement", "act_link")) + (
                ((("approve", "Approuver cet appareil", "act_check"),) if not i["approved"] else ())):
            b = icon_button(ico, label)
            b.setStyleSheet(f"QPushButton {{ background: #7a5f14; color: white; border: none; border-radius: 6px; padding: 9px; font-weight: 600; }}"
                            f"QPushButton:hover {{ background: #8f7019; }}")
            b.clicked.connect(lambda _=False, k=key: self.action.emit(k, i["id"]))
            lay.addWidget(b)


class CardsPage(QScrollArea):
    """Grille de cartes (3 colonnes) pour les vues Liste et Détails."""
    card_clicked = pyqtSignal(int)
    card_action = pyqtSignal(str, int)

    def __init__(self, mode: str, parent=None):
        super().__init__(parent)
        self.mode = mode
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self._host = QWidget()
        self._grid = QGridLayout(self._host)
        self._grid.setContentsMargins(4, 4, 4, 90)       # marge basse : la barre flottante ne cache pas la dernière ligne
        self._grid.setSpacing(12)
        self.setWidget(self._host)
        self.cards: list[DeviceCard] = []
        self.columns = 3

    def fill(self, infos: list[dict]):
        for c in self.cards:
            c.setParent(None)
            c.deleteLater()
        self.cards = []
        while self._grid.count():
            self._grid.takeAt(0)
        routers = [i for i in infos if i["device_type"] in ("router", "ap")]
        gateway = routers[0] if routers else None
        active = [i for i in infos if i["active"] and i is not gateway]
        inactive = [i for i in infos if not i["active"] and i is not gateway]
        ordered = ([(gateway, f"{len([x for x in infos if x['active'] and x is not gateway])} appareil(s) connecté(s)")]
                   if self.mode == "list" and gateway else ([(gateway, "")] if gateway else []))
        ordered += [(i, "") for i in active + inactive]
        for n, (info, extra) in enumerate(ordered):
            card = DeviceCard(info, self.mode, extra if self.mode == "list" else "")
            card.clicked.connect(self.card_clicked.emit)
            card.action.connect(self.card_action.emit)
            self._grid.addWidget(card, n // self.columns, n % self.columns, Qt.AlignmentFlag.AlignTop)
            self.cards.append(card)
        for c in range(self.columns):
            self._grid.setColumnStretch(c, 1)
        self._grid.setRowStretch(len(ordered) // self.columns + 1, 1)


class EditDeviceDialog(QDialog):
    """Modifier ce que l'application ne peut pas deviner : mode de connexion, modèle, signal…"""
    def __init__(self, info: dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Informations — {info['name']}")
        self.setMinimumWidth(420)
        form = QFormLayout(self)
        note = QLabel("Ce que vous saisissez ici remplace la détection automatique.\nLaissez « Automatique » pour revenir à la détection.")
        note.setStyleSheet(f"color: {COLOR['text_sec']};")
        form.addRow(note)
        self.conn = QComboBox()
        for key, label in (("auto", "Automatique"), ("wifi", "Wi-Fi"), ("ethernet", "Ethernet (câble)")):
            self.conn.addItem(label, key)
        cur = info["conn"]["type"] if info["conn"]["source"] == "manual" else "auto"
        self.conn.setCurrentIndex(max(0, self.conn.findData(cur)))
        form.addRow("Mode de connexion :", self.conn)
        self.detail = QLineEdit(info["conn"]["detail"] if info["conn"]["source"] == "manual" else "")
        self.detail.setPlaceholderText("Ex. : Port 4, Salon, nom du Wi-Fi")
        form.addRow("Précision :", self.detail)
        from core.device_info import TYPE_CHOICES
        self.dtype = QComboBox()
        self.dtype.addItem("Automatique", "auto")
        for key, label in TYPE_CHOICES:
            self.dtype.addItem(label, key)
        self.dtype.setCurrentIndex(max(0, self.dtype.findData(info["device_type"] if info.get("type_manual") else "auto")))
        form.addRow("Type d'appareil :", self.dtype)
        self.model = QLineEdit(info["model"] or "")
        self.model.setPlaceholderText("Ex. : iPhone 15, MacBook Air")
        form.addRow("Modèle :", self.model)
        self.band = QComboBox()
        for key, label in (("", "Inconnue"), ("2.4", "2,4 GHz"), ("5", "5 GHz"), ("6", "6 GHz")):
            self.band.addItem(label, key)
        self.band.setCurrentIndex(max(0, self.band.findData(info["band"] or "")))
        form.addRow("Bande Wi-Fi :", self.band)
        self.rssi = QSpinBox()
        self.rssi.setRange(-100, 0)
        self.rssi.setSpecialValueText("Inconnu")
        self.rssi.setValue(info["rssi"] if info["rssi"] is not None else 0)
        self.rssi.setSuffix(" dBm")
        form.addRow("Signal Wi-Fi (RSSI) :", self.rssi)
        self.link = QSpinBox()
        self.link.setRange(0, 400000)
        self.link.setSpecialValueText("Inconnue")
        self.link.setValue(info["link_mbps"] or 0)
        self.link.setSuffix(" Mb/s")
        form.addRow("Vitesse de la liaison :", self.link)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        form.addRow(bb)

    def values(self) -> dict:
        return {"device_type": self.dtype.currentData(), "conn_type": self.conn.currentData(), "conn_detail": self.detail.text(), "model": self.model.text(),
                "wifi_band": self.band.currentData(), "rssi": self.rssi.value() if self.rssi.value() != 0 else None,
                "link_mbps": self.link.value() or None}


class ConnectDeviceDialog(QDialog):
    """Se connecter à un routeur, pare-feu, commutateur, borne ou box : adresse IP + mot de passe (ou autre moyen)."""
    _done = pyqtSignal(bool, str)

    def __init__(self, db, host: dict | None = None, who: str = "system", parent=None):
        super().__init__(parent)
        from core import device_link as dl
        self.db, self.who, self.dl = db, who, dl
        self.setWindowTitle("Se connecter à un équipement")
        self.setMinimumWidth(500)
        form = QFormLayout(self)
        note = QLabel("Procus Secure se connecte en lecture seule pour lire les vraies informations de l'équipement. "
                      "Le mot de passe est chiffré. Rien n'est modifié sur l'équipement.")
        note.setWordWrap(True)
        note.setStyleSheet(f"color: {COLOR['text_sec']};")
        form.addRow(note)
        self.addr = QLineEdit(host["ip_address"] if host else "")
        self.addr.setPlaceholderText("Adresse IP de l'équipement, ex. 192.168.1.254")
        form.addRow("Adresse IP :", self.addr)
        self.name = QLineEdit(host["name"] if host else "")
        self.name.setPlaceholderText("Nom affiché (facultatif)")
        form.addRow("Nom :", self.name)
        self.kind = QComboBox()
        for k, label in dl.KINDS:
            self.kind.addItem(label, k)
        if host:
            self.kind.setCurrentIndex(max(0, self.kind.findData((host.get("device_type") or "router"))))
        form.addRow("Type d'équipement :", self.kind)
        self.method = QComboBox()
        for k, label in dl.METHODS:
            self.method.addItem(label, k)
        self.method.currentIndexChanged.connect(self._sync)
        form.addRow("Moyen de connexion :", self.method)
        self.user = QLineEdit(); self.user.setPlaceholderText("Identifiant (ex. admin)")
        self.secret = QLineEdit(); self.secret.setEchoMode(QLineEdit.EchoMode.Password)
        self.secret.setPlaceholderText("Mot de passe")
        self.port = QSpinBox(); self.port.setRange(1, 65535)
        self.scheme = QComboBox(); self.scheme.addItem("https", "https"); self.scheme.addItem("http", "http")
        self.auth = QComboBox(); self.auth.addItem("Mot de passe", "password"); self.auth.addItem("Clé privée", "key")
        from core.config_backup import PROFILES
        self.profile = QComboBox()
        self.profile.addItem("Détecter automatiquement", "auto")
        for k, v in PROFILES.items():
            if k != "custom":
                self.profile.addItem(v["label"], k)
        self.community = QLineEdit("public")
        self.version = QComboBox(); self.version.addItem("v2c", "2c"); self.version.addItem("v1", "1")
        self._rows = {}
        for key, label, w in (("user", "Identifiant :", self.user), ("secret", "Mot de passe :", self.secret), ("auth", "Authentification SSH :", self.auth),
                              ("profile", "Type de système :", self.profile), ("scheme", "Protocole :", self.scheme), ("port", "Port :", self.port),
                              ("community", "Communauté SNMP :", self.community), ("version", "Version SNMP :", self.version)):
            lbl = QLabel(label)
            form.addRow(lbl, w)
            self._rows[key] = (lbl, w)
        self.public = QCheckBox("Cet équipement est hors de mon réseau local (VPN, site distant)")
        form.addRow(self.public)
        self.result = QLabel("")
        self.result.setWordWrap(True)
        self.result.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)      # on peut copier le diagnostic
        form.addRow(self.result)
        row = QHBoxLayout()
        self.btn_test = icon_button("act_zap", "Tester")
        self.btn_save = icon_button("act_save", "Enregistrer")
        self.btn_cancel = QPushButton("Fermer")
        self.btn_test.clicked.connect(lambda: self._run(False))
        self.btn_save.clicked.connect(lambda: self._run(True))
        self.btn_cancel.clicked.connect(self.reject)
        for b in (self.btn_test, self.btn_save, self.btn_cancel):
            row.addWidget(b)
        form.addRow(row)
        self._done.connect(self._finished)
        self._sync()

    def _sync(self):
        m = self.method.currentData()
        show = {"auto": ("user", "secret", "community"), "ssh": ("user", "secret", "auth", "profile", "port"),
                "web": ("user", "secret", "scheme", "port"), "snmp": ("community", "version", "port"), "box": ("secret",)}[m]
        for k, (lbl, w) in self._rows.items():
            lbl.setVisible(k in show); w.setVisible(k in show)
        self.port.setValue({"auto": 22, "ssh": 22, "web": 443, "snmp": 161, "box": 80}[m])
        self.secret.setPlaceholderText("Mot de passe de la box" if m == "box" else "Mot de passe")
        self.adjustSize()                                    # la fenêtre suit les champs affichés (évite les alertes de géométrie Qt)

    def params(self) -> dict:
        return {"method": self.method.currentData(), "address": self.addr.text(), "name": self.name.text(), "kind": self.kind.currentData(),
                "allow_public": self.public.isChecked(), "port": self.port.value(), "username": self.user.text(), "secret": self.secret.text(),
                "auth_type": self.auth.currentData(), "profile": self.profile.currentData(), "scheme": self.scheme.currentData(),
                "community": self.community.text(), "version": self.version.currentData()}

    def _run(self, save: bool):
        import threading
        p = self.params()
        self.btn_test.setEnabled(False); self.btn_save.setEnabled(False)
        self.result.setStyleSheet(f"color: {COLOR['text_sec']};")
        self.result.setText("Connexion en cours…")

        def work():
            try:
                r = self.dl.connect(self.db, p, self.who, save=save)
                self._done.emit(True, r["message"] + (" — enregistré." if save else ""))
            except self.dl.LinkError as e:
                self._done.emit(False, str(e))
            except Exception as e:                       # jamais de fenêtre figée : l'erreur est affichée
                self._done.emit(False, f"Erreur inattendue : {type(e).__name__}")
        threading.Thread(target=work, name="device-connect", daemon=True).start()

    def _finished(self, ok: bool, msg: str):
        self.btn_test.setEnabled(True); self.btn_save.setEnabled(True)
        self.result.setStyleSheet(f"color: {COLOR['green'] if ok else COLOR['red']}; font-weight: 600;")
        self.result.setText(msg)
        if ok and "enregistré" in msg:
            self.saved = True
