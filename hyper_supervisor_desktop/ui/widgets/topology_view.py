"""
HSR — Carte réseau (topologie interactive)
Procus Tech

  - Un cluster par réseau supervisé : routeur/passerelle au centre, équipements autour
  - Nœuds colorés par statut (vert/rouge/orange/gris), déplaçables (les liens suivent)
  - « + Ajouter un réseau » : saisie d'une IP de routeur/box ou d'un réseau CIDR →
    découverte automatique des équipements, puis surveillance continue
  - Panneau de détail au clic (IP, MAC, fabricant, réseau, statut…)
"""
import math

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QFrame, QSplitter,
    QGraphicsView, QGraphicsScene, QGraphicsEllipseItem, QGraphicsRectItem,
    QGraphicsSimpleTextItem, QGraphicsLineItem, QDialog, QFormLayout, QLineEdit,
    QComboBox, QCheckBox, QDialogButtonBox, QMessageBox, QTableWidget,
    QTableWidgetItem, QHeaderView, QAbstractItemView
)
from database.crypto_db import INTEGRITY_ERRORS
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor, QPen, QBrush, QFont, QPainter

from PyQt6.QtWidgets import QStackedWidget, QScrollArea
from ui.icons import dot_pixmap, icon_button
from ui.styles import COLOR, STATUS_COLORS
from ui.widgets.device_cards import (CardsPage, EditDeviceDialog, FilterChips, FloatingBar, STATUS_TXT, TYPE_FR as CARD_TYPE_FR,
                                     conn_badge_text, dash)


TYPE_FR = {"router": "Routeur", "switch": "Switch", "firewall": "Pare-feu", "ap": "Borne Wi-Fi",
           "server": "Serveur", "workstation": "PC", "printer": "Imprimante", "mobile": "Mobile",
           "iot": "Objet connecté", "tv": "TV / média", "camera": "Caméra", "unknown": "Appareil"}
DEVICE_SHAPES = {"switch": "rect", "firewall": "rect", "server": "rect", "printer": "rect"}
NODE_SIZE = 50
HUB_PREFIX = "net:"          # identifiant des nœuds virtuels (réseau sans routeur connu)


def _qcolor(hex_color: str, alpha: int = 255) -> QColor:
    c = QColor(hex_color)
    c.setAlpha(alpha)
    return c


# ─────────────────────────────────────────────────────────────────
# Disposition (fonction pure, testable)
# ─────────────────────────────────────────────────────────────────

def compute_layout(hosts: list, networks: list) -> dict:
    """
    Retourne {"nodes": [{id, x, y, kind, host|label}], "links": [(a, b)], "clusters": [...]}.
    Un cluster par réseau ; hôtes sans réseau → cluster « Réseau local ».
    Centre = hôte routeur/passerelle du réseau, sinon nœud virtuel (le réseau).
    """
    nets = {n["id"]: n for n in networks}
    groups: dict = {}
    for h in hosts:
        groups.setdefault(h.get("network_id") if h.get("network_id") in nets else None, []).append(h)
    for nid in nets:                                   # réseaux vides : tout de même visibles
        groups.setdefault(nid, [])
    order = sorted(groups, key=lambda k: (k is not None, nets[k]["name"] if k in nets else ""))

    nodes, links, clusters = [], [], []
    cursor_x = 0.0
    for gi, nid in enumerate(order):
        members = groups[nid]
        net = nets.get(nid)
        label = (net["name"] if net["cidr"] in net["name"] else f"{net['name']} · {net['cidr']}") if net else "Autres équipements"
        gw_ip = net.get("gateway_ip") if net else None
        center = next((h for h in members if gw_ip and h.get("ip_address") == gw_ip), None) \
            or next((h for h in members if (h.get("device_type") or "") == "router"), None)
        others = [h for h in members if h is not center]
        # anneaux concentriques : capacité proportionnelle à la circonférence
        rings, i, r = [], 0, 1
        while i < len(others):
            radius = 130 + 100 * (r - 1)
            cap = max(6, int(2 * math.pi * radius / 95))
            rings.append((radius, others[i:i + cap]))
            i += cap
            r += 1
        max_r = rings[-1][0] if rings else 90
        cx, cy = cursor_x + max_r + 70, max_r + 90
        cursor_x = cx + max_r + 120

        if center is not None:
            cid = center["id"]
            nodes.append({"id": cid, "x": cx, "y": cy, "kind": "host", "host": center})
        else:
            cid = f"{HUB_PREFIX}{nid or 0}"
            nodes.append({"id": cid, "x": cx, "y": cy, "kind": "hub",
                          "label": net["cidr"] if net else "LAN"})
        for radius, ring in rings:
            for k, h in enumerate(ring):
                ang = 2 * math.pi * k / len(ring) - math.pi / 2 + (0.3 if radius > 130 else 0)
                nodes.append({"id": h["id"], "x": cx + radius * math.cos(ang),
                              "y": cy + radius * math.sin(ang), "kind": "host", "host": h})
                links.append((cid, h["id"]))
        clusters.append({"label": label, "x": cx, "y": cy - max_r - 60, "count": len(members),
                         "online": sum(1 for h in members if h.get("status") == "online"), "network_id": nid})
    return {"nodes": nodes, "links": links, "clusters": clusters}


# ─────────────────────────────────────────────────────────────────
# Canevas
# ─────────────────────────────────────────────────────────────────

LINK_STYLES = {"wifi": ("#e6c766", Qt.PenStyle.DashLine, 1.6), "ethernet": ("#7FB069", Qt.PenStyle.SolidLine, 2.4),
               "unknown": ("#6e6445", Qt.PenStyle.DotLine, 1.4)}


class _Link(QGraphicsLineItem):
    def __init__(self, a, b, conn: str = "unknown"):
        super().__init__()
        self.a, self.b = a, b
        color, style, width = LINK_STYLES.get(conn, LINK_STYLES["unknown"])
        self.setPen(QPen(_qcolor(color), width, style))
        self.setZValue(-1)
        self.refresh()

    def refresh(self):
        self.setLine(self.a.pos().x(), self.a.pos().y(), self.b.pos().x(), self.b.pos().y())


def _make_node_class(base):
    class _Node(base):
        def __init__(self, *args):
            super().__init__(*args)
            self.links = []
            self.setFlag(base.GraphicsItemFlag.ItemIsMovable)
            self.setFlag(base.GraphicsItemFlag.ItemSendsGeometryChanges)

        def itemChange(self, change, value):
            if change == base.GraphicsItemChange.ItemPositionHasChanged:
                for l in self.links:
                    l.refresh()
            return super().itemChange(change, value)
    return _Node


_RectNode = _make_node_class(QGraphicsRectItem)
_EllipseNode = _make_node_class(QGraphicsEllipseItem)


class TopologyCanvas(QGraphicsView):
    node_clicked = None  # callback (host: dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._scene = QGraphicsScene(self)
        self.setScene(self._scene)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setStyleSheet(f"background: #050505; border: 1px solid {COLOR['border']}; border-radius: 6px;")
        self._nodes: dict = {}   # host_id → {item, host, x, y}

    def _text(self, txt, color, size, bold=False):
        t = QGraphicsSimpleTextItem(txt)
        t.setBrush(QBrush(QColor(color)))
        t.setFont(QFont("Segoe UI", size, QFont.Weight.Bold if bold else QFont.Weight.Normal))
        return t

    @staticmethod
    def _tooltip(host: dict) -> str:
        from core.local_network import REACH_LABELS
        t = [f"{host.get('name', '')}", f"IP : {host.get('ip_address', '—')}",
             f"Type : {TYPE_FR.get((host.get('device_type') or 'unknown').lower(), 'Appareil')}",
             f"Statut : {host.get('status') or '—'}"]
        if host.get("vendor"):
            t.append(f"Fabricant : {host['vendor']}")
        if host.get("mac_address"):
            t.append(f"MAC : {host['mac_address']}")
        if host.get("reach_method"):
            t.append(f"Joint via : {REACH_LABELS.get(host['reach_method'], host['reach_method'])}")
        if host.get("approved") == 0:
            t.append("Équipement inconnu : absent du référentiel")
        return "\n".join(t)

    def draw_topology(self, hosts: list, networks: list = None, conn: dict = None):
        """conn : {host_id: 'wifi'|'ethernet'|'unknown'} → style des liens (pointillé Wi-Fi, trait plein câble)."""
        self._scene.clear()
        self._nodes.clear()
        self._conn = conn or {}
        networks = networks or []
        if not hosts and not networks:
            t = self._text("Aucun équipement à afficher — cliquez sur « + Ajouter un réseau »",
                           COLOR["text_sec"], 10)
            self._scene.addItem(t)
            return

        layout = compute_layout(hosts, networks)
        items = {}
        for n in layout["nodes"]:
            host = n.get("host") or {}
            if n["kind"] == "hub":
                color, icon, shape = "#9c8a55", "", "ellipse"
                name, ip = n["label"], ""
            else:
                color = STATUS_COLORS.get(host.get("status", "unknown"), "#c4bfae")
                dtype = (host.get("device_type") or "unknown").lower()
                icon = ""
                shape = "rect" if DEVICE_SHAPES.get(dtype) == "rect" else "ellipse"
                name, ip = host.get("name", ""), host.get("ip_address", "")
            half = NODE_SIZE // 2
            node = (_RectNode if shape == "rect" else _EllipseNode)(-half, -half, NODE_SIZE, NODE_SIZE)
            node.setPen(QPen(QColor(color), 2))
            node.setBrush(QBrush(_qcolor(color, 40)))
            node.setPos(n["x"], n["y"])
            if n["kind"] == "host":
                node.setData(0, host.get("id"))
                node.setToolTip(self._tooltip(host))
                if host.get("approved") == 0:               # équipement hors référentiel
                    node.setPen(QPen(QColor("#E74C3C"), 3, Qt.PenStyle.DashLine))
            self._scene.addItem(node)

            from PyQt6.QtWidgets import QGraphicsPixmapItem
            from ui.icons import device_pixmap
            ic = QGraphicsPixmapItem(device_pixmap("hub" if n["kind"] == "hub" else dtype, 28, color))
            ic.setParentItem(node)
            ic.setPos(-14, -14)
            ic.setAcceptedMouseButtons(Qt.MouseButton.NoButton)
            lb = self._text((name[:22] + ("  (inconnu)" if host.get("approved") == 0 else "")), COLOR["text_pri"], 7)
            lb.setParentItem(node)
            lb.setPos(-lb.boundingRect().width() / 2, half + 3)
            if ip:
                ipl = self._text(ip, COLOR["text_sec"], 6)
                ipl.setParentItem(node)
                ipl.setPos(-ipl.boundingRect().width() / 2, half + 17)
            items[n["id"]] = node
            if n["kind"] == "host":
                self._nodes[host.get("id")] = {"item": node, "host": host, "x": n["x"], "y": n["y"]}

        for a, b in layout["links"]:
            link = _Link(items[a], items[b], self._conn.get(b, "unknown"))
            link.host_id = b
            self._scene.addItem(link)
            items[a].links.append(link)
            items[b].links.append(link)

        for c in layout["clusters"]:
            t = self._text(f"{c['label']}  ·  {c['online']}/{c['count']} en ligne", COLOR["accent"], 9, True)
            self._scene.addItem(t)
            t.setPos(c["x"] - t.boundingRect().width() / 2, c["y"])
        self._scene.setSceneRect(self._scene.itemsBoundingRect().adjusted(-40, -40, 40, 40))

    def apply_filter(self, ids):
        """ids : ensemble d'identifiants à mettre en avant (None = tous). Les autres sont estompés."""
        for hid, n in self._nodes.items():
            on = ids is None or hid in ids or (n["host"].get("device_type") or "") == "router"      # le centre reste visible
            n["item"].setOpacity(1.0 if on else 0.15)
            for l in n["item"].links:
                l.setOpacity(1.0 if on else 0.08)

    def mousePressEvent(self, event):
        super().mousePressEvent(event)
        item = self.itemAt(event.pos())
        while item is not None and item.data(0) is None:
            item = item.parentItem()
        if item is not None:
            host_id = item.data(0)
            if host_id in self._nodes and self.node_clicked:
                self.node_clicked(self._nodes[host_id]["host"])

    def wheelEvent(self, event):
        p = self.parent()
        while p is not None and not hasattr(p, "_user_zoomed"):
            p = p.parent()
        if p is not None:
            p._user_zoomed = True
        factor = 1.15 if event.angleDelta().y() > 0 else 0.87
        self.scale(factor, factor)


# ─────────────────────────────────────────────────────────────────
# Dialogues
# ─────────────────────────────────────────────────────────────────

class AddNetworkDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Ajouter un réseau à superviser")
        self.setMinimumWidth(480)
        self.setModal(True)
        self._parsed = None
        lay = QVBoxLayout(self)
        intro = QLabel("Saisissez l'adresse IP de votre routeur / box / point d'accès Wi-Fi, ou un réseau "
                       "complet. Procus Secure détecte tous les équipements connectés, dessine la "
                       "topologie et les surveille en continu.")
        intro.setWordWrap(True)
        intro.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 8.5pt;")
        lay.addWidget(intro)
        form = QFormLayout()
        self._f_target = QLineEdit()
        self._f_target.setPlaceholderText("192.168.1.1   ou   192.168.1.0/24")
        self._f_name = QLineEdit()
        self._f_name.setPlaceholderText("ex : Wi-Fi bureau (facultatif)")
        self._f_kind = QComboBox()
        for label, key in (("Réseau local (câble)", "lan"), ("Wi-Fi", "wifi"), ("Derrière un routeur", "router")):
            self._f_kind.addItem(label, key)
        form.addRow("Adresse IP / réseau *", self._f_target)
        form.addRow("Nom", self._f_name)
        form.addRow("Type", self._f_kind)
        lay.addLayout(form)
        self._chk_auto = QCheckBox("Surveiller en continu (alerte si un nouvel équipement apparaît)")
        self._chk_auto.setChecked(True)
        self._chk_auth = QCheckBox("Je confirme être autorisé à superviser ce réseau")
        lay.addWidget(self._chk_auto)
        lay.addWidget(self._chk_auth)
        note = QLabel("Réseaux privés uniquement (10.x, 172.16–31.x, 192.168.x), jusqu'à /22. "
                      "Cette machine doit être connectée à ce réseau.")
        note.setWordWrap(True)
        note.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 7.5pt; font-style: italic;")
        lay.addWidget(note)
        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btns.button(QDialogButtonBox.StandardButton.Ok).setText("Découvrir et surveiller")
        btns.accepted.connect(self._validate)
        btns.rejected.connect(self.reject)
        lay.addWidget(btns)

    def _validate(self):
        from core.local_network import parse_network_input
        try:
            self._parsed = parse_network_input(self._f_target.text())
        except ValueError as e:
            QMessageBox.warning(self, "Réseau invalide", str(e))
            return
        if not self._chk_auth.isChecked():
            QMessageBox.warning(self, "Autorisation requise",
                                "Confirmez que vous êtes autorisé à superviser ce réseau.")
            return
        self.accept()

    def get_data(self) -> dict:
        p = self._parsed
        name = self._f_name.text().strip() or f"Réseau {p['cidr']}"
        return {"name": name, "cidr": p["cidr"], "gateway_ip": p["gateway_ip"],
                "kind": self._f_kind.currentData(), "auto_monitor": int(self._chk_auto.isChecked())}


class SummaryBar(QWidget):
    """Bandeau de synthèse façon Zabbix : grosses tuiles colorées (total, en ligne, hors ligne, à vérifier, réseaux)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(8)
        self._tiles = {}
        for key, label, color, tip in (
                ("total", "Équipements", COLOR["cyan"], "Tous les équipements connus du réseau choisi"),
                ("online", "En ligne", COLOR["green"], "Équipements présents sur le réseau en ce moment"),
                ("offline", "Hors ligne", COLOR["red"], "Équipements qui ne sont plus (ou pas) sur le réseau"),
                ("check", "À vérifier", COLOR["yellow"], "Nouveaux équipements non approuvés ou état encore inconnu"),
                ("nets", "Réseaux", "#c4bfae", "Réseaux supervisés (les suspendus sont comptés à part)")):
            tile = QFrame()
            tile.setToolTip(tip)
            tile.setStyleSheet(f"QFrame {{ background: {COLOR['bg_card']}; border: 1px solid {COLOR['border']};"
                               f" border-left: 5px solid {color}; border-radius: 8px; }}")
            lay = QVBoxLayout(tile)
            lay.setContentsMargins(12, 6, 12, 6)
            lay.setSpacing(0)
            num = QLabel("0")
            num.setStyleSheet(f"color: {color}; font-size: 20pt; font-weight: 800; border: none; background: transparent;")
            txt = QLabel(label)
            txt.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 8pt; font-weight: 600; border: none; background: transparent;")
            lay.addWidget(num)
            lay.addWidget(txt)
            row.addWidget(tile, 1)
            self._tiles[key] = (num, txt, label)

    def set_counts(self, total: int, online: int, offline: int, check: int, nets: int, paused: int = 0):
        vals = {"total": total, "online": online, "offline": offline, "check": check, "nets": nets}
        for k, v in vals.items():
            self._tiles[k][0].setText(str(v))
        self._tiles["nets"][1].setText("Réseaux" + (f" ({paused} suspendu{'s' if paused > 1 else ''})" if paused else ""))


class NetworksDialog(QDialog):
    """Liste des réseaux supervisés : redécouvrir, suspendre, régler la fréquence, supprimer (tout ce qui le concerne)."""
    rescan_requested = pyqtSignal(int)
    network_removed = pyqtSignal(int)

    def __init__(self, db, security=None, parent=None):
        super().__init__(parent)
        self.db, self.security = db, security
        self.setWindowTitle("Réseaux supervisés")
        self.setMinimumSize(760, 340)
        lay = QVBoxLayout(self)
        cols = ["Nom", "Réseau", "Type", "Équipements", "Dernière découverte", "Fréquence", "Supervision"]
        self._t = QTableWidget(0, len(cols))
        self._t.setHorizontalHeaderLabels(cols)
        hdr = self._t.horizontalHeader()
        for c in range(1, len(cols)):
            hdr.setSectionResizeMode(c, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.resize(1050, 460)
        self._t.verticalHeader().setVisible(False)
        self._t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._t.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        lay.addWidget(self._t)
        row = QHBoxLayout()
        b_scan = icon_button("act_refresh", "Redécouvrir")
        b_pause = icon_button("act_activity", "Suspendre / reprendre")
        b_pause.setToolTip("Arrête (ou relance) la supervision de CE réseau uniquement ; les autres ne sont pas touchés.")
        b_freq = icon_button("act_clock", "Fréquence")
        b_freq.setToolTip("Intervalle entre deux redécouvertes de ce réseau")
        b_del = icon_button("act_trash", "Supprimer le réseau", color=COLOR["red"])
        b_close = QPushButton("Fermer")
        b_scan.clicked.connect(self._rescan)
        b_pause.clicked.connect(self._toggle_pause)
        b_freq.clicked.connect(self._set_freq)
        b_del.clicked.connect(self._delete)
        b_close.clicked.connect(self.accept)
        for b in (b_scan, b_pause, b_freq, b_del):
            row.addWidget(b)
        row.addStretch()
        row.addWidget(b_close)
        lay.addLayout(row)
        self.refresh()

    def refresh(self):
        nets = self.db.get_networks()
        self._t.setRowCount(0)
        kinds = {"lan": "Réseau local", "wifi": "Wi-Fi", "router": "Derrière un routeur"}
        for n in nets:
            r = self._t.rowCount()
            self._t.insertRow(r)
            paused = bool(n.get("paused"))
            every = int(n.get("discover_every_s") or 300)
            vals = [n["name"], n["cidr"], kinds.get(n.get("kind"), n.get("kind", "")),
                    f"{n.get('online_count', 0)} en ligne · {n.get('offline_count', 0)} hors ligne · {n.get('host_count', 0)} au total",
                    str(n.get("last_discovery") or "jamais")[:16],
                    f"toutes les {every // 60} min" if every >= 60 else f"{every} s",
                    "Suspendue" if paused else ("Active" if n.get("auto_monitor") else "Manuelle")]
            for c, v in enumerate(vals):
                it = QTableWidgetItem(v)
                if c == 0:
                    it.setData(Qt.ItemDataRole.UserRole, n["id"])
                if c == 6:
                    it.setForeground(QColor(COLOR["yellow"] if paused else COLOR["green"]))
                if c == 3 and n.get("offline_count"):
                    it.setForeground(QColor(COLOR["red"]))
                self._t.setItem(r, c, it)

    def _selected(self):
        r = self._t.currentRow()
        if r < 0:
            QMessageBox.information(self, "Réseaux", "Sélectionnez un réseau dans la liste.")
            return None
        return self._t.item(r, 0).data(Qt.ItemDataRole.UserRole)

    def _perm(self, perm: str) -> bool:
        if self.security:
            try:
                self.security.require_permission(perm)
            except PermissionError as e:
                QMessageBox.warning(self, "Accès refusé", str(e))
                return False
        return True

    def _rescan(self):
        nid = self._selected()
        if nid is not None and self._perm("can_scan"):
            self.rescan_requested.emit(nid)

    def _toggle_pause(self):
        nid = self._selected()
        if nid is None or not self._perm("can_scan"):
            return
        net = next((n for n in self.db.get_networks() if n["id"] == nid), None) or {}
        self.db.set_network_monitoring(nid, enabled=bool(net.get("paused")))
        self.refresh()

    def _set_freq(self):
        nid = self._selected()
        if nid is None or not self._perm("can_scan"):
            return
        from PyQt6.QtWidgets import QInputDialog
        net = next((n for n in self.db.get_networks() if n["id"] == nid), None) or {}
        minutes, ok = QInputDialog.getInt(self, "Fréquence de redécouverte", "Redécouvrir ce réseau toutes les (minutes) :",
                                          max(1, int(net.get("discover_every_s") or 300) // 60), 1, 1440)
        if ok:
            self.db.set_network_monitoring(nid, every_s=minutes * 60)
            self.refresh()

    def _delete(self):
        nid = self._selected()
        if nid is None or not self._perm("can_delete_host"):
            return
        net = next((n for n in self.db.get_networks() if n["id"] == nid), None) or {}
        fp = self.db.network_footprint(nid)
        active = "" if net.get("paused") else "\n\nCe réseau est en cours de supervision : la supervision s'arrêtera immédiatement."
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle("Supprimer le réseau")
        box.setText(f"Êtes-vous sûr de vouloir supprimer le réseau « {net.get('name', '')} » ({net.get('cidr', '')}) ?")
        box.setInformativeText(
            f"Seront effacés définitivement : {fp['hosts']} équipement(s), leurs mesures et historiques, "
            f"{fp['events']} événement(s), {fp['incidents']} incident(s), leur place sur la carte, leurs identifiants de "
            f"connexion et sauvegardes.{active}\n\nLe journal d'audit garde une trace de cette suppression. "
            "Cette action est irréversible.")
        b_yes = box.addButton("Supprimer définitivement", QMessageBox.ButtonRole.DestructiveRole)
        b_no = box.addButton("Annuler", QMessageBox.ButtonRole.RejectRole)
        box.setDefaultButton(b_no)
        box.exec()
        if box.clickedButton() is not b_yes:
            return
        try:
            res = self.db.purge_network(nid)
        except Exception as e:
            QMessageBox.critical(self, "Suppression impossible", f"Rien n'a été supprimé : {e}")
            return
        try:
            who = (self.security.get_current_user() or {}).get("login", "") if self.security else ""
            self.db.write_audit(who or "system", "network_delete", net.get("cidr", ""),
                                f"« {net.get('name', '')} » supprimé : {res['hosts']} équipements, {res['events']} événements, {res['incidents']} incidents")
        except Exception:
            pass
        self.network_removed.emit(nid)
        self.refresh()


# ─────────────────────────────────────────────────────────────────
# Vue
# ─────────────────────────────────────────────────────────────────

class TopologyView(QWidget):
    network_scan_requested = pyqtSignal(int)      # network_id → NetworkSetupWorker.discover_network

    def __init__(self, db=None, security=None, parent=None):
        super().__init__(parent)
        self.db = db
        self.security = security
        self._user_zoomed = False
        self._infos: dict = {}
        self._flt = "all"
        self._sig = None
        self._ctx_local, self._ctx_v6, self._ctx_at = None, {}, 0.0
        self._seen_status: dict = {}
        self._dirty_pages: set = {1, 2}                    # pages Liste (1) et Détails (2) à construire
        self._net = None                                   # None = tous les réseaux ; sinon id du réseau affiché
        self._scope = (db.get_setting("map_scope", "all") if db else "all")
        self._scope = self._scope if self._scope in ("all", "online") else "all"
        self._build_ui()
        self.refresh()
        # Statuts en direct (couleurs des nœuds) sans réinitialiser la disposition ni le zoom
        self.action_done.connect(self._show_action_result)
        self._live_timer = QTimer(self)
        self._live_timer.timeout.connect(self.refresh_statuses)
        self._live_timer.start(5_000)

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(12)

        hdr = QHBoxLayout()
        title = QLabel("Carte réseau")
        title.setStyleSheet(f"font-size: 14pt; font-weight: 700; color: {COLOR['text_pri']};")
        hdr.addWidget(title)
        hdr.addStretch()

        btn_conn = icon_button("act_link", "Connecter un équipement")
        btn_conn.setToolTip("Se connecter à un routeur, un pare-feu ou une box avec son adresse IP et son mot de passe")
        btn_conn.clicked.connect(lambda: self._connect_dialog(None))
        hdr.addWidget(btn_conn)
        btn_add = icon_button("act_globe", "Ajouter un réseau")
        btn_add.setObjectName("btn_primary")
        btn_add.clicked.connect(self._add_network)
        hdr.addWidget(btn_add)
        btn_nets = QPushButton("Réseaux…")
        btn_nets.clicked.connect(self._manage_networks)
        hdr.addWidget(btn_nets)
        btn_refresh = icon_button("act_refresh", "Actualiser")
        btn_refresh.clicked.connect(self.refresh)
        hdr.addWidget(btn_refresh)
        btn_fit = icon_button("act_search", "Ajuster")
        btn_fit.clicked.connect(self._fit_view)
        hdr.addWidget(btn_fit)
        layout.addLayout(hdr)

        legend_row = QHBoxLayout()
        legend_row.setSpacing(16)
        for label, color in [("En ligne", COLOR["green"]), ("Hors ligne", COLOR["red"]),
                             ("Injoignable", COLOR["accent"]), ("Inconnu", "#c4bfae")]:
            dot = QLabel()
            dot.setPixmap(dot_pixmap(color))
            lbl = QLabel(label)
            lbl.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 8pt;")
            legend_row.addWidget(dot)
            legend_row.addWidget(lbl)
        from ui.icons import line_sample_label
        for style, txt, tip in (("dash", "Wi-Fi", "Liaison sans fil"), ("solid", "Câble", "Liaison Ethernet"), ("dot", "Inconnu", "Mode de connexion inconnu")):
            sample = line_sample_label(style, "#c4bfae")
            sample.setToolTip(tip)
            legend_row.addWidget(sample)
            lb = QLabel(txt)
            lb.setToolTip(tip)
            lb.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 8pt;")
            legend_row.addWidget(lb)
        legend_row.addStretch()
        self._lbl_status = QLabel("")
        self._lbl_status.setStyleSheet(f"color: {COLOR['cyan']}; font-size: 8pt;")
        legend_row.addWidget(self._lbl_status)
        layout.addLayout(legend_row)

        self._summary = SummaryBar()
        layout.addWidget(self._summary)
        chips_row = QHBoxLayout()
        self._net_combo = QComboBox()
        self._net_combo.setToolTip("Afficher un seul réseau ou tous les réseaux supervisés")
        self._net_combo.setMinimumWidth(190)
        self._net_combo.currentIndexChanged.connect(self._on_net)
        chips_row.addWidget(self._net_combo)
        chips_row.addSpacing(8)
        self._scope_btns = {}
        for key, label, ico in (("all", "Topologie complète", "dev_hub"), ("online", "Équipements connectés", "act_activity")):
            b = icon_button(ico, label, color=COLOR["cyan"])
            b.setCheckable(True)
            b.setToolTip("Tous les équipements connus, même éteints" if key == "all" else "Seulement les équipements actuellement connectés au réseau")
            b.clicked.connect(lambda _=False, k=key: self._on_scope(k))
            self._scope_btns[key] = b
            chips_row.addWidget(b)
        chips_row.addSpacing(14)
        self._chips = FilterChips()
        self._chips.changed.connect(self._on_filter)
        chips_row.addWidget(self._chips)
        self._lbl_count = QLabel("")
        self._lbl_count.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 8pt;")
        chips_row.addWidget(self._lbl_count)
        layout.addLayout(chips_row)

        self._stack = QStackedWidget()
        splitter = QSplitter(Qt.Orientation.Horizontal)
        self._canvas = TopologyCanvas()
        self._canvas.node_clicked = self._show_detail
        splitter.addWidget(self._canvas)
        self._detail = self._build_detail_panel()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(self._detail)
        scroll.setMinimumWidth(300)
        splitter.addWidget(scroll)
        splitter.setSizes([860, 330])
        self._stack.addWidget(splitter)                       # 0 : Carte
        self._list_page = CardsPage("list")
        self._details_page = CardsPage("details")
        for page in (self._list_page, self._details_page):
            page.card_action.connect(self._on_action)
            page.card_clicked.connect(self._on_card_clicked)
            self._stack.addWidget(page)                       # 1 : Liste, 2 : Détails
        layout.addWidget(self._stack, 1)

        self._bar = FloatingBar(self)                         # barre de tâches flottante en bas
        self._bar.refresh_clicked.connect(self.refresh_all)
        self._bar.mode_changed.connect(self._on_mode)
        self._bar.raise_()

    def _build_detail_panel(self) -> QWidget:
        panel = QFrame()
        panel.setMinimumWidth(290)
        panel.setStyleSheet(f"""
            QFrame {{ background: {COLOR['bg_card']}; border: 1px solid {COLOR['border']}; border-radius: 8px; }}
            QLabel {{ border: none; background: transparent; }}
        """)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)
        self._detail_title = QLabel("Cliquez sur un appareil pour voir ses informations")
        self._detail_title.setStyleSheet(f"font-size: 11pt; font-weight: 700; color: {COLOR['text_pri']};")
        self._detail_title.setWordWrap(True)
        layout.addWidget(self._detail_title)
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        layout.addWidget(sep)
        self._detail_fields: dict = {}
        for key in ["IP", "Statut", "Type", "Réseau", "MAC", "Fabricant", "Groupe", "Localisation",
                    "Communauté SNMP", "Joint via", "Référentiel", "Dernier contrôle"]:
            row = QHBoxLayout()
            k_lbl = QLabel(f"{key} :")
            k_lbl.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 8pt; min-width: 110px;")
            v_lbl = QLabel("")
            v_lbl.setStyleSheet(f"color: {COLOR['text_pri']}; font-size: 8pt;")
            v_lbl.setWordWrap(True)
            v_lbl.setMinimumHeight(34 if key in ("Réseau", "Localisation") else 18)
            k_lbl.setAlignment(Qt.AlignmentFlag.AlignTop)
            v_lbl.setAlignment(Qt.AlignmentFlag.AlignTop)
            row.addWidget(k_lbl)
            row.addWidget(v_lbl, 1)
            layout.addLayout(row)
            self._detail_fields[key] = v_lbl
        self._btn_approve = QPushButton("Approuver (ajouter au référentiel)")
        self._btn_approve.setVisible(False)
        self._btn_approve.clicked.connect(self._approve_current)
        layout.addWidget(self._btn_approve)

        # ── v16.1 : connexion, adresses, historique, débit, actions ──
        sep2 = QFrame()
        sep2.setFrameShape(QFrame.Shape.HLine)
        layout.addWidget(sep2)
        self._extra: dict = {}
        for key in ["Connexion", "Qualité", "Temps de réponse", "IPv6", "Première connexion", "Dernière vue", "Services ouverts"]:
            row = QHBoxLayout()
            k_lbl = QLabel(f"{key} :")
            k_lbl.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 8pt; min-width: 110px;")
            k_lbl.setAlignment(Qt.AlignmentFlag.AlignTop)
            v_lbl = QLabel("")
            v_lbl.setStyleSheet(f"color: {COLOR['text_pri']}; font-size: 8pt;")
            v_lbl.setWordWrap(True)
            v_lbl.setAlignment(Qt.AlignmentFlag.AlignTop)
            v_lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            row.addWidget(k_lbl)
            row.addWidget(v_lbl, 1)
            layout.addLayout(row)
            self._extra[key] = v_lbl
        hist_t = QLabel("Historique de connexion")
        hist_t.setStyleSheet(f"font-size: 9pt; font-weight: 700; color: {COLOR['cyan']};")
        layout.addWidget(hist_t)
        self._hist = QLabel("")
        self._hist.setWordWrap(True)
        self._hist.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 8pt;")
        layout.addWidget(self._hist)
        self._act_btns: dict = {}
        for key, label, ico in (("ping", "Faire un ping", "act_activity"), ("scan", "Faire un scan réseau", "act_search"),
                                ("access", "Autoriser / bloquer cet appareil", "act_shield"), ("edit", "Modifier les informations", "act_edit"),
                                ("connect", "Se connecter à cet équipement", "act_link")):
            b = icon_button(ico, label)
            b.setEnabled(False)
            b.clicked.connect(lambda _=False, k=key: self._on_action(k, getattr(self, "_current_host", {}).get("id")))
            layout.addWidget(b)
            self._act_btns[key] = b
        self._rate_lbl = QLabel("")
        self._rate_lbl.setStyleSheet(f"background: {COLOR['bg_row']}; border-radius: 6px; padding: 6px; color: {COLOR['text_pri']}; font-weight: 600;")
        self._rate_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._rate_lbl)
        layout.addStretch()
        return panel

    def _approve_current(self):
        h = getattr(self, "_current_host", None)
        if not (self.db and h) or not self._perm("can_manage_config"):
            return
        from core.automation import AutomationEngine
        AutomationEngine(self.db, self.security).approve_device(h["id"])
        self.refresh()
        fresh = self.db.get_host_by_id(h["id"])
        if fresh:
            self._show_detail(fresh)

    # ── données ──
    def _net_hosts(self, hosts: list) -> list:
        """Équipements du réseau choisi (tous si « Tous les réseaux »)."""
        return [h for h in hosts if h.get("network_id") == self._net] if self._net is not None else hosts

    def _scoped(self, hosts: list) -> list:
        """Réseau choisi, puis topologie « connectés » : seulement les équipements actuellement en ligne."""
        hosts = self._net_hosts(hosts)
        return [h for h in hosts if h.get("status") == "online"] if self._scope == "online" else hosts

    def _on_net(self, _idx: int = 0):
        nid = self._net_combo.currentData()
        if nid != self._net:
            self._net = nid
            self._seen_status = {}
            self.refresh()

    def _sync_networks(self, nets: list):
        """Remplit le sélecteur de réseau ; un réseau supprimé ramène sur « Tous »."""
        ids = {n["id"] for n in nets}
        if self._net is not None and self._net not in ids:
            self._net = None
        self._net_combo.blockSignals(True)
        self._net_combo.clear()
        self._net_combo.addItem("Tous les réseaux", None)
        for n in nets:
            self._net_combo.addItem(n["name"] + (" (suspendu)" if n.get("paused") else ""), n["id"])
        self._net_combo.setCurrentIndex(max(0, self._net_combo.findData(self._net)))
        self._net_combo.blockSignals(False)

    def _update_summary(self, all_hosts: list, nets: list):
        hs = self._net_hosts(all_hosts)
        on = sum(1 for h in hs if h.get("status") == "online")
        off = sum(1 for h in hs if h.get("status") == "offline")
        chk = sum(1 for h in hs if h.get("status") not in ("online", "offline") or h.get("approved") == 0)
        self._summary.set_counts(len(hs), on, off, chk, len(nets), sum(1 for n in nets if n.get("paused")))

    def _on_scope(self, key: str):
        self._scope = key
        if self.db:
            self.db.set_setting("map_scope", key)
        self._sync_scope_buttons()
        self._seen_status = {}
        self.refresh()

    def _sync_scope_buttons(self):
        for k, b in self._scope_btns.items():
            on = k == self._scope
            b.setChecked(on)
            b.setStyleSheet(f"QPushButton {{ border: 1px solid {COLOR['cyan']}; border-radius: 8px; padding: 6px 14px; font-weight: 600;"
                            f" color: {'#1a1400' if on else COLOR['cyan']}; background: {COLOR['cyan'] if on else 'transparent'}; }}")

    def refresh(self):
        if not self.db:
            return
        all_hosts, nets = self.db.get_all_hosts(), self.db.get_networks()
        self._sync_networks(nets)
        hosts = self._scoped(all_hosts)
        self._update_summary(all_hosts, nets)
        self._sync_scope_buttons()
        self._reload_infos(hosts)
        self._canvas.draw_topology(hosts, [n for n in nets if self._net in (None, n["id"])], {i: v["conn"]["type"] for i, v in self._infos.items()})
        self._apply_filter_everywhere(force=True)
        self._fit_view()

    def refresh_all(self):
        """Bouton « Rafraîchir » : relit tout, y compris IPv6 et type de connexion (en arrière-plan)."""
        self._start_context_refresh(force=True)
        self.refresh()

    # ── fiches d'appareils ──
    def _reload_infos(self, hosts=None):
        from core import device_info as di
        from core.bandwidth import BandwidthManager
        hosts = hosts if hosts is not None else self._scoped(self.db.get_all_hosts())
        try:
            rates = {d["ip"]: d for d in BandwidthManager(self.db).current()}
        except Exception:
            rates = {}
        self._infos = {h["id"]: di.build_info(self.db, h, self._ctx_local, self._ctx_v6, rates) for h in hosts}

    def _start_context_refresh(self, force: bool = False):
        """IPv6 des voisins et interface locale : commandes système, donc hors du fil de l'interface."""
        import threading, time as _t
        if not force and _t.monotonic() - self._ctx_at < 60:
            return
        self._ctx_at = _t.monotonic()

        def work():
            from core import device_info as di
            try:
                self._ctx_local, self._ctx_v6 = di.local_connection(), di.read_ipv6_neighbors()
            except Exception:
                pass
        threading.Thread(target=work, name="devinfo-ctx", daemon=True).start()

    def _visible_infos(self) -> list:
        from core import device_info as di
        return [i for i in self._infos.values() if di.matches_filter(i, self._flt)]

    def _apply_filter_everywhere(self, force: bool = False):
        vis = self._visible_infos()
        ids = None if self._flt == "all" else {i["id"] for i in vis}
        self._canvas.apply_filter(ids)
        self._lbl_count.setText(f"{len(vis)} appareil(s) affiché(s) sur {len(self._infos)}")
        sig = tuple((i["id"], i["name"], i["status"], i["conn"]["type"], i["conn"]["detail"], i["rx_fmt"], i["tx_fmt"], i["quality"],
                     i["ipv6"], i["model"], i["blocked"], i["approved"]) for i in vis)
        if force or sig != self._sig:
            self._sig = sig
            self._dirty_pages = {1, 2}                       # les pages Liste / Détails se reconstruisent à l'ouverture seulement
        self._fill_visible_page(vis)

    def _fill_visible_page(self, vis=None):
        """Construit la page Liste ou Détails seulement si elle est affichée ET périmée : la Carte ne paie plus 2 × N cartes."""
        idx = self._stack.currentIndex()
        if idx not in self._dirty_pages:
            return
        page = self._list_page if idx == 1 else self._details_page
        vis = self._visible_infos() if vis is None else vis
        bar = page.verticalScrollBar().value()
        page.fill(vis)
        page.verticalScrollBar().setValue(bar)
        self._dirty_pages.discard(idx)

    def _on_filter(self, key: str):
        self._flt = key
        self._apply_filter_everywhere(force=True)

    def _on_mode(self, mode: str):
        self._stack.setCurrentIndex({"map": 0, "list": 1, "details": 2}.get(mode, 0))
        self._fill_visible_page()
        self._bar.raise_()

    def _on_card_clicked(self, host_id: int):
        h = self.db.get_host_by_id(host_id) if self.db else None
        if h:
            self._show_detail(h)

    def _place_bar(self):
        b = self._bar
        b.adjustSize()
        b.move(max(0, (self.width() - b.width()) // 2), max(0, self.height() - b.height() - 18))
        b.raise_()

    def refresh_statuses(self):
        """Recolore les nœuds selon le statut courant ; redessine si des équipements ont changé."""
        if not self.db or not self.isVisible():
            return
        all_hosts = self.db.get_all_hosts()
        hosts = self._scoped(all_hosts)
        self._update_summary(all_hosts, self.db.get_networks())
        self._start_context_refresh()
        if {h["id"] for h in hosts} != set(self._canvas._nodes):
            self.refresh()
            return
        self._reload_infos(hosts)
        self._apply_filter_everywhere()
        lost = [h for h in hosts if self._seen_status.get(h["id"]) == "online" and h.get("status") == "offline"]
        self._seen_status = {h["id"]: h.get("status") for h in hosts}
        if lost:
            names = ", ".join(h.get("name") or h.get("ip_address", "") for h in lost[:3]) + (" …" if len(lost) > 3 else "")
            self._lbl_status.setText(f"Appareil déconnecté : {names} — marqué en rouge.")
            self._lbl_status.setStyleSheet(f"color: {COLOR['red']}; font-weight: 700;")
        for h in hosts:
            node = self._canvas._nodes[h["id"]]
            node["host"] = h
            color = STATUS_COLORS.get(h.get("status", "unknown"), "#c4bfae")
            if h.get("approved") == 0:
                node["item"].setPen(QPen(QColor("#E74C3C"), 3, Qt.PenStyle.DashLine))
            else:
                node["item"].setPen(QPen(QColor(color), 2))
            node["item"].setBrush(QBrush(_qcolor(color, 40)))
            from ui.icons import device_pixmap
            for ch in node["item"].childItems()[:1]:
                ch.setPixmap(device_pixmap((h.get("device_type") or "unknown").lower(), 28, color))

    def on_network_discovered(self, network_id: int, added: int, total: int):
        self.refresh()
        if total == 0:
            self._lbl_status.setText("Aucun équipement détecté — cette machine est-elle connectée à ce réseau ?")
        else:
            self._lbl_status.setText(f"Découverte terminée : {total} équipement(s), {added} nouveau(x)")

    # ── actions ──
    def _perm(self, perm: str) -> bool:
        if self.security:
            try:
                self.security.require_permission(perm)
            except PermissionError as e:
                QMessageBox.warning(self, "Accès refusé", str(e))
                return False
        return True

    def _add_network(self):
        if not self.db or not self._perm("can_add_host"):
            return
        dlg = AddNetworkDialog(self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        d = dlg.get_data()
        import sqlite3
        try:
            who = (self.security.get_current_user() or {}).get("login", "") if self.security else ""
            nid = self.db.add_network(d["name"], d["cidr"], d["gateway_ip"], d["kind"], d["auto_monitor"],
                                      authorized_by=who or "administrateur")
        except INTEGRITY_ERRORS:
            QMessageBox.warning(self, "Doublon", "Ce réseau (ou ce nom) est déjà supervisé.")
            return
        except ValueError as e:
            QMessageBox.warning(self, "Réseau en conflit", str(e))
            return
        try:
            user = (self.security.get_current_user() or {}).get("login", "") if self.security else ""
            self.db.write_audit(user or "system", "network_add", d["cidr"], d["name"])
        except Exception:
            pass
        self._lbl_status.setText(f"Découverte de {d['cidr']} en cours…")
        self.refresh()
        self.network_scan_requested.emit(nid)

    def _manage_networks(self):
        if not self.db:
            return
        dlg = NetworksDialog(self.db, self.security, self)
        dlg.rescan_requested.connect(self._rescan)
        dlg.exec()
        self.refresh()

    def _rescan(self, nid: int):
        self._lbl_status.setText("Redécouverte en cours…")
        self.network_scan_requested.emit(nid)

    def _show_detail(self, host: dict):
        self._detail_title.setText(host.get("name", "—"))
        status = host.get("status", "unknown")
        status_color = {"online": COLOR["green"], "offline": COLOR["red"],
                        "unreachable": COLOR["accent"]}.get(status, "#c4bfae")
        net_name = "—"
        if self.db and host.get("network_id"):
            n = next((n for n in self.db.get_networks() if n["id"] == host["network_id"]), None)
            net_name = f"{n['name']} ({n['cidr']})" if n else "—"
        mapping = {
            "IP": host.get("ip_address", "—"),
            "Statut": (host.get("status") or "—").capitalize(),
            "Type": TYPE_FR.get((host.get("device_type") or "unknown").lower(), host.get("device_type") or "—"),
            "Réseau": net_name,
            "MAC": host.get("mac_address") or "Non lue (appareil hors du réseau local)",
            "Fabricant": host.get("vendor") or "Adresse privée (téléphone) : fabricant masqué",
            "Groupe": host.get("group_name") or "Non classé",
            "Localisation": host.get("location") or "Non renseignée (bouton « Modifier »)",
            "Communauté SNMP": "••••••••" if host.get("snmp_community") else "Non utilisée",
            "Joint via": __import__("core.local_network", fromlist=["REACH_LABELS"]).REACH_LABELS.get(
                host.get("reach_method") or "", "Pas encore déterminé"),
            "Référentiel": "Attendu" if host.get("approved", 1) != 0 else "INCONNU — à vérifier",
            "Dernier contrôle": str(host.get("last_check") or "—")[:16],
        }
        self._current_host = host
        self._fill_extra(host)
        self._btn_approve.setVisible(host.get("approved", 1) == 0)
        for key, val in mapping.items():
            lbl = self._detail_fields.get(key)
            if lbl:
                lbl.setText(str(val))
                if key == "Statut":
                    lbl.setStyleSheet(f"color: {status_color}; font-size: 8pt; font-weight: 600;")

    def _fill_extra(self, host: dict):
        info = self._infos.get(host.get("id"))
        if info is None and self.db:
            from core import device_info as di
            info = di.build_info(self.db, host, self._ctx_local, self._ctx_v6)
        if info is None:
            return
        c = info["conn"]
        self._extra["Connexion"].setText(conn_badge_text(info) + (f"  ({c['source_label']})" if c["source_label"] else ""))
        self._extra["Qualité"].setText(info["quality"] or "Appareil hors ligne : non mesurable")
        self._extra["Temps de réponse"].setText(f"{info['latency_ms']:.0f} ms" if info["latency_ms"] is not None else "Pas de réponse mesurée")
        self._extra["IPv6"].setText(info["ipv6"] or "Non annoncée par l'appareil")
        self._extra["Première connexion"].setText(info["first_seen"] or "Pas encore enregistrée")
        self._extra["Dernière vue"].setText(info["last_seen"] or "Pas encore enregistrée")
        self._extra["Services ouverts"].setText(", ".join(info["open_ports"]) if info["open_ports"] else "Aucun trouvé (faire un scan pour vérifier)")
        self._hist.setText("\n".join(f"{h['at']}  {h['what']}" for h in info["history"]) or "Aucun changement d'état enregistré.")
        self._rate_lbl.setText(f"↑ {info['tx_fmt']}      ↓ {info['rx_fmt']}" if info["rx_fmt"] else "Débit : pas encore mesuré pour cet appareil")
        for b in self._act_btns.values():
            b.setEnabled(True)

    # ── actions sur un appareil (panneau, cartes de la vue Détails) ──
    action_done = pyqtSignal(str, str)           # (titre, message) : résultat d'un ping / scan, affiché dans le fil de l'interface

    def _on_action(self, kind: str, host_id):
        h = self.db.get_host_by_id(host_id) if (self.db and host_id) else None
        if not h:
            return
        if kind == "ping":
            self._run_bg(lambda: self._do_ping(h))
        elif kind == "scan":
            self._run_bg(lambda: self._do_scan(h))
        elif kind == "access":
            self._access_dialog(h)
        elif kind == "edit":
            self._edit_dialog(h)
        elif kind == "connect":
            self._connect_dialog(h)
        elif kind == "approve":
            if self._perm("can_manage_config"):
                from core.automation import AutomationEngine
                AutomationEngine(self.db, self.security).approve_device(h["id"])
                self.refresh()

    def _run_bg(self, fn):
        import threading
        self._lbl_status.setText("Opération en cours…")
        threading.Thread(target=fn, name="devinfo-action", daemon=True).start()

    def _do_ping(self, h: dict):
        from core import local_network as lnet
        r = lnet.probe_host_ex(h["ip_address"], timeout=1.0)
        msg = (f"{h['name']} répond ({r['latency_ms']:.0f} ms, méthode : {r['method']})." if r["alive"]
               else f"{h['name']} ne répond pas. Il est peut-être éteint, ou son pare-feu bloque les tests.")
        self.action_done.emit("Résultat du ping", msg)

    def _do_scan(self, h: dict):
        from core import device_info as di
        ports = di.quick_port_scan(h["ip_address"])
        if ports:
            lines = "\n".join(f"  • {p['port']}/tcp  {p['service']}" for p in ports)
            msg = f"{h['name']} : {len(ports)} service(s) ouvert(s) :\n{lines}"
        else:
            msg = f"{h['name']} : aucun des services courants n'est ouvert."
        self.action_done.emit("Résultat du scan", msg + "\n\n(Test rapide des ports courants ; le scan complet se règle dans « Scanner ».)")

    def _show_action_result(self, title: str, msg: str):
        self._lbl_status.setText("")
        QMessageBox.information(self, title, msg)

    def _connect_dialog(self, h):
        if not self._perm("can_manage_config"):
            return
        from ui.widgets.device_cards import ConnectDeviceDialog
        who = (self.security.get_current_user() or {}).get("login", "") if self.security else ""
        dlg = ConnectDeviceDialog(self.db, h, who or "system", self)
        dlg.exec()
        if getattr(dlg, "saved", False):
            self.refresh()

    def _edit_dialog(self, h: dict):
        if not self._perm("can_manage_config"):
            return
        from core import device_info as di
        info = self._infos.get(h["id"]) or di.build_info(self.db, h)
        dlg = EditDeviceDialog(info, self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        who = (self.security.get_current_user() or {}).get("login", "") if self.security else ""
        try:
            di.update_device_meta(self.db, h["id"], who or "system", **dlg.values())
        except ValueError as e:
            QMessageBox.warning(self, "Valeur refusée", str(e))
            return
        self.refresh()
        fresh = self.db.get_host_by_id(h["id"])
        if fresh:
            self._show_detail(fresh)

    def _access_dialog(self, h: dict):
        """Contrôle d'accès : voir comment couper la connexion de cet appareil, ou le retirer de la supervision."""
        if not self._perm("can_manage_config"):
            return
        from core.device_access import AccessRefused, DeviceAccess
        da = DeviceAccess(self.db, self.security)
        box = QMessageBox(self)
        box.setWindowTitle("Contrôle d'accès")
        box.setText(f"Que voulez-vous faire avec « {h['name']} » ({h['ip_address']}) ?")
        box.setInformativeText("Rien n'est coupé sans votre accord. Le plan ci-dessous explique comment bloquer cet appareil sur votre box, "
                               "votre routeur ou votre Wi-Fi.")
        box.setDetailedText(da.manual_plan(h["ip_address"]))
        b_rm = box.addButton("Retirer de la supervision", QMessageBox.ButtonRole.DestructiveRole)
        box.addButton("Fermer", QMessageBox.ButtonRole.RejectRole)
        box.exec()
        if box.clickedButton() is b_rm:
            try:
                da.remove(h["ip_address"], "retiré depuis la carte réseau")
            except (AccessRefused, PermissionError, ValueError) as e:
                QMessageBox.warning(self, "Refusé", str(e))
                return
            self.refresh()

    def showEvent(self, event):
        super().showEvent(event)
        self._start_context_refresh()
        self._place_bar()
        self._fit_view()            # 1re fois : le canevas a enfin sa vraie taille

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._place_bar()
        if not getattr(self, "_user_zoomed", False):
            self._fit_view()

    def _fit_view(self, *_):
        self._user_zoomed = False
        r = self._canvas._scene.itemsBoundingRect()
        if r.isValid() and not r.isEmpty():
            self._canvas.fitInView(r.adjusted(-30, -30, 30, 30), Qt.AspectRatioMode.KeepAspectRatio)
