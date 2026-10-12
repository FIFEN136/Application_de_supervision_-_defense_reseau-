"""
HSR — Carte réseau (topologie interactive)
Procus Tech

Identique à la maquette :
  - Nœuds colorés par statut (vert/rouge/orange/gris)
  - Types : R=routeur, FW=pare-feu, S=switch, AP=access point, SRV=serveur
  - Panneau de détail à droite au clic
  - Liens entre équipements
"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QSizePolicy, QScrollArea, QSplitter, QGraphicsView,
    QGraphicsScene, QGraphicsEllipseItem, QGraphicsTextItem,
    QGraphicsLineItem, QGraphicsRectItem
)
from PyQt6.QtCore import Qt, QPointF, QRectF, QTimer
from PyQt6.QtGui import QColor, QPen, QBrush, QFont, QPainter

from ui.styles import COLOR, STATUS_COLORS


# Icônes texte par type d'équipement
DEVICE_ICONS = {
    "router":      "R",
    "switch":      "S",
    "firewall":    "FW",
    "ap":          "AP",
    "server":      "SRV",
    "workstation": "PC",
    "unknown":     "?",
}

DEVICE_SHAPES = {
    "router":   "circle",
    "switch":   "rect",
    "firewall": "rect",
    "ap":       "circle",
    "server":   "rect",
    "unknown":  "circle",
}

# Positions prédéfinies pour disposition automatique (grille)
DEFAULT_POSITIONS = [
    (400, 80),   # core router
    (200, 200),  (600, 200),  # distribution
    (100, 350),  (300, 350),  (500, 350),  (700, 350),  # access
    (100, 500),  (300, 500),  (500, 500),  (700, 500),  # servers
]


class NodeItem(QWidget):
    """Nœud cliquable sur le canevas de topologie."""
    pass


class TopologyCanvas(QGraphicsView):
    """Canevas vectoriel pour la topologie réseau."""

    node_clicked = None  # callback (host: dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._scene = QGraphicsScene(self)
        self.setScene(self._scene)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setStyleSheet(f"background: #0D1117; border: 1px solid {COLOR['border']}; border-radius: 6px;")
        self._nodes: dict[int, dict] = {}   # host_id → {item, label, host}

    def draw_topology(self, hosts: list):
        self._scene.clear()
        self._nodes.clear()

        if not hosts:
            txt = self._scene.addText("Aucun équipement à afficher")
            txt.setDefaultTextColor(QColor(COLOR["text_sec"]))
            return

        # Disposition automatique
        for i, host in enumerate(hosts):
            if i >= len(DEFAULT_POSITIONS):
                x = (i % 8) * 120 + 50
                y = (i // 8) * 150 + 80
            else:
                x, y = DEFAULT_POSITIONS[i]

            status  = host.get("status", "unknown")
            dtype   = host.get("device_type", "unknown").lower()
            icon    = DEVICE_ICONS.get(dtype, "?")
            color   = STATUS_COLORS.get(status, "#8B9CB0")
            shape   = DEVICE_SHAPES.get(dtype, "circle")

            # Nœud
            size = 50
            if shape == "rect":
                node = self._scene.addRect(x - size//2, y - size//2, size, size,
                                           QPen(QColor(color), 2),
                                           QBrush(QColor(color + "22")))
            else:
                node = self._scene.addEllipse(x - size//2, y - size//2, size, size,
                                              QPen(QColor(color), 2),
                                              QBrush(QColor(color + "22")))
            node.setFlag(node.GraphicsItemFlag.ItemIsMovable)
            node.setData(0, host.get("id"))

            # Icône
            icon_txt = self._scene.addText(icon)
            icon_txt.setDefaultTextColor(QColor(color))
            icon_txt.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
            icon_txt.setPos(x - icon_txt.boundingRect().width() / 2,
                            y - icon_txt.boundingRect().height() / 2)
            icon_txt.setData(0, host.get("id"))

            # Étiquette nom
            label = self._scene.addText(host.get("name", ""))
            label.setDefaultTextColor(QColor(COLOR["text_pri"]))
            label.setFont(QFont("Segoe UI", 7))
            label.setPos(x - label.boundingRect().width() / 2, y + size // 2 + 4)

            # Étiquette IP
            ip_lbl = self._scene.addText(host.get("ip_address", ""))
            ip_lbl.setDefaultTextColor(QColor(COLOR["text_sec"]))
            ip_lbl.setFont(QFont("Segoe UI", 6))
            ip_lbl.setPos(x - ip_lbl.boundingRect().width() / 2, y + size // 2 + 18)

            self._nodes[host.get("id")] = {
                "item": node, "host": host, "x": x, "y": y
            }

        # Liens (premier nœud = cœur de réseau connecté à tous les autres)
        if len(hosts) > 1:
            ids = list(self._nodes.keys())
            root_id = ids[0]
            root_x  = self._nodes[root_id]["x"]
            root_y  = self._nodes[root_id]["y"]
            pen_link = QPen(QColor("#2D3340"), 1.5, Qt.PenStyle.DashLine)
            for nid in ids[1:]:
                nx = self._nodes[nid]["x"]
                ny = self._nodes[nid]["y"]
                self._scene.addLine(root_x, root_y, nx, ny, pen_link)

    def mousePressEvent(self, event):
        super().mousePressEvent(event)
        item = self.itemAt(event.pos())
        if item:
            host_id = item.data(0)
            if host_id and host_id in self._nodes and self.node_clicked:
                self.node_clicked(self._nodes[host_id]["host"])

    def wheelEvent(self, event):
        factor = 1.15 if event.angleDelta().y() > 0 else 0.87
        self.scale(factor, factor)


class TopologyView(QWidget):

    def __init__(self, db=None, parent=None):
        super().__init__(parent)
        self.db = db
        self._build_ui()
        self.refresh()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(12)

        # ── En-tête ──
        hdr = QHBoxLayout()
        title = QLabel("Carte réseau")
        title.setStyleSheet(f"font-size: 14pt; font-weight: 700; color: {COLOR['text_pri']};")
        hdr.addWidget(title)
        hdr.addStretch()

        btn_refresh = QPushButton("⟳  Actualiser")
        btn_refresh.clicked.connect(self.refresh)
        hdr.addWidget(btn_refresh)

        btn_fit = QPushButton("⤢  Ajuster")
        btn_fit.clicked.connect(self._fit_view)
        hdr.addWidget(btn_fit)
        layout.addLayout(hdr)

        # ── Légende ──
        legend_row = QHBoxLayout()
        legend_row.setSpacing(16)
        for label, color in [
            ("En ligne",     COLOR["green"]),
            ("Hors ligne",   COLOR["red"]),
            ("Injoignable",  COLOR["accent"]),
            ("Inconnu",      "#8B9CB0"),
        ]:
            dot = QLabel("●")
            dot.setStyleSheet(f"color: {color}; font-size: 10pt;")
            lbl = QLabel(label)
            lbl.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 8pt;")
            legend_row.addWidget(dot)
            legend_row.addWidget(lbl)
        legend_row.addStretch()
        layout.addLayout(legend_row)

        # ── Splitter : canevas + détail ──
        splitter = QSplitter(Qt.Orientation.Horizontal)

        self._canvas = TopologyCanvas()
        self._canvas.node_clicked = self._show_detail
        splitter.addWidget(self._canvas)

        self._detail = self._build_detail_panel()
        splitter.addWidget(self._detail)
        splitter.setSizes([900, 280])

        layout.addWidget(splitter, 1)

    def _build_detail_panel(self) -> QWidget:
        panel = QFrame()
        panel.setMaximumWidth(300)
        panel.setStyleSheet(f"""
            QFrame {{
                background: {COLOR['bg_card']};
                border: 1px solid {COLOR['border']};
                border-radius: 8px;
            }}
        """)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        self._detail_title = QLabel("Sélectionnez un équipement")
        self._detail_title.setStyleSheet(f"font-size: 11pt; font-weight: 700; color: {COLOR['text_pri']};")
        self._detail_title.setWordWrap(True)
        layout.addWidget(self._detail_title)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet(f"color: {COLOR['border']};")
        layout.addWidget(sep)

        self._detail_fields: dict[str, QLabel] = {}
        for key in ["IP", "Statut", "Type", "Groupe", "Localisation", "Communauté SNMP", "Dernier contrôle"]:
            row = QHBoxLayout()
            k_lbl = QLabel(f"{key} :")
            k_lbl.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 8pt; min-width: 110px;")
            v_lbl = QLabel("—")
            v_lbl.setStyleSheet(f"color: {COLOR['text_pri']}; font-size: 8pt;")
            v_lbl.setWordWrap(True)
            row.addWidget(k_lbl)
            row.addWidget(v_lbl, 1)
            layout.addLayout(row)
            self._detail_fields[key] = v_lbl

        layout.addStretch()

        btn_scan = QPushButton("▷  Scanner maintenant")
        btn_scan.setObjectName("btn_primary")
        layout.addWidget(btn_scan)

        return panel

    def refresh(self):
        if not self.db:
            return
        hosts = self.db.get_all_hosts()
        self._canvas.draw_topology(hosts)

    def _show_detail(self, host: dict):
        self._detail_title.setText(host.get("name", "—"))
        status = host.get("status", "unknown")
        status_color = {"online": COLOR["green"], "offline": COLOR["red"],
                        "unreachable": COLOR["accent"]}.get(status, "#8B9CB0")

        mapping = {
            "IP":                host.get("ip_address", "—"),
            "Statut":            host.get("status", "—").capitalize(),
            "Type":              host.get("device_type", "—"),
            "Groupe":            host.get("group_name", "—"),
            "Localisation":      host.get("location", "—"),
            "Communauté SNMP":   host.get("snmp_community", "—"),
            "Dernier contrôle":  str(host.get("last_check", "—"))[:16],
        }
        for key, val in mapping.items():
            lbl = self._detail_fields.get(key)
            if lbl:
                lbl.setText(str(val))
                if key == "Statut":
                    lbl.setStyleSheet(f"color: {status_color}; font-size: 8pt; font-weight: 600;")

    def _fit_view(self):
        self._canvas.fitInView(self._canvas._scene.sceneRect(),
                               Qt.AspectRatioMode.KeepAspectRatio)
