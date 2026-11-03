"""
HSR — Tableau de bord
Procus Tech

Identique à la maquette :
  • Ligne KPI : En ligne / Hors ligne / Injoignables / Problèmes actifs
  • Barre sévérités (Sinistre / Grave / Moyen / Avertissement / Info)
  • Section disponibilité globale (%)
  • Graphique trafic 24h (PyQtGraph — entrant orange / sortant bleu)
  • TOP 5 CPU
  • Tableau Problèmes récents
"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QTableWidget, QTableWidgetItem, QSizePolicy, QScrollArea,
    QProgressBar, QHeaderView, QComboBox
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor, QFont

from ui.styles import COLOR, SEVERITY_COLORS, STATUS_COLORS, get_severity_badge_style, alpha
from core import local_network as lnet
from ui.icons import ICONS, _svg_icon

try:
    import pyqtgraph as pg
    import numpy as np
    HAS_GRAPH = True
except ImportError:
    HAS_GRAPH = False


# ─────────────────────────────────────────────────────────────────

class KpiCard(QFrame):
    """Carte KPI : valeur + libellé + icône SVG au même style que le menu latéral."""

    def __init__(self, label: str, value: str = "0", color: str = "#ffffff",
                 icon_key: str = "", parent=None, unit: str = ""):
        super().__init__(parent)
        self._color = color
        self.setObjectName("card_frame")
        self.setMinimumWidth(160)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setFixedHeight(90)
        self.setStyleSheet(f"""
            QFrame#card_frame {{
                background-color: {COLOR['bg_card']};
                border: 1px solid {COLOR['border']};
                border-left: 4px solid {color};
                border-radius: 8px;
            }}
            QFrame#card_frame QLabel {{ background: transparent; border: none; }}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 10, 16, 10)
        layout.setSpacing(4)

        row = QHBoxLayout()
        self._val_lbl = QLabel(value)
        self._val_lbl.setStyleSheet(f"font-size: 28pt; font-weight: 800; color: {color};")
        self._unit_lbl = QLabel(unit)
        self._unit_lbl.setStyleSheet(f"font-size: 9pt; font-weight: 600; color: {COLOR['text_sec']};")
        self._unit_lbl.setAlignment(Qt.AlignmentFlag.AlignBottom | Qt.AlignmentFlag.AlignLeft)
        self._unit_lbl.setVisible(bool(unit))
        self._icon_lbl = QLabel()
        self._icon_lbl.setFixedSize(30, 30)
        self._icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._icon_lbl.setStyleSheet(
            f"background-color: {alpha(color, '1F')}; border: 1px solid {alpha(color, '55')}; border-radius: 8px;")
        body = ICONS.get(icon_key, "")
        if body:
            self._icon_lbl.setPixmap(_svg_icon(body, size=18, color=color))
        row.addWidget(self._val_lbl)
        row.addWidget(self._unit_lbl)
        row.addStretch()
        row.addWidget(self._icon_lbl, 0, Qt.AlignmentFlag.AlignTop)
        layout.addLayout(row)

        self._label_lbl = QLabel(label)
        self._label_lbl.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 8pt; font-weight: 600; letter-spacing: 0.5px;")
        layout.addWidget(self._label_lbl)

    def set_value(self, value, unit: str | None = None):
        self._val_lbl.setText(str(value))
        if unit is not None:
            self._unit_lbl.setText(unit)
            self._unit_lbl.setVisible(bool(unit))

    def set_label(self, text: str):
        self._label_lbl.setText(text)


class SeverityBar(QWidget):
    """Barre de sévérité horizontale avec compteurs."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(50)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self._segments: dict[str, QLabel] = {}
        severities = [
            ("disaster",    "Sinistre",      0),
            ("high",        "Grave",         0),
            ("average",     "Moyen",         0),
            ("warning",     "Avertissement", 0),
            ("information", "Information",   0),
        ]

        for sev, label, count in severities:
            color = SEVERITY_COLORS[sev]
            seg = QFrame()
            seg.setObjectName("sev_seg")
            seg.setStyleSheet(
                f"QFrame#sev_seg {{ background-color: {alpha(color, '22')}; border: 1px solid {alpha(color, '66')}; }}"
                "QFrame#sev_seg QLabel { background: transparent; border: none; }")
            seg_lay = QVBoxLayout(seg)
            seg_lay.setContentsMargins(8, 4, 8, 4)
            seg_lay.setSpacing(2)
            count_lbl = QLabel("0")
            count_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            count_lbl.setStyleSheet(f"color: {color}; font-size: 13pt; font-weight: 700; background: transparent;")
            name_lbl = QLabel(label)
            name_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            name_lbl.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 7pt; background: transparent;")
            seg_lay.addWidget(count_lbl)
            seg_lay.addWidget(name_lbl)
            self._segments[sev] = count_lbl
            layout.addWidget(seg, 1)

    def update_counts(self, counts: dict):
        for sev, lbl in self._segments.items():
            lbl.setText(str(counts.get(sev, 0)))


# ─────────────────────────────────────────────────────────────────

class DashboardView(QWidget):

    def __init__(self, db=None, parent=None):
        super().__init__(parent)
        self.db = db
        self._sampler = lnet.BandwidthSampler()
        self._sampler.sample()
        self._bw_user_choice = False
        self._build_ui()

        self._timer = QTimer(self)
        self._timer.timeout.connect(self.refresh)
        self._timer.start(30_000)

        # Débit réseau de la machine en quasi temps réel (lecture locale, non bloquante)
        self._live_timer = QTimer(self)
        self._live_timer.timeout.connect(self._update_live_bandwidth)
        self._live_timer.start(2_000)

        self.refresh()
        self._update_live_bandwidth()

    # ─────────────────────────────────────────
    def _build_ui(self):
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        container = QWidget()
        scroll.setWidget(container)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

        main_layout = QVBoxLayout(container)
        main_layout.setContentsMargins(24, 20, 24, 20)
        main_layout.setSpacing(16)

        # ── Titre ──
        hdr = QHBoxLayout()
        title = QLabel("Tableau de bord")
        title.setStyleSheet(f"font-size: 14pt; font-weight: 700; color: {COLOR['text_pri']};")
        hdr.addWidget(title)
        hdr.addStretch()
        self._lbl_refresh = QLabel()
        self._lbl_refresh.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 8pt;")
        hdr.addWidget(self._lbl_refresh)
        main_layout.addLayout(hdr)

        # ── KPI Cards ──
        kpi_row = QHBoxLayout()
        kpi_row.setSpacing(12)
        self._kpi_online      = KpiCard("En ligne",      "0", COLOR["green"],  "kpi_online")
        self._kpi_offline     = KpiCard("Hors ligne",    "0", COLOR["red"],    "kpi_offline")
        self._kpi_unreachable = KpiCard("Injoignables",  "0", COLOR["accent"], "kpi_unreachable")
        self._kpi_problems    = KpiCard("Problèmes",     "0", COLOR["purple"], "kpi_problems")
        for card in (self._kpi_online, self._kpi_offline, self._kpi_unreachable, self._kpi_problems):
            kpi_row.addWidget(card)
        main_layout.addLayout(kpi_row)

        # ── Bande passante temps réel (machine locale) ──
        bw_row = QHBoxLayout()
        bw_row.setSpacing(12)
        self._kpi_bw_in  = KpiCard("Débit entrant", "0", COLOR["accent"], "kpi_down", unit="Kb/s")
        self._kpi_bw_out = KpiCard("Débit sortant", "0", COLOR["cyan"], "kpi_up", unit="Kb/s")
        self._kpi_net    = KpiCard("Réseau local", "—", COLOR["green"], "kpi_network")
        self._kpi_net._val_lbl.setStyleSheet(
            f"font-size: 14pt; font-weight: 800; color: {COLOR['green']};")
        self._kpi_gw     = KpiCard("Passerelle", "—", COLOR["purple"], "kpi_gateway")
        self._kpi_gw._val_lbl.setStyleSheet(
            f"font-size: 14pt; font-weight: 800; color: {COLOR['purple']};")
        for card in (self._kpi_bw_in, self._kpi_bw_out, self._kpi_net, self._kpi_gw):
            bw_row.addWidget(card)
        main_layout.addLayout(bw_row)

        # ── Barre sévérités ──
        sev_box = QFrame()
        sev_box.setObjectName("card_frame")
        sev_box.setStyleSheet(f"QFrame#card_frame {{ background-color: {COLOR['bg_card']}; border: 1px solid {COLOR['border']}; border-radius: 8px; }}")
        sev_lay = QVBoxLayout(sev_box)
        sev_lay.setContentsMargins(16, 12, 16, 12)
        sev_lay.setSpacing(8)
        sev_label = QLabel("Répartition des sévérités")
        sev_label.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 8pt; font-weight: 600; text-transform: uppercase;")
        sev_lay.addWidget(sev_label)
        self._severity_bar = SeverityBar()
        sev_lay.addWidget(self._severity_bar)
        main_layout.addWidget(sev_box)

        # ── Disponibilité globale ──
        dispo_frame = QFrame()
        dispo_frame.setObjectName("card_frame")
        dispo_frame.setStyleSheet(f"QFrame#card_frame {{ background-color: {COLOR['bg_card']}; border: 1px solid {COLOR['border']}; border-radius: 8px; }}")
        dispo_lay = QVBoxLayout(dispo_frame)
        dispo_lay.setContentsMargins(16, 12, 16, 12)
        dispo_lay.setSpacing(8)
        lbl_dispo = QLabel("Disponibilité globale")
        lbl_dispo.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 8pt; font-weight: 600; text-transform: uppercase;")
        dispo_lay.addWidget(lbl_dispo)
        dispo_row = QHBoxLayout()
        self._pbar_dispo = QProgressBar()
        self._pbar_dispo.setRange(0, 100)
        self._pbar_dispo.setValue(100)
        self._pbar_dispo.setFixedHeight(16)
        self._pbar_dispo.setStyleSheet(f"""
            QProgressBar {{
                background-color: {COLOR['border']};
                border: none;
                border-radius: 8px;
            }}
            QProgressBar::chunk {{
                background-color: {COLOR['green']};
                border-radius: 8px;
            }}
        """)
        self._lbl_dispo_pct = QLabel("100 %")
        self._lbl_dispo_pct.setStyleSheet(f"color: {COLOR['green']}; font-size: 12pt; font-weight: 700;")
        dispo_row.addWidget(self._pbar_dispo, 1)
        dispo_row.addWidget(self._lbl_dispo_pct)
        dispo_lay.addLayout(dispo_row)
        main_layout.addWidget(dispo_frame)

        # ── Graphique trafic ──
        graph_row = QHBoxLayout()
        graph_row.setSpacing(12)

        # Trafic 24h
        graph_frame = QFrame()
        graph_frame.setObjectName("card_frame")
        graph_frame.setStyleSheet(f"QFrame#card_frame {{ background-color: {COLOR['bg_card']}; border: 1px solid {COLOR['border']}; border-radius: 8px; }}")
        g_lay = QVBoxLayout(graph_frame)
        g_lay.setContentsMargins(16, 12, 16, 12)
        g_lay.setSpacing(8)
        g_hdr = QHBoxLayout()
        lbl_trafic = QLabel("Trafic réseau — 24h")
        lbl_trafic.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 8pt; font-weight: 600; text-transform: uppercase;")
        g_hdr.addWidget(lbl_trafic)
        g_hdr.addStretch()
        self._cmb_bw_host = QComboBox()
        self._cmb_bw_host.setMinimumWidth(220)
        self._cmb_bw_host.currentIndexChanged.connect(self._refresh_traffic)
        self._cmb_bw_host.activated.connect(self._on_bw_host_chosen)   # choix explicite de l'utilisateur
        g_hdr.addWidget(self._cmb_bw_host)
        g_lay.addLayout(g_hdr)
        if HAS_GRAPH:
            self._graph_traffic = self._build_traffic_graph()
            g_lay.addWidget(self._graph_traffic)
        else:
            g_lay.addWidget(QLabel("(PyQtGraph requis)"))
        self._lbl_bw_hint = QLabel("")
        self._lbl_bw_hint.setWordWrap(True)
        self._lbl_bw_hint.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 8pt;")
        g_lay.addWidget(self._lbl_bw_hint)
        graph_row.addWidget(graph_frame, 2)

        # TOP CPU
        top_frame = QFrame()
        top_frame.setObjectName("card_frame")
        top_frame.setStyleSheet(f"QFrame#card_frame {{ background-color: {COLOR['bg_card']}; border: 1px solid {COLOR['border']}; border-radius: 8px; }}")
        top_lay = QVBoxLayout(top_frame)
        top_lay.setContentsMargins(16, 12, 16, 12)
        top_lay.setSpacing(8)
        lbl_cpu = QLabel("TOP 5 CPU")
        lbl_cpu.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 8pt; font-weight: 600; text-transform: uppercase;")
        top_lay.addWidget(lbl_cpu)
        self._cpu_rows: list[tuple] = []
        for _ in range(5):
            row_w = QWidget()
            row_lay = QHBoxLayout(row_w)
            row_lay.setContentsMargins(0, 2, 0, 2)
            name = QLabel("—")
            name.setStyleSheet(f"color: {COLOR['text_pri']}; font-size: 8pt;")
            name.setFixedWidth(100)
            bar = QProgressBar()
            bar.setRange(0, 100)
            bar.setFixedHeight(8)
            bar.setStyleSheet(f"""
                QProgressBar {{ background: {COLOR['border']}; border: none; border-radius: 4px; }}
                QProgressBar::chunk {{ background: {COLOR['cyan']}; border-radius: 4px; }}
            """)
            pct = QLabel("0%")
            pct.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 7pt;")
            pct.setFixedWidth(30)
            row_lay.addWidget(name)
            row_lay.addWidget(bar, 1)
            row_lay.addWidget(pct)
            top_lay.addWidget(row_w)
            self._cpu_rows.append((name, bar, pct))
        self._lbl_cpu_hint = QLabel("")
        self._lbl_cpu_hint.setWordWrap(True)
        self._lbl_cpu_hint.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 7pt;")
        top_lay.addWidget(self._lbl_cpu_hint)
        top_lay.addStretch()
        graph_row.addWidget(top_frame, 1)
        main_layout.addLayout(graph_row)

        # ── Débit reçu par équipement (temps réel pour cette machine, relevé chaque minute pour les autres) ──
        rx_frame = QFrame()
        rx_frame.setObjectName("card_frame")
        rx_frame.setStyleSheet(f"QFrame#card_frame {{ background-color: {COLOR['bg_card']}; border: 1px solid {COLOR['border']}; border-radius: 8px; }}")
        rx_lay = QVBoxLayout(rx_frame)
        rx_lay.setContentsMargins(16, 12, 16, 12)
        rx_lay.setSpacing(8)
        lbl_rx = QLabel("Débit reçu par équipement")
        lbl_rx.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 8pt; font-weight: 600; text-transform: uppercase;")
        rx_lay.addWidget(lbl_rx)
        from ui.widgets.bandwidth_view import BarsWidget
        self._rx_bars = BarsWidget(rx_only=True)
        rx_lay.addWidget(self._rx_bars)
        self._lbl_rx_hint = QLabel("")
        self._lbl_rx_hint.setWordWrap(True)
        self._lbl_rx_hint.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 8pt;")
        rx_lay.addWidget(self._lbl_rx_hint)
        main_layout.addWidget(rx_frame)

        # ── Latence par équipement (une courbe par machine, nommée) + Top 5 latence ──
        lat_row = QHBoxLayout()
        lat_row.setSpacing(12)
        lat_frame = QFrame()
        lat_frame.setObjectName("card_frame")
        lat_frame.setStyleSheet(f"QFrame#card_frame {{ background-color: {COLOR['bg_card']}; border: 1px solid {COLOR['border']}; border-radius: 8px; }}")
        l_lay = QVBoxLayout(lat_frame)
        l_lay.setContentsMargins(16, 12, 16, 12)
        l_lay.setSpacing(8)
        lbl_lat = QLabel("Latence par équipement — 24h")
        lbl_lat.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 8pt; font-weight: 600; text-transform: uppercase;")
        l_lay.addWidget(lbl_lat)
        if HAS_GRAPH:
            self._graph_lat = self._build_latency_graph()
            l_lay.addWidget(self._graph_lat)
        self._lbl_lat_hint = QLabel("")
        self._lbl_lat_hint.setWordWrap(True)
        self._lbl_lat_hint.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 8pt;")
        l_lay.addWidget(self._lbl_lat_hint)
        lat_row.addWidget(lat_frame, 2)

        tl_frame = QFrame()
        tl_frame.setObjectName("card_frame")
        tl_frame.setStyleSheet(f"QFrame#card_frame {{ background-color: {COLOR['bg_card']}; border: 1px solid {COLOR['border']}; border-radius: 8px; }}")
        tl_lay = QVBoxLayout(tl_frame)
        tl_lay.setContentsMargins(16, 12, 16, 12)
        tl_lay.setSpacing(8)
        lbl_tl = QLabel("TOP 5 LATENCE")
        lbl_tl.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 8pt; font-weight: 600; text-transform: uppercase;")
        tl_lay.addWidget(lbl_tl)
        self._lat_rows: list[tuple] = []
        for _ in range(5):
            row_w = QWidget()
            row_lay = QHBoxLayout(row_w)
            row_lay.setContentsMargins(0, 2, 0, 2)
            name = QLabel("—")
            name.setStyleSheet(f"color: {COLOR['text_pri']}; font-size: 8pt;")
            name.setFixedWidth(100)
            bar = QProgressBar()
            bar.setRange(0, 100)
            bar.setFixedHeight(8)
            bar.setTextVisible(False)
            val = QLabel("—")
            val.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 7pt;")
            val.setFixedWidth(48)
            row_lay.addWidget(name)
            row_lay.addWidget(bar, 1)
            row_lay.addWidget(val)
            tl_lay.addWidget(row_w)
            self._lat_rows.append((name, bar, val))
        tl_lay.addStretch()
        lat_row.addWidget(tl_frame, 1)
        main_layout.addLayout(lat_row)

        # ── Problèmes récents ──
        prob_frame = QFrame()
        prob_frame.setObjectName("card_frame")
        prob_frame.setStyleSheet(f"QFrame#card_frame {{ background-color: {COLOR['bg_card']}; border: 1px solid {COLOR['border']}; border-radius: 8px; }}")
        prob_lay = QVBoxLayout(prob_frame)
        prob_lay.setContentsMargins(16, 12, 16, 12)
        prob_lay.setSpacing(8)
        lbl_prob = QLabel("Problèmes récents")
        lbl_prob.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 8pt; font-weight: 600; text-transform: uppercase;")
        prob_lay.addWidget(lbl_prob)

        self._tbl_problems = QTableWidget(0, 5)
        self._tbl_problems.setHorizontalHeaderLabels(["Sévérité", "Depuis", "Hôte", "Problème", "Statut"])
        self._tbl_problems.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self._tbl_problems.verticalHeader().setVisible(False)
        self._tbl_problems.setAlternatingRowColors(True)
        self._tbl_problems.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._tbl_problems.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._tbl_problems.setFixedHeight(200)
        prob_lay.addWidget(self._tbl_problems)
        main_layout.addWidget(prob_frame)

        main_layout.addStretch()

    def _build_traffic_graph(self):
        pg.setConfigOption("background", COLOR["bg_card"])
        pg.setConfigOption("foreground", COLOR["text_sec"])
        plot = pg.PlotWidget(axisItems={"bottom": pg.DateAxisItem(orientation="bottom")})
        plot.setFixedHeight(180)
        plot.showGrid(x=True, y=True, alpha=0.2)
        plot.getAxis("bottom").setStyle(tickFont=QFont("Segoe UI", 7))
        plot.getAxis("left").setStyle(tickFont=QFont("Segoe UI", 7))
        plot.getAxis("left").setLabel("Débit (Mb/s)", color=COLOR["text_sec"])
        plot.getAxis("left").enableAutoSIPrefix(False)      # plus de « x0.001 »
        plot.setMouseEnabled(x=False, y=False)
        self._curve_in  = plot.plot([], [], pen=pg.mkPen(COLOR["accent"], width=2), name="Entrant")
        self._curve_out = plot.plot([], [], pen=pg.mkPen(COLOR["cyan"],   width=2), name="Sortant")
        legend = plot.addLegend(offset=(10, 10))
        legend.setLabelTextColor(COLOR["text_sec"])
        return plot

    LAT_COLORS = ["#F39C12", "#1ABC9C", "#3498DB", "#E74C3C", "#9B59B6", "#2ECC71", "#E67E22", "#F1C40F"]

    def _build_latency_graph(self):
        plot = pg.PlotWidget(axisItems={"bottom": pg.DateAxisItem(orientation="bottom")})
        plot.setFixedHeight(180)
        plot.showGrid(x=True, y=True, alpha=0.2)
        plot.getAxis("bottom").setStyle(tickFont=QFont("Segoe UI", 7))
        plot.getAxis("left").setStyle(tickFont=QFont("Segoe UI", 7))
        plot.getAxis("left").setLabel("Latence (ms)", color=COLOR["text_sec"])
        plot.getAxis("left").enableAutoSIPrefix(False)
        plot.setMouseEnabled(x=False, y=False)
        self._lat_legend = plot.addLegend(offset=(10, 10))
        self._lat_legend.setLabelTextColor(COLOR["text_sec"])
        self._lat_curves: list = []
        return plot

    def _refresh_latency(self):
        """Une courbe par équipement mesuré (légende = nom de la machine) + classement des plus lents."""
        if not self.db:
            return
        series = self.db.get_latency_series(hours=24, bucket_minutes=5, max_hosts=8)
        if HAS_GRAPH:
            plot = self._graph_lat
            for c in self._lat_curves:
                plot.removeItem(c)
                self._lat_legend.removeItem(c)
            self._lat_curves = []
            import time
            top = 0.0
            for i, (name, pts) in enumerate(series.items()):
                col = self.LAT_COLORS[i % len(self.LAT_COLORS)]
                curve = plot.plot([float(b) for b, _ in pts], [v for _, v in pts],
                                  pen=pg.mkPen(col, width=2), name=name,
                                  symbol="o", symbolSize=4, symbolBrush=col, symbolPen=col)
                self._lat_curves.append(curve)
                top = max(top, max(v for _, v in pts))
            now = time.time()
            plot.setXRange(now - 24 * 3600, now, padding=0.01)
            plot.setYRange(0, max(top * 1.2, 1.0), padding=0)
        n = len(series)
        self._lbl_lat_hint.setText(
            f"{n} équipement(s) mesuré(s) — une couleur par machine (voir la légende)." if n else
            "Aucune mesure pour l'instant : la latence est relevée à chaque cycle de supervision "
            "(ping ou connexion TCP). Les équipements qui bloquent ping et TCP restent visibles « en ligne » "
            "(ARP) mais sans courbe.")
        top5 = self.db.get_top_latency(5)
        mx = max([r["value"] for r in top5] + [1.0])
        for i, (name_w, bar_w, val_w) in enumerate(self._lat_rows):
            if i < len(top5):
                v = float(top5[i]["value"])
                name_w.setText(top5[i]["name"][:14])
                bar_w.setValue(int(v / mx * 100))
                val_w.setText(f"{v:.1f} ms")
                col = COLOR["red"] if v >= 200 else COLOR["accent"] if v >= 50 else COLOR["green"]
                bar_w.setStyleSheet(f"QProgressBar {{ background: {COLOR['border']}; border: none; border-radius: 4px; }}"
                                    f"QProgressBar::chunk {{ background: {col}; border-radius: 4px; }}")
            else:
                name_w.setText("—")
                bar_w.setValue(0)
                val_w.setText("—")

    # ─────────────────────────────────────────
    # Bande passante
    # ─────────────────────────────────────────

    def _update_live_bandwidth(self):
        """Débit instantané de la machine (compteurs réseau de l'OS)."""
        in_mbps, out_mbps = self._sampler.sample()
        v, u = lnet.format_rate(in_mbps)
        self._kpi_bw_in.set_value(v, u)
        v, u = lnet.format_rate(out_mbps)
        self._kpi_bw_out.set_value(v, u)
        if not getattr(self, "_link_label_done", False) and self._sampler.nic:
            self._link_label_done = True
            spd = lnet.link_speed_mbps(self._sampler.nic)
            tip = f"Interface : {self._sampler.nic}" + (f" · lien {spd:.0f} Mb/s" if spd else "")
            self._kpi_bw_in.setToolTip(tip)
            self._kpi_bw_out.setToolTip(tip)
        self._live_tick = getattr(self, "_live_tick", 0) + 1
        if self._live_tick % 5 == 0 and hasattr(self, "_rx_bars"):     # diagramme « débit reçu » : toutes les 10 s
            self._refresh_rx()

    def _refresh_network_info(self):
        """IP / sous-réseau / passerelle (mis en cache 2 min : la détection peut lancer une commande)."""
        import time
        now = time.monotonic()
        if getattr(self, "_net_cache_t", 0) and now - self._net_cache_t < 120:
            return
        self._net_cache_t = now
        net = lnet.get_primary_network()
        ip = lnet.get_primary_ip()
        self._kpi_net.set_value(f"{ip}  ·  {net}" if ip and net else "Hors réseau")
        self._kpi_gw.set_value(lnet.get_default_gateway() or "—")

    def _on_bw_host_chosen(self, _idx):
        self._bw_user_choice = True

    def _refresh_host_selector(self):
        """Remplit la liste des hôtes. Tant que l'utilisateur n'a pas choisi, cible la machine locale."""
        cmb = self._cmb_bw_host
        previous = cmb.currentData() if cmb.count() else None
        hosts = self.db.get_all_hosts()
        cmb.blockSignals(True)
        cmb.clear()
        cmb.addItem("Tous les hôtes (somme)", None)
        local_idx = 0
        for h in hosts:
            cmb.addItem(f"{h['name']} ({h['ip_address']})", h["id"])
            if local_idx == 0 and lnet.is_local_address(h["ip_address"]):
                local_idx = cmb.count() - 1
        if self._bw_user_choice:
            idx = cmb.findData(previous)
            idx = idx if idx >= 0 else 0
        else:
            idx = local_idx
        cmb.setCurrentIndex(idx)
        cmb.blockSignals(False)

    def _refresh_traffic(self, *_):
        if not (HAS_GRAPH and self.db):
            return
        series = self.db.get_bandwidth_series(
            host_id=self._cmb_bw_host.currentData(), hours=24, bucket_minutes=5)
        xs = [float(b) for b, _, _ in series]
        self._curve_in.setData(xs, [i for _, i, _ in series])
        self._curve_out.setData(xs, [o for _, _, o in series])
        # Axe X fixe sur les dernières 24 h (sinon un seul point donne une plage dégénérée « 00.210 »)
        import time
        now = time.time()
        plot = self._graph_traffic
        plot.setXRange(now - 24 * 3600, now, padding=0.01)
        top = max([0.0] + [i for _, i, _ in series] + [o for _, _, o in series])
        plot.setYRange(0, max(top * 1.2, 0.1), padding=0)
        if not series:
            hid = self._cmb_bw_host.currentData()
            self._lbl_bw_hint.setText(
                "Aucune donnée de débit pour cet équipement : le débit d'un routeur, switch ou serveur distant "
                "n'est lu que s'il a un agent SNMP activé (Hôtes → SNMP). Seule votre machine est mesurée "
                "automatiquement." if hid else "Aucune donnée de débit pour l'instant.")
        else:
            self._lbl_bw_hint.setText("")

    # ─────────────────────────────────────────
    # Rafraîchissement
    # ─────────────────────────────────────────

    def refresh(self):
        if not self.db:
            return
        from datetime import datetime
        self._lbl_refresh.setText(f"Mis à jour : {datetime.now().strftime('%H:%M:%S')}")

        stats = self.db.get_dashboard_stats()
        self._kpi_online.set_value(stats.get("online", 0))
        self._kpi_offline.set_value(stats.get("offline", 0))
        self._kpi_unreachable.set_value(stats.get("unreachable", 0))
        self._kpi_problems.set_value(stats.get("problems_active", 0))
        self._severity_bar.update_counts(stats.get("severity_counts", {}))

        total = stats.get("total", 1) or 1
        online = stats.get("online", 0)
        pct = int(online / total * 100)
        self._pbar_dispo.setValue(pct)
        self._lbl_dispo_pct.setText(f"{pct} %")
        color = COLOR["green"] if pct >= 90 else COLOR["accent"] if pct >= 70 else COLOR["red"]
        self._lbl_dispo_pct.setStyleSheet(f"color: {color}; font-size: 12pt; font-weight: 700;")

        self._refresh_problems()
        self._refresh_top_cpu()
        self._refresh_network_info()
        self._refresh_host_selector()
        self._refresh_traffic()
        self._refresh_latency()
        self._refresh_rx()

    def _refresh_problems(self):
        events = self.db.get_events(limit=20) if self.db else []
        self._tbl_problems.setRowCount(0)
        for evt in events:
            row = self._tbl_problems.rowCount()
            self._tbl_problems.insertRow(row)

            sev = evt.get("severity", "information")
            sev_item = QTableWidgetItem(sev.capitalize())
            sev_item.setForeground(QColor(SEVERITY_COLORS.get(sev, "#c4bfae")))
            sev_item.setFont(QFont("Segoe UI", 8, QFont.Weight.Bold))

            self._tbl_problems.setItem(row, 0, sev_item)
            self._tbl_problems.setItem(row, 1, QTableWidgetItem(str(evt.get("occurred_at", ""))[:16]))
            self._tbl_problems.setItem(row, 2, QTableWidgetItem(evt.get("host_name", "")))
            self._tbl_problems.setItem(row, 3, QTableWidgetItem(evt.get("description", "")))
            acked = "Acquitté" if evt.get("acknowledged") else "En cours"
            ack_item = QTableWidgetItem(acked)
            ack_item.setForeground(QColor(COLOR["green"] if evt.get("acknowledged") else COLOR["accent"]))
            self._tbl_problems.setItem(row, 4, ack_item)

    def _refresh_rx(self):
        """Débit reçu par équipement : le plus gros en premier. Cette machine est lue en direct (carte réseau)."""
        try:
            from core.bandwidth import BandwidthManager
            rows = BandwidthManager(self.db).current()
            me = lnet.get_primary_ip()
            live = self._sampler.last_in_mbps * 1e6
            mine = next((r for r in rows if r["ip"] == me), None)
            if mine is not None:
                mine["rx_bps"], mine["source"], mine["exact"] = live, "local", True
            elif me and live:
                h = self.db.get_host_by_ip(me) or {}
                rows.append({"ip": me, "name": h.get("name", "Cette machine"), "rx_bps": live, "tx_bps": 0.0,
                             "source": "local", "exact": True})
            rows.sort(key=lambda r: r["rx_bps"], reverse=True)
            self._rx_bars.set_rows([dict(r, tx_bps=0.0) for r in rows[:8]])
            self._lbl_rx_hint.setText(
                "Exact pour cette machine, le routeur (SNMP) et les équipements avec agent ; « ≈ » = estimation d'après les flux "
                "observés. Mise à jour chaque minute (cette machine : en direct).")
        except Exception:
            pass

    def _refresh_top_cpu(self):
        if not self.db:
            return
        metrics = self.db.fetchall("""
            SELECT h.name, m.value FROM metrics m
            JOIN hosts h ON m.host_id = h.id
            WHERE m.metric_name = 'cpu_util'
              AND m.id = (
                SELECT MAX(m2.id) FROM metrics m2
                WHERE m2.host_id = m.host_id AND m2.metric_name = 'cpu_util'
              )
            ORDER BY m.value DESC LIMIT 5
        """)
        self._lbl_cpu_hint.setText(
            "" if len(metrics) > 1 else
            "Le CPU des autres équipements s'affiche s'ils ont l'agent Procus installé ou SNMP activé. "
            "Sans l'un des deux, seule cette machine est mesurée.")
        for i, (name_w, bar_w, pct_w) in enumerate(self._cpu_rows):
            if i < len(metrics):
                m = metrics[i]
                val = int(m["value"])
                name_w.setText(m["name"][:14])
                bar_w.setValue(val)
                pct_w.setText(f"{val}%")
                color = COLOR["red"] if val >= 90 else COLOR["accent"] if val >= 70 else COLOR["cyan"]
                bar_w.setStyleSheet(f"""
                    QProgressBar {{ background: {COLOR['border']}; border: none; border-radius: 4px; }}
                    QProgressBar::chunk {{ background: {color}; border-radius: 4px; }}
                """)
            else:
                name_w.setText("—")
                bar_w.setValue(0)
                pct_w.setText("—")

    def on_metrics(self, data: dict):
        """Reçoit les métriques en temps réel du MonitorWorker."""
        self.refresh()
