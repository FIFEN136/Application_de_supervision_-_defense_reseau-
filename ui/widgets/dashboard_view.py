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
    QProgressBar, QHeaderView
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor, QFont

from ui.styles import COLOR, SEVERITY_COLORS, STATUS_COLORS, get_severity_badge_style

try:
    import pyqtgraph as pg
    import numpy as np
    HAS_GRAPH = True
except ImportError:
    HAS_GRAPH = False


# ─────────────────────────────────────────────────────────────────

class KpiCard(QFrame):
    """Carte KPI individuelle (En ligne, Hors ligne, etc.)."""

    def __init__(self, label: str, value: str = "0", color: str = "#E8EAED",
                 icon: str = "", parent=None):
        super().__init__(parent)
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
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 10, 16, 10)
        layout.setSpacing(4)

        row = QHBoxLayout()
        self._val_lbl = QLabel(value)
        self._val_lbl.setStyleSheet(f"font-size: 28pt; font-weight: 800; color: {color};")
        icon_lbl = QLabel(icon)
        icon_lbl.setStyleSheet("font-size: 20pt; color: #3D4455;")
        icon_lbl.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignTop)
        row.addWidget(self._val_lbl)
        row.addStretch()
        row.addWidget(icon_lbl)
        layout.addLayout(row)

        self._label_lbl = QLabel(label)
        self._label_lbl.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 8pt; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;")
        layout.addWidget(self._label_lbl)

    def set_value(self, value):
        self._val_lbl.setText(str(value))


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
            seg = QWidget()
            seg.setStyleSheet(f"background-color: {color}22; border: 1px solid {color}44;")
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
        self._build_ui()

        self._timer = QTimer(self)
        self._timer.timeout.connect(self.refresh)
        self._timer.start(30_000)

        self.refresh()

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
        self._kpi_online      = KpiCard("En ligne",      "0", COLOR["green"],  "✔")
        self._kpi_offline     = KpiCard("Hors ligne",    "0", COLOR["red"],    "✖")
        self._kpi_unreachable = KpiCard("Injoignables",  "0", COLOR["accent"], "⚠")
        self._kpi_problems    = KpiCard("Problèmes",     "0", COLOR["purple"], "🔔")
        for card in (self._kpi_online, self._kpi_offline, self._kpi_unreachable, self._kpi_problems):
            kpi_row.addWidget(card)
        main_layout.addLayout(kpi_row)

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
        lbl_trafic = QLabel("Trafic réseau — 24h")
        lbl_trafic.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 8pt; font-weight: 600; text-transform: uppercase;")
        g_lay.addWidget(lbl_trafic)
        if HAS_GRAPH:
            self._graph_traffic = self._build_traffic_graph()
            g_lay.addWidget(self._graph_traffic)
        else:
            g_lay.addWidget(QLabel("(PyQtGraph requis)"))
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
        top_lay.addStretch()
        graph_row.addWidget(top_frame, 1)
        main_layout.addLayout(graph_row)

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
        plot = pg.PlotWidget()
        plot.setFixedHeight(180)
        plot.showGrid(x=True, y=True, alpha=0.2)
        plot.getAxis("bottom").setStyle(tickFont=QFont("Segoe UI", 7))
        plot.getAxis("left").setStyle(tickFont=QFont("Segoe UI", 7))
        plot.getAxis("left").setLabel("Mbps", color=COLOR["text_sec"])
        x = list(range(24))
        zeros = [0] * 24
        self._curve_in  = plot.plot(x, zeros, pen=pg.mkPen(COLOR["accent"], width=2), name="Entrant")
        self._curve_out = plot.plot(x, zeros, pen=pg.mkPen(COLOR["cyan"],   width=2), name="Sortant")
        # Fill under curves
        fill_in  = pg.FillBetweenItem(self._curve_in,  plot.plot(x, zeros, pen=None), COLOR["accent"] + "40")
        fill_out = pg.FillBetweenItem(self._curve_out, plot.plot(x, zeros, pen=None), COLOR["cyan"]   + "40")
        plot.addItem(fill_in)
        plot.addItem(fill_out)
        legend = plot.addLegend(offset=(10, 10))
        legend.setLabelTextColor(COLOR["text_sec"])
        return plot

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

    def _refresh_problems(self):
        events = self.db.get_events(limit=20) if self.db else []
        self._tbl_problems.setRowCount(0)
        for evt in events:
            row = self._tbl_problems.rowCount()
            self._tbl_problems.insertRow(row)

            sev = evt.get("severity", "information")
            sev_item = QTableWidgetItem(sev.capitalize())
            sev_item.setForeground(QColor(SEVERITY_COLORS.get(sev, "#8B9CB0")))
            sev_item.setFont(QFont("Segoe UI", 8, QFont.Weight.Bold))

            self._tbl_problems.setItem(row, 0, sev_item)
            self._tbl_problems.setItem(row, 1, QTableWidgetItem(str(evt.get("occurred_at", ""))[:16]))
            self._tbl_problems.setItem(row, 2, QTableWidgetItem(evt.get("host_name", "")))
            self._tbl_problems.setItem(row, 3, QTableWidgetItem(evt.get("description", "")))
            acked = "✔ Acquitté" if evt.get("acknowledged") else "En cours"
            ack_item = QTableWidgetItem(acked)
            ack_item.setForeground(QColor(COLOR["green"] if evt.get("acknowledged") else COLOR["accent"]))
            self._tbl_problems.setItem(row, 4, ack_item)

    def _refresh_top_cpu(self):
        if not self.db:
            return
        metrics = self.db.fetchall("""
            SELECT h.name, m.value FROM metrics m
            JOIN hosts h ON m.host_id = h.id
            WHERE m.metric_name = 'cpu_util'
              AND m.collected_at = (
                SELECT MAX(m2.collected_at) FROM metrics m2
                WHERE m2.host_id = m.host_id AND m2.metric_name = 'cpu_util'
              )
            ORDER BY m.value DESC LIMIT 5
        """)
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
