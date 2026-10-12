"""
HSR — Métriques (graphiques temps réel)
Procus Tech

Grille 2×2 de graphiques PyQtGraph :
  - Trafic entrant (orange)
  - Trafic sortant (bleu)
  - CPU utilisation (rouge)
  - Charge CPU (vert)
"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QComboBox, QFrame, QGridLayout
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont

from ui.styles import COLOR

try:
    import pyqtgraph as pg
    import numpy as np
    HAS_GRAPH = True
    pg.setConfigOption("background", COLOR["bg_card"])
    pg.setConfigOption("foreground", COLOR["text_sec"])
except ImportError:
    HAS_GRAPH = False


MAX_POINTS = 60  # 60 échantillons affichés


class MetricPlot(QFrame):
    """Un graphique avec titre, valeur courante et aire colorée."""

    def __init__(self, title: str, unit: str, color: str, parent=None):
        super().__init__(parent)
        self._title  = title
        self._unit   = unit
        self._color  = color
        self._data   = [0.0] * MAX_POINTS
        self.setStyleSheet(f"""
            QFrame {{
                background: {COLOR['bg_card']};
                border: 1px solid {COLOR['border']};
                border-radius: 8px;
            }}
        """)
        self._build()

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(6)

        hdr = QHBoxLayout()
        title_lbl = QLabel(self._title)
        title_lbl.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 8pt; font-weight: 600; text-transform: uppercase;")
        self._cur_lbl = QLabel(f"0 {self._unit}")
        self._cur_lbl.setStyleSheet(f"color: {self._color}; font-size: 16pt; font-weight: 800;")
        hdr.addWidget(title_lbl)
        hdr.addStretch()
        hdr.addWidget(self._cur_lbl)
        layout.addLayout(hdr)

        if HAS_GRAPH:
            self._plot = pg.PlotWidget()
            self._plot.setFixedHeight(140)
            self._plot.showGrid(x=False, y=True, alpha=0.15)
            self._plot.hideAxis("bottom")
            self._plot.getAxis("left").setStyle(tickFont=QFont("Segoe UI", 7))
            self._plot.setMouseEnabled(x=False, y=False)
            self._plot.setMenuEnabled(False)

            x = list(range(MAX_POINTS))
            self._curve  = self._plot.plot(x, self._data,
                                           pen=pg.mkPen(self._color, width=2))
            zero_curve   = self._plot.plot(x, [0] * MAX_POINTS, pen=None)
            self._fill   = pg.FillBetweenItem(self._curve, zero_curve,
                                              self._color + "30")
            self._plot.addItem(self._fill)
            layout.addWidget(self._plot)
        else:
            layout.addWidget(QLabel("(PyQtGraph requis)"))

    def push(self, value: float):
        self._data.append(value)
        if len(self._data) > MAX_POINTS:
            self._data.pop(0)
        self._cur_lbl.setText(f"{value:.1f} {self._unit}")
        if HAS_GRAPH:
            self._curve.setData(list(range(MAX_POINTS)), self._data)


class MetricsView(QWidget):

    def __init__(self, db=None, parent=None):
        super().__init__(parent)
        self.db = db
        self._build_ui()

        self._timer = QTimer(self)
        self._timer.timeout.connect(self.refresh)
        self._timer.start(5_000)

        self.refresh()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)

        # ── En-tête ──
        hdr = QHBoxLayout()
        title = QLabel("Métriques")
        title.setStyleSheet(f"font-size: 14pt; font-weight: 700; color: {COLOR['text_pri']};")
        hdr.addWidget(title)
        hdr.addStretch()

        hdr.addWidget(QLabel("Hôte :"))
        self._host_combo = QComboBox()
        self._host_combo.setFixedWidth(200)
        self._host_combo.currentIndexChanged.connect(self.refresh)
        hdr.addWidget(self._host_combo)

        btn_refresh = QPushButton("⟳  Actualiser")
        btn_refresh.clicked.connect(self.refresh)
        hdr.addWidget(btn_refresh)

        layout.addLayout(hdr)

        # ── Grille 2×2 ──
        grid = QGridLayout()
        grid.setSpacing(12)

        self._plot_in   = MetricPlot("Trafic entrant",  "Mbps", COLOR["accent"])
        self._plot_out  = MetricPlot("Trafic sortant",  "Mbps", COLOR["cyan"])
        self._plot_cpu  = MetricPlot("CPU Utilisation", "%",    COLOR["red"])
        self._plot_mem  = MetricPlot("Mémoire utilisée","%" ,   COLOR["green"])

        grid.addWidget(self._plot_in,  0, 0)
        grid.addWidget(self._plot_out, 0, 1)
        grid.addWidget(self._plot_cpu, 1, 0)
        grid.addWidget(self._plot_mem, 1, 1)

        layout.addLayout(grid, 1)

        self._load_hosts()

    def _load_hosts(self):
        if not self.db:
            return
        self._host_combo.blockSignals(True)
        self._host_combo.clear()
        self._host_combo.addItem("Tous les hôtes", None)
        hosts = self.db.get_all_hosts()
        for h in hosts:
            self._host_combo.addItem(h["name"], h["id"])
        self._host_combo.blockSignals(False)

    def refresh(self):
        if not self.db:
            return

        host_id = self._host_combo.currentData()
        hours = 1

        def get_latest(metric_name: str) -> float:
            if host_id:
                rows = self.db.fetchall("""
                    SELECT value FROM metrics
                    WHERE host_id = ? AND metric_name = ?
                    ORDER BY collected_at DESC LIMIT 1
                """, (host_id, metric_name))
            else:
                rows = self.db.fetchall("""
                    SELECT AVG(value) as value FROM metrics
                    WHERE metric_name = ?
                      AND collected_at >= datetime('now', '-5 minutes')
                """, (metric_name,))
            return float(rows[0]["value"]) if rows and rows[0]["value"] is not None else 0.0

        self._plot_in.push(get_latest("if_in_octets"))
        self._plot_out.push(get_latest("if_out_octets"))
        self._plot_cpu.push(get_latest("cpu_util"))
        self._plot_mem.push(get_latest("mem_used"))
