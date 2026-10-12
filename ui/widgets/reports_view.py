"""
HSR — Rapports de disponibilité
Procus Tech

Identique à la maquette :
  - Graphique barres (disponibilité % par hôte)
  - Résumé global : MTTR, MTBF, Total incidents
  - Bouton Export PDF
"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QComboBox, QProgressBar, QScrollArea, QFileDialog
)
from PyQt6.QtCore import Qt, QDate
from PyQt6.QtGui import QFont

from ui.styles import COLOR

try:
    import pyqtgraph as pg
    HAS_GRAPH = True
    pg.setConfigOption("background", COLOR["bg_card"])
    pg.setConfigOption("foreground", COLOR["text_sec"])
except ImportError:
    HAS_GRAPH = False


class ReportsView(QWidget):

    def __init__(self, db=None, parent=None):
        super().__init__(parent)
        self.db = db
        self._build_ui()
        self.refresh()

    def _build_ui(self):
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        container = QWidget()
        scroll.setWidget(container)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

        layout = QVBoxLayout(container)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)

        # ── En-tête ──
        hdr = QHBoxLayout()
        title = QLabel("Rapports de disponibilité")
        title.setStyleSheet(f"font-size: 14pt; font-weight: 700; color: {COLOR['text_pri']};")
        hdr.addWidget(title)
        hdr.addStretch()

        hdr.addWidget(QLabel("Période :"))
        self._period_combo = QComboBox()
        self._period_combo.addItems(["7 derniers jours", "30 derniers jours", "90 derniers jours"])
        self._period_combo.setFixedWidth(160)
        self._period_combo.currentIndexChanged.connect(self.refresh)
        hdr.addWidget(self._period_combo)

        btn_refresh = QPushButton("⟳  Actualiser")
        btn_refresh.clicked.connect(self.refresh)
        hdr.addWidget(btn_refresh)

        btn_pdf = QPushButton("📄  Export PDF")
        btn_pdf.setObjectName("btn_primary")
        btn_pdf.clicked.connect(self._export_pdf)
        hdr.addWidget(btn_pdf)

        layout.addLayout(hdr)

        # ── KPIs résumé ──
        kpi_row = QHBoxLayout()
        kpi_row.setSpacing(12)

        kpi_data = [
            ("Disponibilité globale",  "—",    COLOR["green"]),
            ("MTTR (moy.)",            "—",    COLOR["accent"]),
            ("MTBF",                   "—",    COLOR["cyan"]),
            ("Total incidents",        "0",    COLOR["red"]),
        ]
        self._kpi_labels: dict[str, QLabel] = {}
        for name, val, color in kpi_data:
            card = QFrame()
            card.setStyleSheet(f"""
                QFrame {{
                    background: {COLOR['bg_card']};
                    border: 1px solid {COLOR['border']};
                    border-left: 4px solid {color};
                    border-radius: 8px;
                }}
            """)
            c_lay = QVBoxLayout(card)
            c_lay.setContentsMargins(16, 10, 16, 10)
            val_lbl = QLabel(val)
            val_lbl.setStyleSheet(f"font-size: 22pt; font-weight: 800; color: {color};")
            name_lbl = QLabel(name)
            name_lbl.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 8pt; text-transform: uppercase; font-weight: 600;")
            c_lay.addWidget(val_lbl)
            c_lay.addWidget(name_lbl)
            kpi_row.addWidget(card, 1)
            self._kpi_labels[name] = val_lbl

        layout.addLayout(kpi_row)

        # ── Graphique barres disponibilité ──
        graph_frame = QFrame()
        graph_frame.setStyleSheet(f"""
            QFrame {{
                background: {COLOR['bg_card']};
                border: 1px solid {COLOR['border']};
                border-radius: 8px;
            }}
        """)
        g_lay = QVBoxLayout(graph_frame)
        g_lay.setContentsMargins(16, 12, 16, 12)
        g_lay.setSpacing(8)

        lbl_g = QLabel("Disponibilité par hôte (%)")
        lbl_g.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 8pt; font-weight: 600; text-transform: uppercase;")
        g_lay.addWidget(lbl_g)

        if HAS_GRAPH:
            self._bar_chart = pg.PlotWidget()
            self._bar_chart.setFixedHeight(220)
            self._bar_chart.showGrid(x=False, y=True, alpha=0.2)
            self._bar_chart.getAxis("left").setLabel("%", color=COLOR["text_sec"])
            self._bar_chart.getAxis("left").setStyle(tickFont=QFont("Segoe UI", 7))
            self._bar_chart.setYRange(0, 105)
            g_lay.addWidget(self._bar_chart)
        else:
            self._host_bars: list = []
            self._bar_container = QVBoxLayout()
            g_lay.addLayout(self._bar_container)

        layout.addWidget(graph_frame)

        # ── Table disponibilité détaillée ──
        detail_frame = QFrame()
        detail_frame.setStyleSheet(f"""
            QFrame {{
                background: {COLOR['bg_card']};
                border: 1px solid {COLOR['border']};
                border-radius: 8px;
            }}
        """)
        d_lay = QVBoxLayout(detail_frame)
        d_lay.setContentsMargins(16, 12, 16, 12)
        d_lay.setSpacing(8)
        lbl_d = QLabel("Détail par hôte")
        lbl_d.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 8pt; font-weight: 600; text-transform: uppercase;")
        d_lay.addWidget(lbl_d)

        self._host_rows_widget = QWidget()
        self._host_rows_layout = QVBoxLayout(self._host_rows_widget)
        self._host_rows_layout.setContentsMargins(0, 0, 0, 0)
        self._host_rows_layout.setSpacing(6)
        d_lay.addWidget(self._host_rows_widget)
        layout.addWidget(detail_frame)

        layout.addStretch()

    def refresh(self):
        if not self.db:
            return

        period_idx = self._period_combo.currentIndex()
        days = [7, 30, 90][period_idx]

        hosts = self.db.get_all_hosts()
        total = len(hosts) or 1
        online = sum(1 for h in hosts if h.get("status") == "online")
        global_pct = round(online / total * 100, 1)

        self._kpi_labels["Disponibilité globale"].setText(f"{global_pct}%")

        events = self.db.fetchall(f"""
            SELECT COUNT(*) as cnt FROM events
            WHERE occurred_at >= datetime('now', '-{days} days')
        """)
        total_events = events[0]["cnt"] if events else 0
        self._kpi_labels["Total incidents"].setText(str(total_events))

        # MTTR / MTBF (calcul simplifié)
        self._kpi_labels["MTTR (moy.)"].setText("—")
        self._kpi_labels["MTBF"].setText("—")

        # Barres par hôte
        self._refresh_host_bars(hosts)

    def _refresh_host_bars(self, hosts: list):
        # Vider l'ancien contenu
        while self._host_rows_layout.count():
            item = self._host_rows_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        names = []
        values = []

        for host in hosts[:20]:  # max 20
            status = host.get("status", "unknown")
            pct = 100 if status == "online" else 0

            names.append(host.get("name", ""))
            values.append(pct)

            # Ligne avec barre
            row_w = QWidget()
            row_lay = QHBoxLayout(row_w)
            row_lay.setContentsMargins(0, 2, 0, 2)
            row_lay.setSpacing(10)

            name_lbl = QLabel(host.get("name", "")[:20])
            name_lbl.setStyleSheet(f"color: {COLOR['text_pri']}; font-size: 8pt;")
            name_lbl.setFixedWidth(150)

            bar = QProgressBar()
            bar.setRange(0, 100)
            bar.setValue(pct)
            bar.setFixedHeight(12)
            bar.setTextVisible(False)
            color = COLOR["green"] if pct >= 99 else COLOR["accent"] if pct >= 90 else COLOR["red"]
            bar.setStyleSheet(f"""
                QProgressBar {{ background: {COLOR['border']}; border: none; border-radius: 6px; }}
                QProgressBar::chunk {{ background: {color}; border-radius: 6px; }}
            """)

            pct_lbl = QLabel(f"{pct:.0f}%")
            pct_lbl.setStyleSheet(f"color: {color}; font-size: 8pt; font-weight: 700;")
            pct_lbl.setFixedWidth(40)

            row_lay.addWidget(name_lbl)
            row_lay.addWidget(bar, 1)
            row_lay.addWidget(pct_lbl)
            self._host_rows_layout.addWidget(row_w)

        # Mise à jour du graphique PyQtGraph si disponible
        if HAS_GRAPH and names:
            self._bar_chart.clear()
            bar_item = pg.BarGraphItem(
                x=list(range(len(values))),
                height=values,
                width=0.6,
                brush=pg.mkBrush(COLOR["accent"] + "AA"),
                pen=pg.mkPen(COLOR["accent"])
            )
            self._bar_chart.addItem(bar_item)
            ax = self._bar_chart.getAxis("bottom")
            ax.setTicks([[(i, n[:10]) for i, n in enumerate(names)]])
            ax.setStyle(tickFont=QFont("Segoe UI", 7))

    def _export_pdf(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Exporter rapport PDF", "rapport_disponibilite_hsr.pdf", "PDF (*.pdf)"
        )
        if not path:
            return
        try:
            from utils.exporter import Exporter
            hosts = self.db.get_all_hosts() if self.db else []
            Exporter.export_pdf(path, hosts, title="Rapport de disponibilité HSR")
        except Exception as e:
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.warning(self, "Erreur", f"Export PDF échoué : {e}")
