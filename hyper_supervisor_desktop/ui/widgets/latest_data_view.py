"""
HSR — Dernières données (auto-refresh 3s)
Procus Tech

Colonnes : Hôte | Élément | Dernière valeur | Unité | Tendance | Min | Moy | Max | Mis à jour
"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget,
    QTableWidgetItem, QPushButton, QHeaderView, QAbstractItemView
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor, QFont

from ui.styles import COLOR
from ui.icons import icon_button


class LatestDataView(QWidget):

    def __init__(self, db=None, parent=None):
        super().__init__(parent)
        self.db = db
        self._build_ui()

        self._timer = QTimer(self)
        self._timer.timeout.connect(self.refresh)
        self._timer.start(3_000)

        self.refresh()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)

        hdr = QHBoxLayout()
        title = QLabel("Dernières données")
        title.setStyleSheet(f"font-size: 14pt; font-weight: 700; color: {COLOR['text_pri']};")
        hdr.addWidget(title)
        hdr.addStretch()
        self._lbl_next = QLabel()
        self._lbl_next.setStyleSheet(f"color: {COLOR['accent']}; font-size: 8pt;")
        hdr.addWidget(self._lbl_next)
        btn_pause = icon_button("act_pause", "Pause")
        btn_pause.setCheckable(True)
        btn_pause.toggled.connect(lambda p: self._timer.stop() if p else self._timer.start(3_000))
        hdr.addWidget(btn_pause)
        layout.addLayout(hdr)

        cols = ["Hôte", "Élément", "Dernière valeur", "Unité", "Tendance", "Min", "Moy", "Max", "Mis à jour"]
        self._table = QTableWidget(0, len(cols))
        self._table.setHorizontalHeaderLabels(cols)
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._table.verticalHeader().setVisible(False)
        self._table.setAlternatingRowColors(True)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        layout.addWidget(self._table)

        foot = QHBoxLayout()
        self._lbl_count = QLabel()
        self._lbl_count.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 8pt;")
        foot.addWidget(self._lbl_count)
        foot.addStretch()
        layout.addLayout(foot)

        self._countdown = 3

    def refresh(self):
        self._countdown = 3
        if not self.db:
            return

        rows = self.db.get_latest_metrics(limit=200)
        self._table.setRowCount(0)

        for r in rows:
            row = self._table.rowCount()
            self._table.insertRow(row)
            self._table.setRowHeight(row, 30)

            val = r.get("value", 0)
            unit = r.get("unit", "")
            metric = r.get("metric_name", "")

            # Couleur valeur selon seuil
            if metric in ("cpu_util", "mem_used") and unit == "%":
                color = COLOR["red"] if val >= 90 else COLOR["accent"] if val >= 70 else COLOR["green"]
            else:
                color = COLOR["cyan"]

            self._table.setItem(row, 0, QTableWidgetItem(r.get("host_name", "")))

            elem = metric
            if r.get("interface"):
                elem += f" [{r['interface']}]"
            self._table.setItem(row, 1, QTableWidgetItem(elem))

            val_item = QTableWidgetItem(f"{val:.2f}")
            val_item.setForeground(QColor(color))
            val_item.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
            val_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            self._table.setItem(row, 2, val_item)

            self._table.setItem(row, 3, QTableWidgetItem(unit))

            # Tendance (placeholder — nécessite historique)
            trend_item = QTableWidgetItem("→")
            trend_item.setForeground(QColor(COLOR["text_sec"]))
            trend_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(row, 4, trend_item)

            # Min / Moy / Max — calculé depuis historique si dispo
            stats = self._get_stats(r.get("host_name", ""), metric)
            self._table.setItem(row, 5, QTableWidgetItem(f"{stats['min']:.1f}" if stats else "—"))
            self._table.setItem(row, 6, QTableWidgetItem(f"{stats['avg']:.1f}" if stats else "—"))
            self._table.setItem(row, 7, QTableWidgetItem(f"{stats['max']:.1f}" if stats else "—"))

            self._table.setItem(row, 8, QTableWidgetItem(str(r.get("collected_at", ""))[:16]))

        self._lbl_count.setText(f"{self._table.rowCount()} élément(s)")
        self._lbl_next.setText("3 s")

    def _get_stats(self, host_name: str, metric_name: str) -> dict | None:
        if not self.db:
            return None
        try:
            row = self.db.fetchone("""
                SELECT MIN(m.value) as mn, AVG(m.value) as avg, MAX(m.value) as mx
                FROM metrics m JOIN hosts h ON m.host_id = h.id
                WHERE h.name = ? AND m.metric_name = ?
                  AND m.collected_at >= datetime('now', '-1 hour')
            """, (host_name, metric_name))
            if row and row.get("mn") is not None:
                return {"min": row["mn"], "avg": row["avg"], "max": row["mx"]}
        except Exception:
            pass
        return None
