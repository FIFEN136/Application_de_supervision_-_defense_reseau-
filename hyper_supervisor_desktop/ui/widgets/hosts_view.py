"""
HSR — Vue Hôtes (Supervision)
Procus Tech

Identique à la maquette :
  Colonnes : Nom | IP | Statut | Agent | SNMP | Problèmes | CPU | RAM | Disque | Dernier contrôle | Localisation | Infos
  Bouton Scanner par ligne
  Filtres rapides : Tous / En ligne / Hors ligne / Injoignables
"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget,
    QTableWidgetItem, QPushButton, QProgressBar, QHeaderView,
    QFrame, QLineEdit, QComboBox, QAbstractItemView
)
from PyQt6.QtCore import Qt, pyqtSignal, pyqtSlot
from PyQt6.QtGui import QColor, QFont

from ui.styles import COLOR, STATUS_COLORS, SEVERITY_COLORS, alpha
from ui.icons import icon_button


class StatusDot(QLabel):
    def __init__(self, status: str = "unknown", parent=None):
        super().__init__(parent)
        self.set_status(status)
        self.setFixedSize(12, 12)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)

    def set_status(self, status: str):
        color = STATUS_COLORS.get(status, "#c4bfae")
        self.setStyleSheet(f"background-color: {color}; border-radius: 6px; min-width:10px; min-height:10px;")


class MiniBar(QProgressBar):
    def __init__(self, value: int = 0, parent=None):
        super().__init__(parent)
        self.setRange(0, 100)
        self.setValue(value)
        self.setFixedHeight(8)
        self.setTextVisible(False)
        self._set_color(value)

    def _set_color(self, val: int):
        color = COLOR["red"] if val >= 90 else COLOR["accent"] if val >= 70 else COLOR["green"]
        self.setStyleSheet(f"""
            QProgressBar {{ background: {COLOR['border']}; border: none; border-radius: 4px; }}
            QProgressBar::chunk {{ background: {color}; border-radius: 4px; }}
        """)

    def set_value_colored(self, val: int):
        self.setValue(val)
        self._set_color(val)


class HostsView(QWidget):

    # Demande de scan → ScannerWorker (QThread dédié, connexion queued)
    scan_requested = pyqtSignal(int, str, str)
    discover_requested = pyqtSignal()

    def __init__(self, db=None, security=None, parent=None):
        super().__init__(parent)
        self.db = db
        self.security = security
        self._build_ui()
        self.refresh()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)

        # ── En-tête ──
        hdr = QHBoxLayout()
        title = QLabel("Hôtes supervisés")
        title.setStyleSheet(f"font-size: 14pt; font-weight: 700; color: {COLOR['text_pri']};")
        hdr.addWidget(title)
        hdr.addStretch()

        self._search = QLineEdit()
        self._search.setPlaceholderText("Rechercher hôte / IP...")
        self._search.setFixedWidth(200)
        self._search.textChanged.connect(self._apply_filter)
        hdr.addWidget(self._search)

        btn_refresh = icon_button("act_refresh", "Actualiser")
        btn_refresh.clicked.connect(self.refresh)
        hdr.addWidget(btn_refresh)

        self._btn_discover = icon_button("act_globe", "Découvrir le réseau")
        self._btn_discover.clicked.connect(self._on_discover_clicked)
        hdr.addWidget(self._btn_discover)

        layout.addLayout(hdr)

        # ── Filtres statut ──
        filter_row = QHBoxLayout()
        filter_row.setSpacing(8)
        self._filter_btns: dict[str, QPushButton] = {}
        filters = [
            ("all",         "Tous",          "#c4bfae"),
            ("online",      "En ligne",      COLOR["green"]),
            ("offline",     "Hors ligne",    COLOR["red"]),
            ("unreachable", "Injoignables",  COLOR["accent"]),
            ("unknown",     "Inconnus",      "#c4bfae"),
        ]
        for key, lbl, color in filters:
            btn = QPushButton(lbl)
            btn.setCheckable(True)
            btn.setFixedHeight(26)
            btn.setStyleSheet(f"""
                QPushButton {{
                    background: {alpha(color, '22')}; color: {color};
                    border: 1px solid {alpha(color, '66')}; border-radius: 4px;
                    padding: 2px 10px; font-size: 8pt; font-weight: 600;
                }}
                QPushButton:checked {{ background: {color}; color: #0b0b0a; }}
            """)
            btn.clicked.connect(lambda ch, k=key: self._filter_status(k))
            self._filter_btns[key] = btn
            filter_row.addWidget(btn)
        self._filter_btns["all"].setChecked(True)
        filter_row.addStretch()
        layout.addLayout(filter_row)

        # ── Tableau ──
        cols = ["Nom", "IP", "Statut", "Agent", "SNMP", "Problèmes", "CPU %", "RAM %", "Disque %", "Dernier contrôle", "Localisation", "Actions"]
        self._table = QTableWidget(0, len(cols))
        self._table.setHorizontalHeaderLabels(cols)
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(10, QHeaderView.ResizeMode.Stretch)
        self._table.verticalHeader().setVisible(False)
        self._table.setAlternatingRowColors(True)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setColumnWidth(1, 110)
        self._table.setColumnWidth(2, 100)
        self._table.setColumnWidth(3, 65)
        self._table.setColumnWidth(4, 65)
        self._table.setColumnWidth(5, 80)
        self._table.setColumnWidth(6, 80)
        self._table.setColumnWidth(7, 80)
        self._table.setColumnWidth(8, 80)
        self._table.setColumnWidth(9, 140)
        self._table.setColumnWidth(11, 120)
        layout.addWidget(self._table)

        # ── Pied ──
        foot = QHBoxLayout()
        self._lbl_count = QLabel()
        self._lbl_count.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 8pt;")
        foot.addWidget(self._lbl_count)
        foot.addStretch()
        layout.addLayout(foot)

        self._current_filter = "all"

    # ─────────────────────────────────────────

    def _filter_status(self, key: str):
        self._current_filter = key
        for k, b in self._filter_btns.items():
            b.setChecked(k == key)
        self.refresh()

    def _apply_filter(self):
        txt = self._search.text().lower()
        for row in range(self._table.rowCount()):
            name = (self._table.item(row, 0) or QTableWidgetItem("")).text().lower()
            ip   = (self._table.item(row, 1) or QTableWidgetItem("")).text().lower()
            hide = txt and (txt not in name and txt not in ip)
            self._table.setRowHidden(row, hide)

    def refresh(self):
        if not self.db:
            return
        hosts = self.db.get_all_hosts()
        self._problem_counts = {
            r["host_id"]: r["cnt"] for r in self.db.fetchall(
                "SELECT host_id, COUNT(*) AS cnt FROM events "
                "WHERE acknowledged = 0 AND resolved_at IS NULL GROUP BY host_id")
        }
        self._populate(hosts)

    def _populate(self, hosts: list):
        self._table.setRowCount(0)
        for host in hosts:
            status = host.get("status", "unknown")
            if self._current_filter != "all" and status != self._current_filter:
                continue

            row = self._table.rowCount()
            self._table.insertRow(row)
            self._table.setRowHeight(row, 38)

            # Nom
            self._table.setItem(row, 0, QTableWidgetItem(host.get("name", "")))
            # IP
            self._table.setItem(row, 1, QTableWidgetItem(host.get("ip_address", "")))

            # Statut — widget avec pastille colorée
            status_w = QWidget()
            status_lay = QHBoxLayout(status_w)
            status_lay.setContentsMargins(6, 0, 6, 0)
            status_lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
            dot = StatusDot(status)
            lbl = QLabel(status.capitalize())
            lbl.setStyleSheet(f"color: {STATUS_COLORS.get(status, '#c4bfae')}; font-size: 8pt; font-weight: 600;")
            status_lay.addWidget(dot)
            status_lay.addWidget(lbl)
            self._table.setCellWidget(row, 2, status_w)

            # Agent / SNMP (indicateurs binaires)
            for col_idx, available in ((3, bool(host.get("agent_enabled"))), (4, bool(host.get("snmp_enabled")) and status == "online")):
                ind_w = QWidget()
                ind_lay = QHBoxLayout(ind_w)
                ind_lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
                ind_lay.setContentsMargins(0, 0, 0, 0)
                from ui.icons import dot_label
                ind_lay.addWidget(dot_label(COLOR["green"] if available else "#4a4430", 10))
                self._table.setCellWidget(row, col_idx, ind_w)

            # Problèmes
            prob_item = QTableWidgetItem(str(getattr(self, "_problem_counts", {}).get(host.get("id"), 0)))
            prob_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(row, 5, prob_item)

            # CPU / RAM / Disque — progress bars
            metrics = self._get_latest_metric(host.get("id"))
            for col_idx, key in ((6, "cpu_util"), (7, "mem_used")):
                self._table.setCellWidget(row, col_idx, self._usage_cell(metrics.get(key), host))

            # Disque
            disk_val = metrics.get("disk_used")
            disk_w = QWidget()
            disk_lay = QVBoxLayout(disk_w)
            disk_lay.setContentsMargins(6, 10, 6, 10)
            disk_bar = MiniBar(int(disk_val) if disk_val is not None else 0)
            disk_lbl = QLabel(f"{int(disk_val)}%" if disk_val is not None else "—")
            disk_lbl.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 7pt;")
            disk_lbl.setAlignment(Qt.AlignmentFlag.AlignRight)
            disk_lay.addWidget(disk_bar)
            disk_lay.addWidget(disk_lbl)
            self._table.setCellWidget(row, 8, disk_w)

            # Dernier contrôle
            self._table.setItem(row, 9, QTableWidgetItem(str(host.get("last_check") or "—")[:16]))

            # Localisation
            self._table.setItem(row, 10, QTableWidgetItem(host.get("location", "")))

            # Bouton scanner
            btn_w = QWidget()
            btn_lay = QHBoxLayout(btn_w)
            btn_lay.setContentsMargins(4, 4, 4, 4)
            btn_lay.setSpacing(4)
            btn_scan = icon_button("act_play", "Scan")
            btn_scan.setFixedHeight(24)
            btn_scan.setStyleSheet(f"""
                QPushButton {{
                    background: transparent; color: {COLOR['cyan']};
                    border: 1px solid {COLOR['cyan']}; border-radius: 3px;
                    padding: 1px 6px; font-size: 7pt;
                }}
                QPushButton:hover {{ background: {COLOR['cyan']}; color: #0b0b0a; }}
            """)
            host_id = host.get("id")
            host_ip = host.get("ip_address", "")
            host_name = host.get("name", "")
            community = host.get("snmp_community", "public")
            btn_scan.clicked.connect(lambda ch, hid=host_id, ip=host_ip, hn=host_name, comm=community:
                                     self._launch_scan(hid, ip, hn, comm))
            btn_lay.addWidget(btn_scan)
            self._table.setCellWidget(row, 11, btn_w)

        self._lbl_count.setText(f"{self._table.rowCount()} hôte(s) affiché(s)")

    @staticmethod
    def _usage_cell(val, host: dict) -> QWidget:
        """Barre d'utilisation, ou « — » expliqué quand l'équipement n'a ni agent ni SNMP (aucune mesure possible)."""
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(6, 10, 6, 10)
        if val is None:
            lbl = QLabel("—")
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lbl.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 9pt;")
            w.setToolTip("Pas de mesure : installez l'agent Procus sur cet équipement ou activez SNMP "
                         "(sinon le processeur et la mémoire ne sont pas visibles à distance).")
            lay.addWidget(lbl)
            return w
        v = int(val)
        pct_lbl = QLabel(f"{v}%")
        pct_lbl.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 7pt;")
        pct_lbl.setAlignment(Qt.AlignmentFlag.AlignRight)
        lay.addWidget(MiniBar(v))
        lay.addWidget(pct_lbl)
        return w

    def _get_latest_metric(self, host_id: int) -> dict:
        if not self.db or not host_id:
            return {}
        rows = self.db.fetchall("""
            SELECT metric_name, value FROM metrics
            WHERE host_id = ?
              AND id = (
                  SELECT MAX(id) FROM metrics m2
                  WHERE m2.host_id = metrics.host_id AND m2.metric_name = metrics.metric_name
              )
        """, (host_id,))
        return {r["metric_name"]: r["value"] for r in rows}

    def _launch_scan(self, host_id: int, ip: str, host_name: str, community: str = ""):
        """Bouton « Scan » : délègue au ScannerWorker partagé (le scan ne bloque jamais l'UI)."""
        self.scan_requested.emit(host_id, ip, host_name)

    @pyqtSlot(int)
    def on_cycle_done(self, n_hosts: int):
        """Fin d'un cycle de collecte : statuts / métriques à jour."""
        self.refresh()

    def _on_discover_clicked(self):
        self._btn_discover.setEnabled(False)
        self._btn_discover.setText("Découverte en cours…")
        self.discover_requested.emit()

    @pyqtSlot(int)
    def on_discovery_finished(self, added: int):
        self._btn_discover.setEnabled(True)
        self._btn_discover.setText("Découvrir le réseau")
        self.refresh()

    def on_scan_result(self, data: dict):
        """Un résultat de port : pas de rafraîchissement (25 ports/hôte) — voir on_scan_complete."""
        pass

    @pyqtSlot(str, list)
    def on_scan_complete(self, host_name: str, results: list):
        self.refresh()

    # ─────────────────────────────────────────
    # Point critique #4 — Détection de changements
    # ─────────────────────────────────────────

    def on_change_detected(self, event_dict: dict):
        """
        Appelé par le signal change_detected du ScannerWorker.
        Le ScannerWorker persiste déjà l'événement en DB ; ici on ne fait
        que rafraîchir la vue pour refléter le nouveau statut immédiatement.
        """
        from loguru import logger
        logger.info(
            f"[HOSTS] Changement détecté : {event_dict.get('host_name')} "
            f"port {event_dict.get('port')} "
            f"{event_dict.get('state_before')} → {event_dict.get('state_after')}"
        )
        self.refresh()

    def refresh(self):
        if not self.db:
            return
        hosts = self.db.get_all_hosts()
        self._populate(hosts)

    def _populate(self, hosts: list):
        self._table.setRowCount(0)
        for host in hosts:
            status = host.get("status", "unknown")
            if self._current_filter != "all" and status != self._current_filter:
                continue

            row = self._table.rowCount()
            self._table.insertRow(row)
            self._table.setRowHeight(row, 38)

            # Nom
            self._table.setItem(row, 0, QTableWidgetItem(host.get("name", "")))
            # IP
            self._table.setItem(row, 1, QTableWidgetItem(host.get("ip_address", "")))

            # Statut — widget avec pastille colorée
            status_w = QWidget()
            status_lay = QHBoxLayout(status_w)
            status_lay.setContentsMargins(6, 0, 6, 0)
            status_lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
            dot = StatusDot(status)
            lbl = QLabel(status.capitalize())
            lbl.setStyleSheet(f"color: {STATUS_COLORS.get(status, '#c4bfae')}; font-size: 8pt; font-weight: 600;")
            status_lay.addWidget(dot)
            status_lay.addWidget(lbl)
            self._table.setCellWidget(row, 2, status_w)

            # Agent / SNMP (indicateurs binaires)
            for col_idx, available in ((3, bool(host.get("agent_enabled"))), (4, bool(host.get("snmp_enabled")) and status == "online")):
                ind_w = QWidget()
                ind_lay = QHBoxLayout(ind_w)
                ind_lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
                ind_lay.setContentsMargins(0, 0, 0, 0)
                from ui.icons import dot_label
                ind_lay.addWidget(dot_label(COLOR["green"] if available else "#4a4430", 10))
                self._table.setCellWidget(row, col_idx, ind_w)

            # Problèmes
            prob_item = QTableWidgetItem("0")
            prob_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(row, 5, prob_item)

            # CPU / RAM / Disque — progress bars
            metrics = self._get_latest_metric(host.get("id"))
            for col_idx, key in ((6, "cpu_util"), (7, "mem_used")):
                self._table.setCellWidget(row, col_idx, self._usage_cell(metrics.get(key), host))

            # Disque (placeholder)
            disk_w = QWidget()
            disk_lay = QVBoxLayout(disk_w)
            disk_lay.setContentsMargins(6, 10, 6, 10)
            disk_bar = MiniBar(0)
            disk_lbl = QLabel("—")
            disk_lbl.setStyleSheet(f"color: {COLOR['text_sec']}; font-size: 7pt;")
            disk_lbl.setAlignment(Qt.AlignmentFlag.AlignRight)
            disk_lay.addWidget(disk_bar)
            disk_lay.addWidget(disk_lbl)
            self._table.setCellWidget(row, 8, disk_w)

            # Dernier contrôle
            self._table.setItem(row, 9, QTableWidgetItem(str(host.get("last_check", "—"))[:16]))

            # Localisation
            self._table.setItem(row, 10, QTableWidgetItem(host.get("location", "")))

            # Bouton scanner
            btn_w = QWidget()
            btn_lay = QHBoxLayout(btn_w)
            btn_lay.setContentsMargins(4, 4, 4, 4)
            btn_lay.setSpacing(4)
            btn_scan = icon_button("act_play", "Scan")
            btn_scan.setFixedHeight(24)
            btn_scan.setStyleSheet(f"""
                QPushButton {{
                    background: transparent; color: {COLOR['cyan']};
                    border: 1px solid {COLOR['cyan']}; border-radius: 3px;
                    padding: 1px 6px; font-size: 7pt;
                }}
                QPushButton:hover {{ background: {COLOR['cyan']}; color: #0b0b0a; }}
            """)
            host_id = host.get("id")
            host_ip = host.get("ip_address", "")
            host_name = host.get("name", "")
            community = host.get("snmp_community", "public")
            btn_scan.clicked.connect(lambda ch, hid=host_id, ip=host_ip, hn=host_name, comm=community:
                                     self._launch_scan(hid, ip, hn, comm))
            btn_lay.addWidget(btn_scan)
            self._table.setCellWidget(row, 11, btn_w)

        self._lbl_count.setText(f"{self._table.rowCount()} hôte(s) affiché(s)")

    def _get_latest_metric(self, host_id: int) -> dict:
        if not self.db or not host_id:
            return {}
        rows = self.db.fetchall("""
            SELECT metric_name, value FROM metrics
            WHERE host_id = ?
              AND collected_at = (
                  SELECT MAX(collected_at) FROM metrics m2
                  WHERE m2.host_id = metrics.host_id AND m2.metric_name = metrics.metric_name
              )
        """, (host_id,))
        return {r["metric_name"]: r["value"] for r in rows}

    def _launch_scan(self, host_id: int, ip: str, host_name: str, community: str = ""):
        """Bouton « Scan » : délègue au ScannerWorker partagé (le scan ne bloque jamais l'UI)."""
        self.scan_requested.emit(host_id, ip, host_name)

    def on_scan_result(self, data: dict):
        """Un résultat de port : pas de rafraîchissement (25 ports/hôte) — voir on_scan_complete."""
        pass

    @pyqtSlot(str, list)
    def on_scan_complete(self, host_name: str, results: list):
        self.refresh()

    # ─────────────────────────────────────────
    # Point critique #4 — Détection de changements
    # ─────────────────────────────────────────

    def on_change_detected(self, event_dict: dict):
        """
        Appelé par le signal change_detected du ScannerWorker.
        Le ScannerWorker persiste déjà l'événement en DB ; ici on ne fait
        que rafraîchir la vue pour refléter le nouveau statut immédiatement.
        """
        from loguru import logger
        logger.info(
            f"[HOSTS] Changement détecté : {event_dict.get('host_name')} "
            f"port {event_dict.get('port')} "
            f"{event_dict.get('state_before')} → {event_dict.get('state_after')}"
        )
        self.refresh()

    def trigger_all_scans(self):
        """
        Déclenché automatiquement par le SchedulerWorker toutes les 5 minutes.
        Lance un scan TCP sur chaque hôte supervisé.
        """
        if not self.db:
            return
        hosts = self.db.get_all_hosts()
        from loguru import logger
        logger.info(f"[HOSTS] Scan automatique de {len(hosts)} hôte(s)...")
        for host in hosts:
            host_id  = host.get("id")
            host_ip  = host.get("ip_address", "")
            host_name = host.get("name", "")
            community = host.get("snmp_community", "public")
            if host_ip:
                self._launch_scan(host_id, host_ip, host_name, community)
