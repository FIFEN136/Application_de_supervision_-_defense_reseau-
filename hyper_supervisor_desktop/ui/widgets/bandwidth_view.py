"""Procus Secure — onglet « Débits » : diagrammes (QPainter) par routeur / Wi-Fi et par équipement, fiche individuelle,
retrait de la supervision et blocage de la connexion (voir core/device_access.py pour les garde-fous)."""
from __future__ import annotations

import html

from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QRectF
from PyQt6.QtGui import QColor, QPainter, QPen, QFont
from PyQt6.QtWidgets import (QComboBox, QHBoxLayout, QInputDialog, QLabel, QMessageBox, QSplitter, QVBoxLayout, QWidget)

from core.bandwidth import fmt_bps, fmt_rate
from core.device_access import AccessRefused
from ui.styles import COLOR
from ui.widgets.defense_view import _fill, _note, _table
from ui.widgets.incidents_view import _btn

RX_COLOR, TX_COLOR = QColor("#3498DB"), QColor("#F39C12")


class BarsWidget(QWidget):
    """Barres horizontales : une ligne par équipement (reçu bleu, émis orange). Clic = sélection."""
    selected = pyqtSignal(str)
    ROW = 26

    def __init__(self, cap_bps: float = 0.0, parent=None, rx_only: bool = False):
        super().__init__(parent)
        self.rx_only = rx_only                   # tableau de bord : seul le débit REÇU est montré
        self.rows: list[dict] = []
        self.cap = cap_bps
        self.current = ""
        self.setMinimumHeight(60)

    def set_rows(self, rows: list[dict], cap_bps: float = 0.0, current: str = ""):
        self.rows, self.cap, self.current = rows, cap_bps, current
        self.setMinimumHeight(max(60, self.ROW * len(rows) + 8))
        self.update()

    def mousePressEvent(self, e):
        i = int(e.position().y() // self.ROW)
        if 0 <= i < len(self.rows):
            self.current = self.rows[i]["ip"]
            self.selected.emit(self.current)
            self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.fillRect(self.rect(), QColor(COLOR["bg_card"]) if "bg_card" in COLOR else QColor("#15140f"))
        if not self.rows:
            p.setPen(QColor(COLOR["text_sec"]))
            p.drawText(self.rect().adjusted(8, 0, 0, 0), Qt.AlignmentFlag.AlignVCenter, "Pas encore de mesure (attendez 1–2 minutes).")
            return
        mx = self.cap or max((r["rx_bps"] + r["tx_bps"]) for r in self.rows) or 1.0
        lab_w, val_w = 170, (230 if self.rx_only else 190)
        bar_w = max(40, self.width() - lab_w - val_w - 16)
        for i, r in enumerate(self.rows):
            y = i * self.ROW + 4
            if r["ip"] == self.current:
                p.fillRect(QRectF(0, y - 2, self.width(), self.ROW), QColor(255, 255, 255, 25))
            p.setPen(QColor(COLOR["text_pri"]))
            p.drawText(QRectF(8, y, lab_w - 8, 20), Qt.AlignmentFlag.AlignVCenter, (r["name"] or r["ip"])[:24])
            rx_w = min(bar_w, bar_w * r["rx_bps"] / mx)
            tx_w = min(bar_w - rx_w, bar_w * r["tx_bps"] / mx)
            p.fillRect(QRectF(lab_w, y + 3, rx_w, 14), RX_COLOR)
            p.fillRect(QRectF(lab_w + rx_w, y + 3, tx_w, 14), TX_COLOR)
            p.setPen(QPen(QColor(COLOR["text_sec"]), 1))
            p.drawRect(QRectF(lab_w, y + 3, bar_w, 14))
            tag = "" if r.get("exact", True) else " ≈"
            txt = (f"↓ {fmt_rate(r['rx_bps'])}{tag}" if self.rx_only
                   else f"↓ {fmt_bps(r['rx_bps'])}  ↑ {fmt_bps(r['tx_bps'])}{tag}")
            if "usage_pct" in r:
                txt = f"{r['usage_pct']:.0f} %  " + txt
            p.drawText(QRectF(lab_w + bar_w + 8, y, val_w, 20), Qt.AlignmentFlag.AlignVCenter, txt)


class LineWidget(QWidget):
    """Courbe reçu / émis dans le temps."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.data: list[tuple] = []
        self.setMinimumHeight(160)

    def set_series(self, data):
        self.data = list(data)
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.fillRect(self.rect(), QColor(COLOR["bg_card"]) if "bg_card" in COLOR else QColor("#15140f"))
        r = self.rect().adjusted(60, 10, -10, -20)
        p.setPen(QColor(COLOR["text_sec"]))
        if len(self.data) < 2:
            p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "Historique insuffisant pour tracer une courbe.")
            return
        mx = max(max(d[1], d[2]) for d in self.data) or 1.0
        t0, t1 = self.data[0][0], self.data[-1][0]
        span = max(1, t1 - t0)
        p.drawRect(r)
        p.drawText(2, r.top() + 10, fmt_bps(mx))
        p.drawText(2, r.bottom(), "0")
        for idx, col in ((1, RX_COLOR), (2, TX_COLOR)):
            p.setPen(QPen(col, 2))
            pts = [(r.left() + r.width() * (d[0] - t0) / span, r.bottom() - r.height() * d[idx] / mx) for d in self.data]
            for a, b in zip(pts, pts[1:]):
                p.drawLine(int(a[0]), int(a[1]), int(b[0]), int(b[1]))


class BandwidthTab(QWidget):
    def __init__(self, db, security, manager, parent=None):
        super().__init__(parent)
        self.db, self.security, self.mgr = db, security, manager
        self.bw, self.access = manager.bandwidth, manager.access
        self.ip = ""
        lay = QVBoxLayout(self)
        lay.addWidget(_note("Débit en temps réel : ↓ reçu, ↑ émis. « ≈ » = estimation d'après les flux observés (NetFlow / agents) ; "
                            "sans « ≈ » = compteurs exacts (SNMP du routeur / Wi-Fi, ou ce poste). Cliquez sur un équipement pour sa fiche."))
        hr = QHBoxLayout()
        self._gw_title = QLabel(""); self._gw_title.setStyleSheet(f"color:{COLOR['text_pri']};font-weight:600;")
        hr.addWidget(self._gw_title, 1)
        b = _btn("Capacité du lien…", "#3498DB"); b.clicked.connect(self._set_cap); hr.addWidget(b)
        b = _btn("Actualiser", "#2ECC71"); b.clicked.connect(self.refresh); hr.addWidget(b)
        lay.addLayout(hr)
        self.gw_bars = BarsWidget(); lay.addWidget(self.gw_bars)
        sp = QSplitter(Qt.Orientation.Horizontal)
        left = QWidget(); ll = QVBoxLayout(left); ll.addWidget(QLabel("Débit par équipement (les plus gros d'abord)"))
        self.dev_bars = BarsWidget(); self.dev_bars.selected.connect(self.select); ll.addWidget(self.dev_bars); ll.addStretch()
        right = QWidget(); rl = QVBoxLayout(right)
        self.info = QLabel("Sélectionnez un équipement."); self.info.setWordWrap(True)
        self.info.setTextFormat(Qt.TextFormat.RichText); self.info.setStyleSheet(f"color:{COLOR['text_pri']};")
        rl.addWidget(self.info)
        rr = QHBoxLayout(); rr.addWidget(QLabel("Période :")); self.span = QComboBox(); self.span.addItems(["1 heure", "24 heures"])
        self.span.currentIndexChanged.connect(lambda _: self.select(self.ip)); rr.addWidget(self.span); rr.addStretch(); rl.addLayout(rr)
        self.line = LineWidget(); rl.addWidget(self.line)
        self.peers = _table(["Interlocuteur", "Octets échangés", "Dont émis"], 2); self.peers.setMaximumHeight(150); rl.addWidget(self.peers)
        ar = QHBoxLayout()
        self.b_sim = _btn("Simuler le blocage", "#3498DB"); self.b_blk = _btn("Bloquer la connexion", "#E74C3C")
        self.b_unb = _btn("Lever le blocage", "#2ECC71"); self.b_rem = _btn("Retirer de la supervision", "#F39C12")
        self.b_man = _btn("Plan manuel", "#a8a393")
        self.b_sim.clicked.connect(lambda: self._block(True)); self.b_blk.clicked.connect(lambda: self._block(False))
        self.b_unb.clicked.connect(self._unblock); self.b_rem.clicked.connect(self._remove); self.b_man.clicked.connect(self._manual)
        for x in (self.b_sim, self.b_blk, self.b_unb, self.b_rem, self.b_man):
            ar.addWidget(x)
        rl.addLayout(ar)
        sp.addWidget(left); sp.addWidget(right); sp.setStretchFactor(0, 3); sp.setStretchFactor(1, 2)
        lay.addWidget(sp, 1)
        lay.addWidget(QLabel("Équipements retirés de la supervision (non rajoutés par la découverte)"))
        self.removed = _table(["Équipement", "Adresse", "Retiré par", "Date"], 3); self.removed.setMaximumHeight(110); lay.addWidget(self.removed)
        b = _btn("Rétablir l'équipement sélectionné", "#2ECC71"); b.clicked.connect(self._restore); lay.addWidget(b, 0, Qt.AlignmentFlag.AlignLeft)
        self._timer = QTimer(self); self._timer.setInterval(10000)
        self._timer.timeout.connect(lambda: self.isVisible() and self.refresh())
        self._timer.start()
        self.refresh()

    # ───────── utilitaires ─────────
    def _do(self, fn, ok=None):
        try:
            r = fn()
        except AccessRefused as e:
            QMessageBox.warning(self, "Refusé", str(e)); return None
        except Exception as e:                                   # SSH indisponible, hôte inconnu…
            QMessageBox.warning(self, "Opération en erreur", str(e)); return None
        if ok:
            QMessageBox.information(self, "Résultat", ok(r) if callable(ok) else ok)
        self.refresh()
        return r

    def _set_cap(self):
        cur = float(self.db.get_setting("bw_link_mbps", "100") or 100)
        v, ok = QInputDialog.getDouble(self, "Capacité du lien", "Débit maximal du lien Internet / Wi-Fi (Mb/s) :", cur, 1, 100000, 0)
        if ok:
            self.db.set_setting("bw_link_mbps", str(v)); self.refresh()

    # ───────── affichage ─────────
    def refresh(self):
        gws = self.bw.gateways()
        cap = float(self.db.get_setting("bw_link_mbps", "100") or 100)
        self._gw_title.setText(f"Routeur / Wi-Fi — utilisation du lien (capacité configurée : {cap:g} Mb/s)")
        self.gw_bars.set_rows([dict(g, name=g["name"], exact=g["source"] in ("snmp", "agent", "local")) for g in gws] if gws else [],
                              gws[0]["capacity_bps"] if gws else 0.0)
        cur = self.bw.current()
        self.dev_bars.set_rows(cur[:30], current=self.ip)
        _fill(self.removed, [(r["name"] or "", r["ip"], r["removed_by"] or "", r["removed_at"] or "") for r in self.access.removed()])
        if self.ip:
            self._fill_detail()

    def select(self, ip: str):
        self.ip = ip
        self.dev_bars.current = ip
        self.dev_bars.update()
        self._fill_detail()

    def _fill_detail(self):
        if not self.ip:
            return
        d = self.bw.detail(self.ip)
        h, c = d["host"], d["current"]
        lines = [f"<b>{html.escape(h.get('name') or self.ip)}</b> — {html.escape(self.ip)}"]
        if h.get("mac_address"):
            lines.append(f"MAC {html.escape(h['mac_address'])} {html.escape(h.get('vendor') or '')}")
        if d["role"]:
            lines.append(f"Rôle : {html.escape(d['role'])}")
        if d["port"]:
            lines.append(f"Branché sur : {html.escape(str(d['port']['switch']))} port {html.escape(str(d['port']['port']))}")
        lines.append(f"Débit : ↓ {fmt_bps(c['rx_bps'])}  ↑ {fmt_bps(c['tx_bps'])} ({'exact' if c['exact'] else 'estimé'}, source {c['source']})"
                     if c else "Aucune mesure récente pour cet équipement.")
        if d["blocked"]:
            lines.append(f"<span style='color:#E74C3C'><b>CONNEXION BLOQUÉE</b> depuis {html.escape(d['blocked']['created_at'])} "
                         f"par {html.escape(d['blocked']['by_user'] or '')}</span>")
        self.info.setText("<br>".join(lines))
        self.line.set_series(d["series_1h"] if self.span.currentIndex() == 0 else d["series_24h"])
        _fill(self.peers, [(p["peer"], p["b"], p["sent"]) for p in d["peers"]])
        self.b_unb.setEnabled(bool(d["blocked"])); self._blk = d["blocked"]

    # ───────── actions ─────────
    def _need_ip(self) -> bool:
        if not self.ip:
            QMessageBox.information(self, "Équipement", "Sélectionnez d'abord un équipement dans le diagramme.")
            return False
        return True

    def _block(self, simulate: bool):
        if not self._need_ip():
            return
        if not simulate:
            if QMessageBox.question(self, "Bloquer la connexion",
                                    f"Couper {self.ip} du réseau via la passerelle Linux ?\nL'appareil perdra son accès. "
                                    f"Vous pourrez lever le blocage.") != QMessageBox.StandardButton.Yes:
                return
        reason, _ = ("", True) if simulate else QInputDialog.getText(self, "Motif", "Motif du blocage (journalisé) :")
        r = self._do(lambda: self.access.block(self.ip, reason, simulate=simulate))
        if r:
            QMessageBox.information(self, "Simulation" if simulate else "Blocage",
                                    f"Statut : {r['status']}\nSur : {r['where']}\n\n{r['command']}\n\nAnnulation : {r['rollback']}")
            if r["status"] == "failed":
                QMessageBox.warning(self, "Échec", r.get("output", ""))
            self._fill_detail()

    def _unblock(self):
        if not self._need_ip() or not getattr(self, "_blk", None):
            return
        self._do(lambda: self.access.unblock(self._blk["id"]), lambda r: f"Statut : {r['status']}")

    def _remove(self):
        if not self._need_ip():
            return
        if QMessageBox.question(self, "Retirer de la supervision",
                                f"Retirer {self.ip} de la supervision ?\nIl ne sera plus rajouté par la découverte (rétablissable). "
                                f"Cela ne coupe pas sa connexion.") != QMessageBox.StandardButton.Yes:
            return
        reason, _ = QInputDialog.getText(self, "Motif", "Motif (journalisé) :")
        if self._do(lambda: self.access.remove(self.ip, reason), "Équipement retiré de la supervision.") is not None:
            self.ip = ""; self.info.setText("Sélectionnez un équipement."); self.line.set_series([])

    def _manual(self):
        if self._need_ip():
            QMessageBox.information(self, "Plan manuel", self.access.manual_plan(self.ip))

    def _restore(self):
        row = self.removed.currentRow()
        it = self.removed.item(row, 1) if row >= 0 else None
        if not it:
            QMessageBox.information(self, "Rétablir", "Sélectionnez une ligne dans la liste des équipements retirés."); return
        self._do(lambda: self.access.restore(it.text()), "Rétabli : la prochaine découverte le rajoutera.")
