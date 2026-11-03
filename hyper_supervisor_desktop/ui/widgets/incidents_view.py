"""
HSR — Vue Incidents (pipeline d'automatisation)
Procus Tech

  • liste des incidents corrélés, triés par priorité ;
  • fiche d'investigation : équipement, chronologie des preuves, ports (référence vs actuel), écart de configuration ;
  • actions proposées par HSR : AUCUNE n'est exécutée sans validation humaine (Approuver / Rejeter, tracé dans l'audit).
"""
import html
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget, QTableWidgetItem, QPushButton,
    QHeaderView, QAbstractItemView, QSplitter, QTextBrowser, QMessageBox, QFrame,
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor

from core.automation import AutomationEngine
from ui.styles import COLOR, SEVERITY_COLORS, alpha
from ui.icons import icon_button

ACTION_LABELS = {
    "isolate_host": "Isoler un équipement", "block_ip": "Bloquer une adresse / un port",
    "modify_config": "Modifier une configuration", "apply_patch": "Appliquer un correctif",
}
STATUS_LABELS = {"open": "Ouvert", "acknowledged": "Pris en charge", "closed": "Clos"}
PRIO_COLORS = {"P1": "#E74C3C", "P2": "#E67E22", "P3": "#F1C40F", "P4": "#3498DB"}


def _btn(text: str, color: str) -> QPushButton:
    b = QPushButton(text)
    b.setStyleSheet(f"QPushButton{{background:{alpha(color,'22')};color:{color};border:1px solid {alpha(color,'66')};"
                    f"border-radius:4px;padding:5px 12px;font-weight:600;}}"
                    f"QPushButton:hover{{background:{color};color:#0b0b0a;}}"
                    f"QPushButton:disabled{{color:{COLOR['text_sec']};border-color:{COLOR['border']};background:transparent;}}")
    return b


class IncidentsView(QWidget):
    run_requested = pyqtSignal()                  # → AutomationWorker.run_pipeline (thread dédié)

    def __init__(self, db=None, security=None, parent=None):
        super().__init__(parent)
        self.db, self.security = db, security
        self.engine = AutomationEngine(db, security)
        self._build_ui()
        self.refresh()

    # ── UI ─────────────────────────────────────────────────────────
    def _build_ui(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 20, 24, 20)
        lay.setSpacing(12)

        hdr = QHBoxLayout()
        t = QLabel("Incidents & automatisation")
        t.setStyleSheet(f"font-size:14pt;font-weight:700;color:{COLOR['text_pri']};")
        hdr.addWidget(t)
        hdr.addStretch()
        self._btn_run = _btn("Analyser maintenant", COLOR["accent"])
        self._btn_run.clicked.connect(self._on_run)
        self._btn_report = _btn("Générer le rapport", "#3498DB")
        self._btn_report.clicked.connect(self._on_report)
        b_ref = icon_button("act_refresh", "Actualiser")
        b_ref.clicked.connect(self.refresh)
        for b in (self._btn_run, self._btn_report, b_ref):
            hdr.addWidget(b)
        lay.addLayout(hdr)

        self._lbl_stats = QLabel("")
        self._lbl_stats.setStyleSheet(f"color:{COLOR['text_sec']};font-size:9pt;")
        lay.addWidget(self._lbl_stats)

        split = QSplitter(Qt.Orientation.Vertical)
        lay.addWidget(split, 1)

        cols = ["Priorité", "Sévérité", "Équipement", "Incident", "Événements", "Statut", "Ouvert"]
        self._table = QTableWidget(0, len(cols))
        self._table.setHorizontalHeaderLabels(cols)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self._table.verticalHeader().setVisible(False)
        self._table.setAlternatingRowColors(True)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        for i, w in enumerate((110, 95, 150, 0, 90, 110, 140)):
            if w:
                self._table.setColumnWidth(i, w)
        self._table.itemSelectionChanged.connect(self._on_select)
        split.addWidget(self._table)

        lower = QWidget()
        ll = QHBoxLayout(lower)
        ll.setContentsMargins(0, 0, 0, 0)
        ll.setSpacing(12)
        self._sheet = QTextBrowser()
        self._sheet.setOpenLinks(False)
        self._sheet.setStyleSheet(f"background:{COLOR['bg_card']};color:{COLOR['text_pri']};"
                                  f"border:1px solid {COLOR['border']};border-radius:6px;padding:8px;")
        self._sheet.setHtml(self._placeholder("Sélectionnez un incident pour ouvrir sa fiche d'investigation."))
        ll.addWidget(self._sheet, 3)

        right = QVBoxLayout()
        right.setSpacing(8)
        lab = QLabel("Validation humaine")
        lab.setStyleSheet(f"font-weight:700;color:{COLOR['text_pri']};")
        right.addWidget(lab)
        note = QLabel("HSR propose, vous décidez. Approuver ne lance rien. L'exécution est une étape distincte : "
                      "« Simuler » montre la commande exacte ; « Exécuter » n'agit que si l'exécution réelle est activée "
                      "(Défense active) et reste annulable. Les autres actions restent manuelles.")
        note.setWordWrap(True)
        note.setStyleSheet(f"color:{COLOR['text_sec']};font-size:8pt;")
        right.addWidget(note)
        self._actions = QTableWidget(0, 3)
        self._actions.setHorizontalHeaderLabels(["Action", "Cible", "État"])
        self._actions.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._actions.verticalHeader().setVisible(False)
        self._actions.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._actions.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._actions.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._actions.itemSelectionChanged.connect(self._update_buttons)
        right.addWidget(self._actions, 1)
        row = QHBoxLayout()
        self._b_ok = _btn("Approuver", "#2ECC71")
        self._b_no = _btn("Rejeter", "#E74C3C")
        self._b_ok.clicked.connect(lambda: self._decide(True))
        self._b_no.clicked.connect(lambda: self._decide(False))
        row.addWidget(self._b_ok)
        row.addWidget(self._b_no)
        right.addLayout(row)
        row2 = QHBoxLayout()
        self._b_sim = _btn("Simuler", "#3498DB")
        self._b_exec = _btn("Exécuter", "#E67E22")
        self._b_undo = _btn("Annuler l'exécution", "#c4bfae")
        self._b_sim.clicked.connect(lambda: self._run_action(True))
        self._b_exec.clicked.connect(lambda: self._run_action(False))
        self._b_undo.clicked.connect(self._undo_action)
        for b in (self._b_sim, self._b_exec, self._b_undo):
            row2.addWidget(b)
        right.addLayout(row2)
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet(f"color:{COLOR['border']};")
        right.addWidget(sep)
        self._b_device = _btn("Ajouter l'équipement au référentiel", "#F39C12")
        self._b_device.clicked.connect(self._approve_device)
        self._b_ack = _btn("Prendre en charge", "#3498DB")
        self._b_ack.clicked.connect(lambda: self._set_status(False))
        self._b_close = _btn("Clôturer l'incident", "#c4bfae")
        self._b_close.clicked.connect(lambda: self._set_status(True))
        for b in (self._b_device, self._b_ack, self._b_close):
            right.addWidget(b)
        rw = QWidget()
        rw.setLayout(right)
        rw.setMaximumWidth(420)
        ll.addWidget(rw, 2)
        split.addWidget(lower)
        split.setSizes([260, 340])
        self._update_buttons()

    @staticmethod
    def _placeholder(text: str) -> str:
        return f"<p style='color:{COLOR['text_sec']};'>{html.escape(text)}</p>"

    # ── données ────────────────────────────────────────────────────
    def refresh(self):
        if not self.db:
            return
        sel = self._selected_id()
        rows = self.db.fetchall("SELECT * FROM incidents ORDER BY (status='closed'), priority DESC, id DESC LIMIT 300")
        self._table.setRowCount(len(rows))
        for r, i in enumerate(rows):
            code = (i.get("priority_label") or "P4")[:2]
            vals = [i.get("priority_label") or "", i["severity"], i.get("host_name") or "—", i["title"],
                    str(i["event_count"]), STATUS_LABELS.get(i["status"], i["status"]), (i["opened_at"] or "")[:16]]
            for c, v in enumerate(vals):
                it = QTableWidgetItem(v)
                if c == 0:
                    it.setForeground(QColor(PRIO_COLORS.get(code, "#c4bfae")))
                    it.setData(Qt.ItemDataRole.UserRole, i["id"])
                if c == 1:
                    it.setForeground(QColor(SEVERITY_COLORS.get(i["severity"], "#c4bfae")))
                if i["status"] == "closed":
                    it.setForeground(QColor(COLOR["text_sec"]))
                self._table.setItem(r, c, it)
        if sel:
            for r in range(self._table.rowCount()):
                if self._table.item(r, 0).data(Qt.ItemDataRole.UserRole) == sel:
                    self._table.selectRow(r)
                    break
        open_n = sum(1 for i in rows if i["status"] != "closed")
        pend = len(self.engine.pending_actions())
        ref = self.engine.reference_status()
        self._lbl_stats.setText(
            f"{open_n} incident(s) actif(s)  ·  {pend} action(s) en attente de validation  ·  "
            f"{len(ref['unapproved'])} équipement(s) hors référentiel  ·  "
            f"dernier rapport : {self.db.get_setting('auto_report_last', 'jamais')[:16].replace('T', ' ') or 'jamais'}")
        self._load_actions()
        self._update_buttons()

    def _selected_id(self):
        r = self._table.currentRow()
        if r < 0 or not self._table.item(r, 0):
            return None
        return self._table.item(r, 0).data(Qt.ItemDataRole.UserRole)

    def _on_select(self):
        iid = self._selected_id()
        self._sheet.setHtml(self._render_sheet(iid) if iid else self._placeholder("Aucun incident sélectionné."))
        self._load_actions()
        self._update_buttons()

    def _render_sheet(self, iid: int) -> str:
        s = self.engine.investigation_sheet(iid)
        if not s:
            return self._placeholder("Incident introuvable.")
        inc, host = s["incident"], s["host"]
        e = html.escape
        h = [f"<h3 style='color:{COLOR['accent']};margin:0'>{e(inc['title'])}</h3>",
             f"<p><b>{e(inc.get('priority_label') or '')}</b> (score {inc['priority']}/100) · sévérité "
             f"<b style='color:{SEVERITY_COLORS.get(inc['severity'], '#c4bfae')}'>{e(inc['severity'])}</b> · "
             f"{inc['event_count']} événement(s) · statut {e(STATUS_LABELS.get(inc['status'], inc['status']))}</p>"]
        if host:
            appr = "oui" if host.get("approved", 1) else "<b style='color:#E74C3C'>NON — équipement inconnu</b>"
            h.append("<h4>Équipement</h4><table cellpadding=2>" + "".join(
                f"<tr><td style='color:{COLOR['text_sec']}'>{k}</td><td>{e(str(v) if v not in (None, '') else '—')}</td></tr>"
                if k != "Dans le référentiel" else f"<tr><td style='color:{COLOR['text_sec']}'>{k}</td><td>{v}</td></tr>"
                for k, v in [("Nom", host["name"]), ("Adresse IP", host["ip_address"]),
                             ("MAC", host.get("mac_address")), ("Fabricant", host.get("vendor")),
                             ("Type", host.get("device_type")), ("Criticité (1-5)", host.get("criticality")),
                             ("Statut", host.get("status")), ("Dans le référentiel", appr)]) + "</table>")
        h.append("<h4>Chronologie (preuves d'origine, non modifiées)</h4><table cellpadding=3 width='100%'>")
        for ev in s["events"]:
            h.append(f"<tr><td style='color:{COLOR['text_sec']}' nowrap>#{ev['id']} {e(ev['occurred_at'][:19])}</td>"
                     f"<td style='color:{SEVERITY_COLORS.get(ev['severity'], '#c4bfae')}' nowrap>{e(ev['severity'])}</td>"
                     f"<td>{e(ev['description'])}</td></tr>")
        h.append("</table>")
        if s["ports"]:
            diffp = [p for p in s["ports"] if p["current"] and p["current"] != p["baseline"]]
            h.append(f"<h4>Ports : référence ↔ dernier scan</h4><p>{len(s['ports'])} port(s) en référence, "
                     f"{len(diffp)} écart(s)" + (" : " + ", ".join(f"{p['port']}/{str(p.get('protocol') or 'TCP').lower()} ({p['baseline']}→{p['current']})"
                                                                  for p in diffp) if diffp else "") + "</p>")
        if s["config_diff"]:
            h.append("<h4>Écart de configuration (dernier instantané)</h4><ul>" +
                     "".join(f"<li>{e(d)}</li>" for d in s["config_diff"]) + "</ul>")
        return "".join(h)

    def _load_actions(self):
        iid = self._selected_id()
        rows = (self.db.fetchall("SELECT * FROM pending_actions WHERE incident_id = ? ORDER BY id DESC", (iid,))
                if iid else self.engine.pending_actions())
        self._actions.setRowCount(len(rows))
        st = {"pending": "À valider", "approved": "Approuvée", "rejected": "Rejetée"}
        for r, a in enumerate(rows):
            for c, v in enumerate([ACTION_LABELS.get(a["action_type"], a["action_type"]), a.get("target") or a.get("host_name") or "",
                                   st.get(a["status"], a["status"])]):
                it = QTableWidgetItem(v)
                if c == 0:
                    it.setData(Qt.ItemDataRole.UserRole, a["id"])
                    it.setToolTip(f"{a.get('reason') or ''}\n\n{a.get('plan') or ''}")
                self._actions.setItem(r, c, it)

    def _selected_action(self):
        r = self._actions.currentRow()
        if r < 0 or not self._actions.item(r, 0):
            return None
        return self.db.fetchone("SELECT * FROM pending_actions WHERE id = ?", (self._actions.item(r, 0).data(Qt.ItemDataRole.UserRole),))

    def _update_buttons(self):
        can_cfg = self._allowed("can_manage_config")
        can_ack = self._allowed("can_acknowledge")
        has_inc = self._selected_id() is not None
        self._b_ok.setEnabled(can_cfg)
        self._b_no.setEnabled(can_cfg)
        a = self._selected_action()
        ok = bool(a) and a["status"] == "approved" and can_cfg
        self._b_sim.setEnabled(ok)
        self._b_exec.setEnabled(ok)
        self._b_undo.setEnabled(bool(a) and can_cfg and self._last_run(a) is not None)
        self._b_device.setEnabled(can_cfg and has_inc)
        self._b_ack.setEnabled(can_ack and has_inc)
        self._b_close.setEnabled(can_ack and has_inc)

    def _allowed(self, perm: str) -> bool:
        try:
            return True if not self.security else bool(self.security.has_permission(perm))
        except Exception:
            return False

    # ── actions utilisateur ───────────────────────────────────────
    def _on_run(self):
        self._btn_run.setEnabled(False)
        self._btn_run.setText("Analyse en cours…")
        self.run_requested.emit()

    def on_pipeline_done(self, _result: dict = None):
        self._btn_run.setEnabled(True)
        self._btn_run.setText("Analyser maintenant")
        self.refresh()

    def _on_report(self):
        try:
            res = self.engine.generate_report(24)
            QMessageBox.information(self, "Rapport généré",
                                    "Rapport construit à partir des données stockées :\n\n" +
                                    "\n".join(res["paths"].values()))
            self.refresh()
        except Exception as e:
            QMessageBox.warning(self, "Rapport", f"Échec de la génération : {e}")

    def _decide(self, approve: bool):
        a = self._selected_action()
        if not a or a["status"] != "pending":
            QMessageBox.information(self, "Validation", "Sélectionnez une action « À valider ».")
            return
        verb = "APPROUVER" if approve else "REJETER"
        ok = QMessageBox.question(
            self, "Validation humaine",
            f"{verb} l'action « {ACTION_LABELS.get(a['action_type'], a['action_type'])} » sur {a.get('target') or a['host_name']} ?\n\n"
            f"Motif : {a.get('reason')}\n\nHSR n'exécutera rien automatiquement ; la décision est enregistrée dans le journal d'audit.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
        if ok != QMessageBox.StandardButton.Yes:
            return
        res = self.engine.decide_action(a["id"], approve)
        if res and approve:
            QMessageBox.information(self, "Plan à appliquer", f"Plan exact à appliquer manuellement :\n\n{a.get('plan')}")
        self.refresh()

    # ── exécution réelle (étape distincte de l'approbation) ───────
    def _runner(self):
        from core.action_runner import ActionRunner
        if not hasattr(self, "_action_runner"):
            from core.defense_common import EventSink
            self._action_runner = ActionRunner(self.db, self.security, EventSink(self.db))
        return self._action_runner

    def _last_run(self, a):
        if not a:
            return None
        return self.db.fetchone("SELECT * FROM action_runs WHERE action_id = ? AND status = 'ok' ORDER BY id DESC LIMIT 1", (a["id"],))

    def _run_action(self, simulate: bool):
        from core.action_runner import ActionRefused
        a = self._selected_action()
        if not a or a["status"] != "approved":
            return
        runner = self._runner()
        try:
            plan = runner.build_plan(a)
        except ActionRefused as e:
            QMessageBox.information(self, "Action non exécutable", str(e)); return
        if not simulate:
            if not runner.enabled():
                QMessageBox.information(self, "Exécution désactivée",
                                        "L'exécution réelle est désactivée (Défense active → Vue d'ensemble). Utilisez « Simuler ».")
                return
            if QMessageBox.question(self, "Exécuter réellement",
                                    f"Commande exacte :\n\n{plan['display']}\n\nExécuter maintenant ?",
                                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                    QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
                return
        try:
            res = runner.execute(a["id"], simulate=simulate)
        except ActionRefused as e:
            QMessageBox.warning(self, "Refusé", str(e)); self.refresh(); return
        except Exception as e:
            QMessageBox.warning(self, "Échec", str(e)); self.refresh(); return
        QMessageBox.information(self, "Simulation" if simulate else "Exécution",
                                f"Résultat : {res.get('status')}\nCible : {res.get('where')}\n\n{(res.get('output') or '')[:600]}")
        self.refresh()

    def _undo_action(self):
        from core.action_runner import ActionRefused
        run = self._last_run(self._selected_action())
        if not run:
            return
        try:
            self._runner().rollback(run["id"])
            QMessageBox.information(self, "Annulation", "L'exécution a été annulée.")
        except (ActionRefused, Exception) as e:
            QMessageBox.warning(self, "Annulation impossible", str(e))
        self.refresh()

    def _approve_device(self):
        iid = self._selected_id()
        inc = self.db.fetchone("SELECT host_id, host_name FROM incidents WHERE id = ?", (iid,)) if iid else None
        if inc and inc["host_id"] and QMessageBox.question(
                self, "Référentiel", f"Ajouter « {inc['host_name']} » à la liste des équipements attendus ?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes:
            self.engine.approve_device(inc["host_id"])
            self.refresh()
            self._on_select()

    def _set_status(self, close: bool):
        iid = self._selected_id()
        if iid:
            self.engine.close_incident(iid, acknowledge_only=not close)
            self.refresh()
