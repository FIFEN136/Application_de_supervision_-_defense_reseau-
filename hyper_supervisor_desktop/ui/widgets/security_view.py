"""
Procus Secure — vue « Sécurité réseau » (v15) : Visibilité · Évaluation · Politique de filtrage.
Tout est en LECTURE et SIMULATION : aucune règle n'est appliquée sur un équipement depuis cet écran.
"""
import html

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidgetItem, QPushButton, QTabWidget, QMessageBox, QComboBox,
    QDialog, QFormLayout, QLineEdit, QSpinBox, QDialogButtonBox, QInputDialog, QFileDialog, QTextBrowser, QCheckBox,
    QSplitter, QPlainTextEdit,
)

from core import assess, classify, policy
from core.policy import PolicyError
from ui.styles import COLOR
from ui.widgets.defense_view import _Job, _table, _fill, _note
from ui.widgets.incidents_view import _btn

SEV_FR = {"critical": "Critique", "high": "Élevée", "medium": "Moyenne", "low": "Faible"}
SEV_COL = {"critical": "#E74C3C", "high": "#E67E22", "medium": "#F1C40F", "low": "#3498DB"}
STATUS_FR = {"open": "À traiter", "accepted": "Risque accepté", "fixed": "Corrigé"}
RULE_STATUS_FR = {"draft": "Brouillon", "approved": "Approuvée", "retired": "Retirée"}


class SecurityView(QWidget):
    def __init__(self, db=None, security=None, manager=None, parent=None):
        super().__init__(parent)
        self.db, self.security, self.mgr = db, security, manager
        self.pm = manager.policy if manager else policy.PolicyManager(db, security)
        self._jobs = []
        lay = QVBoxLayout(self)
        t = QLabel("Sécurité réseau")
        t.setStyleSheet(f"font-size:15pt;font-weight:700;color:{COLOR['text_pri']};")
        lay.addWidget(t)
        lay.addWidget(_note("Visibilité, évaluation et règles de filtrage. Rien n'est appliqué sur vos équipements depuis cet écran : "
                            "les règles se rédigent, se valident et se simulent sur le trafic observé."))
        self.tabs = QTabWidget()
        lay.addWidget(self.tabs, 1)
        self._build_visibility()
        self._build_assessment()
        self._build_policy()
        self._build_bandwidth()
        self.refresh()

    # ───────── utilitaires ─────────
    def _allowed(self, perm="can_manage_config") -> bool:
        try:
            return True if not self.security else bool(self.security.has_permission(perm))
        except Exception:
            return False

    def _need_admin(self) -> bool:
        if not self._allowed():
            QMessageBox.warning(self, "Droits insuffisants", "Cette opération demande le droit « can_manage_config ».")
            return False
        return True

    def _user(self) -> str:
        try:
            return (self.security.get_current_user() or {}).get("login") or "système"
        except Exception:
            return "système"

    def _run(self, fn, then):
        job = _Job(fn, self)
        self._jobs.append(job)

        def fin(res, err):
            if job in self._jobs:
                self._jobs.remove(job)
            if err:
                QMessageBox.warning(self, "Opération en erreur", err)
            else:
                then(res)
            self.refresh()
        job.done.connect(fin)
        job.start()

    def _do(self, fn, ok_msg=None):
        """Appelle une opération de politique ; affiche proprement le refus."""
        try:
            res = fn()
        except PolicyError as e:
            QMessageBox.warning(self, "Refusé", str(e)); return None
        except ValueError as e:
            QMessageBox.warning(self, "Refusé", str(e)); return None
        if ok_msg:
            QMessageBox.information(self, "Politique", ok_msg)
        self.refresh()
        return res if res is not None else True

    # ───────── Visibilité ─────────
    def _build_visibility(self):
        w = QWidget(); l = QVBoxLayout(w)
        row = QHBoxLayout()
        b1 = _btn("Classer les équipements", "#3498DB"); b2 = _btn("Relever voisins, routes et tables MAC (SNMP)", "#3498DB")
        b3 = _btn("Ajouter / modifier une zone", "#2ECC71"); b4 = _btn("Changer le rôle…", "#F39C12")
        b1.clicked.connect(self._classify); b2.clicked.connect(self._netmap); b3.clicked.connect(self._zone_dialog); b4.clicked.connect(self._role_dialog)
        for b in (b1, b2, b3, b4): row.addWidget(b)
        row.addStretch(); l.addLayout(row)
        self._vis_info = QLabel(""); self._vis_info.setStyleSheet(f"color:{COLOR['text_sec']};"); l.addWidget(self._vis_info)
        sp = QSplitter(Qt.Orientation.Vertical)
        top = QWidget(); tl = QHBoxLayout(top)
        zbox = QWidget(); zl = QVBoxLayout(zbox); zl.addWidget(QLabel("Zones (confiance 0 = hostile … 100 = très sûre)"))
        self._zones = _table(["Zone", "Réseau", "Confiance", "Type"], 3); zl.addWidget(self._zones)
        rbox = QWidget(); rl = QVBoxLayout(rbox); rl.addWidget(QLabel("Équipements et rôles"))
        self._roles = _table(["Équipement", "Adresse", "Rôle", "Origine", "Zone"], 4); rl.addWidget(self._roles)
        tl.addWidget(zbox, 2); tl.addWidget(rbox, 3); sp.addWidget(top)
        bot = QWidget(); bl = QHBoxLayout(bot)
        fbox = QWidget(); fl = QVBoxLayout(fbox); fl.addWidget(QLabel("Qui parle à qui (flux agrégés, les plus gros d'abord)"))
        self._flows = _table(["Source", "Destination", "Proto", "Port", "Flux", "Octets"], 5); fl.addWidget(self._flows)
        ebox = QWidget(); el = QVBoxLayout(ebox); el.addWidget(QLabel("Où appliquer les règles (équipement qui relie chaque réseau)"))
        self._enf = _table(["Réseau", "Passerelle", "Équipement", "Peut filtrer"], 3); el.addWidget(self._enf)
        el.addWidget(QLabel("Voisins LLDP"))
        self._links = _table(["Équipement", "Port local", "Voisin", "Port voisin"], 3); el.addWidget(self._links)
        bl.addWidget(fbox, 3); bl.addWidget(ebox, 2); sp.addWidget(bot)
        l.addWidget(sp, 1)
        self.tabs.addTab(w, "Visibilité")

    def _build_bandwidth(self):
        if not self.mgr:
            return
        from ui.widgets.bandwidth_view import BandwidthTab
        self.bwtab = BandwidthTab(self.db, self.security, self.mgr)
        self.tabs.addTab(self.bwtab, "Débits")

    def _classify(self):
        def go():
            n = classify.sync_zones(self.db); r = classify.classify_hosts(self.db); r["zones_created"] = n; return r
        self._run(go, lambda r: QMessageBox.information(
            self, "Classification", f"{r['classified']} équipement(s) classé(s), {r['kept_manual']} rôle(s) manuel(s) conservé(s), {r['zones_created']} zone(s) créée(s)."))

    def _netmap(self):
        if not self.mgr:
            return
        self._run(lambda: self.mgr.netmap.collect_all(), lambda r: QMessageBox.information(
            self, "Relevé SNMP", f"{r['hosts']} équipement(s) interrogé(s) : {r['links']} voisin(s), {r['routes']} route(s), {r['fdb']} adresse(s) MAC."
            if r["hosts"] else "Aucun équipement réseau n'a répondu (SNMP activé ? communauté correcte ?)."))

    def _zone_dialog(self):
        if not self._need_admin(): return
        d = QDialog(self); d.setWindowTitle("Zone réseau"); f = QFormLayout(d)
        name = QLineEdit(); cidr = QLineEdit(); cidr.setPlaceholderText("192.168.50.0/24")
        trust = QSpinBox(); trust.setRange(0, 100); trust.setValue(50)
        for lab, wd in (("Nom", name), ("Réseau", cidr), ("Confiance (0-100)", trust)): f.addRow(lab, wd)
        msg = QLabel(""); msg.setStyleSheet("color:#E74C3C;"); f.addRow(msg)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel); f.addRow(bb); bb.rejected.connect(d.reject)

        def ok():
            try:
                classify.set_zone(self.db, name.text(), cidr.text(), trust.value(), who=self._user()); d.accept()
            except ValueError as e:
                msg.setText(str(e))
        bb.accepted.connect(ok)
        if d.exec(): self.refresh()

    def _role_dialog(self):
        r = self._roles.currentRow()
        if r < 0 or not self._need_admin(): return
        hid = int(self._roles.item(r, 0).data(Qt.ItemDataRole.UserRole))
        labels = list(classify.ROLES.values()); keys = list(classify.ROLES)
        lab, ok = QInputDialog.getItem(self, "Rôle", "Rôle de l'équipement :", labels, keys.index(classify.role_of(self.db, hid)), False)
        if ok:
            self._do(lambda: classify.set_role(self.db, hid, keys[labels.index(lab)], self._user()))

    # ───────── Évaluation ─────────
    def _build_assessment(self):
        w = QWidget(); l = QVBoxLayout(w)
        l.addWidget(_note("Constats déduits des données déjà collectées (ports, bannières, flux). La base de failles est un EXTRAIT local, à compléter "
                          "par import ; une version annoncée par un service peut être corrigée par la distribution : vérifiez avant de conclure."))
        row = QHBoxLayout()
        self._flt = QComboBox(); self._flt.addItems(["À traiter", "Tous", "Risque accepté", "Corrigé"]); self._flt.currentIndexChanged.connect(self._load_findings)
        b1 = _btn("Évaluer maintenant", "#3498DB"); b2 = _btn("Créer la règle recommandée", "#2ECC71"); b3 = _btn("Accepter le risque…", "#F39C12")
        b4 = _btn("Rouvrir", "#c4bfae"); b5 = _btn("Importer des failles (JSON)…", "#c4bfae")
        b1.clicked.connect(self._assess_now); b2.clicked.connect(self._finding_rule); b3.clicked.connect(self._accept); b4.clicked.connect(self._reopen)
        b5.clicked.connect(self._import_cve)
        row.addWidget(self._flt)
        for b in (b1, b2, b3, b4, b5): row.addWidget(b)
        row.addStretch(); l.addLayout(row)
        self._as_sum = QLabel(""); self._as_sum.setStyleSheet(f"color:{COLOR['text_sec']};"); l.addWidget(self._as_sum)
        self._fnd = _table(["Gravité", "Catégorie", "Constat", "Équipement", "État"], 2)
        self._fnd.itemSelectionChanged.connect(self._finding_detail)
        l.addWidget(self._fnd, 2)
        self._fdet = QTextBrowser(); l.addWidget(self._fdet, 1)
        self.tabs.addTab(w, "Évaluation")

    def _sel_finding(self):
        r = self._fnd.currentRow()
        return int(self._fnd.item(r, 0).data(Qt.ItemDataRole.UserRole)) if r >= 0 else None

    def _assess_now(self):
        sink = self.mgr.sink if self.mgr else None
        self._run(lambda: assess.run_assessment(self.db, sink), lambda r: QMessageBox.information(
            self, "Évaluation", f"{r['new']} nouveau(x) constat(s), {r['fixed']} corrigé(s). À traiter : "
            + ", ".join(f"{SEV_FR[k].lower()} {v}" for k, v in r["open"].items() if v) if any(r["open"].values()) else "Aucun constat à traiter."))

    def _finding_rule(self):
        fid = self._sel_finding()
        if fid and self._need_admin():
            if self._do(lambda: self.pm.from_finding(fid)):
                QMessageBox.information(self, "Règle créée", "Brouillon ajouté dans l'onglet Politique : simulez son effet avant de l'approuver.")

    def _accept(self):
        fid = self._sel_finding()
        if not fid or not self._need_admin(): return
        note, ok = QInputDialog.getMultiLineText(self, "Accepter le risque", "Justification (obligatoire, inscrite dans l'audit) :")
        if ok:
            self._do(lambda: assess.set_status(self.db, fid, "accepted", note, self._user()))

    def _reopen(self):
        fid = self._sel_finding()
        if fid and self._need_admin():
            self._do(lambda: assess.set_status(self.db, fid, "open", "", self._user()))

    def _import_cve(self):
        if not self._need_admin(): return
        path, _ = QFileDialog.getOpenFileName(self, "Fichier de failles", "", "JSON (*.json)")
        if path:
            n = self._do(lambda: assess.import_cves(self.db, path, self._user()))
            if n:
                QMessageBox.information(self, "Import", f"{n} faille(s) importée(s).")

    def _load_findings(self):
        st = {0: "open", 1: None, 2: "accepted", 3: "fixed"}[self._flt.currentIndex()]
        rows = assess.list_findings(self.db, st)
        self._fnd.setRowCount(len(rows))
        for r, f in enumerate(rows):
            for c, v in enumerate([SEV_FR.get(f["severity"], f["severity"]), f["category"], f["title"], f.get("host_name") or "—", STATUS_FR.get(f["status"], f["status"])]):
                it = QTableWidgetItem(v)
                if c == 0:
                    it.setData(Qt.ItemDataRole.UserRole, f["id"]); it.setForeground(QColor(SEV_COL.get(f["severity"], "#FFFFFF")))
                self._fnd.setItem(r, c, it)
        op = {s: self.db.fetchone("SELECT COUNT(*) n FROM assess_findings WHERE status='open' AND severity=?", (s,))["n"] for s in SEV_FR}
        self._as_sum.setText("À traiter : " + " · ".join(f"{SEV_FR[s].lower()} {n}" for s, n in op.items()))

    def _finding_detail(self):
        fid = self._sel_finding()
        f = self.db.fetchone("SELECT * FROM assess_findings WHERE id = ?", (fid,)) if fid else None
        if not f:
            self._fdet.setHtml(""); return
        e = html.escape
        self._fdet.setHtml(f"<b>{e(f['title'])}</b><br><br>{e(f['detail'] or '')}<br><br><b>Recommandation :</b> {e(f['recommendation'] or '')}"
                           + (f"<br><br><b>Note :</b> {e(f['note'])}" if f["note"] else "")
                           + f"<br><br><small>Vu pour la première fois le {e(f['first_seen'])} · dernière détection {e(f['last_seen'])}</small>")

    # ───────── Politique ─────────
    def _build_policy(self):
        w = QWidget(); l = QVBoxLayout(w)
        l.addWidget(_note("La première règle qui correspond s'applique. Une règle passe de « brouillon » à « approuvée » après un contrôle anti-blocage : "
                          "la supervision (cette machine → équipements réseau), les agents et les postes d'administration doivent rester joignables."))
        row = QHBoxLayout()
        self._pol_default = QComboBox(); self._pol_default.addItems(["Par défaut : autoriser", "Par défaut : refuser"])
        self._pol_default.activated.connect(self._set_default)
        self._four = QCheckBox("Double validation"); self._four.clicked.connect(self._set_four)
        row.addWidget(self._pol_default); row.addWidget(self._four); row.addStretch(); l.addLayout(row)
        r1 = QHBoxLayout()
        bs = [("Nouvelle règle", "#2ECC71", self._rule_new), ("Modifier", "#3498DB", self._rule_edit), ("Approuver", "#2ECC71", self._rule_approve),
              ("Approuver tous les brouillons", "#2ECC71", self._rule_approve_all), ("Activer / désactiver", "#F39C12", self._rule_toggle),
              ("Retirer", "#E74C3C", self._rule_retire), ("Modèles…", "#c4bfae", self._template), ("Simuler", "#E67E22", self._simulate)]
        for t, c, fn in bs:
            b = _btn(t, c); b.clicked.connect(fn); r1.addWidget(b)
        r1.addStretch(); l.addLayout(r1)
        self._rules = _table(["Prio", "État", "Action", "Source", "Destination", "Service", "Nom"], 6)
        l.addWidget(self._rules, 2)
        self._sim = QTextBrowser(); l.addWidget(self._sim, 2)
        self.tabs.addTab(w, "Politique de filtrage")

    def _set_default(self, i):
        if not self._need_admin():
            self.refresh(); return
        self.db.set_setting("policy_default", "deny" if i == 1 else "allow")
        self.db.write_audit(self._user(), "policy_default_set", "policy", "deny" if i == 1 else "allow")
        issues = policy.lockout_issues(self.db, policy.effective_rows(self.db, False))
        if issues:
            QMessageBox.warning(self, "Attention", "Avec « refuser par défaut », la supervision serait coupée tant qu'aucune autorisation n'est approuvée :\n\n"
                                + issues[0]["message"])
        self.refresh()

    def _set_four(self, checked):
        if self._need_admin():
            self.db.set_setting("policy_four_eyes", "1" if checked else "0")
            self.db.write_audit(self._user(), "policy_four_eyes", "policy", "1" if checked else "0")
        self.refresh()

    def _sel_rule(self):
        r = self._rules.currentRow()
        return int(self._rules.item(r, 0).data(Qt.ItemDataRole.UserRole)) if r >= 0 else None

    def _rule_dialog(self, rule=None):
        d = QDialog(self); d.setWindowTitle("Règle de filtrage"); f = QFormLayout(d)
        name = QLineEdit(rule["name"] if rule else "")
        src = QLineEdit(rule["src"] if rule else "any"); dst = QLineEdit(rule["dst"] if rule else "any")
        svc = QLineEdit(rule["service"] if rule else "any")
        act = QComboBox(); act.addItems(["deny", "allow"]); act.setCurrentText(rule["action"] if rule else "deny")
        pos = QSpinBox(); pos.setRange(1, 9999); pos.setValue(int(rule["position"]) if rule else 100)
        exp = QLineEdit(rule.get("expires_at") or "" if rule else ""); exp.setPlaceholderText("facultatif : AAAA-MM-JJ")
        com = QPlainTextEdit(rule.get("comment") or "" if rule else ""); com.setMaximumHeight(60)
        zones = ", ".join(z["name"] for z in self.db.fetchall("SELECT name FROM net_zones")) or "—"
        f.addRow(_note(f"Source / destination : any · zone:<nom> · role:<rôle> · host:<id> · ip:<réseau>.\nZones : {zones}\n"
                       f"Rôles : {', '.join(classify.ROLES)}\nServices : any · icmp · tcp/445 · udp/53 · tcp/80-443 · ssh, rdp, smb, dns, snmp…"))
        for lab, wd in (("Nom", name), ("Source", src), ("Destination", dst), ("Service", svc), ("Action", act), ("Priorité (1 = d'abord)", pos),
                        ("Expire le", exp), ("Motif", com)):
            f.addRow(lab, wd)
        msg = QLabel(""); msg.setWordWrap(True); msg.setStyleSheet("color:#E74C3C;"); f.addRow(msg)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel); f.addRow(bb); bb.rejected.connect(d.reject)
        out = {}

        def ok():
            data = {"name": name.text(), "src": src.text(), "dst": dst.text(), "service": svc.text(), "action": act.currentText(),
                    "position": pos.value(), "expires_at": exp.text().strip() or None, "comment": com.toPlainText()}
            try:
                if rule:
                    self.pm.update_rule(rule["id"], data)
                else:
                    self.pm.create_rule(data)
                warn = [i["message"] for i in self.pm.validate(data, rule["id"] if rule else None, include_drafts=True) if i["level"] == "warning"]
                out["warn"] = warn
                d.accept()
            except PolicyError as e:
                msg.setText(str(e))
        bb.accepted.connect(ok)
        if d.exec():
            if out.get("warn"):
                QMessageBox.information(self, "À noter", "\n".join(out["warn"]))
            self.refresh()

    def _rule_new(self):
        if self._need_admin(): self._rule_dialog()

    def _rule_edit(self):
        rid = self._sel_rule()
        if rid and self._need_admin():
            self._rule_dialog(self.db.fetchone("SELECT * FROM policy_rules WHERE id = ?", (rid,)))

    def _rule_approve(self):
        rid = self._sel_rule()
        if rid and self._need_admin():
            self._do(lambda: self.pm.approve_rule(rid), "Règle approuvée. Elle est « en vigueur » dans la politique ; aucun équipement n'a été modifié.")

    def _rule_approve_all(self):
        if not self._need_admin(): return
        ids = [r["id"] for r in self.pm.rules() if r["status"] == "draft"]
        if not ids:
            QMessageBox.information(self, "Politique", "Aucun brouillon à approuver."); return
        if QMessageBox.question(self, "Approuver", f"Approuver {len(ids)} brouillon(s) dans l'ordre de priorité ?",
                                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes:
            self._do(lambda: self.pm.approve_many(ids))

    def _rule_toggle(self):
        rid = self._sel_rule()
        if rid and self._need_admin():
            r = self.db.fetchone("SELECT enabled FROM policy_rules WHERE id = ?", (rid,))
            self._do(lambda: self.pm.set_enabled(rid, not r["enabled"]))

    def _rule_retire(self):
        rid = self._sel_rule()
        if rid and self._need_admin():
            self._do(lambda: self.pm.retire_rule(rid))

    def _template(self):
        if not self._need_admin(): return
        titles = [f"{t['title']}" for t in policy.TEMPLATES.values()]
        lab, ok = QInputDialog.getItem(self, "Modèles de règles", "Créer en brouillon :", titles, 0, False)
        if ok:
            name = list(policy.TEMPLATES)[titles.index(lab)]
            ids = self._do(lambda: self.pm.apply_template(name))
            if ids:
                QMessageBox.information(self, "Modèle", f"{len(ids)} règle(s) créée(s) en brouillon. Simulez, puis « Approuver tous les brouillons ».")

    def _simulate(self):
        self._run(lambda: self.pm.simulate(include_drafts=True), self._show_sim)

    def _show_sim(self, s):
        e = html.escape
        h = [f"<h3>Simulation sur {s['flows_total']} flux observés</h3>",
             f"<p>Règles prises en compte : {s['rules']} (brouillons compris) · action par défaut : <b>{'refuser' if s['default'] == 'deny' else 'autoriser'}</b></p>",
             f"<p>Autorisés : <b>{s['allowed_flows']}</b> · Refusés : <b>{s['denied_flows']}</b> ({s['denied_pct']} %)</p>"]
        if s["lockout"]:
            h.append("<p style='color:#E74C3C'><b>Risque de coupure :</b><br>" + "<br>".join(e(i["message"]) for i in s["lockout"]) + "</p>")
        else:
            h.append("<p style='color:#2ECC71'>Les chemins critiques (supervision, agents, administration) restent ouverts.</p>")
        if s["per_rule"]:
            h.append("<b>Utilisation des règles</b><ul>" + "".join(f"<li>{e(r['name'])} ({r['action']}) : {r['flows']} flux</li>" for r in s["per_rule"]) + "</ul>")
        if s["denied_top"]:
            h.append("<b>Principaux flux refusés</b><ul>" + "".join(
                f"<li>{e(d['src_name'])} → {e(d['dst_name'])} {d['proto']}/{d['port']} : {d['flows']} flux (règle « {e(d['rule'])} »)</li>" for d in s["denied_top"]) + "</ul>")
        if s["warnings"]:
            h.append("<b>À vérifier</b><ul>" + "".join(f"<li>{e(w)}</li>" for w in s["warnings"]) + "</ul>")
        self._sim.setHtml("".join(h))

    # ───────── rafraîchissement ─────────
    def refresh(self):
        db = self.db
        # visibilité
        _fill(self._zones, [(z["name"], z["cidr"], z["trust"], z["kind"]) for z in db.fetchall("SELECT * FROM net_zones ORDER BY trust")])
        hosts = db.fetchall("SELECT id, name, ip_address FROM hosts ORDER BY name")
        self._roles.setRowCount(len(hosts))
        for r, h in enumerate(hosts):
            ro = db.fetchone("SELECT role, source FROM host_roles WHERE host_id = ?", (h["id"],)) or {"role": "unknown", "source": "auto"}
            z = classify.zone_of_ip(db, h["ip_address"])
            for c, v in enumerate([h["name"], h["ip_address"], classify.ROLES.get(ro["role"], ro["role"]), "manuel" if ro["source"] == "manual" else "auto", z["name"] if z else "—"]):
                it = QTableWidgetItem(v)
                if c == 0: it.setData(Qt.ItemDataRole.UserRole, h["id"])
                self._roles.setItem(r, c, it)
        _fill(self._flows, [(f["src_ip"], f["dst_ip"], f["proto"], f["dst_port"], f["flows"], f["bytes"])
                            for f in db.fetchall("SELECT * FROM flows_agg ORDER BY bytes DESC LIMIT 200")])
        if self.mgr:
            _fill(self._enf, [(e["network"], e["gateway_ip"] or "—", e["device"] or "inconnu", "oui" if e["can_enforce"] else "non")
                              for e in self.mgr.netmap.enforcement_points()])
            nf = self.mgr.status()["netflow"]
            self._vis_info.setText(f"Flux enregistrés : {self.mgr.flows.count()} · collecteur NetFlow : "
                                   + (f"actif (UDP {nf['port']}, {nf['received']} paquet(s))" if nf["running"] else "arrêté (à activer dans Défense active)"))
        _fill(self._links, [(l["hn"], l["local_port"], l["remote_name"], l["remote_port"]) for l in db.fetchall(
            "SELECT h.name AS hn, n.* FROM net_links n JOIN hosts h ON h.id = n.host_id ORDER BY h.name")])
        # évaluation
        self._load_findings()
        # politique
        self._pol_default.blockSignals(True); self._pol_default.setCurrentIndex(1 if policy.default_action(db) == "deny" else 0); self._pol_default.blockSignals(False)
        self._four.blockSignals(True); self._four.setChecked(db.get_setting("policy_four_eyes", "0") == "1"); self._four.blockSignals(False)
        rules = self.pm.rules()
        self._rules.setRowCount(len(rules))
        for r, ru in enumerate(rules):
            for c, v in enumerate([ru["position"], RULE_STATUS_FR.get(ru["status"], ru["status"]) + ("" if ru["enabled"] else " (désactivée)"),
                                   "AUTORISER" if ru["action"] == "allow" else "REFUSER", policy.describe_selector(db, ru["src"]),
                                   policy.describe_selector(db, ru["dst"]), ru["service"], ru["name"]]):
                it = QTableWidgetItem(str(v))
                if c == 0: it.setData(Qt.ItemDataRole.UserRole, ru["id"])
                if c == 2: it.setForeground(QColor("#2ECC71" if ru["action"] == "allow" else "#E74C3C"))
                self._rules.setItem(r, c, it)
