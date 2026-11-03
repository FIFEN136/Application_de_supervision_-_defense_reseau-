"""
Procus Secure — vue « Défense active » (v13/v14).
Onglets : Vue d'ensemble · Honeypots · Réseau (ARP/DHCP) · Agents & intégrité · Journaux & Sigma · Configurations.
Les opérations longues (sonde DHCP, sauvegarde SSH) tournent dans un thread dédié : l'interface ne se fige jamais.
"""
import json
import html

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget, QTableWidgetItem, QPushButton, QHeaderView,
    QAbstractItemView, QTabWidget, QCheckBox, QMessageBox, QTextEdit, QPlainTextEdit, QDialog, QFormLayout,
    QLineEdit, QComboBox, QSpinBox, QDialogButtonBox, QInputDialog, QFileDialog, QTextBrowser, QGroupBox,
)

from core.config_backup import PROFILES
from core.honeypot import PROFILES as HP_PROFILES, load_ports, save_ports
from core.sigma_engine import RuleError, SigmaEngine, parse_rule
from ui.styles import COLOR, alpha
from ui.widgets.incidents_view import _btn


class _Job(QThread):
    done = pyqtSignal(object, str)

    def __init__(self, fn, parent=None):
        super().__init__(parent)
        self.fn = fn

    def run(self):
        try:
            self.done.emit(self.fn(), "")
        except Exception as e:                        # jamais d'exception non rattrapée dans un thread
            self.done.emit(None, str(e))


def _table(headers, stretch=None):
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.verticalHeader().setVisible(False)
    t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    t.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    t.horizontalHeader().setSectionResizeMode(stretch if stretch is not None else len(headers) - 1,
                                              QHeaderView.ResizeMode.Stretch)
    return t


def _fill(t, rows):
    t.setRowCount(len(rows))
    for r, vals in enumerate(rows):
        for c, v in enumerate(vals):
            t.setItem(r, c, QTableWidgetItem("" if v is None else str(v)))


def _note(text):
    l = QLabel(text)
    l.setWordWrap(True)
    l.setStyleSheet(f"color:{COLOR['text_sec']};font-size:8pt;")
    return l


class DefenseView(QWidget):
    def __init__(self, db=None, security=None, manager=None, parent=None):
        super().__init__(parent)
        self.db, self.security, self.mgr = db, security, manager
        self._jobs = []
        lay = QVBoxLayout(self)
        title = QLabel("Défense active")
        title.setStyleSheet(f"font-size:15pt;font-weight:700;color:{COLOR['text_pri']};")
        lay.addWidget(title)
        self.tabs = QTabWidget()
        lay.addWidget(self.tabs, 1)
        self._build_overview()
        self._build_simple_rules()
        self._build_honeypots()
        self._build_network()
        self._build_agents()
        self._build_logs()
        self._build_configs()
        if self.mgr:
            self.mgr.changed.connect(self.refresh)
            self.mgr.alert.connect(lambda _e: self.refresh_light())
        self.refresh()

    def _build_simple_rules(self):
        from ui.widgets.simple_rules_view import SimpleRulesView
        self.simple_rules = SimpleRulesView(self.db, self.security, self.mgr)
        self.tabs.addTab(self.simple_rules, "Règles simples")

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

    # ───────── Vue d'ensemble ─────────
    def _build_overview(self):
        w = QWidget(); l = QVBoxLayout(w)
        l.addWidget(_note("Chaque service s'active ici. Les services qui ouvrent un port (honeypots, agents, syslog) sont "
                          "désactivés par défaut. Toutes les alertes créent un événement : le pipeline les corrèle en incidents."))
        self._svc = {}
        labels = [("honeypot", "defense_honeypot", "Honeypots (faux services pièges)"),
                  ("arp", "defense_arp", "Détection d'usurpation ARP (passive, toutes les 60 s)"),
                  ("dhcp", "defense_dhcp", "Détection de serveur DHCP pirate (1 sonde / 6 h)"),
                  ("agents", "defense_agents", "Serveur d'agents légers (HTTPS signé)"),
                  ("syslog", "defense_syslog", "Récepteur syslog UDP (analyse Sigma)"),
                  ("netflow", "defense_netflow", "Collecteur de flux NetFlow v5 (UDP 2055) — « qui parle à qui »"),
                  ("fim", "defense_fim_local", "Intégrité des fichiers de cette machine (FIM)")]
        for key, setting, text in labels:
            row = QHBoxLayout()
            cb = QCheckBox(text)
            cb.clicked.connect(lambda checked, s=setting: self._toggle(s, checked))
            st = QLabel("")
            st.setStyleSheet(f"color:{COLOR['text_sec']};")
            row.addWidget(cb, 2); row.addWidget(st, 3)
            l.addLayout(row)
            self._svc[key] = (cb, st)
        row = QHBoxLayout()
        self._cb_exec = QCheckBox("Autoriser l'exécution réelle des actions approuvées (sinon : simulation uniquement)")
        self._cb_exec.clicked.connect(self._toggle_exec)
        row.addWidget(self._cb_exec)
        l.addLayout(row)
        self._recent = _table(["Date", "Gravité", "Type", "Description"])
        l.addWidget(QLabel("Dernières alertes de défense"))
        l.addWidget(self._recent, 1)
        self.tabs.addTab(w, "Vue d'ensemble")

    def _toggle(self, setting, checked):
        if not self._need_admin():
            self.refresh(); return
        self.mgr.set_enabled(setting, checked, self._user())

    def _toggle_exec(self, checked):
        if not self._need_admin():
            self.refresh(); return
        if checked and QMessageBox.question(
                self, "Exécution réelle",
                "Les actions approuvées pourront modifier le pare-feu (local ou d'un serveur Linux via SSH).\n"
                "Les adresses protégées (cette machine, passerelle) restent refusées et chaque exécution est annulable.\n\n"
                "Activer ?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            self.refresh(); return
        self.mgr.runner.set_enabled(checked, self._user())
        self.refresh()

    # ───────── Honeypots ─────────
    def _build_honeypots(self):
        w = QWidget(); l = QVBoxLayout(w)
        l.addWidget(_note("Un honeypot est un faux service : aucun usage légitime ne l'atteint, donc toute connexion est suspecte. "
                          ""))
        self._hp_ports = _table(["Port", "Profil", "État"], 2)
        l.addWidget(self._hp_ports)
        row = QHBoxLayout()
        b1 = _btn("Ajouter un port", "#2ECC71"); b2 = _btn("Retirer", "#E74C3C"); b3 = _btn("Purger l'historique", "#c4bfae")
        b1.clicked.connect(self._hp_add); b2.clicked.connect(self._hp_del); b3.clicked.connect(self._hp_purge)
        for b in (b1, b2, b3): row.addWidget(b)
        row.addStretch(); l.addLayout(row)
        l.addWidget(QLabel("Connexions reçues"))
        self._hp_hits = _table(["Date", "Source", "Port", "Profil", "Données reçues"])
        l.addWidget(self._hp_hits, 1)
        self.tabs.addTab(w, "Honeypots")

    def _hp_add(self):
        if not self._need_admin(): return
        port, ok = QInputDialog.getInt(self, "Honeypot", "Port à écouter (1024–65535) :", 2222, 1, 65535)
        if not ok: return
        prof, ok = QInputDialog.getItem(self, "Honeypot", "Profil :", list(HP_PROFILES), 0, False)
        if not ok: return
        ports = [p for p in load_ports(self.db) if int(p["port"]) != port] + [{"port": port, "profile": prof}]
        save_ports(self.db, ports); self.mgr.apply()

    def _hp_del(self):
        r = self._hp_ports.currentRow()
        if r < 0 or not self._need_admin(): return
        port = int(self._hp_ports.item(r, 0).text())
        save_ports(self.db, [p for p in load_ports(self.db) if int(p["port"]) != port])
        self.mgr.honeypots.stop(); self.mgr.apply()

    def _hp_purge(self):
        if self._need_admin():
            self.db.execute("DELETE FROM honeypot_hits"); self.refresh()

    # ───────── Réseau ARP / DHCP ─────────
    def _build_network(self):
        w = QWidget(); l = QVBoxLayout(w)
        l.addWidget(_note("ARP : mémorise l'adresse MAC de chaque IP et alerte si la passerelle change de MAC (attaque de l'homme du "
                          "milieu). DHCP : envoie une demande et alerte si un serveur inconnu répond."))
        row = QHBoxLayout()
        self._b_arp = _btn("Vérifier ARP maintenant", "#3498DB"); self._b_dhcp = _btn("Sonder le DHCP maintenant", "#3498DB")
        self._b_trust = _btn("Approuver les serveurs DHCP vus", "#F39C12")
        self._b_arp.clicked.connect(lambda: self._job("arp")); self._b_dhcp.clicked.connect(lambda: self._job("dhcp"))
        self._b_trust.clicked.connect(self._trust_dhcp)
        for b in (self._b_arp, self._b_dhcp, self._b_trust): row.addWidget(b)
        row.addStretch(); l.addLayout(row)
        self._dhcp_lbl = QLabel(""); self._dhcp_lbl.setStyleSheet(f"color:{COLOR['text_sec']};")
        l.addWidget(self._dhcp_lbl)
        self._arp_tbl = _table(["Adresse IP", "Adresse MAC", "Passerelle", "Vu en dernier"], 3)
        l.addWidget(self._arp_tbl, 1)
        self.tabs.addTab(w, "Réseau ARP / DHCP")

    def _job(self, name):
        self._run(lambda: self.mgr.run_job(name), lambda r: QMessageBox.information(
            self, "Vérification terminée", self._summ(name, r)))

    @staticmethod
    def _summ(name, r):
        if name == "arp":
            return f"{len(r or [])} alerte(s) ARP."
        if name == "dhcp":
            r = r or {}
            ips = [x["server"] for x in r.get("servers", [])]
            return ("Serveurs vus : " + (", ".join(ips) or "aucun")
                    + f"\nAlertes : {len(r.get('alerts', []))}" + (f"\nErreur : {r['error']}" if r.get("error") else ""))
        return "Terminé."

    def _trust_dhcp(self):
        if not self._need_admin(): return
        def go():
            r = self.mgr.dhcp.probe()
            return [x["server"] for x in r.get("servers", [])]
        def done(servers):
            if servers:
                self.mgr.dhcp.trust(servers); self.mgr.db.write_audit(self._user(), "dhcp_trust", "defense", ",".join(servers))
            QMessageBox.information(self, "DHCP", "Serveurs approuvés : " + (", ".join(servers) or "aucun serveur n'a répondu."))
        self._run(go, done)

    # ───────── Agents & FIM ─────────
    def _build_agents(self):
        w = QWidget(); l = QVBoxLayout(w)
        l.addWidget(_note("L'agent est un fichier unique (agent/procus_agent.py) qui envoie l'inventaire, l'intégrité des fichiers et les "
                          "journaux, signés (HMAC) et chiffrés (TLS épinglé). Le serveur ne lui envoie jamais de commande. "
                          "Le secret n'est montré qu'une seule fois, à l'enrôlement."))
        row = QHBoxLayout()
        b1 = _btn("Enrôler un agent", "#2ECC71"); b2 = _btn("Révoquer", "#E74C3C"); b3 = _btn("Fichiers surveillés…", "#3498DB")
        b4 = _btn("Réinitialiser la référence FIM", "#F39C12"); b5 = _btn("Vérifier cette machine", "#3498DB")
        b1.clicked.connect(self._ag_enroll); b2.clicked.connect(self._ag_revoke); b3.clicked.connect(self._ag_paths)
        b4.clicked.connect(self._ag_reset); b5.clicked.connect(lambda: self._job_fim())
        for b in (b1, b2, b3, b4, b5): row.addWidget(b)
        row.addStretch(); l.addLayout(row)
        self._ag_tbl = _table(["Agent", "Nom", "Système", "Version", "Dernier contact", "Actif"], 4)
        self._ag_tbl.itemSelectionChanged.connect(self._ag_detail)
        l.addWidget(self._ag_tbl)
        self._ag_info = QTextBrowser(); l.addWidget(self._ag_info, 1)
        self.tabs.addTab(w, "Agents & intégrité")

    def _sel_agent(self):
        r = self._ag_tbl.currentRow()
        return self._ag_tbl.item(r, 0).text() if r >= 0 else None

    def _ag_enroll(self):
        if not self._need_admin(): return
        name, ok = QInputDialog.getText(self, "Enrôler un agent", "Nom de la machine :")
        if not ok or not name.strip(): return
        osn, ok = QInputDialog.getItem(self, "Enrôler un agent", "Système :", ["linux", "windows"], 0, False)
        if not ok: return
        try:
            e = self.mgr.registry.enroll(name, os_name=osn)
            cfg = self.mgr.agent_config(e)
            self.db.write_audit(self._user(), "agent_enrolled", e["agent_id"], name)
        except Exception as ex:
            QMessageBox.warning(self, "Enrôlement", str(ex)); return
        path, _ = QFileDialog.getSaveFileName(self, "Enregistrer agent_config.json", "agent_config.json", "JSON (*.json)")
        text = json.dumps(cfg, indent=2)
        if path:
            with open(path, "w", encoding="utf-8") as f: f.write(text)
        else:
            QMessageBox.information(self, "Configuration de l'agent (affichée une seule fois)", text)
        self.refresh()

    def _ag_revoke(self):
        a = self._sel_agent()
        if a and self._need_admin():
            self.mgr.registry.revoke(a); self.db.write_audit(self._user(), "agent_revoked", a, ""); self.refresh()

    def _ag_paths(self):
        a = self._sel_agent()
        if not a or not self._need_admin(): return
        cur = "\n".join(json.loads((self.mgr.registry.get(a) or {}).get("watch_paths") or "[]"))
        d = QDialog(self); d.setWindowTitle("Fichiers surveillés (un par ligne)"); v = QVBoxLayout(d)
        ed = QPlainTextEdit(cur); v.addWidget(ed)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(d.accept); bb.rejected.connect(d.reject); v.addWidget(bb)
        if d.exec():
            self.mgr.registry.set_watch_paths(a, [p.strip() for p in ed.toPlainText().splitlines() if p.strip()])

    def _ag_reset(self):
        a = self._sel_agent()
        if a and self._need_admin():
            from core.fim import FimEngine
            FimEngine(self.db, self.mgr.sink).reset(a); self.db.write_audit(self._user(), "fim_reset", a, "")
            QMessageBox.information(self, "FIM", "Référence effacée : elle sera recréée au prochain rapport.")

    def _job_fim(self):
        self._run(lambda: self.mgr.run_job("fim"), lambda r: QMessageBox.information(
            self, "Intégrité", "Contrôle terminé : %d changement(s)." % len((r or {}).get("changes", []))))

    def _ag_detail(self):
        a = self._sel_agent()
        if not a: return
        out = []
        for r in self.db.fetchall("SELECT kind, data, collected_at FROM agent_data WHERE agent_id = ?", (a,)):
            try:
                d = json.loads(r["data"])
            except Exception:
                d = r["data"]
            n = len(d) if isinstance(d, (list, dict)) else 1
            out.append(f"<b>{html.escape(r['kind'])}</b> — {n} élément(s), relevé {html.escape(r['collected_at'])}")
        fim = self.db.fetchone("SELECT COUNT(*) n FROM fim_baseline WHERE agent_id = ?", (a,))["n"]
        out.append(f"<b>Fichiers sous surveillance d'intégrité</b> : {fim}")
        self._ag_info.setHtml("<br>".join(out))

    # ───────── Journaux & Sigma ─────────
    def _build_logs(self):
        w = QWidget(); l = QVBoxLayout(w)
        l.addWidget(_note("Les journaux (syslog, agents) sont analysés par des règles au format Sigma (sous-ensemble : contains, startswith, "
                          "endswith, re, all ; conditions and/or/not ; seuil Procus « threshold »). Une règle invalide est refusée."))
        self._sg = _table(["Actif", "Identifiant", "Titre", "Niveau", "Origine"], 2)
        l.addWidget(self._sg)
        row = QHBoxLayout()
        b1 = _btn("Activer / désactiver", "#3498DB"); b2 = _btn("Ajouter une règle", "#2ECC71"); b3 = _btn("Supprimer", "#E74C3C")
        b1.clicked.connect(self._sg_toggle); b2.clicked.connect(self._sg_add); b3.clicked.connect(self._sg_del)
        for b in (b1, b2, b3): row.addWidget(b)
        row.addStretch(); l.addLayout(row)
        box = QGroupBox("Tester une ligne de journal"); bl = QHBoxLayout(box)
        self._sg_line = QLineEdit(); self._sg_line.setPlaceholderText("Failed password for root from 10.0.0.9 port 22 ssh2")
        bt = _btn("Tester", "#F39C12"); bt.clicked.connect(self._sg_test)
        bl.addWidget(self._sg_line, 1); bl.addWidget(bt); l.addWidget(box)
        self._sg_out = QLabel(""); self._sg_out.setWordWrap(True); l.addWidget(self._sg_out)
        l.addWidget(QLabel("Journaux reçus récemment"))
        self._lg = _table(["Date", "Source", "Message"])
        l.addWidget(self._lg, 1)
        self.tabs.addTab(w, "Journaux & Sigma")

    def _sg_sel(self):
        r = self._sg.currentRow()
        return self._sg.item(r, 1).text() if r >= 0 else None

    def _sg_reload(self):
        try:
            self.mgr.pipeline.reload_rules()
        except Exception:
            pass

    def _sg_toggle(self):
        rid = self._sg_sel()
        if rid and self._need_admin():
            self.db.execute("UPDATE sigma_rules SET enabled = 1 - enabled WHERE rule_id = ?", (rid,))
            self._sg_reload(); self.refresh()

    def _sg_del(self):
        rid = self._sg_sel()
        if not rid or not self._need_admin(): return
        row = self.db.fetchone("SELECT builtin FROM sigma_rules WHERE rule_id = ?", (rid,))
        if row and row["builtin"]:
            QMessageBox.information(self, "Règle intégrée", "Les règles intégrées se désactivent mais ne se suppriment pas."); return
        self.db.execute("DELETE FROM sigma_rules WHERE rule_id = ?", (rid,)); self._sg_reload(); self.refresh()

    def _sg_add(self):
        if not self._need_admin(): return
        d = QDialog(self); d.setWindowTitle("Nouvelle règle Sigma (YAML)"); d.resize(620, 460); v = QVBoxLayout(d)
        ed = QPlainTextEdit(
            "title: Exemple — connexion root\nid: custom-root-login\nlevel: high\ndetection:\n  sel:\n    message|contains: 'Accepted password for root'\n  condition: sel\n")
        v.addWidget(ed)
        msg = QLabel(""); msg.setStyleSheet("color:#E74C3C;"); v.addWidget(msg)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        v.addWidget(bb); bb.rejected.connect(d.reject)

        def ok():
            try:
                rule = parse_rule(ed.toPlainText())
            except (RuleError, Exception) as e:
                msg.setText(f"Règle refusée : {e}"); return
            self.db.execute("INSERT OR REPLACE INTO sigma_rules (rule_id, title, level, enabled, builtin, yaml) VALUES (?,?,?,?,0,?)",
                            (rule.id, rule.title, rule.level, 1, ed.toPlainText()))
            self.db.write_audit(self._user(), "sigma_rule_added", rule.id, rule.title)
            d.accept()
        bb.accepted.connect(ok)
        if d.exec():
            self._sg_reload(); self.refresh()

    def _sg_test(self):
        try:
            hits = SigmaEngine.from_db(self.db).evaluate(self._sg_line.text(), {})
        except Exception as e:
            self._sg_out.setText(f"Erreur : {e}"); return
        self._sg_out.setText("Aucune règle ne correspond." if not hits else
                             "Correspond à : " + " ; ".join(f"{h['rule'].title} ({h['rule'].level})" for h in hits))

    # ───────── Configurations SSH ─────────
    def _build_configs(self):
        w = QWidget(); l = QVBoxLayout(w)
        l.addWidget(_note("Sauvegarde des configurations par SSH en LECTURE SEULE (liste blanche de commandes), avec empreinte de clé hôte "
                          "mémorisée à la première connexion, secrets chiffrés, historique de 50 versions et différences masquant "
                          "les mots de passe. Un changement de configuration crée une alerte."))
        self._cf_hosts = _table(["Équipement", "Adresse", "Profil", "Identifiants", "Dernière sauvegarde"], 4)
        self._cf_hosts.itemSelectionChanged.connect(self._cf_hist)
        l.addWidget(self._cf_hosts)
        row = QHBoxLayout()
        b1 = _btn("Identifiants SSH…", "#3498DB"); b2 = _btn("Sauvegarder maintenant", "#2ECC71")
        b3 = _btn("Comparer 2 versions", "#F39C12"); b4 = _btn("Oublier la clé hôte", "#E74C3C")
        b1.clicked.connect(self._cf_creds); b2.clicked.connect(self._cf_backup); b3.clicked.connect(self._cf_diff); b4.clicked.connect(self._cf_forget)
        for b in (b1, b2, b3, b4): row.addWidget(b)
        row.addStretch(); l.addLayout(row)
        self._cf_h = _table(["Version", "Date", "+ lignes", "- lignes", "Taille"], 1)
        self._cf_h.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        l.addWidget(self._cf_h)
        self._cf_view = QTextEdit(); self._cf_view.setReadOnly(True); self._cf_view.setFontFamily("Consolas")
        l.addWidget(self._cf_view, 1)
        self.tabs.addTab(w, "Configurations")

    def _cf_host(self):
        r = self._cf_hosts.currentRow()
        return int(self._cf_hosts.item(r, 0).data(Qt.ItemDataRole.UserRole)) if r >= 0 else None

    def _cf_creds(self):
        hid = self._cf_host()
        if not hid or not self._need_admin(): return
        cur = self.mgr.config.get_credentials(hid) or {}
        d = QDialog(self); d.setWindowTitle("Identifiants SSH"); f = QFormLayout(d)
        user = QLineEdit(cur.get("username", "")); pw = QLineEdit(); pw.setEchoMode(QLineEdit.EchoMode.Password)
        pw.setPlaceholderText("(inchangé)" if cur.get("has_secret") else "")
        auth = QComboBox(); auth.addItems(["password", "key"]); auth.setCurrentText(cur.get("auth_type", "password"))
        port = QSpinBox(); port.setRange(1, 65535); port.setValue(int(cur.get("port") or 22))
        prof = QComboBox(); prof.addItems(list(PROFILES)); prof.setCurrentText(cur.get("profile", "cisco_ios"))
        cmds = QPlainTextEdit("\n".join(cur.get("commands", []))); cmds.setPlaceholderText("Profil « custom » : une commande de lecture par ligne")
        cmds.setMaximumHeight(80)
        for lab, wd in (("Utilisateur", user), ("Mot de passe / clé privée", pw), ("Authentification", auth), ("Port", port),
                        ("Profil", prof), ("Commandes (custom)", cmds)):
            f.addRow(lab, wd)
        msg = QLabel(""); msg.setStyleSheet("color:#E74C3C;"); f.addRow(msg)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        f.addRow(bb); bb.rejected.connect(d.reject)

        def ok():
            try:
                self.mgr.config.set_credentials(hid, user.text(), pw.text(), auth.currentText(), port.value(), prof.currentText(),
                                                [c for c in cmds.toPlainText().splitlines() if c.strip()])
            except ValueError as e:
                msg.setText(str(e)); return
            self.db.write_audit(self._user(), "ssh_credentials_set", f"host:{hid}", user.text()); d.accept()
        bb.accepted.connect(ok)
        if d.exec(): self.refresh()

    def _cf_backup(self):
        hid = self._cf_host()
        if not hid: return
        def done(r):
            txt = {"first": "Première sauvegarde enregistrée.", "unchanged": "Aucun changement depuis la dernière sauvegarde.",
                   "changed": f"Changement détecté : +{r.get('added')} / -{r.get('removed')} lignes (alerte créée)."}.get(r.get("status"))
            if r.get("status") == "error":
                QMessageBox.warning(self, "Sauvegarde", r.get("error", "Échec"))
            else:
                QMessageBox.information(self, "Sauvegarde", txt or str(r))
        self._run(lambda: self.mgr.config.backup_host(hid), done)

    def _cf_hist(self):
        hid = self._cf_host()
        rows = self.mgr.config.history(hid) if hid else []
        self._cf_h.setRowCount(len(rows))
        for r, h in enumerate(rows):
            for c, v in enumerate([f"#{h['id']}", h["collected_at"], h.get("lines_added"), h.get("lines_removed"), h.get("size")]):
                it = QTableWidgetItem("" if v is None else str(v))
                if c == 0: it.setData(Qt.ItemDataRole.UserRole, h["id"])
                self._cf_h.setItem(r, c, it)

    def _cf_diff(self):
        ids = sorted({self._cf_h.item(i.row(), 0).data(Qt.ItemDataRole.UserRole) for i in self._cf_h.selectedIndexes()})
        if len(ids) == 1:
            txt = self.mgr.config.get_content(ids[0]) or ""
            from core.config_backup import mask_secrets
            self._cf_view.setPlainText(mask_secrets(txt)); return
        if len(ids) != 2:
            QMessageBox.information(self, "Comparer", "Sélectionnez deux versions (Ctrl+clic), ou une seule pour l'afficher."); return
        self._cf_view.setPlainText(self.mgr.config.diff(ids[0], ids[1]) or "Aucune différence.")

    def _cf_forget(self):
        hid = self._cf_host()
        if hid and self._need_admin() and QMessageBox.question(
                self, "Clé hôte", "N'oubliez la clé qu'après avoir VÉRIFIÉ que l'équipement a bien été remplacé. Continuer ?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes:
            self.mgr.config.forget_host_key(hid); self.db.write_audit(self._user(), "ssh_hostkey_forgotten", f"host:{hid}", "")

    # ───────── rafraîchissement ─────────
    def refresh_light(self):
        types = ("honeypot_hit", "arp_spoof", "arp_restored", "rogue_dhcp", "fim_change", "sigma_match", "ssh_hostkey_changed", "agent_silent", "vulnerability_found")
        rows = self.db.fetchall(
            "SELECT occurred_at, severity, event_type, description FROM events WHERE event_type IN (%s) ORDER BY id DESC LIMIT 100"  # nosec B608
            % ",".join("?" * len(types)), types)
        _fill(self._recent, [(r["occurred_at"], r["severity"], r["event_type"], r["description"]) for r in rows])

    def refresh(self):
        if not self.mgr:
            return
        st = self.mgr.status()
        for key, (cb, lab) in self._svc.items():
            s = st[key]
            cb.blockSignals(True); cb.setChecked(bool(s["enabled"])); cb.blockSignals(False)
            txt = "actif" if s["running"] else "arrêté"
            if key == "agents" and s["running"]:
                txt += f" — port {s['port']} ({'TLS' if s['tls'] else 'sans TLS'})"
            if key == "netflow" and s["running"]:
                txt += f" — UDP {s['port']}, {s['received']} paquet(s)"
            if key == "syslog" and s["running"]:
                txt += f" — UDP {s['port']}, {s['received']} message(s)"
            if s.get("error"):
                txt += f" — erreur : {s['error']}"
            lab.setText(txt)
        self._cb_exec.blockSignals(True); self._cb_exec.setChecked(self.mgr.runner.enabled()); self._cb_exec.blockSignals(False)
        self.refresh_light()
        # honeypots
        det = st["honeypot"]["detail"]
        ports = load_ports(self.db)
        _fill(self._hp_ports, [(p["port"], p["profile"], det.get(int(p["port"]), det.get(p["port"], "arrêté"))) for p in ports])
        _fill(self._hp_hits, [(h["seen_at"], f"{h['src_ip']}:{h['src_port']}", h["port"], h["profile"], (h["payload"] or "")[:120])
                              for h in self.db.fetchall("SELECT * FROM honeypot_hits ORDER BY id DESC LIMIT 200")])
        # réseau
        _fill(self._arp_tbl, [(b["ip"], b["mac"], "oui" if b["is_gateway"] else "", b["last_seen"])
                              for b in self.db.fetchall("SELECT * FROM arp_bindings ORDER BY is_gateway DESC, ip")])
        tr = st["dhcp"]["trusted"]
        self._dhcp_lbl.setText("Serveurs DHCP approuvés : " + (", ".join(tr) if tr else "aucun (appris à la première sonde)"))
        # agents
        sel = self._sel_agent()
        _fill(self._ag_tbl, [(a["agent_id"], a["name"], a["os"], a["version"], a["last_seen"] or "jamais", "oui" if a["enabled"] else "révoqué")
                             for a in self.mgr.registry.list()])
        # sigma + journaux
        sel_r = self._sg_sel()
        _fill(self._sg, [("oui" if r["enabled"] else "non", r["rule_id"], r["title"], r["level"], "intégrée" if r["builtin"] else "personnalisée")
                         for r in self.db.fetchall("SELECT * FROM sigma_rules ORDER BY builtin DESC, rule_id")])
        _fill(self._lg, [(r["received_at"], r["source"], (r["message"] or "")[:200])
                         for r in self.db.fetchall("SELECT * FROM log_events ORDER BY id DESC LIMIT 100")])
        # configurations
        hid = self._cf_host()
        hosts = self.db.fetchall("SELECT id, name, ip_address FROM hosts ORDER BY name")
        self._cf_hosts.setRowCount(len(hosts))
        for r, h in enumerate(hosts):
            cred = self.db.fetchone("SELECT profile FROM host_credentials WHERE host_id = ?", (h["id"],))
            last = self.db.fetchone("SELECT MAX(collected_at) d FROM config_backups WHERE host_id = ?", (h["id"],))
            for c, v in enumerate([h["name"], h["ip_address"], (cred or {}).get("profile", ""), "oui" if cred else "non", (last or {}).get("d") or ""]):
                it = QTableWidgetItem(str(v))
                if c == 0: it.setData(Qt.ItemDataRole.UserRole, h["id"])
                self._cf_hosts.setItem(r, c, it)
