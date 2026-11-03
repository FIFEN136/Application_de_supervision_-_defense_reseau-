"""Procus Secure — onglet « Règles simples » : créer une règle de trafic en 4 choix, sans vocabulaire technique."""
from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (QComboBox, QFrame, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QSpinBox, QVBoxLayout, QWidget,
                             QTableWidgetItem)

from core import simple_rules as sr
from core.policy import PolicyError, PolicyManager
from ui.styles import COLOR
from ui.widgets.defense_view import _fill, _note, _table
from ui.widgets.incidents_view import _btn

CUSTOM = "__custom__"


class SimpleRulesView(QWidget):
    def __init__(self, db, security=None, manager=None, parent=None):
        super().__init__(parent)
        self.db, self.security = db, security
        self.pm = manager.policy if manager else PolicyManager(db, security)
        lay = QVBoxLayout(self)
        lay.addWidget(_note("Décidez qui a le droit de parler à qui, en 4 choix. Procus Secure vérifie que la règle ne vous coupe pas "
                            "l'accès à votre propre réseau et vous montre son effet sur le trafic réellement observé avant de l'ajouter. "
                            "Les règles sont enregistrées dans la politique de filtrage ; elles ne sont pas envoyées automatiquement "
                            "à votre routeur ou pare-feu."))
        # ── 1. composer une règle ──
        box = QFrame(); box.setObjectName("card")
        box.setStyleSheet(f"QFrame#card{{background:{COLOR['bg_card']};border:1px solid {COLOR['border']};border-radius:8px;}}")
        bl = QVBoxLayout(box)
        t = QLabel("1. Composer une règle"); t.setStyleSheet(f"color:{COLOR['text_pri']};font-weight:700;"); bl.addWidget(t)
        row = QHBoxLayout()
        self.action = QComboBox(); self.action.addItem("Interdire", "deny"); self.action.addItem("Autoriser", "allow")
        self.src = QComboBox(); self.src_ip = QLineEdit(); self.src_ip.setPlaceholderText("ex : 192.168.1.20 ou 192.168.1.0/24")
        self.dst = QComboBox(); self.dst_ip = QLineEdit(); self.dst_ip.setPlaceholderText("ex : 192.168.1.10")
        self.what = QComboBox()
        for label, svc in sr.WHAT:
            self.what.addItem(label, svc)
        self.what.addItem("Un port précis…", CUSTOM)
        self.proto = QComboBox(); self.proto.addItems(["tcp", "udp"])
        self.port = QSpinBox(); self.port.setRange(1, 65535); self.port.setValue(8080)
        for w, cap in ((self.action, "Je veux"), (self.src, "Qui ?"), (self.dst, "Accéder à qui ?"), (self.what, "Pour faire quoi ?")):
            col = QVBoxLayout(); col.addWidget(QLabel(cap)); col.addWidget(w); row.addLayout(col, 1)
        bl.addLayout(row)
        extra = QHBoxLayout()
        for w in (self.src_ip, self.dst_ip, self.proto, self.port):
            extra.addWidget(w)
        bl.addLayout(extra)
        self.sentence = QLabel(""); self.sentence.setWordWrap(True)
        self.sentence.setStyleSheet(f"color:{COLOR['text_pri']};font-size:11pt;font-weight:600;padding:6px 0;")
        bl.addWidget(self.sentence)
        self.effect = QLabel(""); self.effect.setWordWrap(True); self.effect.setTextFormat(Qt.TextFormat.RichText)
        self.effect.setStyleSheet(f"color:{COLOR['text_sec']};")
        bl.addWidget(self.effect)
        btns = QHBoxLayout()
        self.b_add = _btn("Ajouter la règle", "#2ECC71"); self.b_add.clicked.connect(self._add)
        btns.addWidget(self.b_add); btns.addStretch(); bl.addLayout(btns)
        lay.addWidget(box)
        # ── 2. règles prêtes à l'emploi ──
        tl = QLabel("2. Règles prêtes à l'emploi (un clic)"); tl.setStyleSheet(f"color:{COLOR['text_pri']};font-weight:700;"); lay.addWidget(tl)
        self._cards = QVBoxLayout()
        for c in sr.template_cards():
            r = QHBoxLayout()
            lbl = QLabel(f"<b>{c['title']}</b><br><span style='color:{COLOR['text_sec']}'>{c['description']}</span>")
            lbl.setWordWrap(True); lbl.setTextFormat(Qt.TextFormat.RichText)
            b = _btn("Appliquer", "#3498DB"); b.clicked.connect(lambda _=False, k=c["key"]: self._template(k))
            r.addWidget(lbl, 1); r.addWidget(b); self._cards.addLayout(r)
        lay.addLayout(self._cards)
        # ── 3. mes règles ──
        ml = QLabel("3. Mes règles"); ml.setStyleSheet(f"color:{COLOR['text_pri']};font-weight:700;"); lay.addWidget(ml)
        self.table = _table(["Règle", "État"], 1)
        lay.addWidget(self.table, 1)
        row2 = QHBoxLayout()
        self.b_toggle = _btn("Activer / désactiver", "#F39C12"); self.b_del = _btn("Retirer la règle", "#E74C3C")
        self.b_approve = _btn("Approuver", "#2ECC71")
        self.b_toggle.clicked.connect(self._toggle); self.b_del.clicked.connect(self._remove); self.b_approve.clicked.connect(self._approve)
        for b in (self.b_approve, self.b_toggle, self.b_del):
            row2.addWidget(b)
        row2.addStretch(); lay.addLayout(row2)
        for w in (self.action, self.src, self.dst, self.what, self.proto):
            w.currentIndexChanged.connect(self._update)
        for w in (self.src_ip, self.dst_ip):
            w.textChanged.connect(self._update)
        self.port.valueChanged.connect(self._update)
        self.reload()

    # ───────── données ─────────
    def reload(self):
        for cmb in (self.src, self.dst):
            cur = cmb.currentData()
            cmb.blockSignals(True); cmb.clear()
            for label, sel in sr.who_choices(self.db):
                cmb.addItem(label, sel)
            cmb.addItem("Une adresse ou un réseau précis…", CUSTOM)
            i = cmb.findData(cur)
            cmb.setCurrentIndex(max(0, i)); cmb.blockSignals(False)
        self._refresh_rules()
        self._update()

    def _refresh_rules(self):
        self._rules = sr.plain_rules(self.db, self.pm)
        self.table.setColumnCount(2)
        self.table.setHorizontalHeaderLabels(["Règle", "État"])
        _fill(self.table, [(r["text"], r["state"]) for r in self._rules])
        self.table.setColumnWidth(0, 640)

    def _data(self) -> dict:
        src, dst, what = self.src.currentData(), self.dst.currentData(), self.what.currentData()
        if src == CUSTOM:
            src = sr.custom_who(self.src_ip.text())
        if dst == CUSTOM:
            dst = sr.custom_who(self.dst_ip.text())
        if what == CUSTOM:
            what = sr.custom_service(self.proto.currentText(), self.port.value())
        return sr.build(self.db, self.action.currentData(), src, dst, what)

    def _update(self, *_):
        self.src_ip.setVisible(self.src.currentData() == CUSTOM)
        self.dst_ip.setVisible(self.dst.currentData() == CUSTOM)
        custom = self.what.currentData() == CUSTOM
        self.proto.setVisible(custom); self.port.setVisible(custom)
        try:
            d = self._data()
            self.sentence.setText(sr.sentence(self.db, d))
            pv = sr.preview(self.db, self.pm, d)
        except PolicyError as e:
            self.sentence.setText("")
            self.effect.setText(f"<span style='color:#F39C12'>{e}</span>")
            self.b_add.setEnabled(False)
            return
        lines = []
        for m in pv["errors"]:
            lines.append(f"<span style='color:#E74C3C'><b>Impossible :</b> {m}</span>")
        for m in pv["warnings"]:
            lines.append(f"<span style='color:#F39C12'>Attention : {m}</span>")
        if pv["flows"]:
            lines.append(f"Sur le trafic observé, cette règle concernerait <b>{pv['flows']}</b> connexion(s) : " + " ; ".join(pv["top"]) + ".")
        else:
            lines.append("Aucune connexion observée ne correspond pour le moment (la règle protégera pour l'avenir).")
        self.effect.setText("<br>".join(lines))
        self.b_add.setEnabled(not pv["errors"])

    # ───────── actions ─────────
    def _allowed(self) -> bool:
        try:
            ok = True if not self.security else bool(self.security.has_permission("can_manage_config"))
        except Exception:
            ok = False
        if not ok:
            QMessageBox.warning(self, "Droits insuffisants", "Cette opération demande le droit « can_manage_config ».")
        return ok

    def _try(self, fn, ok_msg=None):
        try:
            r = fn()
        except (PolicyError, ValueError) as e:
            QMessageBox.warning(self, "Refusé", str(e)); return None
        if ok_msg:
            QMessageBox.information(self, "Règles", ok_msg(r) if callable(ok_msg) else ok_msg)
        self.reload()
        return r

    def _add(self):
        if not self._allowed():
            return
        try:
            d = self._data()
        except PolicyError as e:
            QMessageBox.warning(self, "Règle incomplète", str(e)); return
        self._try(lambda: sr.add(self.db, self.pm, d), lambda r: r["note"])

    def _template(self, key: str):
        if self._allowed():
            self._try(lambda: sr.apply_template(self.pm, key), lambda n: f"{n} règle(s) ajoutée(s).")

    def _sel(self):
        i = self.table.currentRow()
        if i < 0 or i >= len(self._rules):
            QMessageBox.information(self, "Règles", "Sélectionnez d'abord une règle dans la liste.")
            return None
        return self._rules[i]

    def _toggle(self):
        r = self._sel()
        if r and self._allowed():
            self._try(lambda: self.pm.set_enabled(r["id"], not r["enabled"]))

    def _remove(self):
        r = self._sel()
        if r and self._allowed():
            self._try(lambda: self.pm.retire_rule(r["id"]))

    def _approve(self):
        r = self._sel()
        if r and self._allowed():
            self._try(lambda: self.pm.approve_rule(r["id"]), "Règle approuvée.")
