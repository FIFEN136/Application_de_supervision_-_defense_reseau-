"""Règles de trafic simples : phrases, effet, refus clairs, exceptions avant interdictions, interface."""
import pytest
from PyQt6.QtWidgets import QMessageBox

from core import simple_rules as sr
from core.defense import DefenseManager
from core.policy import PolicyError, PolicyManager
from tests.test_policy import net  # noqa: F401


@pytest.fixture()
def env(qapp, db, security, net):
    assert security.authenticate("admin", "admin")
    return PolicyManager(db, security), db, net


def test_choices_are_in_plain_french(env):
    pm, db, h = env
    labels = [l for l, _ in sr.who_choices(db)]
    assert labels[0] == "Tous les appareils" and any(l.startswith("Les appareils de la zone") for l in labels)
    assert any("« cam-1 » (192.168.1.30)" in l for l in labels) and any(l == "Les serveurs" for l in labels)
    assert all("role:" not in l and "zone:" not in l for l in labels)           # aucun jargon dans le texte affiché
    assert dict(sr.WHAT)["Fichiers partagés Windows (SMB)"] == "smb"


def test_sentences(env):
    pm, db, h = env
    d = sr.build(db, "deny", "role:camera", "role:server", "smb")
    assert sr.sentence(db, d) == "Les caméras ne pourront plus accéder aux serveurs : fichiers partagés Windows (SMB)."
    assert sr.sentence(db, sr.build(db, "deny", "any", "any", "telnet")) == "Tous les appareils ne pourront plus accéder à tous les appareils : telnet (ancien et non sécurisé)."
    assert d["name"] == "Interdire les caméras → les serveurs (fichiers partagés Windows (SMB))"
    a = sr.build(db, "allow", f"host:{h['cam']}", f"host:{h['srv']}", "web")
    assert sr.sentence(db, a).startswith("L'appareil « cam-1 » pourra accéder à l'appareil « srv »")
    assert sr.who_label(db, "ip:192.168.1.30/32") == "l'adresse 192.168.1.30" and sr.who_label(db, "ip:10.0.0.0/24") == "le réseau 10.0.0.0/24"


def test_exceptions_come_before_bans(env):
    pm, db, h = env
    assert sr.build(db, "allow", "any", "any", "dns")["position"] < sr.build(db, "deny", "any", "any", "smb")["position"]


def test_custom_inputs_are_validated():
    assert sr.custom_service("tcp", 8080) == "tcp/8080" and sr.custom_who("192.168.1.20") == "ip:192.168.1.20/32"
    for bad in (("tcp", 0), ("tcp", 70000), ("tcp", "abc"), ("icmp", 80), ("gre", 1)):
        with pytest.raises(PolicyError):
            sr.custom_service(*bad)
    for bad in ("", "pas-une-ip", "999.1.1.1", "192.168.1.0/99"):
        with pytest.raises(PolicyError):
            sr.custom_who(bad)
    with pytest.raises(PolicyError):
        sr.build(None, "peut-etre", "any", "any", "any")


def test_preview_shows_effect_on_observed_traffic(env):
    pm, db, h = env
    d = sr.build(db, "deny", "role:camera", "role:server", "smb")
    pv = sr.preview(db, pm, d)
    assert pv["flows"] == 3 and "cam-1 → srv" in pv["top"][0] and not pv["errors"]
    assert sr.preview(db, pm, sr.build(db, "deny", f"host:{h['cam']}", f"host:{h['srv']}", "rdp"))["flows"] == 0


def test_preview_refuses_rules_that_cut_your_own_access(env):
    pm, db, h = env
    d = sr.build(db, "deny", "any", "role:network", "ssh")
    pv = sr.preview(db, pm, d)
    assert pv["errors"], pv                                                # coupe Procus → équipements réseau
    with pytest.raises(PolicyError):
        sr.add(db, pm, d)
    assert db.fetchone("SELECT COUNT(*) n FROM policy_rules")["n"] == 0
    assert any("tout" in w.lower() for w in sr.preview(db, pm, sr.build(db, "allow", "any", "any", "any"))["warnings"])


def test_add_list_toggle_remove(env):
    pm, db, h = env
    d = sr.build(db, "deny", "role:camera", "role:server", "smb")
    r = sr.add(db, pm, d)
    assert r["status"] == "approved" and "active" in r["note"]
    rules = sr.plain_rules(db, pm)
    assert len(rules) == 1 and rules[0]["state"] == "Active" and "ne pourront plus accéder" in rules[0]["text"]
    pm.set_enabled(r["id"], False)
    assert sr.plain_rules(db, pm)[0]["state"] == "Désactivée"
    pm.retire_rule(r["id"])
    assert sr.plain_rules(db, pm) == []


def test_four_eyes_leaves_draft_with_plain_note(env):
    pm, db, h = env
    db.set_setting("policy_four_eyes", "1")
    r = sr.add(db, pm, sr.build(db, "deny", "role:camera", "role:server", "smb"))
    assert r["status"] == "draft" and "pas encore active" in r["note"]
    assert sr.plain_rules(db, pm)[0]["state"] == "À approuver"


def test_templates_one_click(env):
    pm, db, h = env
    cards = sr.template_cards()
    assert {c["key"] for c in cards} >= {"isolate_guests", "block_insecure"} and all(c["title"] and c["description"] for c in cards)
    n = sr.apply_template(pm, "block_insecure")
    assert n >= 1 and all(r["state"] == "Active" for r in sr.plain_rules(db, pm))
    with pytest.raises(PolicyError):
        sr.apply_template(pm, "block_insecure")                              # déjà en place


def test_view_end_to_end(qapp, db, security, net, monkeypatch):
    assert security.authenticate("admin", "admin")
    shown = []
    for fn in ("information", "warning"):
        monkeypatch.setattr(QMessageBox, fn, lambda parent, title, text, *a, **k: shown.append((title, text)))
    from ui.widgets.defense_view import DefenseView
    m = DefenseManager(db, security)
    try:
        dv = DefenseView(db=db, security=security, manager=m)
        v = dv.simple_rules
        assert dv.tabs.tabText(1) == "Règles simples" and v.src.count() >= 8
        v.action.setCurrentIndex(v.action.findData("deny"))
        v.src.setCurrentIndex(v.src.findData("role:camera")); v.dst.setCurrentIndex(v.dst.findData("role:server"))
        v.what.setCurrentIndex(v.what.findData("smb"))
        assert "ne pourront plus accéder" in v.sentence.text() and "3" in v.effect.text() and v.b_add.isEnabled()
        v._add()
        assert shown[-1][0] == "Règles" and "active" in shown[-1][1] and v.table.rowCount() == 1
        v.table.selectRow(0); v._toggle()
        assert v.table.item(0, 1).text() == "Désactivée"
        v.table.selectRow(0); v._toggle(); v.table.selectRow(0); v._remove()
        assert v.table.rowCount() == 0
        # règle dangereuse : bouton désactivé, explication affichée
        v.src.setCurrentIndex(v.src.findData("any")); v.dst.setCurrentIndex(v.dst.findData("role:network"))
        v.what.setCurrentIndex(v.what.findData("ssh"))
        assert not v.b_add.isEnabled() and "Impossible" in v.effect.text()
        # saisie personnalisée invalide : message, pas d'exception
        v.src.setCurrentIndex(v.src.findData(sr.__name__ and "__custom__")); v.src_ip.setText("n'importe quoi")
        assert not v.b_add.isEnabled() and "Adresse invalide" in v.effect.text()
        v.src_ip.setText("192.168.50.9"); v.dst.setCurrentIndex(v.dst.findData("role:server")); v.what.setCurrentIndex(v.what.findData("__custom__"))
        v.port.setValue(445)
        assert v.b_add.isEnabled() and "192.168.50.9" in v.sentence.text()
        v._template("block_insecure"); assert "règle(s) ajoutée(s)" in shown[-1][1]
        v.grab()
    finally:
        m.stop()
