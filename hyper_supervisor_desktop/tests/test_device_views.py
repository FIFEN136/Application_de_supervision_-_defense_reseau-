import pytest
from PyQt6.QtWidgets import QDialog, QMessageBox
from core import device_info as di

V6_LINUX = ("2001:861:3081:bc60:9ea:460d:44f3:c7c1 dev wlan0 lladdr 9a:24:1c:bb:65:59 REACHABLE\n"
            "fe80::1 dev wlan0 lladdr 9a:24:1c:bb:65:59 STALE\nff02::1 dev x lladdr 33:33:00:00:00:01 NOARP\n"
            "2001:db8::5 dev eth0  FAILED\n")
V6_WIN = "  2001:861:3081:bc60:504c:25b8:a903:badf   4c-eb-bd-1a-1d-93   Reachable (Router)\n  fe80::2   4c-eb-bd-1a-1d-93  Stale\n"


def mk(db, name, ip, mac, dtype, status, **cols):
    h = db.add_host(name, ip)
    sets = ["mac_address=?", "device_type=?", "status=?"] + [f"{k}=?" for k in cols]
    db.execute("UPDATE hosts SET " + ", ".join(sets) + " WHERE id=?", (mac, dtype, status, *cols.values(), h))   # colonnes constantes du test
    return h


@pytest.fixture()
def fleet(db):
    gw = mk(db, "Passerelle", "192.168.1.254", "4c:eb:bd:00:00:01", "router", "online")
    pc = mk(db, "PC", "192.168.1.20", "00:1a:2b:3c:4d:5e", "workstation", "online", conn_type="wifi", conn_source="manual")
    tv = mk(db, "TV", "192.168.1.30", "3c:00:11:22:33:44", "tv", "online", conn_type="ethernet", conn_detail="Port 4", conn_source="manual")
    ph = mk(db, "iPhone", "192.168.1.122", "9a:24:1c:bb:65:59", "mobile", "online")
    off = mk(db, "Vieux", "192.168.1.9", "00:1a:2b:3c:4d:99", "unknown", "offline", approved=0)
    return dict(gw=gw, pc=pc, tv=tv, ph=ph, off=off)


# ───────────── données ─────────────
def test_ipv6_parsing_linux_windows_and_garbage():
    a = di.parse_ipv6_neighbors(V6_LINUX)
    assert a == {"9a:24:1c:bb:65:59": ["2001:861:3081:bc60:9ea:460d:44f3:c7c1", "fe80::1"]}      # globale d'abord, multicast/échec ignorés
    assert di.parse_ipv6_neighbors(V6_WIN)["4c:eb:bd:1a:1d:93"][0].startswith("2001:861")
    assert di.parse_ipv6_neighbors("n'importe quoi\n\x00\xff") == {} and di.parse_ipv6_neighbors("") == {}


@pytest.mark.parametrize("name,kind", [("Wi-Fi", "wifi"), ("wlan0", "wifi"), ("wlp3s0", "wifi"), ("Ethernet", "ethernet"), ("eth0", "ethernet"),
                                       ("enp3s0", "ethernet"), ("lo", "other"), ("docker0", "other"), ("vEthernet (WSL)", "other"),
                                       ("Loopback Pseudo-Interface 1", "other")])
def test_interface_classification(name, kind):
    assert di.classify_iface(name) == kind


def test_connection_inference_priority(db, fleet):
    info = {i["name"]: i for i in di.build_all(db)}
    assert info["PC"]["conn"]["type"] == "wifi" and info["PC"]["conn"]["source"] == "manual" and not info["PC"]["conn"]["probable"]
    assert info["TV"]["conn"]["label"] == "Ethernet" and info["TV"]["conn"]["detail"] == "Port 4"
    assert info["iPhone"]["conn"]["type"] == "wifi" and info["iPhone"]["conn"]["probable"]          # MAC aléatoire d'un téléphone
    assert info["Passerelle"]["conn"]["type"] == "unknown"                                         # jamais inventé
    db.execute("INSERT INTO net_fdb (host_id, mac, port) VALUES (?, ?, 'Gi0/7')", (fleet["gw"], "00:1a:2b:3c:4d:99"))
    assert {i["name"]: i for i in di.build_all(db)}["Vieux"]["conn"]["source"] == "snmp"          # port de commutateur → câble


def test_local_machine_connection_wins_over_heuristics(db, fleet):
    local = {"type": "ethernet", "detail": "Ethernet", "ip": "192.168.1.122"}
    i = di.build_info(db, db.get_host_by_id(fleet["ph"]), local)
    assert i["conn"]["type"] == "ethernet" and i["conn"]["source"] == "local"


def test_manual_choice_is_never_overwritten_by_refresh(db, fleet):
    di.refresh_connection_info(db)
    assert db.get_host_by_id(fleet["tv"])["conn_detail"] == "Port 4"
    assert db.get_host_by_id(fleet["ph"])["conn_type"] == "wifi" and db.get_host_by_id(fleet["ph"])["conn_source"] == "heuristic"


def test_unknown_values_stay_empty_not_invented(db, fleet):
    i = {x["name"]: x for x in di.build_all(db)}["Passerelle"]
    assert i["model"] is None and i["rssi"] is None and i["band"] is None and i["ipv6"] is None and i["cpu"] is None and i["rx_fmt"] is None
    assert i["quality"] is None                                                                     # pas de mesure → pas de « Excellent » inventé


def test_quality_labels():
    assert di.quality_label(5) == "Excellent" and di.quality_label(30) == "Bon" and di.quality_label(90) == "Moyen" and di.quality_label(400) == "Faible"
    assert di.quality_label(5, rssi=-80) == "Faible" and di.quality_label(5, rssi=-50) == "Excellent" and di.quality_label(None) is None
    assert di.quality_label(5, failed=2) == "Instable"


def test_filters(db, fleet):
    names = lambda f: {i["name"] for i in di.build_all(db) if di.matches_filter(i, f)}
    assert names("all") == {"Passerelle", "PC", "TV", "iPhone", "Vieux"}
    assert names("wifi") == {"PC", "iPhone"} and names("ethernet") == {"TV"}
    assert names("access") == {"Vieux"}                                                           # hors référentiel
    db.execute("INSERT INTO device_blocks (ip, status) VALUES ('192.168.1.20', 'blocked')")
    assert names("access") == {"Vieux", "PC"}


def test_rates_and_history_and_ports(db, fleet):
    import time
    db.execute("INSERT INTO bw_samples (ip, ts, rx_bps, tx_bps, source) VALUES ('192.168.1.20', ?, 500e6*8, 1e6, 'agent')", (int(time.time()),))
    db.execute("INSERT INTO port_states (host_id, port, protocol, state) VALUES (?, 443, 'TCP', 'open')", (fleet["pc"],))
    i = {x["name"]: x for x in di.build_all(db)}["PC"]
    assert "500" in i["rx_fmt"] and "MB" in i["rx_fmt"] or "Mo" in i["rx_fmt"] or "GB" in i["rx_fmt"] or "Gb" in i["rx_fmt"]
    assert i["open_ports"] == ["443/tcp"]


def test_edit_validation_and_audit(db, fleet):
    db.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('x','1')")
    di.update_device_meta(db, fleet["gw"], "admin", conn_type="wifi", conn_detail="Salon\x00\n", model="Box 6", wifi_band="5", rssi=-55, link_mbps=2400)
    h = db.get_host_by_id(fleet["gw"])
    assert (h["conn_type"], h["conn_source"], h["model"], h["wifi_band"], h["rssi"], h["link_mbps"]) == ("wifi", "manual", "Box 6", "5", -55, 2400)
    assert "\x00" not in h["conn_detail"] and "\n" not in h["conn_detail"]
    for bad in (dict(conn_type="satellite"), dict(wifi_band="7"), dict(rssi=10), dict(link_mbps=0)):
        with pytest.raises(ValueError):
            di.update_device_meta(db, fleet["gw"], "admin", **bad)
    di.update_device_meta(db, fleet["gw"], "admin", conn_type="auto")                                # retour à la détection
    assert db.get_host_by_id(fleet["gw"])["conn_source"] is None
    assert any(r["action"] == "device_info_edit" for r in db.get_audit_logs())


def test_quick_port_scan_finds_real_open_port():
    import socket
    s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(1); port = s.getsockname()[1]
    try:
        assert [p["port"] for p in di.quick_port_scan("127.0.0.1", ports=(port, 1))] == [port]
        assert di.quick_port_scan("pas une ip") == []
    finally:
        s.close()


# ───────────── interface ─────────────
@pytest.fixture()
def view(qtbot, db, security, fleet):
    from ui.widgets.topology_view import TopologyView
    security.authenticate("admin", "admin")
    v = TopologyView(db=db, security=security); qtbot.addWidget(v); v.resize(1400, 800); v.show()
    return v


def test_three_modes_switch_through_floating_bar(view):
    bar = view._bar
    assert view._stack.currentIndex() == 0 and bar.buttons["map"].isChecked()
    bar.buttons["list"].click(); assert view._stack.currentIndex() == 1
    bar.buttons["details"].click(); assert view._stack.currentIndex() == 2
    bar.buttons["map"].click(); assert view._stack.currentIndex() == 0
    assert 0 <= bar.x() and bar.x() + bar.width() <= view.width() and bar.y() + bar.height() <= view.height()     # visible et centrée


def test_list_view_cards_gateway_counter_inactive_last(view):
    view._on_mode("list")                                         # les pages se construisent à l'ouverture (économie de mémoire)
    cards = view._list_page.cards
    assert len(cards) == 5 and cards[0].info["name"] == "Passerelle"
    assert cards[-1].info["name"] == "Vieux" and not cards[-1].info["active"]
    from PyQt6.QtWidgets import QLabel
    texts = " ".join(l.text() for c in cards for l in c.findChildren(QLabel))
    assert "3 appareil(s) connecté(s)" in texts and "Port 4" in texts and "Wi-Fi" in texts


def test_details_view_shows_all_fields_and_actions(view):
    from PyQt6.QtWidgets import QLabel, QPushButton
    view._on_mode("details")
    card = next(c for c in view._details_page.cards if c.info["name"] == "TV")
    texts = " ".join(l.text() for l in card.findChildren(QLabel))
    for needle in ("Informations sur l'appareil", "Connexion", "Adresses", "IPv4", "MAC", "fabricant, modèle", "Première connexion",
                   "Sécurité", "Référentiel", "Port 4", "192.168.1.30", "3c:00:11:22:33:44"):
        assert needle in texts, needle
    buttons = [b.text() for b in card.findChildren(QPushButton)]
    assert any("bloquer" in b for b in buttons) and any("scan réseau" in b for b in buttons) and any("ping" in b for b in buttons)
    unknown = next(c for c in view._details_page.cards if c.info["name"] == "Vieux")
    assert any("Approuver" in b.text() for b in unknown.findChildren(QPushButton))


def test_filter_chips_apply_to_all_three_views(view):
    view._chips.set_filter("wifi")
    view._on_mode("details"); assert {c.info["name"] for c in view._details_page.cards} == {"PC", "iPhone"}
    view._on_mode("list"); assert {c.info["name"] for c in view._list_page.cards} == {"PC", "iPhone"}
    n = view._canvas._nodes
    assert n[view._infos and next(i for i, v in view._infos.items() if v["name"] == "PC")]["item"].opacity() == 1.0
    assert n[next(i for i, v in view._infos.items() if v["name"] == "TV")]["item"].opacity() < 0.5          # estompé sur la carte
    assert n[next(i for i, v in view._infos.items() if v["name"] == "Passerelle")]["item"].opacity() == 1.0   # le routeur central reste visible
    assert "2 appareil(s) affiché(s) sur 5" in view._lbl_count.text()
    view._on_mode("list")
    view._chips.set_filter("all"); assert len(view._list_page.cards) == 5


def test_map_click_fills_rich_panel_with_history_and_rate(view, db, fleet):
    import time
    db.execute("INSERT INTO bw_samples (ip, ts, rx_bps, tx_bps, source) VALUES ('192.168.1.20', ?, 4e6, 1e6, 'agent')", (int(time.time()),))
    db.execute("INSERT INTO events (host_id, host_name, severity, event_type, description) VALUES (?, 'PC', 'high', 'host_down', 'PC hors ligne')", (fleet["pc"],))
    view.refresh()
    view._show_detail(db.get_host_by_id(fleet["pc"]))
    assert "Wi-Fi" in view._extra["Connexion"].text() and "choisi par vous" in view._extra["Connexion"].text()
    assert "PC hors ligne" in view._hist.text() and "↓" in view._rate_lbl.text()
    assert all(b.isEnabled() for b in view._act_btns.values())
    view._show_detail(db.get_host_by_id(fleet["gw"])); assert "pas encore mesuré" in view._rate_lbl.text()


def test_link_styles_by_connection(view):
    from ui.widgets.topology_view import LINK_STYLES
    styles = {}
    for n in view._canvas._nodes.values():
        for l in n["item"].links:
            styles[view._infos[l.host_id]["name"]] = l.pen().style()
    assert styles["TV"] == LINK_STYLES["ethernet"][1] and styles["PC"] == LINK_STYLES["wifi"][1] and styles["Passerelle" if "Passerelle" in styles else "TV"]


def test_edit_dialog_saves_and_refreshes(view, db, fleet, monkeypatch):
    from ui.widgets import topology_view as tv
    class Fake(tv.EditDeviceDialog):
        def exec(self):
            self.conn.setCurrentIndex(self.conn.findData("ethernet")); self.detail.setText("Port 2"); self.model.setText("Imprimante X")
            return QDialog.DialogCode.Accepted
    monkeypatch.setattr(tv, "EditDeviceDialog", Fake)
    view._on_action("edit", fleet["ph"])
    h = db.get_host_by_id(fleet["ph"])
    assert (h["conn_type"], h["conn_detail"], h["model"], h["conn_source"]) == ("ethernet", "Port 2", "Imprimante X", "manual")
    assert view._extra["Connexion"].text().startswith("Port ")


def test_edit_requires_permission(view, security, db, fleet, monkeypatch):
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: None)
    monkeypatch.setattr(view, "_perm", lambda p: False)
    view._on_action("edit", fleet["ph"])
    assert db.get_host_by_id(fleet["ph"])["conn_source"] is None


def test_ping_and_scan_report_results(view, db, fleet, monkeypatch, qtbot):
    got = []
    monkeypatch.setattr(QMessageBox, "information", lambda parent, title, msg, *a: got.append((title, msg)))
    db.execute("UPDATE hosts SET ip_address='127.0.0.1' WHERE id=?", (fleet["pc"],))
    with qtbot.waitSignal(view.action_done, timeout=8000):
        view._on_action("ping", fleet["pc"])
    with qtbot.waitSignal(view.action_done, timeout=15000):
        view._on_action("scan", fleet["pc"])
    assert got[0][0] == "Résultat du ping" and "répond" in got[0][1]
    assert got[1][0] == "Résultat du scan"


def test_access_dialog_shows_plan_and_removes_device_on_request(view, db, fleet, monkeypatch):
    seen = {}
    monkeypatch.setattr(QMessageBox, "exec", lambda self: seen.update(plan=self.detailedText(), text=self.text()) or 0)
    monkeypatch.setattr(QMessageBox, "clickedButton", lambda self: next(b for b in self.buttons() if b.text() == "Retirer de la supervision"))
    view._on_action("access", fleet["off"])
    assert "Vieux" in seen["text"] and "192.168.1.9" in seen["plan"] and "rien n'est envoyé" in seen["plan"].lower()
    assert db.get_host_by_id(fleet["off"]) is None                                                   # retiré à la demande
    assert db.fetchone("SELECT 1 x FROM ignored_devices WHERE ip='192.168.1.9'")
    assert any(r["action"] == "device_removed" for r in db.get_audit_logs())


def test_access_dialog_refuses_protected_gateway(view, db, fleet, monkeypatch):
    warned = []
    monkeypatch.setattr(QMessageBox, "exec", lambda self: 0)
    monkeypatch.setattr(QMessageBox, "clickedButton", lambda self: next(b for b in self.buttons() if b.text() == "Retirer de la supervision"))
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: warned.append(a[2]))
    db.execute("INSERT INTO networks (name, cidr, gateway_ip) VALUES ('n', '192.168.1.0/24', '192.168.1.254')")
    view._on_action("access", fleet["gw"])
    assert warned and db.get_host_by_id(fleet["gw"]) is not None


def test_refresh_all_button(view, qtbot):
    with qtbot.waitSignal(view._bar.refresh_clicked, timeout=2000):
        view._bar.btn_refresh.click()
    assert len(view._infos) == 5


def test_agent_reports_nic_kind_and_server_stores_it_without_overriding_manual(db, fleet):
    from core.agent_server import AgentServer
    srv = AgentServer(db, None, None, port=0)
    srv._store_nic(fleet["ph"], {"net_kind": "ethernet", "net_iface": "Ethernet 2\x00\n", "net_speed_mbps": 1000})
    h = db.get_host_by_id(fleet["ph"])
    assert (h["conn_type"], h["conn_source"], h["link_mbps"]) == ("ethernet", "agent", 1000) and "\x00" not in h["conn_detail"]
    srv._store_nic(fleet["tv"], {"net_kind": "wifi", "net_iface": "wlan0"})                       # TV : choix manuel « Ethernet »
    assert db.get_host_by_id(fleet["tv"])["conn_type"] == "ethernet"
    srv._store_nic(fleet["pc"], {"net_kind": "satellite"}); srv._store_nic(fleet["pc"], {"net_kind": "wifi", "net_speed_mbps": "abc"})
    assert db.get_host_by_id(fleet["pc"])["conn_source"] == "manual"                               # valeurs invalides ignorées / manuel respecté


def test_collect_usage_includes_nic_kind_when_detectable():
    from agent import procus_agent as ag
    out = ag.collect_usage()
    assert out.get("net_kind", "wifi") in ("wifi", "ethernet")


def test_devinfo_job_runs(qapp, db, security, fleet):
    from core.defense import DefenseManager
    m = DefenseManager(db, security)
    assert m.run_job("devinfo") >= 1
    assert db.get_host_by_id(fleet["ph"])["conn_type"] == "wifi"


def test_connected_only_topology_scope(view, db, fleet):
    """Deux topologies : complète (tout) et « connectés » (online seulement), mise à jour en direct."""
    view.refresh()
    assert set(view._canvas._nodes) >= {fleet["off"], fleet["pc"]}
    view._scope_btns["online"].click()
    assert fleet["off"] not in view._canvas._nodes and fleet["pc"] in view._canvas._nodes
    assert db.get_setting("map_scope", "all") == "online"
    db.update_host_status(fleet["tv"], "offline", "2026-10-27 10:00:00")      # un appareil se déconnecte
    view.refresh_statuses()
    assert fleet["tv"] not in view._canvas._nodes
    view._scope_btns["all"].click()
    assert fleet["tv"] in view._canvas._nodes and fleet["off"] in view._canvas._nodes


def test_list_and_details_pages_are_built_only_when_opened(view):
    """Économie de mémoire : la Carte ne construit plus 2 × N cartes à chaque rafraîchissement."""
    view.refresh()
    assert view._list_page.cards == [] and view._details_page.cards == []
    view._on_mode("list"); assert len(view._list_page.cards) == 5 and view._details_page.cards == []
    view._on_mode("details"); assert len(view._details_page.cards) == 5
    view._on_mode("map"); view.refresh()
    assert view._dirty_pages == {1, 2}                              # périmées : refaites à la prochaine ouverture seulement
