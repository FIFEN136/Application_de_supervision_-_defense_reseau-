import time
import pytest
from PyQt6.QtWidgets import QMessageBox
from core import local_network as lnet
from core.bandwidth import BandwidthManager, fmt_bps
from core.defense import DefenseManager
from core.device_access import DeviceAccess, AccessRefused, is_ignored
from core.flows import FlowStore
from ui.widgets.security_view import SecurityView
from tests.test_policy import net  # noqa: F401


T0 = time.time()


class FakeSsh:
    def __init__(self, fail_on=None):
        self.calls, self.fail_on = [], fail_on

    def __call__(self, cred, cmds):
        self.calls.append(cmds[0])
        rc = 1 if self.fail_on and self.fail_on in cmds[0] else 0
        return [{"cmd": cmds[0], "rc": rc, "out": "boom" if rc else ""}]


@pytest.fixture()
def env(qapp, db, security, net):
    assert security.authenticate("admin", "admin")
    ssh = FakeSsh()
    acc = DeviceAccess(db, security, None, ssh_runner=ssh)
    yield acc, ssh, db, net, security


def add_gw_creds(db, net):
    from core.config_backup import ConfigBackupManager
    ConfigBackupManager(db, None).set_credentials(net["gw"], "root", "pw-Test-123", "password", 22, "linux")


def test_fmt_bps():
    assert fmt_bps(500) == "500 b/s" and fmt_bps(2_500_000) == "2.5 Mb/s" and fmt_bps(3e9) == "3.0 Gb/s"


def test_rates_from_flows_are_delta_estimates(db, net):
    bw = BandwidthManager(db)
    bw.sample(now=T0)
    FlowStore(db).add("192.168.1.30", "192.168.1.10", "tcp", 445, 8000, 8)
    bw.sample(now=T0 + 10)
    cam = next(d for d in bw.current() if d["ip"] == "192.168.1.30")
    assert cam["source"] == "netflow" and not cam["exact"] and abs(cam["tx_bps"] - 6400) < 1 and cam["rx_bps"] == 0
    srv = next(d for d in bw.current() if d["ip"] == "192.168.1.10")
    assert abs(srv["rx_bps"] - 6400) < 1
    FlowStore(db).purge(days=0)                      # flux purgés : jamais de débit négatif
    bw.sample(now=T0 + 20)
    assert all(d["rx_bps"] >= 0 and d["tx_bps"] >= 0 for d in bw.current())


def test_snmp_router_usage_and_priority(db, net):
    for m, v in (("bw_in", 50.0), ("bw_out", 10.0)):
        db.execute("INSERT INTO metrics (host_id, metric_name, interface, value, unit) VALUES (?,?,?,?,?)",
                   (net["gw"], m, "total", v, "Mbps"))
    bw = BandwidthManager(db)
    bw.sample(now=T0)
    g = bw.gateways()
    assert len(g) == 1 and g[0]["name"] == "gw" and g[0]["source"] == "snmp"
    assert abs(g[0]["usage_pct"] - 50.0) < 0.01 and abs(g[0]["rx_bps"] - 50e6) < 1
    db.set_setting("bw_link_mbps", "200")
    assert abs(bw.gateways()[0]["usage_pct"] - 25.0) < 0.01


def test_detail_and_series(db, net):
    bw = BandwidthManager(db)
    import time
    now = int(time.time())
    for i in range(5):
        db.execute("INSERT INTO bw_samples (ip, ts, rx_bps, tx_bps, source) VALUES (?,?,?,?,?)",
                   ("192.168.1.30", now - 60 * i, 1000 * i, 500, "netflow"))
    s = bw.series("192.168.1.30", 1)
    assert len(s) >= 2
    d = bw.detail("192.168.1.30")
    assert d["host"]["name"] == "cam-1" and d["peers"][0]["peer"] == "192.168.1.10" and d["blocked"] is None
    db.execute("INSERT INTO bw_samples (ip, ts, rx_bps, tx_bps, source) VALUES ('1.2.3.4', ?, 1, 1, 'x')", (now - 8 * 86400,))
    bw.purge()
    assert not db.fetchone("SELECT 1 FROM bw_samples WHERE ip='1.2.3.4'") and db.fetchone("SELECT 1 FROM bw_samples WHERE ip='192.168.1.30'")


def test_remove_is_reversible_and_discovery_respects_it(env):
    acc, ssh, db, net, sec = env
    acc.remove("192.168.1.30", "appareil inconnu")
    assert not db.fetchone("SELECT 1 FROM hosts WHERE ip_address='192.168.1.30'") and is_ignored(db, "192.168.1.30")
    assert db.fetchone("SELECT 1 FROM audit_logs WHERE action='device_removed'")
    assert lnet.register_discovered(db, [{"ip": "192.168.1.30", "name": "cam-1"}]) == 0
    assert not db.fetchone("SELECT 1 FROM hosts WHERE ip_address='192.168.1.30'")
    assert acc.restore("192.168.1.30") and not is_ignored(db, "192.168.1.30")
    assert lnet.register_discovered(db, [{"ip": "192.168.1.30", "name": "cam-1"}]) == 1


def test_remove_refuses_local_gateway_unknown(env):
    acc, ssh, db, net, sec = env
    for ip in ("192.168.1.100", "192.168.1.1", "192.168.1.2"):
        with pytest.raises(AccessRefused):
            acc.remove(ip)
    with pytest.raises(AccessRefused):
        acc.remove("10.9.9.9")
    with pytest.raises(AccessRefused):
        acc.remove("pas-une-ip")
    assert db.fetchone("SELECT 1 FROM hosts WHERE ip_address='192.168.1.1'")


def test_block_guards(env):
    acc, ssh, db, net, sec = env
    add_gw_creds(db, net)
    for ip in ("192.168.1.100", "192.168.1.1", "192.168.1.2", "192.168.1.101", "10.9.9.9", "127.0.0.1", "224.0.0.1", "xx"):
        with pytest.raises(AccessRefused):
            acc.block(ip, simulate=True)
    assert ssh.calls == []


def test_block_without_linux_gateway_gives_manual_plan(env):
    acc, ssh, db, net, sec = env
    with pytest.raises(AccessRefused, match="passerelle Linux"):
        acc.block("192.168.1.30", simulate=True)
    plan = acc.manual_plan("192.168.1.30")
    assert "192.168.1.30" in plan and "rien n'est envoyé" in plan


def test_block_simulation_then_disabled_then_execute_and_unblock(env):
    acc, ssh, db, net, sec = env
    add_gw_creds(db, net)
    r = acc.block("192.168.1.30", "test", simulate=True)
    assert r["status"] == "simulated" and "procus-block" in r["command"] and ssh.calls == []
    with pytest.raises(AccessRefused, match="désactivée"):
        acc.block("192.168.1.30", "test")
    db.set_setting("actions_execution_enabled", "1")
    r = acc.block("192.168.1.30", "intrus")
    assert r["status"] == "blocked" and len(ssh.calls) == 2
    assert all(c.startswith("sudo -n iptables -I FORWARD") for c in ssh.calls)
    assert db.fetchone("SELECT 1 FROM audit_logs WHERE action='device_block_blocked'")
    with pytest.raises(AccessRefused, match="déjà bloqué"):
        acc.block("192.168.1.30")
    ssh.calls.clear()
    u = acc.unblock(r["id"])
    assert u["status"] == "lifted" and len(ssh.calls) == 2 and all(" -D FORWARD" in c for c in ssh.calls)
    assert db.fetchone("SELECT status FROM device_blocks WHERE id=?", (r["id"],))["status"] == "lifted"


def test_block_partial_failure_rolls_back(env):
    acc, ssh, db, net, sec = env
    add_gw_creds(db, net)
    db.set_setting("actions_execution_enabled", "1")
    acc.ssh_runner = FakeSsh(fail_on="-d 192.168.1.30")
    r = acc.block("192.168.1.30")
    assert r["status"] == "failed" and "annulation" in r["output"]
    assert acc.ssh_runner.calls[-1].startswith("sudo -n iptables -D FORWARD -s")


def test_block_needs_permission(env):
    acc, ssh, db, net, sec = env
    add_gw_creds(db, net)
    class Deny:
        def has_permission(self, p): return False
        def get_current_user(self): return {"login": "x"}
    acc.security = Deny()
    with pytest.raises(AccessRefused, match="droit"):
        acc.block("192.168.1.30", simulate=True)
    with pytest.raises(AccessRefused, match="droit"):
        acc.remove("192.168.1.30")


def test_ui_tab_selects_device_and_actions(qapp, db, security, net, monkeypatch):
    assert security.authenticate("admin", "admin")
    for fn in ("information", "warning"):
        monkeypatch.setattr(QMessageBox, fn, lambda *a, **k: None)
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes)
    from PyQt6.QtWidgets import QInputDialog
    monkeypatch.setattr(QInputDialog, "getText", lambda *a, **k: ("motif", True))
    m = DefenseManager(db, security)
    try:
        add_gw_creds(db, net)
        m.access.ssh_runner = FakeSsh()
        m.bandwidth.sample(now=T0)
        FlowStore(db).add("192.168.1.30", "192.168.1.10", "tcp", 445, 8000, 8)
        m.bandwidth.sample(now=T0 + 10)
        v = SecurityView(db=db, security=security, manager=m)
        t = v.bwtab
        t.refresh()
        assert len(t.dev_bars.rows) >= 2
        t.select("192.168.1.30")
        assert "cam-1" in t.info.text() and t.peers.rowCount() >= 1
        t._block(True)
        assert db.fetchone("SELECT status FROM device_blocks")["status"] == "simulated"
        t._remove()
        assert is_ignored(db, "192.168.1.30") and t.removed.rowCount() == 1
        t.removed.selectRow(0); t._restore()
        assert not is_ignored(db, "192.168.1.30")
        for w in (t.gw_bars, t.dev_bars, t.line):
            w.grab()                                   # le rendu ne plante pas
    finally:
        m.stop()
