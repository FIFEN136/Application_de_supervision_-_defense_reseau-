import os, urllib.request
import pytest
from core import netguard
from core.logging_setup import redact


@pytest.mark.parametrize("url", ["http://127.0.0.1/x", "http://169.254.169.254/latest", "http://192.168.1.5/h", "http://10.0.0.1/",
                                 "http://[::1]/", "http://localhost:8080/", "file:///etc/passwd", "ftp://a.b/", "http://user:pw@8.8.8.8/",
                                 "http://[::ffff:127.0.0.1]/", "http://0.0.0.0/"])
def test_ssrf_blocked(url):
    assert netguard.check_url(url)[0] is False


def test_ssrf_allowlist_and_public():
    assert netguard.check_url("http://192.168.1.5/h", "192.168.1.0/24")[0]
    assert netguard.check_url("http://10.0.0.1/", "10.0.0.1")[0]
    assert not netguard.check_url("http://192.168.2.5/h", "192.168.1.0/24")[0]
    assert netguard.check_url("http://8.8.8.8/")[0]


def test_no_redirect():
    class R(urllib.request.HTTPRedirectHandler): pass
    h = netguard._NoRedirect()
    assert h.redirect_request(None, None, 302, "", {}, "http://127.0.0.1") is None


def test_notifier_refuses_internal_webhook(db):
    from core.notifier import NotifierManager
    n = NotifierManager(db)
    ok, msg = n._send_webhook_ex({"description": "x"}, {"webhook_url": "http://127.0.0.1:9/x"}, "w")
    assert not ok and "refus" in msg.lower()
    ok, msg = n._send_slack_ex({"description": "x"}, {"webhook_url": "http://169.254.169.254/"}, "s")
    assert not ok and "refus" in msg.lower()


def test_log_redaction_and_file(tmp_path, monkeypatch):
    assert "hunter2" not in redact("password=hunter2 token: abc123")
    monkeypatch.setenv("PROCUS_LOG_DIR", str(tmp_path / "logs"))
    from core import logging_setup
    monkeypatch.setattr(logging_setup, "_installed", False)
    from loguru import logger
    d = logging_setup.setup_logging()
    logger.info("test api_key=SECRETVALUE")
    logger.complete()
    txt = (d / "procus.log").read_text(encoding="utf-8")
    assert "test api_key=***" in txt and "SECRETVALUE" not in txt


def test_agent_rate_limit_and_bind(db):
    from core.agent_server import AgentServer
    s = AgentServer(db, None, None, port=0, bind="127.0.0.1", rate_per_min=3)
    assert [s.allow_ip("1.2.3.4") for _ in range(5)] == [True, True, True, False, False]
    assert s.allow_ip("5.6.7.8")
    assert s.start() and s._httpd.server_address[0] == "127.0.0.1"
    s.stop()
