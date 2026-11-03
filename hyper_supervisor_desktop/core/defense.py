"""
Procus Secure — gestionnaire de la défense active (v13/v14).

Orchestre les services : honeypots, surveillance ARP, sonde DHCP, serveur d'agents, récepteur syslog, contrôle
d'intégrité local, sauvegardes de configuration SSH. Chaque service s'active/désactive depuis l'interface
(Défense active) ; les réglages sont dans la table `settings`. Valeurs par défaut prudentes :

    ARP (passif)  ON      Sonde DHCP (1 diffusion / 6 h)  ON      Intégrité locale  ON
    Honeypots     OFF     Serveur d'agents                OFF     Récepteur syslog  OFF      (ouvrent des ports)

Les alertes de tous les services sortent par le signal `alert` (→ notifications) après enregistrement en base.
"""
from __future__ import annotations

import os
import threading
import time
from typing import Optional

from loguru import logger
from PyQt6.QtCore import QObject, pyqtSignal

from core import local_network as lnet
from core.action_runner import ActionRunner
from core.agent_server import AgentRegistry, AgentServer, cert_fingerprint, generate_self_signed
from core.config_backup import ConfigBackupManager
from core.defense_common import EventSink
from core.fim import check_local
from core.honeypot import HoneypotManager, load_ports
from core import assess as assess_mod
from core.bandwidth import BandwidthManager
from core.device_access import DeviceAccess
from core.flows import FlowStore, NetflowCollector, ingest_connections, local_connections
from core.netmap import NetMapper
from core.policy import PolicyManager
from core.log_pipeline import LogPipeline, SyslogReceiver
from core.netdefense import ArpWatcher, DhcpProbe

DEFAULTS = {
    "defense_honeypot": "0", "defense_arp": "1", "defense_dhcp": "1", "defense_agents": "0",
    "defense_syslog": "0", "defense_fim_local": "1",
    "defense_netflow": "0", "netflow_port": "2055", "netflow_exporters": "",
    "defense_assess": "1", "defense_netmap": "1", "defense_flows_local": "1", "policy_default": "allow",
    "agent_port": "8765", "agent_bind": "0.0.0.0", "webhook_allow_internal": "", "agent_tls": "1", "syslog_port": "5514",
    "config_backup_interval_h": "24", "db_backup_interval_h": "24", "db_backup_keep": "7", "db_backup_dir": "", "dhcp_interval_h": "6", "log_retention_days": "14",
}


class DefenseManager(QObject):
    alert = pyqtSignal(dict)                 # événement de sécurité (déjà enregistré en base)
    log_message = pyqtSignal(str, str)       # (niveau, message) → console
    changed = pyqtSignal()                   # l'état d'un service a changé (rafraîchir l'interface)

    def __init__(self, db, security=None, parent=None):
        super().__init__(parent)
        self.db, self.security = db, security
        self.sink = EventSink(db, on_alert=self._on_alert)
        self.pipeline = LogPipeline(db, self.sink)
        self.honeypots = HoneypotManager(db, self.sink)
        self.arp = ArpWatcher(db, self.sink)
        self.dhcp = DhcpProbe(db, self.sink)
        self.config = ConfigBackupManager(db, self.sink)
        self.runner = ActionRunner(db, security, self.sink)
        self.registry = AgentRegistry(db)
        self.flows = FlowStore(db)
        self.netmap = NetMapper(db)
        self.policy = PolicyManager(db, security)
        self.bandwidth = BandwidthManager(db)
        self.access = DeviceAccess(db, security, self.sink)
        self.netflow: Optional[NetflowCollector] = None
        self.agent_server: Optional[AgentServer] = None
        self.syslog: Optional[SyslogReceiver] = None
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last: dict[str, float] = {}
        self._lock = threading.RLock()
        self.errors: dict[str, str] = {}
        for k, v in DEFAULTS.items():                       # réglages par défaut (n'écrase jamais un choix existant)
            if not self.db.fetchone("SELECT 1 FROM settings WHERE key = ?", (k,)):
                self.db.set_setting(k, v)

    # ───────────── réglages ─────────────
    def setting(self, key: str) -> str:
        return self.db.get_setting(key, DEFAULTS.get(key, ""))

    def enabled(self, key: str) -> bool:
        return self.setting(key) == "1"

    def set_enabled(self, key: str, on: bool, who: str = "système"):
        self.db.set_setting(key, "1" if on else "0")
        try:
            self.db.write_audit(who, f"{key}_{'on' if on else 'off'}", "defense", "")
        except Exception:
            pass
        self.apply()

    def _on_alert(self, event: dict):
        self.log_message.emit("WARNING", f"[Défense] {event.get('description', '')[:200]}")
        self.alert.emit(event)

    # ───────────── cycle de vie ─────────────
    def start(self):
        self.apply()
        if not self._thread or not self._thread.is_alive():
            self._stop.clear()
            self._thread = threading.Thread(target=self._loop, name="defense-scheduler", daemon=True)
            self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        self._thread = None
        with self._lock:
            self.honeypots.stop()
            if self.agent_server:
                self.agent_server.stop()
            if self.syslog:
                self.syslog.stop()
            if self.netflow:
                self.netflow.stop()

    def apply(self):
        """Aligne les services sur les réglages (démarre ce qui est activé, arrête le reste)."""
        with self._lock:
            # honeypots
            if self.enabled("defense_honeypot"):
                self.honeypots.ports = load_ports(self.db)
                if not self.honeypots.running:
                    st = self.honeypots.start()
                    bad = [f"{p}: {s}" for p, s in st.items() if s != "à l'écoute"]
                    self.errors["honeypot"] = "; ".join(bad)
                    ok = sum(1 for v in st.values() if v == "à l'écoute")
                    self.log_message.emit("INFO", f"[Défense] Honeypots démarrés : {ok}/{len(st)} port(s) à l'écoute")
            elif self.honeypots.running:
                self.honeypots.stop(); self.errors.pop("honeypot", None)
            # agents
            if self.enabled("defense_agents"):
                if not (self.agent_server and self.agent_server.running):
                    self.agent_server = self._build_agent_server()
                    ok = self.agent_server.start()
                    self.errors["agents"] = "" if ok else (self.agent_server.error or "démarrage impossible")
            elif self.agent_server and self.agent_server.running:
                self.agent_server.stop(); self.errors.pop("agents", None)
            # syslog
            if self.enabled("defense_syslog"):
                if not (self.syslog and self.syslog.running):
                    self.syslog = SyslogReceiver(self.pipeline, port=int(self.setting("syslog_port") or 5514))
                    ok = self.syslog.start()
                    self.errors["syslog"] = "" if ok else (self.syslog.error or "démarrage impossible")
            elif self.syslog and self.syslog.running:
                self.syslog.stop(); self.errors.pop("syslog", None)
            # collecteur de flux NetFlow v5
            if self.enabled("defense_netflow"):
                if not (self.netflow and self.netflow.running):
                    allowed = {x.strip() for x in self.setting("netflow_exporters").split(",") if x.strip()}
                    self.netflow = NetflowCollector(self.flows, port=int(self.setting("netflow_port") or 2055), allowed=allowed)
                    ok = self.netflow.start()
                    self.errors["netflow"] = "" if ok else (self.netflow.error or "démarrage impossible")
            elif self.netflow and self.netflow.running:
                self.netflow.stop(); self.errors.pop("netflow", None)
        self.changed.emit()

    # ───────────── agents : certificat et configuration ─────────────
    def _tls_dir(self) -> str:
        d = os.path.join(os.path.dirname(os.path.abspath(self.db.db_path)), "agent_tls")
        os.makedirs(d, exist_ok=True)
        return d

    def _build_agent_server(self) -> AgentServer:
        cert = key = None
        if self.enabled("agent_tls"):
            d = self._tls_dir(); cert, key = os.path.join(d, "server.pem"), os.path.join(d, "server.key")
            if not (os.path.exists(cert) and os.path.exists(key)):
                generate_self_signed(cert, key)
            self.db.set_setting("agent_cert_fp", cert_fingerprint(cert))
        return AgentServer(self.db, self.sink, self.pipeline, port=int(self.setting("agent_port") or 8765),
                           bind=(self.setting("agent_bind") or "0.0.0.0").strip(),
                           certfile=cert, keyfile=key)

    def agent_config(self, enrolled: dict, server_host: Optional[str] = None) -> dict:
        """Contenu du fichier agent_config.json à copier sur la machine de l'agent."""
        host = server_host or lnet.get_primary_ip() or "127.0.0.1"
        tls = self.enabled("agent_tls")
        cfg = {"server": f"{'https' if tls else 'http'}://{host}:{self.setting('agent_port') or 8765}",
               "agent_id": enrolled["agent_id"], "secret": enrolled["secret"]}
        if tls:
            if not self.db.get_setting("agent_cert_fp", ""):
                d = self._tls_dir(); cert, key = os.path.join(d, "server.pem"), os.path.join(d, "server.key")
                if not (os.path.exists(cert) and os.path.exists(key)):
                    generate_self_signed(cert, key)
                self.db.set_setting("agent_cert_fp", cert_fingerprint(cert))
            cfg["server_fingerprint"] = self.db.get_setting("agent_cert_fp", "")
        return cfg

    # ───────────── état pour l'interface ─────────────
    def status(self) -> dict:
        hp = self.honeypots
        return {
            "honeypot": {"enabled": self.enabled("defense_honeypot"), "running": hp.running, "detail": dict(hp.status),
                         "error": self.errors.get("honeypot", "")},
            "arp": {"enabled": self.enabled("defense_arp"), "running": self.enabled("defense_arp"), "error": ""},
            "dhcp": {"enabled": self.enabled("defense_dhcp"), "running": self.enabled("defense_dhcp"),
                     "trusted": self.dhcp.trusted(), "error": ""},
            "agents": {"enabled": self.enabled("defense_agents"), "running": bool(self.agent_server and self.agent_server.running),
                       "tls": self.enabled("agent_tls"), "port": self.setting("agent_port"), "error": self.errors.get("agents", "")},
            "syslog": {"enabled": self.enabled("defense_syslog"), "running": bool(self.syslog and self.syslog.running),
                       "port": self.setting("syslog_port"), "received": getattr(self.syslog, "received", 0),
                       "error": self.errors.get("syslog", "")},
            "netflow": {"enabled": self.enabled("defense_netflow"), "running": bool(self.netflow and self.netflow.running),
                        "port": self.setting("netflow_port"), "received": getattr(self.netflow, "received", 0),
                        "refused": getattr(self.netflow, "refused", 0), "error": self.errors.get("netflow", "")},
            "fim": {"enabled": self.enabled("defense_fim_local"), "running": self.enabled("defense_fim_local"), "error": ""},
            "actions": {"enabled": self.runner.enabled(), "running": self.runner.enabled(), "error": ""},
        }

    # ───────────── tâches périodiques ─────────────
    def _due(self, name: str, every_s: float) -> bool:
        now = time.monotonic()
        if name not in self._last:                    # premier passage : 30 s après le démarrage (n'alourdit pas l'ouverture)
            self._last[name] = now - every_s + 30
        if now - self._last[name] >= every_s:
            self._last[name] = now
            return True
        return False

    def run_job(self, name: str) -> object:
        """Exécute une tâche immédiatement (aussi utilisée par les boutons « Vérifier maintenant »)."""
        if name == "arp":
            return self.arp.check()
        if name == "dhcp":
            return self.dhcp.check()
        if name == "fim":
            return check_local(self.db, self.sink)
        if name == "backup":
            return self.config.backup_all()
        if name == "silent":
            return self.agent_server.check_silent() if self.agent_server else []
        if name == "assess":
            return assess_mod.run_assessment(self.db, self.sink)
        if name == "netmap":
            return self.netmap.collect_all()
        if name == "flows_local":
            ip = lnet.get_primary_ip() or ""
            return ingest_connections(self.flows, local_connections(), "local", ip)
        if name == "bandwidth":
            return self.bandwidth.sample()
        if name == "mail":
            from core.notifier import NotifierManager
            return NotifierManager(self.db).flush_outbox()
        if name == "devinfo":
            from core import device_info
            return device_info.refresh_connection_info(self.db)
        if name == "enrich":
            from core import enrichment
            return enrichment.enrich_all(self.db)
        if name == "box":
            from core import box_reader
            return box_reader.refresh_from_box(self.db)
        if name == "dbbackup":
            return self.backup_database()
        if name == "purge":
            self.pipeline.purge(); self.honeypots.purge(); self.flows.purge(); self.bandwidth.purge()
            from core.mailer import Outbox
            Outbox(self.db).purge()
            return True
        raise ValueError(name)

    def backup_database(self) -> str:
        """Sauvegarde chiffrée de la base (même clé), vérifiée après écriture ; garde les N plus récentes."""
        import glob
        from datetime import datetime
        from pathlib import Path
        folder = Path(self.setting("db_backup_dir") or (Path.home() / ".procus_hsr" / "backups"))
        folder.mkdir(parents=True, exist_ok=True)
        if os.name == "posix":
            os.chmod(folder, 0o700)
        dest = str(folder / f"procus_{datetime.now():%Y%m%d_%H%M%S}.db")
        self.db.backup_to(dest)
        ok, msg = self.db.validate_backup(dest, getattr(self.db, "_key_hex", None))
        if not ok:
            try:
                os.remove(dest)
            except OSError:
                pass
            raise RuntimeError(f"Sauvegarde de la base invalide : {msg}")
        keep = max(1, int(self.setting("db_backup_keep") or 7))
        for old in sorted(glob.glob(str(folder / "procus_*.db")))[:-keep]:
            try:
                os.remove(old)
            except OSError:
                pass
        logger.success(f"[Défense] Sauvegarde de la base : {dest}")
        return dest

    def _spawn_netmap(self):
        t = getattr(self, "_netmap_thread", None)
        if t and t.is_alive():
            return

        def work():
            try:
                self.run_job("netmap")
            except Exception as e:
                logger.warning(f"[Défense] relevé SNMP : {e}")
        self._netmap_thread = threading.Thread(target=work, name="defense-netmap", daemon=True)
        self._netmap_thread.start()

    def _loop(self):
        while not self._stop.wait(5):
            jobs = []
            if self.enabled("defense_arp") and self._due("arp", 60):
                jobs.append("arp")
            if self.enabled("defense_dhcp") and self._due("dhcp", float(self.setting("dhcp_interval_h") or 6) * 3600):
                jobs.append("dhcp")
            if self.enabled("defense_fim_local") and self._due("fim", 900):
                jobs.append("fim")
            h = float(self.setting("config_backup_interval_h") or 0)
            if h > 0 and self._due("backup", h * 3600):
                jobs.append("backup")
            if self.enabled("defense_assess") and self._due("assess", 6 * 3600):
                jobs.append("assess")
            if self.enabled("defense_netmap") and self._due("netmap", 6 * 3600):
                jobs.append("netmap")
            if self.enabled("defense_flows_local") and self._due("flows_local", 300):
                jobs.append("flows_local")
            if self.enabled("defense_agents") and self._due("silent", 60):
                jobs.append("silent")
            if self._due("bandwidth", 60):
                jobs.append("bandwidth")
            if self._due("mail", 60):
                jobs.append("mail")
            if self._due("devinfo", 300):
                jobs.append("devinfo")
            if self._due("enrich", 600):
                jobs.append("enrich")
            if self.db.get_setting("box_enabled", "0") == "1" and self._due("box", 120):
                jobs.append("box")
            hb = float(self.setting("db_backup_interval_h") or 0)
            if hb > 0 and self._due("dbbackup", hb * 3600):
                jobs.append("dbbackup")
            if self._due("purge", 86400):
                jobs.append("purge")
            for j in jobs:
                if self._stop.is_set():
                    return
                if j == "netmap":                      # relevé SNMP potentiellement long : thread séparé, jamais bloquant
                    self._spawn_netmap()
                    continue
                try:
                    self.run_job(j)
                except Exception as e:
                    logger.warning(f"[Défense] tâche « {j} » : {e}")
                    self.log_message.emit("ERROR", f"[Défense] tâche « {j} » en erreur : {e}")
