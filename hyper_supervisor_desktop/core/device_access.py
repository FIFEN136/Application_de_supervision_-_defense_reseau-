"""
Procus Secure — retirer un équipement de la supervision / bloquer sa connexion.

RETIRER (réversible, sans effet sur le réseau) : l'équipement est supprimé de la supervision et mémorisé dans
« ignored_devices » pour que la découverte ne le rajoute pas ; « rétablir » le fait redécouvrir.

BLOQUER (action réseau, garde-fous) : couper un appareil du réseau exige un POINT D'APPLICATION qui fait passer son
trafic. Procus Secure sait en piloter un seul : une passerelle LINUX (iptables FORWARD) jointe par SSH, avec des
identifiants enregistrés. Pour un routeur Cisco, un point d'accès Wi-Fi, un pare-feu… un plan manuel est fourni
(aucune commande n'est envoyée). Jamais d'usurpation ARP.
  • droit « can_manage_config » ; exécution réelle seulement si « actions_execution_enabled » = 1 ;
    la simulation est toujours possible ;
  • refus : cette machine, passerelles/routeurs/commutateurs/pare-feu/AP, agents, administrateurs, adresses spéciales,
    équipements inconnus ; modèles de commande fixes, IP validée ; chaque blocage porte un commentaire « procus-block » ;
  • échec partiel → retour arrière automatique ; « lever le blocage » exécute la commande inverse ; tout est audité.
"""
from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Callable, Optional

from loguru import logger

from core import local_network as lnet
from core.config_backup import ConfigBackupManager, ssh_run_commands
from core.netmap import NetMapper
from core.policy import protected_context

TAG = "procus-block"


class AccessRefused(Exception):
    """Refus affichable."""


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def is_ignored(db, ip: str) -> bool:
    return bool(db.fetchone("SELECT 1 FROM ignored_devices WHERE ip = ?", (ip,)))


class DeviceAccess:
    def __init__(self, db, security=None, sink=None, ssh_runner: Optional[Callable] = None):
        self.db, self.security, self.sink = db, security, sink
        self.ssh_runner = ssh_runner or ssh_run_commands
        self._cfg = ConfigBackupManager(db, sink)

    # ───────── utilitaires ─────────
    def _user(self) -> str:
        u = self.security.get_current_user() if self.security else None
        return (u or {}).get("login") or "système"

    def _need(self):
        if self.security is not None and not self.security.has_permission("can_manage_config"):
            raise AccessRefused("Votre rôle ne permet pas cette opération (droit « can_manage_config »).")

    def enabled(self) -> bool:
        return self.db.get_setting("actions_execution_enabled", "0") == "1"

    @staticmethod
    def _ip(ip: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
        try:
            a = ipaddress.ip_address((ip or "").strip())
        except ValueError:
            raise AccessRefused(f"Adresse invalide : « {ip} ».") from None
        if a.is_multicast or a.is_unspecified or a.is_loopback:
            raise AccessRefused(f"Refusé : {a} est une adresse spéciale.")
        return a

    def _host(self, ip: str) -> dict:
        h = self.db.fetchone("SELECT * FROM hosts WHERE ip_address = ? ORDER BY id LIMIT 1", (ip,))
        if not h:
            raise AccessRefused(f"{ip} n'est pas un équipement connu de la supervision.")
        return h

    def _protection(self, h: dict, strict: bool) -> Optional[str]:
        """Motif de protection ou None. strict=True (blocage) : tous les équipements d'infrastructure."""
        ip = h["ip_address"]
        pc = protected_context(self.db)
        if ip in pc["local"] or lnet.is_local_address(ip):
            return "c'est CETTE machine (la couper arrêterait la supervision)"
        if ip in pc["devices"]:
            return "c'est une passerelle / un équipement d'infrastructure (routeur, commutateur, pare-feu, point d'accès)"
        if strict and ip in pc["agents"]:
            return "un agent Procus y est installé (équipement supervisé en continu)"
        if strict and ip in pc["admins"]:
            return "il est classé « administration » ou protégé"
        return None

    # ───────── retirer de la supervision ─────────
    def remove(self, ip: str, reason: str = "", who: Optional[str] = None) -> dict:
        who = who or self._user()
        self._need()
        self._ip(ip)
        h = self._host(ip)
        why = self._protection(h, strict=False)
        if why:
            raise AccessRefused(f"Refusé : {why}.")
        self.db.execute("INSERT OR REPLACE INTO ignored_devices (ip, mac, name, reason, removed_by, removed_at) "
                        "VALUES (?,?,?,?,?,datetime('now'))", (ip, h.get("mac_address"), h["name"], reason, who))
        self.db.execute("DELETE FROM hosts WHERE id = ?", (h["id"],))
        self.db.write_audit(who, "device_removed", f"{h['name']} ({ip})", reason or "retiré de la supervision")
        logger.warning(f"[ACCÈS] {h['name']} ({ip}) retiré de la supervision par {who}")
        return {"name": h["name"], "ip": ip}

    def removed(self) -> list[dict]:
        return self.db.fetchall("SELECT * FROM ignored_devices ORDER BY removed_at DESC")

    def restore(self, ip: str, who: Optional[str] = None) -> bool:
        who = who or self._user()
        self._need()
        row = self.db.fetchone("SELECT * FROM ignored_devices WHERE ip = ?", (ip,))
        if not row:
            return False
        self.db.execute("DELETE FROM ignored_devices WHERE ip = ?", (ip,))
        self.db.write_audit(who, "device_restored", f"{row['name']} ({ip})", "la découverte pourra le rajouter")
        return True

    # ───────── bloquer la connexion ─────────
    def manual_plan(self, ip: str) -> str:
        h = self.db.fetchone("SELECT * FROM hosts WHERE ip_address = ?", (ip,)) or {}
        mac = h.get("mac_address") or "?"
        where = NetMapper(self.db).where_is(mac) if h.get("mac_address") else None
        port = f"{where['switch']} port {where['port']}" if where else "(port non relevé — lancez le relevé SNMP)"
        return (f"Plan MANUEL pour couper {ip} (MAC {mac}) — à appliquer sur votre équipement, rien n'est envoyé :\n"
                f"• Commutateur géré ({port}) : désactiver le port (Cisco : « interface <port> » puis « shutdown »).\n"
                f"• Routeur / pare-feu : règle de refus pour {ip} (Cisco ACL : « deny ip host {ip} any » placée avant le permit).\n"
                f"• Point d'accès Wi-Fi : bloquer l'adresse MAC {mac} (liste de filtrage MAC) ou déconnecter le client.\n"
                f"• Passerelle Linux : « iptables -I FORWARD -s {ip} -j DROP » et « -d {ip} ».\n"
                f"Annulation : opération inverse.")

    def _gateway(self) -> tuple[dict, dict]:
        """Passerelle Linux utilisable : hôte avec identifiants SSH de profil « linux »."""
        gws = {n["gateway_ip"] for n in self.db.fetchall("SELECT gateway_ip FROM networks WHERE gateway_ip IS NOT NULL")}
        gw = lnet.get_default_gateway()
        if gw:
            gws.add(gw)
        for ip in sorted(gws):
            h = self.db.fetchone("SELECT * FROM hosts WHERE ip_address = ?", (ip,))
            cred = self._cfg.get_credentials(h["id"], with_secret=True) if h else None
            if cred and cred["profile"] == "linux":
                return h, cred
        raise AccessRefused("Aucune passerelle Linux avec accès SSH enregistré (Défense active → Configurations). "
                            "Blocage non automatisable ici.")

    def build_plan(self, ip: str) -> dict:
        a = self._ip(ip)
        h = self._host(str(a))
        why = self._protection(h, strict=True)
        if why:
            raise AccessRefused(f"Refusé : {why}.")
        if a.version != 4:
            raise AccessRefused("Blocage automatique limité à IPv4.")
        gh, cred = self._gateway()
        steps = [f"sudo -n iptables -I FORWARD 1 -s {a} -m comment --comment {TAG} -j DROP",
                 f"sudo -n iptables -I FORWARD 1 -d {a} -m comment --comment {TAG} -j DROP"]
        undo = [f"sudo -n iptables -D FORWARD -s {a} -m comment --comment {TAG} -j DROP",
                f"sudo -n iptables -D FORWARD -d {a} -m comment --comment {TAG} -j DROP"]
        return {"host": h, "gateway": gh, "steps": steps, "rollback": undo,
                "where": f"{gh['name']} ({gh['ip_address']}) par SSH", "display": " && ".join(steps)}

    def _ssh(self, gateway_id: int, cmds: list[str]) -> tuple[bool, str, int]:
        cred = self._cfg.get_credentials(gateway_id, with_secret=True)
        out, done = [], 0
        for c in cmds:
            res = self.ssh_runner(cred, [c])[0]
            out.append(f"$ {c}\n[{res['rc']}] {res['out']}".strip())
            if res["rc"] != 0:
                return False, "\n".join(out), done
            done += 1
        return True, "\n".join(out), done

    def block(self, ip: str, reason: str = "", simulate: bool = False, who: Optional[str] = None) -> dict:
        who = who or self._user()
        self._need()
        if self.db.fetchone("SELECT 1 FROM device_blocks WHERE ip = ? AND status = 'blocked'", (ip,)):
            raise AccessRefused(f"{ip} est déjà bloqué.")
        if not simulate and not self.enabled():
            raise AccessRefused("L'exécution automatique est désactivée (Paramètres → Défense active). "
                                "Utilisez « Simuler » ou activez-la.")
        plan = self.build_plan(ip)
        name = plan["host"]["name"]
        rb = " && ".join(plan["rollback"])
        if simulate:
            bid = self.db.execute(
                "INSERT INTO device_blocks (ip, mac, name, gateway_id, status, command, rollback, output, reason, by_user) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (ip, plan["host"].get("mac_address"), name, plan["gateway"]["id"], "simulated", plan["display"], rb,
                 f"SIMULATION — rien n'a été exécuté sur {plan['where']}.", reason, who)).lastrowid
            return {"id": bid, "status": "simulated", "where": plan["where"], "command": plan["display"], "rollback": rb}
        ok, out, done = self._ssh(plan["gateway"]["id"], plan["steps"])
        if not ok and done:
            _, undo_out, _ = self._ssh(plan["gateway"]["id"], plan["rollback"][:done])
            out += "\n-- annulation des étapes déjà appliquées --\n" + undo_out
        status = "blocked" if ok else "failed"
        bid = self.db.execute(
            "INSERT INTO device_blocks (ip, mac, name, gateway_id, status, command, rollback, output, reason, by_user) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (ip, plan["host"].get("mac_address"), name, plan["gateway"]["id"], status, plan["display"], rb, out,
             reason, who)).lastrowid
        self.db.write_audit(who, f"device_block_{status}", f"{name} ({ip})", f"{plan['where']} : {reason}")
        logger.warning(f"[ACCÈS] blocage {name} ({ip}) → {status} (par {who})")
        return {"id": bid, "status": status, "where": plan["where"], "command": plan["display"], "rollback": rb,
                "output": out}

    def unblock(self, block_id: int, who: Optional[str] = None) -> dict:
        who = who or self._user()
        self._need()
        b = self.db.fetchone("SELECT * FROM device_blocks WHERE id = ?", (block_id,))
        if not b or b["status"] != "blocked":
            raise AccessRefused("Seul un blocage actif peut être levé.")
        ok, out, _ = self._ssh(b["gateway_id"], b["rollback"].split(" && "))
        if ok:
            self.db.execute("UPDATE device_blocks SET status='lifted', lifted_at=?, output=output||? WHERE id=?",
                            (_now(), f"\n-- LEVÉE par {who} --\n{out}", block_id))
        self.db.write_audit(who, "device_unblock_ok" if ok else "device_unblock_failed", f"{b['name']} ({b['ip']})", "")
        return {"id": block_id, "status": "lifted" if ok else "unblock_failed", "output": out}

    def blocks(self) -> list[dict]:
        return self.db.fetchall("SELECT * FROM device_blocks ORDER BY id DESC LIMIT 200")
