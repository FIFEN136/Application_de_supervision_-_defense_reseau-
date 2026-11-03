"""
Procus Secure — exécution RÉELLE des actions de réponse, après validation humaine.

Garde-fous (tous obligatoires) :
  1. l'action doit avoir été APPROUVÉE par un humain (Incidents → Approuver) ;
  2. l'exécution automatique doit être activée dans les paramètres (« actions_execution_enabled », désactivée par défaut) ;
  3. l'utilisateur doit avoir le droit « can_manage_config » ;
  4. aucune commande libre : chaque action est fabriquée à partir d'un modèle fixe dont les arguments (IP, port)
     sont validés ; ni shell, ni enchaînement de commandes ;
  5. chaque exécution garde la commande exacte ET la commande d'annulation, et passe par le journal d'audit HMAC ;
  6. une « simulation » montre ce qui serait lancé sans rien changer.

Actions exécutables aujourd'hui (les autres restent des plans à appliquer à la main) :
  • block_ip, cible « 10.0.0.5 »       → bloque cette IP dans le pare-feu DE CE POSTE (Windows : netsh ; Linux : iptables) ;
  • block_ip, cible « 10.0.0.5:3389 »  → ferme ce port sur l'équipement distant (Linux) par SSH + iptables.
"""
from __future__ import annotations

import ipaddress
import platform
import shlex
import subprocess
from datetime import datetime
from typing import Callable, Optional

from loguru import logger

from core import local_network as lnet
from core.config_backup import ConfigBackupManager, ssh_run_commands

EXECUTABLE_TYPES = {"block_ip"}


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


class ActionRefused(Exception):
    """Une règle de sécurité interdit l'exécution (message affichable)."""


class ActionRunner:
    def __init__(self, db, security=None, sink=None, ssh_runner: Optional[Callable] = None,
                 local_runner: Optional[Callable] = None, system: Optional[str] = None):
        self.db, self.security, self.sink = db, security, sink
        self.ssh_runner = ssh_runner or ssh_run_commands
        self.local_runner = local_runner or self._run_local
        self.system = system or platform.system()
        self._cfg = ConfigBackupManager(db, sink) if sink else None

    # ───────────── état ─────────────
    def enabled(self) -> bool:
        return self.db.get_setting("actions_execution_enabled", "0") == "1"

    def set_enabled(self, on: bool, who: str = "système"):
        self.db.set_setting("actions_execution_enabled", "1" if on else "0")
        self.db.write_audit(who, "actions_execution_enabled" if on else "actions_execution_disabled", "", "")

    def _user(self) -> str:
        u = self.security.get_current_user() if self.security else None
        return (u or {}).get("login") or "système"

    @staticmethod
    def _run_local(argv: list[str]) -> tuple[int, str]:
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=20, errors="ignore")
            return r.returncode, (r.stdout + r.stderr).strip()
        except (OSError, subprocess.TimeoutExpired) as e:
            return 127, str(e)

    # ───────────── fabrication du plan (modèles fixes) ─────────────
    def _protected_ips(self) -> set[str]:
        prot = set(lnet.get_local_addresses()) | {"127.0.0.1", "::1"}
        try:
            g = lnet.get_default_gateway()
            if g:
                prot.add(g)
        except Exception:
            pass
        for r in self.db.fetchall("SELECT gateway_ip FROM networks WHERE gateway_ip IS NOT NULL"):
            prot.add(r["gateway_ip"])
        return prot

    def build_plan(self, action: dict) -> dict:
        """{'kind','where','steps':[...],'rollback':[...],'display':str} ou lève ActionRefused."""
        if action["action_type"] not in EXECUTABLE_TYPES:
            raise ActionRefused(f"Le type « {action['action_type']} » n'est pas exécutable automatiquement : "
                                f"appliquez le plan manuellement.")
        target = (action.get("target") or "").strip()
        ip_s, _, port_s = target.partition(":")
        try:
            ip = ipaddress.ip_address(ip_s)
        except ValueError:
            raise ActionRefused(f"Cible invalide : « {target} ».") from None
        if ip.is_multicast or ip.is_unspecified or ip.is_loopback or str(ip) in self._protected_ips():
            raise ActionRefused(f"Refusé : {ip} est cette machine, la passerelle ou une adresse spéciale — "
                                f"la bloquer couperait la supervision.")
        aid = action["id"]
        if not port_s:
            if self.system == "Windows":
                steps = [["netsh", "advfirewall", "firewall", "add", "rule", f"name=HSR-block-{aid}-in", "dir=in",
                          "action=block", f"remoteip={ip}"],
                         ["netsh", "advfirewall", "firewall", "add", "rule", f"name=HSR-block-{aid}-out", "dir=out",
                          "action=block", f"remoteip={ip}"]]
                rollback = [["netsh", "advfirewall", "firewall", "delete", "rule", f"name=HSR-block-{aid}-in"],
                            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name=HSR-block-{aid}-out"]]
            elif self.system == "Linux":
                steps = [["iptables", "-I", "INPUT", "-s", str(ip), "-j", "DROP"],
                         ["iptables", "-I", "OUTPUT", "-d", str(ip), "-j", "DROP"]]
                rollback = [["iptables", "-D", "INPUT", "-s", str(ip), "-j", "DROP"],
                            ["iptables", "-D", "OUTPUT", "-d", str(ip), "-j", "DROP"]]
            else:
                raise ActionRefused(f"Pare-feu local non pris en charge sur {self.system}.")
            return {"kind": "local_block_ip", "where": "pare-feu de ce poste", "steps": steps, "rollback": rollback,
                    "display": " && ".join(shlex.join(s) for s in steps)}
        # port distant
        try:
            port = int(port_s)
            assert 1 <= port <= 65535
        except (ValueError, AssertionError):
            raise ActionRefused(f"Port invalide : « {port_s} ».") from None
        host = self.db.fetchone("SELECT id, name FROM hosts WHERE ip_address = ? ORDER BY id LIMIT 1", (str(ip),))
        cred = self._cfg.get_credentials(host["id"], with_secret=True) if host and self._cfg else None
        if not cred:
            raise ActionRefused(f"Aucun accès SSH enregistré pour {ip} (Défense active → Configurations) : "
                                f"appliquez le plan manuellement.")
        if cred["profile"] != "linux":
            raise ActionRefused("Fermeture de port à distance disponible uniquement pour les équipements Linux "
                                "(profil « linux »).")
        if port == int(cred.get("port") or 22):
            raise ActionRefused("Refusé : fermer le port SSH couperait l'accès que Procus Secure utilise.")
        cmd = f"sudo -n iptables -I INPUT -p tcp --dport {port} -j DROP"
        undo = f"sudo -n iptables -D INPUT -p tcp --dport {port} -j DROP"
        return {"kind": "remote_block_port", "where": f"{host['name']} ({ip}) par SSH", "steps": [cmd],
                "rollback": [undo], "display": cmd, "host_id": host["id"]}

    # ───────────── exécution ─────────────
    def _apply(self, plan: dict, steps: list) -> tuple[bool, str, int]:
        out, done = [], 0
        for st in steps:
            if plan["kind"] == "remote_block_port":
                cred = self._cfg.get_credentials(plan["host_id"], with_secret=True)
                res = self.ssh_runner(cred, [st])[0]
                rc, txt = res["rc"], res["out"]
            else:
                rc, txt = self.local_runner(st)
            out.append(f"$ {st if isinstance(st, str) else shlex.join(st)}\n[{rc}] {txt}".strip())
            if rc != 0:
                return False, "\n".join(out), done
            done += 1
        return True, "\n".join(out), done

    def execute(self, action_id: int, who: Optional[str] = None, simulate: bool = False) -> dict:
        who = who or self._user()
        a = self.db.fetchone("SELECT * FROM pending_actions WHERE id = ?", (action_id,))
        if not a:
            raise ActionRefused("Action introuvable.")
        if self.security is not None and not self.security.has_permission("can_manage_config"):
            raise ActionRefused("Votre rôle ne permet pas d'exécuter des actions (droit « can_manage_config »).")
        if a["status"] != "approved":
            raise ActionRefused("L'action doit d'abord être APPROUVÉE par un humain.")
        if not simulate and not self.enabled():
            raise ActionRefused("L'exécution automatique est désactivée (Paramètres → Défense active). "
                                "Utilisez « Simuler » ou activez-la.")
        if self.db.fetchone("SELECT 1 FROM action_runs WHERE action_id = ? AND status = 'ok'", (action_id,)):
            raise ActionRefused("Cette action a déjà été exécutée (annulez-la d'abord si nécessaire).")
        plan = self.build_plan(a)
        now = _now()
        if simulate:
            rid = self.db.execute(
                "INSERT INTO action_runs (action_id, kind, command, rollback, status, output, executed_by, finished_at) "
                "VALUES (?, ?, ?, ?, 'simulated', ?, ?, ?)",
                (action_id, plan["kind"], plan["display"], " && ".join(
                    s if isinstance(s, str) else shlex.join(s) for s in plan["rollback"]),
                 f"SIMULATION — rien n'a été exécuté sur {plan['where']}.", who, now)).lastrowid
            return {"run_id": rid, "status": "simulated", "kind": plan["kind"], "where": plan["where"],
                    "command": plan["display"], "output": "Simulation : aucune modification."}
        ok, output, done = self._apply(plan, plan["steps"])
        if not ok and done:                                       # étape 2 échouée : on défait l'étape 1
            _, undo_out, _ = self._apply(plan, plan["rollback"][:done])
            output += "\n-- annulation des étapes déjà appliquées --\n" + undo_out
        status = "ok" if ok else "failed"
        rb = " && ".join(s if isinstance(s, str) else shlex.join(s) for s in plan["rollback"])
        rid = self.db.execute(
            "INSERT INTO action_runs (action_id, kind, command, rollback, status, output, executed_by, finished_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (action_id, plan["kind"], plan["display"], rb, status, output, who, _now())).lastrowid
        self.db.write_audit(who, f"action_executed_{status}", f"action:{action_id}",
                            f"{plan['kind']} sur {plan['where']} : {plan['display']}")
        logger.warning(f"[ACTION] #{action_id} {plan['kind']} → {status} (par {who})")
        return {"run_id": rid, "status": status, "kind": plan["kind"], "where": plan["where"],
                "command": plan["display"], "rollback": rb, "output": output}

    def rollback(self, run_id: int, who: Optional[str] = None) -> dict:
        who = who or self._user()
        run = self.db.fetchone("SELECT * FROM action_runs WHERE id = ?", (run_id,))
        if not run or run["status"] != "ok":
            raise ActionRefused("Seule une exécution réussie peut être annulée.")
        if self.security is not None and not self.security.has_permission("can_manage_config"):
            raise ActionRefused("Votre rôle ne permet pas d'annuler des actions.")
        a = self.db.fetchone("SELECT * FROM pending_actions WHERE id = ?", (run["action_id"],))
        plan = self.build_plan(a) if a else None
        if not plan:
            raise ActionRefused("Action d'origine introuvable.")
        ok, output, _ = self._apply(plan, plan["rollback"])
        status = "rolled_back" if ok else "ok"             # échec d'annulation : l'état reste « ok » (toujours appliquée)
        self.db.execute("UPDATE action_runs SET status = ?, output = output || ?, finished_at = ? WHERE id = ?",
                        (status, f"\n-- ANNULATION par {who} --\n{output}", _now(), run_id))
        self.db.write_audit(who, "action_rolled_back" if ok else "action_rollback_failed", f"action:{run['action_id']}",
                            plan["display"])
        return {"run_id": run_id, "status": "rolled_back" if ok else "rollback_failed", "output": output}

    def runs_for(self, action_id: int) -> list[dict]:
        return self.db.fetchall("SELECT * FROM action_runs WHERE action_id = ? ORDER BY id DESC", (action_id,))
