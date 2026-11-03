"""
Procus Secure — sauvegarde de configuration par SSH, avec historique et comparaison (style Oxidized).

Principe : pour chaque équipement ayant des identifiants SSH, Procus Secure se connecte, lance des commandes de
LECTURE SEULE (show running-config, display current-configuration, /export…), nettoie les lignes qui changent
toutes seules (horodatages), et ne crée une nouvelle version que si la configuration a réellement changé.
Un changement déclenche l'événement « config_change » (le pipeline propose alors une action de restauration).

Sécurité :
  • mots de passe / clés privées ET configurations sont chiffrés au repos (Fernet) ;
  • empreinte de la clé d'hôte mémorisée à la 1re connexion ; si elle change → alerte (équipement remplacé ou
    attaque man-in-the-middle) et la connexion est refusée ;
  • seules des commandes de lecture issues d'une liste blanche peuvent être exécutées.
"""
from __future__ import annotations

import base64
import difflib
import hashlib
import io
import json
import re
from typing import Callable, Optional

from loguru import logger

from core.security import CryptoHelper

PROFILES = {
    "cisco_ios": {"label": "Cisco IOS / IOS-XE", "commands": ["show running-config"],
                  "volatile": [r"^! Last configuration change", r"^! NVRAM config last updated", r"^ntp clock-period",
                               r"^Building configuration", r"^Current configuration : \d+ bytes"]},
    "juniper":   {"label": "Juniper JunOS", "commands": ["show configuration"],
                  "volatile": [r"^## Last (changed|commit)"]},
    "mikrotik":  {"label": "MikroTik RouterOS", "commands": ["/export"],
                  "volatile": [r"^# \S+ \d+:\d+:\d+ by RouterOS", r"^# software id"]},
    "fortinet":  {"label": "Fortinet FortiGate", "commands": ["show full-configuration"],
                  "volatile": [r"^#config-version"]},
    "huawei":    {"label": "Huawei VRP", "commands": ["display current-configuration"],
                  "volatile": [r"^!Software Version", r"^!Last configuration"]},
    "linux":     {"label": "Linux (serveur)", "commands": ["uname -a", "ip -br addr", "ip route",
                  "cat /etc/ssh/sshd_config", "cat /etc/hosts", "cat /etc/resolv.conf"], "volatile": []},
    "custom":    {"label": "Personnalisé (commandes de lecture)", "commands": [], "volatile": []},
}

_ARG = r"[A-Za-z0-9_./:=\-]+"
READ_ONLY_PATTERNS = [
    re.compile(rf"^(show|display|get|export|/export)( {_ARG})*( \| (display|include|section|begin|grep|no-more|count)( {_ARG})*)?$"),
    re.compile(r"^cat /(etc|proc|sys)/[A-Za-z0-9_./\-]+$"),
    re.compile(r"^uname( -[a-z]+)?$"), re.compile(r"^hostnamectl$"),
    re.compile(r"^ip( -[a-z0-9]+)* (addr|address|route|link|neigh|rule)( show)?$"),
    re.compile(r"^ifconfig( -a)?$"), re.compile(r"^iptables-save$"), re.compile(r"^nft list ruleset$"),
    re.compile(r"^(ss|netstat) -[a-z]+$"),
    re.compile(r"^/system (resource|identity|routerboard) print$"),          # MikroTik : identification en lecture seule
]
SECRET_RE = re.compile(r"(?i)\b(password|secret|community|key|token|passphrase)\b(\s+(?:\d\s+)?)(\S+)")


class HostKeyChanged(Exception):
    pass


class SshUnavailable(Exception):
    pass


def validate_command(cmd: str) -> bool:
    """Seules les commandes de lecture connues sont acceptées (aucune écriture, aucun enchaînement shell)."""
    cmd = (cmd or "").strip()
    return 0 < len(cmd) <= 200 and any(p.match(cmd) for p in READ_ONLY_PATTERNS)


def mask_secrets(text: str) -> str:
    return SECRET_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}***", text)


def _fp(key) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


def ssh_run_commands(cred: dict, commands: list[str], timeout: float = 20.0, host: str = "") -> list[dict]:
    """
    Exécute les commandes et retourne [{cmd, rc, out}]. cred = {username, secret, auth_type, port, host_key, address}.
    Lève HostKeyChanged / SshUnavailable / paramiko.AuthenticationException… Met à jour cred["host_key_seen"].
    """
    try:
        import paramiko
    except ImportError as e:
        raise SshUnavailable("La bibliothèque « paramiko » n'est pas installée (pip install paramiko).") from e

    class _TOFU(paramiko.MissingHostKeyPolicy):
        def missing_host_key(self, client, hostname, key):
            fp = _fp(key)
            cred["host_key_seen"] = fp
            if cred.get("host_key") and cred["host_key"] != fp:
                raise HostKeyChanged(f"Clé d'hôte modifiée pour {hostname} : attendu {cred['host_key']}, reçu {fp}")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(_TOFU())
    kw = dict(hostname=host or cred["address"], port=int(cred.get("port") or 22), username=cred["username"],
              timeout=timeout, banner_timeout=timeout, auth_timeout=timeout, allow_agent=False, look_for_keys=False)
    if cred.get("auth_type") == "key":
        pkey = None
        for cls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
            try:
                pkey = cls.from_private_key(io.StringIO(cred["secret"]))
                break
            except Exception:
                continue
        if pkey is None:
            raise paramiko.AuthenticationException("Clé privée illisible (format non pris en charge ou protégée par phrase secrète)")
        kw["pkey"] = pkey
    else:
        kw["password"] = cred.get("secret") or ""
    out = []
    try:
        client.connect(**kw)
        for cmd in commands:
            stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)  # nosec B601 - commandes fixes de lecture issues du catalogue interne
            data = stdout.read().decode("utf-8", "replace")
            err = stderr.read().decode("utf-8", "replace")
            rc = stdout.channel.recv_exit_status()
            out.append({"cmd": cmd, "rc": rc, "out": data if rc == 0 or data else err})
    finally:
        client.close()
    return out


class ConfigBackupManager:
    KEEP_VERSIONS = 50

    def __init__(self, db, sink, runner: Optional[Callable] = None):
        self.db, self.sink = db, sink
        self.runner = runner or ssh_run_commands

    # ───────────── identifiants ─────────────
    def set_credentials(self, host_id: int, username: str, secret: str, auth_type: str = "password",
                        port: int = 22, profile: str = "cisco_ios", commands: Optional[list[str]] = None,
                        backup_enabled: bool = True):
        if profile not in PROFILES:
            raise ValueError(f"Profil inconnu : {profile}")
        if not username.strip():
            raise ValueError("Nom d'utilisateur requis.")
        if auth_type not in ("password", "key"):
            raise ValueError("Type d'authentification invalide.")
        if not 1 <= int(port) <= 65535:
            raise ValueError("Port SSH invalide.")
        cmds = [c.strip() for c in (commands or []) if c.strip()]
        bad = [c for c in cmds if not validate_command(c)]
        if bad:
            raise ValueError("Commande refusée (lecture seule uniquement) : " + bad[0])
        if profile == "custom" and not cmds:
            raise ValueError("Profil personnalisé : indiquez au moins une commande de lecture.")
        if not self.db.get_host_by_id(host_id):
            raise ValueError("Équipement introuvable.")
        old = self.db.fetchone("SELECT host_key, secret_enc FROM host_credentials WHERE host_id = ?", (host_id,))
        secret_enc = CryptoHelper.encrypt(secret) if secret else (old or {}).get("secret_enc")
        self.db.execute(
            "INSERT OR REPLACE INTO host_credentials (host_id, username, secret_enc, auth_type, port, profile, commands, "
            "host_key, backup_enabled, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))",
            (host_id, username.strip(), secret_enc, auth_type, int(port), profile,
             json.dumps(cmds) if cmds else None, (old or {}).get("host_key"), int(backup_enabled)))

    def get_credentials(self, host_id: int, with_secret: bool = False) -> Optional[dict]:
        row = self.db.fetchone("SELECT * FROM host_credentials WHERE host_id = ?", (host_id,))
        if not row:
            return None
        host = self.db.get_host_by_id(host_id) or {}
        row["address"] = host.get("ip_address")
        row["commands"] = json.loads(row["commands"]) if row.get("commands") else []
        enc = row.pop("secret_enc", None)
        row["has_secret"] = bool(enc)
        if with_secret:
            row["secret"] = CryptoHelper.decrypt(enc) if enc else ""
        return row

    def clear_credentials(self, host_id: int):
        self.db.execute("DELETE FROM host_credentials WHERE host_id = ?", (host_id,))

    def forget_host_key(self, host_id: int):
        """À utiliser après avoir VÉRIFIÉ qu'un équipement a bien été remplacé."""
        self.db.execute("UPDATE host_credentials SET host_key = NULL WHERE host_id = ?", (host_id,))

    def commands_for(self, cred: dict) -> list[str]:
        cmds = cred.get("commands") or PROFILES[cred.get("profile", "custom")]["commands"]
        return [c for c in cmds if validate_command(c)]

    # ───────────── normalisation / diff ─────────────
    @staticmethod
    def normalize(text: str, profile: str) -> str:
        volatile = [re.compile(p) for p in PROFILES.get(profile, {}).get("volatile", [])]
        lines = []
        for ln in text.replace("\r", "").split("\n"):
            ln = ln.rstrip()
            if any(v.search(ln) for v in volatile):
                continue
            lines.append(ln)
        while lines and not lines[-1]:
            lines.pop()
        return "\n".join(lines)

    @staticmethod
    def unified_diff(old: str, new: str, a: str = "avant", b: str = "après") -> str:
        return "\n".join(difflib.unified_diff(old.split("\n"), new.split("\n"), a, b, lineterm="", n=2))

    # ───────────── sauvegarde ─────────────
    def backup_host(self, host_id: int) -> dict:
        cred = self.get_credentials(host_id, with_secret=True)
        host = self.sink.host_by_id(host_id) or {"id": host_id, "name": f"host {host_id}"}
        if not cred:
            return {"status": "error", "error": "Aucun identifiant SSH enregistré pour cet équipement."}
        cmds = self.commands_for(cred)
        if not cmds:
            return {"status": "error", "error": "Aucune commande de lecture valide pour ce profil."}
        try:
            results = self.runner(cred, cmds)
        except HostKeyChanged as e:
            self.sink.emit("disaster", "ssh_hostkey_changed",
                           f"{host['name']} : la clé SSH de l'équipement a changé — équipement remplacé OU attaque "
                           f"man-in-the-middle. Sauvegarde refusée. ({e})", host=host,
                           tags=["attack.credential_access", "attack.t1557"])
            return {"status": "error", "error": str(e), "hostkey_changed": True}
        except Exception as e:
            logger.warning(f"[CFG] {host['name']} : {e}")
            return {"status": "error", "error": f"{type(e).__name__}: {e}"}
        if not results or all(r["rc"] != 0 for r in results):
            return {"status": "error", "error": "Aucune commande n'a réussi : " + "; ".join(
                f"{r['cmd']} → {(r['out'] or '').strip()[:80]}" for r in results)}
        seen = cred.get("host_key_seen")
        if seen and not cred.get("host_key"):                       # confiance à la 1re connexion
            self.db.execute("UPDATE host_credentials SET host_key = ? WHERE host_id = ?", (seen, host_id))
        raw = "\n".join(f"### {r['cmd']}\n{r['out']}" for r in results if r["rc"] == 0)
        text = self.normalize(raw, cred["profile"])
        fp = hashlib.sha256(text.encode("utf-8")).hexdigest()
        last = self.db.fetchone("SELECT * FROM config_backups WHERE host_id = ? ORDER BY id DESC LIMIT 1", (host_id,))
        if last and last["fingerprint"] == fp:
            return {"status": "unchanged", "backup_id": last["id"]}
        added = removed = 0
        diff = ""
        if last:
            old = CryptoHelper.decrypt(last["content"])
            diff = self.unified_diff(old, text, f"v{last['id']}", "nouvelle")
            added = sum(1 for d in diff.split("\n") if d.startswith("+") and not d.startswith("+++"))
            removed = sum(1 for d in diff.split("\n") if d.startswith("-") and not d.startswith("---"))
        bid = self.db.execute(
            "INSERT INTO config_backups (host_id, fingerprint, content, size, lines_added, lines_removed) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (host_id, fp, CryptoHelper.encrypt(text), len(text), added, removed)).lastrowid
        self.purge(host_id)
        if not last:
            return {"status": "first", "backup_id": bid}
        changed = [d for d in diff.split("\n") if d[:1] in "+-" and not d.startswith(("+++", "---"))]
        sample = "; ".join(mask_secrets(d)[:90] for d in changed[:4])
        self.sink.emit("high", "config_change",
                       f"Configuration de {host['name']} modifiée (+{added} / -{removed} lignes) : {sample}",
                       host=host, tags=["attack.defense_evasion", "attack.t1562"], extra={"backup_id": bid})
        return {"status": "changed", "backup_id": bid, "added": added, "removed": removed}

    def backup_all(self) -> list[dict]:
        out = []
        for row in self.db.fetchall("SELECT host_id FROM host_credentials WHERE backup_enabled = 1"):
            res = self.backup_host(row["host_id"])
            res["host_id"] = row["host_id"]
            out.append(res)
        return out

    # ───────────── consultation ─────────────
    def history(self, host_id: int, limit: int = 50) -> list[dict]:
        return self.db.fetchall(
            "SELECT id, fingerprint, size, lines_added, lines_removed, collected_at FROM config_backups "
            "WHERE host_id = ? ORDER BY id DESC LIMIT ?", (host_id, limit))

    def get_content(self, backup_id: int) -> Optional[str]:
        row = self.db.fetchone("SELECT content FROM config_backups WHERE id = ?", (backup_id,))
        return CryptoHelper.decrypt(row["content"]) if row else None

    def diff(self, id_a: int, id_b: int, hide_secrets: bool = True) -> str:
        a, b = self.get_content(id_a), self.get_content(id_b)
        if a is None or b is None:
            return ""
        d = self.unified_diff(a, b, f"v{id_a}", f"v{id_b}")
        return mask_secrets(d) if hide_secrets else d

    def purge(self, host_id: int):
        self.db.execute(
            "DELETE FROM config_backups WHERE host_id = ? AND id NOT IN "
            "(SELECT id FROM config_backups WHERE host_id = ? ORDER BY id DESC LIMIT ?)",
            (host_id, host_id, self.KEEP_VERSIONS))
