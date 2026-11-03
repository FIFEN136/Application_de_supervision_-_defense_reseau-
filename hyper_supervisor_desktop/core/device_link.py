"""
Procus Secure — connexion à un équipement réseau (routeur, pare-feu, commutateur, borne, box) depuis la carte réseau.

Quatre moyens, au choix, pour lire les vraies informations de l'équipement :
  · SSH           identifiant + mot de passe (ou clé privée) ; commandes de LECTURE SEULE uniquement ; empreinte de la clé mémorisée
  · Interface web identifiant + mot de passe sur la page d'administration / API (HTTP Basic) ; certificat auto-signé accepté
  · SNMP          communauté (v1 / v2c) ; lit nom, description, durée de fonctionnement
  · Box           Bbox (liste des appareils, voir core/box_reader.py)
Les secrets sont chiffrés. Un équipement hors réseau local (VPN, site distant) exige une case cochée explicitement.
Rien n'est inventé : ce que l'équipement ne dit pas reste non renseigné.
"""
from __future__ import annotations

import base64
import ipaddress
import re
import ssl
import urllib.error
import urllib.request
from typing import Optional

from loguru import logger

from core.security import CryptoHelper

METHODS = (("auto", "Automatique (recommandé) : l'application choisit"), ("ssh", "SSH (identifiant + mot de passe ou clé)"), ("web", "Interface web / API (identifiant + mot de passe)"),
           ("snmp", "SNMP (communauté)"), ("box", "Box Internet (Bbox)"))
KINDS = (("router", "Routeur / box"), ("firewall", "Pare-feu"), ("switch", "Commutateur"), ("ap", "Borne Wi-Fi"),
         ("server", "Serveur"), ("unknown", "Autre équipement"))
OID_DESCR, OID_NAME, OID_UPTIME = "1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.3.0"


class LinkError(Exception):
    pass


def check_target(ip: str, allow_public: bool = False) -> str:
    """Adresse valide : réseau local par défaut ; adresse publique seulement si l'utilisateur l'a demandé ; jamais boucle locale ni lien-local."""
    try:
        a = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        raise LinkError("Adresse IP invalide (exemple : 192.168.1.254).")
    if a.is_loopback or a.is_unspecified or a.is_multicast or a.is_link_local or a.is_reserved:
        raise LinkError("Cette adresse ne peut pas être utilisée (boucle locale, multidiffusion ou adresse réservée).")
    if not a.is_private and not allow_public:
        raise LinkError("Adresse hors de votre réseau local. Cochez « Cet équipement est hors de mon réseau local » si c'est voulu (VPN, site distant).")
    return str(a)


def _clean(s: str, n: int = 160) -> str:
    return re.sub(r"[\x00-\x1f\x7f]", " ", s or "").strip()[:n]


# ───────────── SSH ─────────────
IDENT_COMMANDS = ("show version", "get system status", "display version", "/system resource print", "uname -a")      # lecture seule


def _ssh_commands(profile: str) -> list[str]:
    one = {"cisco_ios": "show version", "juniper": "show version", "fortinet": "get system status", "huawei": "display version",
           "mikrotik": "/system resource print", "linux": "uname -a"}
    return [one[profile]] if profile in one else list(IDENT_COMMANDS)      # « auto » : on essaie toutes les identifications


def ssh_error(e: Exception, port: int) -> str:
    n = type(e).__name__
    if "Authentication" in n:
        return "Identifiant ou mot de passe refusé par l'équipement."
    if "NoValidConnections" in n or "Refused" in n or isinstance(e, ConnectionRefusedError):
        return (f"Le port SSH {port} est fermé : cet équipement n'accepte pas SSH (c'est normal pour une box Internet grand public). "
                "Choisissez « Automatique » ou « Box Internet », ou activez SSH sur l'équipement.")
    if "Timeout" in n or isinstance(e, TimeoutError) or "timed out" in str(e).lower():
        return f"Pas de réponse sur le port {port} : adresse incorrecte, équipement éteint ou pare-feu qui bloque."
    if "SSHException" in n and "banner" in str(e).lower():
        return "Le port répond mais ce n'est pas un serveur SSH."
    return f"Connexion SSH impossible ({n})."


def test_ssh(address: str, username: str, secret: str, auth_type: str = "password", port: int = 22, profile: str = "auto",
             runner=None, host_key: Optional[str] = None) -> dict:
    from core import config_backup as cb
    cred = {"address": address, "username": username.strip(), "secret": secret, "auth_type": auth_type, "port": int(port), "host_key": host_key}
    if not cred["username"]:
        raise LinkError("Nom d'utilisateur requis.")
    cmds = [c for c in _ssh_commands(profile) if cb.validate_command(c)]
    try:
        res = (runner or cb.ssh_run_commands)(cred, cmds, 12.0)
    except cb.HostKeyChanged as e:
        raise LinkError(f"Clé SSH modifiée : équipement remplacé ou interception possible. Connexion refusée. ({e})")
    except cb.SshUnavailable as e:
        raise LinkError(str(e))
    except Exception as e:
        raise LinkError(ssh_error(e, int(port)))
    out = next((r["out"] for r in res if r["rc"] == 0 and r["out"].strip()), "")
    if not out:
        raise LinkError("Connecté, mais l'équipement n'a répondu à aucune commande d'identification : choisissez le type de système exact.")
    first = next((ln for ln in out.splitlines() if ln.strip()), "")
    used = next((r["cmd"] for r in res if r["rc"] == 0 and r["out"].strip()), "")
    guess = {"show version": "cisco_ios", "get system status": "fortinet", "display version": "huawei",
             "/system resource print": "mikrotik", "uname -a": "linux"}.get(used, "linux")
    return {"ok": True, "info": _clean(first, 120), "host_key": cred.get("host_key_seen"), "profile": guess,
            "message": f"SSH réussi : {_clean(first, 100)}"}


# ───────────── Interface web / API ─────────────
def test_web(address: str, port: int = 443, scheme: str = "https", username: str = "", password: str = "", path: str = "/") -> dict:
    if scheme not in ("http", "https"):
        raise LinkError("Protocole : http ou https.")
    if not path.startswith("/") or ".." in path or len(path) > 200:
        raise LinkError("Chemin invalide.")
    url = f"{scheme}://{address}:{int(port)}{path}"
    req = urllib.request.Request(url, headers={"User-Agent": "ProcusSecure"})            # nosec B310 - schéma http/https contrôlé
    if username:
        req.add_header("Authorization", "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode())
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE                            # nosec B501 - équipements à certificat auto-signé
    public = False
    if username:                                       # la page s'ouvre-t-elle SANS identifiant ? alors rien n'est vérifié
        try:
            plain = urllib.request.Request(url, headers={"User-Agent": "ProcusSecure"})   # nosec B310
            with urllib.request.urlopen(plain, timeout=6, context=ctx) as r0:             # nosec B310
                public = r0.status == 200
        except Exception:
            public = False
    try:
        with urllib.request.urlopen(req, timeout=6, context=ctx) as r:                    # nosec B310
            body = r.read(64 * 1024).decode("utf-8", "ignore")
            server = r.headers.get("Server", "")
            code = r.status
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            raise LinkError("Identifiant ou mot de passe refusé par l'équipement." if username else
                            "L'équipement demande un identifiant : renseignez-le.")
        raise LinkError(f"L'équipement a répondu avec l'erreur {e.code}.")
    except (urllib.error.URLError, OSError) as e:
        raise LinkError(f"Page injoignable ({type(e).__name__}) : vérifiez l'adresse, le port {port} et le protocole.")
    title = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    t = _clean(re.sub(r"<[^>]+>", "", title.group(1)) if title else "", 80)
    info = " · ".join(x for x in (t, _clean(server, 40)) if x)
    msg = f"Page d'administration atteinte (code {code})" + (f" : {info}" if info else "")
    if public or not username:
        msg += " — page publique : vos identifiants n'ont PAS été vérifiés."
    return {"ok": True, "info": info, "authenticated": bool(username) and not public, "message": msg}


# ───────────── SNMP ─────────────
def test_snmp(address: str, community: str = "public", version: str = "2c", port: int = 161) -> dict:
    from core.monitor import MonitorWorker
    w = MonitorWorker(None)
    got = {k: w._snmp_get(address, oid, community or "public", port=int(port), timeout=2, retries=1, version=version)
           for k, oid in (("descr", OID_DESCR), ("name", OID_NAME), ("uptime", OID_UPTIME))}
    if all(v is None for v in got.values()):
        raise LinkError("Aucune réponse SNMP : vérifiez la communauté, la version et que SNMP est activé sur l'équipement.")
    descr = _clean(str(got["descr"] or ""), 120)
    name = _clean(str(got["name"] or ""), 60)
    return {"ok": True, "info": descr or name, "name": name,
            "message": "SNMP réussi : " + " · ".join(x for x in (name, descr[:80]) if x)}


# ───────────── détection automatique ─────────────
PROBE_PORTS = (22, 80, 443, 8080, 8443, 161)


def detect_open_ports(address: str, timeout: float = 0.8) -> list[int]:
    import socket
    from concurrent.futures import ThreadPoolExecutor

    def one(port):
        s = socket.socket()
        s.settimeout(timeout)
        try:
            return port if s.connect_ex((address, port)) == 0 else None
        except OSError:
            return None
        finally:
            s.close()
    with ThreadPoolExecutor(max_workers=len(PROBE_PORTS)) as ex:
        return sorted(p for p in ex.map(one, PROBE_PORTS) if p)


def auto_attempts(open_ports: list[int]) -> list[str]:
    """Moyens à essayer, dans l'ordre, d'après les ports réellement ouverts (SNMP/UDP est toujours tenté en dernier)."""
    out = []
    if 80 in open_ports or 443 in open_ports:
        out.append("box")
        out.append("web")
    if 8080 in open_ports or 8443 in open_ports:
        out.append("web")
    if 22 in open_ports:
        out.insert(0, "ssh")
    out.append("snmp")
    seen = []
    return [m for m in out if not (m in seen or seen.append(m))]


def _try_auto(addr: str, p: dict) -> dict:
    ports = detect_open_ports(addr)
    tried = []
    for m in auto_attempts(ports):
        q = dict(p, method=m)
        if m == "web":
            q["port"] = 443 if 443 in ports else 8443 if 8443 in ports else 80 if 80 in ports else 8080
            q["scheme"] = "https" if q["port"] in (443, 8443) else "http"
        if m == "ssh" and not p.get("username"):
            tried.append("SSH : identifiant manquant"); continue
        if m == "ssh":
            q["port"], q["profile"] = 22, "auto"
        if m == "snmp":
            q["port"] = 161
        try:
            r = connect(None, q, save=False)
            if m == "web" and not r.get("authenticated"):
                tried.append("Interface web : la page s'ouvre sans mot de passe (" + (r.get("info") or "serveur web") + "), ce n'est pas une connexion")
                continue
            r["method"], r["params"] = m, q
            r["open_ports"] = ports
            return r
        except LinkError as e:
            detail = str(e) if m == "box" else str(e).splitlines()[0][:110]       # la box : diagnostic complet, étape par étape
            tried.append(f"{dict(METHODS)[m].split(' (')[0]} : {detail}")
    shown = ", ".join(map(str, ports)) or "aucun"
    raise LinkError(f"Aucun moyen n'a fonctionné. Ports ouverts sur {addr} : {shown}.\n" + "\n".join(tried))


# ───────────── enregistrement ─────────────
def ensure_host(db, address: str, name: str = "", kind: str = "router") -> int:
    row = db.fetchone("SELECT id FROM hosts WHERE ip_address = ?", (address,))
    if row:
        return row["id"]
    if kind not in dict(KINDS):
        kind = "unknown"
    return db.add_host(_clean(name, 60) or f"{dict(KINDS)[kind].split(' /')[0]}-{address.split('.')[-1] if '.' in address else address}", address, device_type=kind)


def connect(db, p: dict, who: str = "system", save: bool = True) -> dict:
    """p = {method, address, name, kind, allow_public, port, username, secret, auth_type, profile, scheme, community, version}.
    Teste ; si `save`, enregistre (hôte, secrets chiffrés, type choisi) et inscrit les informations réellement lues sur la fiche."""
    method = p.get("method")
    addr = check_target(p.get("address", ""), bool(p.get("allow_public")))
    if method == "auto":
        r = _try_auto(addr, p)
        if not save:
            r["message"] += f" (moyen détecté : {dict(METHODS)[r['method']].split(' (')[0]})"
            return r
        p = dict(r["params"])
        method = p["method"]
        r["message"] += f" (moyen détecté : {dict(METHODS)[method].split(' (')[0]})"
    elif method == "ssh":
        r = test_ssh(addr, p.get("username", ""), p.get("secret", ""), p.get("auth_type", "password"), int(p.get("port") or 22), p.get("profile", "linux"))
    elif method == "web":
        r = test_web(addr, int(p.get("port") or 443), p.get("scheme", "https"), p.get("username", ""), p.get("secret", ""))
    elif method == "snmp":
        r = test_snmp(addr, p.get("community", "public"), p.get("version", "2c"), int(p.get("port") or 161))
    elif method == "box":
        from core import box_reader
        ok, msg = box_reader.test_connection(addr, p.get("secret", ""))
        if not ok:
            raise LinkError(msg)
        r = {"ok": True, "info": "Box Internet", "message": msg}
    else:
        raise LinkError("Choisissez un moyen de connexion.")
    if not save:
        return r
    hid = ensure_host(db, addr, p.get("name", ""), p.get("kind", "router"))
    if p.get("kind") in dict(KINDS) and p.get("kind") != "unknown":
        db.execute("UPDATE hosts SET device_type = ?, type_source = 'manual' WHERE id = ?", (p["kind"], hid))
    if method == "ssh":
        from core.config_backup import ConfigBackupManager
        if p.get("profile") in (None, "", "auto"):
            p["profile"] = r.get("profile", "linux")
        mgr = ConfigBackupManager(db, sink=None)
        mgr.set_credentials(hid, p["username"], p.get("secret", ""), p.get("auth_type", "password"), int(p.get("port") or 22),
                            p.get("profile", "linux"), backup_enabled=False)
        if r.get("host_key"):
            db.execute("UPDATE host_credentials SET host_key = ? WHERE host_id = ?", (r["host_key"], hid))
    elif method == "web":
        db.execute("INSERT OR REPLACE INTO device_logins (host_id, method, port, scheme, username, secret_enc, updated_at) "
                   "VALUES (?, 'web', ?, ?, ?, ?, datetime('now'))",
                   (hid, int(p.get("port") or 443), p.get("scheme", "https"), _clean(p.get("username", ""), 60),
                    CryptoHelper.encrypt(p.get("secret", "")) if p.get("secret") else None))
    elif method == "snmp":
        db.execute("UPDATE hosts SET snmp_enabled = 1, snmp_community = ?, snmp_version = ?, snmp_port = ? WHERE id = ?",
                   (db._encrypt_community(p.get("community", "public")), p.get("version", "2c"), int(p.get("port") or 161), hid))
    elif method == "box":
        from core import box_reader
        box_reader.save_settings(db, True, addr, p.get("secret", ""))
        box_reader.refresh_from_box(db)
    info = r.get("info") or ""
    if info and method in ("ssh", "snmp", "web"):
        db.execute("UPDATE hosts SET model = COALESCE(NULLIF(model, ''), ?) WHERE id = ?", (info[:80], hid))
    db.write_audit(who, "device_connect", f"{addr}", f"méthode={method}")
    logger.info(f"[LINK] {addr} connecté par {method}")
    r["host_id"] = hid
    return r
