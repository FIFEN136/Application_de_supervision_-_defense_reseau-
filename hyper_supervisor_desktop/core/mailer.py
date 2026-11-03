"""
Procus Secure — service e-mail intégré.

Deux modes d'envoi, au choix de l'utilisateur :
  • « relay »  : via un serveur SMTP (celui d'un fournisseur : Gmail, Outlook, OVH… ou un relais interne). Sécurité
                 automatique (SSL sur 465, STARTTLS sinon) ; jamais d'identifiants envoyés en clair ;
  • « direct » : Procus Secure remet LUI-MÊME le message au serveur de messagerie du destinataire (recherche de
                 l'enregistrement MX, port 25, chiffrement opportuniste). Aucun compte SMTP à créer. Limite : beaucoup de
                 fournisseurs d'accès bloquent le port 25 sortant et un envoi direct peut être classé en courrier
                 indésirable (SPF / DNS inverse absents) — le diagnostic l'explique en clair.

Fonctions communes : assistant de diagnostic pas à pas (DNS → connexion → chiffrement → identification → destinataire →
envoi), et FILE D'ATTENTE (mail_outbox) : une alerte qui n'a pas pu partir faute de réseau est renvoyée automatiquement
(1, 5, 15, 60 minutes… 8 essais) au lieu d'être perdue.
"""
from __future__ import annotations

import random
import smtplib
import socket
import ssl
import struct
from datetime import datetime, timedelta
from email.utils import parseaddr
from typing import Callable, Optional


PRESETS = {
    "Gmail":              {"host": "smtp.gmail.com", "port": 587, "security": "starttls",
                           "help": "Activez la validation en 2 étapes puis créez un « mot de passe d'application » (compte Google → Sécurité)."},
    "Outlook / Hotmail":  {"host": "smtp-mail.outlook.com", "port": 587, "security": "starttls",
                           "help": "Utilisez votre adresse complète ; si l'authentification est refusée, créez un mot de passe d'application."},
    "Microsoft 365":      {"host": "smtp.office365.com", "port": 587, "security": "starttls",
                           "help": "L'administrateur doit autoriser « SMTP authentifié » pour la boîte utilisée."},
    "Yahoo":              {"host": "smtp.mail.yahoo.com", "port": 465, "security": "ssl",
                           "help": "Créez un « mot de passe d'application » dans la sécurité du compte Yahoo."},
    "OVH":                {"host": "ssl0.ovh.net", "port": 465, "security": "ssl", "help": "Adresse e-mail complète et son mot de passe."},
    "Infomaniak":         {"host": "mail.infomaniak.com", "port": 587, "security": "starttls", "help": "Adresse e-mail complète et son mot de passe."},
    "Zoho":               {"host": "smtp.zoho.eu", "port": 465, "security": "ssl", "help": "Mot de passe d'application recommandé."},
}
SECURITY_CHOICES = {"auto": "Automatique (recommandé)", "starttls": "STARTTLS (port 587)", "ssl": "SSL/TLS (port 465)",
                    "none": "Aucune (relais interne uniquement)"}
RETRY_MINUTES = (1, 5, 15, 60, 180, 360, 720, 1440)
MAX_ATTEMPTS = len(RETRY_MINUTES)
PUBLIC_RESOLVERS = [("1.1.1.1", 53), ("8.8.8.8", 53)]


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


# ───────────────────────── DNS : enregistrements MX (sans bibliothèque externe) ─────────────────────────
def _system_resolvers() -> list[tuple[str, int]]:
    out = []
    try:
        with open("/etc/resolv.conf", encoding="utf-8", errors="ignore") as f:
            for ln in f:
                p = ln.split()
                if len(p) >= 2 and p[0] == "nameserver" and ":" not in p[1]:
                    out.append((p[1], 53))
    except OSError:
        pass
    return out


def _read_name(data: bytes, pos: int, depth: int = 0) -> tuple[str, int]:
    labels = []
    while True:
        if pos >= len(data) or depth > 20:
            raise ValueError("réponse DNS invalide")
        n = data[pos]
        if n == 0:
            pos += 1
            break
        if n & 0xC0 == 0xC0:
            ptr = ((n & 0x3F) << 8) | data[pos + 1]
            name, _ = _read_name(data, ptr, depth + 1)
            labels.append(name)
            pos += 2
            break
        labels.append(data[pos + 1:pos + 1 + n].decode("ascii", "replace"))
        pos += 1 + n
    return ".".join(x for x in labels if x), pos


def parse_mx_response(data: bytes, qid: int) -> list[tuple[int, str]]:
    if len(data) < 12:
        raise ValueError("réponse DNS trop courte")
    rid, flags, qd, an, _, _ = struct.unpack("!HHHHHH", data[:12])
    if rid != qid or not flags & 0x8000:
        raise ValueError("réponse DNS inattendue")
    if flags & 0x000F:
        return []                                        # NXDOMAIN / erreur serveur : pas d'enregistrement
    pos = 12
    for _ in range(qd):
        _, pos = _read_name(data, pos)
        pos += 4
    out = []
    for _ in range(min(an, 50)):
        _, pos = _read_name(data, pos)
        if pos + 10 > len(data):
            break
        rtype, _, _, rdlen = struct.unpack("!HHIH", data[pos:pos + 10])
        pos += 10
        if rtype == 15 and rdlen >= 3:
            pref = struct.unpack("!H", data[pos:pos + 2])[0]
            host, _ = _read_name(data, pos + 2)
            out.append((pref, host))
        pos += rdlen
    return sorted(out)


def resolve_mx(domain: str, nameservers: Optional[list] = None, timeout: float = 3.0) -> list[str]:
    """Serveurs de messagerie du domaine, du plus prioritaire au moins prioritaire (repli RFC 5321 : le domaine lui-même)."""
    domain = (domain or "").strip().strip(".").lower()
    if not domain or len(domain) > 253 or any(not (1 <= len(p) <= 63) for p in domain.split(".")):
        raise ValueError(f"Domaine invalide : « {domain} ».")
    qid = random.getrandbits(16)
    query = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for label in domain.split("."):
        query += bytes([len(label)]) + label.encode("idna")
    query += b"\x00" + struct.pack("!HH", 15, 1)
    servers = nameservers or (_system_resolvers() + PUBLIC_RESOLVERS)
    last: Optional[Exception] = None
    for ns in servers:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(query, ns)
                data, _ = s.recvfrom(4096)
            mx = [h for _, h in parse_mx_response(data, qid)]
            return mx or [domain]
        except (OSError, ValueError) as e:
            last = e
    raise OSError(f"Aucun serveur DNS n'a répondu pour {domain} ({last}).")


# ───────────────────────── messages d'erreur en clair ─────────────────────────
def friendly(exc: Exception, host: str = "", port: int = 0) -> str:
    h = f"{host}:{port}" if host else "le serveur"
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return ("Identifiant ou mot de passe refusé. Gmail, Outlook et Yahoo exigent un « mot de passe d'application » "
                "(pas votre mot de passe habituel).")
    if isinstance(exc, ssl.SSLCertVerificationError):
        return ("Le certificat du serveur n'est pas reconnu. Pour un serveur interne de confiance, décochez "
                "« Vérifier le certificat » ; sinon, vérifiez le nom du serveur.")
    if isinstance(exc, ssl.SSLError):
        return f"Échec du chiffrement avec {h} : essayez l'autre mode de sécurité (STARTTLS ↔ SSL/TLS) ou un autre port."
    if isinstance(exc, smtplib.SMTPNotSupportedError):
        return str(exc)
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        return "Un destinataire a été refusé par le serveur : vérifiez les adresses."
    if isinstance(exc, smtplib.SMTPSenderRefused):
        return "L'adresse d'expéditeur est refusée : utilisez l'adresse du compte SMTP."
    if isinstance(exc, (smtplib.SMTPServerDisconnected, ConnectionResetError)):
        return f"{h} a coupé la connexion : mauvais mode de sécurité pour ce port, ou serveur qui refuse cet envoi."
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return (f"Pas de réponse de {h} (délai dépassé) : pare-feu, antivirus ou fournisseur d'accès qui bloque ce port. "
                f"Essayez 587 ou 465.")
    if isinstance(exc, socket.gaierror):
        return f"Le nom « {host} » est introuvable : vérifiez l'orthographe et votre connexion Internet."
    if isinstance(exc, ConnectionRefusedError):
        return f"Connexion refusée par {h} : mauvais port, ou le service n'est pas démarré."
    return f"{type(exc).__name__} : {exc}"


def is_transient(exc: Exception) -> bool:
    """Panne qui peut passer toute seule (réseau, serveur occupé) → l'e-mail est remis en file d'attente."""
    if isinstance(exc, (smtplib.SMTPAuthenticationError, smtplib.SMTPRecipientsRefused, smtplib.SMTPSenderRefused,
                        smtplib.SMTPNotSupportedError, ssl.SSLError)):
        return False
    if isinstance(exc, smtplib.SMTPResponseException):
        return 400 <= exc.smtp_code < 500
    return isinstance(exc, (OSError, smtplib.SMTPServerDisconnected, smtplib.SMTPConnectError, TimeoutError))


# ───────────────────────── configuration ─────────────────────────
def _truthy(v, default=True) -> bool:
    return default if v is None else str(v).lower() not in ("0", "false", "no", "")


def normalize(cfg: dict) -> dict:
    c = dict(cfg or {})
    try:
        port = int(c.get("smtp_port", 587))
    except (TypeError, ValueError):
        port = 587
    c.update(mode="direct" if c.get("mail_mode") == "direct" else "relay",
             host=(c.get("smtp_host") or "").strip(), port=port,
             security=c.get("smtp_security") if c.get("smtp_security") in SECURITY_CHOICES else "auto",
             verify=_truthy(c.get("smtp_verify_tls")), user=(c.get("smtp_user") or "").strip(),
             password=(c.get("smtp_password") or "").strip(),
             helo=(c.get("mail_helo") or "").strip() or socket.getfqdn() or "procus-secure.local",
             direct_port=int(c.get("direct_port") or 25), timeout=float(c.get("mail_timeout") or 15),
             nameservers=c.get("nameservers"))
    return c


def _ctx(verify: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


# ───────────────────────── envoi ─────────────────────────
def _relay_connect(c: dict) -> smtplib.SMTP:
    """Connexion + chiffrement + identification (règles de sécurité communes à l'envoi et au diagnostic)."""
    sec = c["security"]
    if sec == "auto":
        sec = "ssl" if c["port"] == 465 else "opportunistic"      # STARTTLS si le serveur l'offre
    ctx = _ctx(c["verify"])
    if sec == "ssl":
        server = smtplib.SMTP_SSL(c["host"], c["port"], timeout=c["timeout"], context=ctx, local_hostname=c["helo"])
    else:
        server = smtplib.SMTP(c["host"], c["port"], timeout=c["timeout"], local_hostname=c["helo"])
        try:
            server.ehlo()
            if sec in ("starttls", "opportunistic") and server.has_extn("starttls"):
                server.starttls(context=ctx)
                server.ehlo()
            elif sec == "starttls":
                raise smtplib.SMTPNotSupportedError("Le serveur n'offre pas STARTTLS : choisissez « SSL/TLS » ou « Aucune ».")
            elif c["user"] and c["password"]:
                raise smtplib.SMTPNotSupportedError("Le serveur n'offre pas STARTTLS : envoi authentifié refusé.")
        except Exception:
            server.close()
            raise
    try:
        if c["user"] and c["password"]:
            server.login(c["user"], c["password"])
    except Exception:
        server.close()
        raise
    return server


def deliver(cfg: dict, envelope_from: str, to_list: list[str], raw_message: str) -> str:
    """Remet le message. Retourne un détail lisible ; lève l'exception d'origine en cas d'échec."""
    c = normalize(cfg)
    if c["mode"] == "relay":
        with _relay_connect(c) as server:
            server.sendmail(envelope_from, to_list, raw_message)
        return f"E-mail envoyé à {', '.join(to_list)} via {c['host']}:{c['port']}."
    # envoi direct : un groupe par domaine de destinataire
    domains: dict[str, list[str]] = {}
    for a in to_list:
        domains.setdefault(a.rsplit("@", 1)[-1].lower(), []).append(a)
    errors = []
    for dom, rcpts in domains.items():
        last: Optional[Exception] = None
        for mx in resolve_mx(dom, c["nameservers"])[:3]:
            try:
                with smtplib.SMTP(mx, c["direct_port"], timeout=c["timeout"], local_hostname=c["helo"]) as s:
                    s.ehlo()
                    if s.has_extn("starttls"):                     # chiffrement opportuniste (certificat non exigé : MX tiers)
                        s.starttls(context=_ctx(False))
                        s.ehlo()
                    s.sendmail(envelope_from, rcpts, raw_message)
                break
            except Exception as e:
                last = e
        else:
            errors.append((dom, last))
    if errors:
        raise errors[0][1] or OSError("envoi direct impossible")
    return f"E-mail remis directement aux serveurs de messagerie de : {', '.join(domains)}."


# ───────────────────────── diagnostic pas à pas ─────────────────────────
def diagnose(cfg: dict, recipient: str = "", send_test: bool = False,
             build_message: Optional[Callable[[], tuple[str, str, list[str]]]] = None) -> list[dict]:
    """[{'step','ok','detail','advice'}] — s'arrête à la première étape en échec."""
    c = normalize(cfg)
    steps: list[dict] = []

    def add(name, ok, detail="", advice=""):
        steps.append({"step": name, "ok": ok, "detail": detail, "advice": advice})
        return ok

    rcpt = recipient or (c.get("smtp_to") or "").split(",")[0].strip()
    sender = parseaddr(c.get("smtp_from") or c["user"])[1]
    if "@" not in rcpt:
        add("Destinataire", False, "Aucune adresse de destinataire.", "Renseignez au moins une adresse dans « Destinataires ».")
        return steps
    add("Destinataire", True, rcpt)
    try:
        if c["mode"] == "direct":
            dom = rcpt.rsplit("@", 1)[-1]
            try:
                mx = resolve_mx(dom, c["nameservers"])
            except (OSError, ValueError) as e:
                add("Recherche du serveur de messagerie du destinataire", False, str(e),
                    "Vérifiez l'adresse du destinataire et votre connexion Internet.")
                return steps
            add("Recherche du serveur de messagerie du destinataire", True, ", ".join(mx[:3]))
            try:
                s = smtplib.SMTP(mx[0], c["direct_port"], timeout=min(c["timeout"], 10), local_hostname=c["helo"])
            except Exception as e:
                add(f"Connexion à {mx[0]}:{c['direct_port']}", False, friendly(e, mx[0], c["direct_port"]),
                    "Beaucoup de fournisseurs d'accès bloquent le port 25 sortant. Utilisez plutôt le mode « Serveur SMTP » "
                    "(Gmail, Outlook, OVH…).")
                return steps
            add(f"Connexion à {mx[0]}:{c['direct_port']}", True)
            with s:
                s.ehlo()
                add("Chiffrement", True, "STARTTLS disponible" if s.has_extn("starttls") else "non proposé par ce serveur (envoi en clair)")
                try:
                    s.mail(sender or f"procus@{c['helo']}")
                    code, msg = s.rcpt(rcpt)
                    s.rset()
                except Exception as e:
                    add("Destinataire accepté", False, friendly(e, mx[0], c["direct_port"]),
                        "Le serveur du destinataire refuse l'envoi direct (courrier indésirable). Utilisez un serveur SMTP.")
                    return steps
                if not add("Destinataire accepté", 200 <= code < 300, f"{code} {msg.decode(errors='ignore') if isinstance(msg, bytes) else msg}",
                           "Le serveur refuse ce destinataire ou cet expéditeur d'envoi direct : utilisez un serveur SMTP."):
                    return steps
        else:
            if not c["host"]:
                add("Adresse du serveur", False, "vide", "Choisissez un fournisseur dans la liste ou saisissez le nom du serveur.")
                return steps
            try:
                ips = {a[4][0] for a in socket.getaddrinfo(c["host"], c["port"], type=socket.SOCK_STREAM)}
            except socket.gaierror as e:
                add("Adresse du serveur", False, friendly(e, c["host"]), "Vérifiez le nom du serveur et votre connexion Internet.")
                return steps
            add("Adresse du serveur", True, f"{c['host']} → {', '.join(sorted(ips))}")
            try:
                socket.create_connection((c["host"], c["port"]), timeout=min(c["timeout"], 8)).close()
            except OSError as e:
                add(f"Connexion au port {c['port']}", False, friendly(e, c["host"], c["port"]),
                    "Le port est peut-être bloqué par un pare-feu ou un antivirus : essayez 587 (STARTTLS) ou 465 (SSL/TLS).")
                return steps
            add(f"Connexion au port {c['port']}", True)
            try:
                server = _relay_connect(c)
            except Exception as e:
                is_auth = isinstance(e, smtplib.SMTPAuthenticationError)
                add("Identification" if is_auth else "Chiffrement", False, friendly(e, c["host"], c["port"]),
                    "Vérifiez l'identifiant et le mot de passe (mot de passe d'application pour Gmail/Outlook)." if is_auth
                    else "Essayez l'autre mode de sécurité ou le port 587 / 465.")
                return steps
            add("Chiffrement", True, "connexion sécurisée" if c["security"] != "none" else "aucun chiffrement (relais interne)")
            add("Identification", True, "acceptée" if (c["user"] and c["password"]) else "sans identification")
            with server:
                try:
                    server.mail(sender or c["user"])
                    code, _ = server.rcpt(rcpt)
                    server.rset()
                except Exception as e:
                    add("Expéditeur et destinataire acceptés", False, friendly(e, c["host"], c["port"]),
                        "Utilisez comme expéditeur l'adresse du compte SMTP.")
                    return steps
                if not add("Expéditeur et destinataire acceptés", 200 <= code < 300, f"code {code}", "Le serveur refuse ce destinataire."):
                    return steps
        if send_test and build_message:
            subject, raw, to_list = build_message()
            try:
                add("Envoi du message de test", True, deliver(cfg, sender or c["user"] or f"procus@{c['helo']}", to_list, raw))
            except Exception as e:
                add("Envoi du message de test", False, friendly(e, c["host"], c["port"]), "")
    except Exception as e:                                          # le diagnostic ne doit jamais planter l'interface
        add("Diagnostic", False, f"{type(e).__name__} : {e}", "")
    return steps


# ───────────────────────── file d'attente ─────────────────────────
class Outbox:
    def __init__(self, db):
        self.db = db

    def enqueue(self, envelope_from: str, to_list: list[str], raw: str, subject: str = "", error: str = "") -> int:
        if self.count_pending() >= 500:                              # garde-fou : pas de croissance sans limite
            self.db.execute("DELETE FROM mail_outbox WHERE id = (SELECT MIN(id) FROM mail_outbox WHERE status='pending')")
        return self.db.execute(
            "INSERT INTO mail_outbox (envelope_from, to_addrs, subject, raw, status, attempts, next_try, last_error, created_at) "
            "VALUES (?,?,?,?, 'pending', 1, ?, ?, ?)",          # 1 essai déjà fait : le prochain dans 1 minute
            (envelope_from, ",".join(to_list), subject[:200], raw,
             (datetime.now() + timedelta(minutes=RETRY_MINUTES[0])).isoformat(timespec="seconds"),
             error[:300], _now())).lastrowid

    def count_pending(self) -> int:
        return self.db.fetchone("SELECT COUNT(*) n FROM mail_outbox WHERE status = 'pending'")["n"]

    def pending(self) -> list[dict]:
        return self.db.fetchall("SELECT id, to_addrs, subject, attempts, next_try, last_error FROM mail_outbox "
                                "WHERE status = 'pending' ORDER BY id")

    def flush(self, cfg: dict, force: bool = False, now: Optional[datetime] = None) -> dict:
        """Renvoie les e-mails dus. Retourne {'sent','failed','kept'}."""
        now = now or datetime.now()
        res = {"sent": 0, "failed": 0, "kept": 0}
        for m in self.db.fetchall("SELECT * FROM mail_outbox WHERE status = 'pending' ORDER BY id LIMIT 50"):
            if not force and m["next_try"] and m["next_try"] > now.isoformat(timespec="seconds"):
                res["kept"] += 1
                continue
            try:
                deliver(cfg, m["envelope_from"], m["to_addrs"].split(","), m["raw"])
                self.db.execute("UPDATE mail_outbox SET status='sent', attempts=attempts+1, raw='', last_error='' WHERE id = ?", (m["id"],))
                res["sent"] += 1
            except Exception as e:
                att = m["attempts"] + 1
                if att >= MAX_ATTEMPTS or not is_transient(e):
                    self.db.execute("UPDATE mail_outbox SET status='failed', attempts=?, last_error=? WHERE id = ?",
                                    (att, friendly(e)[:300], m["id"]))
                    res["failed"] += 1
                else:
                    nxt = (now + timedelta(minutes=RETRY_MINUTES[att])).isoformat(timespec="seconds")
                    self.db.execute("UPDATE mail_outbox SET attempts=?, next_try=?, last_error=? WHERE id = ?",
                                    (att, nxt, friendly(e)[:300], m["id"]))
                    res["kept"] += 1
        return res

    def purge(self, days: int = 3):
        self.db.execute("DELETE FROM mail_outbox WHERE status != 'pending' AND created_at < ?",
                        ((datetime.now() - timedelta(days=days)).isoformat(timespec="seconds"),))
