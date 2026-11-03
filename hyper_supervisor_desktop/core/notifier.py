"""
Procus Secure — Gestionnaire de notifications réelles
Procus Tech

Canaux supportés :
  - Email SMTP (smtplib — TLS/STARTTLS)
  - Webhook HTTP (urllib — JSON + HMAC-SHA256 optionnel)
  - Slack (Webhook Block Kit)
"""
import html
import json
import ssl
import hmac
import hashlib
import smtplib
import urllib.request
import urllib.error
from datetime import datetime
from email.utils import parseaddr
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from loguru import logger

from core import netguard

from PyQt6.QtCore import QObject, pyqtSignal, pyqtSlot


# Sévérités qui déclenchent les notifications
NOTIFY_SEVERITIES = {"disaster", "high", "average"}

# Couleurs Slack par sévérité
SLACK_COLORS = {
    "disaster":    "#E74C3C",
    "high":        "#E67E22",
    "average":     "#F1C40F",
    "warning":     "#3498DB",
    "information": "#2ECC71",
}


def explain_smtp_error(exc: Exception, host: str = "", port: int = 0) -> str:
    """Traduit une erreur SMTP/réseau en cause + action concrète (français)."""
    import socket
    where = f"{host}:{port}" if host else "le serveur"
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        hint = ""
        if "gmail" in host.lower() or "google" in host.lower():
            hint = " Gmail exige un « mot de passe d'application » (validation en 2 étapes), pas le mot de passe du compte."
        return f"Authentification refusée par {where} (identifiant ou mot de passe incorrect).{hint}"
    if isinstance(exc, smtplib.SMTPNotSupportedError):
        return f"{exc}. Utilisez le port 587 (STARTTLS) ou 465 (SSL/TLS)."
    if isinstance(exc, smtplib.SMTPSenderRefused):
        return f"Expéditeur refusé par le serveur : « {exc.sender} ». Il doit correspondre à l'utilisateur authentifié."
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        return f"Destinataire(s) refusé(s) par le serveur : {', '.join(exc.recipients)}."
    if isinstance(exc, smtplib.SMTPServerDisconnected):
        return (f"{where} a coupé la connexion. Le port ne correspond sans doute pas au mode de "
                f"chiffrement (587 = STARTTLS, 465 = SSL/TLS).")
    if isinstance(exc, ssl.SSLCertVerificationError):
        return f"Certificat TLS de {host} non valide ({exc.verify_message}). Vérifiez le nom du serveur."
    if isinstance(exc, ssl.SSLError):
        return f"Erreur TLS avec {where} : {exc}. Essayez l'autre port (587 ↔ 465)."
    if isinstance(exc, socket.gaierror):
        return (f"Nom de serveur « {host} » introuvable (DNS). Saisissez un nom d'hôte valide, "
                f"par ex. smtp.gmail.com — pas une adresse e-mail.")
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return (f"Délai dépassé en joignant {where}. Pare-feu/antivirus ou port bloqué par le "
                f"fournisseur d'accès ? Essayez un autre port.")
    if isinstance(exc, ConnectionRefusedError):
        return f"Connexion refusée par {where} : aucun service SMTP sur ce port."
    if isinstance(exc, OSError):
        return f"Réseau inaccessible vers {where} : {exc}"
    return f"{type(exc).__name__} : {exc}"


def validate_smtp_settings(host: str, port: int, to_raw: str, mode: str = "relay") -> str | None:
    """Retourne un message d'erreur de saisie (ou None si les champs sont plausibles)."""
    host = (host or "").strip()
    if mode == "direct":
        host = "direct.invalid"                    # envoi direct : aucun serveur à renseigner
    if not host:
        return "Le serveur SMTP est vide."
    if "@" in host or "://" in host or " " in host or "/" in host:
        return ("« Serveur SMTP » doit être un nom d'hôte (ex : smtp.gmail.com), "
                "pas une adresse e-mail ni une URL.")
    if not (1 <= int(port) <= 65535):
        return "Port SMTP invalide."
    recipients = [a.strip() for a in (to_raw or "").split(",") if a.strip()]
    if not recipients:
        return "Aucun destinataire renseigné."
    for a in recipients:
        addr = parseaddr(a)[1]
        if "@" not in addr or addr.startswith("@") or addr.endswith("@"):
            return f"Destinataire invalide : « {a} »."
    return None


class NotifierManager:
    """
    Lit les media_types actifs en DB et envoie les notifications via SMTP / Webhook / Slack.
    Ne lève jamais d'exception — tout est loggué.
    """

    def __init__(self, db=None):
        self.db = db

    # ─────────────────────────────────────────
    # Point d'entrée principal
    # ─────────────────────────────────────────

    def send_all(self, event: dict, min_severity: set = None) -> list[str]:
        """
        Envoie le même événement sur tous les médias actifs.
        Retourne la liste des canaux ayant réussi.
        """
        if min_severity is None:
            min_severity = NOTIFY_SEVERITIES

        severity = event.get("severity", "information")
        if severity not in min_severity:
            return []

        if not self.db:
            logger.warning("[NOTIF] Pas de DB connectée.")
            return []

        media_types = self.db.get_active_media_types()
        sent = []

        for mt in media_types:
            try:
                config = self._load_config(mt.get("config_json") or "{}")
                mtype  = mt.get("type", "").lower()
                name   = mt.get("name", "")

                if mtype == "email":
                    ok = self._send_email(event, config, name)
                elif mtype == "webhook":
                    if "slack" in name.lower():
                        ok = self._send_slack(event, config, name)
                    else:
                        ok = self._send_webhook(event, config, name)
                else:
                    logger.debug(f"[NOTIF] Type '{mtype}' non géré pour '{name}'.")
                    continue

                if ok:
                    sent.append(name)
            except Exception as e:
                logger.error(f"[NOTIF] Erreur inattendue pour '{mt.get('name')}' : {e}")

        return sent

    # ─────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────

    @staticmethod
    def _load_config(config_json: str) -> dict:
        """Parse + déchiffre le config_json d'un média."""
        try:
            cfg = json.loads(config_json) if config_json else {}
        except Exception:
            cfg = {}

        # Déchiffre les champs sensibles si chiffrés
        from core.security import CryptoHelper
        for key in ("smtp_password", "webhook_secret", "webhook_url", "api_key"):
            if key in cfg and cfg[key]:
                cfg[key] = CryptoHelper.decrypt(cfg[key])
        return cfg

    @staticmethod
    def _valid_url(url: str) -> bool:
        """Seuls http(s) sont acceptés (pas de file://, ftp://… via urllib)."""
        from urllib.parse import urlparse
        u = urlparse(url)
        return u.scheme in ("http", "https") and bool(u.netloc)

    def _check_outbound(self, url: str) -> tuple[bool, str]:
        allow = ""
        if self.db is not None:
            try:
                allow = self.db.get_setting("webhook_allow_internal", "") or ""
            except Exception:
                allow = ""
        return netguard.check_url(url, allow)

    @staticmethod
    def _event_html(event: dict) -> str:
        """Génère un corps HTML pour les emails."""
        # Toutes les valeurs viennent du réseau (noms DNS, descriptions…) → échappées (anti-injection HTML)
        esc = lambda v: html.escape(str(v if v is not None else "—"))
        sev   = esc(event.get("severity", "").upper())
        host  = esc(event.get("host_name", "—"))
        desc  = esc(event.get("description", "—"))
        port  = esc(event.get("port", "—"))
        before = esc(event.get("state_before", "—"))
        after  = esc(event.get("state_after", "—"))
        ts     = esc(event.get("occurred_at", datetime.now().isoformat(timespec='seconds')))

        color_map = {
            "DISASTER":    "#E74C3C", "HIGH": "#E67E22",
            "AVERAGE":     "#F1C40F", "WARNING": "#3498DB",
            "INFORMATION": "#2ECC71",
        }
        badge_color = color_map.get(sev, "#8B9CB0")

        return f"""
        <html><body style="font-family:Arial,sans-serif;background:#1A1D23;color:#D9E5F0;padding:20px;">
          <div style="max-width:600px;margin:0 auto;background:#242830;border-radius:8px;padding:24px;">
            <h2 style="margin:0 0 16px;color:#E45516;">🛡 Procus Secure — Alerte réseau</h2>
            <table style="width:100%;border-collapse:collapse;">
              <tr><td style="padding:8px;color:#7A9BBE;width:140px;">Sévérité</td>
                  <td><span style="background:{badge_color};color:#fff;padding:3px 10px;border-radius:4px;font-weight:bold;">{sev}</span></td></tr>
              <tr style="background:#1A1D23;"><td style="padding:8px;color:#7A9BBE;">Hôte</td><td style="padding:8px;">{host}</td></tr>
              <tr><td style="padding:8px;color:#7A9BBE;">Description</td><td style="padding:8px;">{desc}</td></tr>
              <tr style="background:#1A1D23;"><td style="padding:8px;color:#7A9BBE;">Port</td><td style="padding:8px;">{port}</td></tr>
              <tr><td style="padding:8px;color:#7A9BBE;">Changement</td><td style="padding:8px;">{before} → {after}</td></tr>
              <tr style="background:#1A1D23;"><td style="padding:8px;color:#7A9BBE;">Horodatage</td><td style="padding:8px;">{ts}</td></tr>
            </table>
            <p style="margin-top:20px;font-size:11px;color:#3D5A80;">
              Généré par Procus Secure — Supervision Réseau · Procus Tech
            </p>
          </div>
        </body></html>
        """

    # ─────────────────────────────────────────
    # Email SMTP
    # ─────────────────────────────────────────

    def _send_email(self, event: dict, config: dict, name: str) -> bool:
        return self._send_email_ex(event, config, name)[0]

    def _send_email_ex(self, event: dict, config: dict, name: str) -> tuple[bool, str]:
        """Envoi SMTP. Retourne (succès, détail lisible de l'erreur ou du succès)."""
        host_val  = config.get("smtp_host", "").strip()
        try:
            port_val = int(config.get("smtp_port", 587))
        except (TypeError, ValueError):
            port_val = 587
        user      = config.get("smtp_user", "").strip()
        from_addr = (config.get("smtp_from") or user).strip()
        to_raw    = config.get("smtp_to", "").strip()

        problem = validate_smtp_settings(host_val, port_val, to_raw, config.get("mail_mode", "relay"))
        if problem:
            logger.warning(f"[NOTIF][SMTP] '{name}' : {problem}")
            return False, problem

        to_list = [addr.strip() for addr in to_raw.split(",") if addr.strip()]

        sev      = event.get("severity", "").upper()
        host_name = event.get("host_name", "?")
        desc     = event.get("description", "")

        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[Procus Secure] {sev} — {host_name}"
        msg["From"]    = from_addr or user
        msg["To"]      = ", ".join(to_list)

        # Version texte simple
        text_body = (
            f"ALERTE PROCUS SECURE\n\n"
            f"Sévérité : {sev}\n"
            f"Hôte     : {host_name}\n"
            f"Détail   : {desc}\n"
            f"Port     : {event.get('port', '—')}\n"
            f"Avant    : {event.get('state_before', '—')}\n"
            f"Après    : {event.get('state_after', '—')}\n"
        )
        msg.attach(MIMEText(text_body, "plain", "utf-8"))
        msg.attach(MIMEText(self._event_html(event), "html", "utf-8"))

        envelope_from = parseaddr(from_addr)[1] or user
        direct = config.get("mail_mode") == "direct"
        if "@" not in envelope_from:
            if not direct:
                return False, ("Expéditeur invalide : renseignez une adresse e-mail "
                               "(ex : noreply@votre-domaine.com).")
            envelope_from = "procus-secure@localhost"
        from core import mailer
        try:
            detail = mailer.deliver(config, envelope_from, to_list, msg.as_string())
            logger.success(f"[NOTIF][SMTP] Email envoyé via '{name}' → {to_list}")
            return True, detail
        except Exception as e:
            reason = mailer.friendly(e, host_val, port_val)
            logger.error(f"[NOTIF][SMTP] Échec via '{name}' : {reason}")
            if self.db is not None and event.get("event_type") != "test" and mailer.is_transient(e):
                try:                                   # panne passagère : l'alerte sera renvoyée automatiquement
                    mailer.Outbox(self.db).enqueue(envelope_from, to_list, msg.as_string(), msg["Subject"], reason)
                    reason += " L'alerte est conservée et sera renvoyée automatiquement."
                except Exception as qe:
                    logger.debug(f"[NOTIF] file d'attente indisponible : {qe}")
            return False, reason

    def flush_outbox(self, force: bool = False) -> dict:
        """Renvoie les e-mails d'alerte en attente (tâche périodique de la défense)."""
        from core import mailer
        if not self.db:
            return {"sent": 0, "failed": 0, "kept": 0}
        box = mailer.Outbox(self.db)
        if not box.count_pending():
            return {"sent": 0, "failed": 0, "kept": 0}
        for mt in self.db.get_active_media_types():
            if (mt.get("type") or "").lower() == "email":
                return box.flush(self._load_config(mt.get("config_json") or "{}"), force=force)
        return {"sent": 0, "failed": 0, "kept": 0}

    # ─────────────────────────────────────────
    # Webhook générique
    # ─────────────────────────────────────────

    def _send_webhook(self, event: dict, config: dict, name: str) -> bool:
        return self._send_webhook_ex(event, config, name)[0]

    def _send_webhook_ex(self, event: dict, config: dict, name: str) -> tuple[bool, str]:
        url    = config.get("webhook_url", "").strip()
        secret = config.get("webhook_secret", "").strip()

        if not url:
            logger.warning(f"[NOTIF][WEBHOOK] '{name}' : webhook_url manquant — ignoré.")
            return False, "URL du webhook non renseignée."
        ok_url, why = self._check_outbound(url)
        if not ok_url:
            logger.error(f"[NOTIF][WEBHOOK] '{name}' : URL refusée ({why}).")
            return False, "URL refusée : " + why

        payload = {
            "source":      "Procus Secure",
            "event_type":  event.get("event_type", "port_change"),
            "severity":    event.get("severity", ""),
            "host":        event.get("host_name", ""),
            "description": event.get("description", ""),
            "port":        event.get("port"),
            "state_before": event.get("state_before"),
            "state_after":  event.get("state_after"),
            "timestamp":   event.get("occurred_at", datetime.now().isoformat(timespec='seconds')),
        }
        body = json.dumps(payload).encode("utf-8")

        headers = {"Content-Type": "application/json"}
        if secret:
            sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
            headers["X-Hub-Signature-256"] = f"sha256={sig}"

        try:
            req = urllib.request.Request(url, data=body, headers=headers, method="POST")
            with netguard.open_url(req, timeout=10) as resp:
                status = resp.status
            logger.success(f"[NOTIF][WEBHOOK] '{name}' → HTTP {status}")
            return True, f"Requête acceptée (HTTP {status})."
        except urllib.error.HTTPError as e:
            logger.error(f"[NOTIF][WEBHOOK] Échec via '{name}' : HTTP {e.code}")
            return False, f"Le serveur a répondu HTTP {e.code} ({e.reason}). Vérifiez l'URL/le jeton."
        except Exception as e:
            logger.error(f"[NOTIF][WEBHOOK] Échec via '{name}' : {e}")
            return False, f"Connexion impossible : {e}"

    # ─────────────────────────────────────────
    # Slack (Block Kit)
    # ─────────────────────────────────────────

    def _send_slack(self, event: dict, config: dict, name: str) -> bool:
        return self._send_slack_ex(event, config, name)[0]

    def _send_slack_ex(self, event: dict, config: dict, name: str) -> tuple[bool, str]:
        url = config.get("webhook_url", "").strip()
        if not url:
            logger.warning(f"[NOTIF][SLACK] '{name}' : webhook_url manquant — ignoré.")
            return False, "URL du webhook Slack non renseignée."
        ok_url, why = self._check_outbound(url)
        if not ok_url:
            logger.error(f"[NOTIF][SLACK] '{name}' : URL refusée ({why}).")
            return False, "URL refusée : " + why

        sev   = event.get("severity", "information")
        color = SLACK_COLORS.get(sev, "#8B9CB0")
        host  = event.get("host_name", "?")
        desc  = event.get("description", "")
        port  = event.get("port", "—")
        before = event.get("state_before", "—")
        after  = event.get("state_after", "—")
        ts     = event.get("occurred_at", datetime.now().isoformat(timespec='seconds'))

        payload = {
            "attachments": [{
                "color": color,
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"🛡 Procus Secure — {sev.upper()}"
                        }
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Hôte*\n{host}"},
                            {"type": "mrkdwn", "text": f"*Sévérité*\n{sev.upper()}"},
                            {"type": "mrkdwn", "text": f"*Description*\n{desc}"},
                            {"type": "mrkdwn", "text": f"*Port*\n{port}"},
                            {"type": "mrkdwn", "text": f"*Changement*\n{before} → {after}"},
                            {"type": "mrkdwn", "text": f"*Horodatage*\n{ts}"},
                        ]
                    },
                    {
                        "type": "context",
                        "elements": [{"type": "mrkdwn", "text": "Envoyé par *Procus Secure* · Procus Tech"}]
                    }
                ]
            }]
        }

        body = json.dumps(payload).encode("utf-8")
        try:
            req = urllib.request.Request(
                url, data=body,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with netguard.open_url(req, timeout=10) as resp:
                status = resp.status
            logger.success(f"[NOTIF][SLACK] '{name}' → HTTP {status}")
            return True, f"Requête acceptée (HTTP {status})."
        except urllib.error.HTTPError as e:
            logger.error(f"[NOTIF][SLACK] Échec via '{name}' : HTTP {e.code}")
            return False, f"Le serveur a répondu HTTP {e.code} ({e.reason}). Vérifiez l'URL/le jeton."
        except Exception as e:
            logger.error(f"[NOTIF][SLACK] Échec via '{name}' : {e}")
            return False, f"Connexion impossible : {e}"

    # ─────────────────────────────────────────
    # Test d'envoi (utilisé depuis MediaView/SettingsView)
    # ─────────────────────────────────────────

    def test_media(self, media_name: str) -> tuple[bool, str]:
        """
        Envoie un événement de test sur un média par son nom.
        Retourne (succès, message).
        """
        if not self.db:
            return False, "Pas de base de données connectée."

        mt = next((m for m in self.db.get_media_types() if m.get("name") == media_name), None)
        if not mt:
            return False, f"Média '{media_name}' introuvable."
        if not mt.get("active"):
            return False, f"Le média '{media_name}' est inactif."
        if not (mt.get("config_json") or "").strip() or (mt.get("config_json") or "").strip() == "{}":
            return False, ("Média non configuré. Renseignez-le dans Paramètres système "
                           "(onglet Notifications SMTP ou Webhooks) puis cliquez sur Sauvegarder.")

        test_event = {
            "host_name":   "test-host",
            "host_id":     0,
            "severity":    "high",
            "event_type":  "test",
            "description": "Ceci est un test de notification Procus Secure.",
            "port":        80,
            "state_before": "closed",
            "state_after":  "open",
            "occurred_at": datetime.now().isoformat(timespec='seconds'),
        }

        config = self._load_config(mt.get("config_json") or "{}")
        mtype  = mt.get("type", "").lower()
        name   = mt.get("name", "")

        if mtype == "email":
            ok, detail = self._send_email_ex(test_event, config, name)
        elif mtype == "webhook":
            if "slack" in name.lower():
                ok, detail = self._send_slack_ex(test_event, config, name)
            else:
                ok, detail = self._send_webhook_ex(test_event, config, name)
        else:
            return False, f"Le type « {mtype} » n'est pas pris en charge par cette version."

        return ok, detail if ok else f"Échec : {detail}"


# ─────────────────────────────────────────────
# Worker Qt (thread-safe)
# ─────────────────────────────────────────────

class NotificationDeduper:
    """
    Regroupe les alertes identiques : une même alerte (équipement + type + port + message + sévérité)
    n'est envoyée qu'une fois par fenêtre (1 h par défaut, réglage « notif_dedup_window »).
    Les répétitions sont comptées ; l'alerte suivante dit combien de fois elle s'est répétée.
    Seul l'ENVOI est regroupé : chaque événement reste enregistré en base (preuves intactes).
    """
    DEFAULT_WINDOW_S = 3600

    def __init__(self, db):
        self.db = db

    def _window(self) -> int:
        try:
            row = self.db.fetchone("SELECT value FROM settings WHERE key = 'notif_dedup_window'")
            return max(0, int(row["value"])) if row and str(row["value"]).strip() else self.DEFAULT_WINDOW_S
        except Exception:
            return self.DEFAULT_WINDOW_S

    @staticmethod
    def make_key(event: dict) -> tuple[str, int]:
        import hashlib
        who = event.get("host_id") or 0
        raw = "|".join(str(x) for x in (
            event.get("event_type", ""), who, event.get("host_name", ""), event.get("port"),
            event.get("severity", ""), event.get("description", "")))
        return hashlib.sha1(raw.encode("utf-8", "replace"), usedforsecurity=False).hexdigest(), int(who)

    def check(self, event: dict) -> tuple[bool, int]:
        """(envoyer ?, nb de répétitions regroupées depuis le dernier envoi). Ne lève jamais d'exception."""
        if not self.db:
            return True, 0
        try:
            window = self._window()
            if window <= 0:                                   # 0 = regroupement désactivé
                return True, 0
            key, who = self.make_key(event)
            row = self.db.fetchone(
                "SELECT id, notification_count, "
                "CAST(strftime('%s','now') - strftime('%s', last_sent_at) AS INTEGER) AS age "
                "FROM notification_queue WHERE event_hash = ? AND host_id = ?", (key, who))
            if row and row["age"] is not None and row["age"] < window:
                self.db.execute("UPDATE notification_queue SET notification_count = notification_count + 1 "
                                "WHERE id = ?", (row["id"],))
                return False, 0
            repeats = max(0, int(row["notification_count"]) - 1) if row else 0
            if row:
                self.db.execute("UPDATE notification_queue SET notification_count = 1, "
                                "last_sent_at = datetime('now') WHERE id = ?", (row["id"],))
            else:
                self.db.execute("INSERT INTO notification_queue (event_id, host_id, event_hash) VALUES (?, ?, ?)",
                                (event.get("event_id"), who, key))
            self.db.execute("DELETE FROM notification_queue WHERE last_sent_at < datetime('now', '-7 days')")
            return True, repeats
        except Exception as e:                                # dans le doute, on envoie : jamais d'alerte perdue
            logger.debug(f"[NOTIF] Déduplication ignorée : {e}")
            return True, 0


class NotifierWorker(QObject):
    """
    Worker Qt pour exécuter les notifications dans un QThread séparé.
    Se connecte au signal change_detected du ScannerWorker.
    """
    notification_sent   = pyqtSignal(str)         # nom du canal
    notification_failed = pyqtSignal(str, str)    # nom canal, erreur

    def __init__(self, db=None, parent=None):
        super().__init__(parent)
        self._manager = NotifierManager(db=db)
        self._dedup = NotificationDeduper(db)
        self.suppressed = 0                           # alertes dupliquées regroupées depuis le démarrage

    @pyqtSlot(dict)
    def on_change_detected(self, event: dict):
        """
        Slot connecté à ScannerWorker.change_detected.
        Lance les notifications de manière non-bloquante.
        """
        try:
            send, repeats = self._dedup.check(event)
            if not send:
                self.suppressed += 1
                logger.info(f"[NOTIF] Alerte dupliquée regroupée : {event.get('host_name')} — "
                            f"{str(event.get('description', ''))[:80]}")
                return
            if repeats:
                event = {**event, "description": f"{event.get('description', '')} "
                                                 f"(répétée {repeats} fois depuis la dernière alerte)"}
            sent = self._manager.send_all(event)
            for channel in sent:
                self.notification_sent.emit(channel)
            if not sent:
                logger.debug(f"[NOTIF] Aucun canal actif pour sévérité '{event.get('severity')}'.")
        except Exception as e:
            self.notification_failed.emit("unknown", str(e))
            logger.error(f"[NOTIF] Erreur worker : {e}")

    def test_media(self, name: str) -> tuple[bool, str]:
        """Test synchrone depuis l'UI (thread principal)."""
        return self._manager.test_media(name)
