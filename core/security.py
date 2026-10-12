"""
Procus Secure — Module de sécurité
Procus Tech

Fonctions :
  - Hachage des mots de passe PBKDF2-HMAC-SHA256
  - Gestion des secrets via keyring OS
  - Vérification de l'intégrité de la base d'audit (HMAC)
  - RBAC (vérification des droits par rôle)
  - Chiffrement Fernet des communautés SNMP (point 7)
  - Validation des entrées utilisateur (point 8)
"""
import hashlib
import hmac
import os
import re
import secrets
from pathlib import Path
from loguru import logger


# ─────────────────────────────────────────────
# Chiffrement symétrique Fernet (SNMP communities)
# ─────────────────────────────────────────────

class CryptoHelper:
    """
    Chiffrement/déchiffrement Fernet pour les secrets SNMP.
    La clé Fernet est stockée dans keyring ou dans un fichier protégé.
    """

    SERVICE_NAME = "procus_snmp"
    KEY_NAME     = "fernet_key"

    @classmethod
    def _get_or_create_key(cls) -> bytes:
        """Récupère ou génère la clé Fernet (base64-url 32 octets)."""
        from cryptography.fernet import Fernet

        # 1. keyring OS
        try:
            import keyring
            stored = keyring.get_password(cls.SERVICE_NAME, cls.KEY_NAME)
            if stored:
                return stored.encode()
        except Exception:
            pass

        # 2. Fichier protégé ~/.procus_hsr/.fernet_key
        key_path = Path.home() / ".procus_hsr" / ".fernet_key"
        key_path.parent.mkdir(parents=True, exist_ok=True)
        if key_path.exists():
            raw = key_path.read_bytes().strip()
            if len(raw) == 44:   # clé Fernet base64 = 44 chars
                return raw

        # Génération d'une nouvelle clé
        new_key = Fernet.generate_key()
        try:
            key_path.write_bytes(new_key)
            import stat
            key_path.chmod(stat.S_IRUSR | stat.S_IWUSR)  # chmod 600
            logger.info("[CRYPTO] Clé Fernet SNMP générée dans .fernet_key (600).")
        except Exception as e:
            logger.warning(f"[CRYPTO] Impossible d'écrire .fernet_key : {e}")

        # Persister aussi dans keyring
        try:
            import keyring
            keyring.set_password(cls.SERVICE_NAME, cls.KEY_NAME, new_key.decode())
        except Exception:
            pass

        return new_key

    @classmethod
    def encrypt(cls, plaintext: str) -> str:
        """Chiffre une chaîne, retourne le token Fernet (str)."""
        if not plaintext:
            return ""
        try:
            from cryptography.fernet import Fernet
            f = Fernet(cls._get_or_create_key())
            return f.encrypt(plaintext.encode()).decode()
        except Exception as e:
            logger.error(f"[CRYPTO] Échec chiffrement : {e}")
            return plaintext  # fallback clair (loggué)

    @classmethod
    def decrypt(cls, token: str) -> str:
        """Déchiffre un token Fernet, retourne le texte clair."""
        if not token:
            return ""
        # Si ce n'est pas un token Fernet (ancien enregistrement en clair)
        if not token.startswith("gAAAAA"):
            return token
        try:
            from cryptography.fernet import Fernet, InvalidToken
            f = Fernet(cls._get_or_create_key())
            return f.decrypt(token.encode()).decode()
        except Exception as e:
            logger.warning(f"[CRYPTO] Déchiffrement échoué : {e}")
            return token  # retourne le token brut si clé perdue


# ─────────────────────────────────────────────
# Validation des entrées (point 8)
# ─────────────────────────────────────────────

class InputValidator:
    """Validation et nettoyage des entrées utilisateur."""

    # Caractères autorisés pour les noms (hôtes, groupes, etc.)
    _RE_NAME     = re.compile(r'^[\w\s\-\.\(\)\/]{1,128}$', re.UNICODE)
    # IP ou CIDR
    _RE_IP       = re.compile(
        r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$|^[\w\-\.]{1,253}$'
    )
    # Login utilisateur : alphanumérique + tirets/underscores
    _RE_LOGIN    = re.compile(r'^[a-zA-Z0-9_\-\.]{1,64}$')
    # Communauté SNMP : alphanumérique + ponctuation basique
    _RE_SNMP     = re.compile(r'^[\w\-\.@#!]{1,64}$')

    @classmethod
    def name(cls, value: str) -> str:
        """Valide un nom d'hôte/groupe. Lève ValueError si invalide."""
        v = value.strip()
        if not v:
            raise ValueError("Le nom ne peut pas être vide.")
        if not cls._RE_NAME.match(v):
            raise ValueError(f"Nom invalide : caractères non autorisés.")
        return v

    @classmethod
    def ip_address(cls, value: str) -> str:
        """Valide une adresse IP ou un hostname."""
        import ipaddress
        v = value.strip()
        if not v:
            raise ValueError("L'adresse IP ne peut pas être vide.")
        # Essayer IP/CIDR d'abord
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            pass
        try:
            ipaddress.ip_network(v, strict=False)
            return v
        except ValueError:
            pass
        # Hostname (nom DNS)
        if cls._RE_IP.match(v):
            return v
        raise ValueError(f"Adresse IP ou hostname invalide : {v!r}")

    @classmethod
    def login(cls, value: str) -> str:
        """Valide un identifiant utilisateur."""
        v = value.strip()
        if not cls._RE_LOGIN.match(v):
            raise ValueError("Identifiant invalide (alphanumérique, 1-64 caractères).")
        return v

    @classmethod
    def snmp_community(cls, value: str) -> str:
        """Valide une communauté SNMP."""
        v = value.strip()
        if not v:
            return "public"
        if not cls._RE_SNMP.match(v):
            raise ValueError("Communauté SNMP invalide.")
        return v

    @classmethod
    def safe_limit(cls, value: int, minimum: int = 1, maximum: int = 10_000) -> int:
        """Valide une limite numérique (pour requêtes SQL LIMIT)."""
        v = int(value)
        if not (minimum <= v <= maximum):
            raise ValueError(f"Valeur hors limites ({minimum}–{maximum}).")
        return v


# ─────────────────────────────────────────────
# Rôles et permissions
# ─────────────────────────────────────────────

ROLE_PERMISSIONS = {
    "super-admin": {
        "can_add_host", "can_edit_host", "can_delete_host",
        "can_scan", "can_acknowledge", "can_export",
        "can_manage_users", "can_manage_config",
        "can_view_audit", "can_view_all",
    },
    "operator": {
        "can_scan", "can_acknowledge", "can_export",
        "can_view_all",
    },
    "read-only": {
        "can_view_all",
    },
}


class SecurityManager:
    """
    Gère l'authentification, les droits et l'intégrité de l'audit.
    Les secrets ne sont jamais stockés en clair.
    """

    def __init__(self, db_manager=None):
        self.db = db_manager
        self._current_user: dict | None = None

    # ─────────────────────────────────────────
    # Hachage des mots de passe
    # ─────────────────────────────────────────

    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hache un mot de passe avec PBKDF2-HMAC-SHA256 + sel aléatoire.
        Format : salt_hex$hash_hex
        """
        salt = secrets.token_hex(16)
        key = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            iterations=260_000,
        )
        return f"{salt}${key.hex()}"

    @staticmethod
    def verify_password(password: str, stored_hash: str) -> bool:
        """Vérifie un mot de passe contre le hash stocké."""
        try:
            salt, hash_hex = stored_hash.split("$", 1)
            key = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode("utf-8"),
                salt.encode("utf-8"),
                iterations=260_000,
            )
            return hmac.compare_digest(key.hex(), hash_hex)
        except Exception:
            return False

    # ─────────────────────────────────────────
    # Gestion des secrets (keyring OS)
    # ─────────────────────────────────────────

    @staticmethod
    def store_secret(service: str, username: str, secret: str):
        """Stocke un secret dans le gestionnaire natif OS (jamais en clair sur disque)."""
        try:
            import keyring
            keyring.set_password(f"hsr_{service}", username, secret)
            logger.debug(f"[SEC] Secret '{service}/{username}' stocké dans keyring.")
        except Exception as e:
            logger.warning(f"[SEC] Keyring indisponible ({e}), secret non persisté.")

    @staticmethod
    def get_secret(service: str, username: str) -> str | None:
        """Récupère un secret depuis le gestionnaire natif OS."""
        try:
            import keyring
            return keyring.get_password(f"hsr_{service}", username)
        except Exception:
            return None

    # ─────────────────────────────────────────
    # Authentification
    # ─────────────────────────────────────────

    def authenticate(self, login: str, password: str) -> dict | None:
        """
        Vérifie les identifiants et retourne l'utilisateur si valides.
        Enregistre la tentative dans le journal d'audit.
        """
        if self.db is None:
            return None

        user = self.db.fetchone(
            "SELECT * FROM users WHERE login = ? AND active = 1", (login,)
        )

        if user and self.verify_password(password, user["password_hash"]):
            self._current_user = user
            # Mise à jour last_login
            from datetime import datetime
            self.db.execute(
                "UPDATE users SET last_login = ? WHERE id = ?",
                (datetime.now().isoformat(timespec='seconds'), user["id"])
            )
            self.db.write_audit(
                username=login, action="LOGIN",
                detail="Connexion réussie", user_id=user["id"]
            )
            logger.info(f"[SEC] Connexion réussie : {login} ({user['role']})")
            return user
        else:
            self.db.write_audit(
                username=login, action="LOGIN_FAILED",
                detail="Échec d'authentification"
            )
            logger.warning(f"[SEC] Échec de connexion pour : {login}")
            return None

    def get_current_user(self) -> dict | None:
        return self._current_user

    def set_current_user(self, user: dict):
        """Utilisé pour le démarrage sans écran de login (dev/demo)."""
        self._current_user = user

    # ─────────────────────────────────────────
    # Contrôle des droits (RBAC)
    # ─────────────────────────────────────────

    def has_permission(self, permission: str) -> bool:
        """Vérifie si l'utilisateur courant a un droit précis."""
        if self._current_user is None:
            return False
        role = self._current_user.get("role", "read-only")
        return permission in ROLE_PERMISSIONS.get(role, set())

    def require_permission(self, permission: str) -> bool:
        """
        Lève une exception si le droit est manquant.
        À utiliser avant chaque action sensible.
        """
        if not self.has_permission(permission):
            user = self._current_user["login"] if self._current_user else "anonymous"
            logger.warning(f"[SEC] Accès refusé ({permission}) pour : {user}")
            raise PermissionError(
                f"Action non autorisée : '{permission}'\n"
                f"Votre rôle ({self._current_user.get('role', '?')}) "
                f"ne permet pas cette opération."
            )
        return True

    # ─────────────────────────────────────────
    # Intégrité de la base d'audit
    # ─────────────────────────────────────────

    def verify_db_integrity(self) -> bool:
        """
        Vérifie que les enregistrements d'audit n'ont pas été altérés
        (vérification HMAC sur un échantillon).
        """
        if self.db is None:
            return True
        try:
            logs = self.db.fetchall(
                "SELECT * FROM audit_logs ORDER BY id DESC LIMIT 20"
            )
            key = self.db._get_hmac_key()
            tampered = 0
            for log in logs:
                msg = (
                    f"{log['username']}|{log['action']}|"
                    f"{log['target']}|{log['detail']}|{log['logged_at']}"
                ).encode()
                expected = hmac.new(key, msg, hashlib.sha256).hexdigest()
                if not hmac.compare_digest(expected, log.get("hmac", "")):
                    tampered += 1
                    logger.error(f"[SEC] ALERTE : entrée d'audit altérée ! ID={log['id']}")

            if tampered:
                logger.critical(
                    f"[SEC] {tampered} entrée(s) d'audit corrompue(s) !"
                )
            else:
                logger.success("[SEC] Intégrité du journal d'audit : OK")
            return tampered == 0
        except Exception as e:
            logger.error(f"[SEC] Vérification intégrité échouée : {e}")
            return False

    # ─────────────────────────────────────────
    # Validation des cibles de scan
    # ─────────────────────────────────────────

    @staticmethod
    def validate_scan_target(ip: str) -> bool:
        """
        Valide qu'une cible de scan est une IP valide.
        Les scans ne se font que sur des cibles autorisées.
        """
        import ipaddress
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            try:
                ipaddress.ip_network(ip, strict=False)
                return True
            except ValueError:
                logger.warning(f"[SEC] Cible de scan invalide rejetée : {ip}")
                return False
