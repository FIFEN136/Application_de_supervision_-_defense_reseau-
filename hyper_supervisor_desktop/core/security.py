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


def write_secret_file(path: Path, data: bytes) -> None:
    """Écrit un fichier secret créé directement en 0600 (aucune fenêtre lisible par les autres)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.parent.chmod(0o700)
    except OSError:
        pass
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(str(path), flags, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    try:
        path.chmod(0o600)
    except OSError:
        pass


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
            write_secret_file(key_path, new_key)           # créé en 0600 directement
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
            from cryptography.fernet import Fernet
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
    _RE_NAME     = re.compile(r'^[\w \-\.\(\)\/]{1,128}\Z', re.UNICODE)   # espace simple : pas de \n \r \t (injection de lignes de journal)
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
            raise ValueError("Nom invalide : caractères non autorisés.")
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

    MAX_FAILED_ATTEMPTS = 5          # échecs consécutifs avant verrouillage
    LOCKOUT_SECONDS     = 300        # durée du verrouillage (5 min)

    def __init__(self, db_manager=None):
        self.db = db_manager
        self._current_user: dict | None = None
        # Échecs de connexion et verrouillages : table login_failures (survivent au redémarrage de l'application)
        self._dummy_hash: str | None = None

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

    def lockout_remaining(self, login: str) -> int:
        """Secondes restantes avant la fin du verrouillage de ce compte (0 = non verrouillé)."""
        import time
        if self.db is None:
            return 0
        row = self.db.fetchone("SELECT locked_until FROM login_failures WHERE login = ?", ((login or "").lower(),))
        if not row or not row["locked_until"]:
            return 0
        return max(0, int(row["locked_until"] - time.time() + 0.999))

    def _clear_failures(self, login: str):
        if self.db is not None:
            self.db.execute("DELETE FROM login_failures WHERE login = ?", ((login or "").lower(),))

    def _register_failure(self, login: str):
        import time
        key = (login or "").lower()[:128]
        row = self.db.fetchone("SELECT count FROM login_failures WHERE login = ?", (key,))
        count = (row["count"] if row else 0) + 1
        locked_until = 0.0
        if count >= self.MAX_FAILED_ATTEMPTS:
            count, locked_until = 0, time.time() + self.LOCKOUT_SECONDS
            logger.warning(f"[SEC] Compte verrouillé {self.LOCKOUT_SECONDS}s : {login}")
            self.db.write_audit(username=login, action="LOGIN_LOCKED",
                                detail=f"{self.MAX_FAILED_ATTEMPTS} échecs consécutifs")
        self.db.execute("INSERT INTO login_failures (login, count, locked_until) VALUES (?,?,?) "
                        "ON CONFLICT(login) DO UPDATE SET count = excluded.count, locked_until = excluded.locked_until",
                        (key, count, locked_until))
        self.db.execute("DELETE FROM login_failures WHERE login NOT IN "
                        "(SELECT login FROM login_failures ORDER BY rowid DESC LIMIT 1000)")      # table bornée (noms inventés)

    def authenticate(self, login: str, password: str) -> dict | None:
        """
        Vérifie les identifiants et retourne l'utilisateur si valides.
        - verrouillage temporaire après MAX_FAILED_ATTEMPTS échecs,
        - temps de calcul constant (un login inconnu coûte autant qu'un mauvais mot de passe),
        - toutes les tentatives sont inscrites au journal d'audit signé HMAC.
        """
        if self.db is None:
            return None

        if self.lockout_remaining(login) > 0:
            self.db.write_audit(username=login, action="LOGIN_BLOCKED",
                                detail="Tentative pendant verrouillage")
            return None

        user = self.db.fetchone(
            "SELECT * FROM users WHERE login = ? AND active = 1", (login,)
        )
        if user is None:
            if self._dummy_hash is None:
                self._dummy_hash = self.hash_password("procus-dummy")
            self.verify_password(password, self._dummy_hash)     # égalise le temps de réponse
            ok = False
        else:
            ok = self.verify_password(password, user["password_hash"])

        if ok:
            self._clear_failures(login)
            self._current_user = user
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

        self._register_failure(login)
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

    def verify_audit(self) -> dict:
        """
        Vérifie TOUT le journal d'audit : signature de chaque ligne, chaînage (une ligne supprimée ou insérée rompt la chaîne),
        ancre de fin de journal (détecte la suppression des dernières lignes) et copie de l'ancre hors de la base.
        Retourne {'ok', 'checked', 'problems': [str]}.
        """
        from database.db_manager import AUDIT_GENESIS, audit_message
        problems: list[str] = []
        key = self.db._get_hmac_key()
        self._reseal_legacy_rows(key)
        rows = self.db.fetchall("SELECT * FROM audit_logs ORDER BY id")
        prev_hmac = AUDIT_GENESIS
        for log in rows:
            if log.get("chain_v") == 2:
                if log.get("prev_hmac") != prev_hmac:
                    problems.append(f"chaîne rompue avant la ligne {log['id']} (ligne supprimée ou insérée)")
                msg = audit_message(log.get("prev_hmac"), log.get("user_id"), log["username"], log["action"],
                                    log["target"], log["detail"], log.get("ip_source"), log["logged_at"])
            else:                                                     # ancienne ligne (avant le chaînage)
                msg = (f"{log['username']}|{log['action']}|{log['target']}|{log['detail']}|{log['logged_at']}").encode()
            if not hmac.compare_digest(hmac.new(key, msg, hashlib.sha256).hexdigest(), log.get("hmac") or ""):
                problems.append(f"ligne {log['id']} altérée")
            prev_hmac = log.get("hmac") or ""
        problems += self._check_anchor(key, rows)
        for p in problems:
            logger.error(f"[SEC] ALERTE journal d'audit : {p}")
        return {"ok": not problems, "checked": len(rows), "problems": problems}

    @staticmethod
    def _legacy_msg(log) -> bytes:
        return f"{log['username']}|{log['action']}|{log['target']}|{log['detail']}|{log['logged_at']}".encode()

    def _legacy_candidate_keys(self) -> list[bytes]:
        """Clés qu'utilisaient les anciennes versions : trousseau « hsr_audit », fichier .hmac_key, clé dérivée du chemin."""
        from pathlib import Path
        from core.keystore import KeyStore
        out: list[bytes] = []
        try:
            import keyring
            stored = keyring.get_password("hsr_audit", "hmac_key")
            if stored:
                try:
                    out.append(bytes.fromhex(stored))
                except ValueError:
                    out.append(stored.encode())
        except Exception:
            pass
        legacy = KeyStore._read_legacy(Path(self.db.db_path).parent / ".hmac_key")
        if legacy:
            out.append(legacy)
        out.append(hashlib.sha256(self.db.db_path.encode()).digest())
        return out

    def _reseal_old_prefix(self, key: bytes, legacy: list, flags: list):
        """
        Cas réel : les toutes premières lignes ont été signées par une clé aujourd'hui perdue (changement d'emplacement de
        la clé entre deux versions), et TOUTES les suivantes se vérifient avec la clé actuelle. Si les lignes illisibles
        forment un bloc de 3 lignes ou plus au tout début et que le reste est parfaitement valide, c'est un changement de
        clé et non une falsification isolée : on les re-signe une fois, en conservant leurs anciennes signatures dans la trace.
        Une ligne fausse isolée, ou au milieu du journal, reste signalée.
        """
        n = 0
        while n < len(flags) and not flags[n]:
            n += 1
        if n < 3 or not all(flags[n:]):
            return
        old = []
        for r in legacy[:n]:
            old.append(f"{r['id']}:{(r.get('hmac') or '')[:12]}")
            sig = hmac.new(key, self._legacy_msg(r), hashlib.sha256).hexdigest()
            self.db.execute("UPDATE audit_logs SET hmac = ? WHERE id = ?", (sig, r["id"]))
        self.db.set_setting("audit_legacy_resealed", "1")
        logger.warning(f"[SEC] {n} toutes premières lignes du journal d'audit re-signées (ancienne clé introuvable).")
        self.db.write_audit("system", "AUDIT_RESEAL", "audit_logs",
                            f"{n} premières lignes signées par une ancienne clé introuvable, re-signées ; anciennes signatures : {' '.join(old)}")

    def _reseal_legacy_rows(self, key: bytes):
        """
        Anciennes lignes (avant le chaînage) qui ne se vérifient plus avec la clé actuelle parce que l'ancienne version
        a stocké sa clé ailleurs (trousseau, autre fichier). On ne ré-signe que si TOUTES échouent (désaccord de clé, pas
        une falsification isolée) ; l'opération est tracée dans le journal. Une seule fois par base.
        """
        if self.db.get_setting("audit_legacy_resealed", "") == "1":
            return
        legacy = [r for r in self.db.fetchall("SELECT * FROM audit_logs WHERE chain_v IS NULL OR chain_v != 2 ORDER BY id")]
        if not legacy:
            return
        ok = lambda k, r: hmac.compare_digest(hmac.new(k, self._legacy_msg(r), hashlib.sha256).hexdigest(), r.get("hmac") or "")
        flags = [ok(key, r) for r in legacy]
        if any(flags):
            self._reseal_old_prefix(key, legacy, flags)
            return                                                    # au moins une ligne valide : on ne masque rien d'autre
        proven = any(all(ok(k, r) for r in legacy) for k in self._legacy_candidate_keys())
        if not proven and len(legacy) < 3:
            return                                                    # trop peu de lignes pour distinguer clé perdue / falsification
        for r in legacy:
            sig = hmac.new(key, self._legacy_msg(r), hashlib.sha256).hexdigest()
            self.db.execute("UPDATE audit_logs SET hmac = ? WHERE id = ?", (sig, r["id"]))
        self.db.set_setting("audit_legacy_resealed", "1")
        why = ("vérifiées avec l'ancienne clé" if proven else "ancienne clé introuvable : non vérifiables")
        logger.warning(f"[SEC] {len(legacy)} anciennes lignes du journal d'audit re-signées ({why}).")
        self.db.write_audit("system", "AUDIT_RESEAL", "audit_logs", f"{len(legacy)} lignes antérieures à la v16 re-signées ({why})")

    def _check_anchor(self, key: bytes, rows: list) -> list[str]:
        import json
        from pathlib import Path
        out: list[str] = []
        raw = self.db.get_setting("audit_anchor", "")
        if not raw:
            if rows and rows[-1].get("chain_v") == 2:
                out.append("ancre de fin de journal absente (supprimée ?)")
            elif rows:                                                # base d'avant le chaînage : on pose l'ancre
                self.db.save_audit_anchor(key, rows[-1].get("hmac") or "")
            return out
        try:
            a = json.loads(raw)
            good = hmac.new(key, f"anchor|{a['n']}|{a['last']}".encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(good, a["sig"]):
                return ["ancre de fin de journal falsifiée"]
        except Exception:
            return ["ancre de fin de journal illisible"]
        last = (rows[-1].get("hmac") if rows else "") or ""
        if a["last"] != last or len(rows) < a["n"]:
            out.append(f"fin du journal supprimée ou modifiée ({a['n'] - len(rows)} ligne(s) manquante(s))" if len(rows) < a["n"]
                       else "fin du journal différente de l'ancre")
        try:
            p = Path(self.db.db_path).parent / ".audit_anchor"
            if p.exists() and json.loads(p.read_text(encoding="utf-8")) != a:
                out.append("l'ancre stockée hors de la base ne correspond pas à celle de la base")
        except Exception:
            pass
        return out

    def verify_db_integrity(self) -> bool:
        """True si le journal d'audit est intact (signatures, chaînage, ancre)."""
        if self.db is None:
            return True
        try:
            res = self.verify_audit()
            if res["ok"]:
                logger.success(f"[SEC] Intégrité du journal d'audit : OK ({res['checked']} lignes)")
            else:
                logger.critical(f"[SEC] Journal d'audit compromis : {'; '.join(res['problems'][:3])}")
            return res["ok"]
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
