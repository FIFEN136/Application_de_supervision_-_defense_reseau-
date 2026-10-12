"""
HSR — Gestionnaire de base de données SQLite (avec chiffrement applicatif)
Procus Tech

Utilise sqlite3 standard + chiffrement des données sensibles via cryptography.
Si SQLCipher est disponible sur le poste, remplacer sqlite3 par sqlcipher3.
"""
import sqlite3
import os
import hashlib
import hmac
import json
from pathlib import Path
from loguru import logger

from database.models import SCHEMA_SQL, SEED_SQL


class DatabaseManager:
    """
    Gère la connexion SQLite locale et les opérations CRUD.
    Journal d'audit protégé par HMAC-SHA256.
    """

    DB_FILENAME = "hsr_data.db"

    def __init__(self, db_path: str = None):
        if db_path is None:
            app_dir = Path.home() / ".procus_hsr"
            app_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(app_dir / self.DB_FILENAME)

        self.db_path = db_path
        self._conn: sqlite3.Connection = None
        logger.info(f"[DB] Base de données : {self.db_path}")

    # ─────────────────────────────────────────
    # Connexion & initialisation
    # ─────────────────────────────────────────

    def initialize(self):
        """Ouvre la connexion, crée les tables et insère les données initiales."""
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA foreign_keys=ON;")
        self._run_schema()
        self._run_seed()
        logger.success("[DB] Base initialisée avec succès.")

    def _run_schema(self):
        try:
            self._conn.executescript(SCHEMA_SQL)
            self._conn.commit()
        except sqlite3.Error as e:
            logger.error(f"[DB] Erreur schéma : {e}")
            raise

    def _run_seed(self):
        try:
            self._conn.executescript(SEED_SQL)
            self._conn.commit()
        except sqlite3.Error as e:
            logger.warning(f"[DB] Seed (ignorée si déjà présente) : {e}")

        # Remplacer le hash factice __CHANGE_ME__ par le vrai hash PBKDF2 de "admin"
        try:
            row = self._conn.execute(
                "SELECT password_hash FROM users WHERE login='admin'"
            ).fetchone()
            if row and row[0] == "__CHANGE_ME__":
                import secrets as _sec
                salt = _sec.token_hex(16)
                import hashlib as _hl
                key = _hl.pbkdf2_hmac(
                    "sha256", b"admin", salt.encode(), iterations=260_000
                )
                real_hash = f"{salt}${key.hex()}"
                self._conn.execute(
                    "UPDATE users SET password_hash=? WHERE login='admin'",
                    (real_hash,)
                )
                self._conn.commit()
                logger.info("[DB] Mot de passe admin initialisé (admin/admin).")
        except Exception as e:
            logger.warning(f"[DB] Init hash admin : {e}")

    def close(self):
        if self._conn:
            self._conn.close()
            logger.info("[DB] Connexion fermée.")

    # ─────────────────────────────────────────
    # Accès générique
    # ─────────────────────────────────────────

    def execute(self, sql: str, params: tuple = ()):
        """Exécute une requête INSERT/UPDATE/DELETE, retourne le cursor."""
        cur = self._conn.execute(sql, params)
        self._conn.commit()
        return cur

    def fetchall(self, sql: str, params: tuple = ()) -> list:
        """Exécute une requête SELECT et retourne toutes les lignes."""
        cur = self._conn.execute(sql, params)
        rows = cur.fetchall()
        return [dict(r) for r in rows]

    def fetchone(self, sql: str, params: tuple = ()) -> dict | None:
        """Exécute une requête SELECT et retourne la première ligne."""
        cur = self._conn.execute(sql, params)
        row = cur.fetchone()
        return dict(row) if row else None

    # ─────────────────────────────────────────
    # Hosts
    # ─────────────────────────────────────────

    # ─────────────────────────────────────────
    # Helpers chiffrement SNMP (point 7)
    # ─────────────────────────────────────────

    @staticmethod
    def _encrypt_community(community: str) -> str:
        try:
            from core.security import CryptoHelper
            return CryptoHelper.encrypt(community)
        except Exception:
            return community

    @staticmethod
    def _decrypt_community(token: str) -> str:
        try:
            from core.security import CryptoHelper
            return CryptoHelper.decrypt(token)
        except Exception:
            return token

    def _decrypt_hosts(self, rows: list) -> list:
        """Déchiffre snmp_community sur une liste d'hôtes."""
        for row in rows:
            if "snmp_community" in row:
                row["snmp_community"] = self._decrypt_community(row["snmp_community"])
        return rows

    # ─────────────────────────────────────────
    # Hosts
    # ─────────────────────────────────────────

    def get_all_hosts(self) -> list:
        rows = self.fetchall("""
            SELECT h.*, g.name AS group_name
            FROM hosts h
            LEFT JOIN host_groups g ON h.group_id = g.id
            ORDER BY h.name
        """)
        return self._decrypt_hosts(rows)

    def get_host_by_id(self, host_id: int) -> dict | None:
        row = self.fetchone("SELECT * FROM hosts WHERE id = ?", (host_id,))
        if row and "snmp_community" in row:
            row["snmp_community"] = self._decrypt_community(row["snmp_community"])
        return row

    def add_host(self, name: str, ip: str, group_id: int = None,
                 device_type: str = "unknown", location: str = "",
                 snmp_community: str = "public") -> int:
        encrypted = self._encrypt_community(snmp_community)
        cur = self.execute("""
            INSERT INTO hosts (name, ip_address, group_id, device_type, location, snmp_community)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (name, ip, group_id, device_type, location, encrypted))
        return cur.lastrowid

    def update_host_status(self, host_id: int, status: str, last_check: str):
        self.execute("""
            UPDATE hosts SET status = ?, last_check = ?, updated_at = datetime('now')
            WHERE id = ?
        """, (status, last_check, host_id))

    # ─────────────────────────────────────────
    # Events / Problèmes
    # ─────────────────────────────────────────

    def get_events(self, severity: str = None, limit: int = 500) -> list:
        if severity and severity != "all":
            return self.fetchall("""
                SELECT * FROM events WHERE severity = ?
                ORDER BY occurred_at DESC LIMIT ?
            """, (severity, limit))
        return self.fetchall(
            "SELECT * FROM events ORDER BY occurred_at DESC LIMIT ?", (limit,)
        )

    def add_event(self, host_id: int, host_name: str, group_name: str,
                  severity: str, event_type: str, description: str,
                  port: int = None, state_before: str = None,
                  state_after: str = None, tags: list = None) -> int:
        tags_json = json.dumps(tags) if tags else "[]"
        cur = self.execute("""
            INSERT INTO events
              (host_id, host_name, group_name, severity, event_type,
               description, port, state_before, state_after, tags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (host_id, host_name, group_name, severity, event_type,
              description, port, state_before, state_after, tags_json))
        return cur.lastrowid

    def acknowledge_event(self, event_id: int, username: str):
        from datetime import datetime
        self.execute("""
            UPDATE events
            SET acknowledged = 1, acknowledged_by = ?, acknowledged_at = ?
            WHERE id = ?
        """, (username, datetime.now().isoformat(timespec='seconds'), event_id))

    def get_active_problems_count(self) -> int:
        row = self.fetchone(
            "SELECT COUNT(*) as cnt FROM events WHERE acknowledged = 0 AND resolved_at IS NULL"
        )
        return row["cnt"] if row else 0

    # ─────────────────────────────────────────
    # Métriques
    # ─────────────────────────────────────────

    def add_metric(self, host_id: int, metric_name: str, value: float,
                   unit: str = "", interface: str = None):
        self.execute("""
            INSERT INTO metrics (host_id, metric_name, interface, value, unit)
            VALUES (?, ?, ?, ?, ?)
        """, (host_id, metric_name, interface, value, unit))

    def get_latest_metrics(self, limit: int = 100) -> list:
        return self.fetchall("""
            SELECT h.name AS host_name, m.metric_name, m.value, m.unit,
                   m.interface, m.collected_at
            FROM metrics m
            JOIN hosts h ON m.host_id = h.id
            ORDER BY m.collected_at DESC
            LIMIT ?
        """, (limit,))

    def get_metric_history(self, host_id: int, metric_name: str,
                           hours: int = 24) -> list:
        return self.fetchall("""
            SELECT value, collected_at FROM metrics
            WHERE host_id = ? AND metric_name = ?
              AND collected_at >= datetime('now', ?)
            ORDER BY collected_at ASC
        """, (host_id, metric_name, f"-{hours} hours"))

    # ─────────────────────────────────────────
    # Audit log (HMAC protégé)
    # ─────────────────────────────────────────

    def write_audit(self, username: str, action: str, target: str = "",
                    detail: str = "", user_id: int = None, ip: str = ""):
        from datetime import datetime
        ts = datetime.now().isoformat(timespec='seconds')
        # HMAC-SHA256 sur (username|action|target|detail|ts)
        key = self._get_hmac_key()
        msg = f"{username}|{action}|{target}|{detail}|{ts}".encode()
        sig = hmac.new(key, msg, hashlib.sha256).hexdigest()
        self.execute("""
            INSERT INTO audit_logs (user_id, username, action, target, detail, ip_source, hmac, logged_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (user_id, username, action, target, detail, ip, sig, ts))

    def _get_hmac_key(self) -> bytes:
        """
        Clé HMAC pour le journal d'audit.
        Priorité :
          1. keyring OS (idéal, protégé par le trousseau système)
          2. Fichier ~/.procus_hsr/.hmac_key (chmod 600 — généré aléatoirement)
          3. Dérivation du chemin DB (fallback dégradé, loggué)
        La clé est générée une seule fois et réutilisée.
        """
        # ── 1. keyring OS ──
        try:
            import keyring as _kr
            stored = _kr.get_password("hsr_audit", "hmac_key")
            if stored:
                return stored.encode()
        except Exception:
            pass

        # ── 2. Fichier protégé ~/.procus_hsr/.hmac_key ──
        try:
            key_path = Path(self.db_path).parent / ".hmac_key"
            if key_path.exists():
                raw = key_path.read_bytes().strip()
                if len(raw) >= 32:
                    return raw
            # Première fois : générer une clé aléatoire 64 octets hex
            new_key = os.urandom(32)
            key_path.write_bytes(new_key)
            # Restrictions POSIX (ignorées silencieusement sur Windows)
            try:
                import stat
                key_path.chmod(stat.S_IRUSR | stat.S_IWUSR)  # chmod 600
            except Exception:
                pass
            logger.info("[DB] Clé HMAC générée dans .hmac_key (600).")
            # Essayer de persister aussi dans keyring pour les prochains lancements
            try:
                import keyring as _kr2
                _kr2.set_password("hsr_audit", "hmac_key", new_key.hex())
            except Exception:
                pass
            return new_key
        except Exception as e:
            logger.warning(f"[DB] Impossible d'écrire .hmac_key : {e}")

        # ── 3. Fallback dégradé (prévisible — loggué) ──
        logger.warning("[DB] HMAC fallback : clé dérivée du chemin DB (sécurité réduite).")
        return hashlib.sha256(self.db_path.encode()).digest()

    def get_audit_logs(self, limit: int = 500) -> list:
        return self.fetchall(
            "SELECT * FROM audit_logs ORDER BY logged_at DESC LIMIT ?", (limit,)
        )

    # ─────────────────────────────────────────
    # Groupes & Templates
    # ─────────────────────────────────────────

    def get_host_groups(self) -> list:
        return self.fetchall("""
            SELECT g.*, COUNT(h.id) AS host_count,
                   SUM(CASE WHEN e.resolved_at IS NULL AND e.acknowledged=0 THEN 1 ELSE 0 END) AS problem_count
            FROM host_groups g
            LEFT JOIN hosts h ON h.group_id = g.id
            LEFT JOIN events e ON e.host_id = h.id
            GROUP BY g.id
            ORDER BY g.name
        """)

    def get_templates(self) -> list:
        return self.fetchall("SELECT * FROM templates ORDER BY name")

    def get_users(self) -> list:
        return self.fetchall(
            "SELECT id, login, full_name, role, group_name, active, last_login FROM users ORDER BY login"
        )

    def get_media_types(self) -> list:
        return self.fetchall("SELECT * FROM media_types ORDER BY name")

    # ─────────────────────────────────────────
    # Statistiques tableau de bord
    # ─────────────────────────────────────────

    def get_dashboard_stats(self) -> dict:
        hosts = self.fetchone("SELECT COUNT(*) as total FROM hosts")
        online = self.fetchone("SELECT COUNT(*) as cnt FROM hosts WHERE status='online'")
        offline = self.fetchone("SELECT COUNT(*) as cnt FROM hosts WHERE status='offline'")
        unreachable = self.fetchone("SELECT COUNT(*) as cnt FROM hosts WHERE status='unreachable'")
        problems = self.fetchone(
            "SELECT COUNT(*) as cnt FROM events WHERE acknowledged=0 AND resolved_at IS NULL"
        )
        severity_counts = self.fetchall("""
            SELECT severity, COUNT(*) as cnt FROM events
            WHERE acknowledged=0 AND resolved_at IS NULL
            GROUP BY severity
        """)

        total = hosts["total"] if hosts else 0
        return {
            "total": total,
            "online": online["cnt"] if online else 0,
            "offline": offline["cnt"] if offline else 0,
            "unreachable": unreachable["cnt"] if unreachable else 0,
            "unknown": total - (online["cnt"] or 0) - (offline["cnt"] or 0) - (unreachable["cnt"] or 0),
            "problems_active": problems["cnt"] if problems else 0,
            "severity_counts": {r["severity"]: r["cnt"] for r in severity_counts},
        }
