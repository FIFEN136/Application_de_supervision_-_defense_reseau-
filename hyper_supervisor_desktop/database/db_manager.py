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
import threading
from pathlib import Path
from loguru import logger

from database import crypto_db

from database.models import SCHEMA_SQL, SEED_SQL


AUDIT_GENESIS = "GENESIS"


def audit_message(prev: str, user_id, username, action, target, detail, ip, ts) -> bytes:
    """Contenu signé d'une ligne chaînée : tous les champs, plus l'empreinte de la ligne précédente."""
    return f"v2|{prev}|{user_id if user_id is not None else ''}|{username}|{action}|{target}|{detail}|{ip}|{ts}".encode()


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
        self._conn = None
        self._key_hex = None
        self.encrypted = False
        self.mode = "plain"
        self._dirty = False
        self._closed = False
        # Connexion partagée entre plusieurs QThread : toute opération est sérialisée
        self._lock = threading.RLock()
        logger.info(f"[DB] Base de données : {self.db_path}")

    # ─────────────────────────────────────────
    # Connexion & initialisation
    # ─────────────────────────────────────────

    def initialize(self):
        """Ouvre la connexion, crée les tables et insère les données initiales."""
        self.mode, self._key_hex = crypto_db.prepare(self.db_path)   # "sqlcipher" | "file" | "plain"
        self.encrypted = self.mode != "plain"
        if self.mode == "file":
            self._open_file_mode()
        else:
            self._conn = crypto_db.connect(self.db_path, self._key_hex)
            self._conn.row_factory = crypto_db.row_factory(self._key_hex)
            self._conn.execute("PRAGMA journal_mode=WAL;")
            self._conn.execute("PRAGMA foreign_keys=ON;")
            self._run_schema()
            self._run_seed()
        self._restrict_permissions()
        logger.success(f"[DB] Base initialisée avec succès (chiffrement : {self.mode}).")

    # ── mode « fichier chiffré » : la base vit en mémoire, le disque ne reçoit que du chiffré ──
    FLUSH_INTERVAL_S = 15

    def _open_file_mode(self):
        key = bytes.fromhex(self._key_hex)
        conn = sqlite3.connect(":memory:", check_same_thread=False)
        conn.row_factory = sqlite3.Row
        old = None
        if os.path.exists(self.db_path) and os.path.getsize(self.db_path) > 0:
            if crypto_db.is_file_encrypted(self.db_path):
                with open(self.db_path, "rb") as f:
                    conn.deserialize(crypto_db.normalize_image(crypto_db.decrypt_bytes(key, f.read())))
            else:                                                  # base en clair existante : copie en mémoire puis chiffrement
                src = sqlite3.connect(self.db_path)
                try:
                    src.backup(conn)
                finally:
                    src.close()
                old = self.db_path + ".plain.old"
                os.replace(self.db_path, old)
        self._conn = conn
        self._dirty = True
        self._conn.execute("PRAGMA foreign_keys=ON;")
        self._run_schema()
        self._run_seed()
        self.flush()
        if old:
            self._verify_encrypted_file(key)                       # relecture déchiffrée avant d'effacer l'ancien fichier
            crypto_db._wipe(old)
            for suffix in ("-wal", "-shm"):
                if os.path.exists(self.db_path + suffix):
                    crypto_db._wipe(self.db_path + suffix)
            logger.success("[DB] Base migrée vers le fichier chiffré (AES-256-GCM) ; ancien fichier en clair effacé.")
        self._flush_stop = threading.Event()
        self._flusher = threading.Thread(target=self._flush_loop, name="db-flush", daemon=True)
        self._flusher.start()
        import atexit
        atexit.register(self._safe_flush)

    def _verify_encrypted_file(self, key: bytes):
        chk = sqlite3.connect(":memory:")
        try:
            with open(self.db_path, "rb") as f:
                chk.deserialize(crypto_db.normalize_image(crypto_db.decrypt_bytes(key, f.read())))
            for (t,) in self._conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall():
                q = 'SELECT COUNT(*) FROM "' + t.replace('"', '""') + '"'      # nosec B608 - noms issus de sqlite_master
                if chk.execute(q).fetchone()[0] != self._conn.execute(q).fetchone()[0]:
                    raise crypto_db.DatabaseEncryptedError(f"Migration incomplète (table {t}).")
        finally:
            chk.close()

    def flush(self):
        """Écrit la base chiffrée sur le disque si elle a changé (mode fichier)."""
        if self.mode != "file" or self._conn is None or self._closed:
            return
        with self._lock:
            if not self._dirty:
                return
            self._conn.commit()
            blob = crypto_db.encrypt_bytes(bytes.fromhex(self._key_hex), crypto_db.serialize_db(self._conn))
            crypto_db.write_atomic(self.db_path, blob)
            self._dirty = False

    def _flush_loop(self):
        while not self._flush_stop.wait(self.FLUSH_INTERVAL_S):
            self._safe_flush()

    def _safe_flush(self):
        try:
            self.flush()
        except Exception as e:
            logger.error(f"[DB] Écriture chiffrée impossible : {e}")

    def _restrict_permissions(self):
        """Base et journaux WAL lisibles par le seul propriétaire (0600) sous Linux/macOS. Sous Windows, os.chmod
        n'applique pas les ACL : le dossier de l'utilisateur reste la protection. Jamais bloquant."""
        if os.name != "posix":
            return
        for suffix in ("", "-wal", "-shm"):
            try:
                os.chmod(self.db_path + suffix, 0o600)
            except OSError:
                pass

    def _run_schema(self):
        try:
            self._conn.executescript(SCHEMA_SQL)
            self._migrate()
            self._conn.commit()
        except crypto_db.SQLITE_ERRORS as e:
            logger.error(f"[DB] Erreur schéma : {e}")
            raise

    def _migrate(self):
        """Migrations idempotentes (bases créées par une version précédente)."""
        cols = {r[1] for r in self._conn.execute("PRAGMA table_info(hosts)")}
        statements = {          # DDL constantes (aucune donnée externe dans le SQL)
            "mac_address": "ALTER TABLE hosts ADD COLUMN mac_address TEXT",
            "vendor":      "ALTER TABLE hosts ADD COLUMN vendor TEXT",
            "network_id":  "ALTER TABLE hosts ADD COLUMN network_id INTEGER REFERENCES networks(id) ON DELETE SET NULL",
            "first_seen":  "ALTER TABLE hosts ADD COLUMN first_seen TEXT",
            "reach_method": "ALTER TABLE hosts ADD COLUMN reach_method TEXT",
            "criticality": "ALTER TABLE hosts ADD COLUMN criticality INTEGER DEFAULT 3",
            "approved":    "ALTER TABLE hosts ADD COLUMN approved INTEGER DEFAULT 1",
            "owner":       "ALTER TABLE hosts ADD COLUMN owner TEXT",
            "failed_probes": "ALTER TABLE hosts ADD COLUMN failed_probes INTEGER DEFAULT 0",
            # v16.1 : fiche détaillée d'un appareil (carte réseau)
            "conn_type":   "ALTER TABLE hosts ADD COLUMN conn_type TEXT",         # wifi | ethernet
            "conn_detail": "ALTER TABLE hosts ADD COLUMN conn_detail TEXT",       # « Port 4 », nom du Wi-Fi…
            "conn_source": "ALTER TABLE hosts ADD COLUMN conn_source TEXT",       # manual | local | agent | snmp | heuristic
            "model":       "ALTER TABLE hosts ADD COLUMN model TEXT",
            "ipv6":        "ALTER TABLE hosts ADD COLUMN ipv6 TEXT",
            "wifi_band":   "ALTER TABLE hosts ADD COLUMN wifi_band TEXT",
            "rssi":        "ALTER TABLE hosts ADD COLUMN rssi INTEGER",
            "link_mbps":   "ALTER TABLE hosts ADD COLUMN link_mbps INTEGER",
            "last_seen":   "ALTER TABLE hosts ADD COLUMN last_seen TEXT",
            "dns_name":    "ALTER TABLE hosts ADD COLUMN dns_name TEXT",         # nom annoncé (NetBIOS / mDNS / DNS)
            "os_guess":    "ALTER TABLE hosts ADD COLUMN os_guess TEXT",         # système probable (TTL)
            "last_alive_ts": "ALTER TABLE hosts ADD COLUMN last_alive_ts INTEGER",   # dernier signe de vie (epoch s)
            "type_source": "ALTER TABLE hosts ADD COLUMN type_source TEXT",          # manual : type choisi par l'utilisateur
            "flap_log":    "ALTER TABLE hosts ADD COLUMN flap_log TEXT",             # dates (epoch) des derniers changements en ligne/hors ligne
        }
        for col, ddl in statements.items():
            if col not in cols:
                self._conn.execute(ddl)
        acols = {r[1] for r in self._conn.execute("PRAGMA table_info(audit_logs)")}
        for col, ddl in (("prev_hmac", "ALTER TABLE audit_logs ADD COLUMN prev_hmac TEXT"),
                         ("chain_v", "ALTER TABLE audit_logs ADD COLUMN chain_v INTEGER")):
            if acols and col not in acols:
                self._conn.execute(ddl)
        ncols = {r[1] for r in self._conn.execute("PRAGMA table_info(networks)")}
        net_stmts = {
            "authorized_by": "ALTER TABLE networks ADD COLUMN authorized_by TEXT",
            "authorized_at": "ALTER TABLE networks ADD COLUMN authorized_at TEXT",
        }
        for col, ddl in {         # v16.6 : supervision indépendante par réseau
            "paused": "ALTER TABLE networks ADD COLUMN paused INTEGER DEFAULT 0",                    # 1 = supervision suspendue
            "discover_every_s": "ALTER TABLE networks ADD COLUMN discover_every_s INTEGER DEFAULT 300",  # redécouverte
        }.items():
            if ncols and col not in ncols:
                self._conn.execute(ddl)
        added_auth = False
        for col, ddl in net_stmts.items():
            if ncols and col not in ncols:
                self._conn.execute(ddl)
                added_auth = True
        if added_auth:        # réseaux saisis avant cette version : l'administrateur les avait déjà autorisés en les ajoutant
            self._conn.execute("UPDATE networks SET authorized_by = 'administrateur (avant v11)', "
                               "authorized_at = created_at WHERE authorized_at IS NULL")

        # Migration v12 : colonnes pour authentification renforcée et scanner amélioré
        ucols = {r[1] for r in self._conn.execute("PRAGMA table_info(users)")}
        if "password_changed" not in ucols:
            self._conn.execute("ALTER TABLE users ADD COLUMN password_changed INTEGER DEFAULT 0")

        pcols = {r[1] for r in self._conn.execute("PRAGMA table_info(port_states)")}
        if "service_banner" not in pcols:
            self._conn.execute("ALTER TABLE port_states ADD COLUMN service_banner TEXT")
        if "service_version" not in pcols:
            self._conn.execute("ALTER TABLE port_states ADD COLUMN service_version TEXT")

        # Créer la table notification_queue si elle n'existe pas
        try:
            self._conn.execute(
                """CREATE TABLE IF NOT EXISTS notification_queue (
                    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id            INTEGER,
                    host_id             INTEGER,
                    event_hash          TEXT NOT NULL,
                    notification_count  INTEGER DEFAULT 1,
                    last_sent_at        TEXT NOT NULL DEFAULT (datetime('now')),
                    created_at          TEXT NOT NULL DEFAULT (datetime('now')),
                    UNIQUE(event_hash, host_id)
                )""")
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_notif_sent ON notification_queue(last_sent_at)")
        except Exception as e:
            logger.debug(f"[DB] notification_queue (créée si absente) : {e}")
        # Migration unique : les hôtes enregistrés automatiquement (machine locale, passerelle,
        # découverte) n'ont pas d'agent SNMP → ne plus les marquer « injoignables ».
        done = self._conn.execute("SELECT 1 FROM settings WHERE key='mig_auto_snmp_off'").fetchone()
        if not done:
            self._conn.execute(
                "UPDATE hosts SET snmp_enabled = 0 WHERE location IN "
                "('Machine locale (Procus Secure)', 'Passerelle par défaut', 'Découvert automatiquement', "
                "'Découvert sur le réseau saisi')")
            self._conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('mig_auto_snmp_off','1')")

    def _run_seed(self):
        try:
            self._conn.executescript(SEED_SQL)
            self._conn.commit()
        except crypto_db.SQLITE_ERRORS as e:
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

    # ─────────────────────────────────────────
    # Sauvegarde / restauration (API backup SQLite : cohérente, compatible WAL)
    # ─────────────────────────────────────────

    REQUIRED_TABLES = {"hosts", "events", "users", "settings", "metrics",
                       "baselines", "audit_logs", "port_states", "media_types"}

    def backup_to(self, dest_path: str) -> str:
        """
        Sauvegarde complète et cohérente, même pendant que les workers écrivent.
        (Une simple copie du fichier .db ignorerait le journal WAL → sauvegarde incomplète.)
        """
        with self._lock:
            if self.mode == "file":
                self._conn.commit()
                crypto_db.write_atomic(dest_path, crypto_db.encrypt_bytes(bytes.fromhex(self._key_hex), crypto_db.serialize_db(self._conn)))
                logger.info(f"[DB] Sauvegarde écrite : {dest_path}")
                return dest_path
            dest = crypto_db.connect(dest_path, self._key_hex)         # sauvegarde chiffrée avec la même clé
            try:
                self._conn.commit()
                self._conn.backup(dest)
            finally:
                dest.close()
        logger.info(f"[DB] Sauvegarde écrite : {dest_path}")
        return dest_path

    @classmethod
    def validate_backup(cls, path: str, key_hex: str = None) -> tuple[bool, str]:
        """Vérifie qu'un fichier est une base saine (en clair, ou chiffrée avec la clé fournie) contenant le schéma Procus Secure."""
        try:
            plain = crypto_db.is_plaintext(path)
            if not plain and not key_hex:
                return False, "Ce fichier n'est pas une base SQLite lisible (chiffrée avec une autre clé ?)."
            conn = crypto_db.open_readable(path, key_hex)
            try:
                if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    return False, "Base corrompue (integrity_check en échec)."
                tables = {r[0] for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'")}
            finally:
                conn.close()
            missing = cls.REQUIRED_TABLES - tables
            if missing:
                return False, "Schéma Procus Secure incomplet : " + ", ".join(sorted(missing))
            return True, "OK"
        except (crypto_db.SQLITE_ERRORS + (OSError, crypto_db.DatabaseEncryptedError)) as e:
            return False, f"Fichier illisible : {e}"

    def restore_from(self, src_path: str) -> str:
        """
        Restaure une sauvegarde À CHAUD (sans redémarrage) :
          1. valide le fichier choisi,
          2. écrit une sauvegarde de sécurité de la base actuelle,
          3. recopie via l'API backup dans la connexion ouverte (pas de -wal/-shm périmés).
        Retourne le chemin de la sauvegarde de sécurité. Lève ValueError si le fichier est invalide.
        """
        from datetime import datetime
        ok, msg = self.validate_backup(src_path, self._key_hex)
        if not ok:
            raise ValueError(msg)
        safety = f"{self.db_path}.pre_restore_{datetime.now().strftime('%Y%m%d_%H%M%S')}.bak"
        with self._lock:
            self.backup_to(safety)
            tmp = None
            try:
                if self.mode == "file":
                    src = crypto_db.open_readable(src_path, self._key_hex)
                elif self._key_hex and crypto_db.is_plaintext(src_path):    # sauvegarde ancienne (en clair) → copie chiffrée
                    tmp = src_path + ".restore.tmp"
                    crypto_db.export_plain_to_encrypted(src_path, tmp, self._key_hex)
                    src = crypto_db.connect(tmp, self._key_hex)
                elif self._key_hex:
                    src = crypto_db.connect(src_path, self._key_hex)
                else:
                    src = sqlite3.connect(f"file:{src_path}?mode=ro", uri=True)
                try:
                    src.backup(self._conn)
                finally:
                    src.close()
            finally:
                if tmp:
                    crypto_db._wipe(tmp)
            self._conn.commit()
            self._run_schema()          # complète le schéma si la sauvegarde est plus ancienne
            self._dirty = True
            self.flush()
        logger.warning(f"[DB] Base restaurée depuis {src_path} (sécurité : {safety})")
        return safety

    def close(self):
        if self._conn:
            if self.mode == "file":
                if getattr(self, "_flush_stop", None):
                    self._flush_stop.set()
                self._safe_flush()
            self._closed = True
            self._conn.close()
            logger.info("[DB] Connexion fermée.")

    # ─────────────────────────────────────────
    # Accès générique
    # ─────────────────────────────────────────

    def execute(self, sql: str, params: tuple = ()):
        """Exécute une requête INSERT/UPDATE/DELETE, retourne le cursor (thread-safe)."""
        with self._lock:
            try:
                cur = self._conn.execute(sql, params)
                self._conn.commit()
                self._dirty = True
            except Exception:
                self._conn.rollback()
                raise
            return cur

    def fetchall(self, sql: str, params: tuple = ()) -> list:
        """Exécute une requête SELECT et retourne toutes les lignes (thread-safe)."""
        with self._lock:
            cur = self._conn.execute(sql, params)
            rows = cur.fetchall()
        return [dict(r) for r in rows]

    def fetchone(self, sql: str, params: tuple = ()) -> dict | None:
        """Exécute une requête SELECT et retourne la première ligne (thread-safe)."""
        with self._lock:
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

    def merge_hosts(self, keep_id: int, drop_id: int):
        """Fusionne un doublon dans l'hôte conservé : l'historique (événements, métriques) est
        rattaché à `keep_id`, puis `drop_id` est supprimé (ports/baselines suivent en cascade)."""
        if keep_id == drop_id:
            return
        for sql in ("UPDATE events SET host_id = ? WHERE host_id = ?",
                    "UPDATE metrics SET host_id = ? WHERE host_id = ?",
                    "UPDATE sfp_metrics SET host_id = ? WHERE host_id = ?"):
            self.execute(sql, (keep_id, drop_id))
        for table in ("incidents", "pending_actions", "config_snapshots"):
            try:
                self.execute("UPDATE " + table + " SET host_id = ? WHERE host_id = ?", (keep_id, drop_id))  # nosec B608 - nom de table issu d'un tuple constant
            except crypto_db.OPERATIONAL_ERRORS:
                pass                                   # table absente (ancienne base)
        self.execute("DELETE FROM hosts WHERE id = ?", (drop_id,))

    def update_host_reach(self, host_id: int, method: str):
        self.execute("UPDATE hosts SET reach_method = ? WHERE id = ?", (method, host_id))

    def get_latency_series(self, hours: int = 24, bucket_minutes: int = 5, max_hosts: int = 8) -> dict:
        """{nom_hôte: [(bucket_epoch, latence_moy_ms), ...]} — une courbe par équipement (les plus mesurés)."""
        bucket_s = max(1, int(bucket_minutes)) * 60
        rows = self.fetchall("""
            SELECT h.name AS name, m.host_id AS hid,
                   (CAST(strftime('%s', m.collected_at) AS INTEGER) / ?) * ? AS b, AVG(m.value) AS v
            FROM metrics m JOIN hosts h ON h.id = m.host_id
            WHERE m.metric_name = 'latency' AND m.collected_at >= datetime('now', ?)
            GROUP BY m.host_id, b ORDER BY b
        """, (bucket_s, bucket_s, f"-{int(hours)} hours"))
        series: dict[str, list] = {}
        for r in rows:
            series.setdefault(r["name"], []).append((r["b"], r["v"]))
        top = sorted(series, key=lambda n: -len(series[n]))[:max_hosts]
        return {n: series[n] for n in top}

    def get_top_latency(self, limit: int = 5) -> list:
        """Dernière latence connue par équipement, du plus lent au plus rapide."""
        return self.fetchall("""
            SELECT h.name AS name, m.value AS value FROM metrics m
            JOIN hosts h ON h.id = m.host_id
            WHERE m.metric_name = 'latency'
              AND m.id = (SELECT MAX(m2.id) FROM metrics m2
                          WHERE m2.host_id = m.host_id AND m2.metric_name = 'latency')
            ORDER BY m.value DESC LIMIT ?
        """, (int(limit),))

    # ─────────────────────────────────────────
    # Réseaux supervisés
    # ─────────────────────────────────────────

    def get_networks(self) -> list:
        return self.fetchall("""
            SELECT n.*, (SELECT COUNT(*) FROM hosts h WHERE h.network_id = n.id) AS host_count,
                   (SELECT COUNT(*) FROM hosts h WHERE h.network_id = n.id AND h.status = 'online') AS online_count,
                   (SELECT COUNT(*) FROM hosts h WHERE h.network_id = n.id AND h.status = 'offline') AS offline_count
            FROM networks n ORDER BY n.name
        """)

    def add_network(self, name: str, cidr: str, gateway_ip: str = None,
                    kind: str = "lan", auto_monitor: int = 1, authorized_by: str = None) -> int:
        """authorized_by : qui a explicitement autorisé la supervision (le pipeline ignore les réseaux sans autorisation)."""
        clash = self.network_overlap(cidr)
        if clash and clash["cidr"] != cidr:               # même plage exacte : la contrainte d'unicité répond (doublon)
            raise ValueError(f"Ce réseau chevauche « {clash['name']} » ({clash['cidr']}) : deux réseaux ne peuvent pas partager d'adresses.")
        self._set_removed(cidr, False)                      # l'utilisateur le (re)veut : il n'est plus « retiré »
        cur = self.execute(
            "INSERT INTO networks (name, cidr, gateway_ip, kind, auto_monitor, authorized_by, authorized_at) "
            "VALUES (?, ?, ?, ?, ?, ?, CASE WHEN ? IS NULL THEN NULL ELSE datetime('now') END)",
            (name, cidr, gateway_ip, kind, int(bool(auto_monitor)), authorized_by, authorized_by))
        return cur.lastrowid

    def network_overlap(self, cidr: str) -> dict | None:
        """Réseau déjà supervisé dont les adresses chevauchent `cidr` (deux réseaux ne doivent jamais se partager une adresse)."""
        import ipaddress
        try:
            new = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return None
        for n in self.fetchall("SELECT id, name, cidr FROM networks"):
            try:
                if new.version == ipaddress.ip_network(n["cidr"], strict=False).version and new.overlaps(ipaddress.ip_network(n["cidr"], strict=False)):
                    return n
            except ValueError:
                continue
        return None

    # ── réseaux retirés volontairement : l'application ne les recrée jamais d'elle-même ──
    def removed_networks(self) -> set:
        try:
            return set(json.loads(self.get_setting("removed_networks", "[]") or "[]"))
        except (ValueError, TypeError):
            return set()

    def _set_removed(self, cidr: str, removed: bool):
        cur = self.removed_networks()
        (cur.add if removed else cur.discard)(cidr)
        self.set_setting("removed_networks", json.dumps(sorted(cur)))

    def is_removed_network(self, cidr: str) -> bool:
        """True si ce réseau (ou un réseau qui le contient) a été supprimé par l'utilisateur."""
        import ipaddress
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return False
        for c in self.removed_networks():
            try:
                if net.subnet_of(ipaddress.ip_network(c, strict=False)):
                    return True
            except (ValueError, TypeError):
                continue
        return False

    def adopt_orphan_hosts(self, local_cidr: str = None) -> int:
        """
        Rattache à un réseau chaque équipement qui n'en a pas : d'abord le réseau supervisé qui contient son adresse, sinon
        un réseau créé automatiquement (/24, « Réseau local » pour celui de cette machine). Ainsi tout équipement appartient
        à un réseau visible et supprimable dans « Réseaux supervisés ». Retourne le nombre d'équipements rattachés.
        """
        import ipaddress
        nets = []
        for n in self.fetchall("SELECT id, cidr FROM networks"):
            try:
                nets.append((n["id"], ipaddress.ip_network(n["cidr"], strict=False)))
            except ValueError:
                continue
        moved = 0
        pending: dict = {}
        for h in self.fetchall("SELECT id, ip_address FROM hosts WHERE network_id IS NULL"):
            try:
                ip = ipaddress.ip_address(h["ip_address"])
            except ValueError:
                continue
            if ip.version != 4 or not ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
                continue
            hit = next((nid for nid, net in nets if ip in net), None)
            if hit is not None:
                self.execute("UPDATE hosts SET network_id = ? WHERE id = ?", (hit, h["id"]))
                moved += 1
            else:
                pending.setdefault(str(ipaddress.ip_network(f"{ip}/24", strict=False)), []).append(h["id"])
        for cidr, ids in pending.items():
            if self.is_removed_network(cidr):
                continue
            name = "Réseau local" if cidr == local_cidr else f"Réseau {cidr}"
            if self.fetchone("SELECT 1 x FROM networks WHERE name = ?", (name,)):
                name = f"Réseau {cidr}"
            try:
                nid = self.add_network(name, cidr, None, "lan", 1, authorized_by="automatique")
            except Exception:                                # chevauchement ou doublon : on laisse les équipements tels quels
                continue
            for hid in ids:
                self.execute("UPDATE hosts SET network_id = ? WHERE id = ?", (nid, hid))
                moved += 1
        return moved

    def set_network_monitoring(self, network_id: int, enabled: bool = None, every_s: int = None):
        """Suspend / reprend la supervision d'UN réseau (les autres ne sont pas touchés) et règle sa fréquence de redécouverte."""
        if enabled is not None:
            self.execute("UPDATE networks SET paused = ? WHERE id = ?", (0 if enabled else 1, network_id))
        if every_s is not None:
            self.execute("UPDATE networks SET discover_every_s = ? WHERE id = ?", (max(60, min(int(every_s), 86400)), network_id))

    def active_hosts(self) -> list:
        """Équipements dont le réseau n'est pas suspendu : seuls ceux-là sont sondés."""
        paused = {r["id"] for r in self.fetchall("SELECT id FROM networks WHERE paused = 1")}
        return [h for h in self.get_all_hosts() if h.get("network_id") not in paused]

    # Suppression complète : instructions FIXES (jamais de SQL construit), appliquées dans une seule transaction.
    _PURGE_BY_HOST = (
        "DELETE FROM incident_events WHERE event_id IN (SELECT id FROM events WHERE host_id = ?)",
        "DELETE FROM incident_events WHERE incident_id IN (SELECT id FROM incidents WHERE host_id = ?)",
        "DELETE FROM port_states WHERE host_id = ?", "DELETE FROM baselines WHERE host_id = ?",
        "DELETE FROM events WHERE host_id = ?", "DELETE FROM metrics WHERE host_id = ?",
        "DELETE FROM sfp_metrics WHERE host_id = ?", "DELETE FROM incidents WHERE host_id = ?",
        "DELETE FROM pending_actions WHERE host_id = ?", "DELETE FROM config_snapshots WHERE host_id = ?",
        "DELETE FROM notification_queue WHERE host_id = ?", "DELETE FROM host_credentials WHERE host_id = ?",
        "DELETE FROM device_logins WHERE host_id = ?", "DELETE FROM config_backups WHERE host_id = ?",
        "DELETE FROM agents WHERE host_id = ?", "DELETE FROM log_events WHERE host_id = ?",
        "DELETE FROM net_links WHERE host_id = ?", "DELETE FROM net_routes WHERE host_id = ?",
        "DELETE FROM net_fdb WHERE host_id = ?", "DELETE FROM host_roles WHERE host_id = ?",
        "DELETE FROM assess_findings WHERE host_id = ?", "DELETE FROM hosts WHERE id = ?",
    )
    _PURGE_BY_IP = (
        "DELETE FROM arp_bindings WHERE ip = ?", "DELETE FROM bw_samples WHERE ip = ?",
        "DELETE FROM ignored_devices WHERE ip = ?", "DELETE FROM device_blocks WHERE ip = ?",
    )

    def network_footprint(self, network_id: int) -> dict:
        """Ce qu'effacerait la suppression complète (affiché avant de demander confirmation)."""
        hosts = self.fetchall("SELECT id FROM hosts WHERE network_id = ?", (network_id,))
        ev = inc = 0
        for h in hosts:
            ev += self.fetchone("SELECT COUNT(*) c FROM events WHERE host_id = ?", (h["id"],))["c"]
            inc += self.fetchone("SELECT COUNT(*) c FROM incidents WHERE host_id = ?", (h["id"],))["c"]
        return {"hosts": len(hosts), "events": ev, "incidents": inc}

    def purge_network(self, network_id: int) -> dict:
        """
        Supprime le réseau ET tout ce qui le concerne (équipements, mesures, événements, incidents, liens de carte,
        identifiants de connexion, sauvegardes, zones). TOUT ou RIEN : une erreur annule l'ensemble. Le journal d'audit
        n'est jamais touché. Retourne le décompte effacé.
        """
        with self._lock:
            net = self.fetchone("SELECT * FROM networks WHERE id = ?", (network_id,))
            if not net:
                return {"hosts": 0, "events": 0, "incidents": 0}
            summary = self.network_footprint(network_id)
            rows = self.fetchall("SELECT id, ip_address FROM hosts WHERE network_id = ?", (network_id,))
            try:
                for h in rows:
                    for stmt in self._PURGE_BY_HOST:
                        self._conn.execute(stmt, (h["id"],))
                    for stmt in self._PURGE_BY_IP:
                        self._conn.execute(stmt, (h["ip_address"],))
                self._conn.execute("DELETE FROM net_zones WHERE cidr = ?", (net["cidr"],))
                self._conn.execute("DELETE FROM networks WHERE id = ?", (network_id,))
                self._conn.commit()
                self._dirty = True
            except Exception:
                self._conn.rollback()
                raise
            self._set_removed(net["cidr"], True)             # l'application ne le recrée plus toute seule
        return summary

    def delete_network(self, network_id: int, delete_hosts: bool = False):
        if delete_hosts:
            self.execute("DELETE FROM hosts WHERE network_id = ?", (network_id,))
        self.execute("DELETE FROM networks WHERE id = ?", (network_id,))

    def update_host_identity(self, host_id: int, mac: str = None, vendor: str = None,
                             device_type: str = None, network_id: int = None):
        self.execute("""
            UPDATE hosts SET mac_address = COALESCE(?, mac_address), vendor = COALESCE(?, vendor),
                   device_type = COALESCE(?, device_type), network_id = COALESCE(?, network_id)
            WHERE id = ?
        """, (mac, vendor, device_type, network_id, host_id))

    def update_host_status(self, host_id: int, status: str, last_check: str, at: float = None):
        """Seul point d'écriture de l'état. Les bascules en ligne ↔ hors ligne sont datées : un appareil qui bascule trop
        souvent (téléphone en veille…) se voit exiger un silence plus long avant d'être déclaré hors ligne."""
        if status in ("online", "offline"):
            prev = self.fetchone("SELECT status, flap_log FROM hosts WHERE id = ?", (host_id,)) or {}
            if prev.get("status") in ("online", "offline") and prev.get("status") != status:
                import time as _time
                log = [x for x in (prev.get("flap_log") or "").split(",") if x][-7:]
                log.append(str(int(_time.time() if at is None else at)))
                self.execute("UPDATE hosts SET flap_log = ? WHERE id = ?", (",".join(log), host_id))
        self.execute("""
            UPDATE hosts SET status = ?, last_check = ?, updated_at = datetime('now')
            WHERE id = ?
        """, (status, last_check, host_id))

    # ─────────────────────────────────────────
    # Events / Problèmes
    # ─────────────────────────────────────────

    def get_events(self, severity: str = None, limit: int = 500,
                   offset: int = 0) -> list:
        if severity and severity != "all":
            return self.fetchall("""
                SELECT * FROM events WHERE severity = ?
                ORDER BY occurred_at DESC LIMIT ? OFFSET ?
            """, (severity, limit, offset))
        return self.fetchall(
            "SELECT * FROM events ORDER BY occurred_at DESC LIMIT ? OFFSET ?",
            (limit, offset)
        )

    def count_events(self, severity: str = None) -> int:
        if severity and severity != "all":
            row = self.fetchone(
                "SELECT COUNT(*) AS cnt FROM events WHERE severity = ?",
                (severity,)
            )
        else:
            row = self.fetchone("SELECT COUNT(*) AS cnt FROM events")
        return row["cnt"] if row else 0

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

    def get_host_by_ip(self, ip: str) -> dict | None:
        row = self.fetchone("SELECT * FROM hosts WHERE ip_address = ?", (ip,))
        if row and "snmp_community" in row:
            row["snmp_community"] = self._decrypt_community(row["snmp_community"])
        return row

    def get_bandwidth_series(self, host_id: int | None = None, hours: int = 24,
                             bucket_minutes: int = 30) -> list:
        """
        Série de bande passante (Mbps) pour le graphe du tableau de bord.
        Retourne [(bucket_iso, in_mbps, out_mbps), ...] trié par date.
        host_id=None → somme des hôtes (moyenne par bucket puis somme).
        """
        bucket_s = max(1, int(bucket_minutes)) * 60
        rows = self.fetchall("""
            SELECT metric_name, host_id,
                   (CAST(strftime('%s', collected_at) AS INTEGER) / ?) * ? AS b,
                   AVG(value) AS v
            FROM metrics
            WHERE metric_name IN ('bw_in', 'bw_out')
              AND interface = 'total'
              AND collected_at >= datetime('now', ?)
              AND (? IS NULL OR host_id = ?)
            GROUP BY metric_name, host_id, b
        """, (bucket_s, bucket_s, f"-{int(hours)} hours", host_id, host_id))
        buckets: dict[int, list] = {}
        for r in rows:
            slot = buckets.setdefault(r["b"], [0.0, 0.0])
            slot[0 if r["metric_name"] == "bw_in" else 1] += r["v"] or 0.0
        return [(b, v[0], v[1]) for b, v in sorted(buckets.items())]

    def purge_old_data(self, days: int = 30) -> int:
        """Rétention : supprime métriques et états de ports plus vieux que `days` jours."""
        total = 0
        period = f"-{int(days)} days"
        for sql in (
            "DELETE FROM metrics      WHERE collected_at < datetime('now', ?)",
            "DELETE FROM port_states  WHERE scanned_at   < datetime('now', ?)",
            "DELETE FROM sfp_metrics  WHERE collected_at < datetime('now', ?)",
        ):
            try:
                total += self.execute(sql, (period,)).rowcount or 0
            except Exception as e:
                logger.debug(f"[DB] purge : {e}")
        return total

    # ─────────────────────────────────────────
    # Audit log (HMAC protégé)
    # ─────────────────────────────────────────

    def write_audit(self, username: str, action: str, target: str = "",
                    detail: str = "", user_id: int = None, ip: str = ""):
        from datetime import datetime
        ts = datetime.now().isoformat(timespec='seconds')
        key = self._get_hmac_key()
        with self._lock:                              # une seule écriture à la fois : la chaîne ne se ramifie pas
            last = self.fetchone("SELECT hmac FROM audit_logs ORDER BY id DESC LIMIT 1")
            prev = last["hmac"] if last else AUDIT_GENESIS
            sig = hmac.new(key, audit_message(prev, user_id, username, action, target, detail, ip, ts),
                           hashlib.sha256).hexdigest()
            self.execute("""
                INSERT INTO audit_logs (user_id, username, action, target, detail, ip_source, hmac, logged_at,
                                        prev_hmac, chain_v)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 2)
            """, (user_id, username, action, target, detail, ip, sig, ts, prev))
            self.save_audit_anchor(key, sig)

    # ── ancre de fin de journal : détecte la suppression des DERNIÈRES lignes (que le chaînage seul ne voit pas) ──
    @property
    def _anchor_path(self) -> Path:
        return Path(self.db_path).parent / ".audit_anchor"

    def save_audit_anchor(self, key: bytes, last_hmac: str):
        n = self.fetchone("SELECT COUNT(*) n FROM audit_logs")["n"]
        sig = hmac.new(key, f"anchor|{n}|{last_hmac}".encode(), hashlib.sha256).hexdigest()
        blob = json.dumps({"n": n, "last": last_hmac, "sig": sig})
        self.set_setting("audit_anchor", blob)
        try:                                           # copie hors de la base : il faut modifier les DEUX pour tricher
            from core.security import write_secret_file
            write_secret_file(self._anchor_path, blob.encode())
        except Exception as e:
            logger.debug(f"[DB] ancre d'audit (fichier) : {e}")

    def _get_hmac_key(self) -> bytes:
        """
        Clé HMAC du journal d'audit (voir core/keystore.py) : trousseau du système, sinon protection Windows (DPAPI),
        sinon fichier 0600 HORS du dossier de la base. L'ancien fichier .hmac_key (à côté de la base) est migré puis supprimé.
        Dernier recours, loggué : clé dérivée du chemin (sécurité réduite) si rien n'est inscriptible.
        """
        cached = getattr(self, "_hmac_key_cache", None)
        if cached:
            return cached
        try:
            from core.keystore import KeyStore, key_name_for
            ks = KeyStore()
            key = ks.get_or_create(key_name_for(self.db_path), legacy=Path(self.db_path).parent / ".hmac_key")
            self.key_backend = ks.backend
            self._hmac_key_cache = key
            return key
        except Exception as e:
            logger.warning(f"[DB] Clé HMAC indisponible ({e}) : clé dérivée du chemin (sécurité réduite).")
            self.key_backend = "derived"
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
            SELECT g.*, COUNT(DISTINCT h.id) AS host_count,
                   COUNT(DISTINCT CASE WHEN e.resolved_at IS NULL AND e.acknowledged=0 THEN e.id END) AS problem_count
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

    def get_active_media_types(self) -> list:
        return self.fetchall("SELECT * FROM media_types WHERE active = 1 ORDER BY name")

    def update_media_config(self, media_id: int, config_json: str):
        self.execute(
            "UPDATE media_types SET config_json = ? WHERE id = ?",
            (config_json, media_id)
        )

    # ─────────────────────────────────────────
    # Paramètres système
    # ─────────────────────────────────────────

    def get_setting(self, key: str, default: str = "") -> str:
        try:
            row = self.fetchone("SELECT value FROM settings WHERE key = ?", (key,))
            return row["value"] if row else default
        except Exception:
            return default

    def set_setting(self, key: str, value: str):
        self.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
            (key, value)
        )

    def get_all_settings(self) -> dict:
        try:
            rows = self.fetchall("SELECT key, value FROM settings")
            return {r["key"]: r["value"] for r in rows}
        except Exception:
            return {}

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
