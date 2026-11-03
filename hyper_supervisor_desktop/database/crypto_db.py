"""
Procus Secure — chiffrement de la base de données (SQLCipher, AES-256).

• Base neuve        : créée chiffrée si SQLCipher est installé (paquet « sqlcipher3 »).
• Base existante en clair : migrée automatiquement (copie chiffrée vérifiée table par table avant de remplacer ; le fichier en
  clair est ensuite écrasé puis supprimé).
• Clé               : 256 bits aléatoires, conservée par core/keystore.py (trousseau du système, DPAPI, ou fichier protégé hors
  du dossier de la base). Sans la clé la base est illisible : à sauvegarder avec la base si vous changez de machine.
• Sans SQLCipher    : la base reste en clair (état affiché dans l'application) ; les secrets restent chiffrés champ par champ.
• PROCUS_DB_ENCRYPT=0 désactive le chiffrement des NOUVELLES bases (une base déjà chiffrée reste chiffrée).
"""
from __future__ import annotations

import os
import re
import sqlite3
from typing import Optional

from loguru import logger

PLAIN_HEADER = b"SQLite format 3\x00"
_HEX = re.compile(r"^[0-9a-f]{64}$")
SQLITE_ERRORS: tuple = (sqlite3.Error,)
try:                                         # noqa: SIM105
    import sqlcipher3.dbapi2 as _cipher
    SQLITE_ERRORS = (sqlite3.Error, _cipher.Error)
except Exception:                            # SQLCipher absent : base en clair
    _cipher = None

INTEGRITY_ERRORS: tuple = (sqlite3.IntegrityError,) + ((_cipher.IntegrityError,) if _cipher else ())
OPERATIONAL_ERRORS: tuple = (sqlite3.OperationalError,) + ((_cipher.OperationalError,) if _cipher else ())


class DatabaseEncryptedError(RuntimeError):
    """Base chiffrée impossible à ouvrir (SQLCipher ou clé absents)."""


def available() -> bool:
    return _cipher is not None


def is_plaintext(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(16) == PLAIN_HEADER
    except OSError:
        return False


def _pragma_key(conn, key_hex: str):
    if not _HEX.match(key_hex or ""):
        raise DatabaseEncryptedError("Clé de chiffrement invalide.")
    conn.execute("PRAGMA key = \"x'" + key_hex + "'\"")        # clé binaire (pas de dérivation de mot de passe)


def connect(path: str, key_hex: Optional[str] = None, check_same_thread: bool = False):
    """Connexion adaptée : chiffrée si une clé est fournie, SQLite standard sinon."""
    if key_hex:
        if _cipher is None:
            raise DatabaseEncryptedError("La base est chiffrée mais SQLCipher n'est pas installé (pip install sqlcipher3-binary).")
        conn = _cipher.connect(path, check_same_thread=check_same_thread)
        _pragma_key(conn, key_hex)
        try:
            conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
        except Exception as e:
            conn.close()
            raise DatabaseEncryptedError("Clé de chiffrement incorrecte ou base corrompue.") from e
        return conn
    return sqlite3.connect(path, check_same_thread=check_same_thread)


def row_factory(key_hex: Optional[str]):
    return _cipher.Row if key_hex else sqlite3.Row


def _tables(conn) -> list[str]:
    return [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]


def export_plain_to_encrypted(plain_path: str, enc_path: str, key_hex: str) -> None:
    """Copie complète d'une base en clair vers un fichier chiffré, puis vérifie table par table (nombre de lignes)."""
    if _cipher is None:
        raise DatabaseEncryptedError("SQLCipher n'est pas installé.")
    if os.path.exists(enc_path):
        os.remove(enc_path)
    src = _cipher.connect(plain_path)
    try:
        src.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        src.execute("ATTACH DATABASE ? AS enc KEY \"x'" + key_hex + "'\"", (enc_path,)) if _HEX.match(key_hex) else None
        src.execute("SELECT sqlcipher_export('enc')")
        uv = src.execute("PRAGMA user_version").fetchone()[0]
        src.execute("PRAGMA enc.user_version = " + str(int(uv)))
        src.execute("DETACH DATABASE enc")
        tables = _tables(src)
        counts = {t: src.execute('SELECT COUNT(*) FROM "' + t.replace('"', '""') + '"').fetchone()[0] for t in tables}  # nosec B608 - noms issus de sqlite_master, guillemets échappés
    finally:
        src.close()
    dst = connect(enc_path, key_hex)
    try:
        if dst.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise DatabaseEncryptedError("Copie chiffrée corrompue (integrity_check).")
        for t, n in counts.items():
            m = dst.execute('SELECT COUNT(*) FROM "' + t.replace('"', '""') + '"').fetchone()[0]  # nosec B608
            if m != n:
                raise DatabaseEncryptedError(f"Copie chiffrée incomplète (table {t} : {m}/{n} lignes).")
    finally:
        dst.close()


def _wipe(path: str):
    """Écrase puis supprime un fichier (au mieux : un SSD peut conserver d'anciens blocs)."""
    try:
        size = os.path.getsize(path)
        with open(path, "r+b") as f:
            f.write(b"\x00" * size)
            f.flush()
            os.fsync(f.fileno())
    except OSError:
        pass
    try:
        os.remove(path)
    except OSError:
        pass


def migrate_in_place(path: str, key_hex: str) -> None:
    tmp = path + ".enc.tmp"
    export_plain_to_encrypted(path, tmp, key_hex)
    old = path + ".plain.old"
    os.replace(path, old)
    os.replace(tmp, path)
    for suffix in ("-wal", "-shm"):
        try:
            os.remove(path + suffix)
        except OSError:
            pass
    _wipe(old)
    logger.success("[DB] Base migrée vers le format chiffré (AES-256) ; ancien fichier en clair effacé.")


# ───────────── mode « fichier chiffré » (AES-256-GCM, fonctionne partout, y compris Windows) ─────────────
MAGIC = b"PROCUSENC1\n"


def is_file_encrypted(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(len(MAGIC)) == MAGIC
    except OSError:
        return False


def encrypt_bytes(key: bytes, data: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = os.urandom(12)
    return MAGIC + nonce + AESGCM(key).encrypt(nonce, data, MAGIC)


def decrypt_bytes(key: bytes, blob: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    try:
        if not blob.startswith(MAGIC):
            raise ValueError("en-tête inconnu")
        n = len(MAGIC)
        return AESGCM(key).decrypt(blob[n:n + 12], blob[n + 12:], MAGIC)
    except Exception as e:
        raise DatabaseEncryptedError("Clé de chiffrement incorrecte ou fichier de base corrompu.") from e


def write_atomic(path: str, blob: bytes) -> None:
    """Écriture atomique : fichier temporaire, fsync, remplacement. Un plantage ne laisse jamais un fichier tronqué."""
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(blob)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def normalize_image(data: bytes) -> bytes:
    """Une image SQLite issue d'une base en mode WAL porte l'octet « WAL » (18-19 = 2) : rechargée en mémoire, elle chercherait un
    fichier -wal inexistant. L'image mémoire est complète : on la marque en journal classique (1)."""
    if len(data) > 20 and data[18:20] == b"\x02\x02":
        b = bytearray(data)
        b[18] = b[19] = 1
        return bytes(b)
    return data


def serialize_db(conn) -> bytes:
    return normalize_image(conn.serialize())


def load_memory(path: str, key_hex: str):
    """Base chiffrée (mode fichier) → connexion SQLite en mémoire (rien n'est écrit en clair sur le disque)."""
    key = bytes.fromhex(key_hex)
    with open(path, "rb") as f:
        data = normalize_image(decrypt_bytes(key, f.read()))
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.deserialize(data)
    return conn


def open_readable(path: str, key_hex: Optional[str]):
    """Ouvre en lecture n'importe quelle base Procus : en clair, chiffrée SQLCipher ou chiffrée en mode fichier."""
    if is_plaintext(path):
        return sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    if not key_hex:
        raise DatabaseEncryptedError("Fichier chiffré : clé requise.")
    if is_file_encrypted(path):
        return load_memory(path, key_hex)
    return connect(path, key_hex)


def prepare(path: str):
    """
    Décide du mode d'ouverture et migre si besoin. Retourne (mode, clé_hex) :
      "sqlcipher" : base chiffrée par SQLCipher ;  "file" : base en mémoire, enregistrée chiffrée (AES-GCM) ;  "plain" : en clair.
    Ordre de préférence pour une base neuve : SQLCipher si installé, sinon mode fichier. PROCUS_DB_MODE=file force le mode fichier.
    """
    from core.keystore import KeyStore, key_name_for
    disabled = os.environ.get("PROCUS_DB_ENCRYPT", "").strip().lower() in ("0", "off", "no", "false")
    force_file = os.environ.get("PROCUS_DB_MODE", "").strip().lower() == "file"
    ks = KeyStore()
    name = key_name_for(path, "db")
    exists = os.path.exists(path) and os.path.getsize(path) > 0
    if exists and is_file_encrypted(path):
        key = ks.get(name)
        if key is None:
            raise DatabaseEncryptedError("La base est chiffrée mais sa clé est introuvable (trousseau ou profil changé ?). "
                                         "Restaurez la clé ou une sauvegarde.")
        return "file", key.hex()
    if exists and not is_plaintext(path):                       # chiffrée SQLCipher
        key = ks.get(name)
        if key is None:
            raise DatabaseEncryptedError("La base est chiffrée mais sa clé est introuvable (trousseau ou profil changé ?). "
                                         "Restaurez la clé ou une sauvegarde.")
        return "sqlcipher", key.hex()
    if disabled:
        return "plain", None
    key = ks.get_or_create(name)
    if available() and not force_file:
        if exists:
            migrate_in_place(path, key.hex())
        return "sqlcipher", key.hex()
    return "file", key.hex()                                    # la migration d'une base en clair est faite par DatabaseManager
