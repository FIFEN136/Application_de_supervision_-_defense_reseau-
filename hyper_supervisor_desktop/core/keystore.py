"""
Procus Secure — stockage des clés de signature.

Ordre de préférence (la première méthode disponible est utilisée, et son nom est exposé pour être affiché) :
  1. « keyring »  : trousseau du système (Windows Credential Manager, macOS Keychain, Secret Service) ;
  2. « dpapi »    : Windows, clé enveloppée par DPAPI : le fichier n'est lisible que par CE compte Windows sur CETTE machine ;
  3. « file »     : fichier 0600 dans ~/.procus_hsr/keys/ — JAMAIS dans le dossier de la base (une copie de la base, d'une
                    sauvegarde ou du dossier de travail n'emporte donc pas la clé qui signe son journal).
L'ancien emplacement (fichier .hmac_key à côté de la base) est migré automatiquement puis supprimé.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Callable, Optional

from loguru import logger

SERVICE = "hsr_audit"


def keys_dir() -> Path:
    return Path.home() / ".procus_hsr" / "keys"


def key_name_for(db_path: str, prefix: str = "hmac") -> str:
    return f"{prefix}_" + hashlib.sha256(os.path.abspath(db_path).encode()).hexdigest()[:16]


# ───────────── DPAPI (Windows) ─────────────
def _dpapi(data: bytes, protect: bool) -> bytes:
    import ctypes
    from ctypes import wintypes

    class BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    src = BLOB(len(data), ctypes.cast(ctypes.create_string_buffer(data, len(data)), ctypes.POINTER(ctypes.c_char)))
    out = BLOB()
    fn = ctypes.windll.crypt32.CryptProtectData if protect else ctypes.windll.crypt32.CryptUnprotectData
    ok = fn(ctypes.byref(src), None, None, None, None, 0, ctypes.byref(out)) if protect else \
        fn(ctypes.byref(src), None, None, None, None, 0, ctypes.byref(out))
    if not ok:
        raise OSError("DPAPI : opération refusée")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out.pbData)


class KeyStore:
    def __init__(self, protect: Optional[Callable[[bytes], bytes]] = None, unprotect: Optional[Callable[[bytes], bytes]] = None,
                 use_keyring: bool = True, directory: Optional[Path] = None):
        self._protect = protect or (lambda b: _dpapi(b, True)) if os.name == "nt" else protect
        self._unprotect = unprotect or (lambda b: _dpapi(b, False)) if os.name == "nt" else unprotect
        self.use_keyring = use_keyring
        self.directory = directory
        self.backend = ""

    @property
    def _dir(self) -> Path:
        return self.directory or keys_dir()

    # ───── lecture / écriture par méthode ─────
    def _kr_get(self, name: str) -> Optional[bytes]:
        if not self.use_keyring:
            return None
        try:
            import keyring
            v = keyring.get_password(SERVICE, name)
            return bytes.fromhex(v) if v else None
        except Exception:
            return None

    def _kr_set(self, name: str, key: bytes) -> bool:
        if not self.use_keyring:
            return False
        try:
            import keyring
            keyring.set_password(SERVICE, name, key.hex())
            return keyring.get_password(SERVICE, name) == key.hex()          # le trousseau « null » accepte sans retenir
        except Exception:
            return False

    def _file_get(self, name: str) -> Optional[tuple[bytes, str]]:
        for ext, kind in ((".dpapi", "dpapi"), (".key", "file")):
            p = self._dir / (name + ext)
            if p.exists():
                try:
                    raw = p.read_bytes()
                    if kind == "dpapi":
                        if not self._unprotect:
                            continue
                        raw = self._unprotect(raw)
                    key = bytes.fromhex(raw.decode("ascii").strip())
                    if len(key) == 32:
                        return key, kind
                except Exception as e:
                    logger.warning(f"[KEY] {p.name} illisible : {e}")
        return None

    def _file_set(self, name: str, key: bytes) -> str:
        from core.security import write_secret_file
        hexkey = key.hex().encode("ascii")
        if self._protect:
            try:
                write_secret_file(self._dir / (name + ".dpapi"), self._protect(hexkey))
                return "dpapi"
            except Exception as e:
                logger.warning(f"[KEY] DPAPI indisponible ({e}) : repli sur un fichier protégé.")
        write_secret_file(self._dir / (name + ".key"), hexkey)
        return "file"

    # ───── API ─────
    def get(self, name: str) -> Optional[bytes]:
        """La clé si elle existe (jamais créée ici : une clé neuve ne déchiffrerait rien)."""
        key = self._kr_get(name)
        if key and len(key) == 32:
            self.backend = "keyring"
            return key
        found = self._file_get(name)
        if found:
            self.backend = found[1]
            return found[0]
        return None

    def get_or_create(self, name: str, legacy: Optional[Path] = None) -> bytes:
        key = self._kr_get(name)
        if key and len(key) == 32:
            self.backend = "keyring"
            return key
        found = self._file_get(name)
        if found:
            self.backend = found[1]
            return found[0]
        key = self._read_legacy(legacy) if legacy else None
        migrated = key is not None
        if key is None:
            key = os.urandom(32)
        if self._kr_set(name, key):
            self.backend = "keyring"
        else:
            self.backend = self._file_set(name, key)
        if migrated:
            try:
                legacy.unlink()                                  # plus de clé à côté de la base
                logger.info("[KEY] Clé d'audit migrée hors du dossier de la base.")
            except OSError:
                pass
        return key

    @staticmethod
    def _read_legacy(path: Path) -> Optional[bytes]:
        try:
            if not path.exists():
                return None
            raw = path.read_bytes()
            if len(raw) == 32:                                   # très ancien format : 32 octets bruts
                return raw
            key = bytes.fromhex(raw.decode("ascii").strip())     # JAMAIS de .strip() sur du binaire
            return key if len(key) == 32 else None
        except (OSError, ValueError, UnicodeDecodeError):
            return None


def storage_label(backend: str) -> str:
    return {"keyring": "trousseau du système", "dpapi": "protection Windows (DPAPI)",
            "file": "fichier protégé hors de la base (moins sûr : installez un trousseau)"}.get(backend, "inconnu")
