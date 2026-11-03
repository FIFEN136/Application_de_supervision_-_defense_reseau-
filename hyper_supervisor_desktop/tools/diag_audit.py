"""
Diagnostic LECTURE SEULE du journal d'audit : explique pourquoi des lignes sont « altérées ».
Usage (depuis le dossier de l'application) :  python tools/diag_audit.py
N'affiche ni mot de passe ni clé ; ne modifie rien dans la base.
"""
import hashlib
import hmac
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from database.db_manager import AUDIT_GENESIS, DatabaseManager, audit_message   # noqa: E402
from core.keystore import KeyStore, keys_dir, key_name_for                       # noqa: E402


def candidates(db):
    out = {}
    cur = db._get_hmac_key()
    out["clé actuelle (" + getattr(db, "key_backend", "?") + ")"] = cur
    ks = KeyStore()
    d = keys_dir()
    if d.exists():
        for p in sorted(d.iterdir()):
            found = None
            for ext, kind in ((".dpapi", "dpapi"), (".key", "file")):
                if p.name.endswith(ext):
                    k = ks._file_get(p.name[:-len(ext)])
                    found = k[0] if k else None
            if found:
                out[f"fichier de clé {p.name}"] = found
    legacy = KeyStore._read_legacy(Path(db.db_path).parent / ".hmac_key")
    if legacy:
        out["ancien fichier .hmac_key"] = legacy
    out["clé dérivée du chemin"] = hashlib.sha256(db.db_path.encode()).digest()
    try:
        import keyring
        for name in ("hmac_key", key_name_for(db.db_path)):
            v = keyring.get_password("hsr_audit", name)
            if v:
                out[f"trousseau « {name} »"] = bytes.fromhex(v)
    except Exception:
        pass
    return out


def main():
    db = DatabaseManager()
    db.initialize()
    rows = db.fetchall("SELECT * FROM audit_logs ORDER BY id")
    print(f"Base : {db.db_path}  (mode {db.mode})  — {len(rows)} lignes d'audit")
    print(f"Marqueur de re-signature : {db.get_setting('audit_legacy_resealed', '') or '(absent)'}")
    cands = candidates(db)
    print("Clés candidates trouvées :", ", ".join(cands) or "aucune")
    prev = AUDIT_GENESIS
    for r in rows[:30]:
        v2 = r.get("chain_v") == 2
        link = (r.get("prev_hmac") == prev) if v2 else None
        if v2:
            msg = audit_message(r.get("prev_hmac"), r.get("user_id"), r["username"], r["action"], r["target"],
                                r["detail"], r.get("ip_source"), r["logged_at"])
        else:
            msg = f"{r['username']}|{r['action']}|{r['target']}|{r['detail']}|{r['logged_at']}".encode()
        good = [n for n, k in cands.items() if hmac.compare_digest(hmac.new(k, msg, hashlib.sha256).hexdigest(), r.get("hmac") or "")]
        print(f"  ligne {r['id']:>3} | {'chaînée' if v2 else 'ancienne'} | chaînage {'ok' if link else ('rompu' if link is False else '-')}"
              f" | {r['action'][:24]:<24} | signature valide avec : {', '.join(good) if good else 'AUCUNE clé'}")
        prev = r.get("hmac") or ""
    print("\nCopiez ce texte et envoyez-le (il ne contient aucun secret).")
    db.close() if hasattr(db, "close") else None
    os._exit(0)


if __name__ == "__main__":
    main()
