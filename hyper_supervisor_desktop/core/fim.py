"""
Procus Secure — contrôle d'intégrité des fichiers (FIM).

On calcule l'empreinte SHA-256 de fichiers sensibles et on la compare à une RÉFÉRENCE. Tout fichier modifié,
créé ou supprimé est signalé. Deux usages :
  • agents : l'agent envoie les empreintes des fichiers surveillés de la machine où il est installé ;
  • auto-protection : Procus Secure surveille son propre code et les fichiers que vous ajoutez.
La première observation devient la référence (aucune alerte). Chaque changement est alerté UNE fois, puis la
référence suit le nouvel état (l'événement reste la preuve).
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Optional


from core.defense_common import APP_VERSION

MAX_FILE = 200 * 1024 * 1024          # au-delà, le fichier n'est pas haché
MAX_FILES_PER_DIR = 500
SENSITIVE_MARKERS = ("shadow", "passwd", "sudoers", "sshd_config", "authorized_keys", "/etc/hosts", "crontab",
                     "\\drivers\\etc\\hosts", "\\system32\\config", ".ssh", "pam.d", "ld.so.preload", "rc.local")


def is_sensitive(path: str) -> bool:
    p = path.lower().replace("\\\\", "\\")
    return any(m in p for m in SENSITIVE_MARKERS)


def hash_file(path: str) -> dict:
    """{'sha256','size'} | {'missing': True} | {'error': str}"""
    try:
        st = os.stat(path)
        if st.st_size > MAX_FILE:
            return {"error": "fichier trop volumineux"}
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return {"sha256": h.hexdigest(), "size": st.st_size}
    except FileNotFoundError:
        return {"missing": True}
    except (PermissionError, OSError) as e:
        return {"error": f"{type(e).__name__}"}


def expand_paths(paths: list[str], limit: int = MAX_FILES_PER_DIR) -> list[str]:
    out: list[str] = []
    for p in paths:
        if os.path.isdir(p):
            n = 0
            for root, _dirs, files in os.walk(p):
                for fn in sorted(files):
                    out.append(os.path.join(root, fn)); n += 1
                    if n >= limit:
                        break
                if n >= limit:
                    break
        else:
            out.append(p)
    return out


def snapshot(paths: list[str]) -> dict:
    return {p: hash_file(p) for p in expand_paths(paths)}


class FimEngine:
    def __init__(self, db, sink):
        self.db, self.sink = db, sink

    def _baseline(self, agent_id: str) -> dict:
        return {r["path"]: r for r in self.db.fetchall("SELECT * FROM fim_baseline WHERE agent_id = ?", (agent_id,))}

    def reset(self, agent_id: str):
        self.db.execute("DELETE FROM fim_baseline WHERE agent_id = ?", (agent_id,))

    def compare(self, agent_id: str, snap: dict, host: Optional[dict] = None, label: str = "") -> dict:
        """Compare un instantané à la référence. Retourne {'baseline_created': bool, 'changes': [...]}."""
        base = self._baseline(agent_id)
        changes = []
        if not base:
            n = 0
            for path, e in snap.items():
                if "sha256" in e:
                    self.db.execute("INSERT OR REPLACE INTO fim_baseline (agent_id, path, sha256, size) VALUES (?, ?, ?, ?)",
                                    (agent_id, path, e["sha256"], e.get("size")))
                    n += 1
            return {"baseline_created": True, "files": n, "changes": []}
        where = f" sur {label}" if label else ""
        for path, e in snap.items():
            old = base.get(path)
            if "error" in e:
                continue                                          # illisible : on ne conclut rien
            if "missing" in e:
                if old:
                    changes.append(("deleted", path, old["sha256"], None))
                    self.db.execute("DELETE FROM fim_baseline WHERE agent_id = ? AND path = ?", (agent_id, path))
                continue
            if old is None:
                changes.append(("created", path, None, e["sha256"]))
            elif old["sha256"] != e["sha256"]:
                changes.append(("modified", path, old["sha256"], e["sha256"]))
            else:
                continue
            self.db.execute("INSERT OR REPLACE INTO fim_baseline (agent_id, path, sha256, size, updated_at) "
                            "VALUES (?, ?, ?, ?, datetime('now'))", (agent_id, path, e["sha256"], e.get("size")))
        out = []
        for kind, path, old_h, new_h in changes:
            sens = is_sensitive(path)
            sev = "high" if sens else ("warning" if kind == "created" else "average")   # fichier sensible → toujours « high »
            verb = {"modified": "modifié", "created": "créé", "deleted": "supprimé"}[kind]
            hashes = f" (empreinte {old_h[:10]}… → {new_h[:10]}…)" if old_h and new_h else ""
            self.sink.emit(sev, "fim_change", f"Fichier {verb}{where} : {path}{hashes}", host=host, tags=["fim"],
                           extra={"path": path, "change": kind})
            out.append({"change": kind, "path": path, "severity": sev})
        return {"baseline_created": False, "changes": out}


# ───────── auto-protection de Procus Secure (et fichiers ajoutés par l'administrateur) ─────────

def app_code_paths() -> list[str]:
    root = Path(__file__).resolve().parent.parent
    files = [str(root / "main.py")]
    for sub in ("core", "database", "ui", "utils"):
        d = root / sub
        if d.is_dir():
            files += [str(p) for p in sorted(d.rglob("*.py"))]
    return files


def local_paths(db) -> list[str]:
    try:
        extra = json.loads(db.get_setting("fim_local_paths", "") or "[]")
    except ValueError:
        extra = []
    return app_code_paths() + [p for p in extra if isinstance(p, str) and p.strip()]


def check_local(db, sink) -> dict:
    """Contrôle périodique de cette machine. Une mise à jour de Procus (APP_VERSION) ré-initialise la référence."""
    eng = FimEngine(db, sink)
    if db.get_setting("fim_local_version", "") != APP_VERSION:
        eng.reset("local")
        db.set_setting("fim_local_version", APP_VERSION)
    host_id, host_name = sink.local_host()
    return eng.compare("local", snapshot(local_paths(db)), host={"id": host_id, "name": host_name},
                       label="ce poste")
