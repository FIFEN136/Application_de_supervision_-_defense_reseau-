#!/usr/bin/env python3
"""
Procus Agent — agent léger de supervision (Windows / Linux).  Fichier unique, bibliothèque standard seulement
(psutil est utilisé s'il est installé, sinon repli sur les commandes du système).

Ce que l'agent FAIT      : lit l'inventaire local (processus, ports, services, logiciels, utilisateurs connectés),
                           calcule l'empreinte de fichiers à surveiller, relève les nouvelles lignes de journaux,
                           et envoie le tout signé (HMAC-SHA256) à Procus Secure, par HTTPS à empreinte épinglée.
Ce que l'agent NE FAIT PAS : il n'exécute AUCUNE commande reçue du serveur, n'ouvre AUCUN port, ne modifie rien.

Utilisation :  python procus_agent.py --config agent_config.json            (boucle)
               python procus_agent.py --config agent_config.json --once     (un seul envoi, pour tester)
agent_config.json (généré par Procus Secure) : {"server": "https://IP:8765", "agent_id": "...", "secret": "...",
                                                 "server_fingerprint": "<sha256 hex du certificat>"}
"""
import argparse
import hashlib
import hmac
import http.client
import json
import os
import platform
import re
import secrets
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse

VERSION = "1.0"
MAX_ITEMS = 500
try:
    import psutil
except Exception:           # psutil facultatif
    psutil = None


def _run(cmd, timeout=20):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="ignore")
        return r.stdout
    except Exception:
        return ""


# ───────────────────────── collecte ─────────────────────────

def collect_usage():
    """Charge de la machine : CPU, mémoire, disque (%), octets réseau cumulés. Vide sans psutil."""
    if not psutil:
        return {}
    out = {}
    try:
        out["cpu_pct"] = float(psutil.cpu_percent(interval=0.3))
        out["mem_pct"] = float(psutil.virtual_memory().percent)
        root = os.environ.get("SystemDrive", "C:") + "\\" if platform.system() == "Windows" else "/"
        out["disk_pct"] = float(psutil.disk_usage(root).percent)
        io = psutil.net_io_counters()
        out["net_rx_bytes"], out["net_tx_bytes"] = int(io.bytes_recv), int(io.bytes_sent)
    except Exception:
        pass
    try:
        out.update(_primary_nic())
    except Exception:
        pass
    return out


def _primary_nic():
    """Carte réseau portant l'adresse utilisée pour joindre le serveur : nom, Wi-Fi ou câble, vitesse de liaison."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))                      # aucune donnée envoyée : sert à choisir l'interface sortante
        ip = s.getsockname()[0]
    finally:
        s.close()
    for name, addrs in psutil.net_if_addrs().items():
        if any(getattr(a, "address", None) == ip for a in addrs):
            n = name.lower()
            if any(k in n for k in ("wi-fi", "wifi", "wlan", "wireless", "sans fil", "wlp", "wlx")) or n.startswith("wl"):
                kind = "wifi"
            elif any(k in n for k in ("ethernet", "eth", "enp", "eno", "ens", "enx", "local area")) or n.startswith("en"):
                kind = "ethernet"
            else:
                return {}
            st = psutil.net_if_stats().get(name)
            return {"net_iface": name[:40], "net_kind": kind, "net_speed_mbps": int(st.speed) if st and st.speed else 0}
    return {}


def collect_system():
    return {"hostname": socket.gethostname(), "os": platform.system().lower(), "os_release": platform.release(),
            "os_version": platform.version()[:120], "machine": platform.machine(),
            "uptime_s": int(time.time() - psutil.boot_time()) if psutil else None, **collect_usage()}


def collect_processes():
    out = []
    if psutil:
        for p in psutil.process_iter(["pid", "name", "username", "exe"]):
            i = p.info
            out.append({"pid": i.get("pid"), "name": i.get("name"), "user": i.get("username"), "exe": i.get("exe")})
    elif platform.system() == "Windows":
        for ln in _run(["tasklist", "/fo", "csv", "/nh"]).splitlines():
            parts = [x.strip('"') for x in ln.split('","')]
            if len(parts) >= 2:
                out.append({"pid": int(parts[1]) if parts[1].isdigit() else None, "name": parts[0]})
    else:
        for ln in _run(["ps", "-eo", "pid,user,comm", "--no-headers"]).splitlines():
            sp = ln.split(None, 2)
            if len(sp) == 3:
                out.append({"pid": int(sp[0]), "user": sp[1], "name": sp[2]})
    return out[:MAX_ITEMS]            # volontairement SANS ligne de commande (peut contenir des mots de passe)


def collect_ports():
    out = []
    if psutil:
        try:
            names = {}
            for c in psutil.net_connections(kind="inet"):
                if c.status == psutil.CONN_LISTEN or (c.type == socket.SOCK_DGRAM and not c.raddr):
                    proc = names.get(c.pid)
                    if proc is None and c.pid:
                        try:
                            proc = psutil.Process(c.pid).name()
                        except Exception:
                            proc = ""
                        names[c.pid] = proc
                    out.append({"port": c.laddr.port, "addr": c.laddr.ip,
                                "proto": "tcp" if c.type == socket.SOCK_STREAM else "udp", "process": proc or ""})
        except Exception:
            pass
    elif platform.system() == "Windows":
        for ln in _run(["netstat", "-ano"]).splitlines():
            m = re.match(r"\s*(TCP|UDP)\s+(\S+):(\d+)\s+\S+\s+(LISTENING)?\s*(\d+)?", ln)
            if m and (m.group(1) == "UDP" or m.group(4)):
                out.append({"port": int(m.group(3)), "addr": m.group(2), "proto": m.group(1).lower(), "process": m.group(5) or ""})
    else:
        for ln in _run(["ss", "-tulnH"]).splitlines():
            sp = ln.split()
            if len(sp) >= 5 and ":" in sp[4]:
                addr, _, port = sp[4].rpartition(":")
                if port.isdigit():
                    out.append({"port": int(port), "addr": addr, "proto": sp[0], "process": ""})
    seen, uniq = set(), []
    for o in out:
        k = (o["port"], o["proto"], o["addr"])
        if k not in seen:
            seen.add(k); uniq.append(o)
    return sorted(uniq, key=lambda x: x["port"])[:MAX_ITEMS]


def collect_services():
    out = []
    if platform.system() == "Windows":
        if psutil and hasattr(psutil, "win_service_iter"):
            for s in psutil.win_service_iter():
                try:
                    out.append({"name": s.name(), "display": s.display_name(), "status": s.status(), "start": s.start_type()})
                except Exception:
                    continue
    else:
        for ln in _run(["systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--plain"]).splitlines():
            sp = ln.split(None, 4)
            if sp:
                out.append({"name": sp[0], "status": "running", "display": sp[4] if len(sp) > 4 else ""})
    return out[:MAX_ITEMS * 2]


def collect_software():
    out = []
    if platform.system() == "Windows":
        try:
            import winreg
            for hive, path in ((winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                               (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")):
                try:
                    with winreg.OpenKey(hive, path) as k:
                        for i in range(winreg.QueryInfoKey(k)[0]):
                            try:
                                with winreg.OpenKey(k, winreg.EnumKey(k, i)) as sk:
                                    name = winreg.QueryValueEx(sk, "DisplayName")[0]
                                    try:
                                        ver = winreg.QueryValueEx(sk, "DisplayVersion")[0]
                                    except OSError:
                                        ver = ""
                                    out.append({"name": name, "version": ver})
                            except OSError:
                                continue
                except OSError:
                    continue
        except ImportError:
            pass
    else:
        txt = _run(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"])
        if not txt:
            txt = _run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"])
        for ln in txt.splitlines():
            sp = ln.split("\t")
            if len(sp) == 2:
                out.append({"name": sp[0], "version": sp[1]})
    return out[:MAX_ITEMS * 4]


def collect_users():
    if psutil:
        try:
            return [{"name": u.name, "terminal": u.terminal or "", "host": u.host or "", "started": int(u.started)}
                    for u in psutil.users()]
        except Exception:
            return []
    return []


def fim_snapshot(paths):
    """Empreinte SHA-256 de chaque fichier surveillé (les dossiers sont parcourus, 500 fichiers max)."""
    files = []
    for p in paths:
        if os.path.isdir(p):
            n = 0
            for root, _d, fns in os.walk(p):
                for fn in sorted(fns):
                    files.append(os.path.join(root, fn)); n += 1
                    if n >= 500:
                        break
                if n >= 500:
                    break
        else:
            files.append(p)
    snap = {}
    for f in files:
        try:
            st = os.stat(f)
            if st.st_size > 200 * 1024 * 1024:
                snap[f] = {"error": "trop volumineux"}; continue
            h = hashlib.sha256()
            with open(f, "rb") as fh:
                for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                    h.update(chunk)
            snap[f] = {"sha256": h.hexdigest(), "size": st.st_size}
        except FileNotFoundError:
            snap[f] = {"missing": True}
        except OSError as e:
            snap[f] = {"error": type(e).__name__}
    return snap


# ───────────────────────── journaux ─────────────────────────

LINUX_LOGS = ("/var/log/auth.log", "/var/log/secure")


def tail_new_lines(path, state, max_lines=500):
    """Lignes ajoutées depuis le dernier passage. Au 1er passage on se place à la FIN (pas d'historique envoyé)."""
    try:
        st = os.stat(path)
    except OSError:
        return []
    cur = state.get(path)
    if cur is None or cur.get("inode") != st.st_ino or st.st_size < cur.get("offset", 0):
        state[path] = {"inode": st.st_ino, "offset": st.st_size if cur is None else 0}
        if cur is None:
            return []
        cur = state[path]
    lines = []
    with open(path, "r", errors="ignore") as f:
        f.seek(cur["offset"])
        for ln in f:
            if len(lines) >= max_lines:
                break
            lines.append(ln.rstrip("\n"))
        state[path]["offset"] = f.tell()
    return lines


WIN_EVENT_IDS = (4625, 4720, 4728, 4732, 4756, 1102)


def parse_wevtutil_xml(text):
    """Transforme la sortie XML de `wevtutil qe` en [{'message','fields','record_id'}]."""
    import xml.etree.ElementTree as ET
    out = []
    for chunk in re.findall(r"<Event[ >].*?</Event>", text, re.S):
        try:
            root = ET.fromstring(chunk)  # nosec B314 - journal d'événements Windows local (wevtutil), pas une entrée réseau
        except ET.ParseError:
            continue
        ns = {"e": root.tag.split("}")[0].strip("{")} if "}" in root.tag else {}
        q = (lambda t: f"e:{t}") if ns else (lambda t: t)
        sysn = root.find(q("System"), ns) if ns else root.find("System")
        if sysn is None:
            continue
        def val(tag, sysn=sysn, q=q, ns=ns):
            n = sysn.find(q(tag), ns) if ns else sysn.find(tag)
            return n.text if n is not None else ""
        fields = {"EventID": int(val("EventID") or 0), "Computer": val("Computer")}
        data = root.find(q("EventData"), ns) if ns else root.find("EventData")
        if data is not None:
            for d in data:
                if d.get("Name"):
                    fields[d.get("Name")] = d.text or ""
        rid = int(val("EventRecordID") or 0)
        ip = fields.get("IpAddress") or ""
        if ip in ("-", "::1", "127.0.0.1"):
            fields["IpAddress"] = ""
        out.append({"message": f"Windows EventID {fields['EventID']} {fields.get('TargetUserName', '')} "
                               f"{fields.get('IpAddress', '')}".strip(), "fields": fields, "record_id": rid})
    return out


def collect_logs(state):
    logs = []
    if platform.system() == "Windows":
        q = "*[System[(" + " or ".join(f"EventID={i}" for i in WIN_EVENT_IDS) + ")]]"
        last = state.get("win_last", 0)
        txt = _run(["wevtutil", "qe", "Security", f"/q:{q}", "/c:200", "/rd:false", "/f:xml"], timeout=30)
        for e in parse_wevtutil_xml(txt):
            if e["record_id"] > last:
                logs.append({"message": e["message"], "fields": e["fields"]})
                last = max(last, e["record_id"])
        if last and "win_last" not in state:           # 1er passage : on ne renvoie pas l'historique
            logs = []
        state["win_last"] = last
    else:
        for path in LINUX_LOGS:
            for ln in tail_new_lines(path, state.setdefault("files", {})):
                logs.append({"message": ln})
    return logs[:1000]


# ───────────────────────── envoi ─────────────────────────

def sign(secret, ts, nonce, body):
    return hmac.new(secret.encode(), ts.encode() + b"." + nonce.encode() + b"." + body, hashlib.sha256).hexdigest()


def post_report(cfg, payload, timeout=20):
    """POST signé. HTTPS : le certificat doit avoir l'empreinte configurée (épinglage), sinon la connexion est refusée."""
    u = urllib.parse.urlparse(cfg["server"])
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    ts, nonce = str(int(time.time())), secrets.token_hex(12)
    headers = {"Content-Type": "application/json", "Content-Length": str(len(body)), "X-Procus-Agent": cfg["agent_id"],
               "X-Procus-Timestamp": ts, "X-Procus-Nonce": nonce, "X-Procus-Signature": sign(cfg["secret"], ts, nonce, body)}
    if u.scheme == "https":
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE                      # l'autorité est remplacée par l'épinglage ci-dessous
        conn = http.client.HTTPSConnection(u.hostname, u.port or 443, context=ctx, timeout=timeout)
        conn.connect()
        want = (cfg.get("server_fingerprint") or "").lower().replace(":", "")
        got = hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest()
        if not want or not hmac.compare_digest(want, got):
            conn.close()
            raise ssl.SSLError("empreinte du certificat serveur inattendue : connexion refusée")
    else:
        conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=timeout)
    try:
        conn.request("POST", "/api/v1/report", body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        if resp.status != 200:
            raise RuntimeError(f"serveur : HTTP {resp.status}")
        return json.loads(data.decode("utf-8"))
    finally:
        conn.close()


def collect_connections(limit=500):
    """Connexions TCP établies (adresses et ports seulement, jamais de contenu) : alimente la carte « qui parle à qui »."""
    out = []
    if not psutil:
        return out
    try:
        socks = psutil.net_connections(kind="inet")
        listening = {c.laddr.port for c in socks if c.status == psutil.CONN_LISTEN and c.laddr}
        for c in socks:
            if c.status == psutil.CONN_ESTABLISHED and c.raddr and c.laddr and c.type == socket.SOCK_STREAM:
                out.append({"laddr": c.laddr.ip, "lport": c.laddr.port, "raddr": c.raddr.ip, "rport": c.raddr.port,
                            "proto": "tcp", "dir": "in" if c.laddr.port in listening else "out"})
                if len(out) >= limit:
                    break
    except Exception:
        pass
    return out


def build_payload(watch_paths, state, collect_heavy=True):
    p = {"agent_version": VERSION, "system": collect_system(), "ports": collect_ports(), "users": collect_users()}
    if collect_heavy:
        p.update(processes=collect_processes(), services=collect_services(), software=collect_software())
    if watch_paths:
        p["fim"] = fim_snapshot(watch_paths)
    p["logs"] = collect_logs(state)
    conns = collect_connections()
    if conns:
        p["connections"] = conns
    return p


def main(argv=None):
    ap = argparse.ArgumentParser(description="Procus Agent")
    ap.add_argument("--config", default="agent_config.json")
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--state", default=None, help="fichier d'état (positions de lecture des journaux)")
    a = ap.parse_args(argv)
    with open(a.config, encoding="utf-8") as f:
        cfg = json.load(f)
    state_path = a.state or (os.path.splitext(a.config)[0] + ".state.json")
    try:
        with open(state_path, encoding="utf-8") as f:
            state = json.load(f)
    except (OSError, ValueError):
        state = {}
    watch, interval, n = [], 60, 0
    while True:
        try:
            resp = post_report(cfg, build_payload(watch, state, collect_heavy=(n % 5 == 0)))
            watch = resp.get("watch_paths", watch)
            interval = max(10, int(resp.get("interval", interval)))
            print(time.strftime("%H:%M:%S"), "rapport envoyé", flush=True)
        except Exception as e:
            print(time.strftime("%H:%M:%S"), f"échec d'envoi : {e}", file=sys.stderr, flush=True)
        n += 1
        try:
            with open(state_path, "w", encoding="utf-8") as f:
                json.dump(state, f)
        except OSError:
            pass
        if a.once:
            return 0
        time.sleep(interval)


if __name__ == "__main__":
    sys.exit(main())
