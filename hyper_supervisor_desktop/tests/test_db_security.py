import os, re, stat, threading, pathlib, sqlite3
import pytest

# ───────────── DB ─────────────
def test_seed_admin_pbkdf2(db):
    h = db.fetchone("SELECT password_hash FROM users WHERE login='admin'")["password_hash"]
    assert h != "__CHANGE_ME__" and re.fullmatch(r"[0-9a-f]{32}\$[0-9a-f]{64}", h)

def test_sql_injection_is_inert(db):
    hid = db.add_host("h1", "10.0.0.1")
    db.add_event(hid, "h1", "", "high", "x", "'; DROP TABLE events;--")
    assert db.count_events() == 1
    assert db.get_events(severity="x' OR '1'='1") == []

def test_pagination(db):
    hid = db.add_host("h1", "10.0.0.1")
    for i in range(350):
        db.add_event(hid, "h1", "", "high" if i % 2 else "warning", "t", f"e{i}")
    assert db.count_events() == 350 and db.count_events("high") == 175
    assert len(db.get_events(limit=100, offset=0)) == 100
    assert len(db.get_events(limit=100, offset=300)) == 50
    ids = {e["id"] for p in range(4) for e in db.get_events(limit=100, offset=p*100)}
    assert len(ids) == 350                       # aucune ligne perdue/dupliquée

def test_thread_safety(db):
    hid = db.add_host("h1", "10.0.0.1")
    errs = []
    def work():
        try:
            for _ in range(100): db.add_metric(hid, "cpu_util", 1.0, "%")
        except Exception as e: errs.append(e)
    ts = [threading.Thread(target=work) for _ in range(8)]
    [t.start() for t in ts]; [t.join() for t in ts]
    assert not errs
    assert db.fetchone("SELECT COUNT(*) c FROM metrics")["c"] == 800

def test_bandwidth_series_and_purge(db):
    a = db.add_host("a", "10.0.0.1"); b = db.add_host("b", "10.0.0.2")
    for hid, v in ((a, 10), (b, 5)):
        db.add_metric(hid, "bw_in", v, "Mbps", "total"); db.add_metric(hid, "bw_out", v/2, "Mbps", "total")
    s_all = db.get_bandwidth_series(None, 24, 60); s_a = db.get_bandwidth_series(a, 24, 60)
    assert sum(x[1] for x in s_all) == pytest.approx(15) and sum(x[1] for x in s_a) == pytest.approx(10)
    db.execute("INSERT INTO metrics (host_id, metric_name, value, collected_at) VALUES (?, 'cpu_util', 1, datetime('now','-40 days'))", (a,))
    assert db.purge_old_data(30) >= 1
    assert db.fetchone("SELECT COUNT(*) c FROM metrics WHERE metric_name='cpu_util'")["c"] == 0

def test_backup_restore_roundtrip_wal(db, tmp_path):
    hid = db.add_host("h1", "10.0.0.1")
    for i in range(20): db.add_event(hid, "h1", "", "high", "t", str(i))
    bk = str(tmp_path / "bk.db")
    db.backup_to(bk)                                  # données encore dans le WAL → doivent être sauvegardées
    for i in range(5): db.add_event(hid, "h1", "", "high", "t", "later")
    assert db.count_events() == 25
    safety = db.restore_from(bk)
    assert db.count_events() == 20 and os.path.exists(safety)
    db.add_event(hid, "h1", "", "high", "t", "after")  # connexion toujours utilisable (pas de redémarrage)
    assert db.count_events() == 21

def test_validate_backup_rejects_garbage(db, tmp_path):
    txt = tmp_path / "x.db"; txt.write_text("pas une base")
    assert db.validate_backup(str(txt))[0] is False
    other = tmp_path / "o.db"; c = sqlite3.connect(other); c.execute("create table foo(a)"); c.commit(); c.close()
    ok, msg = db.validate_backup(str(other)); assert not ok and "incomplet" in msg
    with pytest.raises(ValueError): db.restore_from(str(txt))
    assert db.count_events() == 0

# ───────────── Sécurité ─────────────
def test_password_hash(security):
    h1, h2 = security.hash_password("s3cret"), security.hash_password("s3cret")
    assert h1 != h2 and security.verify_password("s3cret", h1)
    assert not security.verify_password("nope", h1) and not security.verify_password("x", "garbage")

def test_auth_audit_and_integrity(security, db):
    assert security.authenticate("admin", "admin")
    assert security.authenticate("admin", "bad") is None
    assert security.authenticate("ghost", "x") is None
    acts = [r["action"] for r in db.get_audit_logs()]
    assert {"LOGIN", "LOGIN_FAILED"} <= set(acts)
    assert security.verify_db_integrity() is True
    db.execute("UPDATE audit_logs SET detail='falsifié' WHERE id=(SELECT MAX(id) FROM audit_logs)")
    assert security.verify_db_integrity() is False       # altération détectée

def test_lockout(security):
    for _ in range(security.MAX_FAILED_ATTEMPTS): assert security.authenticate("admin", "bad") is None
    assert security.lockout_remaining("admin") > 0
    assert security.authenticate("admin", "admin") is None   # même bon mot de passe : bloqué
    security.db.execute("UPDATE login_failures SET locked_until = 1 WHERE login = 'admin'")   # fin du verrouillage
    assert security.authenticate("admin", "admin")

def test_crypto_roundtrip_and_key_perms(_isolated_home):
    from core.security import CryptoHelper
    t = CryptoHelper.encrypt("mot-de-passe-smtp")
    assert t.startswith("gAAAAA") and "mot-de-passe" not in t
    assert CryptoHelper.decrypt(t) == "mot-de-passe-smtp"
    assert CryptoHelper.decrypt("ancien-clair") == "ancien-clair"
    key = pathlib.Path(os.environ["HOME"]) / ".procus_hsr" / ".fernet_key"
    if os.name == "posix": assert stat.S_IMODE(key.stat().st_mode) == 0o600

def test_hmac_key_stable_and_private(db):
    k1 = db._get_hmac_key(); k2 = db._get_hmac_key()
    assert k1 == k2 and len(k1) == 32
    from core.keystore import keys_dir, key_name_for
    p = keys_dir() / (key_name_for(db.db_path) + ".key")
    assert not (pathlib.Path(db.db_path).parent / ".hmac_key").exists()      # jamais à côté de la base
    if os.name == "posix": assert stat.S_IMODE(p.stat().st_mode) == 0o600

def test_validators():
    from core.security import InputValidator as V, SecurityManager as S
    assert V.ip_address("192.168.1.10") and V.login("admin")
    for bad in ("", "a b; rm -rf /", "1.2.3.4; ls"):
        with pytest.raises(ValueError): V.ip_address(bad)
    with pytest.raises(ValueError): V.login("a'; --")
    with pytest.raises(ValueError): V.snmp_community("pub lic;")
    assert S.validate_scan_target("10.0.0.5") and not S.validate_scan_target("evil; rm")

def test_static_no_secrets_no_fstring_sql():
    root = pathlib.Path(__file__).resolve().parent.parent
    secret = re.compile(r"""(password|passwd|secret|api_?key|token)\s*=\s*["'][^"']{4,}["']""", re.I)
    fsql = re.compile(r"""\.(execute|fetchall|fetchone)\(\s*f["']""")
    bad = []
    for f in root.rglob("*.py"):
        if "tests" in f.parts or {"venv", ".venv", "site-packages", "node_modules", "build", "dist"} & set(f.parts): continue
        txt = f.read_text(encoding="utf-8")
        for m in secret.finditer(txt): bad.append((f.name, m.group(0)))
        for m in fsql.finditer(txt): bad.append((f.name, "f-string SQL"))
    assert not bad, bad


@pytest.mark.parametrize("key", [b"\x20" + bytes(range(1, 31)) + b"\x0a", b"\x09" * 32, bytes(range(32))])
def test_hmac_key_survives_whitespace_bytes(tmp_path, key):
    """Régression : .strip() sur une clé binaire tronquait les octets blancs → clé régénérée."""
    from database.db_manager import DatabaseManager
    from core.security import write_secret_file
    d = DatabaseManager(str(tmp_path / "k.db"))
    write_secret_file(tmp_path / ".hmac_key", key.hex().encode())
    assert d._get_hmac_key() == key
    write_secret_file(tmp_path / ".hmac_key", key)                  # ancien format brut
    assert d._get_hmac_key() == key


# ───────────── Chiffrement SQLCipher ─────────────
def test_new_db_encrypted_when_sqlcipher_available(tmp_path):
    from database import crypto_db
    from database.db_manager import DatabaseManager
    d = DatabaseManager(str(tmp_path / "e.db")); d.initialize()
    d.add_host("h1", "10.0.0.1")
    if not crypto_db.available():
        pytest.skip("sqlcipher3 absent")
    assert d.encrypted and not crypto_db.is_plaintext(d.db_path)
    d._conn.commit()
    raw = open(d.db_path, "rb").read()
    assert b"SQLite format" not in raw and b"10.0.0.1" not in raw


def test_plaintext_db_migrated(tmp_path):
    from database import crypto_db
    if not crypto_db.available():
        pytest.skip("sqlcipher3 absent")
    from database.db_manager import DatabaseManager
    p = str(tmp_path / "m.db")
    os.environ["PROCUS_DB_ENCRYPT"] = "0"
    try:
        d = DatabaseManager(p); d.initialize(); d.add_host("h1", "10.0.0.9"); d.close()
    finally:
        del os.environ["PROCUS_DB_ENCRYPT"]
    assert crypto_db.is_plaintext(p)
    d2 = DatabaseManager(p); d2.initialize()
    assert d2.encrypted and not crypto_db.is_plaintext(p)
    assert d2.fetchone("SELECT ip_address FROM hosts WHERE name='h1'")["ip_address"] == "10.0.0.9"
    assert not os.path.exists(p + ".plain.old")


def test_encrypted_backup_roundtrip_and_wrong_key(tmp_path):
    from database import crypto_db
    if not crypto_db.available():
        pytest.skip("sqlcipher3 absent")
    from database.db_manager import DatabaseManager
    d = DatabaseManager(str(tmp_path / "b.db")); d.initialize(); hid = d.add_host("h1", "10.0.0.1")
    bk = str(tmp_path / "bk.db"); d.backup_to(bk)
    assert not crypto_db.is_plaintext(bk)
    assert d.validate_backup(bk)[0] is False                      # sans clé : illisible
    assert d.validate_backup(bk, d._key_hex)[0] is True
    assert d.validate_backup(bk, "00" * 32)[0] is False           # mauvaise clé
    d.add_event(hid, "h1", "", "high", "t", "x"); d.restore_from(bk)
    assert d.count_events() == 0


def test_encrypted_without_key_refuses(tmp_path):
    from database import crypto_db
    if not crypto_db.available():
        pytest.skip("sqlcipher3 absent")
    from database.db_manager import DatabaseManager
    from core.keystore import keys_dir, key_name_for
    p = str(tmp_path / "k.db"); _d = DatabaseManager(p); _d.initialize(); _d.close()
    for f in keys_dir().glob(key_name_for(p, "db") + "*"): f.unlink()
    with pytest.raises(crypto_db.DatabaseEncryptedError):
        DatabaseManager(p).initialize()


# ───────────── Mode « fichier chiffré » (AES-256-GCM, sans SQLCipher : Windows) ─────────────
@pytest.fixture()
def file_mode(monkeypatch):
    monkeypatch.setenv("PROCUS_DB_MODE", "file")


def test_file_mode_never_writes_plaintext_and_persists(tmp_path, file_mode):
    from database import crypto_db
    from database.db_manager import DatabaseManager
    p = str(tmp_path / "f.db")
    d = DatabaseManager(p); d.initialize()
    assert d.mode == "file" and d.encrypted
    d.add_host("secret-host", "10.9.8.7"); d.close()
    raw = open(p, "rb").read()
    assert raw.startswith(crypto_db.MAGIC) and b"SQLite format" not in raw and b"10.9.8.7" not in raw and b"secret-host" not in raw
    assert not os.path.exists(p + "-wal")
    d2 = DatabaseManager(p); d2.initialize()
    assert d2.fetchone("SELECT ip_address FROM hosts WHERE name='secret-host'")["ip_address"] == "10.9.8.7"
    d2.close()


def test_file_mode_periodic_flush_without_close(tmp_path, file_mode, monkeypatch):
    from database.db_manager import DatabaseManager
    monkeypatch.setattr(DatabaseManager, "FLUSH_INTERVAL_S", 0.2)
    p = str(tmp_path / "f.db")
    d = DatabaseManager(p); d.initialize(); d.add_host("h", "10.0.0.1")
    import time; time.sleep(0.8)                                 # simule un plantage : pas de close()
    d2 = DatabaseManager(str(tmp_path / "copy.db")); import shutil; shutil.copy(p, str(tmp_path / "copy.db"))
    from database import crypto_db
    key = bytes.fromhex(d._key_hex)
    conn = crypto_db.load_memory(p, d._key_hex)
    assert conn.execute("SELECT COUNT(*) FROM hosts WHERE name='h'").fetchone()[0] == 1
    d._flush_stop.set(); d.close()


def test_file_mode_migrates_plaintext_db_and_wipes_old(tmp_path, file_mode):
    from database import crypto_db
    from database.db_manager import DatabaseManager
    p = str(tmp_path / "m.db")
    os.environ["PROCUS_DB_ENCRYPT"] = "0"
    try:
        d = DatabaseManager(p); d.initialize(); d.add_host("h1", "10.0.0.9"); d.close()
    finally:
        del os.environ["PROCUS_DB_ENCRYPT"]
    assert crypto_db.is_plaintext(p)
    d2 = DatabaseManager(p); d2.initialize()
    assert d2.mode == "file" and crypto_db.is_file_encrypted(p)
    assert d2.fetchone("SELECT ip_address FROM hosts WHERE name='h1'")["ip_address"] == "10.0.0.9"
    assert not os.path.exists(p + ".plain.old")
    d2.close()


def test_file_mode_backup_restore_wrong_key_and_tamper(tmp_path, file_mode):
    from database import crypto_db
    from database.db_manager import DatabaseManager
    d = DatabaseManager(str(tmp_path / "b.db")); d.initialize(); hid = d.add_host("h", "10.0.0.1")
    bk = str(tmp_path / "bk.db"); d.backup_to(bk)
    assert crypto_db.is_file_encrypted(bk) and d.validate_backup(bk)[0] is False
    assert d.validate_backup(bk, d._key_hex)[0] is True and d.validate_backup(bk, "00" * 32)[0] is False
    blob = bytearray(open(bk, "rb").read()); blob[-5] ^= 1; open(bk + ".bad", "wb").write(blob)
    assert d.validate_backup(bk + ".bad", d._key_hex)[0] is False          # altération détectée (GCM)
    d.add_event(hid, "h", "", "high", "t", "x"); d.restore_from(bk)
    assert d.count_events() == 0
    d.close()


def test_file_mode_key_missing_refuses(tmp_path, file_mode):
    from database import crypto_db
    from database.db_manager import DatabaseManager
    from core.keystore import keys_dir, key_name_for
    p = str(tmp_path / "k.db"); d = DatabaseManager(p); d.initialize(); d.close()
    for f in keys_dir().glob(key_name_for(p, "db") + "*"): f.unlink()
    with pytest.raises(crypto_db.DatabaseEncryptedError):
        DatabaseManager(p).initialize()
