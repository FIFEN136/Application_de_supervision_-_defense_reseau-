import os, sys, pytest
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ["PYTHON_KEYRING_BACKEND"] = "keyring.backends.null.Keyring"   # jamais le vrai trousseau
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


@pytest.fixture(autouse=True, scope="session")
def _isolated_home(tmp_path_factory):
    home = tmp_path_factory.mktemp("home")
    os.environ["HOME"] = str(home)
    os.environ["USERPROFILE"] = str(home)
    yield home


@pytest.fixture()
def db(tmp_path):
    from database.db_manager import DatabaseManager
    d = DatabaseManager(str(tmp_path / "t.db"))
    d.initialize()
    yield d
    d.close()


@pytest.fixture()
def security(db):
    from core.security import SecurityManager
    return SecurityManager(db)


@pytest.fixture(autouse=True)
def _reset_presence_memory():
    """La mémoire « preuves de départ » du module de présence ne doit pas fuiter d'un test à l'autre."""
    from core import presence
    presence._HARD.clear()
    yield
