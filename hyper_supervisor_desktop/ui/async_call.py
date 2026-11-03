"""
Procus Secure — exécution d'une fonction bloquante hors du thread UI.

run_blocking(fn) lance `fn` dans un thread, garde l'interface réactive (curseur
d'attente, repaint) et retourne son résultat ; une exception est renvoyée comme
valeur (jamais levée dans l'UI).
"""
from PyQt6.QtCore import QEventLoop, QThread, QTimer, Qt
from PyQt6.QtWidgets import QApplication


class _Thread(QThread):
    def __init__(self, fn):
        super().__init__()
        self._fn = fn
        self.result = None
        self.error: Exception | None = None

    def run(self):
        try:
            self.result = self._fn()
        except Exception as e:           # ne jamais planter l'UI
            self.error = e


def run_blocking(fn, timeout_ms: int = 60_000):
    """Retourne (résultat, erreur). Boucle d'événements locale pendant l'attente."""
    th = _Thread(fn)
    loop = QEventLoop()
    th.finished.connect(loop.quit)
    QTimer.singleShot(timeout_ms, loop.quit)
    QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
    try:
        th.start()
        if not th.isFinished():
            loop.exec()
        if th.isRunning():                # dépassement : on n'attend pas davantage
            return None, TimeoutError("Délai dépassé")
        th.wait()
        return th.result, th.error
    finally:
        QApplication.restoreOverrideCursor()
