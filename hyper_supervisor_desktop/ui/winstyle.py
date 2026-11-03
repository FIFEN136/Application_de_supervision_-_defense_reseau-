"""
Procus Secure — barre de titre sombre sous Windows 10/11 (fenêtres et boîtes de dialogue cohérentes avec le thème).
Aucun effet ailleurs ; toute erreur est ignorée (l'apparence ne doit jamais empêcher l'application de démarrer).
"""
from __future__ import annotations

import os

from PyQt6.QtCore import QEvent, QObject


def apply_dark_title_bar(widget) -> bool:
    if os.name != "nt":
        return False
    try:
        import ctypes
        hwnd = int(widget.winId())
        value = ctypes.c_int(1)
        for attr in (20, 19):                         # DWMWA_USE_IMMERSIVE_DARK_MODE (Windows 11 / anciennes versions de Windows 10)
            if ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, attr, ctypes.byref(value), ctypes.sizeof(value)) == 0:
                return True
    except Exception:                                # nosec B110 - purement cosmétique
        pass
    return False


class DarkTitleFilter(QObject):
    """Filtre d'application : toute fenêtre de premier niveau reçoit la barre de titre sombre à son affichage."""

    def eventFilter(self, obj, event):
        if event.type() == QEvent.Type.Show and getattr(obj, "isWindow", None) and obj.isWindow():
            apply_dark_title_bar(obj)
        return False
