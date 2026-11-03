"""
Procus Secure — écran de chargement animé (après l'authentification).

Affiche l'illustration « Procus Network Secure » pendant que l'application charge,
puis disparaît (fondu rapide) dès que le tableau de bord est visible.

Animations (QPainter, ~60 i/s, aucune dépendance) :
  • fondu d'entrée, léger « zoom respirant » de l'image
  • halo lumineux pulsant derrière le bouclier
  • reflet qui balaie le nom « PROCUS »
  • particules lumineuses qui montent et scintillent
  • barre de progression animée (lueur + reflet), pilotée par le VRAI chargement
"""
import math
import random
import time
from pathlib import Path

from PyQt6.QtCore import Qt, QRectF, QPointF, QTimer
from PyQt6.QtGui import (QColor, QFont, QLinearGradient, QPainter, QPainterPath,
                         QPen, QPixmap, QRadialGradient, QBrush)
from PyQt6.QtWidgets import QApplication, QWidget

IMAGE = Path(__file__).resolve().parent.parent / "assets" / "splash.jpg"
ASPECT = 1536 / 1024

# Positions relatives (fractions de l'image) — zone vidée sous le logo
BAR = (0.314, 0.787, 0.687, 0.811)      # x0, y0, x1, y1
TEXT_Y = 0.752
PCT_Y = 0.862
LOGO_TEXT = (0.31, 0.535, 0.69, 0.625)  # zone du mot PROCUS (reflet)
SHIELD = (0.50, 0.37)                   # centre du halo


class SplashScreen(QWidget):
    def __init__(self):
        super().__init__(None, Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint
                         | Qt.WindowType.Tool)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, False)
        self.setWindowTitle("Procus Secure")
        scr = QApplication.primaryScreen().availableGeometry()
        w = int(min(1040, scr.width() * 0.72, scr.height() * 0.78 * ASPECT))
        self.resize(w, int(w / ASPECT))
        self.move(scr.center().x() - self.width() // 2, scr.center().y() - self.height() // 2)

        self._pix = None
        if IMAGE.exists():
            pm = QPixmap(str(IMAGE))
            if not pm.isNull():           # pré-mise à l'échelle (marge pour le zoom)
                self._pix = pm.scaled(int(self.width() * 1.06), int(self.height() * 1.06),
                                      Qt.AspectRatioMode.IgnoreAspectRatio,
                                      Qt.TransformationMode.SmoothTransformation)
        self._target = 0.0
        self._shown = 0.0
        self._text = "Initialisation des systèmes de sécurité…"
        self._t0 = time.monotonic()
        self._closing = False
        self._close_t = None
        rnd = random.Random(7)
        self._parts = [{"x": rnd.random(), "y": rnd.random(), "v": 0.02 + rnd.random() * 0.05,
                        "r": 0.8 + rnd.random() * 1.8, "ph": rnd.random() * 6.28} for _ in range(46)]

        self.setWindowOpacity(0.0)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(16)

    # ── API ──────────────────────────────────
    def start(self):
        self.show()
        self.raise_()
        QApplication.processEvents()

    def set_progress(self, pct: float, text: str | None = None):
        """Pourcentage réel (0-100) + message ; laisse la boucle d'événements animer l'écran."""
        self._target = max(self._target, min(100.0, float(pct)))
        if text:
            self._text = text
        self.repaint()
        QApplication.processEvents()

    def finish(self, text: str = "Prêt"):
        """100 % puis fondu rapide et fermeture."""
        if self._closing:
            return
        self._text = text
        self._target = 100.0
        self._closing = True
        self._close_t = None
        # laisse la barre atteindre 100 % (≤ 0,3 s), puis fondu de sortie
        deadline = time.monotonic() + 0.18
        while self._shown < 99.0 and time.monotonic() < deadline:
            QApplication.processEvents()
            time.sleep(0.008)
        self._close_t = time.monotonic()
        # attend la fin du fondu (≈ 0,22 s) pour ne jamais recouvrir une boîte de dialogue suivante
        end = time.monotonic() + 0.6
        while self._timer.isActive() and time.monotonic() < end:
            QApplication.processEvents()
            time.sleep(0.008)
        if self._timer.isActive():
            self._timer.stop()
            self.close()

    # ── animation ────────────────────────────
    def _tick(self):
        now = time.monotonic()
        age = now - self._t0
        if self._close_t_active():
            k = (now - self._close_t) / 0.18
            if k >= 1.0:
                self._timer.stop()
                self.close()
                self.deleteLater()
                return
            self.setWindowOpacity(max(0.0, 1.0 - k))
        else:
            self.setWindowOpacity(min(1.0, age / 0.35))
        self._shown += (self._target - self._shown) * 0.14
        if abs(self._target - self._shown) < 0.05:
            self._shown = self._target
        self.update()

    def _close_t_active(self) -> bool:
        return self._closing and getattr(self, "_close_t", None) is not None

    # ── rendu ────────────────────────────────
    def paintEvent(self, _):
        W, H = self.width(), self.height()
        t = time.monotonic() - self._t0
        p = QPainter(self)
        p.setRenderHints(QPainter.RenderHint.Antialiasing | QPainter.RenderHint.SmoothPixmapTransform
                         | QPainter.RenderHint.TextAntialiasing)
        p.fillRect(self.rect(), QColor("#050505"))

        # image avec « zoom respirant »
        z = 1.0 + 0.045 * (0.5 - 0.5 * math.cos(t * 0.9))
        if self._pix:
            pw, ph = W * 1.06 * z / 1.06, H * 1.06 * z / 1.06
            p.drawPixmap(QRectF((W - pw) / 2, (H - ph) / 2, pw, ph), self._pix,
                         QRectF(0, 0, self._pix.width(), self._pix.height()))
        p.setCompositionMode(QPainter.CompositionMode.CompositionMode_Plus)

        # halo pulsant derrière le bouclier
        pulse = 0.5 + 0.5 * math.sin(t * 2.2)
        cx, cy = SHIELD[0] * W, SHIELD[1] * H
        g = QRadialGradient(QPointF(cx, cy), W * (0.27 + 0.03 * pulse))
        g.setColorAt(0.0, QColor(40, 150, 255, int(55 + 45 * pulse)))
        g.setColorAt(0.55, QColor(20, 90, 255, int(20 + 16 * pulse)))
        g.setColorAt(1.0, QColor(0, 40, 200, 0))
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QBrush(g))
        p.drawEllipse(QPointF(cx, cy), W * 0.31, W * 0.31)

        # reflet qui balaie « PROCUS » (toutes les ~2,8 s)
        lx0, ly0, lx1, ly1 = LOGO_TEXT
        r = QRectF(lx0 * W, ly0 * H, (lx1 - lx0) * W, (ly1 - ly0) * H)
        cyc = (t % 2.8) / 1.5
        if cyc < 1.0:
            p.save()
            p.setClipRect(r)
            sx = r.left() - r.width() * 0.25 + cyc * r.width() * 1.5
            lg = QLinearGradient(sx - 60, r.top(), sx + 60, r.bottom())
            lg.setColorAt(0.0, QColor(255, 255, 255, 0))
            lg.setColorAt(0.5, QColor(190, 235, 255, 150))
            lg.setColorAt(1.0, QColor(255, 255, 255, 0))
            p.setBrush(QBrush(lg))
            p.drawRect(r)
            p.restore()

        # particules lumineuses
        for q in self._parts:
            y = (q["y"] - t * q["v"]) % 1.0
            tw = 0.35 + 0.65 * (0.5 + 0.5 * math.sin(t * 2.0 + q["ph"]))
            col = QColor(90, 200, 255, int(150 * tw))
            p.setBrush(col)
            rad = q["r"] * W / 1000.0 * 1.6
            p.drawEllipse(QPointF(q["x"] * W + 6 * math.sin(t * 0.7 + q["ph"]), y * H), rad, rad)

        p.setCompositionMode(QPainter.CompositionMode.CompositionMode_SourceOver)
        self._paint_bar(p, W, H, t)
        p.end()

    def _paint_bar(self, p: QPainter, W: int, H: int, t: float):
        x0, y0, x1, y1 = BAR
        bar = QRectF(x0 * W, y0 * H, (x1 - x0) * W, (y1 - y0) * H)
        rad = bar.height() / 2

        # texte d'état
        f = QFont("Segoe UI", 1)
        f.setPixelSize(max(11, int(W * 0.0175)))
        p.setFont(f)
        p.setPen(QColor(225, 240, 255))
        p.drawText(QRectF(bar.left() - 60, TEXT_Y * H - 14, bar.width() + 120, 28),
                   Qt.AlignmentFlag.AlignCenter, self._text)

        # piste
        track = QPainterPath()
        track.addRoundedRect(bar, rad, rad)
        p.fillPath(track, QColor(4, 18, 52, 200))
        p.setPen(QPen(QColor(70, 150, 255, 170), 1.4))
        p.drawPath(track)

        # remplissage
        frac = max(0.0, min(1.0, self._shown / 100.0))
        if frac > 0.002:
            inner = bar.adjusted(3, 3, -3, -3)
            fw = max(inner.height(), inner.width() * frac)
            fill = QRectF(inner.left(), inner.top(), fw, inner.height())
            fp = QPainterPath()
            fp.addRoundedRect(fill, inner.height() / 2, inner.height() / 2)
            gg = QLinearGradient(fill.left(), 0, fill.right(), 0)
            gg.setColorAt(0.0, QColor(20, 120, 255))
            gg.setColorAt(1.0, QColor(60, 225, 255))
            p.fillPath(fp, QBrush(gg))
            p.save()
            p.setClipPath(fp)
            hl = QLinearGradient(0, fill.top(), 0, fill.bottom())   # reflet vitré
            hl.setColorAt(0.0, QColor(255, 255, 255, 90))
            hl.setColorAt(0.5, QColor(255, 255, 255, 10))
            hl.setColorAt(1.0, QColor(255, 255, 255, 0))
            p.fillRect(fill, QBrush(hl))
            sh = fill.left() + ((t * 0.55) % 1.3 - 0.15) * fill.width()   # reflet qui défile
            sg = QLinearGradient(sh - 40, 0, sh + 40, 0)
            sg.setColorAt(0.0, QColor(255, 255, 255, 0))
            sg.setColorAt(0.5, QColor(255, 255, 255, 120))
            sg.setColorAt(1.0, QColor(255, 255, 255, 0))
            p.fillRect(fill, QBrush(sg))
            p.restore()
            # lueur en tête de barre
            p.setCompositionMode(QPainter.CompositionMode.CompositionMode_Plus)
            tip = QPointF(fill.right() - 2, fill.center().y())
            rg = QRadialGradient(tip, bar.height() * 1.6)
            rg.setColorAt(0.0, QColor(120, 230, 255, 190))
            rg.setColorAt(1.0, QColor(0, 120, 255, 0))
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QBrush(rg))
            p.drawEllipse(tip, bar.height() * 1.6, bar.height() * 1.6)
            p.setCompositionMode(QPainter.CompositionMode.CompositionMode_SourceOver)

        # pourcentage
        f2 = QFont("Segoe UI", 1)
        f2.setPixelSize(max(11, int(W * 0.0165)))
        p.setFont(f2)
        p.setPen(QColor(70, 215, 255))
        p.drawText(QRectF(bar.left(), PCT_Y * H - 12, bar.width(), 24),
                   Qt.AlignmentFlag.AlignCenter, f"{int(round(self._shown))}%")
