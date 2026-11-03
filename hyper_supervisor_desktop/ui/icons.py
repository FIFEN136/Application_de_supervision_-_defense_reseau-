"""
Procus Secure — bibliothèque d'icônes SVG monochromes (style Lucide/Feather).
Partagée par la barre latérale et le tableau de bord pour un rendu homogène.
"""
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QImage, QPainter, QPixmap


_PIX_CACHE: dict = {}          # (svg, taille, couleur) → QPixmap : une icône n'est dessinée qu'une fois (mémoire et processeur)


def _svg_icon(svg_body: str, size: int = 16, color: str = "#d6d1c4") -> QPixmap:
    key = (svg_body, size, color)
    pix = _PIX_CACHE.get(key)
    if pix is None:
        pix = _render_svg(svg_body, size, color)
        if len(_PIX_CACHE) > 800:
            _PIX_CACHE.clear()
        _PIX_CACHE[key] = pix
    return pix


def _render_svg(svg_body: str, size: int = 16, color: str = "#d6d1c4") -> QPixmap:
    """
    Rendu d'un SVG inline en QPixmap coloré.
    Utilise QSvgRenderer (PyQt6.QtSvg) — inclus dans PyQt6 standard.
    """
    try:
        from PyQt6.QtSvg import QSvgRenderer
        from PyQt6.QtCore import QByteArray
        svg_str = (
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" '
            f'width="{size}" height="{size}" fill="none" '
            f'stroke="{color}" stroke-width="1.8" '
            f'stroke-linecap="round" stroke-linejoin="round">'
            f'{svg_body}</svg>'
        )
        renderer = QSvgRenderer(QByteArray(svg_str.encode("utf-8")))
        img = QImage(size, size, QImage.Format.Format_ARGB32)
        img.fill(0)
        painter = QPainter(img)
        renderer.render(painter)
        painter.end()
        return QPixmap.fromImage(img)
    except Exception:
        # Fallback : pixmap vide si QtSvg non disponible
        pix = QPixmap(size, size)
        pix.fill(Qt.GlobalColor.transparent)
        return pix


# Bibliothèque SVG paths (Feather Icons / Lucide style)
ICONS = {
    # Tableau de bord
    "dashboard": '<rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/>',
    # Problèmes / alertes
    "problems":  '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
    # Hôtes / serveurs
    "hosts":     '<rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/>',
    # Dernières données
    "latest":    '<line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/>',
    # Console / terminal
    "console":   '<polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>',
    # Carte réseau / topologie
    "topology":  '<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
    # Métriques / graphiques
    "metrics":   '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>',
    # Événements / notifications
    "events":    '<path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/>',
    # Rapports
    "reports":   '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/>',
    # Templates / configuration
    "templates": '<circle cx="12" cy="12" r="3"/><path d="M19.07 4.93a10 10 0 0 1 0 14.14M4.93 4.93a10 10 0 0 0 0 14.14"/>',
    # Médias / alerting
    "media":     '<path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07A19.5 19.5 0 0 1 4.15 13a19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 3.07 2h3a2 2 0 0 1 2 1.72c.127.96.361 1.903.7 2.81a2 2 0 0 1-.45 2.11L7.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45c.907.339 1.85.573 2.81.7A2 2 0 0 1 21 16.92z"/>',
    # Paramètres (Settings)
    "settings":  '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>',
    # Administration / shield
    "admin":     '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    # Hôtes (sous-menu)
    "admin_hosts": '<circle cx="12" cy="8" r="4"/><path d="M20 21a8 8 0 1 0-16 0"/>',
    # Groupes (sous-menu)
    "admin_groups": '<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>',
    # Utilisateurs (sous-menu)
    "admin_users": '<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',
    # Utilisateur (avatar bas)
    "user_avatar": '<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',
}


# Icônes du tableau de bord (même trait, même grille 24×24 que le menu)
ICONS.update({
    "incidents": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="13"/><line x1="12" y1="16" x2="12.01" y2="16"/>',
})
ICONS.update({
    "kpi_online":      '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>',
    "kpi_offline":     '<circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>',
    "kpi_unreachable": '<path d="M1 1l22 22"/><path d="M16.72 11.06A10.94 10.94 0 0 1 19 12.55"/><path d="M5 12.55a10.94 10.94 0 0 1 5.17-2.39"/><path d="M10.71 5.05A16 16 0 0 1 22.58 9"/><path d="M1.42 9a15.91 15.91 0 0 1 4.7-2.88"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/>',
    "kpi_problems":    '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
    "kpi_down":        '<line x1="12" y1="5" x2="12" y2="19"/><polyline points="19 12 12 19 5 12"/>',
    "kpi_up":          '<line x1="12" y1="19" x2="12" y2="5"/><polyline points="5 12 12 5 19 12"/>',
    "kpi_network":     '<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
    "kpi_gateway":     '<rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="18" x2="6.01" y2="18"/><path d="M5 10a10 10 0 0 1 14 0"/><path d="M8.5 12.5a5 5 0 0 1 7 0"/>',
})

ICONS.update({
    "media_email":     '<path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/>',
    "media_slack":     '<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>',
    "media_sms":       '<rect x="5" y="2" width="14" height="20" rx="2" ry="2"/><line x1="12" y1="18" x2="12.01" y2="18"/>',
    "media_pagerduty": '<path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/>',
    "media_webhook":   '<polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/>',
})


# Pictogrammes des appareils (carte réseau) : même style que le menu (traits fins, monochromes)
DEVICE_ICON_KEYS = {
    "router": "dev_router", "switch": "dev_switch", "firewall": "dev_firewall", "ap": "dev_ap", "server": "dev_server",
    "workstation": "dev_pc", "printer": "dev_printer", "mobile": "dev_mobile", "iot": "dev_iot", "hub": "dev_hub",
    "tv": "dev_tv", "camera": "dev_camera", "unknown": "dev_unknown",
}
ICONS.update({
    "dev_router":   '<rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="18" x2="6.01" y2="18"/><line x1="10" y1="18" x2="10.01" y2="18"/>'
                    '<path d="M6 14v-3"/><path d="M18 14v-3"/><path d="M8.5 7.5a5 5 0 0 1 7 0"/><path d="M10.5 10a2 2 0 0 1 3 0"/>',
    "dev_switch":   '<rect x="2" y="8" width="20" height="8" rx="2"/><line x1="6" y1="12" x2="6.01" y2="12"/><line x1="10" y1="12" x2="10.01" y2="12"/>'
                    '<line x1="14" y1="12" x2="14.01" y2="12"/><line x1="18" y1="12" x2="18.01" y2="12"/>',
    "dev_firewall": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/>',
    "dev_ap":       '<path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/>'
                    '<line x1="12" y1="20" x2="12.01" y2="20"/>',
    "dev_server":   '<rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/>'
                    '<line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/>',
    "dev_pc":       '<rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>',
    "dev_printer":  '<polyline points="6 9 6 2 18 2 18 9"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/>'
                    '<rect x="6" y="14" width="12" height="8"/>',
    "dev_mobile":   '<rect x="5" y="2" width="14" height="20" rx="2" ry="2"/><line x1="12" y1="18" x2="12.01" y2="18"/>',
    "dev_iot":      '<rect x="4" y="4" width="16" height="16" rx="2" ry="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/>'
                    '<line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/>',
    "dev_hub":      '<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/>'
                    '<path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
    "dev_tv":       '<rect x="2" y="7" width="20" height="15" rx="2" ry="2"/><polyline points="17 2 12 7 7 2"/>',
    "dev_camera":   '<path d="M23 7l-7 5 7 5V7z"/><rect x="1" y="5" width="15" height="14" rx="2" ry="2"/>',
    "dev_unknown":  '<circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
})


def device_pixmap(dtype: str, size: int = 22, color: str = "#d6d1c4") -> QPixmap:
    return _svg_icon(ICONS[DEVICE_ICON_KEYS.get((dtype or "unknown").lower(), "dev_unknown")], size=size, color=color)


# Pictogrammes d'actions (boutons, états) — RÈGLE DU PROJET : toute icône de l'interface est un SVG de cette bibliothèque,
# jamais un caractère emoji. Un test (tests/test_svg_icons_only.py) refuse les emojis dans le code de l'interface.
ICONS.update({
    "act_save":    '<path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/>',
    "act_edit":    '<path d="M12 20h9"/><path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/>',
    "act_delete":  '<polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/>',
    "act_pause":   '<rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/>',
    "act_play":    '<polygon points="5 3 19 12 5 21 5 3"/>',
    "act_export":  '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>',
    "act_import":  '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>',
    "act_search":  '<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>',
    "act_mail":    '<path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/>',
    "act_refresh": '<polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>',
    "act_check":   '<polyline points="20 6 9 17 4 12"/>',
    "act_close":   '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>',
    "act_zap":     '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>',
    "act_file":    '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/>',
    "act_link":    '<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>',
    "act_activity": '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>',
    "act_wifi":    '<path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/>',
    "act_ethernet": '<rect x="2" y="8" width="20" height="8" rx="2"/><line x1="6" y1="12" x2="6.01" y2="12"/><line x1="10" y1="12" x2="10.01" y2="12"/><line x1="14" y1="12" x2="14.01" y2="12"/><line x1="18" y1="12" x2="18.01" y2="12"/>',
    "act_shield":  '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    "act_alert":   '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
    "act_globe":   '<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
    "act_prev":    '<polyline points="15 18 9 12 15 6"/>',
    "act_next":    '<polyline points="9 18 15 12 9 6"/>',
    "act_clock":   '<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>',
    "act_trash":   '<polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/>',
    "act_plug":    '<path d="M18 8h-2V3h-2v5h-4V3H8v5H6v4a6 6 0 0 0 5 5.91V22h2v-4.09A6 6 0 0 0 18 12z"/>',
})


def svg_icon(key: str, color: str = "#ffffff", size: int = 16):
    """QIcon à partir de la bibliothèque SVG (couleur du texte du bouton par défaut)."""
    from PyQt6.QtGui import QIcon
    return QIcon(_svg_icon(ICONS[key], size=size, color=color))


def icon_button(key: str, text: str = "", color: str = "#ffffff", size: int = 16, parent=None):
    """Bouton avec pictogramme SVG à gauche du texte."""
    from PyQt6.QtCore import QSize
    from PyQt6.QtWidgets import QPushButton
    b = QPushButton(text, parent)
    b.setIcon(svg_icon(key, color, size))
    b.setIconSize(QSize(size, size))
    return b


def next_button(text: str = "Suivant", size: int = 16):
    """Bouton « Suivant » : pictogramme à droite du texte."""
    from PyQt6.QtCore import QSize, Qt
    b = icon_button("act_next", text, size=size)
    b.setLayoutDirection(Qt.LayoutDirection.RightToLeft)
    b.setIconSize(QSize(size, size))
    return b


def dot_pixmap(color: str, size: int = 12) -> QPixmap:
    """Pastille d'état dessinée."""
    from PyQt6.QtGui import QColor
    pm = QPixmap(size, size)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setBrush(QColor(color))
    p.setPen(Qt.PenStyle.NoPen)
    p.drawEllipse(1, 1, size - 2, size - 2)
    p.end()
    return pm


def dot_label(color: str, size: int = 12):
    from PyQt6.QtWidgets import QLabel
    lb = QLabel()
    lb.setPixmap(dot_pixmap(color, size))
    lb.setFixedSize(size + 2, size + 2)
    return lb


def line_sample_label(style: str, color: str = "#c4bfae", width: int = 30):
    """Échantillon de trait pour une légende (dessiné) : style « dash », « solid » ou « dot »."""
    from PyQt6.QtCore import QPointF
    from PyQt6.QtGui import QColor, QPen
    from PyQt6.QtWidgets import QLabel
    pm = QPixmap(width, 10)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    pen = QPen(QColor(color), 2)
    pen.setStyle({"dash": Qt.PenStyle.DashLine, "dot": Qt.PenStyle.DotLine}.get(style, Qt.PenStyle.SolidLine))
    p.setPen(pen)
    p.drawLine(QPointF(1, 5), QPointF(width - 1, 5))
    p.end()
    lb = QLabel()
    lb.setPixmap(pm)
    return lb
