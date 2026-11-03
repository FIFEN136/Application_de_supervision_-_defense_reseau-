"""Règle du projet : toute icône de l'interface est un SVG (ui/icons.py). Aucun emoji ni pictogramme-caractère dans le code de l'interface."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# pictogrammes interdits : emojis, symboles divers, dingbats, flèches-pictos, triangles/puces/cases, symboles techniques
FORBIDDEN = re.compile("[\U0001F000-\U0001FFFF\u2190-\u21FF\u2300-\u23FF\u2500-\u25FF\u2600-\u27FF\u2900-\u2BFF\uFE0F]")
# typographie admise dans les phrases : flèches de sens « → » « ↓ » « ↑ » « ↔ » (débits, enchaînements), tirets, guillemets
ALLOWED = set("→↓↑↔")


def test_no_emoji_or_pictogram_characters_in_ui_code():
    import io
    import tokenize
    bad = []
    for f in sorted((ROOT / "ui").rglob("*.py")) + [ROOT / "core" / "device_info.py", ROOT / "core" / "device_link.py"]:
        src = f.read_text(encoding="utf8")
        for tok in tokenize.generate_tokens(io.StringIO(src).readline):         # seuls les textes affichables comptent (pas les commentaires)
            if tok.type != tokenize.STRING:
                continue
            text = re.sub("[\u2500-\u257F]{3,}", "", tok.string)            # traits de séparation des commentaires de code
            text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)                      # commentaires des feuilles de style (invisibles)
            for ch in FORBIDDEN.findall(text):
                if ch not in ALLOWED:
                    bad.append(f"{f.relative_to(ROOT)}:{tok.start[0]}: U+{ord(ch):04X} {tok.string.strip()[:60]}")
    assert not bad, "Icônes : utilisez un SVG de ui/icons.py, pas un caractère.\n" + "\n".join(bad[:40])


def test_every_device_type_and_action_icon_exists_and_renders(qapp):
    from ui.icons import DEVICE_ICON_KEYS, ICONS, device_pixmap, svg_icon
    assert all(k in ICONS for k in DEVICE_ICON_KEYS.values())
    for key in ICONS:
        assert not svg_icon(key).isNull()
    assert not device_pixmap("workstation", 20).isNull()
