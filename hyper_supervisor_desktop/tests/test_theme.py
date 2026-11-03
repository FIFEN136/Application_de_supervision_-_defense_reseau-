"""Thème noir et or : lisibilité (contraste), police fournie et licence respectée."""
import pathlib

from ui.styles import COLOR


def _lum(h: str) -> float:
    h = h.lstrip("#")
    c = [int(h[i:i + 2], 16) / 255 for i in (0, 2, 4)]
    c = [x / 12.92 if x <= 0.03928 else ((x + 0.055) / 1.055) ** 2.4 for x in c]
    return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]


def _ratio(a: str, b: str) -> float:
    la, lb = sorted((_lum(a), _lum(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def test_text_is_white_and_very_readable_on_every_background():
    assert COLOR["text_pri"].lower() == "#ffffff"
    for bg in ("bg_main", "bg_sidebar", "bg_card", "bg_row", "bg_input"):
        assert _ratio(COLOR["text_pri"], COLOR[bg]) >= 15, bg           # AAA exige 7
        assert _ratio(COLOR["text_sec"], COLOR[bg]) >= 10, bg
        assert _ratio(COLOR["accent"], COLOR[bg]) >= 7, bg              # l'or reste lisible
        assert _ratio(COLOR["red"], COLOR[bg]) >= 4.5, bg               # « hors ligne » lisible


def test_bundled_font_is_free_and_marianne_is_not_embedded():
    root = pathlib.Path(__file__).resolve().parent.parent / "assets" / "fonts"
    names = {p.name for p in root.iterdir()}
    assert {"PublicSans-Regular.ttf", "PublicSans-Bold.ttf", "PublicSans-OFL.txt"} <= names
    assert not any("marianne" in n.lower() for n in names)              # réservée à l'administration : jamais distribuée ici


def test_fonts_load_and_family_is_selected(qapp):
    from ui.styles import load_fonts, preferred_family
    assert any(n.startswith("PublicSans") for n in load_fonts())
    assert preferred_family() in ("Public Sans", "Marianne")
