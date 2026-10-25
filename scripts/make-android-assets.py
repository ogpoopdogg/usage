"""Regenerates the Android launcher icons and splash screens from icon-512.png.

Run from the repo root:  python3 scripts/make-android-assets.py
Needs Pillow (pip install pillow). The notification status-bar icon (drawable-*/ic_stat_usage.png)
is the Dispatch app's white crown, copied from the dispatch repo; this script leaves it alone.
"""
from pathlib import Path

from PIL import Image, ImageDraw

SRC = Path('icon-512.png')
RES = Path('android/app/src/main/res')
BG = (10, 10, 9, 255)  # the icon's own dark background (#0A0A09)

icon = Image.open(SRC).convert('RGBA')


def scaled(n):
    return icon.resize((n, n), Image.LANCZOS)


def centered(canvas, img):
    canvas.alpha_composite(img, ((canvas.width - img.width) // 2, (canvas.height - img.height) // 2))
    return canvas


DENS = {'mdpi': 1, 'hdpi': 1.5, 'xhdpi': 2, 'xxhdpi': 3, 'xxxhdpi': 4}
for d, k in DENS.items():
    n = round(48 * k)
    scaled(n).save(RES / f'mipmap-{d}/ic_launcher.png')
    mask = Image.new('L', (n, n), 0)
    ImageDraw.Draw(mask).ellipse((0, 0, n - 1, n - 1), fill=255)
    rnd = centered(Image.new('RGBA', (n, n), BG), scaled(round(n * 0.86)))
    rnd.putalpha(mask)
    rnd.save(RES / f'mipmap-{d}/ic_launcher_round.png')
    # Adaptive icon foreground: 108dp canvas; launchers show the middle 72dp and keep the middle 66dp safe
    f = round(108 * k)
    centered(Image.new('RGBA', (f, f), BG), scaled(round(70 * k))).save(RES / f'mipmap-{d}/ic_launcher_foreground.png')

(RES / 'values/ic_launcher_background.xml').write_text(
    '<?xml version="1.0" encoding="utf-8"?>\n<resources>\n    <color name="ic_launcher_background">#0A0A09</color>\n</resources>\n')

# Splash screens: the icon centred on the app's background, same sizes Capacitor generated
for p in RES.glob('drawable*/splash.png'):
    w, h = Image.open(p).size
    centered(Image.new('RGBA', (w, h), BG), scaled(round(min(w, h) * 0.35))).convert('RGB').save(p)
print('Android icons and splash screens made from', SRC)
