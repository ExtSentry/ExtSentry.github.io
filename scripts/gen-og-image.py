#!/usr/bin/env python3
"""Generate og-image.png for ExtSentry (extsentry.github.io).

Browser Extension Threat Intelligence — dark security-console card:
- near-black ground (#0a0c10, matches index.html <body>), radial red-orange glow
- glowing fiery puzzle-piece "sentry" mark (brand: demon puzzle piece w/ eye slits)
- big wordmark, mono tagline, severity/IOC chip row, footer strip

Run from the repo root: python3 scripts/gen-og-image.py
"""
import os

from PIL import Image, ImageDraw, ImageFont

W, H = 1200, 630

GROUND = "#0a0c10"
PANEL = "#12161d"
PANEL_HI = "#1b212b"
LINE = "#262d38"
INK = "#e6edf3"
INK_2 = "#c8ccd4"
INK_3 = "#8b949e"
ORANGE = "#ff7a18"
RED = "#e0483e"
EMBER = "#ffb066"
BLUE = "#58a6ff"

FONT_DIRS = [
    "/usr/share/fonts/truetype/dejavu",
    "/usr/share/fonts/truetype/noto",
]


def font(name, size):
    for d in FONT_DIRS:
        p = os.path.join(d, name)
        if os.path.exists(p):
            return ImageFont.truetype(p, size)
    raise FileNotFoundError(f"font {name} not found")


def rounded_rect(draw, box, r, fill, outline=None, width=1):
    draw.rounded_rectangle(box, radius=r, fill=fill, outline=outline, width=width)


def draw_puzzle_mark(draw, cx, cy, s, glow=True):
    """Fiery puzzle piece with slitted eyes + jagged grin (brand motif)."""
    # outer glow
    if glow:
        halo = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        hd = ImageDraw.Draw(halo)
        hd.ellipse((cx - s * 1.05, cy - s * 1.05, cx + s * 1.05, cy + s * 1.05),
                   fill=(255, 122, 24, 40))
        return halo

    # puzzle piece body: rounded square with left tab + right notch
    x0, y0, x1, y1 = cx - s, cy - s, cx + s, cy + s
    tab_w, tab_h = int(s * 0.34), int(s * 0.30)
    notch_w, notch_h = int(s * 0.26), int(s * 0.26)

    # body path via rounded_rectangle chunks (PIL has no union; draw layered)
    rounded_rect(draw, (x0, y0 + tab_h, x1, y1 - notch_h), int(s * 0.16),
                 fill=RED, outline=ORANGE, width=3)
    # left tab
    rounded_rect(draw, (x0 - tab_w, y0 + tab_h, x0 + tab_w, y1 - tab_h - int(s * 0.30)),
                 int(s * 0.12), fill=RED, outline=ORANGE, width=3)
    # right notch (cut out): cover with ground-colored rounded rect
    rounded_rect(draw, (x1 - notch_w - 2, cy - notch_h, x1 + 2, cy + notch_h),
                 int(s * 0.08), fill=PANEL, outline=PANEL)

    # gradient-ish top highlight
    rounded_rect(draw, (x0 + 22, y0 + tab_h + 22, x1 - 22, y0 + tab_h + 62),
                 int(s * 0.08), fill=EMBER)

    # two slitted angry eyes
    eye_dx = int(s * 0.30)
    eye_y = cy - int(s * 0.28)
    for ex in (cx - eye_dx, cx + eye_dx):
        draw.polygon([(ex - 24, eye_y + 14), (ex, eye_y - 12), (ex + 24, eye_y + 14),
                      (ex + 10, eye_y + 22), (ex - 10, eye_y + 22)], fill=INK)
        draw.polygon([(ex - 16, eye_y + 10), (ex, eye_y - 6), (ex + 16, eye_y + 10),
                      (ex + 8, eye_y + 16), (ex - 8, eye_y + 16)], fill=ORANGE)

    # jagged grin
    gx0, gx1 = cx - int(s * 0.44), cx + int(s * 0.44)
    gy = cy + int(s * 0.44)
    teeth = 9
    pts = [(gx0, gy)]
    for i in range(teeth):
        px = gx0 + (gx1 - gx0) * (i + 0.5) / teeth
        pts.append((px, gy + 16))
    pts.append((gx1, gy))
    pts.append((gx1, gy + 2))
    for i in range(teeth - 1, -1, -1):
        px = gx0 + (gx1 - gx0) * (i + 0.5) / teeth
        pts.append((px, gy + 22))
    pts.append((gx0, gy + 2))
    draw.polygon(pts, fill="#000000")


def main():
    img = Image.new("RGB", (W, H), GROUND)
    draw = ImageDraw.Draw(img)

    # top scan bar (console vibe)
    draw.rectangle((0, 0, W, 6), fill=ORANGE)

    # halo behind mark
    halo = draw_puzzle_mark(draw, 300, 300, 180, glow=True)
    img = Image.alpha_composite(img.convert("RGBA"), halo).convert("RGB")
    draw = ImageDraw.Draw(img)

    # mark itself
    draw_puzzle_mark(draw, 300, 300, 180, glow=False)

    # mono kicker chip
    kf = font("DejaVuSansMono-Bold.ttf", 22)
    kicker = "THREAT INTELLIGENCE FEED"
    draw.rounded_rectangle((470, 150, 470 + kf.getlength(kicker) + 40, 196), 12,
                           fill=PANEL, outline=LINE, width=2)
    draw.text((490, 162), kicker, font=kf, fill=ORANGE)

    # wordmark
    wf = font("DejaVuSans-Bold.ttf", 104)
    draw.text((466, 210), "ExtSentry", font=wf, fill=INK)

    # tagline
    tf = font("DejaVuSans-Bold.ttf", 28)
    draw.text((466, 336), "Browser Extension Threat Intelligence", font=tf, fill=INK_2)

    # mono sub-line
    sf = font("DejaVuSansMono.ttf", 22)
    draw.text((468, 390), "IOC feeds for malicious & sensitive extensions", font=sf, fill=INK_3)

    # dashed separator
    y = 448
    x = 468
    while x < 1110:
        draw.rectangle((x, y, x + 26, y + 4), fill=LINE)
        x += 42

    # chip row
    chips = [("16+ FEED FORMATS", ORANGE), ("COMMUNITY-DRIVEN", BLUE), ("FREE & OPEN", EMBER)]
    chip_y = 478
    cx = 466
    cf = font("DejaVuSans-Bold.ttf", 18)
    for label, color in chips:
        w = int(cf.getlength(label)) + 44
        draw.rounded_rectangle((cx, chip_y, cx + w, chip_y + 42), 10,
                               fill=PANEL_HI, outline=color, width=2)
        draw.text((cx + 22, chip_y + 10), label, font=cf, fill=color)
        cx += w + 16

    # footer strip
    draw.rectangle((0, 566, W, 630), fill=PANEL)
    ff = font("DejaVuSansMono.ttf", 22)
    draw.text((60, 584), "extsentry.github.io", font=ff, fill=INK_3)
    draw.text((W - 60 - ff.getlength("browser extension threat intelligence"),
               584), "browser extension threat intelligence", font=ff, fill=INK_3)

    out = "og-image.png"
    img.save(out, "PNG")
    print(f"wrote {out}: {img.size[0]}x{img.size[1]}")


if __name__ == "__main__":
    main()
