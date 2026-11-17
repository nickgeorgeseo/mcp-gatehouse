"""Render docs/approval-binding.gif: a record that changes mid-approval (4:5 portrait).

    python docs/approval-binding.py FONT_DIR OUT_DIR

FONT_DIR holds space-grotesk-latin.woff2 and jetbrains-mono-latin.woff2 (the
variable nickgeorgeai.com brand faces). The 0.6.0 version's story (release
test APR-04: the order changes by one cent while a person decides, and the
approval no longer applies), plus what 0.6.1 adds: the refusal says what
changed, and the question asked again shows it first. The change line is
the gate's own default text for a Decimal total, as APR-04 uses.
"""
import math
import re
import subprocess
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

FONT_DIR, OUT = Path(sys.argv[1]), Path(sys.argv[2])
W, H, FPS, SCALE_TO = 1080, 1350, 15, (864, 1080)
M = 84  # side margin

# Brand tokens (DESIGN-DIRECTION-2026 §1; light is canon for off-site collateral)
INK, PAPER = (17, 17, 17), (247, 247, 247)
GOLD7, GOLD_MID, GOLD_HI = (158, 119, 0), (194, 146, 0), (230, 172, 0)
GOLD3 = (227, 179, 65)  # dark-surface gold
MUTED, RULE = (88, 88, 88), (222, 222, 222)


_FONTS = {}


def font(face, wt, size):
    key = (face, wt, size)
    if key not in _FONTS:
        f = ImageFont.truetype(str(FONT_DIR / f"{face}-latin.woff2"), size)
        f.set_variation_by_axes([wt])
        _FONTS[key] = f
    return _FONTS[key]


SG = lambda w, s: font("space-grotesk", w, s)
JB = lambda w, s: font("jetbrains-mono", w, s)


def clamp(x):
    return max(0.0, min(1.0, x))


def ease(x):
    x = clamp(x)
    return 1 - (1 - x) ** 3


def mix(a, b, k):
    k = clamp(k)
    return tuple(round(a[i] + (b[i] - a[i]) * k) for i in range(3))


# ---- NG mark: the SVG's paths are M/L/V/H/Z only, so draw them as polygons.
MARK_PATHS = [
    "M511.994 341.518L315.252 472.59V393.867L511.994 262.797V341.518Z",
    "M511.993 1.55566V79.1553L315.257 210.224V131.849H314.739L511.572 0.714844L511.993 1.55566Z",
    "M511.989 209.907L384.377 294.924V216.202L511.989 131.188V209.907Z",
    "M315.251 472.753L256.948 511.595H256.17V170.79L315.251 131.43V472.753Z",
    "M102.331 68.1738L256.171 375.642V511.991L0 0L102.331 68.1738Z",
    "M59.1289 118.109V380.168L0.046875 340.808V0.0273438L59.1289 118.109Z",
    "M511.989 262.773L452.908 302.134V249.284L511.983 209.928V131.259L511.989 131.254V262.773Z",
]


def path_points(d):
    pts, x, y = [], 0.0, 0.0
    for cmd, args in re.findall(r"([MLVHZ])([^MLVHZ]*)", d):
        n = [float(v) for v in re.findall(r"-?\d*\.?\d+", args)]
        if cmd in "ML":
            for i in range(0, len(n), 2):
                x, y = n[i], n[i + 1]
                pts.append((x, y))
        elif cmd == "V":
            y = n[0]; pts.append((x, y))
        elif cmd == "H":
            x = n[0]; pts.append((x, y))
    return pts


def mark(size, light=True):
    """The NG mark with its diagonal gold ramp, as an RGBA image."""
    big = size * 4
    mask = Image.new("L", (big, big), 0)
    md = ImageDraw.Draw(mask)
    for d in MARK_PATHS:
        md.polygon([(px * big / 512, py * big / 512) for px, py in path_points(d)], fill=255)
    stops = [GOLD_HI, GOLD_MID, GOLD7] if light else [(252, 223, 136), (249, 206, 78), (230, 172, 0)]
    grad = Image.new("RGB", (big, big))
    gp = grad.load()
    for yy in range(big):
        for xx in range(0, big, 4):
            k = (xx + yy) / (2 * big)
            c = mix(stops[0], stops[1], k * 2) if k < 0.5 else mix(stops[1], stops[2], (k - 0.5) * 2)
            for dx in range(4):
                gp[xx + dx, yy] = c
    out = grad.convert("RGBA")
    out.putalpha(mask)
    return out.resize((size, size), Image.LANCZOS)


MARK_BIG, MARK_SMALL = mark(260), mark(64)


# ---- drawing helpers
class Frame:
    def __init__(self, bg):
        self.bg = bg
        self.im = Image.new("RGB", (W, H), bg)
        self.d = ImageDraw.Draw(self.im)

    def text(self, xy, s, f, color, a=1.0, bg=None, anchor="la"):
        if a <= 0:
            return
        self.d.text(xy, s, font=f, fill=mix(bg or self.bg, color, a), anchor=anchor)

    def width(self, s, f):
        return self.d.textlength(s, font=f)

    def rrect(self, box, r, fill, a=1.0, bg=None, outline=None, ow=0):
        if a <= 0:
            return
        self.d.rounded_rectangle(box, r, fill=mix(bg or self.bg, fill, a) if fill else None,
                                 outline=mix(bg or self.bg, outline, a) if outline else None, width=ow)

    def check(self, cx, cy, r, a, ring=GOLD7, tick=PAPER):
        """Gold disc with a drawn tick; `a` 0..1 grows the disc then draws the tick."""
        if a <= 0:
            return
        rr = r * ease(a * 2)
        self.d.ellipse((cx - rr, cy - rr, cx + rr, cy + rr), fill=ring)
        k = clamp(a * 2 - 1)
        if k > 0:
            p1, p2, p3 = (cx - r * .45, cy + r * .02), (cx - r * .12, cy + r * .36), (cx + r * .5, cy - r * .34)
            if k < .4:
                e = k / .4
                self.d.line([p1, (p1[0] + (p2[0] - p1[0]) * e, p1[1] + (p2[1] - p1[1]) * e)], fill=tick, width=int(r * .26))
            else:
                e = (k - .4) / .6
                self.d.line([p1, p2, (p2[0] + (p3[0] - p2[0]) * e, p2[1] + (p3[1] - p2[1]) * e)], fill=tick,
                            width=int(r * .26), joint="curve")

    def arrow(self, x, cy, w, color, a=1.0, bg=None, th=5):
        """A drawn →: the brand's subset mono face has no arrow glyph."""
        if a <= 0:
            return
        c = mix(bg or self.bg, color, a)
        head = th * 3.2
        self.d.line([(x, cy), (x + w - head * .6, cy)], fill=c, width=th)
        self.d.polygon([(x + w, cy), (x + w - head, cy - head * .75), (x + w - head, cy + head * .75)], fill=c)

    def cross(self, cx, cy, r, a):
        if a <= 0:
            return
        rr = r * ease(a * 2)
        self.d.ellipse((cx - rr, cy - rr, cx + rr, cy + rr), fill=INK)
        k = clamp(a * 2 - 1)
        if k > 0:
            s = r * .36 * ease(k)
            self.d.line([(cx - s, cy - s), (cx + s, cy + s)], fill=PAPER, width=int(r * .24))
            self.d.line([(cx - s, cy + s), (cx + s, cy - s)], fill=PAPER, width=int(r * .24))

    def footer(self, progress):
        """Brand strip on every paper scene, plus a gold progress line."""
        y = H - 112
        self.d.line([(M, y - 28), (W - M, y - 28)], fill=RULE, width=2)
        self.im.paste(MARK_SMALL, (M, y - 6), MARK_SMALL)
        self.text((M + 84, y + 26), "mcp-gatehouse 0.6.1", JB(700, 36), INK, anchor="lm")
        self.text((W - M, y + 26), "nickgeorgeai.com", JB(400, 36), MUTED, anchor="rm")
        self.d.rectangle((0, H - 10, W * progress, H), fill=GOLD7)


def appear(f, t, at, dur=.45):
    """(alpha, y-offset) for an element that slides up into place at time `at`."""
    k = ease((t - at) / dur)
    return k, (1 - k) * 36


# ---- scenes: each takes local time t (s) and returns a Frame
def s_hook(t):
    f = Frame(GOLD_HI)
    f.text((M, 150), "MCP SECURITY · 0.6.1", JB(700, 40), INK)
    hl = SG(700, 112)
    for i, line in enumerate(["You approve", "cancelling", "order 4417."]):
        f.text((M, 300 + i * 132), line, hl, INK)
    a, dy = appear(f, t, 1.0, .35)
    if a > 0:
        q = "Then it changes."
        qf = SG(700, 88)
        w = f.width(q, qf)
        f.rrect((M - 6, 760 + dy, M + w + 70, 900 + dy), 30, INK, a)
        f.text((M + 32, 830 + dy), q, qf, PAPER, a, bg=mix(GOLD_HI, INK, a), anchor="lm")
    k, _ = appear(f, t, 1.7)
    f.text((M, H - 150), "Does your yes", SG(500, 54), INK, k, bg=GOLD_HI)
    f.text((M, H - 84), "still count?", SG(500, 54), INK, k, bg=GOLD_HI)
    return f


def money(v):
    return f"${v:,.2f}"


def s_change(t):
    """The approval card shows $812.00; the record behind it ticks to $812.01."""
    f = Frame(PAPER)
    f.text((M, 120), "WHILE YOU DECIDE", JB(700, 40), GOLD7)
    a, dy = appear(f, t, .15, .5)
    card = (M, 200 + dy, W - M, 760 + dy)
    f.rrect(card, 36, INK, a)
    cb = mix(PAPER, INK, a)
    x0, y0 = M + 56, 248 + dy
    f.text((x0, y0), "What you see", JB(700, 34), (190, 190, 190), a, bg=cb)
    f.text((x0, y0 + 64), "cancel_order", JB(700, 54), GOLD3, a, bg=cb)
    tw = f.width("cancel_order", JB(700, 54))
    f.rrect((x0 + tw + 24, y0 + 62, x0 + tw + 290, y0 + 124), 14, None, a, bg=cb, outline=GOLD3, ow=3)
    f.text((x0 + tw + 157, y0 + 93), "DESTRUCTIVE", JB(700, 32), GOLD3, a, bg=cb, anchor="mm")
    f.text((x0, y0 + 160), "Order 4417", SG(700, 60), PAPER, a, bg=cb)
    f.text((x0, y0 + 240), "Blue Ridge Cabinets", SG(500, 48), (190, 190, 190), a, bg=cb)
    f.text((x0, y0 + 304), "$812.00 · for nick", SG(500, 48), (190, 190, 190), a, bg=cb)
    bx = (x0, y0 + 394, W - M - 56, y0 + 484)
    f.rrect(bx, 24, None, a, bg=cb, outline=GOLD_HI, ow=4)
    f.text(((bx[0] + bx[2]) / 2, (bx[1] + bx[3]) / 2), "Approve", SG(700, 52), GOLD_HI, a, bg=cb, anchor="mm")
    # the server's record, below the card
    k, dy2 = appear(f, t, .9)
    if k > 0:
        y = 830 + dy2
        f.text((M, y), "What the server has", JB(700, 34), MUTED, k)
        f.rrect((M, y + 56, W - M, y + 196), 28, (255, 255, 255), k, outline=RULE, ow=3)
        flip = ease((t - 2.2) / .35)
        val = "$812.01" if flip > .5 else "$812.00"
        hi = mix((255, 255, 255), GOLD_HI, flip)
        vf = SG(700, 64)
        f.text((M + 40, y + 126), "Order 4417 ·", SG(500, 52), INK, k, bg=(255, 255, 255), anchor="lm")
        vx = M + 40 + f.width("Order 4417 · ", SG(500, 52)) + 16
        vw = f.width(val, vf)
        if flip > 0:
            f.rrect((vx - 14, y + 86, vx + vw + 14, y + 166), 16, GOLD_HI, flip, bg=(255, 255, 255))
        f.text((vx, y + 126), val, vf, INK, k, bg=hi if flip > 0 else (255, 255, 255), anchor="lm")
        k3, dy3 = appear(f, t, 2.7)
        f.text((M, y + 250 + dy3), "One cent. Changed after you looked.", SG(700, 48), INK, k3)
    return f


def s_refused(t):
    f = Frame(PAPER)
    f.text((M, 120), "YOU CLICK APPROVE", JB(700, 40), GOLD7)
    f.cross(M + 62, 290, 62, clamp((t - .2) / .5))
    a, dy = appear(f, t, .45)
    f.text((M + 160, 290 + dy), "Refused.", SG(700, 104), INK, a, anchor="lm")
    k, dy2 = appear(f, t, .9)
    f.text((M, 430 + dy2), "Your yes was for the order", SG(500, 54), INK, k)
    f.text((M, 500 + dy2), "you saw. That order changed.", SG(500, 54), INK, k)
    # what the agent is told: the field, before and after
    k2, dy3 = appear(f, t, 1.6)
    if k2 > 0:
        y = 640 + dy3
        f.rrect((M, y, W - M, y + 300), 32, INK, k2)
        cb = mix(PAPER, INK, k2)
        jf = JB(700, 48)
        f.text((M + 50, y + 50), "What changed:", JB(400, 34), (170, 170, 170), k2, bg=cb)
        f.text((M + 50, y + 104), "order.total", jf, PAPER, k2, bg=cb)
        x = M + 50
        f.text((x, y + 184), "812.00", jf, (170, 170, 170), k2, bg=cb)
        x += f.width("812.00", jf) + 22
        f.arrow(x, y + 184 + 30, 64, PAPER, k2, bg=cb, th=6)
        x += 64 + 22
        f.text((x, y + 184), "812.01", jf, GOLD3, k2, bg=cb)
    k3, dy4 = appear(f, t, 2.4)
    f.check(M + 40, 1050 + dy4, 40, clamp((t - 2.4) / .5))
    f.text((M + 110, 1050 + dy4), "Nothing ran.", SG(700, 56), INK, k3, anchor="lm")
    return f


def s_reask(t):
    """New in 0.6.1: asked again, the card leads with what changed."""
    f = Frame(PAPER)
    f.text((M, 120), "NEW IN 0.6.1 · ASKED AGAIN", JB(700, 40), GOLD7)
    a, dy = appear(f, t, .15, .5)
    card = (M, 200 + dy, W - M, 900 + dy)
    f.rrect(card, 36, INK, a)
    cb = mix(PAPER, INK, a)
    x0, y0 = M + 56, 248 + dy
    # the banner drops in a beat after the card: it is the point of the scene
    b, bdy = appear(f, t, .8, .45)
    if b > 0:
        band = (x0 - 16, y0 - 8, W - M - 40, y0 + 132)
        f.rrect(band, 22, GOLD_HI, b, bg=cb)
        bb = mix(cb, GOLD_HI, b)
        f.text((x0 + 12, y0 + 36), "Changed since you were last asked", JB(700, 33), INK, b, bg=bb, anchor="lm")
        jf = JB(700, 42)
        x = x0 + 12
        f.text((x, y0 + 92), "order.total: 812.00", jf, INK, b, bg=bb, anchor="lm")
        x += f.width("order.total: 812.00", jf) + 18
        f.arrow(x, y0 + 94, 52, INK, b, bg=bb, th=5)
        x += 52 + 18
        f.text((x, y0 + 92), "812.01", JB(800, 42), INK, b, bg=bb, anchor="lm")
    y1 = y0 + 168
    f.text((x0, y1), "cancel_order", JB(700, 54), GOLD3, a, bg=cb)
    tw = f.width("cancel_order", JB(700, 54))
    f.rrect((x0 + tw + 24, y1 - 2, x0 + tw + 290, y1 + 60), 14, None, a, bg=cb, outline=GOLD3, ow=3)
    f.text((x0 + tw + 157, y1 + 29), "DESTRUCTIVE", JB(700, 32), GOLD3, a, bg=cb, anchor="mm")
    f.text((x0, y1 + 96), "Order 4417", SG(700, 60), PAPER, a, bg=cb)
    f.text((x0, y1 + 176), "Blue Ridge Cabinets", SG(500, 48), (190, 190, 190), a, bg=cb)
    lf = SG(500, 48)
    f.text((x0, y1 + 240), "$812.01", SG(700, 48), GOLD3, a, bg=cb)
    f.text((x0 + f.width("$812.01", SG(700, 48)), y1 + 240), " · for nick", lf, (190, 190, 190), a, bg=cb)
    bx = (x0, y1 + 330, W - M - 56, y1 + 420)
    f.rrect(bx, 24, None, a, bg=cb, outline=GOLD_HI, ow=4)
    f.text(((bx[0] + bx[2]) / 2, (bx[1] + bx[3]) / 2), "Approve", SG(700, 52), GOLD_HI, a, bg=cb, anchor="mm")
    k, dy2 = appear(f, t, 2.2)
    f.text((M, 960 + dy2), "So the second yes", SG(700, 56), INK, k)
    f.text((M, 1030 + dy2), "isn't a reflex.", SG(700, 56), INK, k)
    return f


AUDIT = [('{', None), ('  "tool": ', '"cancel_order",'), ('  "outcome": ', '"denied",'),
         ('  "reason": ', None), ('    ', '"resource changed'), ('    ', ' while awaiting approval",'),
         ('  "changed": ', '["order.total"],'), ('  "caller": ', '"nick"'), ('}', None)]


def s_audit(t):
    f = Frame(PAPER)
    f.text((M, 120), "ON THE RECORD", JB(700, 40), GOLD7)
    f.text((M, 190), "The audit log", SG(700, 92), INK)
    f.text((M, 296), "says what changed.", SG(700, 92), INK)
    f.rrect((M, 450, W - M, 1060), 32, INK)
    total = sum(len(k) + len(v or "") for k, v in AUDIT)
    shown = int(total * clamp((t - .3) / 1.8))
    jf = JB(700, 40)
    y = 490
    for k, v in AUDIT:
        line = k + (v or "")
        n = max(0, min(len(line), shown))
        shown -= len(line)
        ks, vs = line[:n][:len(k)], line[:n][len(k):]
        f.text((M + 46, y), ks, jf, PAPER, bg=INK)
        if vs:
            f.text((M + 46 + f.width(k, jf), y), vs, jf, GOLD3, bg=INK)
        y += 62
    return f


def s_end(t):
    f = Frame(PAPER)
    a, dy = appear(f, t, 0, .5)
    m = MARK_BIG
    f.im.paste(m, ((W - m.width) // 2, int(130 + dy)), m)
    f.text((W / 2, 520 + dy), "You approve", SG(700, 88), INK, a, anchor="mm")
    f.text((W / 2, 620 + dy), "what you saw.", SG(700, 88), INK, a, anchor="mm")
    k, dy2 = appear(f, t, .5)
    f.text((W / 2, 730 + dy2), "mcp-gatehouse 0.6.1", SG(500, 54), INK, k, anchor="mm")
    k2, dy3 = appear(f, t, 1.0)
    cmd = "pip install mcp-gatehouse"
    cf = JB(700, 46)
    w = f.width(cmd, cf)
    f.rrect(((W - w) / 2 - 44, 820 + dy3, (W + w) / 2 + 44, 920 + dy3), 24, INK, k2)
    f.text((W / 2, 870 + dy3), cmd, cf, PAPER, k2, bg=mix(PAPER, INK, k2), anchor="mm")
    k3, _ = appear(f, t, 1.5)
    f.text((W / 2, 1060), "Impossible is just unbuilt.", SG(700, 56), GOLD7, k3, anchor="mm")
    f.text((W / 2, 1140), "nickgeorgeai.com", JB(400, 42), MUTED, k3, anchor="mm")
    return f


SCENES = [(s_hook, 3.4, False), (s_change, 4.6, True), (s_refused, 4.4, True),
          (s_reask, 4.8, True), (s_audit, 3.6, True), (s_end, 3.6, False)]


def main():
    frames = OUT / "frames"
    frames.mkdir(parents=True, exist_ok=True)
    for p in frames.glob("*.png"):
        p.unlink()
    total = sum(d for _, d, _ in SCENES)
    n, t0 = 0, 0.0
    for fn, dur, footer in SCENES:
        for i in range(int(round(dur * FPS))):
            t = i / FPS
            fr = fn(t)
            if footer:
                fr.footer((t0 + t) / total)
            fr.im.resize(SCALE_TO, Image.LANCZOS).save(frames / f"{n:04d}.png")
            n += 1
        t0 += dur
    print(f"{n} frames, {total:.1f} s")
    src = ["-framerate", str(FPS), "-i", str(frames / "%04d.png")]
    subprocess.run(["ffmpeg", "-v", "error", "-y", *src, "-vf",
                    "split[a][b];[a]palettegen=max_colors=64:stats_mode=full[p];[b][p]paletteuse=dither=none",
                    "-loop", "0", str(OUT / "approval-binding.gif")], check=True)


if __name__ == "__main__":
    main()
