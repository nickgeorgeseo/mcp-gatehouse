"""Render docs/explainer.gif, the README's branded explainer (16:9 landscape).

    python docs/explainer.py FONT_DIR OUT_DIR

FONT_DIR holds SpaceGrotesk-500/700.ttf and JetBrainsMono-400/700.ttf (static
instances of the nickgeorgeai.com brand faces). Frames are drawn at 1600x900
and scaled to 960x540; ffmpeg then makes the GIF. Every claim on screen is
something the demo server and the test suite do: a verified caller, a policy
per tool, approval for destructive calls, the 5 s authorization deadline,
the re-check after approval, and one audit line per call.
"""
import re
import subprocess
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

FONT_DIR, OUT = Path(sys.argv[1]), Path(sys.argv[2])
W, H, FPS, SCALE_TO = 1600, 900, 15, (960, 540)
M = 96  # side margin
COL = 840  # left edge of the right-hand column

# Brand tokens (light theme)
INK, PAPER = (17, 17, 17), (247, 247, 247)
GOLD7, GOLD_MID, GOLD_HI = (158, 119, 0), (194, 146, 0), (230, 172, 0)
GOLD3 = (227, 179, 65)  # gold on ink
MUTED, RULE, SOFT = (88, 88, 88), (222, 222, 222), (190, 190, 190)


def font(face, wt, size):
    return ImageFont.truetype(str(FONT_DIR / f"{face}-{wt}.ttf"), size)


def SG(w, s):
    return font("SpaceGrotesk", w, s)


def JB(w, s):
    return font("JetBrainsMono", w, s)


def clamp(x):
    return max(0.0, min(1.0, x))


def ease(x):
    return 1 - (1 - clamp(x)) ** 3


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
            y = n[0]
            pts.append((x, y))
        elif cmd == "H":
            x = n[0]
            pts.append((x, y))
    return pts


def mark(size):
    """The NG mark with its diagonal gold ramp, as an RGBA image."""
    big = size * 4
    mask = Image.new("L", (big, big), 0)
    md = ImageDraw.Draw(mask)
    for d in MARK_PATHS:
        md.polygon([(px * big / 512, py * big / 512) for px, py in path_points(d)], fill=255)
    grad = Image.new("RGB", (big, big))
    gp = grad.load()
    for yy in range(big):
        for xx in range(0, big, 4):
            k = (xx + yy) / (2 * big)
            c = mix(GOLD_HI, GOLD_MID, k * 2) if k < 0.5 else mix(GOLD_MID, GOLD7, (k - 0.5) * 2)
            for dx in range(4):
                gp[xx + dx, yy] = c
    out = grad.convert("RGBA")
    out.putalpha(mask)
    return out.resize((size, size), Image.LANCZOS)


MARK_BIG, MARK_SMALL = mark(200), mark(48)


class Frame:
    def __init__(self, bg):
        self.bg = bg
        self.im = Image.new("RGB", (W, H), bg)
        self.d = ImageDraw.Draw(self.im)

    def text(self, xy, s, f, color, a=1.0, bg=None, anchor="la"):
        if a > 0:
            self.d.text(xy, s, font=f, fill=mix(bg or self.bg, color, a), anchor=anchor)

    def width(self, s, f):
        return self.d.textlength(s, font=f)

    def rrect(self, box, r, fill, a=1.0, bg=None, outline=None, ow=0):
        if a > 0:
            self.d.rounded_rectangle(box, r, fill=mix(bg or self.bg, fill, a) if fill else None,
                                     outline=mix(bg or self.bg, outline, a) if outline else None, width=ow)

    def check(self, cx, cy, r, a):
        """Gold disc, then a drawn tick."""
        if a <= 0:
            return
        rr = r * ease(a * 2)
        self.d.ellipse((cx - rr, cy - rr, cx + rr, cy + rr), fill=GOLD7)
        k = clamp(a * 2 - 1)
        if k > 0:
            p1, p2, p3 = (cx - r * .45, cy + r * .02), (cx - r * .12, cy + r * .36), (cx + r * .5, cy - r * .34)
            if k < .4:
                e = k / .4
                self.d.line([p1, (p1[0] + (p2[0] - p1[0]) * e, p1[1] + (p2[1] - p1[1]) * e)],
                            fill=PAPER, width=int(r * .26))
            else:
                e = (k - .4) / .6
                self.d.line([p1, p2, (p2[0] + (p3[0] - p2[0]) * e, p2[1] + (p3[1] - p2[1]) * e)],
                            fill=PAPER, width=int(r * .26), joint="curve")

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
        y = H - 64
        self.d.line([(M, y - 34), (W - M, y - 34)], fill=RULE, width=2)
        self.im.paste(MARK_SMALL, (M, y - 22), MARK_SMALL)
        self.text((M + 68, y + 2), "mcp-gatehouse", JB(700, 32), INK, anchor="lm")
        self.text((W - M, y + 2), "nickgeorgeai.com", JB(400, 32), MUTED, anchor="rm")
        self.d.rectangle((0, H - 8, W * progress, H), fill=GOLD7)

    def title(self, kicker, lines, y=150):
        """Kicker and a two-line headline in the left column."""
        self.text((M, y), kicker, JB(700, 32), GOLD7)
        for i, line in enumerate(lines):
            self.text((M, y + 60 + i * 96), line, SG(700, 84), INK)


def appear(t, at, dur=.45):
    """(alpha, y-offset) for an element that slides up into place at time `at`."""
    k = ease((t - at) / dur)
    return k, (1 - k) * 30


# ---- scenes: each takes local time t (s) and returns a Frame
def s_hook(t):
    f = Frame(GOLD_HI)
    f.text((M, 120), "MCP AUTHORIZATION", JB(700, 36), INK)
    for i, line in enumerate(["Your AI agent wants", "to cancel order 4418."]):
        f.text((M, 200 + i * 124), line, SG(700, 112), INK)
    a, dy = appear(t, 1.0, .35)
    if a > 0:
        q, qf = "Should it?", SG(700, 88)
        w = f.width(q, qf)
        f.rrect((M - 6, 500 + dy, M + w + 64, 628 + dy), 28, INK, a)
        f.text((M + 30, 564 + dy), q, qf, PAPER, a, bg=mix(GOLD_HI, INK, a), anchor="lm")
    f.text((M, H - 130), "mcp-gatehouse checks every tool call before it runs.", SG(500, 52), INK)
    return f


def s_gate(t):
    f = Frame(PAPER)
    f.title("BEFORE ANY TOOL RUNS", ["The gate asks", "three questions."])
    f.text((M, 470), "Miss one and the call", SG(500, 44), MUTED, ease((t - 3.8) / .5))
    f.text((M, 526), "doesn't run.", SG(500, 44), MUTED, ease((t - 3.8) / .5))
    rows = [("Who's asking?", "A verified caller: nick"),
            ("Is it allowed?", "Policy: nick's own order"),
            ("Is it safe?", "A person approves it")]
    for i, (q, ans) in enumerate(rows):
        at = .5 + i * 1.1
        a, dy = appear(t, at)
        y = 150 + i * 196 + dy
        if a > 0:
            f.text((COL, y + 6), f"0{i + 1}", JB(700, 36), GOLD7, a)
            f.text((COL + 76, y - 6), q, SG(700, 56), INK, a)
            f.text((COL + 76, y + 66), ans, SG(500, 42), MUTED, ease((t - at - .35) / .4))
            f.check(W - M - 40, y + 46, 38, clamp((t - at - .55) / .5))
            if i < 2:
                f.d.line([(COL, y + 152), (W - M, y + 152)], fill=mix(PAPER, RULE, a), width=2)
    return f


def s_approve(t):
    f = Frame(PAPER)
    f.title("IRREVERSIBLE?", ["A person", "says yes."])
    k, dy2 = appear(t, 2.4)
    if k > 0:
        f.check(M + 34, 520 + dy2, 34, clamp((t - 2.4) / .5))
        f.text((M + 90, 520 + dy2), "It runs once,", SG(700, 48), INK, k, anchor="lm")
        f.text((M + 90, 580 + dy2), "and it's logged.", SG(700, 48), INK, k, anchor="lm")
    a, dy = appear(t, .15, .5)
    card = (COL - 40, 110 + dy, W - M, 740 + dy)
    f.rrect(card, 32, INK, a)
    cb = mix(PAPER, INK, a)
    x0, y0 = COL + 8, 150 + dy
    f.text((x0, y0), "Approve this call?", SG(700, 56), PAPER, a, bg=cb)
    f.text((x0, y0 + 96), "cancel_order", JB(700, 46), GOLD3, a, bg=cb)
    tw = f.width("cancel_order", JB(700, 46))
    f.rrect((x0 + tw + 20, y0 + 94, x0 + tw + 250, y0 + 148), 12, None, a, bg=cb, outline=GOLD3, ow=3)
    f.text((x0 + tw + 135, y0 + 121), "DESTRUCTIVE", JB(700, 28), GOLD3, a, bg=cb, anchor="mm")
    f.text((x0, y0 + 186), "Order 4418", SG(700, 52), PAPER, a, bg=cb)
    f.text((x0, y0 + 256), "Piedmont Supply · $240", SG(500, 42), SOFT, a, bg=cb)
    f.text((x0, y0 + 314), "for nick", SG(500, 42), SOFT, a, bg=cb)
    press = ease((t - 1.9) / .3)
    bx = (x0, y0 + 410, W - M - 48, y0 + 510)
    f.rrect(bx, 22, mix(INK, GOLD_HI, press) if press > 0 else None, a, bg=cb, outline=GOLD_HI, ow=4)
    label = "Approved" if press > .5 else "Approve"
    f.text(((bx[0] + bx[2]) / 2, (bx[1] + bx[3]) / 2), label, SG(700, 50),
           INK if press > .5 else GOLD_HI, a, bg=mix(INK, GOLD_HI, press) if press > .5 else cb, anchor="mm")
    return f


def s_denied(t):
    f = Frame(PAPER)
    f.title("NO PASS? NOTHING RUNS.", ["Everything else", "fails closed."])
    rows = ["No verified caller", "Someone else's order", "Policy hangs past 5 s", "Changed during approval"]
    for i, r in enumerate(rows):
        at = .45 + i * .6
        a, dy = appear(t, at, .35)
        y = 150 + i * 146 + dy
        if a > 0:
            f.cross(COL + 34, y + 40, 34, clamp((t - at) / .45))
            f.text((COL + 96, y + 40), r, SG(700, 44), INK, a, anchor="lm")
            if i < 3:
                f.d.line([(COL, y + 110), (W - M, y + 110)], fill=mix(PAPER, RULE, a), width=2)
    return f


AUDIT = [('{', None), ('  "tool": ', '"cancel_order",'), ('  "outcome": ', '"ok",'),
         ('  "authz": ', '"ask",'), ('  "caller": ', '"nick",'), ('  "call_id": ', '"9f2c…"'), ('}', None)]


def s_audit(t):
    f = Frame(PAPER)
    f.title("PROOF ON THE RECORD", ["Every call writes", "one audit line."])
    k, dy = appear(t, 2.3)
    f.text((M, 470 + dy), "Allowed or denied,", SG(500, 44), MUTED, k)
    f.text((M, 526 + dy), "with who and why.", SG(500, 44), MUTED, k)
    f.rrect((COL - 40, 110, W - M, 740), 32, INK)
    total = sum(len(a) + len(b or "") for a, b in AUDIT)
    shown = int(total * clamp((t - .3) / 1.8))
    jf = JB(700, 42)
    y = 160
    for key, val in AUDIT:
        line = key + (val or "")
        n = max(0, min(len(line), shown))
        shown -= len(line)
        ks, vs = line[:n][:len(key)], line[:n][len(key):]
        f.text((COL + 8, y), ks, jf, PAPER, bg=INK)
        if vs:
            f.text((COL + 8 + f.width(key, jf), y), vs, jf, GOLD3, bg=INK)
        y += 78
    return f


def s_end(t):
    f = Frame(PAPER)
    a, dy = appear(t, 0, .5)
    f.im.paste(MARK_BIG, (M + 40, int(250 + dy)), MARK_BIG)
    x = M + 340
    f.text((x, 230 + dy), "mcp-gatehouse", SG(700, 96), INK, a)
    k, dy2 = appear(t, .5)
    f.text((x, 360 + dy2), "Authorization for MCP tools,", SG(500, 50), INK, k)
    f.text((x, 420 + dy2), "enforced at runtime.", SG(500, 50), INK, k)
    k2, dy3 = appear(t, 1.0)
    cmd, cf = "pip install mcp-gatehouse", JB(700, 42)
    w = f.width(cmd, cf)
    f.rrect((x, 520 + dy3, x + w + 80, 610 + dy3), 22, INK, k2)
    f.text((x + 40, 565 + dy3), cmd, cf, PAPER, k2, bg=mix(PAPER, INK, k2), anchor="lm")
    k3, _ = appear(t, 1.5)
    f.text((W / 2, 760), "Impossible is just unbuilt.", SG(700, 48), GOLD7, k3, anchor="mm")
    f.text((W / 2, 826), "nickgeorgeai.com", JB(400, 36), MUTED, k3, anchor="mm")
    return f


SCENES = [(s_hook, 3.2, False), (s_gate, 5.2, True), (s_approve, 4.2, True),
          (s_denied, 3.6, True), (s_audit, 3.8, True), (s_end, 3.8, False)]


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
    subprocess.run(["ffmpeg", "-v", "error", "-y", "-framerate", str(FPS), "-i", str(frames / "%04d.png"),
                    "-vf", "split[a][b];[a]palettegen=max_colors=64:stats_mode=full[p];[b][p]paletteuse=dither=none",
                    "-loop", "0", str(OUT / "explainer.gif")], check=True)


if __name__ == "__main__":
    main()
