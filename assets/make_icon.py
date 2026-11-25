#!/usr/bin/env python3
"""Draw the tray icon for trans-proxier and write a multi-size .ico.

Done in code rather than generated because a tray glyph has to survive 16x16: the
shapes below are drawn at 8x supersample and area-averaged, so edges stay clean and
the result is reproducible from this file alone (no binary asset to lose).

Concept: a slate shield (the interception layer) with a cyan arrow crossing it and a
dashed seam at the middle (traffic handed to a proxy hop). Two colours, no gradient,
no text - matching the industrial look of the rest of the UI.
"""
import math
import os
import struct
import sys

SS = 8                       # supersample factor
SIZES = [16, 20, 24, 32, 48, 64, 128, 256]
SLATE = (74, 85, 104)        # #4A5568 outline
CYAN = (61, 169, 252)        # #3DA9FC arrow


def inside_poly(x, y, pts):
    n = len(pts)
    hit = False
    for i in range(n):
        x1, y1 = pts[i]
        x2, y2 = pts[(i + 1) % n]
        if (y1 > y) != (y2 > y):
            xt = x1 + (y - y1) * (x2 - x1) / (y2 - y1)
            if x < xt:
                hit = not hit
    return hit


def shield(cx, cy, r, squash=1.12):
    """Rounded hexagon: a pointed-top shield, slightly taller than wide."""
    pts = []
    steps = 6
    corners = [
        (0.0, -1.0), (0.87, -0.5), (0.87, 0.42),
        (0.0, 1.0), (-0.87, 0.42), (-0.87, -0.5),
    ]
    for i in range(len(corners)):
        ax, ay = corners[i]
        bx, by = corners[(i + 1) % len(corners)]
        for s in range(steps):
            t = s / steps
            pts.append((cx + r * (ax + (bx - ax) * t), cy + r * squash * (ay + (by - ay) * t)))
    return pts


def seg_dist(px, py, ax, ay, bx, by):
    vx, vy = bx - ax, by - ay
    wx, wy = px - ax, py - ay
    L2 = vx * vx + vy * vy
    t = 0.0 if L2 == 0 else max(0.0, min(1.0, (wx * vx + wy * vy) / L2))
    return math.hypot(wx - t * vx, wy - t * vy)


def sample(u, v):
    """u,v in [0,1). Return (r,g,b,a) with a in 0..255."""
    x, y = (u - 0.5) * 2.0, (v - 0.5) * 2.0
    transparent = (0, 0, 0, 0)

    # margins: the glyph occupies ~82% so taskbar padding looks right
    r = 0.82
    outer = shield(0.0, 0.0, r)
    inner = shield(0.0, 0.0, r * 0.80)
    in_outer = inside_poly(x, y, outer)
    in_inner = inside_poly(x, y, inner)
    ring = in_outer and not in_inner          # the shield outline
    if not (ring or in_inner):
        return transparent

    col = None
    # dashed seam down the middle: the proxy hop
    band = 0.075 * r
    if abs(x) < band and in_inner:
        dash = (int((y + 1.0) / (0.19 * r)) % 2) == 0
        if dash:
            col = SLATE
    # arrow through the shield
    shaft = 0.085 * r
    y0 = -0.02 * r
    if in_inner:
        if abs(y - y0) <= shaft and -0.62 * r <= x <= 0.30 * r:
            col = CYAN
        else:
            # head: two strokes meeting at the tip
            tipx, tipy = 0.60 * r, y0
            d1 = seg_dist(x, y, 0.24 * r, y0 - 0.26 * r, tipx, tipy)
            d2 = seg_dist(x, y, 0.24 * r, y0 + 0.26 * r, tipx, tipy)
            if min(d1, d2) <= shaft:
                col = CYAN
    if col is None:
        col = SLATE if ring else None
    if col is None:
        return transparent if not ring else (SLATE[0], SLATE[1], SLATE[2], 255)
    if ring:
        col = SLATE
    return (col[0], col[1], col[2], 255)


def render(size):
    """Area-averaged RGBA rows, top-down (matching a negative-height BI_RGB DIB)."""
    n = size * SS
    grid = [[sample((i + 0.5) / n, (j + 0.5) / n) for i in range(n)] for j in range(n)]
    out = []
    w = 1.0 / (SS * SS)
    for by in range(size):
        row = []
        for bx in range(size):
            ar = ag = ab = aa = 0.0
            for j in range(by * SS, (by + 1) * SS):
                for i in range(bx * SS, (bx + 1) * SS):
                    r, g, b, a = grid[j][i]
                    ar += r * a * w
                    ag += g * a * w
                    ab += b * a * w
                    aa += a * w
            if aa <= 0.5:
                row.append((0, 0, 0, 0))
            else:
                row.append((int(ar / aa), int(ag / aa), int(ab / aa), int(min(255.0, aa))))
        out.append(row)
    return out


def dib(size):
    """32-bit BGRA DIB, bottom-up rows plus the all-zero AND mask."""
    rows = render(size)
    px = bytearray()
    for row in reversed(rows):                 # bottom-up
        for r, g, b, a in row:
            # straight (not premultiplied) alpha, which is what the icon loader expects
            px += struct.pack("<BBBB", b, g, r, a)
    mask_row = ((size + 31) // 32) * 4
    hdr = struct.pack("<IiiHHIIiiII", 40, size, size * 2, 1, 32, 0,
                      len(px) + mask_row * size, 0, 0, 0, 0)
    return hdr + bytes(px) + bytes(mask_row * size)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "assets/tray.ico"
    os.makedirs(os.path.dirname(out), exist_ok=True)
    entries = [(s, dib(s)) for s in SIZES]
    n = len(entries)
    blob = bytearray(struct.pack("<HHH", 0, 1, n))
    offset = 6 + 16 * n
    data = bytearray()
    for s, body in entries:
        w = 0 if s >= 256 else s
        h = 0 if s >= 256 else s
        blob += struct.pack("<BBBBHHII", w, h, 0, 0, 1, 32, len(body), offset)
        data += body
        offset += len(body)
    with open(out, "wb") as f:
        f.write(bytes(blob) + bytes(data))
    print("wrote %s with sizes %s (%d bytes)" % (out, SIZES, os.path.getsize(out)))


if __name__ == "__main__":
    main()
