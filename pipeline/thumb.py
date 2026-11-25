"""トップページのスライド用の画像を作る（動画サムネイル風）。

横長（1600x600、パソコン向け）と 16:9（1280x720、スマホ向け）の2種類を作る。

絵は製品の種類ごとの線画をその場で描く。写真や外部の素材、AIの画像生成は使わない。
文字は事実データの値（深刻度、CVE番号、製品名）だけ。Pillow が無ければ何もしない。
"""
import os

SIZES = {"wide": (1600, 600), "tall": (1280, 720)}  # 名前: (幅, 高さ)
SEV_COL = {"critical": (226, 28, 58), "high": (240, 120, 0), "medium": (200, 150, 0),
           "low": (40, 150, 95), "none": (110, 124, 150)}
YELLOW = (255, 214, 0)
LINE_H = 1.16
FONTS_JP = (
    "/usr/share/fonts/opentype/noto/NotoSansCJK-Bold.ttc",
    "/usr/share/fonts/noto-cjk/NotoSansCJK-Bold.ttc",
    "/usr/share/fonts/truetype/noto/NotoSansCJK-Bold.ttc",
    "/System/Library/Fonts/ヒラギノ角ゴシック W6.ttc",
    "C:/Windows/Fonts/YuGothB.ttc",
    "C:/Windows/Fonts/meiryob.ttc",
)


def _font_path():
    return next((p for p in FONTS_JP if os.path.exists(p)), None)


class _Pen:
    """24x24の升目で指定した線画を、位置と倍率を変えて描く。"""

    def __init__(self, d, ox, oy, s, w, col):
        self.d, self.ox, self.oy, self.s, self.w, self.col = d, ox, oy, s, w, col

    def _p(self, x, y):
        return (self.ox + x * self.s, self.oy + y * self.s)

    def line(self, *pts, close=False):
        ps = [self._p(x, y) for x, y in pts]
        if close:
            ps.append(ps[0])
        self.d.line(ps, fill=self.col, width=self.w, joint="curve")
        r = self.w / 2
        for x, y in ps:  # 線の端と角を丸くする
            self.d.ellipse([x - r, y - r, x + r, y + r], fill=self.col)

    def rrect(self, x0, y0, x1, y1, r=2):
        self.d.rounded_rectangle([*self._p(x0, y0), *self._p(x1, y1)], r * self.s, outline=self.col, width=self.w)

    def ell(self, x0, y0, x1, y1):
        self.d.ellipse([*self._p(x0, y0), *self._p(x1, y1)], outline=self.col, width=self.w)

    def arc(self, x0, y0, x1, y1, a0, a1):
        self.d.arc([*self._p(x0, y0), *self._p(x1, y1)], a0, a1, fill=self.col, width=self.w)

    def dot(self, x, y):
        cx, cy = self._p(x, y)
        r = self.w * 0.8
        self.d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=self.col)


def _draw_kind(p, kind):
    if kind == "os":
        p.rrect(3, 4, 21, 16); p.line((8, 20), (16, 20)); p.line((12, 16), (12, 20))
    elif kind == "server":
        p.rrect(3, 4, 21, 11, 1.5); p.rrect(3, 13, 21, 20, 1.5)
        p.dot(7, 7.5); p.dot(7, 16.5); p.line((11, 7.5), (17, 7.5)); p.line((11, 16.5), (17, 16.5))
    elif kind == "network":
        p.rrect(3, 14, 21, 21); p.dot(7, 17.5); p.dot(11, 17.5); p.line((12, 14), (12, 10))
        p.arc(8, 6, 16, 14, 215, 325); p.arc(5, 2.5, 19, 16.5, 222, 318)
    elif kind == "security":
        p.line((12, 3), (20, 6), (20, 12), (17.6, 17.4), (12, 21), (6.4, 17.4), (4, 12), (4, 6), close=True)
        p.line((9, 12), (11, 14), (15, 10))
    elif kind == "nas":
        p.rrect(5, 3, 19, 21); p.line((9, 8), (15, 8)); p.line((9, 12), (15, 12)); p.dot(12, 17)
    elif kind == "cloud":
        p.arc(2.5, 10, 10.5, 18, 90, 262); p.arc(6, 3.5, 18, 15.5, 188, 352)
        p.arc(13.2, 9.4, 21.8, 18, 280, 90); p.line((6.5, 18), (17.5, 18))
    elif kind == "web":
        p.ell(3, 3, 21, 21); p.line((3, 12), (21, 12)); p.ell(8.2, 3, 15.8, 21)
    elif kind == "db":
        p.ell(4, 3, 20, 9); p.line((4, 6), (4, 18)); p.line((20, 6), (20, 18))
        p.arc(4, 9, 20, 15, 0, 180); p.arc(4, 15, 20, 21, 0, 180)
    elif kind == "dev":
        p.line((8, 7), (3, 12), (8, 17)); p.line((16, 7), (21, 12), (16, 17)); p.line((13.5, 5), (10.5, 19))
    elif kind == "ai":
        p.rrect(6, 6, 18, 18); p.rrect(10, 10, 14, 14, 0.5)
        for a in (9, 15):
            p.line((a, 2), (a, 6)); p.line((a, 18), (a, 22)); p.line((2, a), (6, a)); p.line((18, a), (22, a))
    elif kind == "auth":
        p.ell(4, 11, 12, 19); p.line((10.8, 12.2), (20, 3)); p.line((17, 6), (20, 9)); p.line((14, 9), (16, 11))
    elif kind == "mail":
        p.rrect(3, 5, 21, 19); p.line((3.6, 7.4), (12, 13), (20.4, 7.4))
    elif kind == "browser":
        p.rrect(3, 4, 21, 20); p.line((3, 9), (21, 9)); p.dot(6.5, 6.5); p.dot(9.5, 6.5)
    elif kind == "lib":
        p.line((12, 3), (21, 8), (12, 13), (3, 8), close=True)
        p.line((3, 12), (12, 17), (21, 12)); p.line((3, 16), (12, 21), (21, 16))
    else:  # app
        p.line((12, 3), (20, 7.5), (20, 16.5), (12, 21), (4, 16.5), (4, 7.5), close=True)
        p.line((4, 7.5), (12, 12), (20, 7.5)); p.line((12, 12), (12, 21))


def _wrap(d, text, font_at, max_w, max_h, sizes, max_lines=3):
    """幅と高さに収まる最大の文字サイズと行分けを選ぶ。収まらなければ最小サイズで末尾を省く。"""
    words = text.split(" ")
    for size in sizes:
        f = font_at(size)
        lines, cur = [], ""
        for wd in words:
            t = (cur + " " + wd).strip()
            if d.textlength(t, font=f) <= max_w:
                cur = t
                continue
            if cur:
                lines.append(cur)
            cur = ""
            for ch in wd:  # 1語が長すぎる（日本語など）ときは文字単位で折る
                if d.textlength(cur + ch, font=f) > max_w:
                    lines.append(cur)
                    cur = ""
                cur += ch
        lines.append(cur)
        if len(lines) <= max_lines and len(lines) * size * LINE_H <= max_h:
            return f, lines
    lines = lines[:max(1, min(max_lines, int(max_h // (size * LINE_H))))]
    while lines[-1] and d.textlength(lines[-1] + "…", font=f) > max_w:
        lines[-1] = lines[-1][:-1]
    lines[-1] += "…"
    return f, lines


_BG = {}


def hero_image(path, shape, *, sev, kind, cve, badge, exploited, vendor, name, site):
    """1枚作って保存する。作れたら True。

    shape: wide（横長）か tall（16:9）
    sev: critical/high/…  kind: 絵の種類  badge: 「緊急 9.8」など  exploited: 悪用確認済みか
    vendor/name: 開発元と製品名（name は必須。製品が不明な件は見出しを渡す）
    """
    try:
        from PIL import Image, ImageDraw, ImageFilter, ImageFont
    except ImportError:
        return False
    fp = _font_path()
    if not fp:
        return False  # 日本語の太字フォントが無い環境では作らない（文字が出ないため）
    cache = {}

    def font_at(size):
        if size not in cache:
            cache[size] = ImageFont.truetype(fp, size)
        return cache[size]

    W, H = SIZES[shape]
    wide = shape == "wide"
    # 右側の絵の大きさと位置（24升の線画を size 倍する）
    size = 17.5
    pic = int(24 * size)
    ox = W - pic - (150 if wide else 60)
    oy = (H - pic) // 2
    cx, cy = ox + pic // 2, oy + pic // 2
    col = SEV_COL.get(sev, SEV_COL["none"])
    # 背景: 濃紺の縦グラデーション + 右側に深刻度の色の光
    if (shape, sev) not in _BG:
        bg = Image.new("RGB", (1, 2))
        bg.putpixel((0, 0), (20, 32, 56))
        bg.putpixel((0, 1), (6, 10, 20))
        bg = bg.resize((W, H), Image.BILINEAR)
        glow = Image.new("RGB", (W, H), (0, 0, 0))
        gd = ImageDraw.Draw(glow)
        gd.ellipse([cx - 300, cy - 300, cx + 300, cy + 300], fill=tuple(int(c * 0.75) for c in col))
        gd.polygon([(0, H), (0, H - 150), (520, H)], fill=tuple(int(c * 0.5) for c in col))
        glow = glow.filter(ImageFilter.GaussianBlur(110))
        _BG[(shape, sev)] = Image.composite(glow, bg, glow.convert("L").point(lambda v: min(255, int(v * 1.6))))
    img = _BG[(shape, sev)].copy()
    d = ImageDraw.Draw(img, "RGBA")
    for x in range(0, W, 64):
        d.line([(x, 0), (x, H)], fill=(255, 255, 255, 12))
    for y in range(0, H, 64):
        d.line([(0, y), (W, y)], fill=(255, 255, 255, 12))
    d.rectangle([0, 0, W, 14], fill=col + (255,))

    # 右側の絵（影つき）
    _draw_kind(_Pen(d, ox + 6, oy + 8, size, 22, (0, 0, 0, 110)), kind)
    _draw_kind(_Pen(d, ox, oy, size, 22, (255, 255, 255, 255)), kind)

    # 左上: 深刻度と悪用確認の札
    x, y = 64, (48 if wide else 64)
    fb = font_at(62)
    if badge:
        w = d.textlength(badge, font=fb)
        d.rounded_rectangle([x, y, x + w + 56, y + 96], 14, fill=col + (255,))
        d.text((x + 28, y + 48), badge, font=fb, fill=(255, 255, 255), anchor="lm")
        x += w + 56 + 20
    if exploited:
        w = d.textlength("悪用確認", font=fb)
        d.rounded_rectangle([x, y, x + w + 56, y + 96], 14, fill=YELLOW + (255,))
        d.text((x + 28, y + 48), "悪用確認", font=fb, fill=(16, 16, 16), anchor="lm")

    # 中央: 開発元（小）と製品名（大、黒フチ）
    y += 96 + (30 if wide else 40)
    bottom = H - (140 if wide else 232)  # 製品名を書ける下の限界
    if vendor:
        d.text((66, y), vendor, font=font_at(44), fill=(200, 212, 232), stroke_width=3, stroke_fill=(0, 0, 0))
        y += 62
    f, lines = _wrap(d, name, font_at, ox - 64 - 50, bottom - y, (124, 108, 94, 82, 72, 64, 56))
    for ln in lines:
        d.text((64, y), ln, font=f, fill=(255, 255, 255), stroke_width=7, stroke_fill=(0, 0, 0))
        y += int(f.size * LINE_H)

    # 下: 「脆弱性」とCVE番号（横長では1行に並べる）、右下にサイト名
    fv, fc = font_at(64), font_at(58)
    if name == cve:  # CVE番号を上に大きく出した場合は、下には繰り返さない
        d.text((64, H - 52 if wide else H - 60), "脆弱性", font=fv, fill=YELLOW, stroke_width=5, stroke_fill=(0, 0, 0), anchor="ls")
    elif wide:
        d.text((64, H - 52), "脆弱性", font=fv, fill=YELLOW, stroke_width=5, stroke_fill=(0, 0, 0), anchor="ls")
        d.text((64 + d.textlength("脆弱性", font=fv) + 36, H - 52), cve, font=fc, fill=(255, 255, 255),
               stroke_width=5, stroke_fill=(0, 0, 0), anchor="ls")
    else:
        d.text((64, H - 150), "脆弱性", font=fv, fill=YELLOW, stroke_width=5, stroke_fill=(0, 0, 0), anchor="ls")
        d.text((64, H - 60), cve, font=fc, fill=(255, 255, 255), stroke_width=5, stroke_fill=(0, 0, 0), anchor="ls")
    d.text((W - 48, H - 44), site, font=font_at(30), fill=(190, 202, 224), anchor="rs")
    img.save(path, "JPEG", quality=86, optimize=True)
    return True
