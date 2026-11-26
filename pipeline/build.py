"""保存データから静的サイトを生成する。出力先は public/。"""
import html
import json
import os
import re
import shutil
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from . import aifeed, insights, thumb
from .store import sev_ja

JST = timezone(timedelta(hours=9))
E = html.escape


def dt(s):
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def jst(s, fmt="%Y-%m-%d %H:%M"):
    return dt(s).astimezone(JST).strftime(fmt)


def slug(p):
    s = re.sub(r"[^a-z0-9]+", "-", f"{p['vendor']} {p['product']}".lower()).strip("-")
    return s or "other"


# 製品別の一覧に出す、種類ごとのアイコン（24x24の線画）。各社のロゴは使わない。
ICONS = {
    "ai": ("AI", '<rect x="6" y="6" width="12" height="12" rx="2"/><rect x="10" y="10" width="4" height="4"/><path d="M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4"/>'),
    "auth": ("認証", '<circle cx="8" cy="15" r="4"/><path d="M10.8 12.2 20 3M17 6l3 3M14 9l2 2"/>'),
    "mail": ("メール", '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3 7 9 6 9-6"/>'),
    "browser": ("ブラウザ", '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 9h18M6.5 6.5h.01M9.5 6.5h.01"/>'),
    "security": ("セキュリティ製品", '<path d="m12 3 8 3v6c0 4.5-3.4 8-8 9-4.6-1-8-4.5-8-9V6z"/><path d="m9 12 2 2 4-4"/>'),
    "nas": ("ストレージ", '<rect x="5" y="3" width="14" height="18" rx="2"/><path d="M9 8h6M9 12h6M12 17h.01"/>'),
    "network": ("ネットワーク機器", '<rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 16.5h.01M11 16.5h.01M12 13V9M8.5 6.5a5 5 0 0 1 7 0"/>'),
    "cloud": ("クラウド・仮想化", '<path d="M7 18a4 4 0 0 1-.5-8A6 6 0 0 1 18 9.5a4.3 4.3 0 0 1-.5 8.5z"/>'),
    "web": ("Web・業務アプリ", '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.7 3.8 5.7 3.8 9s-1.3 6.3-3.8 9c-2.5-2.7-3.8-5.7-3.8-9S9.5 5.7 12 3z"/>'),
    "db": ("データベース", '<ellipse cx="12" cy="6" rx="8" ry="3"/><path d="M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>'),
    "dev": ("開発・運用ツール", '<path d="m8 7-5 5 5 5M16 7l5 5-5 5M13.5 5l-3 14"/>'),
    "server": ("サーバー", '<rect x="3" y="4" width="18" height="7" rx="1.5"/><rect x="3" y="13" width="18" height="7" rx="1.5"/><path d="M7 7.500h.01M7 16.500h.01"/>'),
    "os": ("OS", '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>'),
    "lib": ("ライブラリ", '<path d="m12 3 9 5-9 5-9-5zM3 12l9 5 9-5M3 16l9 5 9-5"/>'),
    "app": ("ソフトウェア", '<path d="m12 3 8 4.500v9L12 21l-8-4.500v-9z"/><path d="m4 7.5 8 4.5 8-4.500M12 12v9"/>'),
}
# 上から順に試し、最初に合った種類にする（「開発元 製品名」を小文字にして照合）
ICON_RULES = [
    ("ai", r"\bai\b|\bllm|litellm|monai|lightspeed|ollama|langchain"),
    ("auth", r"keycloak|sign-on|\bsso\b|identity|active directory|ldap"),
    ("mail", r"mail|exchange|postfix|outlook|zimbra"),
    ("browser", r"chrome|chromium|firefox|\bedge\b|safari|webkit"),
    ("security", r"checkpoint|check point|forti|palo ?alto|pan-os|sonicwall|sophos|ivanti|firewall|vpn|security|antivirus|defender"),
    ("nas", r"synology|qnap|diskstation|\bnas\b|storage|backup"),
    ("network", r"cisco|juniper|zyxel|tp-link|d-link|netgear|mikrotik|ubiquiti|router|switch|gateway"),
    ("cloud", r"vmware|vcenter|esxi|openshift|kubernetes|docker|cloud|hyper-v|citrix|\bxen"),
    ("web", r"sharepoint|wordpress|drupal|joomla|roller|portal|\bweb|nginx|http server|tomcat|redcap|\bcms\b|confluence"),
    ("db", r"mysql|mariadb|postgres|database|redis|mongodb|\bsql|elasticsearch"),
    ("dev", r"teamcity|jenkins|gitlab|github|\bgit\b|puppet|ansible|virtualenv|jetbrains|visual studio|\bnpm\b|\bpip\b"),
    ("server", r"\bserver\b|jboss|application platform|syslog|ircd"),
    ("os", r"windows|linux|macos|\bios\b|ipados|android|ubuntu|debian|\bos\b"),
    ("lib", r"\blib|axis|openssl|csrf|\bsdk\b|library|log4j"),
]


def icon_kind(text):
    """文字列（開発元と製品名など）から種類を決める。どの規則にも合わなければ app。"""
    key = text.lower()
    return next((k for k, pat in ICON_RULES if re.search(pat, key)), "app")


def prod_icon(p):
    """製品の種類を表すアイコン（インラインSVG）。どの規則にも合わなければ箱の絵にする。"""
    label, body = ICONS[icon_kind(f"{p['vendor']} {p['product']}")]
    return f'<svg class="pico" viewBox="0 0 24 24" aria-hidden="true"><title>{label}</title>{body}</svg>'


def sev_class(it):
    c = it["facts"].get("cvss")
    return (c["severity"].lower() if c and c.get("severity") else "none")


def chips(it):
    f = it["facts"]
    out = []
    c = f.get("cvss")
    if c:
        out.append(f'<span class="chip sev">{sev_ja(c["severity"])} <b>{c["score"]}</b></span>')
    else:
        out.append('<span class="chip">未評価</span>')
    if f.get("kev"):
        out.append('<span class="chip kev">悪用確認</span>')
        if f["kev"].get("ransomware"):
            out.append('<span class="chip kev">ランサム悪用</span>')
    e = f.get("epss")
    if e and e["score"] >= 0.1:
        out.append(f'<span class="chip">悪用確率 {e["score"] * 100:.0f}%</span>')
    n = sum(1 for t in it["timeline"] if t["kind"] == "update")
    if n:
        out.append(f'<span class="chip upd">追記 {n}回</span>')
    return "".join(out)


def card(it, pre):
    f, s = it["facts"], it["summary"]
    prods = " ".join(p["product"] for p in f.get("products") or [])
    flags = " ".join(filter(None, [
        sev_class(it), "kev" if f.get("kev") else "",
        "upd" if len(it["timeline"]) > 1 else ""]))
    last = it["timeline"][-1]
    note = ""
    if last["kind"] == "update":
        note = f'<p class="note"><b>追記</b> {E(last["changes"][0])}</p>'
    # 対象製品（先頭の1つ）をアイコンつきで出す。カード全体がリンクなので、ここはリンクにしない
    ps = f.get("products") or []
    prod = ""
    if ps:
        more = f'<small>ほか{len(ps) - 1}製品</small>' if len(ps) > 1 else ""
        prod = f'<p class="prod">{prod_icon(ps[0])}<span>{E(ps[0]["vendor"])} {E(ps[0]["product"])}</span>{more}</p>'
    return f'''<article class="card s-{sev_class(it)}" data-flags="{flags}" data-text="{E((it["id"] + " " + s["title"] + " " + prods).lower())}">
<a class="card-link" href="{pre}v/{it["id"]}.html">
<div class="meta"><span class="id">{it["id"]}</span><time datetime="{it["updated"]}">{jst(it["updated"])}</time></div>
{prod}<h2>{E(s["title"])}</h2>
<p class="lead">{E(s["summary"])}</p>
{note}
<div class="chips">{chips(it)}</div>
</a></article>'''


def ad(cfg, slot_key, label="広告"):
    a = cfg.get("ads", {})
    if a.get("adsense_client") and a.get(slot_key):
        return f'''<aside class="ad" aria-label="広告"><ins class="adsbygoogle" style="display:block" data-ad-client="{E(a["adsense_client"])}" data-ad-slot="{E(a[slot_key])}" data-ad-format="auto" data-full-width-responsive="true"></ins><script>(adsbygoogle=window.adsbygoogle||[]).push({{}});</script></aside>'''
    if cfg.get("demo"):
        return f'<aside class="ad placeholder" aria-label="広告">{label}枠（設定すると表示されます）</aside>'
    return ""


def sponsor(cfg, pre):
    sp, pay = cfg.get("sponsor", {}), cfg.get("payments", {})
    if not sp.get("enabled"):
        return ""
    if sp.get("name") and sp.get("url"):
        return f'<aside class="sponsor"><span class="pr">スポンサー</span><a href="{E(sp["url"])}" rel="sponsored noopener">{E(sp["name"])}</a><span>{E(sp.get("text", ""))}</span></aside>'
    if pay.get("sponsor_link"):
        return f'<aside class="sponsor"><span class="pr">スポンサー募集</span><span>この枠に社名とリンクを掲載できます（{E(pay.get("sponsor_price", ""))}）。</span><a href="{pre}support.html">申し込む</a></aside>'
    return ""


def affiliate(cfg, it):
    text = (it["summary"]["title"] + " " + " ".join(
        f'{p["vendor"]} {p["product"]}' for p in it["facts"].get("products") or [])).lower()
    hits = [a for a in cfg.get("affiliate", [])
            if a.get("url") and any(k.lower() in text for k in a.get("match", []))]
    if not hits:
        hits = [a for a in cfg.get("affiliate", []) if a.get("url") and a.get("default")]
    if not hits:
        return ""
    rows = "".join(
        f'<li><a href="{E(a["url"])}" rel="sponsored nofollow noopener">{E(a["title"])}</a><span>{E(a.get("text", ""))}</span></li>'
        for a in hits[:2])
    return f'<aside class="aff"><span class="pr">PR</span><h3>対策に役立つ製品・サービス</h3><ul>{rows}</ul><p class="fine">このリンクから申し込むと、当サイトに紹介料が入ることがあります。記事の内容は紹介料の影響を受けません。</p></aside>'


def alerts_on(cfg):
    """メール通知を案内・送信するか（config の alerts.enabled。未設定なら出さない）。"""
    return bool(cfg.get("alerts", {}).get("enabled"))


def alert_cta(cfg, pre, product=None):
    if not alerts_on(cfg):
        return ""
    pay = cfg.get("payments", {})
    target = f"{E(product)} の" if product else "使っている製品の"
    return f'''<aside class="cta"><h3>{target}脆弱性だけを、メールで受け取る</h3>
<p>製品名を登録すると、新着と追記を1時間以内にお知らせします。{E(pay.get("alert_price", ""))}</p>
<a class="btn" href="{pre}alerts.html">通知を申し込む</a></aside>'''


def page(cfg, pre, title, body, desc="", canonical="", og="", jsonld="", extra_head=""):
    name = cfg["site_name"]
    # トップは検索結果で内容が伝わるよう、サイト名に見出しを添える
    full = f"{title} | {name}" if title != name else " | ".join(filter(None, [name, cfg.get("headline")]))
    og_type = "article" if canonical.startswith("v/") else "website"
    url = cfg["site_url"].rstrip("/") + "/" + canonical
    ads = cfg.get("ads", {}).get("adsense_client")
    adsense = f'<script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client={E(ads)}" crossorigin="anonymous"></script>' if ads else ""
    ogimg = f'<meta property="og:image" content="{cfg["site_url"].rstrip("/")}/{og}"><meta name="twitter:card" content="summary_large_image">' if og else '<meta name="twitter:card" content="summary">'
    gsv = cfg.get("google_site_verification")  # Search Console の所有権確認用
    verify = f'<meta name="google-site-verification" content="{E(gsv)}">' if gsv else ""
    nav_alerts = f'<a href="{pre}alerts.html">メール通知</a>' if alerts_on(cfg) else ""
    demo = '<div class="demo">サンプルデータで表示しています。製品名とCVE番号は架空のものです。</div>' if cfg.get("demo") else ""
    return f'''<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="max-image-preview:large">{verify}
<title>{E(full)}</title>
<meta name="description" content="{E(desc[:150])}">
<link rel="canonical" href="{E(url)}">
<meta property="og:title" content="{E(title)}"><meta property="og:description" content="{E(desc[:150])}">
<meta property="og:type" content="{og_type}"><meta property="og:url" content="{E(url)}"><meta property="og:site_name" content="{E(name)}">
{ogimg}
<link rel="alternate" type="application/rss+xml" title="{E(name)}" href="{pre}feed.xml">
<link rel="alternate" type="text/plain" title="AI向けの案内（llms.txt）" href="{pre}llms.txt">
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@500;600&family=IBM+Plex+Sans+JP:wght@400;500;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="{pre}static/style.css">
{extra_head}{jsonld}{adsense}
</head>
<body>
{demo}
<header class="top"><div class="wrap">
<a class="brand" href="{pre}index.html"><span class="pulse" aria-hidden="true"></span>{E(name)}</a>
<nav><a href="{pre}index.html">新着</a><a href="{pre}products.html">製品別</a><a href="{pre}insights.html">分析</a><a href="{pre}ai.html">AIで使う</a>{nav_alerts}<a href="{pre}about.html">編集方針</a></nav>
</div></header>
<main class="wrap">
{body}
</main>
<footer class="foot"><div class="wrap">
<p>{E(cfg.get("tagline", ""))}</p>
<p><a href="{pre}about.html">編集方針と出典</a><a href="{pre}support.html">{"支援・スポンサー" if cfg.get("sponsor", {}).get("enabled") else "寄付"}</a><a href="{pre}tokushoho.html">特定商取引法に基づく表記</a><a href="{pre}feed.xml">RSS</a><a href="{pre}llms.txt">llms.txt</a></p>
<p class="fine">要約は公開情報をもとに自動生成しています。対応の判断は必ず出典の原文で確認してください。</p>
</div></footer>
<script src="{pre}static/app.js" defer></script>
</body>
</html>'''


def list_block(items, pre, cfg, with_filters=True):
    filt = '''<div class="tools">
<div class="filters" role="group" aria-label="絞り込み">
<button type="button" class="on" data-f="">すべて</button>
<button type="button" data-f="critical">緊急</button>
<button type="button" data-f="kev">悪用確認</button>
<button type="button" data-f="upd">追記あり</button>
</div>
<input id="q" type="search" placeholder="製品名やCVE番号で絞り込む" aria-label="製品名やCVE番号で絞り込む">
</div>''' if with_filters else ""
    cards = []
    for i, it in enumerate(items):
        cards.append(card(it, pre))
        if i == 3:
            cards.append(ad(cfg, "slot_list"))
    empty = '<p id="empty" hidden>条件に合う記事がありません。絞り込みを解除してください。</p>'
    return f'{filt}<div class="list" id="list">{"".join(cards)}</div>{empty}'


def item_page(cfg, it):
    pre = "../"
    f, s = it["facts"], it["summary"]
    c, kev, e, jv = f.get("cvss"), f.get("kev"), f.get("epss"), f.get("jvn")
    url = f'{cfg["site_url"].rstrip("/")}/v/{it["id"]}.html'
    rows = []
    if c:
        rows.append(("深刻度（CVSS v" + c["version"] + "）", f'{sev_ja(c["severity"])} {c["score"]}<br><code>{E(c["vector"])}</code>'))
    else:
        rows.append(("深刻度", "まだ評価されていません"))
    if kev:
        rows.append(("実際の攻撃での悪用", f'確認済み（CISA KEV、{E(kev["added"])} 追加）' + (f'<br>米政府機関の対応期限 {E(kev["due"])}' if kev.get("due") else "")))
    else:
        rows.append(("実際の攻撃での悪用", "CISA KEVには未掲載"))
    if e:
        rows.append(("30日以内に悪用される確率（EPSS）", f'{e["score"] * 100:.1f}%（全体の上位 {max(0.1, (1 - e["percentile"]) * 100):.1f}%）'))
    if f.get("cwe"):
        rows.append(("問題の種類", E("、".join(f["cwe"]))))
    if f.get("published"):
        rows.append(("CVE公開日", E(f["published"][:10])))
    table = "".join(f"<tr><th>{k}</th><td>{v}</td></tr>" for k, v in rows)

    tl = "".join(
        f'<li class="{t["kind"]}"><time datetime="{t["at"]}">{jst(t["at"])}</time><div>{"".join("<p>" + E(x) + "</p>" for x in t["changes"])}</div></li>'
        for t in reversed(it["timeline"]))

    prods = "".join(f'<a class="tag" href="{pre}p/{slug(p)}.html">{E(p["product"])}</a>' for p in f.get("products") or [])
    srcs = [f'<li><a href="https://nvd.nist.gov/vuln/detail/{it["id"]}" rel="noopener">NVD: {it["id"]}</a></li>']
    if jv:
        srcs.append(f'<li><a href="{E(jv["url"])}" rel="noopener">JVN iPedia: {E(jv["id"])}</a></li>')
    if kev:
        srcs.append('<li><a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" rel="noopener">CISA 悪用が確認された脆弱性の一覧（KEV）</a></li>')
    for u in (f.get("refs") or [])[:8]:
        srcs.append(f'<li><a href="{E(u)}" rel="noopener nofollow">{E(u)}</a></li>')

    share_text = quote(f'{s["title"]}（{it["id"]}）')
    share = f'''<div class="share" aria-label="共有">
<a href="https://twitter.com/intent/tweet?text={share_text}&url={quote(url, safe="")}" rel="noopener">Xで共有</a>
<a href="https://b.hatena.ne.jp/entry/panel/?url={quote(url, safe="")}" rel="noopener">はてなブックマーク</a>
<a href="https://social-plugins.line.me/lineit/share?url={quote(url, safe="")}" rel="noopener">LINEで送る</a>
<button type="button" id="copy" data-url="{E(url)}">リンクをコピー</button>
</div>'''
    first_prod = (f.get("products") or [{}])[0].get("product")
    ai_note = "AIが出典から要約し、数値を機械照合しています。" if s.get("ai") else "定型文による自動要約です。"
    orig = f'<details><summary>公式の説明（英語の原文）</summary><p lang="en">{E(f["desc_en"])}</p></details>' if f.get("desc_en") else ""
    ld = {
        "@context": "https://schema.org", "@type": "TechArticle", "headline": s["title"],
        "datePublished": it["first_seen"], "dateModified": it["updated"], "inLanguage": "ja",
        "mainEntityOfPage": url, "description": s["summary"],
        "author": {"@type": "Organization", "name": cfg["site_name"]},
        "publisher": {"@type": "Organization", "name": cfg["site_name"]}}
    if it["id"] in cfg.get("_og", ()):
        ld["image"] = [f'{cfg["site_url"].rstrip("/")}/og/{it["id"]}.jpg']
    jsonld = '<script type="application/ld+json">' + json.dumps(ld, ensure_ascii=False) + "</script>"
    n_upd = sum(1 for t in it["timeline"] if t["kind"] == "update")
    body = f'''<article class="detail s-{sev_class(it)}">
<p class="crumbs"><a href="{pre}index.html">新着</a> / <span class="id">{it["id"]}</span></p>
<h1>{E(s["title"])}</h1>
<div class="chips">{chips(it)}</div>
<p class="times">掲載 <time datetime="{it["first_seen"]}">{jst(it["first_seen"])}</time>{f' ・ 最終追記 <time datetime="{it["updated"]}">{jst(it["updated"])}</time>' if n_upd else ''}</p>
{share}
<section class="points">
<div><h2>何が問題か</h2><p>{E(s["summary"])}</p></div>
<div><h2>悪用されると</h2><p>{E(s["impact"])}</p></div>
<div><h2>取るべき対応</h2><p>{E(s["action"])}</p></div>
</section>
<p class="fine">{ai_note}</p>
<section><h2>更新履歴</h2><ol class="timeline">{tl}</ol></section>
{alert_cta(cfg, pre, first_prod)}
<section><h2>指標</h2><div class="scroll"><table>{table}</table></div></section>
{f'<section><h2>対象製品</h2><div class="tags">{prods}</div></section>' if prods else ''}
{affiliate(cfg, it)}
<section><h2>出典</h2><ul class="src">{"".join(srcs)}</ul>{orig}</section>
{ad(cfg, "slot_article")}
{sponsor(cfg, pre)}
</article>'''
    og = f'og/{it["id"]}.jpg' if it["id"] in cfg.get("_og", ()) else ""
    return page(cfg, pre, f'{s["title"]}（{it["id"]}）', body, s["summary"], f'v/{it["id"]}.html', og, jsonld)


def rss(cfg, items, title, self_path):
    base = cfg["site_url"].rstrip("/")
    ents = []
    for it in items[:50]:
        last = it["timeline"][-1]
        pref = "【追記】" if last["kind"] == "update" else ""
        desc = it["summary"]["summary"] + (" 追記: " + " ".join(last["changes"]) if pref else "")
        pub = dt(it["updated"]).strftime("%a, %d %b %Y %H:%M:%S +0000")
        ents.append(f'<item><title>{E(pref + it["summary"]["title"])}（{it["id"]}）</title><link>{base}/v/{it["id"]}.html</link><guid isPermaLink="false">{it["id"]}-{len(it["timeline"])}</guid><pubDate>{pub}</pubDate><description>{E(desc)}</description></item>')
    return f'<?xml version="1.0" encoding="UTF-8"?>\n<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom"><channel><title>{E(title)}</title><link>{base}/</link><description>{E(cfg.get("tagline", ""))}</description><language>ja</language><atom:link href="{base}/{self_path}" rel="self" type="application/rss+xml"/>{"".join(ents)}</channel></rss>'


def slide_name(it):
    """スライドに大きく出す (開発元, 名前)。何の製品か分からない件は None。"""
    f = it["facts"]
    kev, ps = f.get("kev") or {}, f.get("products") or []
    if ps:
        return ps[0]["vendor"], ps[0]["product"]
    if kev.get("product"):
        return kev.get("vendor", ""), kev["product"]
    if it["summary"].get("ai") or f.get("jvn"):  # 製品情報は無いが、中身のある見出しがある
        return "", it["summary"]["title"]
    return None


def featured(ordered, n):
    """スライドに出す件。悪用確認済みか緊急（CVSS 9.0以上）のものを新しい順に n 件。
    3件に満たないときは、残りの新しい件で3件まで埋める。製品が分からない件は出さない。"""
    def hot(it):
        f = it["facts"]
        return bool(f.get("kev")) or ((f.get("cvss") or {}).get("score") or 0) >= 9.0
    pick, seen = [], set()
    # 悪用確認・緊急の件を先に選び、足りなければ残りで3件まで埋める。
    # 同じ製品が続くと同じ絵が並ぶので、製品ごとに1件だけにする。
    for want, limit in ((True, n), (False, min(n, 3))):
        for it in ordered:
            nm = slide_name(it)
            if len(pick) >= limit:
                break
            if nm and nm not in seen and hot(it) == want:
                seen.add(nm)
                pick.append(it)
    return pick[:n]


def thumb_args(cfg, it):
    """記事1件ぶんの、サムネイル風画像の材料。"""
    f = it["facts"]
    c, kev = f.get("cvss"), f.get("kev") or {}
    # 何の製品か分からない件は、CVE番号を大きく出す（「対象製品 の脆弱性」とは書かない）
    vendor, name = slide_name(it) or ("", it["id"])
    return dict(sev=sev_class(it), kind=icon_kind(f"{vendor} {name}"), cve=it["id"],
                badge=f'{sev_ja(c["severity"])} {c["score"]}' if c else "",
                exploited=bool(kev), vendor=vendor, name=name, site=cfg["site_name"])


def og_image(cfg, out, it):
    """共有用の画像（16:9、1280x720）。検索やSNSで記事の絵として使われる。作れたら True。"""
    return thumb.hero_image(os.path.join(out, "og", f'{it["id"]}.jpg'), "tall", **thumb_args(cfg, it))


def slides(cfg, out, ordered):
    """トップのスライド。画像を作れた件だけ並べる（Pillowやフォントが無ければ出さない）。"""
    n = cfg.get("hero", {}).get("count", 5)
    if n <= 0:
        return ""
    cells = []
    for it in featured(ordered, n):
        # スマホ向けの16:9は記事の共有用画像と同じもの。パソコン向けの横長だけここで作る
        if it["id"] not in cfg["_og"] and og_image(cfg, out, it):
            cfg["_og"].add(it["id"])
        if it["id"] not in cfg["_og"] or not thumb.hero_image(
                os.path.join(out, "hero", f'{it["id"]}.jpg'), "wide", **thumb_args(cfg, it)):
            continue
        a = thumb_args(cfg, it)
        badge, kev = a["badge"], a["exploited"]
        alt = " ".join(filter(None, [badge, "悪用確認" if kev else "", it["summary"]["title"], it["id"]]))
        lazy = ' loading="lazy"' if cells else ' fetchpriority="high"'
        (ww, wh), (tw, th) = thumb.SIZES["wide"], thumb.SIZES["tall"]
        cells.append(f'<a class="slide" href="v/{it["id"]}.html"><picture>'
                     f'<source media="(min-width: 720px)" srcset="hero/{it["id"]}.jpg" width="{ww}" height="{wh}">'
                     f'<img src="og/{it["id"]}.jpg" width="{tw}" height="{th}" alt="{E(alt)}"{lazy}></picture></a>')
    if not cells:
        return ""
    return f'''<section class="slides" aria-roledescription="carousel" aria-label="注目の脆弱性">
<div class="slides-track" id="slides" tabindex="0">{"".join(cells)}</div>
<div class="slides-nav" id="slides-nav" hidden><button type="button" data-d="-1" aria-label="前のスライド">‹</button><span class="dots"></span><button type="button" data-d="1" aria-label="次のスライド">›</button></div>
</section>'''


def ai_page(base):
    """「AIで使う」ページ。利用者がAIに渡す依頼文と、データの場所を案内する。"""
    ask = (f"{base}/llms.txt を読み、そこに書かれた手順に従って、このプロジェクトに関係する脆弱性があるか調べてください。"
           "依存関係のファイル、Dockerfile、使っているミドルウェアを対象にします。"
           "該当しそうな件は、CVE番号、深刻度、悪用確認の有無、該当すると考えた根拠、取るべき対応を表にまとめてください。"
           "判断できない件は「要確認」としてください。")
    rule = (f"依存関係を追加・更新するときは、{base}/llms.txt の手順で、"
            "その製品やライブラリに悪用確認済みまたは深刻度の高い脆弱性が出ていないか確認する。")
    chat = (f"{base}/api/recent.md を読んで、次の製品やライブラリに関係する脆弱性があれば教えてください。"
            "該当する件は、CVE番号、深刻度、取るべき対応をまとめてください。\n\n（ここに、使っている製品名とバージョンを書く）")

    def box(i, text, label):
        return (f'<div class="prompt"><pre id="ask{i}">{E(text)}</pre>'
                f'<button type="button" data-copy="ask{i}">{label}</button></div>')
    return f'''<h1>AIに読ませて、自分のプロジェクトを調べる</h1>
<p>このサイトのデータは、AIが読みやすい形でも公開しています。AIコーディングの道具に依頼文を渡すと、プロジェクトの依存関係や構成と照らし合わせて、関係のありそうな脆弱性を挙げてくれます。無料で、登録は要りません。</p>
<h2>1. プロジェクトを調べさせる</h2>
<p>Claude Code、Cursor、Codex、GitHub Copilot など、プロジェクトのファイルを読めるAIに、次の文をそのまま渡します。</p>
{box(1, ask, "依頼文をコピー")}
<h2>2. 依存関係を変えるたびに確認させる</h2>
<p>プロジェクトの指示ファイル（CLAUDE.md、AGENTS.md、.cursor/rules など）に次の1行を足しておくと、依存関係を触るときにAIが自分から確認します。</p>
{box(2, rule, "この1行をコピー")}
<h2>3. チャットのAIで調べる</h2>
<p>ChatGPT や Claude など、Webを読めるチャットでは、製品名を自分で書いて渡します。</p>
{box(3, chat, "依頼文をコピー")}
<h2>公開しているデータ</h2>
<ul class="bullets">
<li><a href="llms.txt">llms.txt</a> … AI向けの案内。データの場所、照合の手順、結果の扱い方</li>
<li><a href="api/vulns.jsonl">api/vulns.jsonl</a> … 直近{aifeed.DAYS}日に更新された件と悪用確認済みの件を、1行1件のJSONで</li>
<li><a href="api/recent.md">api/recent.md</a> … 悪用確認済みの件と新しい{aifeed.RECENT}件の、1件1行の一覧</li>
<li><a href="feed.xml">RSS</a> … 新着と追記。製品ごとのRSSは<a href="products.html">製品別の一覧</a>から</li>
</ul>
<p>データは1時間ごとに更新します。登録なしで、個人・業務を問わず読み込んで使えます。</p>
<h2>知っておいてほしいこと</h2>
<ul class="bullets">
<li>載っているのは、深刻度が高い件（CVSS 7.0以上）と、実際に悪用が確認された件だけです。「該当なし」は「安全」を意味しません。</li>
<li>ライブラリの検査は、npm audit、pip-audit、osv-scanner、Dependabot などの専用の道具と併用してください。このサイトが役立つのは、それらが見ないOS、ミドルウェア、ネットワーク機器、業務ソフトと、いま悪用されている件の把握です。</li>
<li>AIの判定は誤ることがあります。対応を決める前に、各記事の出典（NVD、開発元の案内）で影響するバージョンを確認してください。</li>
</ul>'''


def build(root, out, cfg, items, now):
    here = os.path.dirname(os.path.abspath(__file__))
    if os.path.exists(out):
        shutil.rmtree(out)
    for d in ("v", "p", "m", "og", "hero", "static"):
        os.makedirs(os.path.join(out, d))
    for fn in ("style.css", "app.js"):
        shutil.copy(os.path.join(here, "..", "static", fn), os.path.join(out, "static", fn))

    def w(path, text):
        with open(os.path.join(out, path), "w", encoding="utf-8") as f:
            f.write(text)

    ordered = sorted(items.values(), key=lambda i: i["updated"], reverse=True)
    stamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    # 共有用の画像（新しい300件）。作れた記事のページにだけ、画像の指定を入れる。
    cfg["_og"] = {it["id"] for it in ordered[:300] if og_image(cfg, out, it)}

    for it in ordered:
        w(f'v/{it["id"]}.html', item_page(cfg, it))

    # トップ
    day = (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
    new24 = sum(1 for i in ordered if i["first_seen"] >= day)
    upd24 = sum(1 for i in ordered if i["updated"] >= day and len(i["timeline"]) > 1)
    kev24 = sum(1 for i in ordered if i["updated"] >= day and i["facts"].get("kev"))
    months = sorted({jst(i["first_seen"], "%Y-%m") for i in ordered}, reverse=True)
    mlinks = "".join(f'<a class="tag" href="m/{m}.html">{m}</a>' for m in months[:12])
    site_ld = '<script type="application/ld+json">' + json.dumps({
        "@context": "https://schema.org", "@type": "WebSite", "name": cfg["site_name"],
        "url": cfg["site_url"].rstrip("/") + "/", "inLanguage": "ja",
        "description": cfg.get("tagline", "")}, ensure_ascii=False) + "</script>"
    head = f'''<section class="hero">
<h1>{E(cfg.get("headline", cfg["site_name"]))}</h1>
<p>{E(cfg.get("tagline", ""))}</p>
<dl class="stats"><div><dt>新着</dt><dd>{new24}</dd></div><div><dt>追記</dt><dd>{upd24}</dd></div><div><dt>悪用確認</dt><dd>{kev24}</dd></div></dl>
<p class="fine">数字は直近24時間。最終確認 <time datetime="{stamp}">{jst(stamp)}</time>（1時間ごとに自動更新）</p>
</section>
{slides(cfg, out, ordered)}
<aside class="cta"><h3>自分のプロジェクトに関係する脆弱性を、AIに調べさせる</h3>
<p>Claude Code や Cursor などに依頼文を1つ渡すと、このサイトのデータと依存関係を照らし合わせます。無料、登録不要。</p>
<a class="btn" href="ai.html">使い方を見る</a></aside>
{sponsor(cfg, "")}'''
    w("index.html", page(cfg, "", cfg["site_name"],
                         head + list_block(ordered[:100], "", cfg) + alert_cta(cfg, "") +
                         f'<section><h2>月別の一覧</h2><div class="tags">{mlinks}</div></section>',
                         cfg.get("tagline", ""), "", jsonld=site_ld))

    # 月別
    for m in months:
        sub = [i for i in ordered if jst(i["first_seen"], "%Y-%m") == m]
        w(f"m/{m}.html", page(cfg, "../", f"{m} の脆弱性",
                              f"<h1>{m} に掲載した脆弱性</h1>" + list_block(sub, "../", cfg),
                              f"{m} に掲載した脆弱性の一覧。", f"m/{m}.html"))

    # 製品別（検索からの入口になるページ。製品ごとのRSSも出す）
    prod = {}
    for it in ordered:
        for p in it["facts"].get("products") or []:
            prod.setdefault(slug(p), {"p": p, "items": []})["items"].append(it)
    for sl, v in prod.items():
        name = v["p"]["product"]
        body = f'''<p class="crumbs"><a href="../products.html">製品別</a> / {E(name)}</p>
<h1>{E(name)} の脆弱性</h1>
<p>{E(v["p"]["vendor"])} {E(name)} に関する脆弱性の新着と追記を、新しい順に載せています。<a href="{sl}.xml">この製品だけのRSS</a></p>
{alert_cta(cfg, "../", name)}''' + list_block(v["items"], "../", cfg, False)
        w(f"p/{sl}.html", page(cfg, "../", f"{name} の脆弱性", body,
                               f"{name} の脆弱性情報の新着と追記。", f"p/{sl}.html"))
        w(f"p/{sl}.xml", rss(cfg, v["items"], f'{name} の脆弱性 | {cfg["site_name"]}', f"p/{sl}.xml"))
    plist = "".join(
        f'<li>{prod_icon(v["p"])}<a href="p/{sl}.html">{E(v["p"]["product"])}</a><span>{E(v["p"]["vendor"])}</span><b>{len(v["items"])}</b></li>'
        for sl, v in sorted(prod.items(), key=lambda kv: -len(kv[1]["items"])))
    w("products.html", page(cfg, "", "製品別の一覧",
                            f'<h1>製品別の一覧</h1><p>製品名を選ぶと、その製品の脆弱性だけを追えます。</p><ul class="plist">{plist}</ul>',
                            "製品ごとの脆弱性一覧。", "products.html"))

    # 分析（掲載中の件を項目ごとに数えたページ）
    w("insights.html", page(cfg, "", "数字で見る脆弱性", insights.body(ordered, now, icon_kind, ICONS),
                            "掲載中の脆弱性を、種類、攻撃の条件、開発元などで数えた集計。", "insights.html"))

    # 固定ページ
    pay = cfg.get("payments", {})
    def paybtn(key, text):
        return f'<a class="btn" href="{E(pay[key])}" rel="noopener">{text}</a>' if pay.get(key) else '<p class="fine">申し込みの受付を準備しています。</p>'
    if alerts_on(cfg):
        w("alerts.html", page(cfg, "", "メール通知", f'''<h1>使っている製品の脆弱性だけを、メールで受け取る</h1>
<p>製品名を登録しておくと、その製品に新しい脆弱性が出たとき、または掲載済みの件に追記があったときに、1時間以内にメールでお知らせします。</p>
<ul class="bullets"><li>登録できる製品名は10個まで</li><li>深刻度の下限を選べます（例: 重要以上だけ）</li><li>攻撃での悪用が確認されたときは、深刻度にかかわらず通知</li><li>いつでも解約できます</li></ul>
<p class="price">{E(pay.get("alert_price", ""))}</p>
{paybtn("alert_link", "申し込む")}
<p class="fine">サイトの記事と製品別RSSは、これまでどおり無料で読めます。</p>''',
                          "製品名を登録すると、その製品の脆弱性だけをメールで受け取れます。", "alerts.html"))
    sp_on = cfg.get("sponsor", {}).get("enabled")
    sp_title = "支援・スポンサー" if sp_on else "寄付"
    sp_block = f'''<h2>スポンサー枠</h2><p>トップと全記事の下部に、社名・リンク・一言を掲載します。{E(pay.get("sponsor_price", ""))}。申し込みから掲載まで、やり取りは不要です。</p>
{paybtn("sponsor_link", "スポンサー枠を申し込む")}
<h2>寄付</h2>''' if sp_on else ""
    w("support.html", page(cfg, "", sp_title, f'''<h1>{sp_title}</h1>
{sp_block}<p>運営費（AIの利用料とサーバー代）に充てます。</p>
{paybtn("donate_link", "寄付する")}''', "サイト運営への支援の案内。", "support.html"))
    w("about.html", page(cfg, "", "編集方針と出典", '''<h1>編集方針と出典</h1>
<h2>情報の出どころ</h2><p>記事は、次の公開情報だけをもとに作っています。他のニュースサイトの記事は材料にしていません。</p>
<ul class="bullets"><li>NVD（米国立標準技術研究所の脆弱性データベース）</li><li>CISA KEV（米サイバーセキュリティ庁による、悪用が確認された脆弱性の一覧）</li><li>JVN iPedia（IPAとJPCERT/CCが運営する脆弱性対策情報データベース）</li><li>FIRST EPSS（悪用される確率の推定値）</li></ul>
<p class="fine">This product uses the NVD API but is not endorsed or certified by the NVD.</p>
<h2>掲載の基準</h2><p>CVSSスコアが7.0以上のもの、または攻撃での悪用が確認されたもの（CISA KEVに載ったもの）を載せています。</p>
<h2>AIの使い方</h2><p>要約文はAIが書いています。AIには出典の内容だけを渡し、書かれた数値や番号が出典にあるかを機械的に照合して、合わない要約は掲載しません。更新履歴の文は、数値の差分から機械的に作っています。</p>
<h2>追記の方針</h2><p>同じ脆弱性の続報は新しい記事にせず、同じページの更新履歴に時刻つきで追記します。</p>
<h2>広告と紹介リンク</h2><p>広告と、紹介料が発生するリンクには「広告」「PR」と表示しています。掲載の有無や記事の内容は、紹介料の影響を受けません。</p>
<h2>免責</h2><p>内容の正確さには注意していますが、誤りが残ることがあります。対応の判断は、必ず出典の原文と開発元の案内で確認してください。</p>''',
                         "情報源、掲載基準、AIの使い方、追記の方針。", "about.html"))
    w("tokushoho.html", page(cfg, "", "特定商取引法に基づく表記", '''<h1>特定商取引法に基づく表記</h1>
<div class="scroll"><table><tr><th>販売事業者</th><td>（記入してください）</td></tr><tr><th>所在地・連絡先</th><td>（記入してください）</td></tr><tr><th>販売価格</th><td>各申し込みページに記載</td></tr><tr><th>支払方法・時期</th><td>クレジットカード。申し込み時、以降は毎月同日に決済</td></tr><tr><th>提供時期</th><td>決済の完了後、すぐに利用できます</td></tr><tr><th>解約</th><td>いつでも解約できます。次回の決済日以降の請求は発生しません</td></tr></table></div>''',
                             "特定商取引法に基づく表記。", "tokushoho.html"))

    w("feed.xml", rss(cfg, ordered, cfg["site_name"], "feed.xml"))
    base = cfg["site_url"].rstrip("/")
    aifeed.write(out, cfg, ordered, now)
    w("ai.html", page(cfg, "", "AIで使う", ai_page(base),
                      "このサイトをAIに読ませて、自分のプロジェクトに関係する脆弱性を調べる方法。Claude Code や Cursor に渡す依頼文つき。", "ai.html"))

    # サイトマップ。更新日時を付けて、検索エンジンが変わったページから見に来られるようにする
    urls = [(f"{base}/", stamp), (f"{base}/products.html", stamp), (f"{base}/insights.html", stamp),
            (f"{base}/ai.html", ""), (f"{base}/about.html", "")]
    urls += [(f'{base}/v/{i["id"]}.html', i["updated"]) for i in ordered]
    urls += [(f"{base}/p/{sl}.html", max(i["updated"] for i in v["items"])) for sl, v in prod.items()]
    urls += [(f"{base}/m/{m}.html", "") for m in months]
    w("sitemap.xml", '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">' +
      "".join(f"<url><loc>{E(u)}</loc>" + (f"<lastmod>{m}</lastmod>" if m else "") + "</url>" for u, m in urls) + "</urlset>")
    w("robots.txt", f"User-agent: *\nAllow: /\nSitemap: {base}/sitemap.xml\n")
    return len(ordered), len(prod)
