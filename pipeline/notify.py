"""拡散（SNS自動投稿）と集金（有料メール通知）。

どちらも、認証情報が環境変数に無いときは送信せず、送る予定の内容を表示するだけ。
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import smtplib
import time
import urllib.parse
import urllib.request
from email.mime.text import MIMEText

from .store import public_url, sev_ja


# ---------- 投稿文 ----------

def post_text(cfg, it, ev):
    f, s = it["facts"], it["summary"]
    c = f.get("cvss")
    head = "【追記】" if ev["kind"] == "update" else ("【悪用確認】" if f.get("kev") else f"【{sev_ja((c or {}).get('severity'))}】")
    bits = [f"{head}{s['title']}", it["id"] + (f" / CVSS {c['score']}" if c else "")]
    if ev["kind"] == "update" and ev["changes"]:
        bits.append(ev["changes"][0])
    url = public_url(cfg, f'v/{it["id"]}.html')
    tags = " ".join("#" + t for t in cfg.get("social", {}).get("hashtags", []))
    body = "\n".join(bits)
    room = 250 - len(tags)  # Xは日本語140字相当。URLは別に数えられるので本文を短めに保つ
    if len(body) > room // 2:
        body = body[: room // 2 - 1] + "…"
    return body, url, tags


# ---------- Bluesky ----------

def _json_post(url, data, headers=None):
    h = {"content-type": "application/json"}
    h.update(headers or {})
    req = urllib.request.Request(url, data=json.dumps(data).encode(), headers=h)
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read() or b"{}")


def post_bluesky(body, url, tags):
    ses = _json_post("https://bsky.social/xrpc/com.atproto.server.createSession",
                     {"identifier": os.environ["BSKY_HANDLE"], "password": os.environ["BSKY_APP_PASSWORD"]})
    text = f"{body}\n{url}"
    start = len((body + "\n").encode())
    rec = {"$type": "app.bsky.feed.post", "text": text, "langs": ["ja"],
           "createdAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "facets": [{"index": {"byteStart": start, "byteEnd": start + len(url.encode())},
                       "features": [{"$type": "app.bsky.richtext.facet#link", "uri": url}]}]}
    _json_post("https://bsky.social/xrpc/com.atproto.repo.createRecord",
               {"repo": ses["did"], "collection": "app.bsky.feed.post", "record": rec},
               {"authorization": "Bearer " + ses["accessJwt"]})


# ---------- X (OAuth 1.0a) ----------

def post_x(body, url, tags):
    api = "https://api.twitter.com/2/tweets"
    q = lambda s: urllib.parse.quote(str(s), safe="")
    o = {"oauth_consumer_key": os.environ["X_API_KEY"], "oauth_nonce": secrets.token_hex(16),
         "oauth_signature_method": "HMAC-SHA1", "oauth_timestamp": str(int(time.time())),
         "oauth_token": os.environ["X_ACCESS_TOKEN"], "oauth_version": "1.0"}
    base = "&".join(["POST", q(api), q("&".join(f"{q(k)}={q(v)}" for k, v in sorted(o.items())))])
    key = f'{q(os.environ["X_API_SECRET"])}&{q(os.environ["X_ACCESS_SECRET"])}'
    o["oauth_signature"] = base64.b64encode(hmac.new(key.encode(), base.encode(), hashlib.sha1).digest()).decode()
    auth = "OAuth " + ", ".join(f'{q(k)}="{q(v)}"' for k, v in sorted(o.items()))
    _json_post(api, {"text": f"{body}\n{url} {tags}".strip()}, {"authorization": auth})


def social(root, cfg, items, events):
    """重大な新着・追記だけを投稿する。同じ出来事を二度投稿しないよう記録を残す。"""
    logp = os.path.join(root, "social_posted.json")
    posted = json.load(open(logp, encoding="utf-8")) if os.path.exists(logp) else []
    cap = cfg.get("social", {}).get("max_posts_per_run", 4)
    queue = []
    for ev in events:
        it = items.get(ev["cve"])
        if not it or not ev.get("major"):
            continue
        key = f'{ev["cve"]}#{len(it["timeline"])}'
        if key in posted:
            continue
        queue.append((key, post_text(cfg, it, ev)))
    for key, (body, url, tags) in queue[:cap]:
        sent = False
        for name, fn, need in (("Bluesky", post_bluesky, "BSKY_APP_PASSWORD"), ("X", post_x, "X_ACCESS_SECRET")):
            if not os.environ.get(need):
                continue
            try:
                fn(body, url, tags)
                sent = True
                print(f"[social] {name} に投稿: {key}")
            except Exception as e:
                print(f"[warn] {name} への投稿に失敗: {e}")
        if not sent:
            print(f"[social:予定] {body} {url} {tags}".replace("\n", " / "))
        posted.append(key)
    with open(logp, "w", encoding="utf-8") as f:
        json.dump(posted[-2000:], f)
    return len(queue[:cap])


# ---------- 有料メール通知 ----------

def _match(sub, it):
    f = it["facts"]
    hay = (it["summary"]["title"] + " " + " ".join(
        f'{p["vendor"]} {p["product"]}' for p in f.get("products") or []) + " " +
        (f.get("kev") or {}).get("product", "")).lower()
    if not any(w.lower() in hay for w in sub.get("watch", [])):
        return False
    score = (f.get("cvss") or {}).get("score") or 0
    return bool(f.get("kev")) or score >= sub.get("min_cvss", 0)


def load_subscribers():
    """購読者の一覧。環境変数 SUBSCRIBERS_JSON（本番）か、手元の subscribers.json（試験）から読む。
    形式: [{"email": "a@example.com", "watch": ["wordpress"], "min_cvss": 7.0}]"""
    raw = os.environ.get("SUBSCRIBERS_JSON")
    if not raw and os.path.exists("subscribers.json"):
        with open("subscribers.json", encoding="utf-8") as f:
            raw = f.read()
    return json.loads(raw or "[]")


def build_mail(cfg, sub, pairs, test=False):
    """1人分のメールを組み立てる。pairs は (記事, 出来事) の並び。該当なしなら None。"""
    base = cfg["site_url"].rstrip("/")
    lines = []
    for it, ev in pairs:
        kind = "追記" if ev["kind"] == "update" else "新着"
        c = it["facts"].get("cvss")
        sev = f' / {sev_ja(c["severity"])} CVSS {c["score"]}' if c else ""
        kev = " / 悪用確認" if it["facts"].get("kev") else ""
        lines.append(f'[{kind}] {it["summary"]["title"]}\n  {it["id"]}{sev}{kev}\n' +
                     "".join(f"  ・{c}\n" for c in ev["changes"]) +
                     f'  {it["summary"]["summary"]}\n  {base}/v/{it["id"]}\n')
    if not lines:
        return None
    head = "これは通知の試験メールです。実際の通知は次の形で届きます。\n\n" if test else ""
    text = (head + "登録した製品（" + "、".join(sub.get("watch", [])) + "）に関する脆弱性のお知らせです。\n\n" +
            "\n".join(lines) + f"\n配信の停止・変更: {base}/alerts\n")
    msg = MIMEText(text, "plain", "utf-8")
    msg["Subject"] = ("【テスト】" if test else "") + f'[{cfg["site_name"]}] 登録製品の脆弱性 {len(lines)}件'
    msg["From"] = os.environ.get("SMTP_FROM") or os.environ.get("SMTP_USER") or "alerts@localhost"
    msg["To"] = sub["email"]
    return msg


def smtp_ready():
    return bool(os.environ.get("SMTP_HOST"))


def send_mail(msg):
    """SMTP_SECURITY: ssl（既定、465番）/ starttls（587番）/ none（手元の試験用サーバー向け）"""
    host, mode = os.environ["SMTP_HOST"], os.environ.get("SMTP_SECURITY", "ssl")
    port = int(os.environ.get("SMTP_PORT") or {"ssl": 465, "starttls": 587, "none": 25}[mode])
    cls = smtplib.SMTP_SSL if mode == "ssl" else smtplib.SMTP
    with cls(host, port, timeout=30) as s:
        if mode == "starttls":
            s.starttls()
        if os.environ.get("SMTP_USER"):
            s.login(os.environ["SMTP_USER"], os.environ["SMTP_PASS"])
        s.send_message(msg)


def alerts(cfg, items, events):
    n = 0
    for sub in load_subscribers():
        pairs = [(items[ev["cve"]], ev) for ev in events
                 if ev["cve"] in items and _match(sub, items[ev["cve"]])]
        msg = build_mail(cfg, sub, pairs)
        if not msg:
            continue
        n += 1
        if not smtp_ready():
            print(f"[alert:予定] {sub['email']} へ {len(pairs)} 件")
            continue
        try:
            send_mail(msg)
            print(f"[alert] {sub['email']} へ {len(pairs)} 件を送信")
        except Exception as e:
            print(f"[warn] メール送信に失敗: {e}")
    return n
