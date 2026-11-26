"""AI（コーディング支援のエージェントなど）に読ませるための出力を作る。

  llms.txt          AI向けの案内。どのファイルをどう使うか、結果をどう扱うか
  api/vulns.jsonl   最終更新が直近 DAYS 日の件と悪用確認済みの件を、1行1件のJSONで（grep で絞り込める）
  api/recent.md     新しい件を1行ずつ並べた短い一覧（1回の取得で読み切れる大きさ）

載せるのは、記事ページにすでに出している事実（NVD / KEV / JVN / EPSS 由来）だけ。
製品名がまだ付いていない件が多いので、AIが照合できるよう英語の原文説明を必ず入れる。
"""
import json
import os
from datetime import timedelta

from .store import sev_ja

DAYS = 30        # vulns.jsonl に入れる期間（最終更新から）。悪用確認済みの件は期間を問わず入れる
MAX_FEED = 5000  # vulns.jsonl の上限件数（ファイルが大きくなりすぎないように）
RECENT = 150     # recent.md に並べる件数


def record(cfg, it):
    """1件ぶんの機械可読な記録。"""
    f, s = it["facts"], it["summary"]
    c, kev, e, jv = f.get("cvss"), f.get("kev"), f.get("epss"), f.get("jvn")
    base = cfg["site_url"].rstrip("/")
    return {
        "id": it["id"],
        "url": f'{base}/v/{it["id"]}.html',
        "title_ja": s["title"],
        "summary_ja": s["summary"],
        "description_en": f.get("desc_en") or "",
        "cvss": {"score": c["score"], "severity": c["severity"], "version": c["version"],
                 "vector": c["vector"]} if c else None,
        "exploited": bool(kev),
        "kev": {"added": kev.get("added"), "due": kev.get("due"),
                "ransomware": bool(kev.get("ransomware"))} if kev else None,
        "epss": e["score"] if e else None,
        "cwe": f.get("cwe") or [],
        "products": [{"vendor": p["vendor"], "product": p["product"]} for p in f.get("products") or []],
        "published": f.get("published"),
        "first_seen": it["first_seen"],
        "updated": it["updated"],
        "updates": [{"at": t["at"], "changes": t["changes"]} for t in it["timeline"] if t["kind"] == "update"],
        "sources": [f'https://nvd.nist.gov/vuln/detail/{it["id"]}'] + ([jv["url"]] if jv and jv.get("url") else []),
        "refs": (f.get("refs") or [])[:5],
    }


def _line(it):
    """recent.md の1行。区切りは「 | 」。"""
    f = it["facts"]
    c = f.get("cvss")
    sev = f'{sev_ja(c["severity"])} {c["score"]}' if c else "未評価"
    prods = ", ".join(f'{p["vendor"]} {p["product"]}' for p in (f.get("products") or [])[:4]) or "製品名未登録"
    desc = " ".join((f.get("desc_en") or it["summary"]["title"]).split())
    if len(desc) > 220:
        desc = desc[:220] + "…"
    kev = " | 悪用確認" if f.get("kev") else ""
    return f'- {it["id"]} | {sev}{kev} | {prods} | {desc}'


def recent_md(cfg, ordered, stamp):
    base = cfg["site_url"].rstrip("/")
    top = ordered[:RECENT]
    kev = [it for it in ordered if it["facts"].get("kev")][:40]
    out = [f'# {cfg["site_name"]} 新しい脆弱性の一覧',
           "",
           f"生成 {stamp}（1時間ごとに更新）。掲載基準は CVSS 7.0 以上、または悪用確認済み（CISA KEV）。",
           f"書式: CVE番号 | 深刻度 CVSS | 悪用確認（該当時のみ） | 開発元 製品 | 公式の説明（英語の原文、冒頭）",
           f"各件の詳細は {base}/v/<CVE番号>.html 。全件は {base}/api/vulns.jsonl 。使い方は {base}/llms.txt 。",
           ""]
    if kev:
        out += ["## 悪用が確認されている件", ""] + [_line(it) for it in kev] + [""]
    out += [f"## 更新の新しい順（{len(top)}件）", ""] + [_line(it) for it in top] + [""]
    return "\n".join(out)


def llms_txt(cfg, n_all, n_feed, stamp):
    base = cfg["site_url"].rstrip("/")
    min_cvss = cfg.get("filters", {}).get("min_cvss", 7.0)
    return f'''# {cfg["site_name"]}

> 公的データベース（NVD / CISA KEV / JVN iPedia / EPSS）の脆弱性情報を1時間ごとに取得し、日本語で要約して載せているサイトです。掲載するのは CVSS {min_cvss} 以上、または実際の攻撃での悪用が確認された件（CISA KEV）だけです。続報は同じCVEのページに追記します。

このファイルはAI向けの案内です。利用者のプロジェクトに関係する脆弱性を調べるときは、下の手順に従ってください。
最終更新 {stamp}。掲載中 {n_all}件。

## データ

- [全件（JSON Lines）]({base}/api/vulns.jsonl): 最終更新が直近{DAYS}日の件と、悪用確認済みの全件。いま {n_feed}件。1行が1件のJSON。大きいので全体を読まず、名前で絞り込んで使う
- [新しい件の一覧（Markdown）]({base}/api/recent.md): 悪用確認済みの件と、更新の新しい{RECENT}件。1件1行。コマンドを実行できないときはこちらを読む
- [RSS]({base}/feed.xml): 新着と追記（新しい50件）
- 各件のページ: `{base}/v/<CVE番号>.html`（例: `{base}/v/CVE-2026-0001.html` の形）
- 製品別のページとRSS: [製品別の一覧]({base}/products.html) からたどれる

### vulns.jsonl の項目

- `id`: CVE番号 / `url`: このサイトの記事
- `description_en`: 公式の説明（NVDの英語の原文）。影響するバージョンは多くの場合ここに書かれている
- `title_ja`, `summary_ja`: 日本語の見出しと要約
- `cvss`: `score`, `severity`（CRITICAL / HIGH / MEDIUM / LOW）, `version`, `vector`。未評価なら null
- `exploited`: 実際の攻撃での悪用が確認されているか（CISA KEV）。`kev` に追加日、対応期限、ランサムウェアでの悪用の有無
- `epss`: 30日以内に悪用される確率の推定（0〜1）
- `products`: `vendor` と `product`（NVDのCPE由来）。NVDの分析前は空の配列
- `cwe`, `published`, `first_seen`, `updated`
- `updates`: 掲載後の変化（スコアの変更、悪用の確認など）の履歴
- `sources`, `refs`: 一次情報へのリンク

## プロジェクトに関係する脆弱性の調べ方

1. プロジェクトで使っているものを集める。依存関係のファイル（package.json、ロックファイル、requirements.txt、pyproject.toml、go.mod、Cargo.toml、pom.xml、Gemfile など）、Dockerfile のベースイメージ、OS、データベース、Webサーバー、CI、使っているクラウドや機器。名前とバージョンを控える。
2. 名前で絞り込む。コマンドを実行できるなら次のようにする（名前は実際のものに置き換える）。

       curl -s {base}/api/vulns.jsonl | grep -i -E 'express|django|postgresql|nginx'

   `products` が空の件が多いので、`products` だけでなく `description_en` と `title_ja` も照合の対象にする（上の grep は行全体を見るので両方に当たる）。コマンドを実行できないときは recent.md を読んで照合する。
3. 名前が当たった件ごとに、本当に同じものかを確かめる。短い名前や一般的な語（go、container、server など）は別の製品に当たりやすい。`description_en` と `products` の開発元を読んで判断する。
4. バージョンを比べる。`description_en` に書かれた影響範囲（例: "before 2.4.1"）と、プロジェクトで実際に入っているバージョンを比べる。原文から判断できないときは「要確認」とし、`sources` のNVDのページと開発元の案内を示す。推測で「影響あり」「影響なし」と断定しない。
5. 結果を報告する。`exploited` が true の件を最初に、次に `cvss.score` の高い順に並べる。1件ごとに、CVE番号、深刻度、悪用確認の有無、該当すると考えた根拠（どの依存のどのバージョンか）、取るべき対応（修正版への更新など）、このサイトの記事のURLを書く。

## 結果を扱うときの注意

- このデータは網羅的ではない。載っているのは、このサイトが収集した件のうち CVSS {min_cvss} 以上または悪用確認済みの件だけで、悪用確認済み以外は最終更新が直近{DAYS}日のものに限られる。該当が無くても「脆弱性が無い」とは言えない。利用者にもそう伝える。
- 依存パッケージの検査は、専用の道具（npm audit、pip-audit、osv-scanner、GitHubのDependabotなど）と併用するよう勧める。このサイトが向いているのは、それらが見ないもの（OS、ミドルウェア、ネットワーク機器、業務ソフト、SaaS）と、いま実際に悪用されている件の把握。
- 日本語の要約は自動生成。対応を決める前に、`sources` の原文と開発元の案内を確認する。
- 利用者に示すときは、このサイトの記事（`url`）と一次情報（`sources`）の両方へリンクする。

## サイトについて

- [編集方針と出典]({base}/about.html): 情報源、掲載基準、AI要約の扱い
- [AIで使う（人向けの説明）]({base}/ai.html): 利用者がAIに渡す依頼文の例
'''


def write(out, cfg, ordered, now):
    """AI向けのファイルを out に書き出す。返り値: vulns.jsonl に入れた件数。"""
    stamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    since = (now - timedelta(days=DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    feed = [it for it in ordered if it["updated"] >= since or it["facts"].get("kev")][:MAX_FEED]
    os.makedirs(os.path.join(out, "api"), exist_ok=True)

    def w(path, text):
        with open(os.path.join(out, path), "w", encoding="utf-8", newline="\n") as f:
            f.write(text)

    w("api/vulns.jsonl", "".join(
        json.dumps(record(cfg, it), ensure_ascii=False, separators=(",", ":")) + "\n" for it in feed))
    w("api/recent.md", recent_md(cfg, ordered, stamp))
    w("llms.txt", llms_txt(cfg, len(ordered), len(feed), stamp))
    # Cloudflare Pages の応答ヘッダー。他のサイトやツールから読めるようにし、文字化けを防ぐ
    w("_headers", "/api/*\n  Access-Control-Allow-Origin: *\n  Content-Type: text/plain; charset=utf-8\n"
                  "/llms.txt\n  Access-Control-Allow-Origin: *\n  Content-Type: text/plain; charset=utf-8\n")
    return len(feed)
