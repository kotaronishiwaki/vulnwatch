"""分析ページ（insights.html）の中身を作る。

掲載中の記事の事実データを数えるだけ。AIは使わず、推測や評価の文も書かない。
グラフはHTMLとCSSだけで描く（外部のライブラリや通信は使わない）。
"""
import html
from collections import Counter
from datetime import timedelta, timezone, datetime

E = html.escape
JST = timezone(timedelta(hours=9))

# よく出る脆弱性の種類（CWE）の日本語名。表に無い番号は「CWE-番号」のまま出す。
CWE_JA = {
    "CWE-20": "不適切な入力確認", "CWE-22": "パストラバーサル", "CWE-59": "リンク解釈の問題",
    "CWE-77": "コマンドインジェクション", "CWE-78": "OSコマンドインジェクション",
    "CWE-79": "クロスサイトスクリプティング", "CWE-89": "SQLインジェクション",
    "CWE-94": "コードインジェクション", "CWE-116": "出力のエンコード不備",
    "CWE-119": "バッファエラー", "CWE-120": "バッファオーバーフロー",
    "CWE-121": "スタックバッファオーバーフロー", "CWE-122": "ヒープバッファオーバーフロー",
    "CWE-125": "境界外読み取り", "CWE-190": "整数オーバーフロー", "CWE-200": "情報漏えい",
    "CWE-269": "不適切な権限管理", "CWE-276": "不適切な初期権限", "CWE-284": "不適切なアクセス制御",
    "CWE-287": "不適切な認証", "CWE-288": "代替経路による認証回避", "CWE-295": "証明書の検証不備",
    "CWE-306": "重要な機能の認証欠如", "CWE-352": "クロスサイトリクエストフォージェリ",
    "CWE-362": "競合状態", "CWE-400": "リソースの枯渇", "CWE-416": "解放済みメモリの使用",
    "CWE-427": "検索パスの制御不備", "CWE-434": "危険なファイルのアップロード",
    "CWE-476": "NULLポインタ参照", "CWE-502": "信頼できないデータのデシリアライズ",
    "CWE-601": "オープンリダイレクト", "CWE-611": "XML外部実体参照",
    "CWE-639": "ユーザー制御の鍵による認可回避", "CWE-732": "重要リソースへの不適切な権限設定",
    "CWE-770": "制限のないリソース割り当て", "CWE-787": "境界外書き込み",
    "CWE-798": "認証情報のハードコード", "CWE-843": "型の取り違え", "CWE-862": "認可の欠如",
    "CWE-863": "不正な認可", "CWE-918": "サーバーサイドリクエストフォージェリ",
    "CWE-1321": "プロトタイプ汚染",
}


def _score(it):
    return (it["facts"].get("cvss") or {}).get("score") or 0


def _vector(it):
    """CVSSのベクトル文字列を {項目: 値} にする。例: {"AV": "N", "PR": "N", "UI": "N"}"""
    v = (it["facts"].get("cvss") or {}).get("vector") or ""
    return dict(p.split(":", 1) for p in v.split("/") if ":" in p and not p.startswith("CVSS"))


def _hbars(rows, unit="件"):
    """横棒の一覧。rows: [(見出しHTML, 値)]。値は右に必ず文字で出す。"""
    if not rows:
        return '<p class="fine">該当するデータがまだありません。</p>'
    top = max(v for _, v in rows) or 1
    return '<ul class="hbars">' + "".join(
        f'<li><span class="hb-l">{label}</span><span class="hb-t"><i style="width:{max(v / top * 100, 1.5):.1f}%"></i></span>'
        f'<b>{v}<small>{unit}</small></b></li>' for label, v in rows) + "</ul>"


def _meter(label, n, total, note=""):
    pct = round(n / total * 100) if total else 0
    return (f'<div class="meter"><div class="meter-h"><span>{label}</span><b>{pct}<small>%</small></b></div>'
            f'<div class="hb-t"><i style="width:{pct}%"></i></div>'
            f'<p class="fine">{total}件中 {n}件{note}</p></div>')


def _daily(items, now, days=14):
    """NVDでの公開日（日本時間）ごとの件数。緊急とそれ以外を積む。"""
    today = now.astimezone(JST).date()
    span = [today - timedelta(days=i) for i in range(days - 1, -1, -1)]
    crit, rest = Counter(), Counter()
    for it in items:
        p = it["facts"].get("published")
        if not p:
            continue
        try:
            d = datetime.fromisoformat(p.replace("Z", "+00:00"))
        except ValueError:
            continue
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        (crit if _score(it) >= 9.0 else rest)[d.astimezone(JST).date()] += 1
    tot = {d: crit[d] + rest[d] for d in span}
    top = max(tot.values()) or 1
    peak = max(span, key=lambda d: tot[d])
    cols, trs = [], []
    for d in span:
        show = d in (peak, span[-1]) and tot[d]  # 数字は最大の日と最新の日にだけ添える
        seg = "".join(f'<i class="{c}" style="height:{n / top * 100:.1f}%"></i>'
                      for c, n in (("c", crit[d]), ("r", rest[d])) if n)
        tip = f"{d.month}/{d.day}: {tot[d]}件（うち緊急 {crit[d]}件）"
        cols.append(f'<div class="vb" title="{tip}"><span class="vb-n">{tot[d] if show else ""}</span>'
                    f'<div class="vb-s">{seg}</div><span class="vb-d">{d.month}/{d.day}</span></div>')
        trs.append(f"<tr><th>{d.month}/{d.day}</th><td>{tot[d]}</td><td>{crit[d]}</td></tr>")
    return f'''<div class="legend"><span><i class="c"></i>緊急（CVSS 9.0以上）</span><span><i class="r"></i>それ以外</span></div>
<div class="vbars" role="img" aria-label="直近{days}日の公開日ごとの件数。詳しい数は下の表にあります。">{"".join(cols)}</div>
<details class="tbl"><summary>数字を表で見る</summary><div class="scroll"><table><tr><th>公開日</th><th>件数</th><th>うち緊急</th></tr>{"".join(trs)}</table></div></details>'''


def body(items, now, icon_kind, icons):
    """分析ページの本文HTML。items: 掲載中の記事の一覧。icon_kind / icons: 製品の種類のアイコン。"""
    n = len(items)
    crit = sum(1 for i in items if _score(i) >= 9.0)
    kev = [i for i in items if i["facts"].get("kev")]
    ransom = sum(1 for i in kev if i["facts"]["kev"].get("ransomware"))

    # 攻撃の条件（CVSSのベクトルから）
    vec = [v for v in map(_vector, items) if v.get("AV")]
    net = sum(1 for v in vec if v["AV"] == "N")
    noauth = sum(1 for v in vec if v.get("PR") == "N")
    noui = sum(1 for v in vec if v.get("UI") == "N")
    easy = sum(1 for v in vec if v["AV"] == "N" and v.get("PR") == "N" and v.get("UI") == "N")

    # 種類（CWE）
    cwe = Counter()
    for it in items:
        for c in set(it["facts"].get("cwe") or []):
            if c.startswith("CWE-"):
                cwe[c] += 1
    cwe_rows = [(f'{E(CWE_JA.get(c, c))}<small>{E(c)}</small>' if c in CWE_JA else E(c), v)
                for c, v in cwe.most_common(10)]

    # 開発元と製品の種類（製品情報がある件だけ）
    with_p = [i for i in items if i["facts"].get("products")]
    vendor, kind = Counter(), Counter()
    for it in with_p:
        ps = it["facts"]["products"]
        for v in {p["vendor"] for p in ps}:
            vendor[v] += 1
        for k in {icon_kind(f'{p["vendor"]} {p["product"]}') for p in ps}:
            kind[k] += 1
    kind_rows = [(f'<svg class="pico" viewBox="0 0 24 24" aria-hidden="true">{icons[k][1]}</svg>{E(icons[k][0])}', v)
                 for k, v in kind.most_common()]

    # 悪用されやすさ（EPSS）の上位
    epss = sorted((i for i in items if i["facts"].get("epss")), key=lambda i: -i["facts"]["epss"]["score"])[:8]
    epss_rows = "".join(
        f'<tr><td><a href="v/{i["id"]}.html">{i["id"]}</a></td><td>{E(i["summary"]["title"])}</td>'
        f'<td class="num">{i["facts"]["epss"]["score"] * 100:.0f}%</td><td class="num">{_score(i) or "-"}</td></tr>'
        for i in epss)
    kev_rows = "".join(
        f'<tr><td><a href="v/{i["id"]}.html">{i["id"]}</a></td><td>{E(i["summary"]["title"])}</td>'
        f'<td class="num">{E(i["facts"]["kev"].get("added") or "-")}</td><td class="num">{E(i["facts"]["kev"].get("due") or "-")}</td></tr>'
        for i in sorted(kev, key=lambda i: i["facts"]["kev"].get("added") or "", reverse=True)[:10])

    stamp = now.astimezone(JST).strftime("%Y-%m-%d %H:%M")
    return f'''<h1>数字で見る脆弱性</h1>
<p>このサイトに掲載中の {n}件を、項目ごとに数えたものです。数字は1時間ごとに作り直します（{stamp} 時点）。</p>
<dl class="stats"><div><dt>掲載中</dt><dd>{n}</dd></div><div><dt>緊急</dt><dd>{crit}</dd></div><div><dt>悪用確認</dt><dd>{len(kev)}</dd></div></dl>
<div class="ins">
<section class="panel wide"><h2>公開日ごとの件数（直近14日）</h2>{_daily(items, now)}
<p class="fine">NVDでの公開日（日本時間）で数えています。このサイトが取得を始める前に公開された分は、一部しか含まれません。</p></section>
<section class="panel"><h2>攻撃の条件</h2>
{_meter("ネットワーク経由で攻撃できる", net, len(vec))}
{_meter("認証なしで攻撃できる", noauth, len(vec))}
{_meter("利用者の操作が要らない", noui, len(vec))}
{_meter("上の3つがすべて当てはまる", easy, len(vec))}
<p class="fine">CVSSの評価項目（攻撃元区分、必要な特権、利用者の関与）から数えています。</p></section>
<section class="panel"><h2>多い種類（上位10）</h2>{_hbars(cwe_rows)}
<p class="fine">NVDが付けた分類（CWE）ごとの件数。1件に複数の分類が付くことがあります。</p></section>
<section class="panel"><h2>製品の種類</h2>{_hbars(kind_rows)}
<p class="fine">NVDに製品情報がある {len(with_p)}件が対象です。種類は製品名から機械的に振り分けています。</p></section>
<section class="panel"><h2>開発元（上位10）</h2>{_hbars([(E(v), c) for v, c in vendor.most_common(10)])}
<p class="fine">NVDに製品情報がある {len(with_p)}件が対象です。</p></section>
<section class="panel wide"><h2>悪用が確認された件（新しい順）</h2>
{f'<div class="scroll"><table><tr><th>CVE番号</th><th>見出し</th><th>KEV追加日</th><th>対応期限</th></tr>{kev_rows}</table></div>' if kev_rows else '<p class="fine">該当する件はありません。</p>'}
<p class="fine">CISA KEVに載った {len(kev)}件のうち、ランサムウェアでの悪用が確認されているのは {ransom}件です。対応期限は米政府機関向けのものです。</p></section>
<section class="panel wide"><h2>悪用される確率の推定が高い件</h2>
{f'<div class="scroll"><table><tr><th>CVE番号</th><th>見出し</th><th>EPSS</th><th>CVSS</th></tr>{epss_rows}</table></div>' if epss_rows else '<p class="fine">該当する件はありません。</p>'}
<p class="fine">EPSSは、今後30日以内に悪用される確率をFIRSTが推定した値です。</p></section>
</div>'''
