"""AIによる日本語要約と、その事実検証。

正確さのための決まり:
  1. AIには取得済みの事実データだけを渡し、そこに無いことは書かせない。
  2. 出力に出てくるCVE番号・数値・バージョン番号が、渡した事実データに
     実在するかを機械的に照合する。1つでも無ければその要約は捨てる。
  3. 捨てた場合やAPIキーが無い場合は、定型文の要約に切り替える。
"""
import json
import os
import re
import urllib.request

from .store import sev_ja

API_URL = "https://api.anthropic.com/v1/messages"

SYSTEM = """あなたは脆弱性情報の編集者です。渡されたJSONの事実だけを使い、日本の情シス担当者向けに日本語で要約します。
厳守事項:
- JSONに無い事実、数値、バージョン、製品名、攻撃者名、被害規模を書かない。推測しない。
- 分からない点は「公表されていません」と書く。
- 煽る表現（「今すぐ」「壊滅的」など）を使わない。
- 出力は次のキーだけを持つJSON1個。前後に文章を付けない。
  title: 40字以内の見出し（製品名と問題の種類が分かるもの。CVE番号は入れない）
  summary: 何が問題かを2〜3文で
  impact: 悪用されると何が起きるかを1〜2文で
  action: 利用者が取るべき対応を1〜2文で（修正版の番号はJSONにある場合のみ）"""

NUM = re.compile(r"CVE-\d{4}-\d+|\d+(?:\.\d+)+|\d{3,}")


def _facts_for_ai(it):
    f = it["facts"]
    return {
        "cve": it["id"],
        "description_en": f.get("desc_en", ""),
        "cvss": f.get("cvss"),
        "cwe": f.get("cwe"),
        "products": f.get("products"),
        "exploited_in_the_wild": f.get("kev"),
        "jvn_title_ja": (f.get("jvn") or {}).get("title"),
        "jvn_description_ja": (f.get("jvn") or {}).get("desc_ja"),
        "update_history": [c for t in it["timeline"] if t["kind"] == "update" for c in t["changes"]],
    }


def verify(out, facts_json):
    """出力中の番号・数値がすべて事実データにあるかを確かめる。"""
    for key in ("title", "summary", "impact", "action"):
        if not isinstance(out.get(key), str) or not out[key].strip():
            return False, f"{key} が空"
    if len(out["title"]) > 60:
        return False, "見出しが長すぎる"
    text = " ".join(out[k] for k in ("title", "summary", "impact", "action"))
    for tok in NUM.findall(text):
        if tok not in facts_json:
            return False, f"事実データに無い値: {tok}"
    return True, ""


def call_ai(model, payload):
    fx = os.environ.get("FIXTURES")
    if fx:  # 試験用: 用意した応答を返す（検証の動作確認に使う）
        with open(os.path.join(fx, "ai.json"), encoding="utf-8") as f:
            return json.load(f).get(json.loads(payload)["cve"], {})
    body = json.dumps({
        "model": model, "max_tokens": 700, "system": SYSTEM,
        "messages": [{"role": "user", "content": payload}],
    }).encode()
    req = urllib.request.Request(API_URL, data=body, headers={
        "content-type": "application/json",
        "x-api-key": os.environ["ANTHROPIC_API_KEY"],
        "anthropic-version": "2023-06-01"})
    with urllib.request.urlopen(req, timeout=60) as r:
        res = json.loads(r.read())
    text = "".join(b.get("text", "") for b in res.get("content", []))
    m = re.search(r"\{.*\}", text, re.S)
    return json.loads(m.group(0)) if m else {}


def template_summary(it):
    """AIを使わない定型の要約。事実データの値をそのまま並べるだけ。"""
    f = it["facts"]
    prods = "、".join(p["product"] for p in (f.get("products") or [])[:3])
    kev = f.get("kev") or {}
    name = prods or kev.get("product") or "対象製品"
    jvn_title = (f.get("jvn") or {}).get("title")
    title = jvn_title or f"{name} の脆弱性"
    c = f.get("cvss")
    sev = f"深刻度は{sev_ja(c['severity'])}（CVSS {c['score']}）です。" if c else "深刻度はまだ評価されていません。"
    summary = f"{name} に脆弱性が報告されました。{sev}"
    impact = "実際の攻撃での悪用が確認されています。" if kev else "影響の詳細は下の原文と出典を確認してください。"
    action = "開発元の案内を確認し、修正版への更新または回避策の適用を検討してください。"
    return {"title": title[:60], "summary": summary, "impact": impact, "action": action, "ai": False}


def run(items, cfg, save):
    model = cfg["ai"]["model"]
    limit = cfg["ai"].get("max_per_run", 40)
    fx = os.environ.get("FIXTURES")
    use_ai = bool(os.environ.get("ANTHROPIC_API_KEY")) or bool(fx and os.path.exists(os.path.join(fx, "ai.json")))
    done = rejected = 0
    for it in items.values():
        if not it.get("needs_summary"):
            continue
        out = None
        if use_ai and done < limit:
            payload = json.dumps(_facts_for_ai(it), ensure_ascii=False)
            try:
                cand = call_ai(model, payload)
                ok, why = verify(cand, payload)
                if ok:
                    out = {k: cand[k].strip() for k in ("title", "summary", "impact", "action")}
                    out["ai"] = True
                else:
                    rejected += 1
                    print(f"[info] {it['id']}: AI要約を不採用（{why}）")
            except Exception as e:
                print(f"[warn] {it['id']}: AI呼び出しに失敗（{e}）")
            done += 1
        if out is None:
            # 以前に検証済みのAI要約があれば、定型文で上書きせず残す
            if it.get("summary") and it["summary"].get("ai") and not use_ai:
                it["needs_summary"] = False
                save(it)
                continue
            out = template_summary(it)
        it["summary"] = out
        it["needs_summary"] = use_ai and not out["ai"] and done >= limit  # 上限超過分は次回に回す
        save(it)
    if use_ai:
        print(f"[info] AI要約 {done}件を処理（不採用 {rejected}件）")
