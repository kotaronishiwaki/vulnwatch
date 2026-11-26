"""記事データの保存と、同一件の統合・更新履歴の追記。

1つのCVE = 1つのファイル（data/items/CVE-xxxx-nnnn.json）= 1つのページ。
続報が来たら新しい記事を作らず、同じファイルの timeline に追記する。
追記の文面はAIに書かせず、数値の差分から機械的に作る（誤りを入れないため）。
"""
import json
import os

SEV_JA = {"CRITICAL": "緊急", "HIGH": "重要", "MEDIUM": "警告", "LOW": "注意"}


def sev_ja(sev):
    return SEV_JA.get((sev or "").upper(), "未評価")


def public_url(cfg, path=""):
    """公開先でのURL。Cloudflare Pages は .html つきのURLを拡張子なしへ転送するので、
    外へ出すURL（canonical、サイトマップ、RSS、SNS、メール、AI向けデータ）は外した形で書く。
    サイト内のリンクは、手元でファイルを直接開いても動くよう .html のままにしている。"""
    if path.endswith(".html"):
        path = path[:-5]
    if path == "index":
        path = ""
    return cfg["site_url"].rstrip("/") + "/" + path


def item_path(root, cve):
    return os.path.join(root, "items", f"{cve}.json")


def load_all(root):
    d = os.path.join(root, "items")
    out = {}
    if not os.path.isdir(d):
        return out
    for fn in os.listdir(d):
        if fn.endswith(".json"):
            with open(os.path.join(d, fn), encoding="utf-8") as f:
                it = json.load(f)
                out[it["id"]] = it
    return out


def save(root, item):
    os.makedirs(os.path.join(root, "items"), exist_ok=True)
    with open(item_path(root, item["id"]), "w", encoding="utf-8") as f:
        json.dump(item, f, ensure_ascii=False, indent=1, sort_keys=True)


def _merge_facts(old, new):
    """空の値で既存の値を消さない。参考リンクと製品は足し合わせる。"""
    out = dict(old)
    for k, v in new.items():
        if v in (None, "", [], {}):
            continue
        if k == "refs":
            out[k] = (old.get(k) or []) + [u for u in v if u not in (old.get(k) or [])]
        elif k == "products":
            have = {(p["vendor"], p["product"]) for p in old.get(k) or []}
            out[k] = (old.get(k) or []) + [p for p in v if (p["vendor"], p["product"]) not in have]
        else:
            out[k] = v
    return out


def diff(old, new):
    """事実の差分を、追記用の日本語の文にする。返り値: (文のリスト, 重大な変化か)"""
    ch, major = [], False
    oc, nc = old.get("cvss"), new.get("cvss")
    if nc and not oc:
        ch.append(f"CVSSスコア {nc['score']}（{sev_ja(nc['severity'])}）が付与されました。")
        major = major or nc["score"] >= 9.0
    elif nc and oc and nc["score"] != oc["score"]:
        ch.append(f"CVSSスコアが {oc['score']} から {nc['score']}（{sev_ja(nc['severity'])}）に変更されました。")
        major = major or (nc["score"] > oc["score"] and nc["score"] >= 9.0)
    ok, nk = old.get("kev"), new.get("kev")
    if nk and not ok:
        due = f"米政府機関の対応期限は {nk['due']} です。" if nk.get("due") else ""
        ch.append(f"CISAが実際の攻撃での悪用を確認しました（{nk['added']} にKEVへ追加）。{due}")
        major = True
    if nk and nk.get("ransomware") and not (ok or {}).get("ransomware"):
        ch.append("ランサムウェア攻撃での悪用が確認されています。")
        major = True
    if new.get("jvn") and not old.get("jvn"):
        ch.append(f"JVNが日本語の情報を公開しました（{new['jvn']['id']}）。")
    if old.get("desc_en") and new.get("desc_en") and old["desc_en"] != new["desc_en"]:
        ch.append("公式の説明文が更新されました。")
    added = [u for u in new.get("refs") or [] if u not in (old.get("refs") or [])]
    if added and old.get("refs"):
        ch.append(f"参考情報が {len(added)} 件追加されました。")
    have = {(p["vendor"], p["product"]) for p in old.get("products") or []}
    newp = [p for p in new.get("products") or [] if (p["vendor"], p["product"]) not in have]
    if newp and old.get("products"):
        ch.append("対象製品に " + "、".join(p["product"] for p in newp[:4]) + " が追加されました。")
    oe, ne = (old.get("epss") or {}).get("score", 0), (new.get("epss") or {}).get("score", 0)
    if ne >= 0.1 and ne - oe >= 0.1:  # 日々の小さな揺れは追記しない
        ch.append(f"悪用される確率の推定（EPSS）が {oe * 100:.0f}% から {ne * 100:.0f}% に上がりました。")
    return ch, major


def is_major_new(facts):
    score = (facts.get("cvss") or {}).get("score") or 0
    return bool(facts.get("kev")) or score >= 9.0


def visible(item, cfg):
    """サイトに載せる件か。CVSSが基準以上、または悪用確認済み（KEV）のものだけ載せる。

    基準外の件も data/ には残す。後からスコアが上がるかKEVに入れば、その時点で掲載される。
    """
    f = item["facts"]
    score = (f.get("cvss") or {}).get("score") or 0
    return bool(f.get("kev")) or score >= cfg.get("filters", {}).get("min_cvss", 7.0)


def merge(root, collected, now):
    """取得した事実を保存データへ反映する。返り値: 今回の出来事のリスト"""
    items = load_all(root)
    events = []
    stamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    for cve, facts in sorted(collected.items()):
        if cve in items:
            it = items[cve]
            merged = _merge_facts(it["facts"], facts)
            changes, major = diff(it["facts"], merged)
            it["facts"] = merged
            if changes:
                it["timeline"].append({"at": stamp, "kind": "update", "changes": changes})
                it["updated"] = stamp
                it["needs_summary"] = True
                events.append({"cve": cve, "kind": "update", "changes": changes, "major": major})
            save(root, it)
        else:
            if not facts.get("desc_en") and not facts.get("jvn"):
                continue  # 本体の情報がまだ無い件は、情報が出てから載せる
            it = {"id": cve, "facts": facts, "first_seen": stamp, "updated": stamp,
                  "timeline": [{"at": stamp, "kind": "new", "changes": ["初回掲載。"]}],
                  "summary": None, "needs_summary": True}
            save(root, it)
            events.append({"cve": cve, "kind": "new", "changes": [], "major": is_major_new(facts)})
    with open(os.path.join(root, "last_run.json"), "w", encoding="utf-8") as f:
        json.dump({"at": stamp, "events": events}, f, ensure_ascii=False, indent=1)
    return events
