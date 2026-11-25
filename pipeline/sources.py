"""一次情報の取得と正規化。

取得元:
  - NVD (CVE API 2.0)          … CVEの本体、CVSS、対象製品、参考リンク
  - CISA KEV                   … 実際の攻撃で悪用が確認された脆弱性
  - JVN iPedia (新着RSS)       … 日本語の題名と国内向け情報
  - FIRST EPSS                 … 今後30日以内に悪用される確率の推定

環境変数 FIXTURES にフォルダを指定すると、ネットワークに出ずに
そのフォルダの nvd.json / kev.json / jvn.rdf / epss.json を読む（試験用）。
"""
import json
import os
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

UA = "vulnwatch/0.1 (+static site generator)"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
JVN_URL = "https://jvndb.jvn.jp/ja/rss/jvndb_new.rdf"
EPSS_URL = "https://api.first.org/data/v1/epss"


def _fixture(name):
    d = os.environ.get("FIXTURES")
    if not d:
        return None
    p = os.path.join(d, name)
    if not os.path.exists(p):
        return b""
    with open(p, "rb") as f:
        return f.read()


def http_get(url, headers=None, tries=3, timeout=40):
    h = {"User-Agent": UA}
    h.update(headers or {})
    last = None
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers=h)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except Exception as e:  # 取得失敗は次回の実行で取り戻せるので握って続行する
            last = e
            time.sleep(4 * (i + 1))
    print(f"[warn] 取得失敗 {url}: {last}")
    return b""


# ---------- NVD ----------

def _pick_cvss(metrics):
    for key, ver in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"),
                     ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        arr = metrics.get(key) or []
        if not arr:
            continue
        arr = sorted(arr, key=lambda m: 0 if m.get("type") == "Primary" else 1)
        m = arr[0]
        d = m.get("cvssData", {})
        score = d.get("baseScore")
        if score is None:
            continue
        sev = (d.get("baseSeverity") or m.get("baseSeverity") or "").upper()
        return {"score": float(score), "severity": sev,
                "vector": d.get("vectorString", ""), "version": ver}
    return None


def _products(cve):
    out, seen = [], set()
    for conf in cve.get("configurations") or []:
        for node in conf.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                if not m.get("vulnerable", True):
                    continue
                parts = m.get("criteria", "").split(":")
                if len(parts) < 5:
                    continue
                vendor, product = parts[3], parts[4]
                key = (vendor, product)
                if key in seen or product in ("*", "-"):
                    continue
                seen.add(key)
                out.append({"vendor": vendor.replace("_", " ").title(),
                            "product": product.replace("_", " ").title()})
    return out[:8]


def norm_nvd(v):
    c = v.get("cve", {})
    if c.get("vulnStatus") == "Rejected":
        return None
    desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
    cwes = []
    for w in c.get("weaknesses") or []:
        for d in w.get("description") or []:
            val = d.get("value", "")
            if val.startswith("CWE-") and val not in cwes:
                cwes.append(val)
    refs = []
    for r in c.get("references") or []:
        u = r.get("url")
        if u and u not in refs:
            refs.append(u)
    return {
        "cve": c.get("id"),
        "published": c.get("published"),
        "modified": c.get("lastModified"),
        "desc_en": desc.strip(),
        "cvss": _pick_cvss(c.get("metrics") or {}),
        "cwe": cwes[:3],
        "products": _products(c),
        "refs": refs[:15],
    }


def fetch_nvd(since, until):
    fx = _fixture("nvd.json")
    if fx is not None:
        raw = json.loads(fx or b'{"vulnerabilities":[]}')
        return [n for n in (norm_nvd(v) for v in raw.get("vulnerabilities", [])) if n]
    headers = {}
    if os.environ.get("NVD_API_KEY"):
        headers["apiKey"] = os.environ["NVD_API_KEY"]
    out, start = [], 0
    fmt = "%Y-%m-%dT%H:%M:%S.000+00:00"
    while True:
        q = urllib.parse.urlencode({
            "lastModStartDate": since.strftime(fmt),
            "lastModEndDate": until.strftime(fmt),
            "resultsPerPage": 2000, "startIndex": start})
        body = http_get(f"{NVD_URL}?{q}", headers)
        if not body:
            break
        raw = json.loads(body)
        out += [n for n in (norm_nvd(v) for v in raw.get("vulnerabilities", [])) if n]
        start += raw.get("resultsPerPage", 0)
        if start >= raw.get("totalResults", 0) or not raw.get("resultsPerPage"):
            break
        time.sleep(1 if headers else 6)  # NVDの利用制限に合わせる
    return out


def fetch_nvd_by_id(cve_id):
    fx = _fixture("nvd.json")
    if fx is not None:
        for n in fetch_nvd(None, None):
            if n["cve"] == cve_id:
                return n
        return None
    headers = {}
    if os.environ.get("NVD_API_KEY"):
        headers["apiKey"] = os.environ["NVD_API_KEY"]
    body = http_get(f"{NVD_URL}?cveId={urllib.parse.quote(cve_id)}", headers)
    time.sleep(1 if headers else 6)
    if not body:
        return None
    vs = json.loads(body).get("vulnerabilities", [])
    return norm_nvd(vs[0]) if vs else None


# ---------- CISA KEV ----------

def fetch_kev(now, days=14):
    fx = _fixture("kev.json")
    body = fx if fx is not None else http_get(KEV_URL)
    if not body:
        return {}
    cutoff = (now - timedelta(days=days)).strftime("%Y-%m-%d")
    out = {}
    for v in json.loads(body).get("vulnerabilities", []):
        if v.get("dateAdded", "") < cutoff:
            continue
        out[v["cveID"]] = {
            "added": v.get("dateAdded"),
            "due": v.get("dueDate"),
            "ransomware": v.get("knownRansomwareCampaignUse", "") == "Known",
            "name": v.get("vulnerabilityName", ""),
            "vendor": v.get("vendorProject", ""),
            "product": v.get("product", ""),
            "action": v.get("requiredAction", ""),
        }
    return out


# ---------- JVN iPedia ----------

def _local(tag):
    return tag.rsplit("}", 1)[-1]


def fetch_jvn():
    fx = _fixture("jvn.rdf")
    body = fx if fx is not None else http_get(JVN_URL)
    if not body:
        return {}
    try:
        root = ET.fromstring(body)
    except ET.ParseError as e:
        print(f"[warn] JVNの解析に失敗: {e}")
        return {}
    out = {}
    for el in root.iter():
        if _local(el.tag) != "item":
            continue
        rec = {"id": "", "title": "", "url": "", "desc_ja": "", "cves": []}
        for ch in el:
            name = _local(ch.tag)
            text = (ch.text or "").strip()
            if name == "title":
                rec["title"] = text
            elif name == "link":
                rec["url"] = text
            elif name == "description":
                rec["desc_ja"] = text
            elif name == "identifier":
                rec["id"] = text
            elif name == "references":
                rid = ch.attrib.get("id", "")
                if rid.startswith("CVE-"):
                    rec["cves"].append(rid)
        for cve in rec["cves"]:
            out[cve] = {k: rec[k] for k in ("id", "title", "url", "desc_ja")}
    return out


# ---------- EPSS ----------

def fetch_epss(cves):
    fx = _fixture("epss.json")
    out = {}
    if fx is not None:
        for d in json.loads(fx or b'{"data":[]}').get("data", []):
            if d["cve"] in cves:
                out[d["cve"]] = {"score": float(d["epss"]), "percentile": float(d["percentile"])}
        return out
    cves = sorted(cves)
    for i in range(0, len(cves), 80):
        body = http_get(f"{EPSS_URL}?cve={','.join(cves[i:i + 80])}")
        if not body:
            continue
        for d in json.loads(body).get("data", []):
            out[d["cve"]] = {"score": float(d["epss"]), "percentile": float(d["percentile"])}
    return out


# ---------- まとめて取得 ----------

def collect(now, cfg, known_ids):
    """今回の実行で扱うCVEごとの事実データを返す。 {cve: facts}"""
    f = cfg["filters"]
    since = now - timedelta(hours=f.get("lookback_hours", 6))
    nvd = {n["cve"]: n for n in fetch_nvd(since, now)}
    kev = fetch_kev(now)
    jvn = fetch_jvn()

    wanted = {}
    for cve, n in nvd.items():
        score = (n.get("cvss") or {}).get("score") or 0
        if cve in known_ids or score >= f.get("min_cvss", 7.0) or cve in kev or cve in jvn:
            wanted[cve] = n
    # KEVやJVNにだけ出てきた件はNVDから本体を引く（1回の実行あたり上限つき）
    extra = [c for c in list(kev) + list(jvn) if c not in wanted]
    budget = f.get("max_extra_lookups", 20)
    for cve in extra:
        if cve in known_ids:
            wanted[cve] = {"cve": cve}  # 既存の記事に差分だけ足す
            continue
        if budget <= 0:
            break
        if cve in jvn and cve not in kev and not f.get("include_jvn_only", True):
            continue
        n = fetch_nvd_by_id(cve)
        budget -= 1
        wanted[cve] = n or {"cve": cve}

    epss = fetch_epss(set(wanted))
    for cve, facts in wanted.items():
        if cve in kev:
            facts["kev"] = kev[cve]
        if cve in jvn:
            facts["jvn"] = jvn[cve]
        if cve in epss:
            facts["epss"] = epss[cve]
    return wanted


def utcnow():
    if os.environ.get("NOW"):
        return datetime.fromisoformat(os.environ["NOW"]).astimezone(timezone.utc)
    return datetime.now(timezone.utc)
