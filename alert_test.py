"""メール通知の試験。

  python alert_test.py --to you@example.com --watch wordpress
      SMTPの設定が無ければ送信せず、文面を表示して alert_preview.eml に保存する。
      SMTPの設定（SMTP_HOST など）があれば、【テスト】付きで実際に送る。

  python alert_test.py --to you@example.com --watch wordpress --preview
      設定があっても送らず、文面だけ確認する。

  python alert_test.py --subscribers
      購読者一覧（SUBSCRIBERS_JSON か subscribers.json）の全員について、
      直近の実行結果（data/last_run.json）で誰に何件届くかを表示する。送信はしない。

掲載済みの記事（data/）から、--watch の言葉に合うものを最大3件選んで文面を作る。
合うものが無いときは、その旨を表示して最新の記事で代用する。
"""
import argparse
import json
import os
import sys

from pipeline import notify, store

ap = argparse.ArgumentParser()
ap.add_argument("--to")
ap.add_argument("--watch", nargs="+", default=[])
ap.add_argument("--min-cvss", type=float, default=0)
ap.add_argument("--config", default="config.json")
ap.add_argument("--data", default="data")
ap.add_argument("--preview", action="store_true")
ap.add_argument("--subscribers", action="store_true")
a = ap.parse_args()

with open(a.config, encoding="utf-8") as f:
    cfg = json.load(f)
items = {k: it for k, it in store.load_all(a.data).items() if store.visible(it, cfg)}
if not items:
    sys.exit(f"記事がありません。先に run.py を実行してください（{a.data}/ が空）。")


def as_event(it):
    last = it["timeline"][-1]
    return {"cve": it["id"], "kind": last["kind"], "changes": last["changes"] if last["kind"] == "update" else []}


if a.subscribers:
    subs = notify.load_subscribers()
    path = os.path.join(a.data, "last_run.json")
    events = json.load(open(path, encoding="utf-8"))["events"] if os.path.exists(path) else []
    print(f"購読者 {len(subs)}人 / 直近の出来事 {len(events)}件")
    for sub in subs:
        hit = [ev["cve"] for ev in events if ev["cve"] in items and notify._match(sub, items[ev["cve"]])]
        print(f'  {sub["email"]}  監視: {"、".join(sub.get("watch", []))}  → {len(hit)}件 {" ".join(hit)}')
    sys.exit(0)

if not a.to or not a.watch:
    sys.exit("--to と --watch を指定してください。例: --to you@example.com --watch wordpress")

sub = {"email": a.to, "watch": a.watch, "min_cvss": a.min_cvss}
ordered = sorted(items.values(), key=lambda i: i["updated"], reverse=True)
hits = [it for it in ordered if notify._match(sub, it)][:3]
if hits:
    print(f"条件に合う記事: {len(hits)}件（{' '.join(i['id'] for i in hits)}）")
else:
    hits = ordered[:2]
    print("条件に合う記事が無いため、最新の記事で代用します（本番ではこの条件だと通知は出ません）。")
msg = notify.build_mail(cfg, sub, [(it, as_event(it)) for it in hits], test=True)

if a.preview or not notify.smtp_ready():
    with open("alert_preview.eml", "wb") as f:
        f.write(msg.as_bytes())
    print(f"\n件名: {msg['Subject']}\n宛先: {msg['To']}\n差出人: {msg['From']}\n" + "-" * 40)
    print(msg.get_payload(decode=True).decode("utf-8"))
    print("-" * 40 + "\n送信はしていません。文面を alert_preview.eml に保存しました。")
    if not notify.smtp_ready():
        print("実際に送るには SMTP_HOST / SMTP_USER / SMTP_PASS / SMTP_FROM を設定してください。")
else:
    try:
        notify.send_mail(msg)
        print(f"送信しました: {a.to}")
    except Exception as e:
        sys.exit(f"送信に失敗しました: {e}")
