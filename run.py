"""1回分の更新を実行する: 取得 → 統合と追記 → AI要約 → サイト生成 → 投稿と通知

使い方:
  python run.py                      本番の取得元から取得
  FIXTURES=fixtures/run1 python run.py --config config.demo.json   サンプルで試す
"""
import argparse
import json
import os

from pipeline import build, notify, sources, store, summarize

ap = argparse.ArgumentParser()
ap.add_argument("--config", default="config.json")
ap.add_argument("--data", default="data")
ap.add_argument("--out", default="public")
ap.add_argument("--no-notify", action="store_true")
a = ap.parse_args()

with open(a.config, encoding="utf-8") as f:
    cfg = json.load(f)

now = sources.utcnow()
os.makedirs(a.data, exist_ok=True)
known = set(store.load_all(a.data))
collected = sources.collect(now, cfg, known)
events = store.merge(a.data, collected, now)
stored = store.load_all(a.data)
items = {k: it for k, it in stored.items() if store.visible(it, cfg)}  # 基準外は保存だけして載せない
summarize.run(items, cfg, lambda it: store.save(a.data, it))
n_items, n_prod = build.build(a.data, a.out, cfg, items, now)
new = sum(1 for e in events if e["kind"] == "new")
print(f"[done] 取得 {len(collected)}件 / 新着 {new}件 / 追記 {len(events) - new}件 / 掲載 {n_items}件（基準外で非掲載 {len(stored) - len(items)}件） / 製品ページ {n_prod}")
if not a.no_notify:
    notify.social(a.data, cfg, items, events)
    notify.alerts(cfg, items, events)
