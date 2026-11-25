# vulnwatch（脆弱性ウォッチ）作業メモ

公的データベースの脆弱性情報を毎時取得し、AIで日本語に要約して、続報は同じページに追記する静的サイト。
公開先: https://vulnwatch.pages.dev/ （GitHub Actions → Cloudflare Pages）。仕組みと設定は README.md を参照。

## 作業時の決まり

- GitHub Actions が毎時7分に `data/` を main へ自動コミットする。プッシュの前に必ず `git pull --rebase`。
- `data/` は手で編集しない。`public/` は生成物（Git管理外）。
- APIキーやトークン、購読者のメールアドレスはリポジトリに入れない（GitHubのSecretsに置く）。
- 記事の材料は一次情報（NVD / CISA KEV / JVN iPedia / EPSS）だけ。他サイトの記事は使わない。
- 追記の文面は `pipeline/store.py` の差分から機械的に作る。AIに書かせない。
- AI要約は `pipeline/summarize.py` の `verify()` で数値照合を通ったものだけ載せる。この照合を弱めない。

## 手元での確認（ネットワーク不要）

    FIXTURES=fixtures/run1 NOW=2099-01-10T06:00:00+00:00 python run.py --config config.demo.json --data /tmp/vw/data --out /tmp/vw/public --no-notify
    FIXTURES=fixtures/run2 NOW=2099-01-10T10:00:00+00:00 python run.py --config config.demo.json --data /tmp/vw/data --out /tmp/vw/public --no-notify

2回目で CVE-2099-0002 に追記が入り、CVE-2099-0003 のAI要約が不採用になれば正常。
本番の `data/` を汚さないよう、試験では必ず `--data` を別の場所にする。

## 現在の状態（2026-11-25）

- 取得、追記、サイト生成、Cloudflareへの公開: 本番で動作確認済み
- 掲載基準: CVSS 7.0以上、または悪用確認済み（`store.visible()`）
- AI要約: `ANTHROPIC_API_KEY` が未登録のため定型文。実際のAPI呼び出しは未確認
- SNS投稿（Bluesky / X）、メール通知の実送信: 未設定・未確認
- スポンサー枠: 非表示（`config.json` の `sponsor.enabled`）

## 残っている作業

1. 更新後の実行ログで `掲載 ○件（基準外で非掲載 ○件）` を確認する
2. Secrets に `ANTHROPIC_API_KEY` を登録し、ログの `[info] AI要約 ○件を処理` と不採用の件数を確認する
3. メール通知を `alert_test.py` で試す（SMTPの設定が必要）
4. 決済（Stripe）から購読者一覧への自動反映を作る（現状は `SUBSCRIBERS_JSON` を手で更新）
5. `tokushoho.html` の文面を記入する（`pipeline/build.py` 内）
6. 製品名の大文字小文字を直す（CPE由来で `Vpn` `Ffmpeg` のようになる）
7. 独自ドメイン、広告、紹介リンクの設定
