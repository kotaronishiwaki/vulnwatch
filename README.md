# 脆弱性ウォッチ（試作）

公的データベースの脆弱性情報を1時間ごとに取得し、AIで日本語に要約して、
続報は同じページに追記する静的サイトの一式です。

## 仕組み

    取得 (NVD / CISA KEV / JVN iPedia / EPSS)
      → 統合と追記判定 (1つのCVE = 1ファイル = 1ページ)
      → AI要約 + 数値の機械照合
      → 静的サイト生成 (public/)
      → SNS投稿・有料メール通知

| ファイル | 役割 |
|---|---|
| `run.py` | 1回分の更新を実行 |
| `pipeline/sources.py` | 取得と正規化 |
| `pipeline/store.py` | 保存、同一件の統合、更新履歴の追記文の生成 |
| `pipeline/summarize.py` | AI要約と事実照合、定型文への切り替え |
| `pipeline/build.py` | サイト生成（記事、製品別、月別、RSS、サイトマップ、共有画像） |
| `pipeline/notify.py` | Bluesky / X への投稿、購読者へのメール |
| `config.json` | サイト名、掲載基準、広告、紹介リンク、決済リンク |
| `.github/workflows/update.yml` | 毎時の自動実行と公開 |

## まず手元で試す

    FIXTURES=fixtures/run1 NOW=2099-01-10T06:00:00+00:00 python run.py --config config.demo.json
    FIXTURES=fixtures/run2 NOW=2099-01-10T10:00:00+00:00 python run.py --config config.demo.json

2回目で CVE-2099-0002 に追記が入ります。`public/index.html` を開いて確認できます。
（fixtures の製品名とCVE番号は架空です。試したあとは `data/` を消してください。）

## 本番にする手順

1. GitHubにリポジトリを作ってこの一式を置く。**公開リポジトリ**ならActionsの実行時間は無料。
   非公開だと毎時実行で無料枠（月2,000分）に近づきます。
2. Cloudflare Pages でプロジェクトを作り（Direct Upload）、独自ドメインを付ける。
3. `config.json` の `site_name` と `site_url` を書き換える。
4. リポジトリの Settings → Secrets に登録:
   - 必須: `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`（Variables に `CF_PAGES_PROJECT`）
   - AI要約: `ANTHROPIC_API_KEY`（無いと定型文の要約になります）
   - 推奨: `NVD_API_KEY`（無料。無いと取得が遅い）
   - 拡散: `BSKY_HANDLE`, `BSKY_APP_PASSWORD` / `X_API_KEY`, `X_API_SECRET`, `X_ACCESS_TOKEN`, `X_ACCESS_SECRET`
   - 有料通知: `SUBSCRIBERS_JSON`, `SMTP_HOST`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM`
5. Actions タブから `update` を手動で1回実行する。以後は毎時7分に動きます。

## 収益の設定（config.json）

- **広告**: `ads.adsense_client` と各 `slot_*` を入れると一覧と記事下に表示。
- **紹介リンク**: `affiliate` に、製品名のキーワード（`match`）とリンクを登録。
  一致した記事にだけ「PR」表示つきで出ます。`default: true` は一致が無いときの既定。
- **有料メール通知**: 初期状態では非表示です。出すときは `alerts.enabled` を `true` にし、
  Stripe の Payment Link を `payments.alert_link` に入れる。
  購読者は `SUBSCRIBERS_JSON` に `[{"email":"…","watch":["wordpress"],"min_cvss":7.0}]` の形で登録。
- **寄付**: `payments.donate_link`。
- **スポンサー枠**: 初期状態では非表示です。出すときに `sponsor.enabled` を `true` にし、
  `payments.sponsor_link` を入れます。掲載する社名は `sponsor` に記入。
- 有料販売を始める前に `tokushoho.html`（特定商取引法に基づく表記）の中身を埋めてください。
  文面は `pipeline/build.py` にあります。

## メール通知を試す

文面だけ確認（送信しない）:

    python alert_test.py --to you@example.com --watch wordpress

`alert_preview.eml` に保存されるので、メールソフトで開いて見た目も確認できます。

自分宛てに実際に送る（件名に【テスト】が付きます）:

    export SMTP_HOST=smtp.example.com SMTP_USER=… SMTP_PASS=… SMTP_FROM=alerts@example.com
    python alert_test.py --to you@example.com --watch wordpress

587番ポートのサーバーなら `SMTP_SECURITY=starttls` を追加します（既定は465番のSSL）。

GitHub上から送る: Actions → update → Run workflow で、送り先と製品名を入力して実行。

購読者ごとの届き方を確認（送信しない）:

    python alert_test.py --subscribers

手元では `subscribers.json`（Gitには入りません）に購読者を書いて試せます。

## 確認できていること / いないこと

確認済み（サンプルデータで実行）:
- 新着の掲載、続報の追記、変化が無いときに追記が増えないこと
- AI要約のうち、出典に無い数値を含むものが不採用になること
- メール通知の作成と送信（手元に立てた試験用メールサーバーで受信を確認）
- スマホ幅（390px）とPC幅で横スクロールが出ないこと

未確認（この環境からは外部に接続できないため）:
- NVD / KEV / JVN / EPSS への実際の接続と、現在の応答形式との一致
- Anthropic API の実呼び出し、Bluesky / X への実投稿、実際のメールサービス経由の送信、Cloudflare への公開

初回の手動実行でログを見て、取得件数が0でないことを確かめてください。

## 既知の制約

- 購読者の登録は手作業です（Stripeの決済通知から `SUBSCRIBERS_JSON` へ自動反映する処理は未実装）。
- 製品名はCPEという識別子から作るため、`Vpn` のように大文字小文字が不自然になることがあります。
- CVSSがまだ付いていない新しいCVEは、スコアが7.0以上になるかKEVに載るまで掲載されません（JVNにだけ載った件は `data/` に保存され、基準を満たした時点で掲載されます）。
- GitHub Actionsの定時実行は混雑時に数分〜数十分遅れることがあります。
- 各取得元の利用条件（特にJVN iPediaの商用利用と、Xの投稿APIの料金・回数）は公開前に確認してください。
