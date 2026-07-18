# 収集成果物のGit管理方針

最終更新: 2026-07-18

## Gitで管理するもの

- `data/vendors/<vendor>/advisories/<year>/<id>/advisory.json`: 個別アドバイザリJSON
- `data/vendors/<vendor>/advisories/<year>/<id>/summary.ja.md`: 任意のAI要約
- `data/vendors/<vendor>/index.json`: ベンダー別アドバイザリ一覧
- `state/sources/<source-id>.json`: ETag、最終取得時刻、既知IDなどの収集状態
- `reports/daily/<year>/<month>/<date>.md`: 日次レポート
- `reports/daily/<year>/<month>/<date>.summary.json`: 2つの表のAIサマリと生成メタデータ
- `quarantine/<source-id>/latest.json`: 収集・解析失敗の詳細
- `vulndb/index.csv`: CVE単位の脆弱性台帳の全体索引
- `vulndb/vulns/<vendor>/<year>/<month>/<内部ID>.yaml`: 脆弱性ごとの台帳エントリ（年・月は最初に観測した`created_at`）
- `vulndb/registry.json`: 台帳の採番・索引状態
- `run-manifest.json`: 最新収集の変更記録
- `run-summary.md`: 最新収集の実行サマリ

検証済みの生成成果物はすべてGitで管理し、最終的に定期実行で`main`へ反映されます。`staging/`
だけは同じ成果物の複製とローカル開発履歴を含む一時作業領域なので、Git管理対象外です。
`.env`、仮想環境、テスト・解析ツールのcacheも従来どおり除外します。

## 定期実行のフロー（Actions収集 → routine処理 → 自動マージ）

定期収集はAI処理を持たない収集と、後続処理を分担します。

1. `.github/workflows/collect-advisories.yml`（毎朝04:00 JST）が全ソースを収集し、生ツリー
   （`data`、`state`、`quarantine`、`vulndb`、manifest、summary）を `bot/collected-raw` へ
   commitする。`vulnwatch publish`は使わず、レポート生成前の生ツリーをそのまま渡す。
2. 同workflowがWebhookで Claude Code の routine を起動し、収集ブランチとコミットSHAを渡す。
3. routine が収集ツリーをstagingへ展開し、`summarize`（Claudeが日本語サマリを代筆）→
   `report` → `validate` → `publish` を実行し、`bot/vulnwatch-daily` へpushする。
4. `.github/workflows/auto-merge-daily.yml` が構文チェック・ユニットテスト・`vulnwatch validate`
   を通したうえで、`bot/vulnwatch-daily → main` のPRを作成してマージする。

## ローカルでの更新

```bash
vulnwatch collect --profile daily --since 90d --output staging
vulnwatch summarize --root staging
vulnwatch report --root staging \
  --critical-summary '<Critical全件の日本語AIサマリ>' \
  --exploitation-summary '<悪用済み・PoC公開済みの日本語AIサマリ>'
vulnwatch validate --root staging
vulnwatch publish --root staging --repository .
```

新規・更新・取り下げ変更が0件の場合は、2つのサマリオプションを付けずに定型的な変更なし
レポートを生成し、日次サマリsidecarは不要です。

`publish`は必要な生成パスが欠けている場合やsymbolic linkを含む場合は失敗します。全ファイルを
一時領域へコピーしてから入れ替え、途中で失敗した場合は既存成果物へ戻します。
`staging/history/`などallowlist外のローカルファイルは公開しません。

## 収集成果物の規模

件数は日次収集のたびに増えます。目安（有効80ソース時点）:

- ベンダー別一覧: 約56ファイル
- 個別アドバイザリJSON: 約1,000ファイル（増加）
- 収集状態: 80ファイル（有効ソース数と一致）
- vulndb台帳エントリ: 約2,100ファイル（`vulns/<vendor>/<year>/<month>/` 配下、増加）
- 日次レポートと対象変更ありの日のAIサマリsidecar

vulndbはベンダー・年・月でフォルダ分けするため、1フォルダあたりのファイル数はGitHubの
一覧表示上限（1,000）を下回るよう分散します。
