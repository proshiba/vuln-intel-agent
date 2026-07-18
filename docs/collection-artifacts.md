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
- `run-manifest.json`: 最新収集の変更記録
- `run-summary.md`: 最新収集の実行サマリ

検証済みの生成成果物はすべてGitHub Actionsの定期収集後にbot branchへcommitされ、PRとして
公開されます。`staging/`だけは同じ成果物の複製とローカル開発履歴を含む一時作業領域なので、
Git管理対象外です。`.env`、仮想環境、テスト・解析ツールのcacheも従来どおり除外します。

## 公開workflow

`.github/workflows/collect-advisories.yml`のpublish jobは次を行います。

1. stagingの生成ツリー全体を検証する。
2. `vulnwatch publish`でallowlist化した全成果物をリポジトリ直下へ同期する。
3. `data`、`reports`、`state`、`quarantine`、manifest、summaryをすべてstageする。
4. advisoryの意味的変更がなくても、状態・レポート・実行情報の実差分があればcommitする。
5. 未mergeでopen中のbot PRにある最新成果物を検証し、互換性があれば次回収集の基準として
   復元する。旧形式など現行検証に適合しない場合は警告を出して復元をスキップする。

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

## 現在の収集成果物

- ベンダー別一覧: 56ファイル
- 個別アドバイザリJSON: 827ファイル
- 収集状態: 80ファイル
- 日次レポート: 2ファイル
- 日次レポートAIサマリ: 1ファイル
- Git管理する生成ファイル: 969ファイル（空のquarantineを保持する`.gitkeep`を含む）
