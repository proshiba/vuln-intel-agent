# 収集成果物のGit管理方針

最終更新: 2026-07-17

## Gitで管理するもの

- `data/vendors/<vendor>/index.json`: ベンダー別アドバイザリ一覧
- `reports/daily/<year>/<month>/<date>.md`: 日次レポート

これらはGitHub Actionsの定期収集後、bot branchへcommitされ、PRとして公開されます。

## Gitで管理しないもの

- `data/**/advisories/`: 個別アドバイザリJSON
- `state/`: ETag、最終取得時刻、既知IDなどのruntime状態
- `quarantine/`: 収集・解析失敗の詳細
- `staging/`: 生成途中の全データ、manifest、ローカル開発履歴

管理対象外のデータは`.gitignore`で除外します。個別データや障害詳細をGitHubへ公開せず、
人が確認する一覧と日次レポートだけを履歴管理するための方針です。

## 公開workflow

`.github/workflows/collect-advisories.yml`のpublish jobは次を行います。

1. stagingの生成ツリー全体を検証する。
2. `staging/data/vendors/**/index.json`だけを`data/`へコピーする。
3. `staging/reports/`を`reports/`へコピーする。
4. 過去に追跡されていた`state/`と`quarantine/`があれば削除対象にする。
5. `data`と`reports`の差分だけを含むbot PRを作成する。

## ローカルでの更新

```bash
vulnwatch collect --profile daily --since 90d --output staging
vulnwatch report --root staging
vulnwatch validate --root staging
```

検証後、ベンダー別`index.json`と`reports/`だけをリポジトリ直下へ反映します。

## 現在の収集成果物

- ベンダー別一覧: 35ファイル
- 日次レポート: `reports/daily/2026/07/2026-07-17.md`
- 個別アドバイザリJSON: Git管理対象には0件
