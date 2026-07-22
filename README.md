# vulnwatch

vulnwatch は、ベンダー公式サイトや公的データベースから脆弱性アドバイザリを収集し、共通形式の JSON、CVE 単位の台帳、日本語の日次レポートを生成する Python 3.12 製 CLI ツールです。

このリポジトリには、ツール本体に加えて、収集済みデータ、日次レポート、収集状態、CVE 単位の脆弱性台帳が入っています。

## インストール

Python 3.12 を用意し、リポジトリ直下で仮想環境を作成します。

```bash
python -m venv .venv
.venv/bin/python -m pip install -e '.[dev,ai,browser]'
.venv/bin/python -m playwright install --with-deps chromium
```

- `browser` extra と Chromium は、ブラウザでページを取得する収集ソースに必要です。
- PDF 収集を使う場合は、必要に応じて `.[pdf]` も追加してください。
- GitHub API を使う収集では、レート制限を避けるため読み取り専用トークンを環境変数に設定します。

```bash
export GH_TOKEN="..."
# または
export GITHUB_TOKEN="..."
```

GitHub API を使わず OSV 経由で GitHub Advisory 系の情報を取得したい場合は、次の環境変数を設定します。

```bash
export VULNWATCH_GITHUB_BACKEND=osv
```

AI による日本語要約を自動生成する場合は、OpenAI API キーとモデル名を設定します。

```bash
export OPENAI_API_KEY="..."
export LLM_MODEL="..."
```

## 基本的な使い方

まず設定を検証します。

```bash
.venv/bin/vulnwatch config validate
```

日次収集は、リポジトリ直下ではなく一時ディレクトリ `staging/` に生成します。

```bash
.venv/bin/vulnwatch collect --profile daily --since 90d --output staging
```

収集後は、`staging/run-manifest.json` の `source_outcomes` を確認します。対象ソースごとに 1 件の outcome があり、`status` が `success` または `not_modified` であれば正常です。`failed`、`partial`、欠落がある場合は、`quarantine/<source-id>/latest.json` と outcome の `endpoint`、`count`、`error` を確認してから再実行してください。

AI 要約を生成します。

```bash
.venv/bin/vulnwatch summarize --root staging
```

日次レポートを生成します。

```bash
.venv/bin/vulnwatch report --root staging
```

AI 要約を手動で指定する場合は、Critical 表と「悪用済み・PoC 公開済み」表の 2 つを同時に渡します。

```bash
.venv/bin/vulnwatch report --root staging \
  --critical-summary '<Critical全件の日本語サマリ>' \
  --exploitation-summary '<悪用済み・PoC公開済みの日本語サマリ>'
```

生成物を検証します。

```bash
.venv/bin/vulnwatch validate --root staging
```

検証済みの生成物をリポジトリ直下へ反映します。

```bash
.venv/bin/vulnwatch publish --root staging --repository .
```

## CLI コマンド

| コマンド | 用途 |
|---|---|
| `vulnwatch config validate` | `config/sources.yaml` と `config/products.yaml` を検証します。 |
| `vulnwatch collect --profile daily --since 90d --output staging` | 有効な収集ソースから脆弱性情報を取得し、`staging/` に保存します。 |
| `vulnwatch summarize --root staging` | 個別アドバイザリと日次レポート用の日本語 AI 要約を生成します。 |
| `vulnwatch report --root staging` | 収集結果から Markdown の日次レポートを生成します。 |
| `vulnwatch validate --root staging` | 生成ツリー、収集完全性、レポート、台帳を検証します。 |
| `vulnwatch publish --root staging --repository .` | 検証済み生成物をリポジトリ直下の公開用パスへ同期します。 |
| `vulnwatch source test <source-id> --fixture <file>` | fixture を使って特定ソースのパース結果を確認します。 |

## 収集されるデータ

現在の daily profile は、ベンダー公式アドバイザリ、CSAF、RSS/Atom feed、HTML、JSON API、NVD、OSV、CISA KEV などを対象にします。収集結果は次の形式で保存されます。

| パス | 内容 |
|---|---|
| `data/vendors/<vendor>/advisories/<year>/<id>/advisory.json` | 正規化済みの個別アドバイザリ。CVE、製品、深刻度、修正版、出典 URL、悪用・PoC 情報などを含みます。 |
| `data/vendors/<vendor>/advisories/<year>/<id>/summary.ja.md` | 任意で生成される個別アドバイザリの日本語要約。 |
| `data/vendors/<vendor>/index.json` | ベンダー単位のアドバイザリ索引。 |
| `vulndb/index.csv` | CVE または内部 ID 単位で集約した脆弱性台帳の一覧。 |
| `vulndb/vulns/<vendor>/<year>/<month>/<id>.yaml` | 脆弱性ごとの台帳エントリ。公開、修正、PoC、悪用確認の状態を管理します。 |
| `reports/daily/<year>/<month>/<date>.md` | 日本語の日次レポート。 |
| `reports/daily/<year>/<month>/<date>.summary.json` | 日次レポートの AI サマリと生成メタデータ。 |
| `run-manifest.json` | 最新実行の変更一覧、対象期間、各ソースの outcome。 |
| `run-summary.md` | 最新実行の概要。 |
| `state/sources/<source-id>.json` | ETag、Last-Modified、最終成功時刻、既知 ID などの増分収集状態。 |
| `quarantine/<source-id>/latest.json` | 収集または解析に失敗したデータと診断情報。 |

`staging/` は一時作業領域です。公開対象として Git 管理されるのは、`publish` 後にリポジトリ直下へ同期された生成物です。

## 結果の見方

### 日次レポート

`reports/daily/<year>/<month>/<date>.md` を確認します。主な確認点は次のとおりです。

- 冒頭の件数サマリで、新規、更新、取り下げ、隔離などの変化を確認します。
- リスク区分（緊急・高・中・低）で対応優先度を確認します。
- Critical 表では、Critical 判定のアドバイザリを一覧できます。
- 「悪用済み・PoC 公開済み」表では、実際の悪用確認と PoC 公開を区別して確認できます。
- 各行の出典リンクから、ベンダーまたは公的機関の原文を確認できます。

### 個別アドバイザリ JSON

`data/vendors/.../advisory.json` では、正規化された事実情報を確認できます。主に見る項目は次のとおりです。

- `id` / `canonical_id`: ツール内での識別子。
- `cves`: 関連 CVE。
- `title` / `description`: タイトルと説明。
- `vendor` / `products`: 影響を受けるベンダーと製品。
- `severity` / `cvss`: 深刻度と CVSS 情報。
- `fixed_versions` / `references`: 修正版と出典 URL。
- `exploitation`: 悪用確認、PoC 公開、CISA KEV などの補強情報。
- `priority`: 製品台帳や悪用状況を加味した対応優先度。

### CVE 単位の脆弱性台帳

`vulndb/` は、複数ソースで同じ CVE が観測された場合に情報を集約する台帳です。

- `vulndb/index.csv` で全体を一覧できます。
- 詳細は `vulndb/vulns/<vendor>/<year>/<month>/<id>.yaml` にあります。
- CVE 未採番の脆弱性には `VW-YYYY-NNNN...` 形式の内部 ID が付与されます。
- 後から CVE が判明してもファイル名は維持され、エントリ内の `cve` フィールドが更新されます。

### 収集成否

収集成否はレポートの行数ではなく、`run-manifest.json.source_outcomes` で確認します。

- `success`: 取得と解析が成功しました。
- `not_modified`: 条件付き取得により、前回から変更がありませんでした。
- `failed`: 収集または解析に失敗しました。
- `partial`: 一部だけ取得または解析できました。

`failed` または `partial` がある場合、その実行結果は公開前検証で拒否されます。

## 設定ファイル

| パス | 用途 |
|---|---|
| `config/sources.yaml` | 収集ソース、collector、parser、許可ホスト、取得上限などを定義します。 |
| `config/products.yaml` | 自組織で利用している製品名、公開区分、担当部署を定義します。 |

`config/products.yaml` には IP アドレス、ホスト名、認証情報などの機密情報を保存しないでください。
