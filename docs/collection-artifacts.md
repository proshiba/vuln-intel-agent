# 収集データとレポートの見方

この文書は、vulnwatch が生成・保存するデータの種類と確認方法をまとめた利用者向けガイドです。

## 生成される主なファイル

| パス | 内容 |
|---|---|
| `data/vendors/<vendor>/advisories/<year>/<id>/advisory.json` | ベンダーや公的機関の情報を共通形式に正規化した個別アドバイザリです。 |
| `data/vendors/<vendor>/advisories/<year>/<id>/summary.ja.md` | AI による個別アドバイザリの日本語要約です。生成設定がない場合は存在しないことがあります。 |
| `data/vendors/<vendor>/index.json` | ベンダー別のアドバイザリ一覧です。 |
| `reports/daily/<year>/<month>/<date>.md` | 日本語の日次レポートです。新規、更新、取り下げ、注目すべき脆弱性を確認できます。 |
| `reports/daily/<year>/<month>/<date>.summary.json` | 日次レポート内の Critical 表と悪用・PoC 表に使う AI サマリのメタデータです。 |
| `vulndb/index.csv` | CVE または内部 ID 単位に集約した脆弱性台帳の一覧です。 |
| `vulndb/vulns/<vendor>/<year>/<month>/<id>.yaml` | 台帳の詳細エントリです。公開、修正、PoC、悪用確認の状態を保持します。 |
| `vulndb/registry.json` | CVE 未採番脆弱性の内部 ID 採番状態と索引です。 |
| `run-manifest.json` | 最新収集の変更記録と、ソースごとの収集結果です。 |
| `run-summary.md` | 最新収集の概要です。 |
| `state/sources/<source-id>.json` | ETag、Last-Modified、最終成功時刻など、増分収集に使う状態です。 |
| `quarantine/<source-id>/latest.json` | 収集・解析失敗時の診断情報です。 |

`staging/` は収集直後の一時生成先です。公開用のデータは、`vulnwatch publish --root staging --repository .` の後にリポジトリ直下へ同期されます。

## 日次レポートで確認すること

`reports/daily/<year>/<month>/<date>.md` を開き、次の順に確認します。

1. 冒頭の実行概要で、収集日、対象期間、変更件数を確認します。
2. リスク件数で、緊急・高・中・低の分布を確認します。
3. 要対応セクションで、優先して確認すべきアドバイザリを確認します。
4. Critical 表で、Critical 判定のアドバイザリを確認します。
5. 悪用済み・PoC 公開済み表で、実際の悪用確認と PoC 公開を区別して確認します。
6. 各アドバイザリの出典 URL から、ベンダーや公的機関の原文を確認します。

## 個別アドバイザリ JSON の主な項目

| 項目 | 見方 |
|---|---|
| `canonical_id` | vulnwatch 内で一意に扱うための識別子です。 |
| `cves` | 関連する CVE ID です。 |
| `title` / `description` | 原典から取得・正規化したタイトルと説明です。 |
| `vendor` / `products` | 影響を受けるベンダーと製品です。 |
| `severity` / `cvss` | ベンダー深刻度や CVSS 情報です。 |
| `published_at` / `updated_at` | 公開日と更新日です。 |
| `fixed_versions` | 修正版や修正状況です。 |
| `references` | 原典や関連情報へのリンクです。 |
| `exploitation` | 悪用確認、PoC 公開、CISA KEV などの補強情報です。 |
| `priority` | 資産台帳、深刻度、悪用状況などを加味した対応優先度です。 |

## 脆弱性台帳（vulndb）

`vulndb/` は、アドバイザリ単位ではなく CVE または内部 ID 単位で脆弱性を追跡するための台帳です。

- `vulndb/index.csv` は全体一覧です。
- 詳細は `vulndb/vulns/<vendor>/<year>/<month>/<id>.yaml` にあります。
- CVE がある脆弱性は CVE 単位で集約されます。
- CVE 未採番の脆弱性は `VW-YYYY-NNNN...` 形式の内部 ID で管理されます。
- 同じ CVE が複数ソースで見つかった場合は、出典情報が同じ台帳エントリに集約されます。
- 一度観測された「修正あり」「PoC 公開」「悪用確認」は、観測日時とともに保持されます。

## 収集成否の確認

収集の成功・失敗は `run-manifest.json` の `source_outcomes` で確認します。

| status | 意味 |
|---|---|
| `success` | 取得と解析が成功しました。 |
| `not_modified` | 条件付き取得の結果、前回から変更がありませんでした。 |
| `failed` | 収集または解析に失敗しました。 |
| `partial` | 一部だけ取得または解析できました。 |

公開前に期待する状態は、対象ソースすべてに outcome があり、`failed` と `partial` が 0 件であることです。失敗がある場合は、`quarantine/<source-id>/latest.json` と `run-manifest.json` の `endpoint`、`count`、`error` を確認します。
