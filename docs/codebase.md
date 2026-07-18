# vulnwatch コードガイド

## 目的

vulnwatchは、公式ベンダーの脆弱性情報を収集・正規化し、CISA KEVと組織の製品台帳で
補強して、対応優先度、構造化JSON、任意の日本語AI要約、日次レポートを生成します。

## 処理フロー

```text
sources.yaml -> Collector -> RawRecord -> Parser -> AdvisoryDraft
                                                     |
products.yaml -> asset matching ---------------------+
CISA KEV -----> exploitation enrichment -------------+
                                                     v
                                             Advisory + Priority
                                                     |
                                +--------------------+-------------+
                                v                    v             v
                         advisory.json         AI summary     daily report
```

`vulnwatch collect`は次の順番で処理します。

1. 既存の公開データと状態をstagingへコピーする。
2. profileと`enabled`設定から対象を選び、最大6ソースを並行収集する。
3. ETagとLast-Modifiedを利用して条件付き取得を行う。
4. 取得結果をソース別パーサーで`AdvisoryDraft`へ変換する。
5. CVE、製品、深刻度、修正版、悪用状況を`Advisory`へ正規化する。
6. CISA KEVと製品台帳の一致結果を付加し、優先度を決定する。
7. 既存アドバイザリのメモリ索引を使い、semantic hashで変更状態を判定する。
8. JSON、状態、索引、run manifest、run summaryをstagingへ出力する。

## モジュール

| モジュール | 責務 |
|---|---|
| `cli.py` | Typer CLIと引数検証 |
| `pipeline.py` | 収集、正規化、差分判定、隔離、保存の統括 |
| `models.py` | 設定、収集結果、アドバイザリ、実行結果のPydanticモデル |
| `config.py` | YAML設定の読み込みと検証 |
| `collectors/` | CSAF、JSON API、feed、HTML、browser、PDFからの取得 |
| `parsers/` | ベンダー形式から共通の`AdvisoryDraft`への変換 |
| `identity.py` | canonical ID、slug、semantic hashの生成 |
| `priority.py` | 製品台帳との照合と優先度判定 |
| `exploitation.py` | 明示表現から悪用・公開PoC状態を推定 |
| `storage/filesystem.py` | atomic write、状態管理、索引再構築 |
| `summarizers/` | 個別・日次セクションのOpenAI日本語要約と構造化出力検証 |
| `report.py` | AIサマリsidecarとMarkdown日次レポート生成 |
| `validation.py` | 設定、生成ツリー、日次AIサマリの公開前検証 |

## データモデル

- `SourceDefinition`: URL、collector、許可ホスト、制限値、parserなどの設定
- `RawRecord`: Collectorが返す未正規化レコード
- `AdvisoryDraft`: Parserが抽出した共通の中間形式
- `Advisory`: 保存・公開する正規化済み形式
- `SourceState`: ETag、成功時刻、件数、既知ID、消失回数などの状態
- `RunManifest`: 1回の収集における変更と結果

ベンダー由来の情報は`facts`、外部・組織情報は`enrichment`、判定結果は`decision`に
分離されます。AI出力は`ai`に隔離され、原典由来の事実を上書きしません。

## 優先度

| 優先度 | 条件 |
|---|---|
| P1 | 資産一致かつCISA KEV掲載または悪用確認済み |
| P1 | 公開資産に一致し、認証不要のリモート攻撃が可能 |
| P2 | 資産一致、高深刻度、修正版あり |
| P3 | 資産一致だが追加確認が必要 |
| INFO | 資産不一致または判定情報不足 |

`config/products.yaml`が空の場合、原則としてINFOです。製品台帳には製品名、公開区分、
担当部署のみを保存し、IPアドレス、ホスト名、認証情報を保存しないでください。

## 安全性と障害処理

- HTTPSのみ許可し、redirect先を含めて`allowed_hosts`と照合する。
- GitHub tokenは`api.github.com`へのrequestだけに付与し、redirect先へ転送しない。
- response size、Content-Type、timeout、rate limit、redirect回数を制限する。
- network error、HTTP 429、5xxを制限付きでretryする。
- 取得件数0と異常増加を拒否し、完全スナップショットでは85%以上の急減も拒否する。
- 収集・parse失敗はソース単位で`quarantine`へ記録する。
- withdrawn判定には3回以上かつ24時間以上の欠落を必要とする。
- CSAFの上限制御とローリングfeedは部分取得として既知IDを和集合で保持し、未取得レコードを
  withdrawn判定しない。
- 一時ファイルと`os.replace()`を使ってatomicに更新する。
- AI要約の失敗で収集全体を失敗させない。

## 保存レイアウト

```text
data/vendors/<vendor>/index.json
data/vendors/<vendor>/advisories/<year>/<id>/advisory.json
state/sources/<source-id>.json
reports/daily/<year>/<month>/<date>.md
reports/daily/<year>/<month>/<date>.summary.json
quarantine/<source-id>/latest.json
run-manifest.json
run-summary.md
```

結果はstagingに生成し、検証成功後に`vulnwatch publish`で上記の全パスをリポジトリ直下へ
同期します。GitHub Actionsは個別JSON、索引、状態、隔離データ、レポート、実行manifest/summaryを
すべてbot branchへ反映してPRにします。重複する一時領域`staging/`だけはGit対象外です。

## ソース追加

1. `config/sources.yaml`に公式URL、collector、parser、許可ホストを追加する。
2. 必要なら`collectors/`または`parsers/`を拡張する。
3. `tests/fixtures/vendors/`に外部接続不要の最小fixtureを追加する。
4. `tests/fixtures/expected.json`とparser testへ期待値を追加する。
5. 品質チェックをすべて通す。

## 開発と検証

```bash
python -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/vulnwatch config validate
.venv/bin/ruff check src tests
.venv/bin/ruff format --check src tests
.venv/bin/mypy src
.venv/bin/pytest
```

AI要約には`.[dev,ai]`、browserまたはPDF collectorには対応する任意依存を追加します。
通常のテストは外部ネットワークへ接続しません。
