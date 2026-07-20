# vulnwatch 開発記録・現状仕様

最終更新: 2026-07-19

この文書は、プロジェクト開始から現在までに実装された内容、今回の開発作業、現行仕様、
検証結果、既知の制約、今後の作業を一つにまとめた引き継ぎ資料です。

> 追補（2026-07-18 以降）: 本記録の3節以降はプロジェクト前半のスナップショットです。
> 以降のセッションで次を追加・変更しました。最新の運用フローとレイアウトは
> `README.md`、`docs/codebase.md`、`docs/collection-artifacts.md` を参照してください。
>
> - **vulndb**: CVE単位の脆弱性台帳（`vulndb/index.csv` ＋ `vulndb/vulns/<ベンダー>/<年>/<月>/<内部ID>.yaml`
>   ＋ `vulndb/registry.json`）。公開・修正・PoC公開・悪用を管理し、CVE未採番は内部ID
>   `VW-YYYY-NNNN…`（年内通番は4桁以上）で採番。
>   年・月は最初に観測した`created_at`でフォルダ分けし、恒久的に安定させる（15・16節を更新）。
> - **リスク評価**: 日次レポートに緊急/高/中/低のリスクスコア（CVSS・悪用/PoC・修正経過・攻撃経路・
>   機器分類・資産一致の合成）と「要対応」節を追加し、各表をリスク順に並べる（12節を更新）。
> - **OSVバックエンド**: `VULNWATCH_GITHUB_BACKEND=osv` でGitHub由来ソースをosv.devから取得可能（6節を更新）。
> - **収集の自動化**: Actionsは収集のみ→`bot/collected-raw`へcommit→Webhookで Claude Code routine を起動→
>   routineが要約・レポート・公開して`bot/vulnwatch-daily`へpush→auto-mergeで`main`へマージ（16節を更新）。
> - CIの型チェックに`ai`エクストラを追加（`openai`型解決のため）。
> - **全カタログ収集**: 160件すべてを有効化。個別runtime未設定のカタログ項目には
>   `catalog_runtime`が上限付きHTML/generic設定を補い、検証済み機械可読endpointは個別設定を優先する。
> - **Collector拡張**: NVD API、OSV global、汎用Web、ページネーション付きJSON APIを追加。
>   Broadcom VMware専用API Collectorと、full dailyで使用するPlaywright browser 9件を含む
>   定期実行依存を整備した（6・7・17節を更新）。
> - **収集完全性**: `run-manifest.json.source_outcomes`へ全ソースの結果を記録し、定期実行は
>   outcome欠落または`failed`/`partial`があればhandoff前に停止する（5・8・14・16節を更新）。
> - **coverage role**: JVN iPedia、NVD、GitHub Advisory Database、OSVの横断情報は保存データと
>   vulndbを補完し、重複防止のため日次レポート変更行には直接追加しない（5・7・8節を更新）。

## 1. プロジェクトの目的

vulnwatchは、公式ベンダー情報を優先して脆弱性アドバイザリを収集し、出典付きの
構造化JSON、日本語要約、日次レポートを生成するPython 3.12製ツールです。

目標は次のとおりです。

- ベンダー公式情報を機械的かつ継続的に収集する。
- ベンダーごとに異なる形式を共通モデルへ正規化する。
- CISA KEVや組織の製品台帳を使い、対応優先度を決定する。
- 更新、取り下げ、収集障害を安全に検出する。
- 個別AI要約を任意機能として利用し、日次の注目表には検証済みAIサマリを付ける。
- 生成結果を検証後にGitHub上のPRとして公開する。

## 2. 開発履歴

### リポジトリ既存履歴

| コミット | 内容 |
|---|---|
| `7709835` | Initial commit |
| `0b55c33` | 基本アプリ、設定、Collector、Parser、保存、AI要約、CI、テストを実装 |
| `3a53e5a` | 収集対象、Parser、悪用判定、レポートを拡張 |

今回の作業開始時点のHEADは`3a53e5a`でした。

### 今回実施した作業

1. リポジトリ全体を調査し、構成と現行機能を確認した。
2. 既存`.venv`へ`.[dev]`をeditable installした。
3. 設定検証、Ruff、mypy、pytestを実行できる環境を整えた。
4. 既存のRuff format差分4ファイルを整形した。
5. 公式GitHub Repository Security Advisories APIを利用する25ソースを追加した。
6. 有効ソース数を25件から50件へ増やした。
7. 日次レポートへCritical全件表と、悪用済み・PoC公開済みの和集合表を追加した。
8. コードガイドと本開発記録を追加した。
9. Git対象外の`staging/`へセッション継続用のローカル履歴を作成した。

## 3. 現在の構成

```text
config/sources.yaml -> Collector -> RawRecord -> Parser -> AdvisoryDraft
                                                            |
config/products.yaml -> asset matching ---------------------+
CISA KEV -----------> exploitation enrichment --------------+
                                                            v
                                                    Advisory + Priority
                                                            |
                                     +----------------------+--------------+
                                     v                      v              v
                              advisory.json           AI summary      daily report
```

主なモジュールは次のとおりです。

| パス | 責務 |
|---|---|
| `src/vulnwatch/cli.py` | Typer CLI、引数の解析と検証 |
| `src/vulnwatch/pipeline.py` | 収集から保存までのオーケストレーション |
| `src/vulnwatch/models.py` | Pydanticによる厳密なデータモデル |
| `src/vulnwatch/config.py` | YAML設定の読み込みと検証 |
| `src/vulnwatch/collectors/` | 外部情報の安全な取得 |
| `src/vulnwatch/parsers/` | ベンダー形式から共通形式への変換 |
| `src/vulnwatch/identity.py` | canonical ID、slug、semantic hash |
| `src/vulnwatch/priority.py` | 資産照合と優先度判定 |
| `src/vulnwatch/exploitation.py` | 明示文から悪用・PoC状態を推定 |
| `src/vulnwatch/storage/filesystem.py` | atomic write、状態、索引管理 |
| `src/vulnwatch/summarizers/` | 個別・日次セクションのOpenAI日本語要約 |
| `src/vulnwatch/report.py` | AIサマリsidecarとMarkdown日次レポート生成 |
| `src/vulnwatch/validation.py` | 設定・公開ツリー・日次AIサマリの検証 |

詳細なコード構成は`docs/codebase.md`も参照してください。

## 4. CLI

```bash
vulnwatch config validate
vulnwatch collect --profile edge --since 90d --output staging
vulnwatch collect --profile daily --since 90d --output staging
vulnwatch summarize --root staging --priority P1,P2
vulnwatch report --root staging
vulnwatch validate --root staging
vulnwatch source test cisco --fixture tests/fixtures/vendors/cisco.json
```

オプションなしの`report`は、`summarize`が現在の収集結果に対応する日次AIサマリを正常生成済み
の場合、または新規・更新・取り下げ変更が0件の場合に使用します。対話型AIエージェントは
`AGENTS.md`に従って2文章を明示指定します。

- `edge`: 境界機器とCISA KEVを中心とするソースを収集する。
- `daily`: 有効な全ソースを収集する。
- `since`: `90d`の形式で収集対象期間を指定する。

## 5. 収集パイプライン

`Pipeline.run()`は次の処理を行います。

1. 公開済みの`data`、`state`、`reports`、`quarantine`をstagingへコピーする。
2. profile、tier、enabledから今回の対象を選ぶ。
3. ソースごとのCollectorを最大6件並行で実行し、失敗時はfallback Collectorを試す。
4. CISA KEVなどの補強結果を、全Collector完了後の正規化処理で使用する。
5. ETagとLast-Modifiedを状態ファイルへ保存し、条件付き取得に使用する。
6. RawRecordをParserへ渡してAdvisoryDraftを生成する。
7. CVE、製品、CVSS、修正版、悪用情報などをAdvisoryへ正規化する。
8. 製品台帳とCISA KEVで補強し、優先度を決定する。
9. semantic hashで既存アドバイザリと比較する。
10. new、updated、unchanged、withdrawn、quarantinedを記録する。
11. coverageソースを保存データとvulndbへ反映し、全対象の`source_outcomes`を記録する。
12. ベンダー索引、run manifest、run summaryを生成する。

## 6. CollectorとParser

現在有効な160ソースのCollector内訳は次のとおりです。

| Collector | 有効ソース数 |
|---|---:|
| JSON API | 76 |
| HTML / 汎用Web | 27 |
| Feed | 37 |
| Playwright browser | 9 |
| CSAF | 6 |
| Broadcom VMware API | 1 |
| Ubiquiti API | 1 |
| NVD API | 2 |
| OSV global | 1 |

実装済みCollectorはCSAF、JSON API、RSS/Atom feed、HTML/汎用Web、Playwright browser、PDF、
Broadcom VMware API、NVD API、OSV package query、OSV globalです。browserはfull dailyで
必須、PDFは現行の有効ソースでは未使用の任意依存です。

Parserは次を扱います。

- CSAF 2.x
- GitHub Repository Security Advisory
- ベンダー固有JSON
- 汎用JSON
- RSS/Atom/HTML由来の汎用レコード
- CISA KEV補強データ

## 7. 情報源

設定全体160件がすべて有効です。tier内訳はdaily 154件、edge 6件、role内訳はadvisory 155件、
coverage 4件、enrichment 1件です。`catalog_runtime`は`enabled`が未記載のカタログ項目を、
公式`advisory_url`、許可ホスト、取得上限を使うHTML/generic runtimeとして有効化します。
ソース固有のCollectorや機械可読endpointがある場合は個別設定を優先します。

### 開発開始時から有効だった25件

- Cisco
- Fortinet
- Palo Alto Networks
- Juniper Networks
- SonicWall
- Veeam
- Microsoft
- Red Hat
- Canonical
- Debian
- SUSE
- GitLab
- Jenkins
- Kubernetes
- Redis
- Grafana
- Matrix Synapse
- Prometheus
- etcd
- Gitea
- Traefik
- MinIO
- Jupyter Server
- JVN
- CISA KEV

### 第2期に追加した25件

- Helm
- Argo CD
- Flux
- containerd
- Moby
- Docker Compose
- OpenTelemetry Collector
- Immich
- Jellyfin
- Home Assistant Core
- Deno
- Caddy
- Envoy
- Prometheus Alertmanager
- OAuth2 Proxy
- Syncthing
- Tailscale
- NetBird
- Keycloak
- gRPC-Go
- Electron
- Next.js
- Nuxt
- Ruby on Rails
- Laravel Framework

追加した25件は各プロジェクトの公式GitHub Repository Security Advisories APIを使用します。
設定追加前に、各APIが公開され、少なくとも1件のアドバイザリを返すことを確認しました。

### 第3期に追加した30件

- Flask、Express、FastAPI、Starlette、aiohttp
- SvelteKit、Angular、Werkzeug、Jinja、urllib3
- Requests、cryptography、Pillow、Pydantic、Scrapy、Tornado
- Strapi、Directus、Payload CMS、Vite、webpack
- pnpm、npm CLI、NestJS、Koa、Socket.IO
- Fiber、Echo、Gorilla WebSocket、rustls

この30件も公式GitHub Repository Security Advisories APIを使用し、当時の有効ソースを
合計80件に拡張しました。その後、残りのカタログ80件も有効化して現行160件になっています。

共通設定は次の方針です。

- Collector: `json_api`
- Parser: `github_advisory`
- API取得上限: 100件
- 許可ホスト: `api.github.com`、`github.com`
- Content-Type: JSONまたはGitHub JSON
- tier: `daily`

## 8. データモデル

主要モデルは未知フィールドを拒否し、代入時にも検証します。

- `SourceDefinition`: 収集URL、許可ホスト、Collector、Parser、制限値
- `RawRecord`: Collectorが返す未正規化データ
- `AdvisoryDraft`: Parserが生成する中間形式
- `AdvisoryFacts`: ベンダー情報から得た事実
- `AdvisoryEnrichment`: CISA KEVと資産一致結果
- `AdvisoryDecision`: 優先度と理由
- `Provenance`: 取得形式、content hash、extractor version
- `AiMetadata`: AI要約の状態と構造化出力
- `Advisory`: 保存・公開する最終形式
- `SourceState`: 条件付き取得と消失検知の状態
- `SourceOutcome`: ソース別status、使用Collector、endpoint、取得・parse件数、エラー
- `RunManifest`: 1回の実行結果

Source roleは`advisory`、`enrichment`、`coverage`の3種です。coverageは横断データを通常の
Advisoryとして保存しvulndb更新にも使いますが、同一脆弱性の重複を避けるためmanifestの
日次レポート変更行へは追加しません。収集できたかどうかは`source_outcomes`で判定します。

ベンダー由来の事実、補強情報、判断、AI出力を分離しているため、AIが原典の事実を
上書きすることはありません。

## 9. 識別と差分検出

- ベンダーアドバイザリIDを優先してcanonical IDを生成する。
- IDがない場合も安定した識別子を生成する。
- semantic hashはAI状態や観測時刻ではなく、意味のある内容変更を判定する。
- 新規は`new`、意味のある変更は`updated`、同一内容は`unchanged`とする。
- 消失は即時に取り下げず、3回以上かつ24時間以上欠落した場合に`withdrawn`とする。

## 10. 悪用・PoC判定

悪用と公開PoCについて、ベンダー本文の明示的な英語表現のみを正規表現で推定します。

- active exploitation
- in-the-wild exploitation
- exploitation observed/confirmed
- publicly available proof-of-concept
- no evidence/reports of exploitation
- not aware of public PoC

否定表現を先に除去してから肯定表現を調べ、単に「exploit」という単語があるだけでは
悪用済みと判定しません。CISA KEV掲載は独立した強い悪用根拠として扱います。

## 11. 資産照合と優先度

| 優先度 | 条件 |
|---|---|
| P1 | 資産一致かつCISA KEV掲載または悪用確認済み |
| P1 | インターネット公開資産に一致し、認証不要のリモート攻撃が可能 |
| P2 | 資産一致、高深刻度、修正版あり |
| P3 | 資産一致したが攻撃条件または修正版の追加確認が必要 |
| INFO | 資産不一致または判定情報不足 |

現在の`config/products.yaml`は空です。このため、実際の製品台帳を登録するまで資産一致は
発生せず、原則としてINFOになります。

製品台帳には製品名、別名、公開区分、担当部署のみを保存します。IPアドレス、ホスト名、
認証情報などの機密情報は保存しません。

## 12. 日次レポート

日次レポートはAsia/Tokyoの日付で次へ生成します。

```text
reports/daily/<year>/<month>/<YYYY-MM-DD>.md
```

レポートには次が含まれます。

- ベンダー×危険度の件数マトリクス
- ベンダーごとの深刻度、合計、悪用済み、PoC公開済みの独立した数値列
- 当該レポートの新規・更新・取り下げ変更に含まれるCritical全件のAIサマリと一覧表
- 深刻度に関係しない悪用済み・PoC公開済みのAIサマリと和集合表
- Critical、High、Moderate、その他の順に並ぶ詳細一覧
- CVE、CVSS、優先度、変更状態、悪用状況、原典リンク

### Criticalセクション

当該レポートの新規・更新・取り下げ変更のうち、悪用状況に関係なくCriticalに分類された
全アドバイザリを専用表へ掲載します。各節の表の前に、現在の生成データだけを根拠にした
日本語AIサマリを掲載します。対象変更が0件の場合だけは変更なしレポートとし、両節とsidecarを
省略します。

該当項目ごとに次を表示します。

- タイトルと原典リンク
- ベンダー
- CVE。未採番の場合はその旨
- CVSS。未確認の場合はその旨
- 悪用済み、CISA KEV、PoC公開済みの状態
- 悪用済みとPoC公開済みの独立した状態

悪用済み・PoC公開済みセクションは両状態の和集合であり、両方に該当するアドバイザリも
同じ表内では1行として掲載します。該当項目がない場合はその旨を決定論的に表示します。

## 13. AI要約

個別アドバイザリのOpenAI要約は任意です。使用時のみ`OPENAI_API_KEY`と`LLM_MODEL`を
設定します。対象変更がある場合、日次のCritical節と悪用済み・PoC公開済み節のAIサマリは
公開時に必須です。

AI出力は次の構造です。

- 日本語概要
- 影響対象資産
- 攻撃成立条件
- 推奨対応
- 不確実な点
- 根拠URL

APIキー未設定、拒否、timeout、schema違反はAI状態へ記録され、収集は継続します。日次サマリは
入力hash、model、prompt version、状態とともに`.summary.json`へ保存し、欠落・失敗・古い結果は
公開前検証で拒否します。対話型AIエージェントは`AGENTS.md`に従って2文章を明示指定できます。

## 14. 安全設計

- HTTPS以外のURLを拒否する。
- redirect先も含めて`allowed_hosts`と照合する。
- 許可していないContent-Typeを拒否する。
- response size、timeout、rate limit、redirect回数を制限する。
- timeout、network error、HTTP 429、5xxを制限付きでretryする。
- 完全スナップショットの異常な0件や全件parse失敗を隔離する。ローリング/部分取得ソースの
  0件は、対象期間に更新がない可能性があるため既知IDを維持する。
- 前回から85%以上件数が減った場合に異常とする。
- ソース別の`max_items`/`max_index_items`と前回比で異常増加を検知する。
- 収集・parse失敗はソース単位でquarantineへ隔離する。
- 一つのソースが失敗しても他ソースの処理を継続する。
- `source_outcomes`に全対象の成否を残し、定期dailyでは件数不一致または`failed`/`partial`が
  1件でもあれば生ツリーのhandoff前に停止する。
- 公開前の`vulnwatch validate`もprofileに対するoutcomeの欠落・余分・重複と
  `failed`/`partial`を拒否する。
- 一時ファイルへの書き込み後に`os.replace()`でatomicに更新する。
- stagingで生成・検証し、allowlist化した全成果物だけをリポジトリ直下へ公開する。

## 15. 保存形式

```text
data/vendors/<vendor>/
  index.json
  advisories/<year>/<advisory-id>/advisory.json
state/sources/<source-id>.json
reports/daily/<year>/<month>/<date>.md
reports/daily/<year>/<month>/<date>.summary.json
quarantine/<source-id>/latest.json
run-manifest.json
run-summary.md
```

各アドバイザリにはsource URL、content SHA-256、extractor versionを保存し、出典と生成元を
追跡できるようにしています。

## 16. GitHub Actions

通常CIは次を実行します。

1. Python 3.12セットアップ
2. `.[dev]`インストール
3. 設定検証
4. Ruff lint
5. Ruff format check
6. mypy strict type check
7. fixtureを使ったoffline pytest

定期処理はシステム間で次のように分担します。

1. `collect-advisories.yml`がbrowser extraとChromiumを導入し、dailyの全160ソースをstagingへ収集する。
2. outcomeが160件そろい、`failed`/`partial`が0件であることを検証する。不完全ならここで停止する。
3. 生ツリーを`bot/collected-raw`へcommitし、WebhookでClaude Code routineを起動する。
4. routineがAIサマリ・レポート・検証・公開を行い、`bot/vulnwatch-daily`へpushする。
5. auto-merge workflowがテストと生成物検証を通し、PRを`main`へマージする。

## 17. 開発環境

既存の`.venv`はPython 3.12.13です。今回、次を実行済みです。

```bash
.venv/bin/python -m pip install -e '.[dev,browser]'
.venv/bin/python -m playwright install chromium
```

依存関係の`pip check`結果は`No broken requirements found.`でした。

通常の検証コマンドは次のとおりです。

```bash
.venv/bin/vulnwatch config validate
.venv/bin/ruff check src tests
.venv/bin/ruff format --check src tests
.venv/bin/mypy src
.venv/bin/pytest -q
```

AI要約をローカル生成する場合は`ai` extraも導入します。browser extraとChromiumはfull dailyで
使用します。PDF extraは現行の有効ソースでは使用しません。

## 18. テストと現在の品質状態

現行設定の検証結果は`160 sources, 160 enabled`です。以下は2026-07-18の80ソース構成時点の
履歴として残す品質スナップショットであり、現行件数を示すものではありません。

- 設定検証（当時）: `160 sources, 80 enabled`
- Ruff lint: 成功
- Ruff format check: 成功
- mypy: 30 source files、問題なし
- pytest: 76 passed
- pip check: 問題なし
- git diff check: 空白エラーなし

テストはCollector、CSAF、設定、モデル、Parser、identity、storage、pipeline、priority、
悪用推定、AI要約、report、全成果物のpublish、Git除外方針を対象にしています。通常テストは
保存fixtureを使い、外部サイトへ接続しません。

2026-07-17の実接続確認では、Juniper 40件、Microsoft 100件、Red Hat 100件、SUSE 100件を
収集・解析できました。edge全6ソースは124件、隔離0件で生成ツリー検証に成功しました。
token未設定のdaily実行は254秒で完了し、非GitHub 16ソースはすべて成功、GitHub 64ソースだけが
意図した認証案内付きで隔離されました。当時の全80ソース定期実行には専用tokenを使用しました。

2026-07-18の認証済みdaily実行では当時の全80ソースが成功し、隔離0件、アドバイザリ827件を
検証しました。個別JSONを含む生成成果物969ファイルをGit管理対象へ反映しています。

## 19. ドキュメントとローカル履歴

| ファイル | 用途 | Git管理 |
|---|---|---|
| `README.md` | 利用者向け概要 | 対象 |
| `docs/codebase.md` | コード構成と拡張方法 | 対象 |
| `docs/development-record.md` | 開発履歴と現状仕様の統合文書 | 対象 |
| `staging/DEVELOPMENT_HISTORY.md` | セッション再開用メモ | 対象外 |
| `staging/history/*.md` | 作業単位の詳細履歴 | 対象外 |

新しいセッションでは、まず本書、`docs/codebase.md`、Git差分、ローカル履歴を確認します。

## 20. 既知の制約と注意事項

### GitHub API rate limit

既定の`github` backendでは67ソースの収集URLが`api.github.com`を使用し、未認証の時間当たり
上限を超えます。`VULNWATCH_GITHUB_BACKEND=osv`では、OSV座標を持つ62ソースをpackage query、
Redis・Nextcloud・Immichを公式公開HTML、GitHub Advisory Database coverageをOSVのGHSA増分へ
切り替えるため、全160ソースをtokenなしで収集できます。既定backendのCollectorは
`GH_TOKEN`、次に`GITHUB_TOKEN`を使用し、tokenを`api.github.com`だけへ送ります。
GitHub Actionsでは第三者repositoryを読める専用tokenを`VULNWATCH_GITHUB_TOKEN` secretとして
必須化し、未設定ならdaily収集前に停止します。ローカルdaily収集でも、いずれかのtoken設定が
必要です。edge profileはGitHub APIを使わないためtokenを要求しません。

### 大規模CSAF索引

Microsoft、Red Hat、SUSEのCSAF索引は90日分だけでも1,000件を超えます。索引全体には
`max_index_items`、詳細取得には`max_detail_fetches`を別々に適用し、更新日時が新しい100件を
取得します。部分取得時は既知IDを和集合で保持し、未取得分をwithdrawnと誤判定しません。
詳細が1件でも失敗したバッチは隔離し、索引の条件付き取得状態を進めず次回再試行します。

### OSV globalの初回境界

OSVの全ecosystem `modified_id.csv`は90日指定で数十万件に達するため、初回だけ
`bootstrap_window_hours: 1`を適用します。以後はGit管理されるsource stateの
`last_success_at`から連続差分を取得します。初回実行を過去全件backfillとは扱いません。

### 製品台帳

製品台帳が空のため、現時点では資産ベースのP1～P3判定を実運用できません。組織の対象製品を
機密情報なしで登録する必要があります。

### 汎用Parser

feedや汎用JSONはベンダー固有形式より抽出できる項目が少ない場合があります。fixtureと
期待値を追加しながら、必要なソースだけ専用Parserへ段階的に移行してください。

### 検討中のParser整理

JSON Parserでは複数候補キーを`or`で選択する箇所があり、明示的な`False`または`0`を
後続候補へ置き換える可能性があります。値選択helperと回帰テストを追加するリファクタリングを
検討済みですが、まだ実装していません。

## 21. 次の推奨作業

1. GitHub APIのrate limit headerを状態またはmanifestへ記録する。
2. `config/products.yaml`へ実運用対象製品を登録する。
3. JSON Parserの明示的な`False`と`0`の扱いを修正する。
4. 新規GitHubソースの代表fixtureを増やし、プロジェクト固有フィールドを確認する。
5. AI要約を使用する場合はP1/P2だけから段階的に有効化する。

## 22. セッション再開手順

```bash
git status --short
sed -n '1,260p' docs/development-record.md
sed -n '1,220p' staging/DEVELOPMENT_HISTORY.md
.venv/bin/vulnwatch config validate
.venv/bin/pytest -q
```

未完了作業は`staging/history/`の最新ファイルへ追記します。APIキー、token、認証情報、
IPアドレス、ホスト名などは開発履歴へ記載しないでください。
