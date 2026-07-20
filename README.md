# vulnwatch

公式ベンダー情報を優先して脆弱性アドバイザリを収集し、出典を保持したJSON、
日本語要約、日次レポートを生成するPython 3.12製のツールです。

## 開発環境

```bash
python -m venv .venv
.venv/bin/pip install -e '.[dev,ai,browser]'
.venv/bin/playwright install chromium
.venv/bin/vulnwatch config validate
.venv/bin/pytest
```

## CLI

```bash
vulnwatch config validate
vulnwatch collect --profile daily --since 90d --output staging
vulnwatch summarize --root staging --priority P1,P2
vulnwatch report --root staging
vulnwatch validate --root staging
vulnwatch publish --root staging --repository .
vulnwatch source test cisco --fixture tests/fixtures/vendors/cisco.json
```

`vulnwatch report`をオプションなしで実行できるのは、直前の`vulnwatch summarize`が現在の
収集結果に対応する日次AIサマリを正常生成した場合、または新規・更新・取り下げ変更がない
場合です。対話型AIエージェントによる明示指定は後述の2オプションを使用します。

日次レポートの各アドバイザリには、CVSS・ベンダー深刻度、悪用・PoC公開状況、
修正提供状況とその経過時間、攻撃経路（認証不要リモートなど）、対象機器の利用され方
（境界機器・サーバー基盤・広く使われるOSなど）、自組織資産との一致を組み合わせた
リスクスコア（緊急・高・中・低）が付きます。冒頭にリスク件数を表示し、
「緊急」「高」のアドバイザリは根拠付きの「要対応」節にまとめ、各表はリスク順に
並べます。機器の分類は`config/sources.yaml`のカテゴリとtierから導出します。

`edge` は境界機器とCISA KEV、`daily` は有効な全ソースを対象にします。収集結果は
まず `staging` に作られます。`vulnwatch publish`は検証後の個別JSON、索引、状態、隔離データ、
レポート、実行manifest/summaryをリポジトリ直下へ同期し、すべてGit管理対象にします。
`staging`だけは重複する一時作業領域としてGit対象外です。設定は `config/sources.yaml`、
機密情報を含まない製品台帳は `config/products.yaml` です。

設定済みの160ソースはすべて有効です。内訳は `daily` 154件、`edge` 6件で、Collector別では
JSON API 76件、HTML 27件、RSS/Atom feed 37件、Playwright browser 9件、CSAF 6件、Broadcom
VMware API 1件、Ubiquiti API 1件、NVD 2件、OSV global 1件です。`catalog_runtime`により、`enabled`を明示して
いないカタログ項目も、件数・
詳細取得数・許可ホストを制限した公式Webソースとして自動的に有効になります。個別に検証済みの
機械可読endpointがある場合は、そのソース固有設定が共通値より優先されます。

役割は通常のアドバイザリ155件、横断coverage 4件、CISA KEV enrichment 1件です。coverageの
JVN iPedia、NVD、GitHub Advisory Database、OSVは保存データと`vulndb`の網羅性を補いますが、
同一脆弱性の重複を避けるため日次レポートの変更行には直接追加しません。収集成否はレポート行
ではなく、後述の`source_outcomes`で確認します。

OSV globalの`modified_id.csv`は90日で数十万件規模になるため、初回有効化だけは設定済みの
1時間境界から開始し、その後はGit管理される`state/sources/osv.json`の`last_success_at`以降を
欠けなく差分取得します。これは過去全件のbackfillではありません。OSVの全履歴dumpはGB級の
別運用になるため、初回の過去網羅はNVD・GitHub Advisory Database等のcoverageで補完します。

GitHub APIを利用するソースは、認証なしではAPIの時間当たり上限を
超えます。ローカル収集では読み取り専用のGitHub tokenを`GH_TOKEN`（優先）または
`GITHUB_TOKEN`に設定してください。tokenは`api.github.com`にだけ送信され、redirect先や
隔離ログには渡しません。

```bash
export GH_TOKEN="..."
vulnwatch collect --profile daily --since 90d --output staging
```

GitHub Actionsで全160ソースを収集するには、公開情報の読み取りだけに使う専用tokenを
repository secret `VULNWATCH_GITHUB_TOKEN`へ登録してください。第三者repositoryには
Actions組み込み`GITHUB_TOKEN`の権限が及ばないため、secret未設定時は部分的な結果を公開せず
daily収集前に停止します。GitHub APIを使わないedge profileはtokenなしでも実行できます。

各実行の`run-manifest.json.source_outcomes`には、対象ソースごとのstatus、実際に使った
Collector、endpoint、取得件数、parse件数、parse失敗数、エラーが記録されます。daily定期実行は
全160件のoutcomeがそろい、`failed`または`partial`が0件であることを確認してから後続処理へ
渡します。`vulnwatch validate`も同じ完全性条件を検証するため、不完全な実行はquarantineや
manifestへ診断情報を残しても、そのままレポート・公開へ進めません。

### GitHub由来ソースの取り込み元切り替え（GitHub直接 / OSV）

GitHubリポジトリのSecurity Advisory（`parser: github_advisory`）は、`api.github.com`から
直接取得するか、[OSV.dev](https://osv.dev)から取得するかを`VULNWATCH_GITHUB_BACKEND`で
切り替えられます。

- `github`（既定）: 各リポジトリの`security-advisories` APIから、メンテナ発行分を取得。
- `osv`: OSV座標があるソースはpackage queryのGHSAレコードへ切り替えます。OSV未収録の
  Repository Advisoryは公式の公開HTMLをページングし、横断GitHub Advisory Databaseは
  OSV modified indexのGHSA増分だけを取得します。`api.github.com`を使わないためtokenは不要です。
  CVSSはOSVのvectorから数値スコアを算出します。

```bash
export VULNWATCH_GITHUB_BACKEND=osv
vulnwatch collect --profile daily --since 90d --output staging
```

OSV座標が設定された62ソースに加え、Redis、Nextcloud、Immich、横断coverageの
GitHub Advisory Databaseにも上記の認証不要経路を適用するため、`osv`選択時の有効160ソースに
`api.github.com` endpointは残りません。公開HTML経路は同一repository advisory pathだけを
許可し、指定期間を過ぎるページまで有界に追跡します。
OSVは反映に数分〜数時間の遅れがあるため、速報性が要る境界機器等は引き続き各ベンダーの
直接ソースから即時取得します。

大規模なCSAF索引は全索引を検証したうえで、更新日時が新しい詳細をソースごとに最大100件
取得します。この部分取得結果やローリングfeedでは、未取得の既知アドバイザリをwithdrawn
扱いにしません。CSAF詳細が一部でも失敗した場合は、そのバッチを隔離して次回再試行します。

個別アドバイザリのOpenAI要約は任意です。`OPENAI_API_KEY` と `LLM_MODEL` を設定すると、
`vulnwatch summarize`は個別要約に加えて、Critical表と悪用済み・PoC公開済み表の日本語
AIサマリを日次sidecarへ生成します。対象変更がある日次レポートでは、2サマリが公開前検証で
必須です。対象変更が0件なら、サマリsidecarなしの定型的な変更なしレポートを生成します。
対話型AIエージェントは`AGENTS.md`の規則に従い、次のように現在の収集結果に基づく2文章を
レポート生成時に渡すこともできます。

```bash
vulnwatch report --root staging \
  --critical-summary '<Critical全件の日本語AIサマリ>' \
  --exploitation-summary '<悪用済み・PoC公開済みの日本語AIサマリ>'
```

未設定、拒否、タイムアウト、Schema違反はAI状態へ記録され、収集自体は継続します。ただし、
対象変更があるのに最新の成功済み日次サマリがなければ検証と公開は停止し、未生成文章を
公開しません。

Playwrightは9件の有効ソースが使用するため、全160ソースのdaily収集では必須です。PDFは
Collectorとして利用できますが、現行の有効ソースでは使用していない任意依存です。

```bash
pip install -e '.[browser]'
playwright install --with-deps chromium
```

通常のPR CIは保存fixtureのみを使い、外部サイトへアクセスしません。定期収集は次の分担で
自動化されています。GitHub Actions（`.github/workflows/collect-advisories.yml`、毎朝04:00 JST）
がAI処理なしで全ソースを収集し、生ツリーを `bot/collected-raw` へcommitしてWebhookで
Claude Code の routine を起動します。routine は要約（Claudeが日本語サマリを代筆するため
OpenAIキーは不要）・レポート・検証・公開を行って `bot/vulnwatch-daily` へpushし、
`.github/workflows/auto-merge-daily.yml` が構文チェック・ユニットテスト・生成物検証を通した
うえで main へ自動マージします。手動でGitHub直接収集したい場合は同workflowを
`workflow_dispatch` で起動できます（`VULNWATCH_GITHUB_TOKEN` が必要）。

## vulndb（CVE単位の脆弱性台帳）

収集結果から、CVE単位で公開・修正・PoC公開・悪用有無を管理する台帳を
`vulndb/` に生成します。全体索引の `vulndb/index.csv` と、脆弱性ごとの
`vulndb/vulns/<ベンダー>/<年>/<月>/<内部ID>.yaml` で構成され、採番状態は
`vulndb/registry.json` が保持します。すべてGit管理対象です。年・月は最初に観測した
タイミング（台帳への登録日 = `created_at`）で、一度決まると変わらないためファイル配置は
安定します。ベンダー・年・月でフォルダ分けすることで、1フォルダあたりのファイル数を抑え、
GitHub上でも閲覧しやすくしています。

CVE未採番の脆弱性（ゼロデイなど）には内部ID `VW-YYYY-NNNN…`（年内通番は4桁以上）を採番します。
内部IDは恒久キーとしてファイル名に使い続け、後からCVEが判明した場合は
エントリの `cve` フィールドへ付与するだけで、ファイルの移動や統合は行いません。
同一CVEを複数ベンダーが公表した場合は1エントリに出典を集約します。修正版・
PoC公開・悪用確認は一度trueになったら維持し、観測日時を記録します。

台帳は収集のたびに変更分だけ増分更新され、`vulndb/registry.json` が存在しない
初回実行時のみ `data/vendors` 配下の全アドバイザリからシードされます。

## 資産台帳の制約

資産台帳には製品名、公開区分、担当部署だけを保存し、IPアドレス、ホスト名、
認証情報は保存しないでください。
