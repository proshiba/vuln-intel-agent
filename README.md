# vulnwatch

公式ベンダー情報を優先して脆弱性アドバイザリを収集し、出典を保持したJSON、
日本語要約、日次レポートを生成するPython 3.12製のツールです。

## 開発環境

```bash
python -m venv .venv
.venv/bin/pip install -e '.[dev,ai]'
.venv/bin/vulnwatch config validate
.venv/bin/pytest
```

## CLI

```bash
vulnwatch config validate
vulnwatch collect --profile edge --since 90d --output staging
vulnwatch summarize --root staging --priority P1,P2
vulnwatch report --root staging
vulnwatch validate --root staging
vulnwatch publish --root staging --repository .
vulnwatch source test cisco --fixture tests/fixtures/vendors/cisco.json
```

`vulnwatch report`をオプションなしで実行できるのは、直前の`vulnwatch summarize`が現在の
収集結果に対応する日次AIサマリを正常生成した場合、または新規・更新・取り下げ変更がない
場合です。対話型AIエージェントによる明示指定は後述の2オプションを使用します。

`edge` は境界機器とCISA KEV、`daily` は有効な全ソースを対象にします。収集結果は
まず `staging` に作られます。`vulnwatch publish`は検証後の個別JSON、索引、状態、隔離データ、
レポート、実行manifest/summaryをリポジトリ直下へ同期し、すべてGit管理対象にします。
`staging`だけは重複する一時作業領域としてGit対象外です。設定は `config/sources.yaml`、
機密情報を含まない製品台帳は `config/products.yaml` です。

有効な80ソースのうちGitHub APIを利用するソースは、認証なしではAPIの時間当たり上限を
超えます。ローカル収集では読み取り専用のGitHub tokenを`GH_TOKEN`（優先）または
`GITHUB_TOKEN`に設定してください。tokenは`api.github.com`にだけ送信され、redirect先や
隔離ログには渡しません。

```bash
export GH_TOKEN="..."
vulnwatch collect --profile daily --since 90d --output staging
```

GitHub Actionsで全80ソースを収集するには、公開情報の読み取りだけに使う専用tokenを
repository secret `VULNWATCH_GITHUB_TOKEN`へ登録してください。第三者repositoryには
Actions組み込み`GITHUB_TOKEN`の権限が及ばないため、secret未設定時は部分的な結果を公開せず
daily収集前に停止します。GitHub APIを使わないedge profileはtokenなしでも実行できます。

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

PlaywrightとPDFは拡張用の任意依存です。

```bash
pip install -e '.[browser,pdf]'
playwright install --with-deps chromium
```

通常のPR CIは保存fixtureのみを使い、外部サイトへアクセスしません。定期収集は
GitHub Actionsで毎日1回、`collect → summarize → report → validate → publish` の順に
daily profileで実行されます。

## vulndb（CVE単位の脆弱性台帳）

収集結果から、CVE単位で公開・修正・PoC公開・悪用有無を管理する台帳を
`vulndb/` に生成します。全体索引の `vulndb/index.csv` と、脆弱性ごとの
`vulndb/vulns/<内部ID>.yaml` で構成され、採番状態は `vulndb/registry.json` が
保持します。すべてGit管理対象です。

CVE未採番の脆弱性（ゼロデイなど）には内部ID `VW-YYYY-NNNN` を採番します。
内部IDは恒久キーとしてファイル名に使い続け、後からCVEが判明した場合は
エントリの `cve` フィールドへ付与するだけで、ファイルの移動や統合は行いません。
同一CVEを複数ベンダーが公表した場合は1エントリに出典を集約します。修正版・
PoC公開・悪用確認は一度trueになったら維持し、観測日時を記録します。

台帳は収集のたびに変更分だけ増分更新され、`vulndb/registry.json` が存在しない
初回実行時のみ `data/vendors` 配下の全アドバイザリからシードされます。

## 資産台帳の制約

資産台帳には製品名、公開区分、担当部署だけを保存し、IPアドレス、ホスト名、
認証情報は保存しないでください。
