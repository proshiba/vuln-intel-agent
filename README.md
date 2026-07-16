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
vulnwatch validate --root staging
vulnwatch report --root staging
vulnwatch source test cisco --fixture tests/fixtures/vendors/cisco.json
```

`edge` は境界機器とCISA KEV、`daily` は有効な全ソースを対象にします。収集結果は
まず `staging` に作られ、検証後に `data/vendors/<vendor>/advisories/<year>/...`
として公開されます。設定は `config/sources.yaml`、機密情報を含まない製品台帳は
`config/products.yaml` です。

OpenAIによる要約は任意です。利用する場合だけ `OPENAI_API_KEY` と `LLM_MODEL` を
設定してください。未設定、拒否、タイムアウト、Schema違反はアドバイザリのAI状態へ
記録され、収集と公開を失敗させません。

PlaywrightとPDFは拡張用の任意依存です。

```bash
pip install -e '.[browser,pdf]'
playwright install --with-deps chromium
```

通常のPR CIは保存fixtureのみを使い、外部サイトへアクセスしません。定期収集は
GitHub Actionsで `collect → summarize → publish` の順に実行されます。

## 資産台帳の制約

資産台帳には製品名、公開区分、担当部署だけを保存し、IPアドレス、ホスト名、
認証情報は保存しないでください。
