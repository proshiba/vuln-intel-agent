# vulnwatch 利用ガイド補足

この文書は、README の補足として、設定と処理の流れを利用者向けに説明します。

## 処理の流れ

```text
config/sources.yaml  ->  collect  ->  staging/data・staging/state・staging/run-manifest.json
                                   ->  summarize  ->  日本語要約
                                   ->  report     ->  日次レポート
                                   ->  validate   ->  公開前検証
                                   ->  publish    ->  リポジトリ直下へ反映
config/products.yaml ->  優先度判定
CISA KEV / OSV / NVD ->  補強情報・coverage
```

## 収集ソース設定

`config/sources.yaml` には、収集対象、取得方式、parser、許可ホスト、取得上限などが定義されています。

代表的な取得方式は次のとおりです。

| 種類 | 内容 |
|---|---|
| JSON API | ベンダーやサービスが提供する JSON endpoint から取得します。 |
| RSS / Atom | フィードから更新情報を取得します。 |
| HTML | 公式ページを取得し、アドバイザリ情報を抽出します。 |
| Browser | JavaScript 実行が必要なページを Playwright で取得します。 |
| CSAF | CSAF 形式のセキュリティアドバイザリを取得します。 |
| NVD / OSV | 横断データベースから coverage 情報を取得します。 |

## 製品台帳設定

`config/products.yaml` は、自組織で利用する製品を記録し、日次レポートの優先度判定に使います。

保存してよい情報は次のような機密性の低い情報に限定してください。

- 製品名
- 公開区分
- 担当部署

IP アドレス、ホスト名、認証情報、内部 URL、個人情報は保存しないでください。

## 優先度の見方

日次レポートや個別アドバイザリには、対応優先度が付与されます。

| 優先度 | 目安 |
|---|---|
| P1 | 資産一致があり、悪用確認済み、CISA KEV 掲載、または認証不要リモート攻撃など緊急性が高いもの。 |
| P2 | 資産一致があり、高深刻度または修正版ありなど、早期確認が必要なもの。 |
| P3 | 資産一致はあるが、追加確認が必要なもの。 |
| INFO | 資産不一致、または判断材料が不足しているもの。 |

`config/products.yaml` が空の場合、多くのアドバイザリは `INFO` として扱われます。

## coverage ソースの扱い

NVD、OSV、GitHub Advisory Database、JVN iPedia などの横断 coverage ソースは、保存データと `vulndb/` の網羅性を補うために使われます。同じ脆弱性を重複して日次レポートに出さないよう、coverage ソースだけで観測された情報はレポートの変更行に直接出ない場合があります。

収集できたかどうかは、レポートの行数ではなく `run-manifest.json.source_outcomes` で確認してください。
