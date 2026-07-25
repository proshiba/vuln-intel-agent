# vulnwatch 脆弱性ビューア（GitHub Pages）

`vulndb/index.csv` に集約された脆弱性台帳を、ブラウザ上で一覧・検索・絞り込みできる静的ビューアです。GitHub Pages で公開します。

## 構成

| ファイル | 役割 |
|---|---|
| `index.html` | 単一ファイルのビューア本体（CSS・JS を内包）。`data/index.json` を取得して描画します。 |
| `build_index.py` | `vulndb/index.csv` から軽量な検索インデックス `data/index.json` を生成します。 |
| `data/index.json` | 生成物（Git 管理対象外）。デプロイ時に自動生成されます。 |

台帳 CSV は数十 MB あり、そのままブラウザで読むには大きすぎます。`build_index.py` は表示・検索・並び替えに必要な列だけを、配列の配列・ビットマスク・日付のみ・文字列の切り詰めで圧縮し、gzip 配信で扱いやすいサイズにします。

## できること

- 総登録数・CISA KEV・悪用確認・PoC 公開・修正あり・優先度の件数サマリ
- CVE / ベンダー / 製品 / タイトル / 内部 ID を対象とした全文検索（スペース区切りで AND）
- 優先度・ベンダー・CVSS 下限・KEV / 悪用 / PoC / 修正の絞り込み
- 更新日・公開日・CVSS・優先度での並び替え
- 行クリックで詳細（製品、深刻度、公開・更新日、NVD / OSV への参照リンク）を展開
- ライト / ダークの自動切り替え、スマートフォン幅への対応

## ローカルでの確認

```bash
python web/build_index.py
python -m http.server 8000 --directory web
# http://localhost:8000/ を開く
```

## デプロイ

`.github/workflows/pages.yml` が、`main` への `vulndb/index.csv` または `web/` の変更時（および手動実行時）に、インデックスを生成して GitHub Pages へ公開します。初回のみ、リポジトリの Settings → Pages → Build and deployment → Source で「GitHub Actions」を選択してください。
