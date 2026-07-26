# vulnwatch 脆弱性ビューア（GitHub Pages）

`vulndb/index.csv` に集約された脆弱性台帳を、ブラウザ上で一覧・検索・絞り込みできる静的ビューアです。GitHub Pages で公開します。

## 構成

| ファイル | 役割 |
|---|---|
| `index.html` | 単一ファイルのビューア本体（CSS・JS を内包）。`api/v1/search.json` を取得して描画します。 |
| `build_index.py` | 台帳から静的 JSON API（`api/v1/`）を生成します。 |
| `openapi.yaml` | API の OpenAPI 3.1 定義。 |
| `api/v1/meta.json` | 生成物（Git 管理対象外）。件数・スキーマ版・詳細 URL の組み立て方。 |
| `api/v1/search.json` | 生成物（Git 管理対象外）。全件の検索索引。 |

台帳 CSV は数十 MB あり、そのままブラウザで読むには大きすぎます。`build_index.py` は表示・検索・並び替えに必要な列だけを、配列の配列・ビットマスク・日付のみ・文字列の切り詰めで圧縮し、gzip 配信で扱いやすいサイズにします。

## できること

- 総登録数・CISA KEV・悪用確認・PoC 公開・修正あり・優先度の件数サマリ
- CVE / ベンダー / 製品 / タイトル / 内部 ID を対象とした全文検索（スペース区切りで AND）
- 優先度・ベンダー・CVSS 下限・公開日（過去 7 / 30 / 90 日・1 年）・攻撃対象面（初期アクセス面）・KEV / 悪用 / PoC / ランサム悪用 / 修正の絞り込み
- CISA KEV 掲載より早く悪用を観測できた脆弱性には「KEVより N 日早く観測」バッジを表示
- 「攻撃対象面 × 悪用確認」を組み合わせると、VPN 機器やメール/コラボ基盤など初期アクセスに使われうる製品で実際に悪用が確認された脆弱性だけを抽出できる
- 更新日・公開日・CVSS・優先度での並び替え
- 行クリックで詳細（製品、深刻度、公開・更新日、NVD / OSV への参照リンク）を展開
- ライト / ダークの自動切り替え、スマートフォン幅への対応

## 静的 JSON API

サーバは動いていませんが、ビルド時に生成した JSON と、リポジトリ上の台帳ファイルそのものを配信することで、読み取り専用の API として使えます。GitHub Pages と raw.githubusercontent.com はどちらも `Access-Control-Allow-Origin: *` を返すため、**別オリジンのポータルから JavaScript で直接読めます**。

| エンドポイント | 内容 |
|---|---|
| `api/v1/meta.json` | discovery 文書。まずこれを読みます。 |
| `api/v1/search.json` | 全件の検索索引（gzip 約 1.8MB）。 |
| `https://raw.githubusercontent.com/<repo>/main/vulndb/vulns/<prefix>/<id>.yaml` | 個別詳細。 |

個別詳細は事前生成していません。台帳の YAML がそのまま配信できるため、常に最新で、索引より内容も厚いためです（修正バージョン、全出典 URL、OSINT 報告の根拠文など）。`<prefix>` は `search.json` の `prefix_dictionary[row[13]]` から得ます。

```js
const base = "https://proshiba.github.io/vuln-intel-agent/";
const meta = await (await fetch(base + "api/v1/meta.json")).json();
const idx = await (await fetch(base + meta.endpoints.search)).json();

// 検索・絞り込みは取得した索引に対して呼び出し側で行う
const F = meta.search_index.flags;
const hits = idx.rows.filter((r) => r[11] === "vpn_gateway" && r[8] & F.exploited);

// 詳細は必要な時だけ取得する
const url = meta.endpoints.detail_url_template
  .replace("{prefix}", idx.prefix_dictionary[hits[0][13]])
  .replace("{vuln_id}", hits[0][0]);
const yaml = await (await fetch(url)).text();
```

クエリパラメータによるサーバ側の絞り込みはできません（静的配信のため）。検索は索引を取得したうえで呼び出し側で行います。

## ポータルへの iframe 埋め込み

`X-Frame-Options` や CSP `frame-ancestors` は設定されていないため、そのまま iframe で埋め込めます。埋め込んだビューアとは `postMessage` で連携できます。

```js
const frame = document.getElementById("vulnwatch");

window.addEventListener("message", (event) => {
  const data = event.data;
  if (data.type === "vulnwatch:ready") { /* meta と stats が届く */ }
  if (data.type === "vulnwatch:result") { /* matched 件数と rows */ }
});

// 表示を絞り込む（毎回まっさらな条件から組み立てられる）
frame.contentWindow.postMessage({
  type: "vulnwatch:query",
  requestId: "q1",
  q: "ivanti",
  filters: { attackSurface: "vpn_gateway", exploited: true, minCvss: 7 },
  sort: "cvss",
  limit: 50,
}, "*");
```

| 受け付けるメッセージ | 応答 | 用途 |
|---|---|---|
| `vulnwatch:meta` | `vulnwatch:meta` | discovery 文書を得る |
| `vulnwatch:query` | `vulnwatch:result` | 絞り込みを反映し、結果を返す |
| `vulnwatch:get`（`cve` か `id`） | `vulnwatch:entry` | 1 件を得る |
| （読み込み完了時） | `vulnwatch:ready` | 親へ準備完了を通知 |

`vulnwatch:result` と `vulnwatch:entry` の各行には `detailUrl` が入っており、そのまま詳細 YAML を取得できます。

配信するのはすべて公開情報で、書き込み操作はありません。そのため送信元オリジンは制限しておらず、応答は必ず要求元のウィンドウへ返します。

## ローカルでの確認

```bash
python -m pip install -e .   # 攻撃対象面の分類器と API 補助を使うため
python web/build_index.py
python -m http.server 8000 --directory web
# http://localhost:8000/ を開く
```

## デプロイ

`.github/workflows/pages.yml` が、`main` への `vulndb/index.csv` または `web/` の変更時（および手動実行時）に、静的 API を生成して GitHub Pages へ公開します。公開先のリポジトリ名やブランチを変える場合は、環境変数 `VULNWATCH_REPOSITORY` / `VULNWATCH_REF` / `VULNWATCH_SITE_URL` で上書きできます。初回のみ、リポジトリの Settings → Pages → Build and deployment → Source で「GitHub Actions」を選択してください。
