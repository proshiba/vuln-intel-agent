# vulnwatch 外部連携ガイド

このリポジトリが外部へ公開している UI と API の仕様です。**ポータルなど別サイトから組み込む側**が読むことを想定しており、この文書だけで実装できるよう自己完結させています。

- 公開 UI: <https://proshiba.github.io/vuln-intel-agent/>
- API 入口: <https://proshiba.github.io/vuln-intel-agent/api/v1/meta.json>
- 形式定義: <https://proshiba.github.io/vuln-intel-agent/openapi.yaml>（OpenAPI 3.1）

## 全体像

サーバは動いていません。すべて静的ファイルです。

```
ポータル（別オリジン）
├── iframe  → https://proshiba.github.io/vuln-intel-agent/     … 一覧UIをそのまま表示
│              ↕ postMessage                                    … 表示の制御・選択の受け取り
└── fetch   → api/v1/meta.json     … 何が提供されているか（最初に読む）
             api/v1/search.json    … 全件の検索索引（検索は取得側で行う）
             raw.githubusercontent … 個別脆弱性の詳細（YAML）
```

GitHub Pages と raw.githubusercontent.com はどちらも `Access-Control-Allow-Origin: *` を返すため、別オリジンの JavaScript から直接読めます。`X-Frame-Options` も CSP `frame-ancestors` も設定していないため、iframe 埋め込みも可能です。

### できないこと

- **サーバ側のクエリ（`?q=...&exploited=true`）はできません。** 静的配信のためです。検索は `search.json` を取得したうえで、取得した側で行います。
- 書き込み・認証・レート制限つきの個別問い合わせもありません。すべて読み取り専用の公開データです。

## 1. まず meta.json を読む

```
GET https://proshiba.github.io/vuln-intel-agent/api/v1/meta.json
```

件数、スキーマ版、検索索引の場所、詳細 URL の組み立て方が入っています。**エンドポイントの場所をハードコードせず、この文書から解決してください。** 将来パスが変わっても追従できます。

```jsonc
{
  "schema_version": 1,
  "api_version": "v1",
  "generated_at": "2026-07-26T03:49:37+00:00",
  "cors": true,
  "endpoints": {
    "meta": "api/v1/meta.json",
    "search": "api/v1/search.json",
    "detail_url_template": "https://raw.githubusercontent.com/proshiba/vuln-intel-agent/main/vulndb/vulns/{prefix}/{vuln_id}.yaml"
  },
  "search_index": { "fields": [...], "flags": {...}, "detail_format": "yaml" },
  "attack_surfaces": { "vpn_gateway": "VPN/リモートアクセス", ... },
  "stats": { "total": 42171, "kev": 688, "exploited": 1173, ... }
}
```

`endpoints.meta` と `endpoints.search` は `site_url` からの相対パスです。

複数リポジトリを横断する場合は、**各リポジトリの `meta.json` を集めて回る**のが基本形になります。`name`・`stats`・`generated_at` を見れば、対象と鮮度を一覧できます。

## 2. 検索索引（search.json）

```
GET https://proshiba.github.io/vuln-intel-agent/api/v1/search.json
```

台帳全件（現在 42,171 件）を、検索・絞り込み・並び替えに必要な列だけへ圧縮したものです。**gzip 配信で約 1.8MB**。1 回取得してメモリに置き、以降の検索はローカルで行ってください。

各行は**配列**です。列の意味は `fields` が定義します（添字を直書きせず `fields.indexOf()` で解決することを推奨）。

| 添字 | 名前 | 型 | 内容 |
|---|---|---|---|
| 0 | `id` | string | 内部 ID（`VW-YYYY-NNNN`）。**常に存在する恒久キー** |
| 1 | `cve` | string | CVE ID。**未採番なら空文字**（現在 5,794 件） |
| 2 | `vendors` | string | `; ` 区切り。**先頭 3 件のみ**、超過時は末尾に `…` |
| 3 | `products` | string | `;` 区切り。**80 文字で切り詰め** |
| 4 | `title` | string | **160 文字で切り詰め**（末尾 `…`） |
| 5 | `cvss` | number \| "" | 基本スコア。**未取得は空文字**（現在 8,473 件） |
| 6 | `sev` | string | ベンダー深刻度の**生値**。後述の注意あり |
| 7 | `prio` | string | `P1`/`P2`/`P3`/`INFO`。後述の注意あり |
| 8 | `flags` | number | ビットマスク。後述 |
| 9 | `pub` | string | 公開日 `YYYY-MM-DD`。不明は空文字（現在 1,022 件） |
| 10 | `upd` | string | 更新日 `YYYY-MM-DD` |
| 11 | `asc` | string | 初期アクセス面の分類 ID。該当なしは空文字 |
| 12 | `lag` | number \| "" | CISA KEV 掲載より何日早く悪用を観測できたか |
| 13 | `prefix` | number | `prefix_dictionary` への添字（`-1` は不明） |

`rows` は**更新日の新しい順**に並んでいます。

### flags のビットマスク

`meta.search_index.flags` で定義されます。値は固定ではないので、この定義を参照してください。

| ビット | 名前 | 意味 |
|---|---|---|
| 1 | `fixed` | 修正版あり |
| 2 | `poc` | PoC 公開 |
| 4 | `exploited` | **悪用確認済み** |
| 8 | `kev` | CISA KEV 掲載 |
| 16 | `ransomware` | ランサムウェア攻撃での悪用確認 |

```js
const F = meta.search_index.flags;
const exploited = rows.filter((r) => r[8] & F.exploited);
```

### 索引に含まれる補助データ

| キー | 内容 |
|---|---|
| `prefix_dictionary` | 詳細ファイルの配置パターン（139 種類）。`rows[i][13]` がこの配列への添字 |
| `attack_surfaces` | 分類 ID → 表示名 |
| `vendors` | 出現するベンダー名の一覧（140 件） |
| `stats` | 件数サマリ |

## 3. 個別詳細（raw.githubusercontent.com）

事前生成した JSON はありません。**台帳の YAML をそのまま配信**します。常に最新で、索引より内容が厚くなります。

```js
const url = meta.endpoints.detail_url_template
  .replace("{prefix}", idx.prefix_dictionary[row[13]])
  .replace("{vuln_id}", row[0]);
const yamlText = await (await fetch(url)).text();   // YAML パーサが必要（js-yaml など）
```

詳細にのみ含まれる主な項目:

| 項目 | 内容 |
|---|---|
| `fixed_versions` | 修正版の一覧 |
| `sources[]` | 全出典（`url`・`vendor`・`first_seen_at`・`last_seen_at`） |
| `exploitation_reports[]` | OSINT が報じた実悪用。**根拠となった記事中の文（`evidence`）と出典 URL 付き** |
| `exploitation_source` | 最初に悪用を裏づけた出典（`cisa_kev` / `osint` / ベンダーの source ID） |
| `kev_listed_at` | CISA KEV 掲載日 |
| `products` / `vendors` | 切り詰めのない全量 |

`prefix` が `-1` の行は配置が不明なため、詳細 URL を組み立てられません（現在は 0 件）。

## 4. iframe 埋め込みと postMessage

```html
<iframe id="vulnwatch" src="https://proshiba.github.io/vuln-intel-agent/"
        width="100%" height="800"></iframe>
```

読み込みが終わると、子から親へ `vulnwatch:ready` が届きます。**これを待ってから問い合わせてください。**

```js
const frame = document.getElementById("vulnwatch");

window.addEventListener("message", (event) => {
  const d = event.data;
  if (!d || typeof d !== "object") return;
  switch (d.type) {
    case "vulnwatch:ready":  /* d.meta, d.stats */ break;
    case "vulnwatch:result": /* d.matched, d.rows（d.requestId で対応付け） */ break;
    case "vulnwatch:entry":  /* d.entry */ break;
    case "vulnwatch:meta":   /* d.meta */ break;
  }
});

frame.contentWindow.postMessage({
  type: "vulnwatch:query",
  requestId: "q1",
  q: "ivanti",
  filters: {
    priority: "P1",            // P1 | P2 | P3 | INFO
    vendor: "Ivanti",
    minCvss: 7,                // 0 | 4 | 7 | 9
    sinceDays: 30,             // 0 | 7 | 30 | 90 | 365（公開日）
    attackSurface: "vpn_gateway",
    kev: true, exploited: true, poc: false, ransomware: false, fixed: false,
  },
  sort: "cvss",                // upd | pub | cvss | prio
  limit: 50,                   // 1..500（既定 50）
}, "*");
```

送ったクエリは**そのまま iframe 内の表示にも反映**されます。ポータルの検索欄と表示を連動させられます。

| 送るメッセージ | 返るメッセージ | 用途 |
|---|---|---|
| `vulnwatch:meta` | `vulnwatch:meta` | discovery 文書を得る |
| `vulnwatch:query` | `vulnwatch:result` | 絞り込み＋結果取得 |
| `vulnwatch:get`（`cve` か `id`） | `vulnwatch:entry` | 1 件取得 |

`vulnwatch:result` / `vulnwatch:entry` の各行は、索引の生配列ではなく**名前付きオブジェクト**で返ります。

```jsonc
{ "id": "VW-2026-0001", "cve": "CVE-2026-1281", "vendors": "Ivanti",
  "products": "Connect Secure", "title": "...", "cvss": 9.8, "severity": "Critical",
  "priority": "INFO", "attackSurface": "vpn_gateway", "kevLagDays": 6,
  "published": "2026-07-20", "updated": "2026-07-25",
  "kev": true, "exploited": true, "poc": false, "ransomware": false, "fixed": true,
  "detailUrl": "https://raw.githubusercontent.com/.../VW-2026-0001.yaml" }
```

`severity` はここでは正規化済み（`Critical`/`High`/`Moderate`/`Low`）です。`detailUrl` はそのまま取得できます。

### 問い合わせの性質

- **状態を持ち越しません。** 各 `vulnwatch:query` は毎回まっさらな条件から組み立てられるため、前回指定した絞り込みが残ることはありません。
- 応答は**要求元のウィンドウにのみ**返します。
- 送信元オリジンは制限していません。配信内容はすべて公開情報で、書き込み操作が存在しないためです。

## 5. 実装時の注意（重要）

データの素性を知らないと誤った UI を作りやすい箇所です。

### `sev`（索引の 6 列目）は正規化されていない

出典ごとの生の文字列がそのまま入ります。実データでの分布:

```
"" (12,421)  HIGH (11,520)  MEDIUM (9,589)  CRITICAL (3,463)  high (1,000)
medium (1,000)  LOW (784)  important (613)  Important (591)  critical (388) ...
```

大文字小文字が混在し、Red Hat 系の `Important` / `Moderate` 語彙も混ざります。**`cvss` から判定するか、`toLowerCase()` したうえで `important`→High、`moderate`→Medium として正規化してください。** postMessage 応答の `severity` は正規化済みなので、そちらを使う手もあります。

### `prio` は現在すべて `INFO`

優先度は「自組織の資産台帳（`config/products.yaml`）と一致するか」で決まります。現在この台帳は空のため、**全 42,171 件が `INFO`** です。優先度を軸にした画面を作っても意味を持ちません。重要度は `cvss`・`flags`・`asc` から組み立ててください。

### 欠損は珍しくない

`cve` 5,794 件、`cvss` 8,473 件、`pub` 1,022 件が空です。**空文字を数値として扱わないよう**注意してください。CVE 未採番の脆弱性は内部 ID（`id`）で識別します。

### `poc` フラグは網羅していない

現在 8 件しか立っていません。PoC の公開有無を体系的に追跡してはいないため、**「PoC なし」を根拠に安全と判断しないでください。**

### 悪用確認は取り消されない

`exploited` は一度立つと下げません。OSINT 由来の報告は**独立 2 ソースの裏づけが取れるまで**このフラグを立てず、詳細側の `exploitation_reports` に候補として溜まります。「報告はあるが未確定」を扱いたい場合は詳細を参照してください。

### `ransomware` と `lag` は蓄積中

スキーマは入っていますが、値が入るのは次回以降の日次収集分からです。現時点の集計は 0 件です。

### 鮮度とキャッシュ

日次収集のたびに再生成されます。`meta.generated_at` が生成時刻です。キャッシュは Pages が 600 秒、raw が 300 秒。**リアルタイム性は前提にしないでください。**

## 6. 最小実装例

```js
const BASE = "https://proshiba.github.io/vuln-intel-agent/";

const meta = await (await fetch(BASE + "api/v1/meta.json")).json();
const idx  = await (await fetch(BASE + meta.endpoints.search)).json();

const col = Object.fromEntries(idx.fields.map((n, i) => [n, i]));
const F = meta.search_index.flags;

// 初期アクセスに使われうる製品で、実際に悪用が確認されているもの
const hits = idx.rows.filter(
  (r) => r[col.asc] === "vpn_gateway" && r[col.flags] & F.exploited
);

// 詳細は必要になった時だけ取得する
const first = hits[0];
const detailUrl = meta.endpoints.detail_url_template
  .replace("{prefix}", idx.prefix_dictionary[first[col.prefix]])
  .replace("{vuln_id}", first[col.id]);
```

## 7. 互換性について

- `meta.schema_version` と `api_version` を確認してください。破壊的変更時に上げます。
- `fields` への**列の追加は予告なく行います。** 添字を直書きせず `fields` から解決してください。
- `flags` のビット値も `meta` から解決してください。
- 内部 ID（`id`）は恒久キーです。CVE が後から判明しても変わりません。
