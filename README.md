# sigil-aegis-waf

Sigil 製の独立した Web アプリケーション・ファイアウォール（WAF）部品。

仕様は [goodnasubi/sigil](https://github.com/goodnasubi/sigil) の ADR 0068（Web アプリケーション・ファイアウォール（sigil-aegis-waf））に基づき、配置境界において `shield-tls → aegis-waf → sigix` の順で HTTP リクエストの検査、既知攻撃の遮断、レート制限、IP 評価を担当します。

## 第1段: ポリシーと検査の核（ADR 0068 決定 7）

- **型付き検査入力と検査結果** (`RequestInput`, `Decision`, `Action`, `Header`)
  - 検査対象: メソッド、パス、クエリ、ヘッダー、本文、固定経路 ID。
  - 作用の優先順位: 遮断 (`Block`) ＞ 追加確認 (`Challenge`) ＞ 記録のみ (`LogOnly`) ＞ 通過 (`Pass`)。
- **ポリシーとルールの宣言スキーマ** (`Policy`, `Rule`, `Exception`)
  - UTF-8 の版付き JSON を `std.json` で読み、型付きで評価。
  - 演算子: 完全一致 (`exact`)、前方一致 (`prefix`)、リテラル部分一致 (`contains`)、有限集合への所属 (`in`)。
  - 全体検証: 版・未知項目・型・重複 ID・件数・サイズ上限を検証。
- **版付きのマネージド基本ルールセット** (`default_managed_policy`)
  - 版: `2026-11-28-v1`
  - TRACE/TRACK メソッド遮断、パストラバーサル遮断、SQL インジェクション検知、XSS 検知、管理パス記録、認証確認。
- **理由と失効日時付きの例外** (`Exception`)
  - ルール ID と固定の経路 ID を指定した例外により、遮断を記録のみに降格。
  - 期限切れの例外は作用しない。
- **ポリシーの原子的な差し替え** (`AegisEngine`)
  - 再読み込み時、検証エラーが発生した場合は直前の有効版を保持。

## 検証方法

Sigil コンパイラは `goodnasubi/sigil` の完全コミット SHA `e1a0291ab419dca0a04c9d7315c3567b81308a1f` に固定されています。

```bash
# 検証スクリプトの実行（フォーマット、評価器、ネイティブバイナリのテスト）
./scripts/check.sh
```

## 第2段（HTTP と配置境界）

`aegis_gateway` は IPv4 ループバックの専用リスナーで、接続の先頭に shield-tls
形式の PROXY v2 を受け付けます。平文区間を shield-tls・WAF・sigix の管理下に置き、
同居するプロセスを信頼できる環境で使用してください。PROXY v2 のアドレスは
TCP over IPv4・IPv6 の両方を扱い、TLS 1.3 の SSL TLV を必須とします。

```bash
build_root=$(mktemp -d)
cp Sigil.toml sigil/*.sigil "$build_root/"
git clone https://github.com/goodnasubi/sigil-argus-observe.git "$build_root/argus"
git -C "$build_root/argus" checkout --detach 113aeed4932d841d752d752e77dc767ed6b4c886
cp "$build_root/argus/argus_observe.sigil" "$build_root/"
sigil build --root "$build_root" "$build_root/aegis_gateway.sigil" main -o aegis
AEGIS_PORT=8080 AEGIS_UPSTREAM_PORT=8081 ./aegis
```

標準の増分 HTTP パーサーで受信し、SNI がある場合は Host の DNS 名を照合します。
検査には設定で割り当てた経路 ID と第1段の基本ルールを使います。この経路では本文の
メディア型別の検査は設定せず、本文のフレーミングとサイズ上限を適用します。
要求を一件ずつ処理して接続を閉じます。通過時に専用の上流接続を開き、PROXY v2
の受信バイト列に続けて、検証済みの要求を Content-Length 方式で送信します。

`scripts/check.sh` は Sigil の固定版に加えて、shield-tls
`63d3051b18e6d0e90c1ebe8f76e6ce267d7534a4` の PROXY v2 エンコーダーを使います。
ループバック試験では上流の受信側をテスト用ソケットで構成し、通常要求の転送、
接続情報の一致、本文受信完了までの待機、エラー応答、遮断・追加確認時の
上流接続の不在を確認します。

### 実プロセス間の結合に必要な追補

- **sigix** の固定確認版 `430b484b4f8d35f313a857974f7d1d63ad06cad3` は
  HTTP を直接受け付け、信頼済みピアからの HTTP 転送ヘッダーを利用します。
  ADR 0063 決定 5.2 の専用 PROXY v2 リスナー、SNI と Host の照合、接続元と
  TLS 情報の継承は sigix 側の追補です。対応版を完全 SHA で固定してから実機の
  受信確認を行う必要があります。
- **shield-tls** の上記固定版では PROXY v2 生成は利用可能です。
  `stage7_interop_server` は TLS 相互運用の試験サーバーで、後段への接続を
  行う運用エントリポイントが必要です。現時点の結合試験は同じエンコーダーが
  生成する平文区間のバイト列から始めます。

## 第3段（IP 評価・Argus 観測・レート制限の核）

- `AEGIS_IP_TABLE` は起動時に読み込む版付き JSON です。既定は空の表です。
  最大 256 件で、`expires_at` は UTC の Unix 秒です。理由は短い運用者定義の
  コードです。受信した PROXY v2 の送信元を正規化し、期限内の最長一致で
  `block` または `record` を適用します。`record` の場合も通常の検査を続けます。
- `AEGIS_ROUTES` は最大 64 件の `{"path":"/auth/verify","id":"verify"}` を持つ
  JSON 配列です。完全一致で経路 ID を選び、未分類は共通の `default` になります。
  CIDR 表と経路表の更新は、新しい設定を指定したプロセスの起動で適用します。
- `AEGIS_ARGUS_PORT` を設定すると、ループバック上の Argus の TCP 収集口へ
  NDJSON を送ります。既定の `0` は出力無効です。`AEGIS_TELEMETRY_CAPACITY` は
  送信待ちの最大件数で、既定は 128 件です。`waf_requests_total` と
  `waf_detections_total` はバッファの空きにかかわらず集計し、観測の欠落は
  `waf_telemetry_dropped_total` として報告します。送信処理が取り出した一バッチを
  別途保持します。この PROXY v2 契約には信頼済みの追跡 ID がありません。
- 送信形式と結合試験は Argus `113aeed4932d841d752d752e77dc767ed6b4c886`、
  結合試験の保存先は sigil-db `9483e36f08c35bfc62b3beeb008a531887506037` に固定しています。

```json
{
  "version": "v1",
  "entries": [
    {"cidr": "192.0.2.0/24", "effect": "record", "reason": "review_source", "expires_at": 1893456000}
  ]
}
```

### Sigil 側の追補

第3段の時点では単調時間の公開 API が無く、ゲートウェイへの接続は保留でした。
Sigil `1a4bf74`（PR #778）の `clock.monotonic_nanos()` により、第4段でレート制限
（429、`Retry-After`、表の満杯時の 503）と `waf_decision_seconds` を接続しました。

標準 HTTP パーサーはヘッダー受信済みの状態を公開しますが、検証済みの
ヘッダー・パスを得られるのは `HttpProgress.Done` の時点です。
現時点の IP 評価は HTTP の受信とフレーミングの完了後、WAF の本文ポリシー
評価前に行います。本文受信自体に先行する判定には、Sigil 側で検証済みの
要求ヘッドを渡せるパーサー API が必要です。

## 第4段（配備条件と計測）

制限値（要求行 8 KiB、ヘッダー 16 KiB・100 件、本文 1 MiB、検査期限 10 ms）、
状態コード（414/431/413/408/503/400/429）、`waf_decision_seconds`、計測結果、
誤検知対応・ロールバック・既知の制約は [docs/stage4-deploy.md](docs/stage4-deploy.md)、
ADR 0020 の完了記録は [docs/records/g2-stage4.md](docs/records/g2-stage4.md) にあります。
期限の確認には Sigil の単調時計 API（`clock.monotonic_nanos()`）を使います。
