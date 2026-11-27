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
sigil build --root sigil sigil/aegis_gateway.sigil main -o aegis
AEGIS_PORT=8080 AEGIS_UPSTREAM_PORT=8081 ./aegis
```

標準の増分 HTTP パーサーで受信し、SNI がある場合は Host の DNS 名を照合します。
検査には固定経路 ID `default` と第1段の基本ルールを使います。この経路では本文の
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
