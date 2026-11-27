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
