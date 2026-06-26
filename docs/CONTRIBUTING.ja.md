# コントリビューションガイド

`nimsodium` は、小さく、高水準で、誤用しにくい libsodium ラッパーであることを重視します。

コントリビューションを歓迎します。特に、テストの拡充、ドキュメント、examples、OS/Nim/libsodium ごとの動作確認報告、CI 改善、packaging 修正、メンテナンス更新を歓迎します。動作確認で見つかった不具合の報告と、そのバグ修正も歓迎します。

## はじめやすい貢献

- 既存 workflow の examples を改善する
- 不正入力や失敗経路のテストを追加する
- 特定の OS、Nim version、libsodium version でインストールとテストを確認する
- docs、翻訳、release notes を改善する
- 安定した upstream reference に基づく known-answer tests を追加する
- 新しい libsodium または Nim release に合わせて maintenance notes を更新する

## セキュリティに関わる変更

次の変更は、先に issue または design note を開いてください。

- 公開 cryptographic API の形
- 保存される binary format
- password encryption parameters
- nonce、salt、tag、header の扱い
- key derivation context や typed key behavior
- raw FFI declarations
- authentication failure behavior
- file output replacement behavior

セキュリティに関わる変更を、説明のない refactor として送らないでください。use case、使う raw libsodium symbol、想定される failure mode、誤用しにくさを確認する test を説明してください。

## 設計ルール

- 暗号そのものを独自実装しない。
- main API として raw libsodium API 全体を公開しない。
- 一般的な用途で caller に nonce、MAC tag、output buffer を管理させない。
- password storage に generic hash を使わない。
- authentication に失敗したとき plaintext を返さない。
- 新しい public high-level API では string-based key parameter を増やさない。用途別 key type と checked constructor を使う。
- 失敗しうる libsodium return code は必ず確認する。
- package-specific exception は `nimsodium/errors.nim` から投げる。
- raw symbol coverage より safe workflow coverage を優先する。

## テスト

```sh
nim check --path:src --nimcache:/tmp/nimsodium_nimcache src/nimsodium.nim
nim check --path:src --nimcache:/tmp/nimsodium_nimcache src/nimsodium/advanced.nim
nim c -r --path:src --nimcache:/tmp/nimsodium_nimcache tests/test_nimsodium.nim
env NIMBLE_DIR=/tmp/nimble nimble check
```

リリース前には docs 生成も確認してください。

```sh
nim doc --project --index:on --outdir:/tmp/nimsodium_htmldocs --path:src src/nimsodium.nim
nim doc --outdir:/tmp/nimsodium_htmldocs --path:src src/nimsodium/advanced.nim
```

脆弱性の可能性がある内容は [Security Policy](../SECURITY.md) に従って報告してください。実際の secret、token、password、private key は issue や pull request に含めないでください。
