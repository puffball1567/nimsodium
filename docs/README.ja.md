# nimsodium 日本語ガイド

`nimsodium` は、Nim アプリケーション向けの安全寄りな libsodium ラッパーです。

パスワードハッシュ、トークンのフィンガープリント、認証付き暗号化、ファイル暗号化、公開鍵 sealed box、署名を、nonce、MAC tag、出力バッファ、raw return code を直接扱わずに使いたい場合に選んでください。

libsodium の C API 全体へ直接アクセスしたい場合は、raw binding のほうが適しています。`nimsodium` は完全な binding ではなく、アプリケーション向けの高水準 API です。

## nimsodium を選ぶ理由

- nonce は内部で生成され、ciphertext に保存されます。
- 公開 API では key material を plain string ではなく用途別の型で扱います。
- password、token、AEAD、file encryption、public-key encryption、signature、KDF、random、encoding、cleanup をカバーします。
- 暗号プリミティブの実装は libsodium に委譲します。
- tests、examples、audit notes、security policy、third-party notices を含みます。

## インストール

libsodium が C linker から見える必要があります。

Ubuntu/Debian:

```sh
sudo apt-get install libsodium-dev
```

macOS:

```sh
brew install libsodium
```

確認:

```sh
pkg-config --modversion libsodium
```

公開後は Nimble project に `nimsodium` を追加してください。

## ステータス

このプロジェクトは `v0.2` pre-release です。評価や early adoption を想定していますが、`v1.0` までは API 名や stored format が変わる可能性があります。raw libsodium FFI は実装詳細であり、公開 API ではありません。

## コントリビューション

[コントリビューションガイド](CONTRIBUTING.ja.md)では、テストの拡充、動作確認報告、その報告に基づくバグ修正、翻訳、docs、examples の追加方針を説明しています。

## Quickstart

```nim
import nimsodium

let passwordHash = hashPassword("correct horse battery staple")
doAssert verifyPassword(passwordHash, "correct horse battery staple")

let key = generateAeadKey()
let ciphertext = encryptAead("secret payload", key, "record:42")
doAssert decryptAead(ciphertext, key, "record:42") == "secret payload"

let token = randomBase64(32)
let hashKey = generateKeyedHashKey()
let fingerprint = keyedHashHex(token, hashKey)
```

実行:

```sh
nim c -r --path:src --nimcache:/tmp/nimsodium_example_quickstart examples/quickstart.nim
```

## どの API を使うべきか

```text
やりたいこと                         使う API
パスワード保存                       hashPassword / verifyPassword
API key や session token の生成      randomBase64 / randomHex
token fingerprint の保存             generateKeyedHashKey / keyedHashHex
DB field の暗号化                    generateAeadKey / encryptAead / decryptAead
小さな local secret の暗号化         generateSecretBoxKey / encryptSecretBox / decryptSecretBox
大きな file の暗号化                 generateStreamKey / encryptFile / decryptFile
公開鍵宛ての暗号化                   generateBoxKeyPair / sealBox / openBox
message の署名と検証                 generateSigningKeyPair / signDetached / verifyDetached
用途別 subkey の導出                 generateKdfKey / deriveKey
secret value の比較                  constantTimeEquals
現在の string buffer の消去          secureZero / secureClear
binary data の encoding              toHex / fromHex / toBase64 / fromBase64
```

Advanced API は `import nimsodium/advanced` で明示的に使います。

```text
client/server session key の導出     generateKeyExchangeKeyPair / clientSessionKeys / serverSessionKeys
短い keyed identifier の計算          generateShortHashKey / shortHashHex
暗号化前の padding                   padMessage / unpadMessage
detached AEAD field の処理            encryptAeadDetached / decryptAeadDetached
detached secretbox field の処理       encryptSecretBoxDetached / decryptSecretBoxDetached
one-time message authentication       generateOneTimeAuthKey / oneTimeAuthenticate / verifyOneTimeAuthentication
```

## 運用上の注意

- libsodium は OS や信頼できる package manager で更新してください。
- 診断や起動ログでは `sodiumVersion()` で linked runtime を確認できます。
- key を source code や log に置かないでください。
- key を保存・転送する必要がある場合だけ `rawBytes` を使い、アプリケーション側の key management で保護してください。
- associated data は protocol の一部です。復号時には暗号化時と同じ値が必要です。
- `CryptoError` は認証失敗として扱い、平文が得られたものとして処理しないでください。
- 再配布する場合は `THIRD_PARTY_NOTICES.md` と `licenses/` を含めてください。

## 制限

- `0.x` では名前や型が変わる可能性があります。
- `src/nimsodium/private/raw/` はサポート対象の API ではありません。
- `secureZero` / `secureClear` は現在の string buffer だけを対象にします。Nim やアプリケーションがすでに作った copy は消せません。
