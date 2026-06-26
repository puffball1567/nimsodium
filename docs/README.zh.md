# nimsodium 中文指南

`nimsodium` 是面向 Nim 应用程序的安全优先 libsodium 封装。

当你需要密码哈希、token 指纹、认证加密、文件加密、公钥 sealed box 或签名，并且不想直接管理 nonce、MAC tag、输出缓冲区或原始返回码时，可以选择它。

如果你需要直接访问完整的 libsodium C API，请选择 raw binding。`nimsodium` 是面向应用的高层 API，不是完整 binding。

## 为什么选择 nimsodium？

- nonce 在内部生成，并随 ciphertext 一起保存。
- 公共 API 中的密钥材料使用独立的 Nim 类型，而不是普通 string。
- 覆盖常见需求：password、token、AEAD、file encryption、public-key encryption、signature、KDF、random、encoding 和 cleanup。
- 加密原语由 libsodium 提供。
- 包含 tests、examples、audit notes、security policy 和 third-party notices。

## 安装

libsodium 必须能被 C linker 找到。

Ubuntu/Debian:

```sh
sudo apt-get install libsodium-dev
```

macOS:

```sh
brew install libsodium
```

检查:

```sh
pkg-config --modversion libsodium
```

发布后，将 `nimsodium` 添加到你的 Nimble 项目中。

## 状态

项目仍处于 `v0.2` pre-release。它适合评估和早期采用，但在 `v1.0` 之前 API 名称和存储格式仍可能变化。原始 libsodium FFI 是实现细节，不是公共 API。

## 贡献

[贡献指南](CONTRIBUTING.zh.md) 说明了如何贡献测试扩充、运行确认报告、基于这些报告的 bug 修复、翻译、文档和示例。

## 快速开始

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

运行:

```sh
nim c -r --path:src --nimcache:/tmp/nimsodium_example_quickstart examples/quickstart.nim
```

## 应该使用哪个 API？

```text
需求                              API
保存密码                          hashPassword / verifyPassword
生成 API key 或 session token      randomBase64 / randomHex
保存 token 指纹                   generateKeyedHashKey / keyedHashHex
加密数据库字段                     generateAeadKey / encryptAead / decryptAead
加密小型本地 secret                generateSecretBoxKey / encryptSecretBox / decryptSecretBox
加密大型文件                       generateStreamKey / encryptFile / decryptFile
发送给公钥持有者                   generateBoxKeyPair / sealBox / openBox
签名和验证消息                     generateSigningKeyPair / signDetached / verifyDetached
按用途派生 subkey                  generateKdfKey / deriveKey
比较 secret value                  constantTimeEquals
清除当前 string buffer             secureZero / secureClear
编码 binary data                   toHex / fromHex / toBase64 / fromBase64
```

Advanced API 需要显式使用 `import nimsodium/advanced`。

```text
派生 client/server session key      generateKeyExchangeKeyPair / clientSessionKeys / serverSessionKeys
计算短 keyed identifier             generateShortHashKey / shortHashHex
加密前 padding                      padMessage / unpadMessage
处理 detached AEAD 字段              encryptAeadDetached / decryptAeadDetached
处理 detached secretbox 字段         encryptSecretBoxDetached / decryptSecretBoxDetached
一次性消息认证                       generateOneTimeAuthKey / oneTimeAuthenticate / verifyOneTimeAuthentication
```

## 生产环境注意事项

- 通过操作系统或可信包管理器安装并更新 libsodium。
- 可在诊断信息或启动日志中使用 `sodiumVersion()` 检查链接到的运行时版本。
- 不要把密钥写入源代码或日志。
- 只有在需要持久化或传输密钥时才使用 `rawBytes`，并用应用自己的 key management 机制保护它。
- associated data 是协议的一部分。解密时必须使用与加密时完全相同的值。
- 将 `CryptoError` 视为认证失败，而不是可以恢复的 plaintext。
- 重新分发时请包含 `THIRD_PARTY_NOTICES.md` 和 `licenses/`。

## 限制

- `0.x` 版本仍可能调整名称和类型。
- `src/nimsodium/private/raw/` 不是受支持的 API。
- `secureZero` 和 `secureClear` 只清除当前 string buffer。Nim 或应用已经创建的副本不会被清除。
