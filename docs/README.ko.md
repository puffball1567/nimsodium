# nimsodium 한국어 가이드

`nimsodium`은 Nim 애플리케이션을 위한 안전 기본값 중심의 libsodium 래퍼입니다.

password hashing, token fingerprint, authenticated encryption, file encryption, public-key sealed box, signature가 필요하지만 nonce, MAC tag, output buffer, raw return code를 직접 다루고 싶지 않을 때 사용하세요.

libsodium C API 전체에 직접 접근해야 한다면 raw binding이 더 적합합니다. `nimsodium`은 완전한 binding이 아니라 애플리케이션용 고수준 API입니다.

## 왜 nimsodium인가?

- nonce는 내부에서 생성되고 ciphertext와 함께 저장됩니다.
- 공개 API의 key material은 plain string이 아니라 목적별 Nim 타입을 사용합니다.
- password, token, AEAD, file encryption, public-key encryption, signature, KDF, random, encoding, cleanup을 다룹니다.
- 암호 프리미티브는 libsodium에 위임합니다.
- tests, examples, audit notes, security policy, third-party notices를 포함합니다.

## 설치

libsodium이 C linker에서 보여야 합니다.

Ubuntu/Debian:

```sh
sudo apt-get install libsodium-dev
```

macOS:

```sh
brew install libsodium
```

확인:

```sh
pkg-config --modversion libsodium
```

공개 후에는 Nimble 프로젝트에 `nimsodium`을 추가하세요.

## 상태

이 프로젝트는 `v0.2` pre-release입니다. 평가와 early adoption을 위한 상태이며, `v1.0` 전까지는 API 이름과 stored format이 바뀔 수 있습니다. raw libsodium FFI는 구현 세부사항이며 공개 API가 아닙니다.

## 기여

[기여 가이드](CONTRIBUTING.ko.md)는 테스트 확충, 동작 확인 보고, 그 보고에 기반한 버그 수정, 번역, 문서, 예제 기여 방식을 설명합니다.

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

실행:

```sh
nim c -r --path:src --nimcache:/tmp/nimsodium_example_quickstart examples/quickstart.nim
```

## 어떤 API를 써야 하나?

```text
필요한 작업                         API
password 저장                       hashPassword / verifyPassword
API key 또는 session token 생성      randomBase64 / randomHex
token fingerprint 저장              generateKeyedHashKey / keyedHashHex
database field 암호화               generateAeadKey / encryptAead / decryptAead
작은 local secret 암호화             generateSecretBoxKey / encryptSecretBox / decryptSecretBox
큰 file 암호화                      generateStreamKey / encryptFile / decryptFile
public key 대상으로 암호화           generateBoxKeyPair / sealBox / openBox
message 서명과 검증                 generateSigningKeyPair / signDetached / verifyDetached
용도별 subkey 파생                  generateKdfKey / deriveKey
secret value 비교                   constantTimeEquals
현재 string buffer 삭제              secureZero / secureClear
binary data encoding                toHex / fromHex / toBase64 / fromBase64
```

Advanced API는 `import nimsodium/advanced`로 명시적으로 사용합니다.

```text
client/server session key 파생       generateKeyExchangeKeyPair / clientSessionKeys / serverSessionKeys
짧은 keyed identifier 계산           generateShortHashKey / shortHashHex
암호화 전 padding                    padMessage / unpadMessage
detached AEAD field 처리             encryptAeadDetached / decryptAeadDetached
detached secretbox field 처리        encryptSecretBoxDetached / decryptSecretBoxDetached
one-time message authentication      generateOneTimeAuthKey / oneTimeAuthenticate / verifyOneTimeAuthentication
```

## 운영 시 주의사항

- libsodium은 운영체제나 신뢰할 수 있는 package manager로 설치하고 업데이트하세요.
- 진단 정보나 시작 로그에서 `sodiumVersion()`으로 연결된 runtime을 확인할 수 있습니다.
- key를 source code나 log에 저장하지 마세요.
- key를 저장하거나 전송해야 할 때만 `rawBytes`를 사용하고, 애플리케이션의 key management로 보호하세요.
- associated data는 protocol의 일부입니다. 복호화에는 암호화 때와 정확히 같은 값이 필요합니다.
- `CryptoError`는 인증 실패로 처리해야 하며, 복구 가능한 plaintext로 다루면 안 됩니다.
- 재배포할 때는 `THIRD_PARTY_NOTICES.md`와 `licenses/`를 포함하세요.

## 제한

- `0.x` 릴리스에서는 이름과 타입이 아직 바뀔 수 있습니다.
- `src/nimsodium/private/raw/`는 지원되는 API가 아닙니다.
- `secureZero`와 `secureClear`는 현재 string buffer만 지웁니다. Nim이나 애플리케이션이 이미 만든 복사본은 지우지 않습니다.
