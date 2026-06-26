# 기여 가이드

`nimsodium`은 작고, 고수준이며, 오용하기 어렵게 유지되어야 합니다.

기여를 환영합니다. 특히 테스트 확충, 문서, 예제, OS/Nim/libsodium 조합별 동작 확인 보고, CI 개선, packaging 수정, 유지보수 업데이트를 환영합니다. 동작 확인 중 발견한 문제 보고와 그 보고에 기반한 버그 수정도 환영합니다.

## 시작하기 좋은 기여

- 기존 workflow 예제 개선
- 잘못된 입력과 실패 경로 테스트 추가
- 특정 OS, Nim 버전, libsodium 버전에서 설치와 테스트 확인
- 문서, 번역, release notes 개선
- 안정적인 upstream reference 기반 known-answer tests 추가
- 새로운 libsodium 또는 Nim release에 맞춘 maintenance notes 업데이트

## 보안에 민감한 변경

다음 내용을 바꾸기 전에는 먼저 issue 또는 design note를 열어 주세요.

- 공개 cryptographic API 형태
- 저장되는 binary format
- password encryption parameters
- nonce, salt, tag, header 처리
- key derivation context 또는 typed key 동작
- raw FFI declarations
- authentication failure behavior
- file output replacement behavior

보안에 민감한 변경을 설명 없는 refactor로 보내지 마세요. use case, 사용하는 raw libsodium symbol, 예상되는 failure mode, 오용 방지를 검증하는 test를 설명해 주세요.

## 설계 규칙

- 암호 자체를 직접 발명하지 않습니다.
- main API로 raw libsodium API 전체를 노출하지 않습니다.
- 일반적인 작업에서 caller가 nonce, MAC tag, output buffer를 직접 관리하게 하지 않습니다.
- password storage에 generic hash를 사용하지 않습니다.
- authentication 실패 시 plaintext를 반환하지 않습니다.
- 새로운 public high-level API에서는 string-based key parameter를 늘리지 않습니다. 목적별 key type과 checked constructor를 사용합니다.
- 실패할 수 있는 libsodium return code는 모두 확인합니다.
- package-specific exception은 `nimsodium/errors.nim`에서 던집니다.
- raw symbol coverage보다 safe workflow coverage를 우선합니다.

## 테스트

```sh
nim check --path:src --nimcache:/tmp/nimsodium_nimcache src/nimsodium.nim
nim check --path:src --nimcache:/tmp/nimsodium_nimcache src/nimsodium/advanced.nim
nim c -r --path:src --nimcache:/tmp/nimsodium_nimcache tests/test_nimsodium.nim
env NIMBLE_DIR=/tmp/nimble nimble check
```

릴리스 전에는 문서 생성도 확인해 주세요.

```sh
nim doc --project --index:on --outdir:/tmp/nimsodium_htmldocs --path:src src/nimsodium.nim
nim doc --outdir:/tmp/nimsodium_htmldocs --path:src src/nimsodium/advanced.nim
```

취약점 가능성이 있는 내용은 [Security Policy](../SECURITY.md)에 따라 보고해 주세요. 실제 secret, token, password, private key를 issue나 pull request에 포함하지 마세요.
