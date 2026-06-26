# Testing Strategy

`nimsodium` tests are organized around safe workflows and security failure
cases, not raw libsodium symbol coverage.

## Required Checks

Run before release:

```sh
nim check --path:src --nimcache:/tmp/nimsodium_nimcache src/nimsodium.nim
nim check --path:src --nimcache:/tmp/nimsodium_nimcache src/nimsodium/advanced.nim
nim c -r --path:src --nimcache:/tmp/nimsodium_nimcache tests/test_nimsodium.nim
env NIMBLE_DIR=/tmp/nimble nimble check
nim doc --project --index:on --outdir:/tmp/nimsodium_htmldocs --path:src src/nimsodium.nim
nim doc --outdir:/tmp/nimsodium_htmldocs --path:src src/nimsodium/advanced.nim
```

CI also runs all examples.

## Security Cases

Every encryption or authentication workflow should have tests for the relevant
failure modes:

- wrong key or wrong password
- wrong associated data
- modified nonce, salt, header, ciphertext, tag, signature, or payload
- malformed or short structured input
- invalid key lengths
- invalid encoded input
- output replacement only after successful file authentication

## Current Coverage Matrix

| Workflow | Success | Wrong secret | Wrong AD | Tamper | Malformed | Output safety |
| --- | --- | --- | --- | --- | --- | --- |
| Password storage | yes | yes | n/a | invalid hash | yes | n/a |
| Password message encryption | yes | yes | yes | salt/ciphertext | magic/profile/short | n/a |
| Password file encryption | yes | yes | yes | header/ciphertext | magic/profile/short/missing salt | yes |
| Secretbox | yes | yes | n/a | nonce/ciphertext | yes | n/a |
| AEAD | yes | yes | yes | nonce/ciphertext | yes | n/a |
| Secretstream file encryption | yes | yes | yes | header/ciphertext | yes | yes |
| Sealed box | yes | yes | n/a | yes | yes | n/a |
| Authenticated public-key encryption | yes | yes | n/a | nonce/ciphertext | min length | n/a |
| Signatures | yes | wrong message/public key | n/a | yes | short signature | n/a |
| File signatures | yes | modified file | n/a | yes | short signature | n/a |
| Message authentication | yes | yes | n/a | yes | short tag | n/a |
| Token fingerprints | yes | wrong token | n/a | invalid hex | invalid length | n/a |
| KDF | yes | n/a | n/a | n/a | invalid context/length/key | n/a |
| Key import/export | yes | n/a | n/a | invalid base64 | invalid key length | n/a |
| Advanced key exchange | yes | invalid peer key | n/a | n/a | invalid key length | n/a |
| Advanced detached encryption | yes | yes | yes | yes | invalid parts | n/a |
| Advanced padding | yes | n/a | n/a | invalid padding | invalid block size | n/a |
| Advanced one-time auth | yes | yes | n/a | yes | short tag/key | n/a |

## Adding Tests

When adding a workflow:

1. Add a success test with binary-safe input where relevant.
2. Add authentication failure tests.
3. Add structured input validation tests.
4. Add output-safety tests for file-writing APIs.
5. Add an example if the workflow is user-facing.
6. Update this matrix.

Tests should assert that authentication failures never return plaintext.
