# Security Policy

## Supported Versions

`nimsodium` is pre-release. Until `1.0.0`, security fixes are applied to the
latest development version.

## Reporting a Vulnerability

Please report suspected security issues privately before opening a public issue.

If no private security advisory channel is configured for the repository yet,
contact the maintainers directly and include:

- affected version or commit
- operating system and libsodium version
- minimal reproduction
- expected and actual behavior
- whether secrets, plaintext, keys, or authentication failures are involved

Do not include real production secrets in reports.

## Scope

Security-sensitive areas include:

- FFI signatures and buffer lengths
- nonce generation and storage
- authentication failure handling
- password hashing and rehash checks
- key derivation contexts
- key and signature length validation
- secret memory handling
- stored encrypted formats and migration behavior
- file output replacement after authentication failure

`nimsodium` delegates cryptographic primitives to libsodium. Reports about the
cryptographic implementation itself should also be checked against libsodium.

## Not Security Reports

Use normal issues or pull requests for:

- documentation improvements
- examples
- installation problems without secret exposure
- feature requests
- non-sensitive compatibility updates

If unsure, report privately first.
