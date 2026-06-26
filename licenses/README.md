# Dependency Licenses

This directory stores license material for third-party projects that
`nimsodium` depends on or links against.

`nimsodium` does not vendor libsodium source code. It links against a system or
user-provided libsodium installation. The files under `licenses/libsodium/`
make the dependency license visible for users and redistributors.

When redistributing a build that bundles or ships libsodium itself, also review
the exact upstream libsodium source distribution used for that build.
