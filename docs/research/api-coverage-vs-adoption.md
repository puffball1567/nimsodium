# API Coverage vs Adoption

Research date: 2026-06-26.

This note compares libsodium-related libraries by adoption signals and API
surface strategy. Download numbers are time-dependent and should be refreshed
before making release or positioning decisions.

## Current nimsodium Coverage

`nimsodium` currently exposes 89 public procs over 356 internal raw FFI procs.
That is about 25.0% by a simple proc-count comparison.

This is not intended to mean "25% of libsodium's usefulness." The public API is
curated: common and safe workflows are exposed by default, while specialized
but still high-level APIs live under `nimsodium/advanced`.

## Adoption Signals

| Project | Ecosystem | Adoption signal | API strategy | Coverage signal |
| --- | --- | ---: | --- | --- |
| PyNaCl | Python | 53,598,564 downloads last week; 229,260,716 last month | High-level Python binding with selected feature groups | Not full libsodium coverage |
| tweetnacl | JavaScript | 31,964,810 npm downloads last week | Very small NaCl-style API | Low coverage, very high adoption |
| libsodium / libsodium-wrappers | JavaScript | 2,886,609 / 2,862,956 npm downloads last week | Recommended standard package with common high-level functions | Medium-high coverage |
| libsodium-wrappers-sumo | JavaScript | 307,135 npm downloads last week | Full symbol package including rare, undocumented, deprecated, and easy-to-misuse symbols | Very high coverage, lower adoption than standard |
| sodium-native | JavaScript | 546,326 npm downloads last week | Thin low-level wrapper around libsodium | High coverage, lower adoption than standard wrappers |
| sodiumoxide | Rust | 7,356,699 total crates.io downloads; 853,112 recent downloads | Broad Rust binding/wrapper | High coverage, but archived/deprecated |
| dryoc | Rust | 186,643 total crates.io downloads; 32,488 recent downloads | Type-safe, hard-to-misuse, broad Rust implementation | High coverage, newer/lower adoption |

Sources:

- npm downloads API:
  - `https://api.npmjs.org/downloads/point/last-week/libsodium`
  - `https://api.npmjs.org/downloads/point/last-week/libsodium-wrappers`
  - `https://api.npmjs.org/downloads/point/last-week/libsodium-wrappers-sumo`
  - `https://api.npmjs.org/downloads/point/last-week/sodium-native`
  - `https://api.npmjs.org/downloads/point/last-week/tweetnacl`
- PyPI Stats API:
  - `https://pypistats.org/api/packages/pynacl/recent`
- crates.io API:
  - `https://crates.io/api/v1/crates/sodiumoxide`
  - `https://crates.io/api/v1/crates/dryoc`

## Observations

API coverage is not the primary explanation for download volume.

The strongest counterexample is `tweetnacl`: it has a very small API surface but
massive weekly npm downloads. This points to install simplicity, ecosystem
fit, stability, and transitive dependency usage as stronger adoption drivers
than raw API breadth.

The JavaScript libsodium packages also argue against "more symbols means more
downloads." `libsodium-wrappers` has about 9.3x the weekly downloads of
`libsodium-wrappers-sumo`, even though the sumo package exposes far more
symbols. The standard package is explicitly recommended for most projects,
while sumo exists for users who need extra symbols.

`sodium-native` shows that broad low-level coverage is useful, but it does not
automatically dominate adoption. It serves users who want a thin binding and
accept more responsibility for buffer and API details.

`PyNaCl` has very high adoption without trying to expose every libsodium
primitive as the main product. It presents selected cryptographic workflows,
ships wheels, includes bundled libsodium support, and has long ecosystem
presence. Its adoption looks more related to trust, packaging, and common-use
coverage than to full raw coverage.

The Rust comparison is mixed. `sodiumoxide` has broad coverage and historical
download volume, but it is archived. `dryoc` is broad and quality-oriented, but
its adoption is much smaller. This suggests that coverage helps once a project
is already trusted, but coverage alone does not create adoption.

## Implication for nimsodium

The goal should not be "bind everything publicly." The stronger strategy is:

1. Keep `import nimsodium` safe, small enough, and obvious for application code.
2. Grow `nimsodium/advanced` for legitimate protocols and interoperability.
3. Keep raw FFI private unless there is a compelling reason to expose a separate
   unsafe/low-level package later.
4. Prioritize workflows over symbols: password hashing, token generation,
   hashes, MACs, KDF, secretbox, AEAD, sealed boxes, signatures, secretstream,
   file encryption, key exchange, padding, detached fields, and one-time auth.
5. Treat tests, examples, docs, CI, license notices, and install reliability as
   adoption features, not secondary polish.

## Recommended Coverage Direction

For "choose this by default" positioning, `nimsodium` should keep expanding
coverage only where the wrapper can preserve a safer shape than the raw C API.

Good candidates:

- more conversion helpers for key and signature formats
- sealed-box and signature examples for interoperability
- additional stream/file tests with corruption and partial-write cases
- deterministic test-vector coverage for public wrappers
- clearer API matrix in documentation
- platform installation notes for libsodium

Poor candidates for the default import:

- raw nonce-management variants
- low-level scalar/core operations
- undocumented or deprecated libsodium symbols
- APIs that require callers to manually manage output buffers, state pointers,
  or return codes

The current 25.0% public-proc coverage is therefore a healthy midpoint for a
pre-release Nim library. Increasing toward 30-40% can help differentiate
`nimsodium`, but only if that growth stays behind safe default APIs and an
explicit advanced namespace.
