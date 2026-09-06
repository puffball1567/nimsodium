#!/usr/bin/env bash
set -euo pipefail

build_root="${NIMSODIUM_C_ABI_BUILD_ROOT:-${TMPDIR:-/tmp}/nimsodium-c}"
library_path="$build_root/libnimsodium_c.so"
test_path="$build_root/test_nimsodium_c_abi"
sodium_libdir="$(pkg-config --variable=libdir libsodium)"
read -r -a sodium_link_flags <<< "$(pkg-config --libs libsodium)"

mkdir -p "$build_root"

nim c --mm:arc --app:lib --path:src --nimcache:"$build_root/nimcache" \
  --out:"$library_path" src/nimsodium_c.nim

gcc -Iinclude tests/test_c_abi.c -L"$build_root" -lnimsodium_c \
  "${sodium_link_flags[@]}" \
  -Wl,-rpath,"$build_root" -Wl,-rpath,"$sodium_libdir" -o "$test_path"

"$test_path"
