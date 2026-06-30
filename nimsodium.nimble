version       = "0.2.2"
author        = "nimsodium contributors"
description   = "Safe high-level libsodium wrapper for Nim applications"
license       = "MIT"
srcDir        = "src"
installExt    = @["nim"]
skipDirs      = @["tests", "examples"]
requires "nim >= 2.0.0"

import std/os

let cAbiBuildRoot = getEnv("NIMSODIUM_C_ABI_BUILD_ROOT", getTempDir() / "nimsodium-c")
let cAbiLib = cAbiBuildRoot / "libnimsodium_c.so"
let cAbiTest = cAbiBuildRoot / "test_nimsodium_c_abi"

task buildCAbi, "build the experimental nimsodium C ABI shared library":
  exec "mkdir -p " & cAbiBuildRoot
  exec "nim c --app:lib --path:src --nimcache:" & cAbiBuildRoot / "nimcache" &
    " --out:" & cAbiLib & " src/nimsodium_c.nim"

task testCAbi, "build and run the C ABI smoke test":
  exec "mkdir -p " & cAbiBuildRoot
  exec "nim c --app:lib --path:src --nimcache:" & cAbiBuildRoot / "nimcache" &
    " --out:" & cAbiLib & " src/nimsodium_c.nim"
  exec "gcc -Iinclude tests/test_c_abi.c -L" & cAbiBuildRoot &
    " -lnimsodium_c -Wl,-rpath," & cAbiBuildRoot & " -o " & cAbiTest
  exec cAbiTest
