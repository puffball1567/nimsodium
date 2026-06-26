import std/os

import nimsodium

let stored = hashPassword("correct horse battery staple")

doAssert verifyPassword(stored, "correct horse battery staple")
doAssert not verifyPassword(stored, "wrong password")
doAssert not needsRehashPassword(stored)

let encrypted = encryptWithPassword(
  "private note",
  "correct horse battery staple",
  "note:42"
)

doAssert decryptWithPassword(
  encrypted,
  "correct horse battery staple",
  "note:42"
) == "private note"

let plainPath = getTempDir() / "nimsodium-password-file.txt"
let encryptedPath = plainPath & ".enc"
let decryptedPath = plainPath & ".out"

writeFile(plainPath, "private file")
encryptFileWithPassword(
  plainPath,
  encryptedPath,
  "correct horse battery staple",
  "backup:v1"
)
decryptFileWithPassword(
  encryptedPath,
  decryptedPath,
  "correct horse battery staple",
  "backup:v1"
)

doAssert readFile(decryptedPath) == "private file"

for path in [plainPath, encryptedPath, decryptedPath]:
  if fileExists(path):
    removeFile(path)
