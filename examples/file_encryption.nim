import std/os

import nimsodium

let plainPath = getCurrentDir() / "examples" / "file_plain.tmp"
let encryptedPath = getCurrentDir() / "examples" / "file_encrypted.tmp"
let decryptedPath = getCurrentDir() / "examples" / "file_decrypted.tmp"

for path in [plainPath, encryptedPath, decryptedPath]:
  if fileExists(path):
    removeFile(path)

let key = generateStreamKey()
let associatedData = "backup:v1"

writeFile(plainPath, "large secret payload")
encryptFile(plainPath, encryptedPath, key, associatedData)
decryptFile(encryptedPath, decryptedPath, key, associatedData)

doAssert readFile(decryptedPath) == "large secret payload"

for path in [plainPath, encryptedPath, decryptedPath]:
  if fileExists(path):
    removeFile(path)
