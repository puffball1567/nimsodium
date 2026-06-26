import nimsodium

var storedKey = rawBytes(generateSecretBoxKey())
doAssert storedKey.len == SecretBoxKeyBytes

secureClear(storedKey)
doAssert storedKey.len == 0
