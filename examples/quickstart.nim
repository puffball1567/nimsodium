import nimsodium

let passwordHash = hashPassword("correct horse battery staple")
doAssert verifyPassword(passwordHash, "correct horse battery staple")

let key = generateAeadKey()
let ciphertext = encryptAead("secret payload", key, "record:42")
let plaintext = decryptAead(ciphertext, key, "record:42")
doAssert plaintext == "secret payload"

let token = randomBase64(32)
let fingerprintKey = generateKeyedHashKey()
let fingerprint = keyedHashHex(token, fingerprintKey)
doAssert fingerprint.len == GenericHashBytes * 2
