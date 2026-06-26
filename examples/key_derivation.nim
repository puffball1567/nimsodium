import nimsodium

let masterKey = generateKdfKey()

let encryptionKey = deriveAeadKey(masterKey, "AEADv001", 1'u64)
let tokenKey = deriveKeyedHashKey(masterKey, "TOKNv001", 1'u64)

let ciphertext = encryptAead("secret", encryptionKey, "record:42")
doAssert decryptAead(ciphertext, encryptionKey, "record:42") == "secret"

doAssert keyedHashHex("token", tokenKey).len == GenericHashBytes * 2
doAssert rawBytes(encryptionKey) != rawBytes(tokenKey)
