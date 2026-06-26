import nimsodium

let key = generateAeadKey()
let associatedData = "record:42"
let ciphertext = encryptAead("secret payload", key, associatedData)

doAssert decryptAead(ciphertext, key, associatedData) == "secret payload"
