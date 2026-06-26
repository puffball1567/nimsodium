import nimsodium

let recipient = generateBoxKeyPair()
let ciphertext = sealBox("hello", recipient.publicKey)

doAssert openBox(ciphertext, recipient.publicKey, recipient.secretKey) == "hello"

let sender = generateBoxKeyPair()
let authenticated = encryptBox("hello", recipient.publicKey, sender.secretKey)

doAssert decryptBox(authenticated, sender.publicKey, recipient.secretKey) == "hello"
