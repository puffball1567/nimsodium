import nimsodium

let key = generateAuthKey()
let message = "signed payload"
let tag = authenticate(message, key)

doAssert verifyAuthentication(message, tag, key)
doAssert not verifyAuthentication("tampered payload", tag, key)
