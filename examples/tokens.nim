import nimsodium

let token = generateToken()
let fingerprintKey = generateKeyedHashKey()
let fingerprint = fingerprintToken(token, fingerprintKey)
let storedFingerprint = fingerprintTokenHex(token, fingerprintKey)

doAssert fromBase64(token).len == 32
doAssert rawBytes(fingerprint).len == GenericHashBytes
doAssert verifyTokenFingerprint(token, fingerprint, fingerprintKey)
doAssert verifyTokenFingerprintHex(token, storedFingerprint, fingerprintKey)
doAssert not verifyTokenFingerprint("wrong", fingerprint, fingerprintKey)
