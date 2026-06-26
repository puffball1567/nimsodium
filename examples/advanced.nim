import nimsodium
import nimsodium/advanced

let client = generateKeyExchangeKeyPair()
let server = generateKeyExchangeKeyPair()

let clientKeys = clientSessionKeys(
  client.publicKey,
  client.secretKey,
  server.publicKey
)
let serverKeys = serverSessionKeys(
  server.publicKey,
  server.secretKey,
  client.publicKey
)

doAssert rawBytes(clientKeys.transmitKey) == rawBytes(serverKeys.receiveKey)
doAssert rawBytes(clientKeys.receiveKey) == rawBytes(serverKeys.transmitKey)

let shortHashKey = generateShortHashKey()
doAssert shortHashHex("cache-key", shortHashKey).len == ShortHashBytes * 2

let padded = padMessage("secret payload", 32)
doAssert padded.len mod 32 == 0
doAssert unpadMessage(padded, 32) == "secret payload"

let aeadKey = generateAeadKey()
let detachedAead = encryptAeadDetached("secret payload", aeadKey, "record:42")
doAssert decryptAeadDetached(detachedAead, aeadKey, "record:42") == "secret payload"

let secretBoxKey = generateSecretBoxKey()
let detachedSecretBox = encryptSecretBoxDetached("local secret", secretBoxKey)
doAssert decryptSecretBoxDetached(detachedSecretBox, secretBoxKey) == "local secret"

let oneTimeKey = generateOneTimeAuthKey()
let oneTimeTag = oneTimeAuthenticate("message", oneTimeKey)
doAssert verifyOneTimeAuthentication("message", oneTimeTag, oneTimeKey)
