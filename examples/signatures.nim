import std/os

import nimsodium

let signer = generateSigningKeyPair()
let signedMessage = sign("message", signer.secretKey)

doAssert openSigned(signedMessage, signer.publicKey) == "message"

let seed = signingSeed(signer.secretKey)
let restored = generateSigningKeyPair(seed)
doAssert rawBytes(restored.publicKey) == rawBytes(signer.publicKey)

let signature = signDetached("message", signer.secretKey)
doAssert verifyDetached("message", signature, signer.publicKey)
doAssert not verifyDetached("tampered", signature, signer.publicKey)

let path = getTempDir() / "nimsodium-signature-example.txt"
writeFile(path, "file payload")
let fileSignature = signFileDetached(path, signer.secretKey)

doAssert verifyFileDetached(path, fileSignature, signer.publicKey)
removeFile(path)
