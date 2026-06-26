import ./encoding
import ./errors
import ./private/internal/[bytes, init, secure_bytes]
import ./private/raw/sodium

const
  SigningPublicKeyBytes* = sodium.crypto_sign_PUBLICKEYBYTES
  SigningSecretKeyBytes* = sodium.crypto_sign_SECRETKEYBYTES
  SigningSeedBytes* = sodium.crypto_sign_SEEDBYTES
  SignatureBytes* = sodium.crypto_sign_BYTES

type
  SigningPublicKey* = distinct string
  SigningSecretKey* = object
    bytes: SecureBytes
  SigningSeed* = object
    bytes: SecureBytes

  SigningKeyPair* = object
    publicKey*: SigningPublicKey
    secretKey*: SigningSecretKey

proc rawBytes*(key: SigningPublicKey): string =
  ## Returns the raw bytes for storage by the application.
  string(key)

proc rawBytes*(key: SigningSecretKey): string =
  ## Returns the raw bytes for storage by the application.
  secure_bytes.rawBytes(key.bytes)

proc rawBytes*(seed: SigningSeed): string =
  ## Returns the raw seed bytes for storage by the application.
  secure_bytes.rawBytes(seed.bytes)

proc secretBytes(key: SigningSecretKey): SecureBytes =
  if key.bytes.len != SigningSecretKeyBytes:
    raise newException(
      InvalidKeyError,
      "signing secret key must be " & $SigningSecretKeyBytes & " bytes"
    )
  key.bytes

proc seedBytes(seed: SigningSeed): SecureBytes =
  if seed.bytes.len != SigningSeedBytes:
    raise newException(
      InvalidKeyError,
      "signing seed must be " & $SigningSeedBytes & " bytes"
    )
  seed.bytes

proc toHex*(key: SigningPublicKey): string =
  ## Encodes a signing public key as hexadecimal.
  encoding.toHex(string(key))

proc toHex*(key: SigningSecretKey): string =
  ## Encodes a signing secret key as hexadecimal.
  rawBytes(key).toHex()

proc toHex*(seed: SigningSeed): string =
  ## Encodes a signing seed as hexadecimal.
  rawBytes(seed).toHex()

proc signingPublicKeyFromBytes*(key: string): SigningPublicKey =
  ## Wraps an existing signing public key.
  if key.len != SigningPublicKeyBytes:
    raise newException(
      InvalidKeyError,
      "signing public key must be " & $SigningPublicKeyBytes & " bytes"
    )
  SigningPublicKey(key)

proc signingSecretKeyFromBytes*(key: string): SigningSecretKey =
  ## Wraps an existing signing secret key.
  if key.len != SigningSecretKeyBytes:
    raise newException(
      InvalidKeyError,
      "signing secret key must be " & $SigningSecretKeyBytes & " bytes"
    )
  SigningSecretKey(bytes: secureBytesFromBytes(key))

proc signingSeedFromBytes*(seed: string): SigningSeed =
  ## Wraps an existing signing seed.
  if seed.len != SigningSeedBytes:
    raise newException(
      InvalidKeyError,
      "signing seed must be " & $SigningSeedBytes & " bytes"
    )
  SigningSeed(bytes: secureBytesFromBytes(seed))

proc signingPublicKeyFromHex*(hex: string): SigningPublicKey =
  ## Decodes a hexadecimal signing public key.
  signingPublicKeyFromBytes(encoding.fromHex(hex))

proc signingSecretKeyFromHex*(hex: string): SigningSecretKey =
  ## Decodes a hexadecimal signing secret key.
  signingSecretKeyFromBytes(encoding.fromHex(hex))

proc signingSeedFromHex*(hex: string): SigningSeed =
  ## Decodes a hexadecimal signing seed.
  signingSeedFromBytes(encoding.fromHex(hex))

proc generateSigningSeed*(): SigningSeed =
  ## Returns a new seed for deterministic signing key-pair generation.
  SigningSeed(bytes: randomSecureBytes(SigningSeedBytes))

proc generateSigningKeyPair*(): SigningKeyPair =
  ## Returns a new signing key pair.
  init.ensureInitialized()

  var publicKey = newString(SigningPublicKeyBytes)
  var secretKey = newSecureBytes(SigningSecretKeyBytes)
  let rc = sodium.Sodium.crypto_sign_keypair(
    bytes.unsafeCString(publicKey),
    secure_bytes.unsafeCString(secretKey)
  )
  if rc != 0:
    raise newException(CryptoError, "signing key pair generation failed")
  result.publicKey = SigningPublicKey(publicKey)
  secretKey.protectReadOnly()
  result.secretKey = SigningSecretKey(bytes: secretKey)

proc generateSigningKeyPair*(seed: SigningSeed): SigningKeyPair =
  ## Returns the signing key pair deterministically derived from a seed.
  init.ensureInitialized()

  var publicKey = newString(SigningPublicKeyBytes)
  let seedData = seed.seedBytes()
  var secretKey = newSecureBytes(SigningSecretKeyBytes)
  let rc = sodium.Sodium.crypto_sign_seed_keypair(
    bytes.unsafeCString(publicKey),
    secure_bytes.unsafeCString(secretKey),
    secure_bytes.unsafeCString(seedData)
  )
  if rc != 0:
    raise newException(CryptoError, "seeded signing key pair generation failed")
  result.publicKey = SigningPublicKey(publicKey)
  secretKey.protectReadOnly()
  result.secretKey = SigningSecretKey(bytes: secretKey)

proc signingPublicKey*(secretKey: SigningSecretKey): SigningPublicKey =
  ## Extracts the public key from a signing secret key.
  init.ensureInitialized()

  var publicKey = newString(SigningPublicKeyBytes)
  let rc = sodium.Sodium.crypto_sign_ed25519_sk_to_pk(
    bytes.unsafeCString(publicKey),
    secure_bytes.unsafeCString(secretKey.secretBytes())
  )
  if rc != 0:
    raise newException(CryptoError, "signing public key extraction failed")
  SigningPublicKey(publicKey)

proc signingSeed*(secretKey: SigningSecretKey): SigningSeed =
  ## Extracts the deterministic seed from a signing secret key.
  init.ensureInitialized()

  var seed = newSecureBytes(SigningSeedBytes)
  let rc = sodium.Sodium.crypto_sign_ed25519_sk_to_seed(
    secure_bytes.unsafeCString(seed),
    secure_bytes.unsafeCString(secretKey.secretBytes())
  )
  if rc != 0:
    raise newException(CryptoError, "signing seed extraction failed")
  seed.protectReadOnly()
  SigningSeed(bytes: seed)

proc signDetached(message, secretKey: string): string =
  ## Signs a message and returns a detached signature.
  init.ensureInitialized()

  if secretKey.len != SigningSecretKeyBytes:
    raise newException(
      InvalidKeyError,
      "signing secret key must be " & $SigningSecretKeyBytes & " bytes"
    )

  result = newString(SignatureBytes)
  var signatureLen: culonglong
  let rc = sodium.Sodium.crypto_sign_detached(
    bytes.unsafeCString(result),
    cast[pointer](addr signatureLen),
    bytes.unsafeCString(message),
    culonglong(message.len),
    bytes.unsafeCString(secretKey)
  )
  if rc != 0 or signatureLen != culonglong(result.len):
    raise newException(CryptoError, "signing failed")

proc signDetached*(message: string; secretKey: SigningSecretKey): string =
  ## Signs a message using a typed signing secret key.
  let secretData = secretKey.secretBytes()
  init.ensureInitialized()

  result = newString(SignatureBytes)
  var signatureLen: culonglong
  let rc = sodium.Sodium.crypto_sign_detached(
    bytes.unsafeCString(result),
    cast[pointer](addr signatureLen),
    bytes.unsafeCString(message),
    culonglong(message.len),
    secure_bytes.unsafeCString(secretData)
  )
  if rc != 0 or signatureLen != culonglong(result.len):
    raise newException(CryptoError, "signing failed")

proc sign*(message: string; secretKey: SigningSecretKey): string =
  ## Signs a message and returns signature || message.
  init.ensureInitialized()

  result = newString(message.len + SignatureBytes)
  var signedLen: culonglong
  let rc = sodium.Sodium.crypto_sign(
    bytes.unsafeCString(result),
    cast[pointer](addr signedLen),
    bytes.unsafeCString(message),
    culonglong(message.len),
    secure_bytes.unsafeCString(secretKey.secretBytes())
  )
  if rc != 0 or signedLen != culonglong(result.len):
    raise newException(CryptoError, "signing failed")

proc verifyDetached(message, signature, publicKey: string): bool =
  ## Verifies a detached signature.
  init.ensureInitialized()

  if publicKey.len != SigningPublicKeyBytes:
    raise newException(
      InvalidKeyError,
      "signing public key must be " & $SigningPublicKeyBytes & " bytes"
    )
  if signature.len != SignatureBytes:
    return false

  sodium.Sodium.crypto_sign_verify_detached(
    bytes.unsafeCString(signature),
    bytes.unsafeCString(message),
    culonglong(message.len),
    bytes.unsafeCString(publicKey)
  ) == 0

proc verifyDetached*(message, signature: string; publicKey: SigningPublicKey): bool =
  ## Verifies a detached signature using a typed public key.
  verifyDetached(message, signature, string(publicKey))

proc openSigned*(signedMessage: string; publicKey: SigningPublicKey): string =
  ## Verifies signature || message and returns the original message.
  init.ensureInitialized()

  if signedMessage.len < SignatureBytes:
    raise newException(InvalidInputError, "signed message is too short")

  result = newString(signedMessage.len - SignatureBytes)
  var messageLen: culonglong
  let rc = sodium.Sodium.crypto_sign_open(
    bytes.unsafeCString(result),
    cast[pointer](addr messageLen),
    bytes.unsafeCString(signedMessage),
    culonglong(signedMessage.len),
    bytes.unsafeCString(string(publicKey))
  )
  if rc != 0:
    raise newException(CryptoError, "signature verification failed")
  result.setLen(int(messageLen))

proc signFileDetached*(path: string; secretKey: SigningSecretKey): string =
  ## Signs a file and returns a detached signature.
  signDetached(readFile(path), secretKey)

proc verifyFileDetached*(
    path, signature: string;
    publicKey: SigningPublicKey
): bool =
  ## Verifies a detached file signature.
  verifyDetached(readFile(path), signature, publicKey)
