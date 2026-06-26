import ./encoding
import ./errors
import ./private/internal/[bytes, init, secure_bytes]
import ./private/raw/sodium
import ./random

const
  BoxSeedBytes* = sodium.crypto_box_SEEDBYTES
  BoxPublicKeyBytes* = sodium.crypto_box_PUBLICKEYBYTES
  BoxSecretKeyBytes* = sodium.crypto_box_SECRETKEYBYTES
  BoxNonceBytes* = sodium.crypto_box_NONCEBYTES
  BoxMacBytes* = sodium.crypto_box_MACBYTES
  BoxSealBytes* = sodium.crypto_box_SEALBYTES

type
  BoxSeed* = object
    bytes: SecureBytes
  BoxPublicKey* = distinct string
  BoxSecretKey* = object
    bytes: SecureBytes

  BoxKeyPair* = object
    publicKey*: BoxPublicKey
    secretKey*: BoxSecretKey

proc rawBytes*(key: BoxPublicKey): string =
  ## Returns the raw bytes for storage by the application.
  string(key)

proc rawBytes*(key: BoxSecretKey): string =
  ## Returns the raw bytes for storage by the application.
  secure_bytes.rawBytes(key.bytes)

proc rawBytes*(seed: BoxSeed): string =
  ## Returns the raw seed bytes for storage by the application.
  secure_bytes.rawBytes(seed.bytes)

proc secretBytes(key: BoxSecretKey): SecureBytes =
  if key.bytes.len != BoxSecretKeyBytes:
    raise newException(
      InvalidKeyError,
      "box secret key must be " & $BoxSecretKeyBytes & " bytes"
    )
  key.bytes

proc seedBytes(seed: BoxSeed): SecureBytes =
  if seed.bytes.len != BoxSeedBytes:
    raise newException(
      InvalidKeyError,
      "box seed must be " & $BoxSeedBytes & " bytes"
    )
  seed.bytes

proc toHex*(key: BoxPublicKey): string =
  ## Encodes a box public key as hexadecimal.
  encoding.toHex(string(key))

proc toHex*(key: BoxSecretKey): string =
  ## Encodes a box secret key as hexadecimal.
  rawBytes(key).toHex()

proc toHex*(seed: BoxSeed): string =
  ## Encodes a box seed as hexadecimal.
  rawBytes(seed).toHex()

proc boxPublicKeyFromBytes*(key: string): BoxPublicKey =
  ## Wraps an existing sealed-box public key.
  if key.len != BoxPublicKeyBytes:
    raise newException(
      InvalidKeyError,
      "box public key must be " & $BoxPublicKeyBytes & " bytes"
    )
  BoxPublicKey(key)

proc boxSecretKeyFromBytes*(key: string): BoxSecretKey =
  ## Wraps an existing sealed-box secret key.
  if key.len != BoxSecretKeyBytes:
    raise newException(
      InvalidKeyError,
      "box secret key must be " & $BoxSecretKeyBytes & " bytes"
    )
  BoxSecretKey(bytes: secureBytesFromBytes(key))

proc boxSeedFromBytes*(seed: string): BoxSeed =
  ## Wraps an existing box seed.
  if seed.len != BoxSeedBytes:
    raise newException(
      InvalidKeyError,
      "box seed must be " & $BoxSeedBytes & " bytes"
    )
  BoxSeed(bytes: secureBytesFromBytes(seed))

proc boxPublicKeyFromHex*(hex: string): BoxPublicKey =
  ## Decodes a hexadecimal box public key.
  boxPublicKeyFromBytes(encoding.fromHex(hex))

proc boxSecretKeyFromHex*(hex: string): BoxSecretKey =
  ## Decodes a hexadecimal box secret key.
  boxSecretKeyFromBytes(encoding.fromHex(hex))

proc boxSeedFromHex*(hex: string): BoxSeed =
  ## Decodes a hexadecimal box seed.
  boxSeedFromBytes(encoding.fromHex(hex))

proc generateBoxSeed*(): BoxSeed =
  ## Returns a new seed for deterministic box key-pair generation.
  BoxSeed(bytes: randomSecureBytes(BoxSeedBytes))

proc generateBoxKeyPair*(): BoxKeyPair =
  ## Returns a new public-key encryption key pair.
  init.ensureInitialized()

  var publicKey = newString(BoxPublicKeyBytes)
  var secretKey = newSecureBytes(BoxSecretKeyBytes)
  let rc = sodium.Sodium.crypto_box_keypair(
    bytes.unsafeCString(publicKey),
    secure_bytes.unsafeCString(secretKey)
  )
  if rc != 0:
    raise newException(CryptoError, "box key pair generation failed")
  result.publicKey = BoxPublicKey(publicKey)
  secretKey.protectReadOnly()
  result.secretKey = BoxSecretKey(bytes: secretKey)

proc generateBoxKeyPair*(seed: BoxSeed): BoxKeyPair =
  ## Returns the box key pair deterministically derived from a seed.
  init.ensureInitialized()

  var publicKey = newString(BoxPublicKeyBytes)
  let seedData = seed.seedBytes()
  var secretKey = newSecureBytes(BoxSecretKeyBytes)
  let rc = sodium.Sodium.crypto_box_seed_keypair(
    bytes.unsafeCString(publicKey),
    secure_bytes.unsafeCString(secretKey),
    secure_bytes.unsafeCString(seedData)
  )
  if rc != 0:
    raise newException(CryptoError, "seeded box key pair generation failed")
  result.publicKey = BoxPublicKey(publicKey)
  secretKey.protectReadOnly()
  result.secretKey = BoxSecretKey(bytes: secretKey)

proc sealBox(plaintext, publicKey: string): string =
  ## Encrypts data for a recipient public key using libsodium sealed boxes.
  ##
  ## The sender is anonymous. The recipient decrypts with their public and
  ## secret key.
  init.ensureInitialized()

  if publicKey.len != BoxPublicKeyBytes:
    raise newException(
      InvalidKeyError,
      "box public key must be " & $BoxPublicKeyBytes & " bytes"
    )

  result = newString(plaintext.len + BoxSealBytes)
  let rc = sodium.Sodium.crypto_box_seal(
    bytes.unsafeCString(result),
    bytes.unsafeCString(plaintext),
    culonglong(plaintext.len),
    bytes.unsafeCString(publicKey)
  )
  if rc != 0:
    raise newException(CryptoError, "box sealing failed")

proc sealBox*(plaintext: string; publicKey: BoxPublicKey): string =
  ## Encrypts data for a typed recipient public key.
  sealBox(plaintext, string(publicKey))

proc openBox(ciphertext, publicKey, secretKey: string): string =
  ## Decrypts and verifies data produced by sealBox.
  init.ensureInitialized()

  if publicKey.len != BoxPublicKeyBytes:
    raise newException(
      InvalidKeyError,
      "box public key must be " & $BoxPublicKeyBytes & " bytes"
    )
  if secretKey.len != BoxSecretKeyBytes:
    raise newException(
      InvalidKeyError,
      "box secret key must be " & $BoxSecretKeyBytes & " bytes"
    )
  if ciphertext.len < BoxSealBytes:
    raise newException(InvalidInputError, "sealed box ciphertext is too short")

  result = newString(ciphertext.len - BoxSealBytes)
  let rc = sodium.Sodium.crypto_box_seal_open(
    bytes.unsafeCString(result),
    bytes.unsafeCString(ciphertext),
    culonglong(ciphertext.len),
    bytes.unsafeCString(publicKey),
    bytes.unsafeCString(secretKey)
  )
  if rc != 0:
    raise newException(CryptoError, "sealed box authentication failed")

proc openBox*(ciphertext: string; publicKey: BoxPublicKey; secretKey: BoxSecretKey): string =
  ## Decrypts and verifies data using typed sealed-box keys.
  let secretData = secretKey.secretBytes()
  init.ensureInitialized()

  if ciphertext.len < BoxSealBytes:
    raise newException(InvalidInputError, "sealed box ciphertext is too short")

  result = newString(ciphertext.len - BoxSealBytes)
  let rc = sodium.Sodium.crypto_box_seal_open(
    bytes.unsafeCString(result),
    bytes.unsafeCString(ciphertext),
    culonglong(ciphertext.len),
    bytes.unsafeCString(string(publicKey)),
    secure_bytes.unsafeCString(secretData)
  )
  if rc != 0:
    raise newException(CryptoError, "sealed box authentication failed")

proc encryptBox(
    plaintext, recipientPublicKey, senderSecretKey: string
): string =
  ## Encrypts data to a recipient and authenticates the sender.
  ##
  ## A nonce is generated automatically and stored with the ciphertext.
  init.ensureInitialized()

  if recipientPublicKey.len != BoxPublicKeyBytes:
    raise newException(
      InvalidKeyError,
      "box public key must be " & $BoxPublicKeyBytes & " bytes"
    )
  if senderSecretKey.len != BoxSecretKeyBytes:
    raise newException(
      InvalidKeyError,
      "box secret key must be " & $BoxSecretKeyBytes & " bytes"
    )

  let nonce = randomBytes(BoxNonceBytes)
  var sealed = newString(BoxMacBytes + plaintext.len)
  let rc = sodium.Sodium.crypto_box_easy(
    bytes.unsafeCString(sealed),
    bytes.unsafeCString(plaintext),
    culonglong(plaintext.len),
    bytes.unsafeCString(nonce),
    bytes.unsafeCString(recipientPublicKey),
    bytes.unsafeCString(senderSecretKey)
  )
  if rc != 0:
    raise newException(CryptoError, "authenticated box encryption failed")

  nonce & sealed

proc encryptBox*(
    plaintext: string;
    recipientPublicKey: BoxPublicKey;
    senderSecretKey: BoxSecretKey
): string =
  ## Encrypts data to a recipient and authenticates the sender.
  let secretData = senderSecretKey.secretBytes()
  init.ensureInitialized()

  let nonce = randomBytes(BoxNonceBytes)
  var sealed = newString(BoxMacBytes + plaintext.len)
  let rc = sodium.Sodium.crypto_box_easy(
    bytes.unsafeCString(sealed),
    bytes.unsafeCString(plaintext),
    culonglong(plaintext.len),
    bytes.unsafeCString(nonce),
    bytes.unsafeCString(string(recipientPublicKey)),
    secure_bytes.unsafeCString(secretData)
  )
  if rc != 0:
    raise newException(CryptoError, "authenticated box encryption failed")

  nonce & sealed

proc decryptBox(
    ciphertext, senderPublicKey, recipientSecretKey: string
): string =
  ## Decrypts data produced by encryptBox and verifies the sender.
  init.ensureInitialized()

  if senderPublicKey.len != BoxPublicKeyBytes:
    raise newException(
      InvalidKeyError,
      "box public key must be " & $BoxPublicKeyBytes & " bytes"
    )
  if recipientSecretKey.len != BoxSecretKeyBytes:
    raise newException(
      InvalidKeyError,
      "box secret key must be " & $BoxSecretKeyBytes & " bytes"
    )
  if ciphertext.len < BoxNonceBytes + BoxMacBytes:
    raise newException(InvalidInputError, "authenticated box ciphertext is too short")

  let nonce = ciphertext[0 ..< BoxNonceBytes]
  let sealed = ciphertext[BoxNonceBytes .. ^1]
  result = newString(sealed.len - BoxMacBytes)
  let rc = sodium.Sodium.crypto_box_open_easy(
    bytes.unsafeCString(result),
    bytes.unsafeCString(sealed),
    culonglong(sealed.len),
    bytes.unsafeCString(nonce),
    bytes.unsafeCString(senderPublicKey),
    bytes.unsafeCString(recipientSecretKey)
  )
  if rc != 0:
    raise newException(CryptoError, "authenticated box verification failed")

proc decryptBox*(
    ciphertext: string;
    senderPublicKey: BoxPublicKey;
    recipientSecretKey: BoxSecretKey
): string =
  ## Decrypts data using a sender public key and recipient secret key.
  let secretData = recipientSecretKey.secretBytes()
  init.ensureInitialized()

  if ciphertext.len < BoxNonceBytes + BoxMacBytes:
    raise newException(InvalidInputError, "authenticated box ciphertext is too short")

  let nonce = ciphertext[0 ..< BoxNonceBytes]
  let sealed = ciphertext[BoxNonceBytes .. ^1]
  result = newString(sealed.len - BoxMacBytes)
  let rc = sodium.Sodium.crypto_box_open_easy(
    bytes.unsafeCString(result),
    bytes.unsafeCString(sealed),
    culonglong(sealed.len),
    bytes.unsafeCString(nonce),
    bytes.unsafeCString(string(senderPublicKey)),
    secure_bytes.unsafeCString(secretData)
  )
  if rc != 0:
    raise newException(CryptoError, "authenticated box verification failed")
