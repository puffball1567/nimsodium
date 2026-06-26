import ./encoding
import ./errors
import ./private/internal/[bytes, init]
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
  BoxSeed* = distinct string
  BoxPublicKey* = distinct string
  BoxSecretKey* = distinct string

  BoxKeyPair* = object
    publicKey*: BoxPublicKey
    secretKey*: BoxSecretKey

proc rawBytes*(key: BoxPublicKey): string =
  ## Returns the raw bytes for storage by the application.
  string(key)

proc rawBytes*(key: BoxSecretKey): string =
  ## Returns the raw bytes for storage by the application.
  string(key)

proc rawBytes*(seed: BoxSeed): string =
  ## Returns the raw seed bytes for storage by the application.
  string(seed)

proc toHex*(key: BoxPublicKey): string =
  ## Encodes a box public key as hexadecimal.
  encoding.toHex(string(key))

proc toHex*(key: BoxSecretKey): string =
  ## Encodes a box secret key as hexadecimal.
  encoding.toHex(string(key))

proc toHex*(seed: BoxSeed): string =
  ## Encodes a box seed as hexadecimal.
  encoding.toHex(string(seed))

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
  BoxSecretKey(key)

proc boxSeedFromBytes*(seed: string): BoxSeed =
  ## Wraps an existing box seed.
  if seed.len != BoxSeedBytes:
    raise newException(
      InvalidKeyError,
      "box seed must be " & $BoxSeedBytes & " bytes"
    )
  BoxSeed(seed)

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
  BoxSeed(randomBytes(BoxSeedBytes))

proc generateBoxKeyPair*(): BoxKeyPair =
  ## Returns a new public-key encryption key pair.
  init.ensureInitialized()

  var publicKey = newString(BoxPublicKeyBytes)
  var secretKey = newString(BoxSecretKeyBytes)
  let rc = sodium.Sodium.crypto_box_keypair(
    bytes.unsafeCString(publicKey),
    bytes.unsafeCString(secretKey)
  )
  if rc != 0:
    raise newException(CryptoError, "box key pair generation failed")
  result.publicKey = BoxPublicKey(publicKey)
  result.secretKey = BoxSecretKey(secretKey)

proc generateBoxKeyPair*(seed: BoxSeed): BoxKeyPair =
  ## Returns the box key pair deterministically derived from a seed.
  init.ensureInitialized()

  var publicKey = newString(BoxPublicKeyBytes)
  var secretKey = newString(BoxSecretKeyBytes)
  let rc = sodium.Sodium.crypto_box_seed_keypair(
    bytes.unsafeCString(publicKey),
    bytes.unsafeCString(secretKey),
    bytes.unsafeCString(string(seed))
  )
  if rc != 0:
    raise newException(CryptoError, "seeded box key pair generation failed")
  result.publicKey = BoxPublicKey(publicKey)
  result.secretKey = BoxSecretKey(secretKey)

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
  openBox(ciphertext, string(publicKey), string(secretKey))

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
  encryptBox(plaintext, string(recipientPublicKey), string(senderSecretKey))

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
  decryptBox(ciphertext, string(senderPublicKey), string(recipientSecretKey))
