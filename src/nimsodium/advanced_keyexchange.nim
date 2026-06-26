import ./errors
import ./private/internal/[bytes, init, secure_bytes]
import ./private/raw/sodium

const
  KeyExchangePublicKeyBytes* = sodium.crypto_kx_PUBLICKEYBYTES
  KeyExchangeSecretKeyBytes* = sodium.crypto_kx_SECRETKEYBYTES
  KeyExchangeSessionKeyBytes* = sodium.crypto_kx_SESSIONKEYBYTES

type
  KeyExchangePublicKey* = distinct string
  KeyExchangeSecretKey* = object
    bytes: SecureBytes
  KeyExchangeKeyPair* = object
    publicKey*: KeyExchangePublicKey
    secretKey*: KeyExchangeSecretKey

  ReceiveSessionKey* = object
    bytes: SecureBytes
  TransmitSessionKey* = object
    bytes: SecureBytes
  SessionKeys* = object
    receiveKey*: ReceiveSessionKey
    transmitKey*: TransmitSessionKey

proc rawBytes*(key: KeyExchangePublicKey): string =
  ## Returns the raw bytes for storage or transport by the application.
  string(key)

proc rawBytes*(key: KeyExchangeSecretKey): string =
  ## Returns the raw bytes for storage by the application.
  secure_bytes.rawBytes(key.bytes)

proc rawBytes*(key: ReceiveSessionKey): string =
  ## Returns the raw bytes for use as symmetric key material.
  secure_bytes.rawBytes(key.bytes)

proc rawBytes*(key: TransmitSessionKey): string =
  ## Returns the raw bytes for use as symmetric key material.
  secure_bytes.rawBytes(key.bytes)

proc secretBytes(key: KeyExchangeSecretKey): SecureBytes =
  if key.bytes.len != KeyExchangeSecretKeyBytes:
    raise newException(
      InvalidKeyError,
      "key exchange secret key must be " & $KeyExchangeSecretKeyBytes & " bytes"
    )
  key.bytes

proc keyExchangePublicKeyFromBytes*(key: string): KeyExchangePublicKey =
  ## Wraps an existing key exchange public key.
  if key.len != KeyExchangePublicKeyBytes:
    raise newException(
      InvalidKeyError,
      "key exchange public key must be " & $KeyExchangePublicKeyBytes & " bytes"
    )
  KeyExchangePublicKey(key)

proc keyExchangeSecretKeyFromBytes*(key: string): KeyExchangeSecretKey =
  ## Wraps an existing key exchange secret key.
  if key.len != KeyExchangeSecretKeyBytes:
    raise newException(
      InvalidKeyError,
      "key exchange secret key must be " & $KeyExchangeSecretKeyBytes & " bytes"
    )
  KeyExchangeSecretKey(bytes: secureBytesFromBytes(key))

proc generateKeyExchangeKeyPair*(): KeyExchangeKeyPair =
  ## Returns a new key pair for deriving client/server session keys.
  init.ensureInitialized()

  var publicKey = newString(KeyExchangePublicKeyBytes)
  var secretKey = newSecureBytes(KeyExchangeSecretKeyBytes)
  let rc = sodium.Sodium.crypto_kx_keypair(
    bytes.unsafeCString(publicKey),
    secure_bytes.unsafeCString(secretKey)
  )
  if rc != 0:
    raise newException(CryptoError, "key exchange key pair generation failed")

  result.publicKey = KeyExchangePublicKey(publicKey)
  secretKey.protectReadOnly()
  result.secretKey = KeyExchangeSecretKey(bytes: secretKey)

proc clientSessionKeys*(
  clientPublicKey: KeyExchangePublicKey;
  clientSecretKey: KeyExchangeSecretKey;
  serverPublicKey: KeyExchangePublicKey
): SessionKeys =
  ## Derives receive/transmit keys for the client side of a connection.
  init.ensureInitialized()

  let clientSecret = clientSecretKey.secretBytes()
  var receiveKey = newSecureBytes(KeyExchangeSessionKeyBytes)
  var transmitKey = newSecureBytes(KeyExchangeSessionKeyBytes)
  let rc = sodium.Sodium.crypto_kx_client_session_keys(
    secure_bytes.unsafeCString(receiveKey),
    secure_bytes.unsafeCString(transmitKey),
    bytes.unsafeCString(string(clientPublicKey)),
    secure_bytes.unsafeCString(clientSecret),
    bytes.unsafeCString(string(serverPublicKey))
  )
  if rc != 0:
    raise newException(CryptoError, "client key exchange failed")

  receiveKey.protectReadOnly()
  transmitKey.protectReadOnly()
  result.receiveKey = ReceiveSessionKey(bytes: receiveKey)
  result.transmitKey = TransmitSessionKey(bytes: transmitKey)

proc serverSessionKeys*(
  serverPublicKey: KeyExchangePublicKey;
  serverSecretKey: KeyExchangeSecretKey;
  clientPublicKey: KeyExchangePublicKey
): SessionKeys =
  ## Derives receive/transmit keys for the server side of a connection.
  init.ensureInitialized()

  let serverSecret = serverSecretKey.secretBytes()
  var receiveKey = newSecureBytes(KeyExchangeSessionKeyBytes)
  var transmitKey = newSecureBytes(KeyExchangeSessionKeyBytes)
  let rc = sodium.Sodium.crypto_kx_server_session_keys(
    secure_bytes.unsafeCString(receiveKey),
    secure_bytes.unsafeCString(transmitKey),
    bytes.unsafeCString(string(serverPublicKey)),
    secure_bytes.unsafeCString(serverSecret),
    bytes.unsafeCString(string(clientPublicKey))
  )
  if rc != 0:
    raise newException(CryptoError, "server key exchange failed")

  receiveKey.protectReadOnly()
  transmitKey.protectReadOnly()
  result.receiveKey = ReceiveSessionKey(bytes: receiveKey)
  result.transmitKey = TransmitSessionKey(bytes: transmitKey)
