import ./errors
import ./memory
import ./password_encryption
import ./password_file_encryption
import ./private/internal/secure_bytes
import ./secretstream
import ./signatures

const
  DefaultWalletSecretBytes* = 32
  WalletSecretMinBytes* = 1

type
  WalletSecret* = object
    ## Secret material intended for local wallet or application-secret storage.
    ##
    ## This is not a chain-specific private-key type. It is a secure-memory
    ## container for seed/private-key-like bytes that the application owns.
    bytes: SecureBytes

  ProtectedWalletSecret* = distinct string
    ## Binary password-protected wallet-secret envelope.

proc walletAssociatedData(label: string): string =
  "nimsodium.wallet.v1" & '\0' & $label.len & '\0' & label

proc offchainMessageToSign(domain, message: string): string =
  "nimsodium.offchain-sign.v1" & '\0' &
    $domain.len & '\0' & domain & '\0' &
    $message.len & '\0' & message

proc rawBytes*(secret: WalletSecret): string =
  ## Returns a copy of the wallet secret bytes.
  ##
  ## The returned string is normal Nim memory. Clear it with secureClear after
  ## export when possible.
  secure_bytes.rawBytes(secret.bytes)

proc rawBytes*(secret: ProtectedWalletSecret): string =
  ## Returns the binary protected-secret envelope for storage.
  string(secret)

proc walletSecretFromBytes*(secret: string): WalletSecret =
  ## Wraps existing wallet/application secret material in secure memory.
  if secret.len < WalletSecretMinBytes:
    raise newException(InvalidInputError, "wallet secret must not be empty")
  WalletSecret(bytes: secureBytesFromBytes(secret))

proc generateWalletSecret*(length = DefaultWalletSecretBytes): WalletSecret =
  ## Generates random secret material in secure memory.
  if length < WalletSecretMinBytes:
    raise newException(ValueError, "wallet secret length must be positive")
  WalletSecret(bytes: randomSecureBytes(length))

proc protectedWalletSecretFromBytes*(protectedSecret: string): ProtectedWalletSecret =
  ## Wraps a stored password-protected wallet-secret envelope.
  if protectedSecret.len == 0:
    raise newException(InvalidInputError, "protected wallet secret must not be empty")
  ProtectedWalletSecret(protectedSecret)

proc protectWalletSecret*(
    secret: WalletSecret;
    password: string;
    label = "wallet-secret";
    profile = pepInteractive
): ProtectedWalletSecret =
  ## Password-protects wallet/application secret material.
  ##
  ## `label` is authenticated associated data. Use a stable application or
  ## account label so a protected blob cannot be silently moved to another
  ## context.
  var secretBytes = rawBytes(secret)
  try:
    ProtectedWalletSecret(
      encryptWithPassword(secretBytes, password, walletAssociatedData(label), profile)
    )
  finally:
    secureClear(secretBytes)

proc openProtectedWalletSecret*(
    protectedSecret: ProtectedWalletSecret;
    password: string;
    label = "wallet-secret"
): WalletSecret =
  ## Opens a password-protected wallet secret into secure memory.
  var secretBytes = decryptWithPassword(
    string(protectedSecret),
    password,
    walletAssociatedData(label)
  )
  try:
    walletSecretFromBytes(secretBytes)
  finally:
    secureClear(secretBytes)

proc encryptWalletSecretFile*(
    inputPath, outputPath, password: string;
    label = "wallet-secret-file";
    profile = pepInteractive;
    chunkSize = DefaultStreamChunkBytes
) =
  ## Password-protects a file containing wallet/application secret material.
  ##
  ## This is a workflow alias over password-based file encryption with
  ## wallet-specific associated data. It does not implement BIP39, BIP32, or
  ## chain-specific key formats.
  encryptFileWithPassword(
    inputPath,
    outputPath,
    password,
    walletAssociatedData(label),
    profile,
    chunkSize
  )

proc decryptWalletSecretFile*(
    inputPath, outputPath, password: string;
    label = "wallet-secret-file";
    chunkSize = DefaultStreamChunkBytes
) =
  ## Decrypts a file produced by encryptWalletSecretFile.
  decryptFileWithPassword(
    inputPath,
    outputPath,
    password,
    walletAssociatedData(label),
    chunkSize
  )

proc signOffchainMessage*(
    message, domain: string;
    secretKey: SigningSecretKey
): string =
  ## Signs an off-chain application message with domain separation.
  ##
  ## This uses Ed25519 and is not a Bitcoin/Ethereum transaction signature.
  if domain.len == 0:
    raise newException(InvalidInputError, "off-chain signing domain must not be empty")
  signDetached(offchainMessageToSign(domain, message), secretKey)

proc verifyOffchainMessage*(
    message, domain, signature: string;
    publicKey: SigningPublicKey
): bool =
  ## Verifies a signature produced by signOffchainMessage.
  if domain.len == 0:
    return false
  verifyDetached(offchainMessageToSign(domain, message), signature, publicKey)
