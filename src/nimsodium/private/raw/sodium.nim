# Internal libsodium FFI declarations.
# This module is an implementation detail for nimsodium high-level wrappers.

{.passL: "-lsodium".}

type
  Sodium* = object  # namespace marker (zero-size)
  CRYPTO_ALIGN* {.importc, incompleteStruct.} = object
  crypto_auth_hmacsha256_state* {.importc: "crypto_auth_hmacsha256_state", incompleteStruct.} = object
  crypto_auth_hmacsha512_state* {.importc: "crypto_auth_hmacsha512_state", incompleteStruct.} = object
  crypto_hash_sha256_state* {.importc: "crypto_hash_sha256_state", bycopy.} = object
    state*: array[8, uint32]
    count*: uint64
    buf*: array[64, uint8]
  crypto_hash_sha512_state* {.importc: "crypto_hash_sha512_state", bycopy.} = object
    state*: array[8, uint64]
    count*: array[2, uint64]
    buf*: array[128, uint8]
  crypto_secretstream_xchacha20poly1305_state* {.importc: "crypto_secretstream_xchacha20poly1305_state", incompleteStruct.} = object
  crypto_sign_ed25519ph_state* {.importc: "crypto_sign_ed25519ph_state", bycopy.} = object
    hs*: crypto_hash_sha512_state
  randombytes_implementation* {.importc: "randombytes_implementation", bycopy.} = object
    implementation_name*: cstring
    random*: pointer
    stir*: pointer
    uniform*: pointer
    buf*: pointer
    close*: pointer
  crypto_auth_hmacsha512256_state* = crypto_auth_hmacsha512_state
  crypto_generichash_state* {.importc: "crypto_generichash_state", incompleteStruct.} = object
  crypto_onetimeauth_state* {.importc: "crypto_onetimeauth_state", incompleteStruct.} = object
  crypto_sign_state* {.importc: "crypto_sign_state", incompleteStruct.} = object

# Macros (object-like)
const
  crypto_aead_aes256gcm_KEYBYTES* = 32
  crypto_aead_aes256gcm_NSECBYTES* = 0
  crypto_aead_aes256gcm_NPUBBYTES* = 12
  crypto_aead_aes256gcm_ABYTES* = 16
  crypto_aead_chacha20poly1305_ietf_KEYBYTES* = 32
  crypto_aead_chacha20poly1305_ietf_NSECBYTES* = 0
  crypto_aead_chacha20poly1305_ietf_NPUBBYTES* = 12
  crypto_aead_chacha20poly1305_ietf_ABYTES* = 16
  crypto_aead_chacha20poly1305_KEYBYTES* = 32
  crypto_aead_chacha20poly1305_NSECBYTES* = 0
  crypto_aead_chacha20poly1305_NPUBBYTES* = 8
  crypto_aead_chacha20poly1305_ABYTES* = 16
  crypto_aead_xchacha20poly1305_ietf_KEYBYTES* = 32
  crypto_aead_xchacha20poly1305_ietf_NSECBYTES* = 0
  crypto_aead_xchacha20poly1305_ietf_NPUBBYTES* = 24
  crypto_aead_xchacha20poly1305_ietf_ABYTES* = 16
  crypto_auth_hmacsha512256_BYTES* = 32
  crypto_auth_BYTES* = crypto_auth_hmacsha512256_BYTES
  crypto_auth_hmacsha512256_KEYBYTES* = 32
  crypto_auth_KEYBYTES* = crypto_auth_hmacsha512256_KEYBYTES
  crypto_auth_hmacsha256_BYTES* = 32
  crypto_auth_hmacsha256_KEYBYTES* = 32
  crypto_auth_hmacsha512_BYTES* = 64
  crypto_auth_hmacsha512_KEYBYTES* = 32
  crypto_box_curve25519xsalsa20poly1305_SEEDBYTES* = 32
  crypto_box_SEEDBYTES* = crypto_box_curve25519xsalsa20poly1305_SEEDBYTES
  crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES* = 32
  crypto_box_PUBLICKEYBYTES* = crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES
  crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES* = 32
  crypto_box_SECRETKEYBYTES* = crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES
  crypto_box_curve25519xsalsa20poly1305_NONCEBYTES* = 24
  crypto_box_NONCEBYTES* = crypto_box_curve25519xsalsa20poly1305_NONCEBYTES
  crypto_box_curve25519xsalsa20poly1305_MACBYTES* = 16
  crypto_box_MACBYTES* = crypto_box_curve25519xsalsa20poly1305_MACBYTES
  crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES* = 32
  crypto_box_BEFORENMBYTES* = crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES
  crypto_box_SEALBYTES* = (crypto_box_PUBLICKEYBYTES + crypto_box_MACBYTES)
  crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES* = 16
  crypto_box_curve25519xsalsa20poly1305_ZEROBYTES* = (crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES + crypto_box_curve25519xsalsa20poly1305_MACBYTES)
  crypto_box_ZEROBYTES* = crypto_box_curve25519xsalsa20poly1305_ZEROBYTES
  crypto_box_BOXZEROBYTES* = crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES
  crypto_box_curve25519xchacha20poly1305_SEEDBYTES* = 32
  crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES* = 32
  crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES* = 32
  crypto_box_curve25519xchacha20poly1305_BEFORENMBYTES* = 32
  crypto_box_curve25519xchacha20poly1305_NONCEBYTES* = 24
  crypto_box_curve25519xchacha20poly1305_MACBYTES* = 16
  crypto_box_curve25519xchacha20poly1305_SEALBYTES* = (crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES + crypto_box_curve25519xchacha20poly1305_MACBYTES)
  crypto_core_ed25519_BYTES* = 32
  crypto_core_ed25519_UNIFORMBYTES* = 32
  crypto_core_ed25519_HASHBYTES* = 64
  crypto_core_ed25519_SCALARBYTES* = 32
  crypto_core_ed25519_NONREDUCEDSCALARBYTES* = 64
  crypto_core_hchacha20_OUTPUTBYTES* = 32
  crypto_core_hchacha20_INPUTBYTES* = 16
  crypto_core_hchacha20_KEYBYTES* = 32
  crypto_core_hchacha20_CONSTBYTES* = 16
  crypto_core_hsalsa20_OUTPUTBYTES* = 32
  crypto_core_hsalsa20_INPUTBYTES* = 16
  crypto_core_hsalsa20_KEYBYTES* = 32
  crypto_core_hsalsa20_CONSTBYTES* = 16
  crypto_core_ristretto255_BYTES* = 32
  crypto_core_ristretto255_HASHBYTES* = 64
  crypto_core_ristretto255_SCALARBYTES* = 32
  crypto_core_ristretto255_NONREDUCEDSCALARBYTES* = 64
  crypto_core_salsa20_OUTPUTBYTES* = 64
  crypto_core_salsa20_INPUTBYTES* = 16
  crypto_core_salsa20_KEYBYTES* = 32
  crypto_core_salsa20_CONSTBYTES* = 16
  crypto_core_salsa2012_OUTPUTBYTES* = 64
  crypto_core_salsa2012_INPUTBYTES* = 16
  crypto_core_salsa2012_KEYBYTES* = 32
  crypto_core_salsa2012_CONSTBYTES* = 16
  crypto_core_salsa208_OUTPUTBYTES* = 64
  crypto_core_salsa208_INPUTBYTES* = 16
  crypto_core_salsa208_KEYBYTES* = 32
  crypto_core_salsa208_CONSTBYTES* = 16
  crypto_generichash_blake2b_BYTES_MIN* = 16
  crypto_generichash_BYTES_MIN* = crypto_generichash_blake2b_BYTES_MIN
  crypto_generichash_blake2b_BYTES_MAX* = 64
  crypto_generichash_BYTES_MAX* = crypto_generichash_blake2b_BYTES_MAX
  crypto_generichash_blake2b_BYTES* = 32
  crypto_generichash_BYTES* = crypto_generichash_blake2b_BYTES
  crypto_generichash_blake2b_KEYBYTES_MIN* = 16
  crypto_generichash_KEYBYTES_MIN* = crypto_generichash_blake2b_KEYBYTES_MIN
  crypto_generichash_blake2b_KEYBYTES_MAX* = 64
  crypto_generichash_KEYBYTES_MAX* = crypto_generichash_blake2b_KEYBYTES_MAX
  crypto_generichash_blake2b_KEYBYTES* = 32
  crypto_generichash_KEYBYTES* = crypto_generichash_blake2b_KEYBYTES
  crypto_generichash_blake2b_SALTBYTES* = 16
  crypto_generichash_blake2b_PERSONALBYTES* = 16
  crypto_hash_sha512_BYTES* = 64
  crypto_hash_BYTES* = crypto_hash_sha512_BYTES
  crypto_hash_sha256_BYTES* = 32
  crypto_kdf_blake2b_BYTES_MIN* = 16
  crypto_kdf_BYTES_MIN* = crypto_kdf_blake2b_BYTES_MIN
  crypto_kdf_blake2b_BYTES_MAX* = 64
  crypto_kdf_BYTES_MAX* = crypto_kdf_blake2b_BYTES_MAX
  crypto_kdf_blake2b_CONTEXTBYTES* = 8
  crypto_kdf_CONTEXTBYTES* = crypto_kdf_blake2b_CONTEXTBYTES
  crypto_kdf_blake2b_KEYBYTES* = 32
  crypto_kdf_KEYBYTES* = crypto_kdf_blake2b_KEYBYTES
  crypto_kx_PUBLICKEYBYTES* = 32
  crypto_kx_SECRETKEYBYTES* = 32
  crypto_kx_SEEDBYTES* = 32
  crypto_kx_SESSIONKEYBYTES* = 32
  crypto_onetimeauth_poly1305_BYTES* = 16
  crypto_onetimeauth_BYTES* = crypto_onetimeauth_poly1305_BYTES
  crypto_onetimeauth_poly1305_KEYBYTES* = 32
  crypto_onetimeauth_KEYBYTES* = crypto_onetimeauth_poly1305_KEYBYTES
  crypto_pwhash_argon2i_ALG_ARGON2I13* = 1
  crypto_pwhash_ALG_ARGON2I13* = crypto_pwhash_argon2i_ALG_ARGON2I13
  crypto_pwhash_argon2id_ALG_ARGON2ID13* = 2
  crypto_pwhash_ALG_ARGON2ID13* = crypto_pwhash_argon2id_ALG_ARGON2ID13
  crypto_pwhash_ALG_DEFAULT* = crypto_pwhash_ALG_ARGON2ID13
  crypto_pwhash_argon2id_BYTES_MIN* = 16
  crypto_pwhash_BYTES_MIN* = crypto_pwhash_argon2id_BYTES_MIN
  crypto_pwhash_argon2id_PASSWD_MIN* = 0
  crypto_pwhash_PASSWD_MIN* = crypto_pwhash_argon2id_PASSWD_MIN
  crypto_pwhash_argon2id_PASSWD_MAX* = 4294967295
  crypto_pwhash_PASSWD_MAX* = crypto_pwhash_argon2id_PASSWD_MAX
  crypto_pwhash_argon2id_SALTBYTES* = 16
  crypto_pwhash_SALTBYTES* = crypto_pwhash_argon2id_SALTBYTES
  crypto_pwhash_argon2id_STRBYTES* = 128
  crypto_pwhash_STRBYTES* = crypto_pwhash_argon2id_STRBYTES
  crypto_pwhash_argon2id_OPSLIMIT_MIN* = 1
  crypto_pwhash_OPSLIMIT_MIN* = crypto_pwhash_argon2id_OPSLIMIT_MIN
  crypto_pwhash_argon2id_OPSLIMIT_MAX* = 4294967295
  crypto_pwhash_OPSLIMIT_MAX* = crypto_pwhash_argon2id_OPSLIMIT_MAX
  crypto_pwhash_argon2id_MEMLIMIT_MIN* = 8192
  crypto_pwhash_MEMLIMIT_MIN* = crypto_pwhash_argon2id_MEMLIMIT_MIN
  crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE* = 2
  crypto_pwhash_OPSLIMIT_INTERACTIVE* = crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE
  crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE* = 67108864
  crypto_pwhash_MEMLIMIT_INTERACTIVE* = crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE
  crypto_pwhash_argon2id_OPSLIMIT_MODERATE* = 3
  crypto_pwhash_OPSLIMIT_MODERATE* = crypto_pwhash_argon2id_OPSLIMIT_MODERATE
  crypto_pwhash_argon2id_MEMLIMIT_MODERATE* = 268435456
  crypto_pwhash_MEMLIMIT_MODERATE* = crypto_pwhash_argon2id_MEMLIMIT_MODERATE
  crypto_pwhash_argon2id_OPSLIMIT_SENSITIVE* = 4
  crypto_pwhash_OPSLIMIT_SENSITIVE* = crypto_pwhash_argon2id_OPSLIMIT_SENSITIVE
  crypto_pwhash_argon2id_MEMLIMIT_SENSITIVE* = 1073741824
  crypto_pwhash_MEMLIMIT_SENSITIVE* = crypto_pwhash_argon2id_MEMLIMIT_SENSITIVE
  crypto_pwhash_argon2i_BYTES_MIN* = 16
  crypto_pwhash_argon2i_PASSWD_MIN* = 0
  crypto_pwhash_argon2i_PASSWD_MAX* = 4294967295
  crypto_pwhash_argon2i_SALTBYTES* = 16
  crypto_pwhash_argon2i_STRBYTES* = 128
  crypto_pwhash_argon2i_OPSLIMIT_MIN* = 3
  crypto_pwhash_argon2i_OPSLIMIT_MAX* = 4294967295
  crypto_pwhash_argon2i_MEMLIMIT_MIN* = 8192
  crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE* = 4
  crypto_pwhash_argon2i_MEMLIMIT_INTERACTIVE* = 33554432
  crypto_pwhash_argon2i_OPSLIMIT_MODERATE* = 6
  crypto_pwhash_argon2i_MEMLIMIT_MODERATE* = 134217728
  crypto_pwhash_argon2i_OPSLIMIT_SENSITIVE* = 8
  crypto_pwhash_argon2i_MEMLIMIT_SENSITIVE* = 536870912
  crypto_pwhash_scryptsalsa208sha256_BYTES_MIN* = 16
  crypto_pwhash_scryptsalsa208sha256_PASSWD_MIN* = 0
  crypto_pwhash_scryptsalsa208sha256_SALTBYTES* = 32
  crypto_pwhash_scryptsalsa208sha256_STRBYTES* = 102
  crypto_pwhash_scryptsalsa208sha256_STRPREFIX* = "$7$"
  crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN* = 32768
  crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX* = 4294967295
  crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN* = 16777216
  crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE* = 524288
  crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE* = 16777216
  crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE* = 33554432
  crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE* = 1073741824
  crypto_scalarmult_curve25519_BYTES* = 32
  crypto_scalarmult_BYTES* = crypto_scalarmult_curve25519_BYTES
  crypto_scalarmult_curve25519_SCALARBYTES* = 32
  crypto_scalarmult_SCALARBYTES* = crypto_scalarmult_curve25519_SCALARBYTES
  crypto_scalarmult_ed25519_BYTES* = 32
  crypto_scalarmult_ed25519_SCALARBYTES* = 32
  crypto_scalarmult_ristretto255_BYTES* = 32
  crypto_scalarmult_ristretto255_SCALARBYTES* = 32
  crypto_secretbox_xsalsa20poly1305_KEYBYTES* = 32
  crypto_secretbox_KEYBYTES* = crypto_secretbox_xsalsa20poly1305_KEYBYTES
  crypto_secretbox_xsalsa20poly1305_NONCEBYTES* = 24
  crypto_secretbox_NONCEBYTES* = crypto_secretbox_xsalsa20poly1305_NONCEBYTES
  crypto_secretbox_xsalsa20poly1305_MACBYTES* = 16
  crypto_secretbox_MACBYTES* = crypto_secretbox_xsalsa20poly1305_MACBYTES
  crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES* = 16
  crypto_secretbox_xsalsa20poly1305_ZEROBYTES* = (crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES + crypto_secretbox_xsalsa20poly1305_MACBYTES)
  crypto_secretbox_ZEROBYTES* = crypto_secretbox_xsalsa20poly1305_ZEROBYTES
  crypto_secretbox_BOXZEROBYTES* = crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES
  crypto_secretbox_xchacha20poly1305_KEYBYTES* = 32
  crypto_secretbox_xchacha20poly1305_NONCEBYTES* = 24
  crypto_secretbox_xchacha20poly1305_MACBYTES* = 16
  crypto_secretstream_xchacha20poly1305_ABYTES* = 17
  crypto_secretstream_xchacha20poly1305_HEADERBYTES* = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
  crypto_secretstream_xchacha20poly1305_KEYBYTES* = crypto_aead_xchacha20poly1305_ietf_KEYBYTES
  crypto_secretstream_xchacha20poly1305_TAG_MESSAGE* = 0
  crypto_secretstream_xchacha20poly1305_TAG_PUSH* = 1
  crypto_secretstream_xchacha20poly1305_TAG_REKEY* = 2
  crypto_secretstream_xchacha20poly1305_TAG_FINAL* = crypto_secretstream_xchacha20poly1305_TAG_PUSH or crypto_secretstream_xchacha20poly1305_TAG_REKEY
  crypto_shorthash_siphash24_BYTES* = 8
  crypto_shorthash_BYTES* = crypto_shorthash_siphash24_BYTES
  crypto_shorthash_siphash24_KEYBYTES* = 16
  crypto_shorthash_KEYBYTES* = crypto_shorthash_siphash24_KEYBYTES
  crypto_shorthash_siphashx24_BYTES* = 16
  crypto_shorthash_siphashx24_KEYBYTES* = 16
  crypto_sign_ed25519_BYTES* = 64
  crypto_sign_BYTES* = crypto_sign_ed25519_BYTES
  crypto_sign_ed25519_SEEDBYTES* = 32
  crypto_sign_SEEDBYTES* = crypto_sign_ed25519_SEEDBYTES
  crypto_sign_ed25519_PUBLICKEYBYTES* = 32
  crypto_sign_PUBLICKEYBYTES* = crypto_sign_ed25519_PUBLICKEYBYTES
  crypto_sign_ed25519_SECRETKEYBYTES* = 64
  crypto_sign_SECRETKEYBYTES* = crypto_sign_ed25519_SECRETKEYBYTES
  crypto_sign_edwards25519sha512batch_BYTES* = 64
  crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES* = 32
  crypto_stream_xsalsa20_KEYBYTES* = 32
  crypto_stream_KEYBYTES* = crypto_stream_xsalsa20_KEYBYTES
  crypto_stream_xsalsa20_NONCEBYTES* = 24
  crypto_stream_NONCEBYTES* = crypto_stream_xsalsa20_NONCEBYTES
  crypto_stream_chacha20_KEYBYTES* = 32
  crypto_stream_chacha20_NONCEBYTES* = 8
  crypto_stream_chacha20_ietf_KEYBYTES* = 32
  crypto_stream_chacha20_ietf_NONCEBYTES* = 12
  crypto_stream_salsa20_KEYBYTES* = 32
  crypto_stream_salsa20_NONCEBYTES* = 8
  crypto_stream_salsa2012_KEYBYTES* = 32
  crypto_stream_salsa2012_NONCEBYTES* = 8
  crypto_stream_salsa208_KEYBYTES* = 32
  crypto_stream_salsa208_NONCEBYTES* = 8
  crypto_stream_xchacha20_KEYBYTES* = 32
  crypto_stream_xchacha20_NONCEBYTES* = 24
  crypto_verify_16_BYTES* = 16
  crypto_verify_32_BYTES* = 32
  crypto_verify_64_BYTES* = 64
  randombytes_SEEDBYTES* = 32
  sodium_base64_VARIANT_ORIGINAL* = 1
  sodium_base64_VARIANT_ORIGINAL_NO_PADDING* = 3
  sodium_base64_VARIANT_URLSAFE* = 5
  sodium_base64_VARIANT_URLSAFE_NO_PADDING* = 7
  SODIUM_VERSION_STRING* = "1.0.18"
  SODIUM_LIBRARY_VERSION_MAJOR* = 10
  SODIUM_LIBRARY_VERSION_MINOR* = 3

# Macros (function-like)
template SODIUM_MIN*(A, B: untyped): untyped =
  ((if (A) < (B): (A) else: (B)))

template SODIUM_C99*(X: untyped): untyped =
  X

template sodium_base64_ENCODED_LEN*(BIN_LEN, VARIANT: untyped): untyped =
  (((BIN_LEN) / 3U) * 4U + (((cast[BIN_LEN]( - ((BIN_LEN) / 3U)) * 3U) or ((cast[BIN_LEN]( - ((BIN_LEN) / 3U)) * 3U) shr 1)) and 1U) (4U - ( not ((((VARIANT)[] and 2U) shr 1) - 1U) and (3U - (cast[BIN_LEN]( - ((BIN_LEN) / 3U)) * 3U)))) + 1U)


proc sodium_init*(_: type Sodium): cint {.importc: "sodium_init", cdecl.}
  ##  ----
proc sodium_set_misuse_handler*(_: type Sodium; handler: pointer): cint {.importc: "sodium_set_misuse_handler", cdecl.}
proc sodium_misuse*(_: type Sodium): cint {.importc: "sodium_misuse", cdecl.}
proc crypto_aead_aes256gcm_is_available*(_: type Sodium): cint {.importc: "crypto_aead_aes256gcm_is_available", cdecl.}
proc crypto_aead_aes256gcm_encrypt*(_: type Sodium; c: cstring; clen_p: pointer; m: cstring; mlen: culonglong; ad: cstring; adlen: culonglong; nsec: cstring; npub: cstring; k: cstring): cint {.importc: "crypto_aead_aes256gcm_encrypt", cdecl.}
proc crypto_aead_aes256gcm_decrypt*(_: type Sodium; m: cstring; mlen_p: pointer; nsec: cstring; c: cstring; clen: culonglong; ad: cstring; adlen: culonglong; npub: cstring; k: cstring): cint {.importc: "crypto_aead_aes256gcm_decrypt", cdecl.}
proc crypto_aead_aes256gcm_encrypt_detached*(_: type Sodium; c: cstring; mac: cstring; maclen_p: pointer; m: cstring; mlen: culonglong; ad: cstring; adlen: culonglong; nsec: cstring; npub: cstring; k: cstring): cint {.importc: "crypto_aead_aes256gcm_encrypt_detached", cdecl.}
proc crypto_aead_aes256gcm_decrypt_detached*(_: type Sodium; m: cstring; nsec: cstring; c: cstring; clen: culonglong; mac: cstring; ad: cstring; adlen: culonglong; npub: cstring; k: cstring): cint {.importc: "crypto_aead_aes256gcm_decrypt_detached", cdecl.}
  ##  -- Precomputation interface --
proc crypto_aead_aes256gcm_beforenm*(_: type Sodium; ctx: pointer; k: cstring): cint {.importc: "crypto_aead_aes256gcm_beforenm", cdecl.}
proc crypto_aead_aes256gcm_encrypt_afternm*(_: type Sodium; c: cstring; clen_p: pointer; m: cstring; mlen: culonglong; ad: cstring; adlen: culonglong; nsec: cstring; npub: cstring; ctx: pointer): cint {.importc: "crypto_aead_aes256gcm_encrypt_afternm", cdecl.}
proc crypto_aead_aes256gcm_decrypt_afternm*(_: type Sodium; m: cstring; mlen_p: pointer; nsec: cstring; c: cstring; clen: culonglong; ad: cstring; adlen: culonglong; npub: cstring; ctx: pointer): cint {.importc: "crypto_aead_aes256gcm_decrypt_afternm", cdecl.}
proc crypto_aead_aes256gcm_encrypt_detached_afternm*(_: type Sodium; c: cstring; mac: cstring; maclen_p: pointer; m: cstring; mlen: culonglong; ad: cstring; adlen: culonglong; nsec: cstring; npub: cstring; ctx: pointer): cint {.importc: "crypto_aead_aes256gcm_encrypt_detached_afternm", cdecl.}
proc crypto_aead_aes256gcm_decrypt_detached_afternm*(_: type Sodium; m: cstring; nsec: cstring; c: cstring; clen: culonglong; mac: cstring; ad: cstring; adlen: culonglong; npub: cstring; ctx: pointer): cint {.importc: "crypto_aead_aes256gcm_decrypt_detached_afternm", cdecl.}
proc crypto_aead_aes256gcm_keygen*(_: type Sodium; k: array[32, uint8]): cint {.importc: "crypto_aead_aes256gcm_keygen", cdecl.}
proc crypto_aead_chacha20poly1305_ietf_encrypt*(_: type Sodium; c: cstring; clen_p: pointer; m: cstring; mlen: culonglong; ad: cstring; adlen: culonglong; nsec: cstring; npub: cstring; k: cstring): cint {.importc: "crypto_aead_chacha20poly1305_ietf_encrypt", cdecl.}
proc crypto_aead_chacha20poly1305_ietf_decrypt*(_: type Sodium; m: cstring; mlen_p: pointer; nsec: cstring; c: cstring; clen: culonglong; ad: cstring; adlen: culonglong; npub: cstring; k: cstring): cint {.importc: "crypto_aead_chacha20poly1305_ietf_decrypt", cdecl.}
proc crypto_aead_chacha20poly1305_ietf_encrypt_detached*(_: type Sodium; c: cstring; mac: cstring; maclen_p: pointer; m: cstring; mlen: culonglong; ad: cstring; adlen: culonglong; nsec: cstring; npub: cstring; k: cstring): cint {.importc: "crypto_aead_chacha20poly1305_ietf_encrypt_detached", cdecl.}
proc crypto_aead_chacha20poly1305_ietf_decrypt_detached*(_: type Sodium; m: cstring; nsec: cstring; c: cstring; clen: culonglong; mac: cstring; ad: cstring; adlen: culonglong; npub: cstring; k: cstring): cint {.importc: "crypto_aead_chacha20poly1305_ietf_decrypt_detached", cdecl.}
proc crypto_aead_chacha20poly1305_ietf_keygen*(_: type Sodium; k: array[32, uint8]): cint {.importc: "crypto_aead_chacha20poly1305_ietf_keygen", cdecl.}
  ##  -- Original ChaCha20-Poly1305 construction with a 64-bit nonce and a 64-bit internal counter --
proc crypto_aead_chacha20poly1305_encrypt*(_: type Sodium; c: cstring; clen_p: pointer; m: cstring; mlen: culonglong; ad: cstring; adlen: culonglong; nsec: cstring; npub: cstring; k: cstring): cint {.importc: "crypto_aead_chacha20poly1305_encrypt", cdecl.}
proc crypto_aead_chacha20poly1305_decrypt*(_: type Sodium; m: cstring; mlen_p: pointer; nsec: cstring; c: cstring; clen: culonglong; ad: cstring; adlen: culonglong; npub: cstring; k: cstring): cint {.importc: "crypto_aead_chacha20poly1305_decrypt", cdecl.}
proc crypto_aead_chacha20poly1305_encrypt_detached*(_: type Sodium; c: cstring; mac: cstring; maclen_p: pointer; m: cstring; mlen: culonglong; ad: cstring; adlen: culonglong; nsec: cstring; npub: cstring; k: cstring): cint {.importc: "crypto_aead_chacha20poly1305_encrypt_detached", cdecl.}
proc crypto_aead_chacha20poly1305_decrypt_detached*(_: type Sodium; m: cstring; nsec: cstring; c: cstring; clen: culonglong; mac: cstring; ad: cstring; adlen: culonglong; npub: cstring; k: cstring): cint {.importc: "crypto_aead_chacha20poly1305_decrypt_detached", cdecl.}
proc crypto_aead_chacha20poly1305_keygen*(_: type Sodium; k: array[32, uint8]): cint {.importc: "crypto_aead_chacha20poly1305_keygen", cdecl.}
  ##  Aliases
proc crypto_aead_xchacha20poly1305_ietf_encrypt*(_: type Sodium; c: cstring; clen_p: pointer; m: cstring; mlen: culonglong; ad: cstring; adlen: culonglong; nsec: cstring; npub: cstring; k: cstring): cint {.importc: "crypto_aead_xchacha20poly1305_ietf_encrypt", cdecl.}
proc crypto_aead_xchacha20poly1305_ietf_decrypt*(_: type Sodium; m: cstring; mlen_p: pointer; nsec: cstring; c: cstring; clen: culonglong; ad: cstring; adlen: culonglong; npub: cstring; k: cstring): cint {.importc: "crypto_aead_xchacha20poly1305_ietf_decrypt", cdecl.}
proc crypto_aead_xchacha20poly1305_ietf_encrypt_detached*(_: type Sodium; c: cstring; mac: cstring; maclen_p: pointer; m: cstring; mlen: culonglong; ad: cstring; adlen: culonglong; nsec: cstring; npub: cstring; k: cstring): cint {.importc: "crypto_aead_xchacha20poly1305_ietf_encrypt_detached", cdecl.}
proc crypto_aead_xchacha20poly1305_ietf_decrypt_detached*(_: type Sodium; m: cstring; nsec: cstring; c: cstring; clen: culonglong; mac: cstring; ad: cstring; adlen: culonglong; npub: cstring; k: cstring): cint {.importc: "crypto_aead_xchacha20poly1305_ietf_decrypt_detached", cdecl.}
proc crypto_aead_xchacha20poly1305_ietf_keygen*(_: type Sodium; k: array[32, uint8]): cint {.importc: "crypto_aead_xchacha20poly1305_ietf_keygen", cdecl.}
  ##  Aliases
proc crypto_auth_primitive*(_: type Sodium): pointer {.importc: "crypto_auth_primitive", cdecl.}
proc crypto_auth*(_: type Sodium; `out`: cstring; `in`: cstring; inlen: culonglong; k: cstring): cint {.importc: "crypto_auth", cdecl.}
proc crypto_auth_verify*(_: type Sodium; h: cstring; `in`: cstring; inlen: culonglong; k: cstring): cint {.importc: "crypto_auth_verify", cdecl.}
proc crypto_auth_keygen*(_: type Sodium; k: uint8): cint {.importc: "crypto_auth_keygen", cdecl.}
proc crypto_auth_hmacsha256*(_: type Sodium; `out`: cstring; `in`: cstring; inlen: culonglong; k: cstring): cint {.importc: "crypto_auth_hmacsha256", cdecl.}
proc crypto_auth_hmacsha256_verify*(_: type Sodium; h: cstring; `in`: cstring; inlen: culonglong; k: cstring): cint {.importc: "crypto_auth_hmacsha256_verify", cdecl.}
  ##  -------------------------------------------------------------------------
proc crypto_auth_hmacsha256_init*(_: type Sodium; state: pointer; key: cstring; keylen: csize_t): cint {.importc: "crypto_auth_hmacsha256_init", cdecl.}
proc crypto_auth_hmacsha256_update*(_: type Sodium; state: pointer; `in`: cstring; inlen: culonglong): cint {.importc: "crypto_auth_hmacsha256_update", cdecl.}
proc crypto_auth_hmacsha256_final*(_: type Sodium; state: pointer; `out`: cstring): cint {.importc: "crypto_auth_hmacsha256_final", cdecl.}
proc crypto_auth_hmacsha256_keygen*(_: type Sodium; k: array[32, uint8]): cint {.importc: "crypto_auth_hmacsha256_keygen", cdecl.}
proc crypto_auth_hmacsha512*(_: type Sodium; `out`: cstring; `in`: cstring; inlen: culonglong; k: cstring): cint {.importc: "crypto_auth_hmacsha512", cdecl.}
proc crypto_auth_hmacsha512_verify*(_: type Sodium; h: cstring; `in`: cstring; inlen: culonglong; k: cstring): cint {.importc: "crypto_auth_hmacsha512_verify", cdecl.}
  ##  -------------------------------------------------------------------------
proc crypto_auth_hmacsha512_init*(_: type Sodium; state: pointer; key: cstring; keylen: csize_t): cint {.importc: "crypto_auth_hmacsha512_init", cdecl.}
proc crypto_auth_hmacsha512_update*(_: type Sodium; state: pointer; `in`: cstring; inlen: culonglong): cint {.importc: "crypto_auth_hmacsha512_update", cdecl.}
proc crypto_auth_hmacsha512_final*(_: type Sodium; state: pointer; `out`: cstring): cint {.importc: "crypto_auth_hmacsha512_final", cdecl.}
proc crypto_auth_hmacsha512_keygen*(_: type Sodium; k: array[32, uint8]): cint {.importc: "crypto_auth_hmacsha512_keygen", cdecl.}
proc crypto_auth_hmacsha512256*(_: type Sodium; `out`: cstring; `in`: cstring; inlen: culonglong; k: cstring): cint {.importc: "crypto_auth_hmacsha512256", cdecl.}
proc crypto_auth_hmacsha512256_verify*(_: type Sodium; h: cstring; `in`: cstring; inlen: culonglong; k: cstring): cint {.importc: "crypto_auth_hmacsha512256_verify", cdecl.}
  ##  -------------------------------------------------------------------------
proc crypto_auth_hmacsha512256_init*(_: type Sodium; state: pointer; key: cstring; keylen: csize_t): cint {.importc: "crypto_auth_hmacsha512256_init", cdecl.}
proc crypto_auth_hmacsha512256_update*(_: type Sodium; state: pointer; `in`: cstring; inlen: culonglong): cint {.importc: "crypto_auth_hmacsha512256_update", cdecl.}
proc crypto_auth_hmacsha512256_final*(_: type Sodium; state: pointer; `out`: cstring): cint {.importc: "crypto_auth_hmacsha512256_final", cdecl.}
proc crypto_auth_hmacsha512256_keygen*(_: type Sodium; k: array[32, uint8]): cint {.importc: "crypto_auth_hmacsha512256_keygen", cdecl.}
proc crypto_box_primitive*(_: type Sodium): pointer {.importc: "crypto_box_primitive", cdecl.}
proc crypto_box_seed_keypair*(_: type Sodium; pk: cstring; sk: cstring; seed: cstring): cint {.importc: "crypto_box_seed_keypair", cdecl.}
proc crypto_box_keypair*(_: type Sodium; pk: cstring; sk: cstring): cint {.importc: "crypto_box_keypair", cdecl.}
proc crypto_box_easy*(_: type Sodium; c: cstring; m: cstring; mlen: culonglong; n: cstring; pk: cstring; sk: cstring): cint {.importc: "crypto_box_easy", cdecl.}
proc crypto_box_open_easy*(_: type Sodium; m: cstring; c: cstring; clen: culonglong; n: cstring; pk: cstring; sk: cstring): cint {.importc: "crypto_box_open_easy", cdecl.}
proc crypto_box_detached*(_: type Sodium; c: cstring; mac: cstring; m: cstring; mlen: culonglong; n: cstring; pk: cstring; sk: cstring): cint {.importc: "crypto_box_detached", cdecl.}
proc crypto_box_open_detached*(_: type Sodium; m: cstring; c: cstring; mac: cstring; clen: culonglong; n: cstring; pk: cstring; sk: cstring): cint {.importc: "crypto_box_open_detached", cdecl.}
  ##  -- Precomputation interface --
proc crypto_box_beforenm*(_: type Sodium; k: cstring; pk: cstring; sk: cstring): cint {.importc: "crypto_box_beforenm", cdecl.}
proc crypto_box_easy_afternm*(_: type Sodium; c: cstring; m: cstring; mlen: culonglong; n: cstring; k: cstring): cint {.importc: "crypto_box_easy_afternm", cdecl.}
proc crypto_box_open_easy_afternm*(_: type Sodium; m: cstring; c: cstring; clen: culonglong; n: cstring; k: cstring): cint {.importc: "crypto_box_open_easy_afternm", cdecl.}
proc crypto_box_detached_afternm*(_: type Sodium; c: cstring; mac: cstring; m: cstring; mlen: culonglong; n: cstring; k: cstring): cint {.importc: "crypto_box_detached_afternm", cdecl.}
proc crypto_box_open_detached_afternm*(_: type Sodium; m: cstring; c: cstring; mac: cstring; clen: culonglong; n: cstring; k: cstring): cint {.importc: "crypto_box_open_detached_afternm", cdecl.}
  ##  -- Ephemeral SK interface --
proc crypto_box_seal*(_: type Sodium; c: cstring; m: cstring; mlen: culonglong; pk: cstring): cint {.importc: "crypto_box_seal", cdecl.}
proc crypto_box_seal_open*(_: type Sodium; m: cstring; c: cstring; clen: culonglong; pk: cstring; sk: cstring): cint {.importc: "crypto_box_seal_open", cdecl.}
  ##  -- NaCl compatibility interface ; Requires padding --
proc crypto_box*(_: type Sodium; c: cstring; m: cstring; mlen: culonglong; n: cstring; pk: cstring; sk: cstring): cint {.importc: "crypto_box", cdecl.}
proc crypto_box_open*(_: type Sodium; m: cstring; c: cstring; clen: culonglong; n: cstring; pk: cstring; sk: cstring): cint {.importc: "crypto_box_open", cdecl.}
proc crypto_box_afternm*(_: type Sodium; c: cstring; m: cstring; mlen: culonglong; n: cstring; k: cstring): cint {.importc: "crypto_box_afternm", cdecl.}
proc crypto_box_open_afternm*(_: type Sodium; m: cstring; c: cstring; clen: culonglong; n: cstring; k: cstring): cint {.importc: "crypto_box_open_afternm", cdecl.}
proc crypto_box_curve25519xchacha20poly1305_seed_keypair*(_: type Sodium; pk: cstring; sk: cstring; seed: cstring): cint {.importc: "crypto_box_curve25519xchacha20poly1305_seed_keypair", cdecl.}
proc crypto_box_curve25519xchacha20poly1305_keypair*(_: type Sodium; pk: cstring; sk: cstring): cint {.importc: "crypto_box_curve25519xchacha20poly1305_keypair", cdecl.}
proc crypto_box_curve25519xchacha20poly1305_easy*(_: type Sodium; c: cstring; m: cstring; mlen: culonglong; n: cstring; pk: cstring; sk: cstring): cint {.importc: "crypto_box_curve25519xchacha20poly1305_easy", cdecl.}
proc crypto_box_curve25519xchacha20poly1305_open_easy*(_: type Sodium; m: cstring; c: cstring; clen: culonglong; n: cstring; pk: cstring; sk: cstring): cint {.importc: "crypto_box_curve25519xchacha20poly1305_open_easy", cdecl.}
proc crypto_box_curve25519xchacha20poly1305_detached*(_: type Sodium; c: cstring; mac: cstring; m: cstring; mlen: culonglong; n: cstring; pk: cstring; sk: cstring): cint {.importc: "crypto_box_curve25519xchacha20poly1305_detached", cdecl.}
proc crypto_box_curve25519xchacha20poly1305_open_detached*(_: type Sodium; m: cstring; c: cstring; mac: cstring; clen: culonglong; n: cstring; pk: cstring; sk: cstring): cint {.importc: "crypto_box_curve25519xchacha20poly1305_open_detached", cdecl.}
  ##  -- Precomputation interface --
proc crypto_box_curve25519xchacha20poly1305_beforenm*(_: type Sodium; k: cstring; pk: cstring; sk: cstring): cint {.importc: "crypto_box_curve25519xchacha20poly1305_beforenm", cdecl.}
proc crypto_box_curve25519xchacha20poly1305_easy_afternm*(_: type Sodium; c: cstring; m: cstring; mlen: culonglong; n: cstring; k: cstring): cint {.importc: "crypto_box_curve25519xchacha20poly1305_easy_afternm", cdecl.}
proc crypto_box_curve25519xchacha20poly1305_open_easy_afternm*(_: type Sodium; m: cstring; c: cstring; clen: culonglong; n: cstring; k: cstring): cint {.importc: "crypto_box_curve25519xchacha20poly1305_open_easy_afternm", cdecl.}
proc crypto_box_curve25519xchacha20poly1305_detached_afternm*(_: type Sodium; c: cstring; mac: cstring; m: cstring; mlen: culonglong; n: cstring; k: cstring): cint {.importc: "crypto_box_curve25519xchacha20poly1305_detached_afternm", cdecl.}
proc crypto_box_curve25519xchacha20poly1305_open_detached_afternm*(_: type Sodium; m: cstring; c: cstring; mac: cstring; clen: culonglong; n: cstring; k: cstring): cint {.importc: "crypto_box_curve25519xchacha20poly1305_open_detached_afternm", cdecl.}
  ##  -- Ephemeral SK interface --
proc crypto_box_curve25519xchacha20poly1305_seal*(_: type Sodium; c: cstring; m: cstring; mlen: culonglong; pk: cstring): cint {.importc: "crypto_box_curve25519xchacha20poly1305_seal", cdecl.}
proc crypto_box_curve25519xchacha20poly1305_seal_open*(_: type Sodium; m: cstring; c: cstring; clen: culonglong; pk: cstring; sk: cstring): cint {.importc: "crypto_box_curve25519xchacha20poly1305_seal_open", cdecl.}
proc crypto_box_curve25519xsalsa20poly1305_seed_keypair*(_: type Sodium; pk: cstring; sk: cstring; seed: cstring): cint {.importc: "crypto_box_curve25519xsalsa20poly1305_seed_keypair", cdecl.}
proc crypto_box_curve25519xsalsa20poly1305_keypair*(_: type Sodium; pk: cstring; sk: cstring): cint {.importc: "crypto_box_curve25519xsalsa20poly1305_keypair", cdecl.}
proc crypto_box_curve25519xsalsa20poly1305_beforenm*(_: type Sodium; k: cstring; pk: cstring; sk: cstring): cint {.importc: "crypto_box_curve25519xsalsa20poly1305_beforenm", cdecl.}
  ##  -- NaCl compatibility interface ; Requires padding --
proc crypto_box_curve25519xsalsa20poly1305*(_: type Sodium; c: cstring; m: cstring; mlen: culonglong; n: cstring; pk: cstring; sk: cstring): cint {.importc: "crypto_box_curve25519xsalsa20poly1305", cdecl.}
proc crypto_box_curve25519xsalsa20poly1305_open*(_: type Sodium; m: cstring; c: cstring; clen: culonglong; n: cstring; pk: cstring; sk: cstring): cint {.importc: "crypto_box_curve25519xsalsa20poly1305_open", cdecl.}
proc crypto_box_curve25519xsalsa20poly1305_afternm*(_: type Sodium; c: cstring; m: cstring; mlen: culonglong; n: cstring; k: cstring): cint {.importc: "crypto_box_curve25519xsalsa20poly1305_afternm", cdecl.}
proc crypto_box_curve25519xsalsa20poly1305_open_afternm*(_: type Sodium; m: cstring; c: cstring; clen: culonglong; n: cstring; k: cstring): cint {.importc: "crypto_box_curve25519xsalsa20poly1305_open_afternm", cdecl.}
proc crypto_core_ed25519_is_valid_point*(_: type Sodium; p: cstring): cint {.importc: "crypto_core_ed25519_is_valid_point", cdecl.}
proc crypto_core_ed25519_add*(_: type Sodium; r: cstring; p: cstring; q: cstring): cint {.importc: "crypto_core_ed25519_add", cdecl.}
proc crypto_core_ed25519_sub*(_: type Sodium; r: cstring; p: cstring; q: cstring): cint {.importc: "crypto_core_ed25519_sub", cdecl.}
proc crypto_core_ed25519_from_uniform*(_: type Sodium; p: cstring; r: cstring): cint {.importc: "crypto_core_ed25519_from_uniform", cdecl.}
proc crypto_core_ed25519_from_hash*(_: type Sodium; p: cstring; h: cstring): cint {.importc: "crypto_core_ed25519_from_hash", cdecl.}
proc crypto_core_ed25519_random*(_: type Sodium; p: cstring): cint {.importc: "crypto_core_ed25519_random", cdecl.}
proc crypto_core_ed25519_scalar_random*(_: type Sodium; r: cstring): cint {.importc: "crypto_core_ed25519_scalar_random", cdecl.}
proc crypto_core_ed25519_scalar_invert*(_: type Sodium; recip: cstring; s: cstring): cint {.importc: "crypto_core_ed25519_scalar_invert", cdecl.}
proc crypto_core_ed25519_scalar_negate*(_: type Sodium; neg: cstring; s: cstring): cint {.importc: "crypto_core_ed25519_scalar_negate", cdecl.}
proc crypto_core_ed25519_scalar_complement*(_: type Sodium; comp: cstring; s: cstring): cint {.importc: "crypto_core_ed25519_scalar_complement", cdecl.}
proc crypto_core_ed25519_scalar_add*(_: type Sodium; z: cstring; x: cstring; y: cstring): cint {.importc: "crypto_core_ed25519_scalar_add", cdecl.}
proc crypto_core_ed25519_scalar_sub*(_: type Sodium; z: cstring; x: cstring; y: cstring): cint {.importc: "crypto_core_ed25519_scalar_sub", cdecl.}
proc crypto_core_ed25519_scalar_mul*(_: type Sodium; z: cstring; x: cstring; y: cstring): cint {.importc: "crypto_core_ed25519_scalar_mul", cdecl.}
  ## The interval `s` is sampled from should be at least 317 bits to ensure almost
  ## uniformity of `r` over `L`.
proc crypto_core_ed25519_scalar_reduce*(_: type Sodium; r: cstring; s: cstring): cint {.importc: "crypto_core_ed25519_scalar_reduce", cdecl.}
proc crypto_core_hchacha20*(_: type Sodium; `out`: cstring; `in`: cstring; k: cstring; c: cstring): cint {.importc: "crypto_core_hchacha20", cdecl.}
proc crypto_core_hsalsa20*(_: type Sodium; `out`: cstring; `in`: cstring; k: cstring; c: cstring): cint {.importc: "crypto_core_hsalsa20", cdecl.}
proc crypto_core_ristretto255_is_valid_point*(_: type Sodium; p: cstring): cint {.importc: "crypto_core_ristretto255_is_valid_point", cdecl.}
proc crypto_core_ristretto255_add*(_: type Sodium; r: cstring; p: cstring; q: cstring): cint {.importc: "crypto_core_ristretto255_add", cdecl.}
proc crypto_core_ristretto255_sub*(_: type Sodium; r: cstring; p: cstring; q: cstring): cint {.importc: "crypto_core_ristretto255_sub", cdecl.}
proc crypto_core_ristretto255_from_hash*(_: type Sodium; p: cstring; r: cstring): cint {.importc: "crypto_core_ristretto255_from_hash", cdecl.}
proc crypto_core_ristretto255_random*(_: type Sodium; p: cstring): cint {.importc: "crypto_core_ristretto255_random", cdecl.}
proc crypto_core_ristretto255_scalar_random*(_: type Sodium; r: cstring): cint {.importc: "crypto_core_ristretto255_scalar_random", cdecl.}
proc crypto_core_ristretto255_scalar_invert*(_: type Sodium; recip: cstring; s: cstring): cint {.importc: "crypto_core_ristretto255_scalar_invert", cdecl.}
proc crypto_core_ristretto255_scalar_negate*(_: type Sodium; neg: cstring; s: cstring): cint {.importc: "crypto_core_ristretto255_scalar_negate", cdecl.}
proc crypto_core_ristretto255_scalar_complement*(_: type Sodium; comp: cstring; s: cstring): cint {.importc: "crypto_core_ristretto255_scalar_complement", cdecl.}
proc crypto_core_ristretto255_scalar_add*(_: type Sodium; z: cstring; x: cstring; y: cstring): cint {.importc: "crypto_core_ristretto255_scalar_add", cdecl.}
proc crypto_core_ristretto255_scalar_sub*(_: type Sodium; z: cstring; x: cstring; y: cstring): cint {.importc: "crypto_core_ristretto255_scalar_sub", cdecl.}
proc crypto_core_ristretto255_scalar_mul*(_: type Sodium; z: cstring; x: cstring; y: cstring): cint {.importc: "crypto_core_ristretto255_scalar_mul", cdecl.}
  ## The interval `s` is sampled from should be at least 317 bits to ensure almost
  ## uniformity of `r` over `L`.
proc crypto_core_ristretto255_scalar_reduce*(_: type Sodium; r: cstring; s: cstring): cint {.importc: "crypto_core_ristretto255_scalar_reduce", cdecl.}
proc crypto_core_salsa20*(_: type Sodium; `out`: cstring; `in`: cstring; k: cstring; c: cstring): cint {.importc: "crypto_core_salsa20", cdecl.}
proc crypto_core_salsa2012*(_: type Sodium; `out`: cstring; `in`: cstring; k: cstring; c: cstring): cint {.importc: "crypto_core_salsa2012", cdecl.}
proc crypto_core_salsa208*(_: type Sodium; `out`: cstring; `in`: cstring; k: cstring; c: cstring): cint {.importc: "crypto_core_salsa208", cdecl.}
proc crypto_generichash_primitive*(_: type Sodium): pointer {.importc: "crypto_generichash_primitive", cdecl.}
  ## Important when writing bindings for other programming languages:
  ## the state address should be 64-bytes aligned.
proc crypto_generichash*(_: type Sodium; `out`: cstring; outlen: csize_t; `in`: cstring; inlen: culonglong; key: cstring; keylen: csize_t): cint {.importc: "crypto_generichash", cdecl.}
proc crypto_generichash_init*(_: type Sodium; state: pointer; key: cstring; keylen: csize_t; outlen: csize_t): cint {.importc: "crypto_generichash_init", cdecl.}
proc crypto_generichash_update*(_: type Sodium; state: pointer; `in`: cstring; inlen: culonglong): cint {.importc: "crypto_generichash_update", cdecl.}
proc crypto_generichash_final*(_: type Sodium; state: pointer; `out`: cstring; outlen: csize_t): cint {.importc: "crypto_generichash_final", cdecl.}
proc crypto_generichash_keygen*(_: type Sodium; k: uint8): cint {.importc: "crypto_generichash_keygen", cdecl.}
proc crypto_generichash_blake2b*(_: type Sodium; `out`: cstring; outlen: csize_t; `in`: cstring; inlen: culonglong; key: cstring; keylen: csize_t): cint {.importc: "crypto_generichash_blake2b", cdecl.}
proc crypto_generichash_blake2b_salt_personal*(_: type Sodium; `out`: cstring; outlen: csize_t; `in`: cstring; inlen: culonglong; key: cstring; keylen: csize_t; salt: cstring; personal: cstring): cint {.importc: "crypto_generichash_blake2b_salt_personal", cdecl.}
proc crypto_generichash_blake2b_init*(_: type Sodium; state: pointer; key: cstring; keylen: csize_t; outlen: csize_t): cint {.importc: "crypto_generichash_blake2b_init", cdecl.}
proc crypto_generichash_blake2b_init_salt_personal*(_: type Sodium; state: pointer; key: cstring; keylen: csize_t; outlen: csize_t; salt: cstring; personal: cstring): cint {.importc: "crypto_generichash_blake2b_init_salt_personal", cdecl.}
proc crypto_generichash_blake2b_update*(_: type Sodium; state: pointer; `in`: cstring; inlen: culonglong): cint {.importc: "crypto_generichash_blake2b_update", cdecl.}
proc crypto_generichash_blake2b_final*(_: type Sodium; state: pointer; `out`: cstring; outlen: csize_t): cint {.importc: "crypto_generichash_blake2b_final", cdecl.}
proc crypto_generichash_blake2b_keygen*(_: type Sodium; k: array[32, uint8]): cint {.importc: "crypto_generichash_blake2b_keygen", cdecl.}
proc crypto_hash*(_: type Sodium; `out`: cstring; `in`: cstring; inlen: culonglong): cint {.importc: "crypto_hash", cdecl.}
proc crypto_hash_primitive*(_: type Sodium): pointer {.importc: "crypto_hash_primitive", cdecl.}
proc crypto_hash_sha256*(_: type Sodium; `out`: cstring; `in`: cstring; inlen: culonglong): cint {.importc: "crypto_hash_sha256", cdecl.}
proc crypto_hash_sha256_init*(_: type Sodium; state: pointer): cint {.importc: "crypto_hash_sha256_init", cdecl.}
proc crypto_hash_sha256_update*(_: type Sodium; state: pointer; `in`: cstring; inlen: culonglong): cint {.importc: "crypto_hash_sha256_update", cdecl.}
proc crypto_hash_sha256_final*(_: type Sodium; state: pointer; `out`: cstring): cint {.importc: "crypto_hash_sha256_final", cdecl.}
proc crypto_hash_sha512*(_: type Sodium; `out`: cstring; `in`: cstring; inlen: culonglong): cint {.importc: "crypto_hash_sha512", cdecl.}
proc crypto_hash_sha512_init*(_: type Sodium; state: pointer): cint {.importc: "crypto_hash_sha512_init", cdecl.}
proc crypto_hash_sha512_update*(_: type Sodium; state: pointer; `in`: cstring; inlen: culonglong): cint {.importc: "crypto_hash_sha512_update", cdecl.}
proc crypto_hash_sha512_final*(_: type Sodium; state: pointer; `out`: cstring): cint {.importc: "crypto_hash_sha512_final", cdecl.}
proc crypto_kdf_primitive*(_: type Sodium): pointer {.importc: "crypto_kdf_primitive", cdecl.}
proc crypto_kdf_derive_from_key*(_: type Sodium; subkey: cstring; subkey_len: csize_t; subkey_id: uint64; ctx: cchar; key: uint8): cint {.importc: "crypto_kdf_derive_from_key", cdecl.}
proc crypto_kdf_keygen*(_: type Sodium; k: uint8): cint {.importc: "crypto_kdf_keygen", cdecl.}
proc crypto_kdf_blake2b_derive_from_key*(_: type Sodium; subkey: cstring; subkey_len: csize_t; subkey_id: uint64; ctx: array[8, cchar]; key: array[32, uint8]): cint {.importc: "crypto_kdf_blake2b_derive_from_key", cdecl.}
proc crypto_kx_primitive*(_: type Sodium): pointer {.importc: "crypto_kx_primitive", cdecl.}
proc crypto_kx_seed_keypair*(_: type Sodium; pk: array[32, uint8]; sk: array[32, uint8]; seed: array[32, uint8]): cint {.importc: "crypto_kx_seed_keypair", cdecl.}
proc crypto_kx_keypair*(_: type Sodium; pk: array[32, uint8]; sk: array[32, uint8]): cint {.importc: "crypto_kx_keypair", cdecl.}
proc crypto_kx_client_session_keys*(_: type Sodium; rx: array[32, uint8]; tx: array[32, uint8]; client_pk: array[32, uint8]; client_sk: array[32, uint8]; server_pk: array[32, uint8]): cint {.importc: "crypto_kx_client_session_keys", cdecl.}
proc crypto_kx_server_session_keys*(_: type Sodium; rx: array[32, uint8]; tx: array[32, uint8]; server_pk: array[32, uint8]; server_sk: array[32, uint8]; client_pk: array[32, uint8]): cint {.importc: "crypto_kx_server_session_keys", cdecl.}
proc crypto_onetimeauth_primitive*(_: type Sodium): pointer {.importc: "crypto_onetimeauth_primitive", cdecl.}
proc crypto_onetimeauth*(_: type Sodium; `out`: cstring; `in`: cstring; inlen: culonglong; k: cstring): cint {.importc: "crypto_onetimeauth", cdecl.}
proc crypto_onetimeauth_verify*(_: type Sodium; h: cstring; `in`: cstring; inlen: culonglong; k: cstring): cint {.importc: "crypto_onetimeauth_verify", cdecl.}
proc crypto_onetimeauth_init*(_: type Sodium; state: pointer; key: cstring): cint {.importc: "crypto_onetimeauth_init", cdecl.}
proc crypto_onetimeauth_update*(_: type Sodium; state: pointer; `in`: cstring; inlen: culonglong): cint {.importc: "crypto_onetimeauth_update", cdecl.}
proc crypto_onetimeauth_final*(_: type Sodium; state: pointer; `out`: cstring): cint {.importc: "crypto_onetimeauth_final", cdecl.}
proc crypto_onetimeauth_keygen*(_: type Sodium; k: uint8): cint {.importc: "crypto_onetimeauth_keygen", cdecl.}
proc crypto_onetimeauth_poly1305*(_: type Sodium; `out`: cstring; `in`: cstring; inlen: culonglong; k: cstring): cint {.importc: "crypto_onetimeauth_poly1305", cdecl.}
proc crypto_onetimeauth_poly1305_verify*(_: type Sodium; h: cstring; `in`: cstring; inlen: culonglong; k: cstring): cint {.importc: "crypto_onetimeauth_poly1305_verify", cdecl.}
proc crypto_onetimeauth_poly1305_init*(_: type Sodium; state: pointer; key: cstring): cint {.importc: "crypto_onetimeauth_poly1305_init", cdecl.}
proc crypto_onetimeauth_poly1305_update*(_: type Sodium; state: pointer; `in`: cstring; inlen: culonglong): cint {.importc: "crypto_onetimeauth_poly1305_update", cdecl.}
proc crypto_onetimeauth_poly1305_final*(_: type Sodium; state: pointer; `out`: cstring): cint {.importc: "crypto_onetimeauth_poly1305_final", cdecl.}
proc crypto_onetimeauth_poly1305_keygen*(_: type Sodium; k: array[32, uint8]): cint {.importc: "crypto_onetimeauth_poly1305_keygen", cdecl.}
proc crypto_pwhash_alg_argon2i13_proc*(_: type Sodium): cint {.importc: "crypto_pwhash_alg_argon2i13", cdecl.}
proc crypto_pwhash_alg_argon2id13_proc*(_: type Sodium): cint {.importc: "crypto_pwhash_alg_argon2id13", cdecl.}
proc crypto_pwhash_alg_default_proc*(_: type Sodium): cint {.importc: "crypto_pwhash_alg_default", cdecl.}
proc crypto_pwhash_strprefix*(_: type Sodium): pointer {.importc: "crypto_pwhash_strprefix", cdecl.}
proc crypto_pwhash*(_: type Sodium; `out`: cstring; outlen: culonglong; passwd: cstring; passwdlen: culonglong; salt: cstring; opslimit: culonglong; memlimit: csize_t; alg: cint): cint {.importc: "crypto_pwhash", cdecl.}
  ## The output string already includes all the required parameters, including
  ## the algorithm identifier. The string is all that has to be stored in
  ## order to verify a password.
proc crypto_pwhash_str*(_: type Sodium; `out`: cchar; passwd: cstring; passwdlen: culonglong; opslimit: culonglong; memlimit: csize_t): cint {.importc: "crypto_pwhash_str", cdecl.}
proc crypto_pwhash_str_alg*(_: type Sodium; `out`: cchar; passwd: cstring; passwdlen: culonglong; opslimit: culonglong; memlimit: csize_t; alg: cint): cint {.importc: "crypto_pwhash_str_alg", cdecl.}
proc crypto_pwhash_str_verify*(_: type Sodium; str: cchar; passwd: cstring; passwdlen: culonglong): cint {.importc: "crypto_pwhash_str_verify", cdecl.}
proc crypto_pwhash_str_needs_rehash*(_: type Sodium; str: cchar; opslimit: culonglong; memlimit: csize_t): cint {.importc: "crypto_pwhash_str_needs_rehash", cdecl.}
proc crypto_pwhash_primitive*(_: type Sodium): pointer {.importc: "crypto_pwhash_primitive", cdecl.}
proc crypto_pwhash_argon2i_alg_argon2i13_proc*(_: type Sodium): cint {.importc: "crypto_pwhash_argon2i_alg_argon2i13", cdecl.}
proc crypto_pwhash_argon2i_strprefix*(_: type Sodium): pointer {.importc: "crypto_pwhash_argon2i_strprefix", cdecl.}
proc crypto_pwhash_argon2i*(_: type Sodium; `out`: cstring; outlen: culonglong; passwd: cstring; passwdlen: culonglong; salt: cstring; opslimit: culonglong; memlimit: csize_t; alg: cint): cint {.importc: "crypto_pwhash_argon2i", cdecl.}
proc crypto_pwhash_argon2i_str*(_: type Sodium; `out`: array[128, cchar]; passwd: cstring; passwdlen: culonglong; opslimit: culonglong; memlimit: csize_t): cint {.importc: "crypto_pwhash_argon2i_str", cdecl.}
proc crypto_pwhash_argon2i_str_verify*(_: type Sodium; str: array[128, cchar]; passwd: cstring; passwdlen: culonglong): cint {.importc: "crypto_pwhash_argon2i_str_verify", cdecl.}
proc crypto_pwhash_argon2i_str_needs_rehash*(_: type Sodium; str: array[128, cchar]; opslimit: culonglong; memlimit: csize_t): cint {.importc: "crypto_pwhash_argon2i_str_needs_rehash", cdecl.}
proc crypto_pwhash_argon2id_alg_argon2id13_proc*(_: type Sodium): cint {.importc: "crypto_pwhash_argon2id_alg_argon2id13", cdecl.}
proc crypto_pwhash_argon2id_strprefix*(_: type Sodium): pointer {.importc: "crypto_pwhash_argon2id_strprefix", cdecl.}
proc crypto_pwhash_argon2id*(_: type Sodium; `out`: cstring; outlen: culonglong; passwd: cstring; passwdlen: culonglong; salt: cstring; opslimit: culonglong; memlimit: csize_t; alg: cint): cint {.importc: "crypto_pwhash_argon2id", cdecl.}
proc crypto_pwhash_argon2id_str*(_: type Sodium; `out`: array[128, cchar]; passwd: cstring; passwdlen: culonglong; opslimit: culonglong; memlimit: csize_t): cint {.importc: "crypto_pwhash_argon2id_str", cdecl.}
proc crypto_pwhash_argon2id_str_verify*(_: type Sodium; str: array[128, cchar]; passwd: cstring; passwdlen: culonglong): cint {.importc: "crypto_pwhash_argon2id_str_verify", cdecl.}
proc crypto_pwhash_argon2id_str_needs_rehash*(_: type Sodium; str: array[128, cchar]; opslimit: culonglong; memlimit: csize_t): cint {.importc: "crypto_pwhash_argon2id_str_needs_rehash", cdecl.}
proc crypto_pwhash_scryptsalsa208sha256_strprefix_proc*(_: type Sodium): pointer {.importc: "crypto_pwhash_scryptsalsa208sha256_strprefix", cdecl.}
proc crypto_pwhash_scryptsalsa208sha256*(_: type Sodium; `out`: cstring; outlen: culonglong; passwd: cstring; passwdlen: culonglong; salt: cstring; opslimit: culonglong; memlimit: csize_t): cint {.importc: "crypto_pwhash_scryptsalsa208sha256", cdecl.}
proc crypto_pwhash_scryptsalsa208sha256_str*(_: type Sodium; `out`: array[102, cchar]; passwd: cstring; passwdlen: culonglong; opslimit: culonglong; memlimit: csize_t): cint {.importc: "crypto_pwhash_scryptsalsa208sha256_str", cdecl.}
proc crypto_pwhash_scryptsalsa208sha256_str_verify*(_: type Sodium; str: array[102, cchar]; passwd: cstring; passwdlen: culonglong): cint {.importc: "crypto_pwhash_scryptsalsa208sha256_str_verify", cdecl.}
proc crypto_pwhash_scryptsalsa208sha256_ll*(_: type Sodium; passwd: pointer; passwdlen: csize_t; salt: pointer; saltlen: csize_t; N: uint64; r: uint32; p: uint32; buf: pointer; buflen: csize_t): cint {.importc: "crypto_pwhash_scryptsalsa208sha256_ll", cdecl.}
proc crypto_pwhash_scryptsalsa208sha256_str_needs_rehash*(_: type Sodium; str: array[102, cchar]; opslimit: culonglong; memlimit: csize_t): cint {.importc: "crypto_pwhash_scryptsalsa208sha256_str_needs_rehash", cdecl.}
proc crypto_scalarmult_primitive*(_: type Sodium): pointer {.importc: "crypto_scalarmult_primitive", cdecl.}
proc crypto_scalarmult_base*(_: type Sodium; q: cstring; n: cstring): cint {.importc: "crypto_scalarmult_base", cdecl.}
  ## NOTE: Do not use the result of this function directly for key exchange.
  ##
  ## Hash the result with the public keys in order to compute a shared
  ## secret key: H(q || client_pk || server_pk)
  ##
  ## Or unless this is not an option, use the crypto_kx() API instead.
proc crypto_scalarmult*(_: type Sodium; q: cstring; n: cstring; p: cstring): cint {.importc: "crypto_scalarmult", cdecl.}
proc crypto_scalarmult_curve25519*(_: type Sodium; q: cstring; n: cstring; p: cstring): cint {.importc: "crypto_scalarmult_curve25519", cdecl.}
proc crypto_scalarmult_curve25519_base*(_: type Sodium; q: cstring; n: cstring): cint {.importc: "crypto_scalarmult_curve25519_base", cdecl.}
proc crypto_scalarmult_ed25519*(_: type Sodium; q: cstring; n: cstring; p: cstring): cint {.importc: "crypto_scalarmult_ed25519", cdecl.}
proc crypto_scalarmult_ed25519_noclamp*(_: type Sodium; q: cstring; n: cstring; p: cstring): cint {.importc: "crypto_scalarmult_ed25519_noclamp", cdecl.}
proc crypto_scalarmult_ed25519_base*(_: type Sodium; q: cstring; n: cstring): cint {.importc: "crypto_scalarmult_ed25519_base", cdecl.}
proc crypto_scalarmult_ed25519_base_noclamp*(_: type Sodium; q: cstring; n: cstring): cint {.importc: "crypto_scalarmult_ed25519_base_noclamp", cdecl.}
proc crypto_scalarmult_ristretto255*(_: type Sodium; q: cstring; n: cstring; p: cstring): cint {.importc: "crypto_scalarmult_ristretto255", cdecl.}
proc crypto_scalarmult_ristretto255_base*(_: type Sodium; q: cstring; n: cstring): cint {.importc: "crypto_scalarmult_ristretto255_base", cdecl.}
proc crypto_secretbox_primitive*(_: type Sodium): pointer {.importc: "crypto_secretbox_primitive", cdecl.}
proc crypto_secretbox_easy*(_: type Sodium; c: cstring; m: cstring; mlen: culonglong; n: cstring; k: cstring): cint {.importc: "crypto_secretbox_easy", cdecl.}
proc crypto_secretbox_open_easy*(_: type Sodium; m: cstring; c: cstring; clen: culonglong; n: cstring; k: cstring): cint {.importc: "crypto_secretbox_open_easy", cdecl.}
proc crypto_secretbox_detached*(_: type Sodium; c: cstring; mac: cstring; m: cstring; mlen: culonglong; n: cstring; k: cstring): cint {.importc: "crypto_secretbox_detached", cdecl.}
proc crypto_secretbox_open_detached*(_: type Sodium; m: cstring; c: cstring; mac: cstring; clen: culonglong; n: cstring; k: cstring): cint {.importc: "crypto_secretbox_open_detached", cdecl.}
proc crypto_secretbox_keygen*(_: type Sodium; k: uint8): cint {.importc: "crypto_secretbox_keygen", cdecl.}
  ##  -- NaCl compatibility interface ; Requires padding --
proc crypto_secretbox*(_: type Sodium; c: cstring; m: cstring; mlen: culonglong; n: cstring; k: cstring): cint {.importc: "crypto_secretbox", cdecl.}
proc crypto_secretbox_open*(_: type Sodium; m: cstring; c: cstring; clen: culonglong; n: cstring; k: cstring): cint {.importc: "crypto_secretbox_open", cdecl.}
proc crypto_secretbox_xchacha20poly1305_easy*(_: type Sodium; c: cstring; m: cstring; mlen: culonglong; n: cstring; k: cstring): cint {.importc: "crypto_secretbox_xchacha20poly1305_easy", cdecl.}
proc crypto_secretbox_xchacha20poly1305_open_easy*(_: type Sodium; m: cstring; c: cstring; clen: culonglong; n: cstring; k: cstring): cint {.importc: "crypto_secretbox_xchacha20poly1305_open_easy", cdecl.}
proc crypto_secretbox_xchacha20poly1305_detached*(_: type Sodium; c: cstring; mac: cstring; m: cstring; mlen: culonglong; n: cstring; k: cstring): cint {.importc: "crypto_secretbox_xchacha20poly1305_detached", cdecl.}
proc crypto_secretbox_xchacha20poly1305_open_detached*(_: type Sodium; m: cstring; c: cstring; mac: cstring; clen: culonglong; n: cstring; k: cstring): cint {.importc: "crypto_secretbox_xchacha20poly1305_open_detached", cdecl.}
proc crypto_secretbox_xsalsa20poly1305*(_: type Sodium; c: cstring; m: cstring; mlen: culonglong; n: cstring; k: cstring): cint {.importc: "crypto_secretbox_xsalsa20poly1305", cdecl.}
proc crypto_secretbox_xsalsa20poly1305_open*(_: type Sodium; m: cstring; c: cstring; clen: culonglong; n: cstring; k: cstring): cint {.importc: "crypto_secretbox_xsalsa20poly1305_open", cdecl.}
proc crypto_secretbox_xsalsa20poly1305_keygen*(_: type Sodium; k: array[32, uint8]): cint {.importc: "crypto_secretbox_xsalsa20poly1305_keygen", cdecl.}
  ##  -- NaCl compatibility interface ; Requires padding --
proc crypto_secretstream_xchacha20poly1305_keygen*(_: type Sodium; k: array[32, uint8]): cint {.importc: "crypto_secretstream_xchacha20poly1305_keygen", cdecl.}
proc crypto_secretstream_xchacha20poly1305_init_push*(_: type Sodium; state: pointer; header: array[24, uint8]; k: array[32, uint8]): cint {.importc: "crypto_secretstream_xchacha20poly1305_init_push", cdecl.}
proc crypto_secretstream_xchacha20poly1305_push*(_: type Sodium; state: pointer; c: cstring; clen_p: pointer; m: cstring; mlen: culonglong; ad: cstring; adlen: culonglong; tag: uint8): cint {.importc: "crypto_secretstream_xchacha20poly1305_push", cdecl.}
proc crypto_secretstream_xchacha20poly1305_init_pull*(_: type Sodium; state: pointer; header: array[24, uint8]; k: array[32, uint8]): cint {.importc: "crypto_secretstream_xchacha20poly1305_init_pull", cdecl.}
proc crypto_secretstream_xchacha20poly1305_pull*(_: type Sodium; state: pointer; m: cstring; mlen_p: pointer; tag_p: cstring; c: cstring; clen: culonglong; ad: cstring; adlen: culonglong): cint {.importc: "crypto_secretstream_xchacha20poly1305_pull", cdecl.}
proc crypto_secretstream_xchacha20poly1305_rekey*(_: type Sodium; state: pointer): cint {.importc: "crypto_secretstream_xchacha20poly1305_rekey", cdecl.}
proc crypto_shorthash_primitive*(_: type Sodium): pointer {.importc: "crypto_shorthash_primitive", cdecl.}
proc crypto_shorthash*(_: type Sodium; `out`: cstring; `in`: cstring; inlen: culonglong; k: cstring): cint {.importc: "crypto_shorthash", cdecl.}
proc crypto_shorthash_keygen*(_: type Sodium; k: uint8): cint {.importc: "crypto_shorthash_keygen", cdecl.}
proc crypto_shorthash_siphash24*(_: type Sodium; `out`: cstring; `in`: cstring; inlen: culonglong; k: cstring): cint {.importc: "crypto_shorthash_siphash24", cdecl.}
proc crypto_shorthash_siphashx24*(_: type Sodium; `out`: cstring; `in`: cstring; inlen: culonglong; k: cstring): cint {.importc: "crypto_shorthash_siphashx24", cdecl.}
proc crypto_sign_primitive*(_: type Sodium): pointer {.importc: "crypto_sign_primitive", cdecl.}
proc crypto_sign_seed_keypair*(_: type Sodium; pk: cstring; sk: cstring; seed: cstring): cint {.importc: "crypto_sign_seed_keypair", cdecl.}
proc crypto_sign_keypair*(_: type Sodium; pk: cstring; sk: cstring): cint {.importc: "crypto_sign_keypair", cdecl.}
proc crypto_sign*(_: type Sodium; sm: cstring; smlen_p: pointer; m: cstring; mlen: culonglong; sk: cstring): cint {.importc: "crypto_sign", cdecl.}
proc crypto_sign_open*(_: type Sodium; m: cstring; mlen_p: pointer; sm: cstring; smlen: culonglong; pk: cstring): cint {.importc: "crypto_sign_open", cdecl.}
proc crypto_sign_detached*(_: type Sodium; sig: cstring; siglen_p: pointer; m: cstring; mlen: culonglong; sk: cstring): cint {.importc: "crypto_sign_detached", cdecl.}
proc crypto_sign_verify_detached*(_: type Sodium; sig: cstring; m: cstring; mlen: culonglong; pk: cstring): cint {.importc: "crypto_sign_verify_detached", cdecl.}
proc crypto_sign_init*(_: type Sodium; state: pointer): cint {.importc: "crypto_sign_init", cdecl.}
proc crypto_sign_update*(_: type Sodium; state: pointer; m: cstring; mlen: culonglong): cint {.importc: "crypto_sign_update", cdecl.}
proc crypto_sign_final_create*(_: type Sodium; state: pointer; sig: cstring; siglen_p: pointer; sk: cstring): cint {.importc: "crypto_sign_final_create", cdecl.}
proc crypto_sign_final_verify*(_: type Sodium; state: pointer; sig: cstring; pk: cstring): cint {.importc: "crypto_sign_final_verify", cdecl.}
proc crypto_sign_ed25519*(_: type Sodium; sm: cstring; smlen_p: pointer; m: cstring; mlen: culonglong; sk: cstring): cint {.importc: "crypto_sign_ed25519", cdecl.}
proc crypto_sign_ed25519_open*(_: type Sodium; m: cstring; mlen_p: pointer; sm: cstring; smlen: culonglong; pk: cstring): cint {.importc: "crypto_sign_ed25519_open", cdecl.}
proc crypto_sign_ed25519_detached*(_: type Sodium; sig: cstring; siglen_p: pointer; m: cstring; mlen: culonglong; sk: cstring): cint {.importc: "crypto_sign_ed25519_detached", cdecl.}
proc crypto_sign_ed25519_verify_detached*(_: type Sodium; sig: cstring; m: cstring; mlen: culonglong; pk: cstring): cint {.importc: "crypto_sign_ed25519_verify_detached", cdecl.}
proc crypto_sign_ed25519_keypair*(_: type Sodium; pk: cstring; sk: cstring): cint {.importc: "crypto_sign_ed25519_keypair", cdecl.}
proc crypto_sign_ed25519_seed_keypair*(_: type Sodium; pk: cstring; sk: cstring; seed: cstring): cint {.importc: "crypto_sign_ed25519_seed_keypair", cdecl.}
proc crypto_sign_ed25519_pk_to_curve25519*(_: type Sodium; curve25519_pk: cstring; ed25519_pk: cstring): cint {.importc: "crypto_sign_ed25519_pk_to_curve25519", cdecl.}
proc crypto_sign_ed25519_sk_to_curve25519*(_: type Sodium; curve25519_sk: cstring; ed25519_sk: cstring): cint {.importc: "crypto_sign_ed25519_sk_to_curve25519", cdecl.}
proc crypto_sign_ed25519_sk_to_seed*(_: type Sodium; seed: cstring; sk: cstring): cint {.importc: "crypto_sign_ed25519_sk_to_seed", cdecl.}
proc crypto_sign_ed25519_sk_to_pk*(_: type Sodium; pk: cstring; sk: cstring): cint {.importc: "crypto_sign_ed25519_sk_to_pk", cdecl.}
proc crypto_sign_ed25519ph_init*(_: type Sodium; state: pointer): cint {.importc: "crypto_sign_ed25519ph_init", cdecl.}
proc crypto_sign_ed25519ph_update*(_: type Sodium; state: pointer; m: cstring; mlen: culonglong): cint {.importc: "crypto_sign_ed25519ph_update", cdecl.}
proc crypto_sign_ed25519ph_final_create*(_: type Sodium; state: pointer; sig: cstring; siglen_p: pointer; sk: cstring): cint {.importc: "crypto_sign_ed25519ph_final_create", cdecl.}
proc crypto_sign_ed25519ph_final_verify*(_: type Sodium; state: pointer; sig: cstring; pk: cstring): cint {.importc: "crypto_sign_ed25519ph_final_verify", cdecl.}
proc crypto_sign_edwards25519sha512batch*(_: type Sodium; sm: cstring; smlen_p: pointer; m: cstring; mlen: culonglong; sk: cstring): cint {.importc: "crypto_sign_edwards25519sha512batch", cdecl.}
proc crypto_sign_edwards25519sha512batch_open*(_: type Sodium; m: cstring; mlen_p: pointer; sm: cstring; smlen: culonglong; pk: cstring): cint {.importc: "crypto_sign_edwards25519sha512batch_open", cdecl.}
proc crypto_sign_edwards25519sha512batch_keypair*(_: type Sodium; pk: cstring; sk: cstring): cint {.importc: "crypto_sign_edwards25519sha512batch_keypair", cdecl.}
proc crypto_stream_primitive*(_: type Sodium): pointer {.importc: "crypto_stream_primitive", cdecl.}
proc crypto_stream*(_: type Sodium; c: cstring; clen: culonglong; n: cstring; k: cstring): cint {.importc: "crypto_stream", cdecl.}
proc crypto_stream_xor*(_: type Sodium; c: cstring; m: cstring; mlen: culonglong; n: cstring; k: cstring): cint {.importc: "crypto_stream_xor", cdecl.}
proc crypto_stream_keygen*(_: type Sodium; k: uint8): cint {.importc: "crypto_stream_keygen", cdecl.}
proc crypto_stream_chacha20*(_: type Sodium; c: cstring; clen: culonglong; n: cstring; k: cstring): cint {.importc: "crypto_stream_chacha20", cdecl.}
proc crypto_stream_chacha20_xor*(_: type Sodium; c: cstring; m: cstring; mlen: culonglong; n: cstring; k: cstring): cint {.importc: "crypto_stream_chacha20_xor", cdecl.}
proc crypto_stream_chacha20_xor_ic*(_: type Sodium; c: cstring; m: cstring; mlen: culonglong; n: cstring; ic: uint64; k: cstring): cint {.importc: "crypto_stream_chacha20_xor_ic", cdecl.}
proc crypto_stream_chacha20_keygen*(_: type Sodium; k: array[32, uint8]): cint {.importc: "crypto_stream_chacha20_keygen", cdecl.}
  ##  ChaCha20 with a 96-bit nonce and a 32-bit counter (IETF)
proc crypto_stream_chacha20_ietf*(_: type Sodium; c: cstring; clen: culonglong; n: cstring; k: cstring): cint {.importc: "crypto_stream_chacha20_ietf", cdecl.}
proc crypto_stream_chacha20_ietf_xor*(_: type Sodium; c: cstring; m: cstring; mlen: culonglong; n: cstring; k: cstring): cint {.importc: "crypto_stream_chacha20_ietf_xor", cdecl.}
proc crypto_stream_chacha20_ietf_xor_ic*(_: type Sodium; c: cstring; m: cstring; mlen: culonglong; n: cstring; ic: uint32; k: cstring): cint {.importc: "crypto_stream_chacha20_ietf_xor_ic", cdecl.}
proc crypto_stream_chacha20_ietf_keygen*(_: type Sodium; k: array[32, uint8]): cint {.importc: "crypto_stream_chacha20_ietf_keygen", cdecl.}
  ##  Aliases
proc crypto_stream_salsa20*(_: type Sodium; c: cstring; clen: culonglong; n: cstring; k: cstring): cint {.importc: "crypto_stream_salsa20", cdecl.}
proc crypto_stream_salsa20_xor*(_: type Sodium; c: cstring; m: cstring; mlen: culonglong; n: cstring; k: cstring): cint {.importc: "crypto_stream_salsa20_xor", cdecl.}
proc crypto_stream_salsa20_xor_ic*(_: type Sodium; c: cstring; m: cstring; mlen: culonglong; n: cstring; ic: uint64; k: cstring): cint {.importc: "crypto_stream_salsa20_xor_ic", cdecl.}
proc crypto_stream_salsa20_keygen*(_: type Sodium; k: array[32, uint8]): cint {.importc: "crypto_stream_salsa20_keygen", cdecl.}
proc crypto_stream_salsa2012*(_: type Sodium; c: cstring; clen: culonglong; n: cstring; k: cstring): cint {.importc: "crypto_stream_salsa2012", cdecl.}
proc crypto_stream_salsa2012_xor*(_: type Sodium; c: cstring; m: cstring; mlen: culonglong; n: cstring; k: cstring): cint {.importc: "crypto_stream_salsa2012_xor", cdecl.}
proc crypto_stream_salsa2012_keygen*(_: type Sodium; k: array[32, uint8]): cint {.importc: "crypto_stream_salsa2012_keygen", cdecl.}
proc crypto_stream_salsa208*(_: type Sodium; c: cstring; clen: culonglong; n: cstring; k: cstring): cint {.importc: "crypto_stream_salsa208", cdecl.}
proc crypto_stream_salsa208_xor*(_: type Sodium; c: cstring; m: cstring; mlen: culonglong; n: cstring; k: cstring): cint {.importc: "crypto_stream_salsa208_xor", cdecl.}
proc crypto_stream_salsa208_keygen*(_: type Sodium; k: array[32, uint8]): cint {.importc: "crypto_stream_salsa208_keygen", cdecl.}
proc crypto_stream_xchacha20*(_: type Sodium; c: cstring; clen: culonglong; n: cstring; k: cstring): cint {.importc: "crypto_stream_xchacha20", cdecl.}
proc crypto_stream_xchacha20_xor*(_: type Sodium; c: cstring; m: cstring; mlen: culonglong; n: cstring; k: cstring): cint {.importc: "crypto_stream_xchacha20_xor", cdecl.}
proc crypto_stream_xchacha20_xor_ic*(_: type Sodium; c: cstring; m: cstring; mlen: culonglong; n: cstring; ic: uint64; k: cstring): cint {.importc: "crypto_stream_xchacha20_xor_ic", cdecl.}
proc crypto_stream_xchacha20_keygen*(_: type Sodium; k: array[32, uint8]): cint {.importc: "crypto_stream_xchacha20_keygen", cdecl.}
proc crypto_stream_xsalsa20*(_: type Sodium; c: cstring; clen: culonglong; n: cstring; k: cstring): cint {.importc: "crypto_stream_xsalsa20", cdecl.}
proc crypto_stream_xsalsa20_xor*(_: type Sodium; c: cstring; m: cstring; mlen: culonglong; n: cstring; k: cstring): cint {.importc: "crypto_stream_xsalsa20_xor", cdecl.}
proc crypto_stream_xsalsa20_xor_ic*(_: type Sodium; c: cstring; m: cstring; mlen: culonglong; n: cstring; ic: uint64; k: cstring): cint {.importc: "crypto_stream_xsalsa20_xor_ic", cdecl.}
proc crypto_stream_xsalsa20_keygen*(_: type Sodium; k: array[32, uint8]): cint {.importc: "crypto_stream_xsalsa20_keygen", cdecl.}
proc crypto_verify_16*(_: type Sodium; x: cstring; y: cstring): cint {.importc: "crypto_verify_16", cdecl.}
proc crypto_verify_32*(_: type Sodium; x: cstring; y: cstring): cint {.importc: "crypto_verify_32", cdecl.}
proc crypto_verify_64*(_: type Sodium; x: cstring; y: cstring): cint {.importc: "crypto_verify_64", cdecl.}
proc randombytes_seedbytes_proc*(_: type Sodium): csize_t {.importc: "randombytes_seedbytes", cdecl.}
proc randombytes_buf*(_: type Sodium; buf: pointer; size: csize_t) {.importc: "randombytes_buf", cdecl.}
proc randombytes_buf_deterministic*(_: type Sodium; buf: pointer; size: csize_t; seed: array[32, uint8]) {.importc: "randombytes_buf_deterministic", cdecl.}
proc randombytes_random*(_: type Sodium): uint32 {.importc: "randombytes_random", cdecl.}
proc randombytes_uniform*(_: type Sodium; upper_bound: uint32): uint32 {.importc: "randombytes_uniform", cdecl.}
proc randombytes_stir*(_: type Sodium) {.importc: "randombytes_stir", cdecl.}
proc randombytes_close*(_: type Sodium): cint {.importc: "randombytes_close", cdecl.}
proc randombytes_set_implementation*(_: type Sodium; impl: pointer): cint {.importc: "randombytes_set_implementation", cdecl.}
proc randombytes_implementation_name*(_: type Sodium): cstring {.importc: "randombytes_implementation_name", cdecl.}
  ##  -- NaCl compatibility interface --
proc randombytes*(_: type Sodium; buf: cstring; buf_len: culonglong) {.importc: "randombytes", cdecl.}
proc sodium_runtime_has_neon*(_: type Sodium): cint {.importc: "sodium_runtime_has_neon", cdecl.}
proc sodium_runtime_has_sse2*(_: type Sodium): cint {.importc: "sodium_runtime_has_sse2", cdecl.}
proc sodium_runtime_has_sse3*(_: type Sodium): cint {.importc: "sodium_runtime_has_sse3", cdecl.}
proc sodium_runtime_has_ssse3*(_: type Sodium): cint {.importc: "sodium_runtime_has_ssse3", cdecl.}
proc sodium_runtime_has_sse41*(_: type Sodium): cint {.importc: "sodium_runtime_has_sse41", cdecl.}
proc sodium_runtime_has_avx*(_: type Sodium): cint {.importc: "sodium_runtime_has_avx", cdecl.}
proc sodium_runtime_has_avx2*(_: type Sodium): cint {.importc: "sodium_runtime_has_avx2", cdecl.}
proc sodium_runtime_has_avx512f*(_: type Sodium): cint {.importc: "sodium_runtime_has_avx512f", cdecl.}
proc sodium_runtime_has_pclmul*(_: type Sodium): cint {.importc: "sodium_runtime_has_pclmul", cdecl.}
proc sodium_runtime_has_aesni*(_: type Sodium): cint {.importc: "sodium_runtime_has_aesni", cdecl.}
proc sodium_runtime_has_rdrand*(_: type Sodium): cint {.importc: "sodium_runtime_has_rdrand", cdecl.}
  ##  -------------------------------------------------------------------------
proc sodium_memzero*(_: type Sodium; pnt: pointer; len: csize_t) {.importc: "sodium_memzero", cdecl.}
proc sodium_stackzero*(_: type Sodium; len: csize_t) {.importc: "sodium_stackzero", cdecl.}
# WARNING: sodium_memcmp() must be used to verify if two secret keys are equal,
# in constant time. It returns 0 if the keys are equal, and -1 if they differ.
# This function is not designed for lexicographical comparisons.
proc sodium_memcmp*(_: type Sodium; b1: pointer; b2: pointer; len: csize_t): cint {.importc: "sodium_memcmp", cdecl.}
# sodium_compare() returns -1 if b1_ < b2_, 1 if b1_ > b2_ and 0 if b1_ == b2_.
# It is suitable for lexicographical comparisons, or to compare nonces and
# counters stored in little-endian format. However, it is slower than
# sodium_memcmp().
proc sodium_compare*(_: type Sodium; b1: cstring; b2: cstring; len: csize_t): cint {.importc: "sodium_compare", cdecl.}
proc sodium_is_zero*(_: type Sodium; n: cstring; nlen: csize_t): cint {.importc: "sodium_is_zero", cdecl.}
proc sodium_increment*(_: type Sodium; n: cstring; nlen: csize_t) {.importc: "sodium_increment", cdecl.}
proc sodium_add*(_: type Sodium; a: cstring; b: cstring; len: csize_t) {.importc: "sodium_add", cdecl.}
proc sodium_sub*(_: type Sodium; a: cstring; b: cstring; len: csize_t) {.importc: "sodium_sub", cdecl.}
proc sodium_bin2hex*(_: type Sodium; hex: cstring; hex_maxlen: csize_t; bin: cstring; bin_len: csize_t): cstring {.importc: "sodium_bin2hex", cdecl.}
proc sodium_hex2bin*(_: type Sodium; bin: cstring; bin_maxlen: csize_t; hex: cstring; hex_len: csize_t; ignore: cstring; bin_len: pointer; hex_end: cstring): cint {.importc: "sodium_hex2bin", cdecl.}
proc sodium_base64_encoded_len*(_: type Sodium; bin_len: csize_t; variant: cint): csize_t {.importc: "sodium_base64_encoded_len", cdecl.}
proc sodium_bin2base64*(_: type Sodium; b64: cstring; b64_maxlen: csize_t; bin: cstring; bin_len: csize_t; variant: cint): cstring {.importc: "sodium_bin2base64", cdecl.}
proc sodium_base642bin*(_: type Sodium; bin: cstring; bin_maxlen: csize_t; b64: cstring; b64_len: csize_t; ignore: cstring; bin_len: pointer; b64_end: cstring; variant: cint): cint {.importc: "sodium_base642bin", cdecl.}
proc sodium_mlock*(_: type Sodium; `addr`: pointer; len: csize_t): cint {.importc: "sodium_mlock", cdecl.}
proc sodium_munlock*(_: type Sodium; `addr`: pointer; len: csize_t): cint {.importc: "sodium_munlock", cdecl.}
# WARNING: sodium_malloc() and sodium_allocarray() are not general-purpose
# allocation functions. They use guard pages and can intentionally terminate
# the process on out-of-bounds access. See libsodium documentation before use.
proc sodium_malloc*(_: type Sodium; size: csize_t): pointer {.importc: "sodium_malloc", cdecl.}
proc sodium_allocarray*(_: type Sodium; count: csize_t; size: csize_t): pointer {.importc: "sodium_allocarray", cdecl.}
proc sodium_free*(_: type Sodium; `ptr`: pointer) {.importc: "sodium_free", cdecl.}
proc sodium_mprotect_noaccess*(_: type Sodium; `ptr`: pointer): cint {.importc: "sodium_mprotect_noaccess", cdecl.}
proc sodium_mprotect_readonly*(_: type Sodium; `ptr`: pointer): cint {.importc: "sodium_mprotect_readonly", cdecl.}
proc sodium_mprotect_readwrite*(_: type Sodium; `ptr`: pointer): cint {.importc: "sodium_mprotect_readwrite", cdecl.}
proc sodium_pad*(_: type Sodium; padded_buflen_p: pointer; buf: cstring; unpadded_buflen: csize_t; blocksize: csize_t; max_buflen: csize_t): cint {.importc: "sodium_pad", cdecl.}
proc sodium_unpad*(_: type Sodium; unpadded_buflen_p: pointer; buf: cstring; padded_buflen: csize_t; blocksize: csize_t): cint {.importc: "sodium_unpad", cdecl.}
  ##  --------
proc sodium_version_string*(_: type Sodium): cstring {.importc: "sodium_version_string", cdecl.}
proc sodium_library_version_major*(_: type Sodium): cint {.importc: "sodium_library_version_major", cdecl.}
proc sodium_library_version_minor*(_: type Sodium): cint {.importc: "sodium_library_version_minor", cdecl.}
proc sodium_library_minimal*(_: type Sodium): cint {.importc: "sodium_library_minimal", cdecl.}

# Local compatibility overloads for declarations that need writable C strings.
proc crypto_pwhash_str*(_: type Sodium; `out`: cstring; passwd: cstring; passwdlen: culonglong; opslimit: culonglong; memlimit: csize_t): cint {.importc: "crypto_pwhash_str", cdecl.}
proc crypto_pwhash_str_alg*(_: type Sodium; `out`: cstring; passwd: cstring; passwdlen: culonglong; opslimit: culonglong; memlimit: csize_t; alg: cint): cint {.importc: "crypto_pwhash_str_alg", cdecl.}
proc crypto_pwhash_str_verify*(_: type Sodium; str: cstring; passwd: cstring; passwdlen: culonglong): cint {.importc: "crypto_pwhash_str_verify", cdecl.}
proc crypto_pwhash_str_needs_rehash*(_: type Sodium; str: cstring; opslimit: culonglong; memlimit: csize_t): cint {.importc: "crypto_pwhash_str_needs_rehash", cdecl.}
proc crypto_kdf_keygen*(_: type Sodium; k: cstring) {.importc: "crypto_kdf_keygen", cdecl.}
proc crypto_kdf_derive_from_key*(_: type Sodium; subkey: cstring; subkey_len: csize_t; subkey_id: uint64; ctx: cstring; key: cstring): cint {.importc: "crypto_kdf_derive_from_key", cdecl.}
proc crypto_kx_keypair*(_: type Sodium; pk: cstring; sk: cstring): cint {.importc: "crypto_kx_keypair", cdecl.}
proc crypto_kx_client_session_keys*(_: type Sodium; rx: cstring; tx: cstring; client_pk: cstring; client_sk: cstring; server_pk: cstring): cint {.importc: "crypto_kx_client_session_keys", cdecl.}
proc crypto_kx_server_session_keys*(_: type Sodium; rx: cstring; tx: cstring; server_pk: cstring; server_sk: cstring; client_pk: cstring): cint {.importc: "crypto_kx_server_session_keys", cdecl.}
proc crypto_shorthash_keygen*(_: type Sodium; k: cstring) {.importc: "crypto_shorthash_keygen", cdecl.}
proc crypto_onetimeauth_keygen*(_: type Sodium; k: cstring) {.importc: "crypto_onetimeauth_keygen", cdecl.}
proc crypto_secretstream_xchacha20poly1305_statebytes*(_: type Sodium): csize_t {.importc: "crypto_secretstream_xchacha20poly1305_statebytes", cdecl.}
proc crypto_secretstream_xchacha20poly1305_keygen*(_: type Sodium; k: cstring) {.importc: "crypto_secretstream_xchacha20poly1305_keygen", cdecl.}
proc crypto_secretstream_xchacha20poly1305_init_push*(_: type Sodium; state: pointer; header: cstring; k: cstring): cint {.importc: "crypto_secretstream_xchacha20poly1305_init_push", cdecl.}
proc crypto_secretstream_xchacha20poly1305_init_pull*(_: type Sodium; state: pointer; header: cstring; k: cstring): cint {.importc: "crypto_secretstream_xchacha20poly1305_init_pull", cdecl.}
proc crypto_secretstream_xchacha20poly1305_pull*(_: type Sodium; state: pointer; m: cstring; mlen_p: pointer; tag_p: ptr uint8; c: cstring; clen: culonglong; ad: cstring; adlen: culonglong): cint {.importc: "crypto_secretstream_xchacha20poly1305_pull", cdecl.}
