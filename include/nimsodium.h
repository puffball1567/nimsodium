#ifndef NIMSODIUM_H
#define NIMSODIUM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NIMSODIUM_PROFILE_INTERACTIVE 0
#define NIMSODIUM_PROFILE_MODERATE 1
#define NIMSODIUM_PROFILE_SENSITIVE 2

#define NIMSODIUM_SIGNING_PUBLIC_KEY_BYTES 32
#define NIMSODIUM_SIGNING_SECRET_KEY_BYTES 64
#define NIMSODIUM_SIGNATURE_BYTES 64

typedef struct nimsodium_buffer {
  void *data;
  size_t len;
} nimsodium_buffer;

const char *nimsodium_c_abi_version(void);
const char *nimsodium_package_version(void);
const char *nimsodium_libsodium_version(void);
const char *nimsodium_last_error(void);

int nimsodium_init(void);

/*
 * Frees and zeroes a buffer returned by nimsodium.
 *
 * Call this for every nimsodium_buffer returned by a successful function,
 * including public data. This keeps ownership rules consistent across
 * language bindings.
 */
void nimsodium_free_buffer(nimsodium_buffer *buffer);

int nimsodium_hash_password(
  const void *password,
  size_t password_len,
  int profile,
  nimsodium_buffer *out_hash
);

int nimsodium_verify_password(
  const void *hash,
  size_t hash_len,
  const void *password,
  size_t password_len,
  int *verified
);

int nimsodium_protect_wallet_secret(
  const void *secret,
  size_t secret_len,
  const void *password,
  size_t password_len,
  const void *label,
  size_t label_len,
  int profile,
  nimsodium_buffer *out_protected
);

int nimsodium_open_protected_wallet_secret(
  const void *protected_secret,
  size_t protected_secret_len,
  const void *password,
  size_t password_len,
  const void *label,
  size_t label_len,
  nimsodium_buffer *out_secret
);

int nimsodium_encrypt_wallet_secret_file(
  const char *input_path,
  const char *output_path,
  const void *password,
  size_t password_len,
  const void *label,
  size_t label_len,
  int profile,
  size_t chunk_size
);

int nimsodium_decrypt_wallet_secret_file(
  const char *input_path,
  const char *output_path,
  const void *password,
  size_t password_len,
  const void *label,
  size_t label_len,
  size_t chunk_size
);

int nimsodium_generate_signing_keypair(
  nimsodium_buffer *out_public_key,
  nimsodium_buffer *out_secret_key
);

int nimsodium_sign_offchain_message(
  const void *message,
  size_t message_len,
  const void *domain,
  size_t domain_len,
  const void *secret_key,
  size_t secret_key_len,
  nimsodium_buffer *out_signature
);

int nimsodium_verify_offchain_message(
  const void *message,
  size_t message_len,
  const void *domain,
  size_t domain_len,
  const void *signature,
  size_t signature_len,
  const void *public_key,
  size_t public_key_len,
  int *verified
);

#ifdef __cplusplus
}
#endif

#endif
