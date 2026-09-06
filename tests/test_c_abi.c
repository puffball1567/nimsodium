#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nimsodium.h"

static int fail(const char *message) {
  fprintf(stderr, "%s", message);
  const char *err = nimsodium_last_error();
  if (err != NULL && err[0] != '\0') {
    fprintf(stderr, ": %s", err);
  }
  fprintf(stderr, "\n");
  return 1;
}

static int expect_ok(int rc, const char *message) {
  if (rc != 0) {
    return fail(message);
  }
  return 0;
}

static int expect_true(int condition, const char *message) {
  if (!condition) {
    return fail(message);
  }
  return 0;
}

int main(void) {
  if (expect_ok(nimsodium_init(), "init failed")) return 1;
  if (expect_true(
        strcmp(nimsodium_c_abi_version(), "0.1.0") == 0,
        "unexpected C ABI version"
      )) return 1;
  if (expect_true(
        strcmp(nimsodium_package_version(), "0.2.3") == 0,
        "unexpected package version"
      )) return 1;

  const char *libsodium_version = nimsodium_libsodium_version();
  if (expect_true(libsodium_version != NULL, "missing libsodium version")) return 1;
  const char *expected_libsodium = getenv("NIMSODIUM_EXPECTED_LIBSODIUM");
  if (expected_libsodium != NULL && expected_libsodium[0] != '\0') {
    if (expect_true(
          strcmp(libsodium_version, expected_libsodium) == 0,
          "unexpected libsodium version"
        )) return 1;
  }

  const uint8_t password[] = {'p', 'a', 's', 's', 0, 'w', 'o', 'r', 'd'};
  nimsodium_buffer hash = {0};
  if (expect_ok(
        nimsodium_hash_password(
          password,
          sizeof(password),
          NIMSODIUM_PROFILE_INTERACTIVE,
          &hash
        ),
        "hash password failed"
      )) return 1;

  int verified = 0;
  if (expect_ok(
        nimsodium_verify_password(
          hash.data,
          hash.len,
          password,
          sizeof(password),
          &verified
        ),
        "verify password failed"
      )) return 1;
  if (expect_true(verified == 1, "password should verify")) return 1;

  const char wrong_password[] = "wrong";
  if (expect_ok(
        nimsodium_verify_password(
          hash.data,
          hash.len,
          wrong_password,
          strlen(wrong_password),
          &verified
        ),
        "verify wrong password call failed"
      )) return 1;
  if (expect_true(verified == 0, "wrong password should not verify")) return 1;
  nimsodium_free_buffer(&hash);

  const uint8_t secret[] = {'s', 'e', 'e', 'd', 0, 'm', 'a', 't', 'e', 'r', 'i', 'a', 'l'};
  const char label[] = "wallet:primary";
  nimsodium_buffer protected_secret = {0};
  if (expect_ok(
        nimsodium_protect_wallet_secret(
          secret,
          sizeof(secret),
          password,
          sizeof(password),
          label,
          strlen(label),
          NIMSODIUM_PROFILE_INTERACTIVE,
          &protected_secret
        ),
        "protect wallet secret failed"
      )) return 1;

  nimsodium_buffer opened_secret = {0};
  if (expect_ok(
        nimsodium_open_protected_wallet_secret(
          protected_secret.data,
          protected_secret.len,
          password,
          sizeof(password),
          label,
          strlen(label),
          &opened_secret
        ),
        "open protected wallet secret failed"
      )) return 1;
  if (expect_true(opened_secret.len == sizeof(secret), "opened secret length mismatch")) return 1;
  if (expect_true(memcmp(opened_secret.data, secret, sizeof(secret)) == 0, "opened secret mismatch")) return 1;
  nimsodium_free_buffer(&opened_secret);

  const char other_label[] = "wallet:other";
  if (expect_true(
        nimsodium_open_protected_wallet_secret(
          protected_secret.data,
          protected_secret.len,
          password,
          sizeof(password),
          other_label,
          strlen(other_label),
          &opened_secret
        ) != 0,
        "wrong wallet label should fail"
      )) return 1;
  nimsodium_free_buffer(&protected_secret);

  nimsodium_buffer public_key = {0};
  nimsodium_buffer secret_key = {0};
  if (expect_ok(
        nimsodium_generate_signing_keypair(&public_key, &secret_key),
        "generate signing keypair failed"
      )) return 1;
  if (expect_true(public_key.len == NIMSODIUM_SIGNING_PUBLIC_KEY_BYTES, "public key length mismatch")) return 1;
  if (expect_true(secret_key.len == NIMSODIUM_SIGNING_SECRET_KEY_BYTES, "secret key length mismatch")) return 1;

  const char domain[] = "example-wallet";
  const char message[] = "approve payload";
  nimsodium_buffer signature = {0};
  if (expect_ok(
        nimsodium_sign_offchain_message(
          message,
          strlen(message),
          domain,
          strlen(domain),
          secret_key.data,
          secret_key.len,
          &signature
        ),
        "sign offchain message failed"
      )) return 1;
  if (expect_true(signature.len == NIMSODIUM_SIGNATURE_BYTES, "signature length mismatch")) return 1;

  if (expect_ok(
        nimsodium_verify_offchain_message(
          message,
          strlen(message),
          domain,
          strlen(domain),
          signature.data,
          signature.len,
          public_key.data,
          public_key.len,
          &verified
        ),
        "verify offchain message failed"
      )) return 1;
  if (expect_true(verified == 1, "signature should verify")) return 1;

  if (expect_ok(
        nimsodium_verify_offchain_message(
          message,
          strlen(message),
          other_label,
          strlen(other_label),
          signature.data,
          signature.len,
          public_key.data,
          public_key.len,
          &verified
        ),
        "verify wrong domain call failed"
      )) return 1;
  if (expect_true(verified == 0, "wrong domain should not verify")) return 1;

  nimsodium_free_buffer(&signature);
  nimsodium_free_buffer(&public_key);
  nimsodium_free_buffer(&secret_key);
  return 0;
}
