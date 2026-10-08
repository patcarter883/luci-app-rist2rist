/* librist. Copyright © 2026 SipRadius LLC. All right reserved.
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef RIST_CRYPTO_EAP_V4_CRYPTO_H
#define RIST_CRYPTO_EAP_V4_CRYPTO_H

#include "common/attributes.h"
#include "crypto-private.h"
#include <stdint.h>
#include <stddef.h>

/* EAP SHA256-SRP6a Version 4 authenticated passphrase channel primitives:
 * HKDF-Expand-SHA256 (per-direction key derivation) and AES-256-GCM. AEAD/HMAC
 * need a real crypto backend (mbedTLS or Nettle); the built-in fallback returns
 * -1, which the caller treats as "v4 unavailable, negotiate down to v3".
 *
 * All functions return 0 on success and a negative value on error / backend
 * unavailable. */

/* _librist_crypto_secure_zero (best-effort key-material wipe) is provided by
 * crypto-private.h. */

/* RFC 5869 §2.3 HKDF-Expand with SHA-256. PRK is used directly as the HMAC key
 * (K is already a uniformly random 256-bit value, so Extract is unnecessary). */
RIST_PRIV int _librist_crypto_hkdf_expand_sha256(const uint8_t *prk, size_t prk_len,
                                                 const uint8_t *info, size_t info_len,
                                                 uint8_t *okm, size_t okm_len);

/* AES-256-GCM encrypt. key is 32 octets; iv is iv_len octets (12 for v4);
 * tag_len is 16. ct must have room for pt_len octets. */
RIST_PRIV int _librist_crypto_aes_gcm_encrypt(const uint8_t *key, const uint8_t *iv, size_t iv_len,
                                              const uint8_t *aad, size_t aad_len,
                                              const uint8_t *pt, size_t pt_len,
                                              uint8_t *ct, uint8_t *tag, size_t tag_len);

/* AES-256-GCM decrypt with tag verification. Returns 0 only if the tag is valid;
 * on any failure the plaintext buffer is zeroed so a caller can never act on
 * unverified output. */
RIST_PRIV int _librist_crypto_aes_gcm_decrypt(const uint8_t *key, const uint8_t *iv, size_t iv_len,
                                              const uint8_t *aad, size_t aad_len,
                                              const uint8_t *ct, size_t ct_len,
                                              const uint8_t *tag, size_t tag_len,
                                              uint8_t *pt);

#endif
