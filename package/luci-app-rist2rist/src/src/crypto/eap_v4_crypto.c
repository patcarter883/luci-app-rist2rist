/* librist. Copyright © 2026 SipRadius LLC. All right reserved.
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * EAP SHA256-SRP6a Version 4 authenticated passphrase channel primitives.
 * Self-contained: depends only on the crypto backend (mbedTLS or Nettle) so it
 * can be unit-tested without the rest of librist.
 */

#include "config.h"
#include "eap_v4_crypto.h"
#include <string.h>

#if HAVE_MBEDTLS
#include "mbedtls/md.h"
#include "mbedtls/gcm.h"
#elif HAVE_NETTLE
#include <nettle/hmac.h>
#include <nettle/gcm.h>
#include <nettle/memops.h>
#include <nettle/version.h>

/* nettle 4.0 dropped the length argument from the digest calls, and with it
 * their ability to truncate. Take the whole digest and cut it here so the
 * call sites read the same against either nettle. */
#if NETTLE_VERSION_MAJOR >= 4
static void rist_hmac_sha256_digest(struct hmac_sha256_ctx *ctx, size_t len, uint8_t *out)
{
	uint8_t full[SHA256_DIGEST_SIZE];
	hmac_sha256_digest(ctx, full);
	memcpy(out, full, len < sizeof(full) ? len : sizeof(full));
	_librist_crypto_secure_zero(full, sizeof(full));
}

static void rist_gcm_aes256_digest(struct gcm_aes256_ctx *ctx, size_t len, uint8_t *out)
{
	uint8_t full[GCM_DIGEST_SIZE];
	gcm_aes256_digest(ctx, full);
	memcpy(out, full, len < sizeof(full) ? len : sizeof(full));
}
#else
#define rist_hmac_sha256_digest hmac_sha256_digest
#define rist_gcm_aes256_digest gcm_aes256_digest
#endif
#endif

int _librist_crypto_hkdf_expand_sha256(const uint8_t *prk, size_t prk_len,
									   const uint8_t *info, size_t info_len,
									   uint8_t *okm, size_t okm_len)
{
	const size_t hash_len = 32;
	if (okm_len == 0 || okm_len > 255 * hash_len)
		return -1;
#if HAVE_MBEDTLS
	const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	if (md == NULL)
		return -1;
	mbedtls_md_context_t ctx;
	mbedtls_md_init(&ctx);
	int rc = -1;
	if (mbedtls_md_setup(&ctx, md, 1) != 0)
		goto done;
	uint8_t t[32];
	size_t t_len = 0;
	size_t done_len = 0;
	uint8_t counter = 0;
	while (done_len < okm_len) {
		counter++;
		if (mbedtls_md_hmac_starts(&ctx, prk, prk_len) != 0) goto done;
		if (t_len && mbedtls_md_hmac_update(&ctx, t, t_len) != 0) goto done;
		if (info_len && mbedtls_md_hmac_update(&ctx, info, info_len) != 0) goto done;
		if (mbedtls_md_hmac_update(&ctx, &counter, 1) != 0) goto done;
		if (mbedtls_md_hmac_finish(&ctx, t) != 0) goto done;
		t_len = hash_len;
		size_t n = okm_len - done_len < hash_len ? okm_len - done_len : hash_len;
		memcpy(okm + done_len, t, n);
		done_len += n;
	}
	rc = 0;
done:
	_librist_crypto_secure_zero(t, sizeof(t));
	mbedtls_md_free(&ctx);
	if (rc != 0)
		memset(okm, 0, okm_len);
	return rc;
#elif HAVE_NETTLE
	struct hmac_sha256_ctx ctx;
	hmac_sha256_set_key(&ctx, prk_len, prk);
	uint8_t t[32];
	size_t t_len = 0;
	size_t done_len = 0;
	uint8_t counter = 0;
	while (done_len < okm_len) {
		counter++;
		if (t_len) hmac_sha256_update(&ctx, t_len, t);
		if (info_len) hmac_sha256_update(&ctx, info_len, info);
		hmac_sha256_update(&ctx, 1, &counter);
		rist_hmac_sha256_digest(&ctx, hash_len, t); /* resets to post-set-key state */
		t_len = hash_len;
		size_t n = okm_len - done_len < hash_len ? okm_len - done_len : hash_len;
		memcpy(okm + done_len, t, n);
		done_len += n;
	}
	_librist_crypto_secure_zero(t, sizeof(t));
	_librist_crypto_secure_zero(&ctx, sizeof(ctx));
	return 0;
#else
	(void)prk; (void)prk_len; (void)info; (void)info_len;
	memset(okm, 0, okm_len);
	return -1;
#endif
}

int _librist_crypto_aes_gcm_encrypt(const uint8_t *key, const uint8_t *iv, size_t iv_len,
									const uint8_t *aad, size_t aad_len,
									const uint8_t *pt, size_t pt_len,
									uint8_t *ct, uint8_t *tag, size_t tag_len)
{
#if HAVE_MBEDTLS
	mbedtls_gcm_context ctx;
	mbedtls_gcm_init(&ctx);
	int rc = -1;
	if (mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256) != 0)
		goto done;
	if (mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, pt_len, iv, iv_len,
								  aad, aad_len, pt, ct, tag_len, tag) != 0)
		goto done;
	rc = 0;
done:
	mbedtls_gcm_free(&ctx);
	return rc;
#elif HAVE_NETTLE
	struct gcm_aes256_ctx ctx;
	gcm_aes256_set_key(&ctx, key);
	gcm_aes256_set_iv(&ctx, iv_len, iv);
	if (aad_len)
		gcm_aes256_update(&ctx, aad_len, aad);
	gcm_aes256_encrypt(&ctx, pt_len, ct, pt);
	rist_gcm_aes256_digest(&ctx, tag_len, tag);
	_librist_crypto_secure_zero(&ctx, sizeof(ctx));
	return 0;
#else
	(void)key; (void)iv; (void)iv_len; (void)aad; (void)aad_len;
	(void)pt; (void)pt_len; (void)ct; (void)tag; (void)tag_len;
	return -1;
#endif
}

int _librist_crypto_aes_gcm_decrypt(const uint8_t *key, const uint8_t *iv, size_t iv_len,
									const uint8_t *aad, size_t aad_len,
									const uint8_t *ct, size_t ct_len,
									const uint8_t *tag, size_t tag_len,
									uint8_t *pt)
{
#if HAVE_MBEDTLS
	mbedtls_gcm_context ctx;
	mbedtls_gcm_init(&ctx);
	int rc = -1;
	if (mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256) != 0)
		goto done;
	if (mbedtls_gcm_auth_decrypt(&ctx, ct_len, iv, iv_len, aad, aad_len,
								 tag, tag_len, ct, pt) != 0)
		goto done;
	rc = 0;
done:
	mbedtls_gcm_free(&ctx);
	if (rc != 0 && ct_len)
		memset(pt, 0, ct_len);
	return rc;
#elif HAVE_NETTLE
	struct gcm_aes256_ctx ctx;
	uint8_t local_tag[16];
	if (tag_len > sizeof(local_tag))
		return -1;
	gcm_aes256_set_key(&ctx, key);
	gcm_aes256_set_iv(&ctx, iv_len, iv);
	if (aad_len)
		gcm_aes256_update(&ctx, aad_len, aad);
	gcm_aes256_decrypt(&ctx, ct_len, pt, ct);
	rist_gcm_aes256_digest(&ctx, tag_len, local_tag);
	/* nettle memeql_sec is constant-time; returns 1 when equal. */
	if (memeql_sec(local_tag, tag, tag_len) != 1) {
		if (ct_len)
			memset(pt, 0, ct_len);
		_librist_crypto_secure_zero(&ctx, sizeof(ctx));
		return -1;
	}
	_librist_crypto_secure_zero(&ctx, sizeof(ctx));
	return 0;
#else
	(void)key; (void)iv; (void)iv_len; (void)aad; (void)aad_len;
	(void)ct; (void)tag; (void)tag_len;
	if (ct_len)
		memset(pt, 0, ct_len);
	return -1;
#endif
}
