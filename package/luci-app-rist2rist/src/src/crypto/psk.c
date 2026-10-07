/* librist. Copyright © 2020 SipRadius LLC. All right reserved.
 * Author: Gijs Peskens <gijs@in2ip.nl>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "config.h"
#include "psk.h"
#include "log-private.h"
#include "crypto-private.h"
#include "proto/rist_time.h"
#include <string.h>

/* Minimum wall-time between nonce-adoption rekeys (PBKDF2) on one key.
 * Bounds the CPU a packet flood with randomized nonces can burn. The floor
 * is dictated by the reflector topology: a subscriber's single key sees
 * interleaved nonces from the reflector's own RTCP and the forwarded
 * publisher media, so legitimate rekeys arrive at the RTCP cadence
 * (~2 per 100 ms interval); the limit must stay well above that or valid
 * media is dropped. 10 ms still caps a flood at ~100 PBKDF2/s per key. */
#define RIST_REKEY_MIN_INTERVAL (ONE_SECOND / 100)

/* bad_count strikes marking decryption-failure abuse before the decrypt-path
 * rekey rate limit engages; legitimate nonce churn keeps bad_count at 0. */
#define RIST_REKEY_ABUSE_STRIKES 2

#if HAVE_MBEDTLS
#include "mbedtls/aes.h"
#include "mbedtls/md.h"
#include "mbedtls/pkcs5.h"
#elif HAVE_NETTLE
#include <nettle/pbkdf2.h>
#include <nettle/aes.h>
#include <nettle/ctr.h>
#elif defined(LINUX_CRYPTO)
#include "linux-crypto.h"
#endif
#if !HAVE_MBEDTLS
#include "fastpbkdf2.h"
#endif

#ifndef AES_BLOCK_SIZE
#define AES_BLOCK_SIZE 16
#endif

#include <stdint.h>

//TODO: handle failures?
int _librist_crypto_psk_rist_key_init(struct rist_key *key, uint32_t key_size, uint32_t rotation, const char *password, bool odd)
{
	key->password_len = strnlen(password, sizeof(key->password) - 1);
	memcpy(key->password, password, key->password_len);
	key->password[key->password_len] = '\0';
	key->key_size = key_size;
	key->key_rotation = rotation;
#if HAVE_MBEDTLS
	mbedtls_aes_init(&key->mbedtls_aes_ctx);
#elif HAVE_NETTLE
	memset(&key->nettle_ctx, 0, sizeof(key->nettle_ctx));
#elif defined(LINUX_CRYPTO)
	linux_crypto_init(&key->linux_crypto_ctx);
#endif
	key->odd = odd;
	return 0;
}

int _librist_crypto_psk_rist_key_destroy(struct rist_key *key)
{
    if (key->key_size) {
#if HAVE_MBEDTLS
	    mbedtls_aes_free(&key->mbedtls_aes_ctx);
#elif HAVE_NETTLE
	//nothing to do here
#elif defined(LINUX_CRYPTO)
	    linux_crypto_free(&key->linux_crypto_ctx);
#endif
    }
	/* Wipe key material: the peer struct is freed without zeroing. */
	_librist_crypto_secure_zero(key->password, sizeof(key->password));
	_librist_crypto_secure_zero(key->gre_nonce, sizeof(key->gre_nonce));
	_librist_crypto_secure_zero(key->iv, sizeof(key->iv));
	_librist_crypto_secure_zero(key->aes_key_sched, sizeof(key->aes_key_sched));
	return 0;
}

int _librist_crypto_psk_rist_key_clone(struct rist_key *key_in, struct rist_key *key_out)
{
	key_out->password_len = key_in->password_len;
	memcpy(key_out->password, key_in->password, key_in->password_len);
	key_out->password[key_out->password_len] = '\0';
    key_out->key_size = key_in->key_size;
    key_out->key_rotation = key_in->key_rotation;
#if HAVE_MBEDTLS
	mbedtls_aes_init(&key_out->mbedtls_aes_ctx);
#elif HAVE_NETTLE
    memset(&key_out->nettle_ctx, 0, sizeof(key_out->nettle_ctx));
#elif defined(LINUX_CRYPTO)
	linux_crypto_init(&key_out->linux_crypto_ctx);
#endif
	key_out->odd = key_in->odd;
	return 0;
}

static void _librist_crypto_aes_key(struct rist_key *key)
{
    uint8_t aes_key[256 / 8];
    /* Hard invariant: key_size drives the PBKDF2 output length into this
     * 32-byte stack buffer. Anything but a valid AES size here means the
     * value arrived unvalidated from the wire or config; refuse rather
     * than overflow. */
    if (key->key_size != 128 && key->key_size != 192 && key->key_size != 256) {
        key->bad_decryption = true;
        return;
    }
#if HAVE_MBEDTLS
    mbedtls_md_context_t sha_ctx;
    const mbedtls_md_info_t *info_sha;
    int ret = -1;
    mbedtls_md_init(&sha_ctx);
    info_sha = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (info_sha == NULL)
        goto fail;

    ret = mbedtls_md_setup(&sha_ctx, info_sha, 1);
    if (ret != 0)
        goto fail;

    ret = mbedtls_pkcs5_pbkdf2_hmac(
        &sha_ctx, (const unsigned char *)key->password, key->password_len,
        key->gre_nonce, sizeof(key->gre_nonce),
        RIST_PBKDF2_HMAC_SHA256_ITERATIONS, key->key_size / 8, aes_key);
    if (ret != 0)
        goto fail;
    mbedtls_md_free(&sha_ctx);
#elif HAVE_NETTLE
    nettle_pbkdf2_hmac_sha256(key->password_len,(const uint8_t*)key->password,
							  RIST_PBKDF2_HMAC_SHA256_ITERATIONS,
							  sizeof(key->gre_nonce), key->gre_nonce,
							  key->key_size/8, aes_key);
#else
    fastpbkdf2_hmac_sha256(
            (const void *) key->password, key->password_len,
            (const void *) key->gre_nonce, sizeof(key->gre_nonce),
            RIST_PBKDF2_HMAC_SHA256_ITERATIONS,
            aes_key, key->key_size / 8);
#endif


#if HAVE_MBEDTLS
    mbedtls_aes_setkey_enc(&key->mbedtls_aes_ctx, aes_key, key->key_size);
#elif HAVE_NETTLE
	switch(key->key_size) {
	case 256:
        nettle_aes256_set_encrypt_key(&key->nettle_ctx.ctx256, aes_key);
        break;
	case 192:
        nettle_aes192_set_encrypt_key(&key->nettle_ctx.ctx192, aes_key);
        break;
	case 128:
		RIST_FALLTHROUGH;
	default:
		nettle_aes128_set_encrypt_key(&key->nettle_ctx.ctx128, aes_key);
    }
#elif defined(LINUX_CRYPTO)
    if (key->linux_crypto_ctx)
		linux_crypto_set_key(aes_key, key->key_size / 8, key->linux_crypto_ctx);
    else
        aes_key_setup(aes_key, key->aes_key_sched, key->key_size);
#else
    aes_key_setup(aes_key, key->aes_key_sched, key->key_size);
#endif
    key->used_times = 0;
    _librist_crypto_secure_zero(aes_key, sizeof(aes_key));
    return;
#if HAVE_MBEDTLS
fail:
    mbedtls_md_free(&sha_ctx);
    _librist_crypto_secure_zero(aes_key, sizeof(aes_key));
    /* Leave any prior key install in place but force the lockout flag so we
     * don't run AES-CTR with whatever happened to be on the stack. */
    key->bad_decryption = true;
    return;
#endif
}

//This doesn't really belong here (not PSK related), but since all other crypto interop stuff is here it goes in here..
void _librist_crypto_aes_ctr(const uint8_t key[], int key_size, uint8_t iv[], const uint8_t inbuf[], uint8_t outbuf[], size_t payload_len) {
#if HAVE_MBEDTLS
	mbedtls_aes_context ctx;
	mbedtls_aes_init(&ctx);
	mbedtls_aes_setkey_enc(&ctx, key, key_size);
	uint8_t stream_block[AES_BLOCK_SIZE] = {0};
	size_t nc_off = 0;
	mbedtls_aes_crypt_ctr(&ctx, payload_len, &nc_off, iv, stream_block, inbuf, outbuf);
	mbedtls_aes_free(&ctx);
#elif HAVE_NETTLE
    union rist_nettle_aes_ctx aes_ctx;
    memset(&aes_ctx, 0, sizeof(aes_ctx));
    nettle_cipher_func *f;
    switch (key_size) {
    case 256:
		nettle_aes256_set_encrypt_key(&aes_ctx.ctx256, key);
		f = (nettle_cipher_func *)nettle_aes256_encrypt;
		break;
	case 192:
		nettle_aes192_set_encrypt_key(&aes_ctx.ctx192, key);
		f = (nettle_cipher_func *)nettle_aes192_encrypt;
		break;
	case 128:
		nettle_aes128_set_encrypt_key(&aes_ctx.ctx128, key);
		f = (nettle_cipher_func *)nettle_aes128_encrypt;
		break;
	default:
		return;
	}
	nettle_ctr_crypt(&aes_ctx, f, AES_BLOCK_SIZE, iv, payload_len, outbuf, inbuf);
#else
    uint32_t aes_key_sched[60];
    aes_key_setup(key, aes_key_sched, key_size);
    aes_decrypt_ctr(inbuf, payload_len, outbuf, aes_key_sched, key_size, iv);
#endif
}

static void _librist_crypto_psk_aes_ctr(struct rist_key *key, const uint8_t inbuf[], uint8_t outbuf[], size_t payload_len)
{
#if HAVE_MBEDTLS
	mbedtls_aes_crypt_ctr(&key->mbedtls_aes_ctx, payload_len, &key->aes_offset, key->iv, key->strean_block, inbuf, outbuf);
#elif HAVE_NETTLE
	nettle_cipher_func *f;
	switch(key->key_size) {
	case 128:
		f = (nettle_cipher_func *)nettle_aes128_encrypt;
		break;
	case 192:
		f = (nettle_cipher_func *)nettle_aes192_encrypt;
		break;
	case 256:
		f = (nettle_cipher_func *)nettle_aes256_encrypt;
		break;
	default:
		return;
	}
	nettle_ctr_crypt(&key->nettle_ctx, f, AES_BLOCK_SIZE, key->iv,payload_len, outbuf, inbuf);
#elif defined(LINUX_CRYPTO)
	if (key->linux_crypto_ctx)
		linux_crypto_decrypt(inbuf, outbuf, payload_len, key->iv, key->linux_crypto_ctx);
	else
		aes_decrypt_ctr(inbuf, payload_len, outbuf,	key->aes_key_sched, key->key_size, key->iv);
#else
	aes_decrypt_ctr(inbuf, payload_len, outbuf, key->aes_key_sched, key->key_size, key->iv);
#endif
    key->used_times++;
}

static void _librist_crypto_psk_prepare_iv(struct rist_key *key, uint8_t gre_version, uint32_t seq_nbe) {
    /* Prepare AES iv */
    // The byte array needs to be zeroes and then the seq in network byte order
    uint8_t copy_offset = gre_version >= 1 ? 0 : 12;
    memset(key->iv, 0, 16);
    memcpy(key->iv + copy_offset, &seq_nbe, sizeof(seq_nbe));
}

static void _librist_crypto_psk_generate_nonce(struct rist_key *key) {
	/* Fail-closed CSPRNG: on failure, mark the key locked so encrypt/decrypt
	 * short-circuit instead of running AES under a predictable nonce. */
	uint32_t nonce_val = 0;
	for (int attempts = 0; attempts < 8; attempts++) {
		if (_librist_crypto_random_u32(&nonce_val) != 0) {
			rist_log_priv3(RIST_LOG_ERROR,
				"PSK nonce generation: CSPRNG unavailable, "
				"PSK encrypt/decrypt locked out until passphrase rotation\n");
			key->csprng_failed = true;
			key->bad_decryption = true;
			return;
		}
		if (nonce_val != 0)
			break;
	}
	if (nonce_val == 0) {
		/* 8 zeros in a row from a working CSPRNG is 2^-256; treat as malfunction. */
		rist_log_priv3(RIST_LOG_ERROR,
			"PSK nonce generation: CSPRNG returned only zeros, locking out\n");
		key->csprng_failed = true;
		key->bad_decryption = true;
		return;
	}

	memcpy(key->gre_nonce, &nonce_val, sizeof(key->gre_nonce));

    UNSET_BIT(key->gre_nonce[0], 7);
    if (key->odd)
        SET_BIT(key->gre_nonce[0], 7);
}

void _librist_crypto_psk_decrypt(struct rist_key *key, uint8_t nonce[4], uint32_t seq_nbe, uint8_t gre_version, const uint8_t inbuf[], uint8_t outbuf[], size_t payload_len)
{
	uint32_t nonce_val;
	memcpy(&nonce_val, nonce, sizeof(nonce_val));
    /* A zero nonce never comes from a legitimate sender; drop the packet.
     * Do NOT latch bad_decryption here: a zero nonce triggers no PBKDF2,
     * so the latch only served as a one-packet permanent session kill. */
    if (!nonce_val)
        return;

    if (memcmp(nonce, key->gre_nonce, sizeof(key->gre_nonce)) != 0) {
        /* Adopt the new nonce even while locked out: a latch no fresh nonce
         * can clear turns one spoofed packet (or six garbage decryptions)
         * into a permanent session kill and blocks legitimate passphrase
         * rotations. The PBKDF2-CPU-DoS protection the lockout provided
         * becomes a rekey rate limit that engages ONLY under abuse:
         * legitimate nonce churn (rotations, reflector RTCP/media nonce
         * interleave) decrypts cleanly and keeps bad_count at 0, so it is
         * never throttled; a garbage flood pushes bad_count past
         * RIST_REKEY_ABUSE_STRIKES and is throttled to RIST_REKEY_MIN_INTERVAL. */
        uint64_t now = timestampNTP_u64();
        if (key->bad_count > RIST_REKEY_ABUSE_STRIKES && key->last_rekey &&
            (now - key->last_rekey) < RIST_REKEY_MIN_INTERVAL)
            return;
        memcpy(key->gre_nonce, nonce, sizeof(key->gre_nonce));
        _librist_crypto_aes_key(key);
        /* Only clear the flag if _librist_crypto_aes_key succeeded;
         * it sets bad_decryption=true on PBKDF2/setup failure. */
        if (key->bad_decryption)
            return;
        key->bad_count = 0;
        key->last_rekey = now;
    }

    if (key->used_times > RIST_AES_KEY_REUSE_TIMES) {
        key->bad_decryption = true;
        return;
    }

    _librist_crypto_psk_prepare_iv(key, gre_version, seq_nbe);
#if HAVE_MBEDTLS
    key->aes_offset = 0;
#endif
    _librist_crypto_psk_aes_ctr(key, inbuf, outbuf, payload_len);
    return;
}

void _librist_crypto_psk_encrypt(struct rist_key *key, uint32_t seq_nbe, uint8_t gre_version,const uint8_t inbuf[], uint8_t outbuf[], size_t payload_len)
{
    uint32_t nonce_val;
    memcpy(&nonce_val, key->gre_nonce, sizeof(nonce_val));
    if (!nonce_val || (key->used_times +1) > RIST_AES_KEY_REUSE_TIMES || (key->key_rotation > 0 && key->used_times >= key->key_rotation)) {
        _librist_crypto_psk_generate_nonce(key);
        if (key->csprng_failed) {
            memset(outbuf, 0, payload_len);
            return;
        }
        _librist_crypto_aes_key(key);
    }
    if (key->csprng_failed) {
        memset(outbuf, 0, payload_len);
        return;
    }
    _librist_crypto_psk_prepare_iv(key, gre_version, seq_nbe);
#if HAVE_MBEDTLS
    key->aes_offset = 0;
#endif
    _librist_crypto_psk_aes_ctr(key, inbuf, outbuf, payload_len);
    return;
}

int _librist_crypto_psk_set_passphrase(struct rist_key *key, const uint8_t *passsphrase, size_t passphrase_len) {
	if (passphrase_len > sizeof(key->password) -1) {
		return -1;
	}
	if (key->key_size == 0)
		key->key_size = 256;
	memcpy(key->password, passsphrase, passphrase_len);
	key->password_len = passphrase_len;
	key->used_times = 0;
	key->csprng_failed = false; /* fresh passphrase, retry CSPRNG */
	key->bad_decryption = false; /* fresh passphrase: clear any lockout */
	key->bad_count = 0;
	key->last_rekey = 0;
	_librist_crypto_psk_generate_nonce(key);
	_librist_crypto_aes_key(key);
	return 0;
}

void _librist_crypto_psk_get_passphrase(struct rist_key *key, const uint8_t **passphrase, size_t *passphrase_len) {
	*passphrase = key->password;
	*passphrase_len = key->password_len;
}

void _librist_crypto_psk_encrypt_continue(struct rist_key *key, const uint8_t inbuf[], uint8_t outbuf[], size_t payload_len) {
	_librist_crypto_psk_aes_ctr(key, inbuf, outbuf, payload_len);
}

void _librist_crypto_psk_preannounce_nonce(struct rist_key *key, const uint8_t nonce[4], uint32_t key_size_bits) {
	uint32_t nonce_val;
	memcpy(&nonce_val, nonce, sizeof(nonce_val));
	if (!nonce_val)
		return;
	if (memcmp(nonce, key->gre_nonce, sizeof(key->gre_nonce)) == 0)
		return;
	/* key_size_bits comes straight off the wire (Advanced PSK nonce
	 * control message); accept only valid AES sizes. */
	if (key_size_bits) {
		if (key_size_bits != 128 && key_size_bits != 192 && key_size_bits != 256)
			return;
		key->key_size = key_size_bits;
	}
	/* This control message is reachable before authentication and carries no
	 * decrypt outcome, so there is no bad_count abuse signal to gate on (unlike
	 * the decrypt path); keep the flat RIST_REKEY_MIN_INTERVAL rate limit
	 * unconditionally. Preannounce is not in the media hot path, so the flat
	 * floor costs nothing legitimate. */
	uint64_t now = timestampNTP_u64();
	if (key->last_rekey && (now - key->last_rekey) < RIST_REKEY_MIN_INTERVAL)
		return;
	memcpy(key->gre_nonce, nonce, sizeof(key->gre_nonce));
	_librist_crypto_aes_key(key);
	if (!key->bad_decryption) {
		key->bad_count = 0;
		key->last_rekey = now;
	}
}
