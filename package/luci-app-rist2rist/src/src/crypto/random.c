#include "random.h"
#include "config.h"
#include "log-private.h"

#if HAVE_MBEDTLS
#include <string.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

#include "pthread-shim.h"
#include "vcs_version.h"

#ifdef _WIN32
/* Seed the DRBG from BCryptGenRandom (CNG) directly. The mbedTLS-provided
 * Windows entropy source uses the legacy CryptoAPI which is missing or
 * unconfigured under wine and stripped-down container images (#210); going
 * through f_rng instead of the entropy module also avoids touching any
 * MBEDTLS_PRIVATE() internals on mbedTLS 3.x. */
#include <windows.h>
#include <bcrypt.h>
#ifndef BCRYPT_USE_SYSTEM_PREFERRED_RNG
#define BCRYPT_USE_SYSTEM_PREFERRED_RNG 0x00000002
#endif

static int _librist_bcrypt_f_rng(void *data, unsigned char *output, size_t len)
{
	(void) data;
	NTSTATUS s = BCryptGenRandom(NULL, output, (ULONG) len,
	                             BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	if (s != 0)
		return MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
	return 0;
}
#endif /* _WIN32 */

#ifndef _WIN32
static mbedtls_entropy_context entropy_ctx;
#endif
static mbedtls_ctr_drbg_context ctr_drbg_ctx;
/* 0 once mbedtls_ctr_drbg_seed succeeds; non-zero (the mbedTLS error)
 * if seeding failed and the DRBG context is unusable. Read-only after
 * pthread_once / InitOnce returns. */
static int ctr_drbg_seed_ret = MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;

#if !defined(_WIN32) || HAVE_PTHREADS
//For some reason GNU Hurd complains that PTHREAD_ONCE_INIT isn't a constant
#if defined(__GNU__)
static pthread_once_t entropy_init_once = {__PTHREAD_ONCE_INIT};
#else
static pthread_once_t entropy_init_once = PTHREAD_ONCE_INIT;
#endif
#endif
#if defined(_WIN32) && !HAVE_PTHREADS
static INIT_ONCE entropy_init_once = INIT_ONCE_STATIC_INIT;
#endif


#if HAVE_PTHREADS
static void _librist_crypto_random_init_func(void)
#else
static BOOL WINAPI librist_crypto_srp_init_random_func(PINIT_ONCE InitOnce, PVOID Parameter, PVOID *Context)
#endif
{
#if HAVE_MBEDTLS
	mbedtls_ctr_drbg_init(&ctr_drbg_ctx);
	//ctr_drbg_ctx is threadsafe, so can be used by multiple threads freely, seeding isn't though.
	const char user_custom[] = "libRIST librist_crypto_random_init_func "LIBRIST_VERSION;
#ifdef _WIN32
	ctr_drbg_seed_ret = mbedtls_ctr_drbg_seed(&ctr_drbg_ctx, _librist_bcrypt_f_rng, NULL,
		(const unsigned char *)user_custom, sizeof(user_custom));
#else
	mbedtls_entropy_init(&entropy_ctx);
	ctr_drbg_seed_ret = mbedtls_ctr_drbg_seed(&ctr_drbg_ctx, mbedtls_entropy_func, &entropy_ctx,
		(const unsigned char *)user_custom, sizeof(user_custom));
#endif
	if (ctr_drbg_seed_ret != 0) {
		/* Sandbox / container with no entropy source, missing /dev/urandom,
		 * or a broken mbedTLS build. The DRBG is now unusable; every
		 * subsequent _librist_crypto_ramdom_get_bytes() call will return
		 * the same error rather than silently emitting zeros. */
		rist_log_priv3(RIST_LOG_ERROR,
			"CSPRNG seeding failed (mbedtls_ctr_drbg_seed = -0x%04x); "
			"all crypto-random calls will fail until the entropy source is fixed\n",
			(unsigned)-ctr_drbg_seed_ret);
	}
#endif
#if !HAVE_PTHREADS
	return 1;
#endif
}

static void _librist_crypto_random_init(void) {
#if HAVE_PTHREADS
	pthread_once(&entropy_init_once, _librist_crypto_random_init_func);
#else
	InitOnceExecuteOnce(&entropy_init_once, librist_crypto_srp_init_random_func, NULL, NULL);
#endif
}

#elif HAVE_NETTLE
#include <gnutls/crypto.h>
static void _librist_crypto_random_init(void) {
	return;
}
#endif

int _librist_crypto_ramdom_get_bytes(uint8_t buf[], size_t buflen) {
#if HAVE_MBEDTLS || HAVE_NETTLE
	_librist_crypto_random_init();
	int ret;
#if HAVE_MBEDTLS
	if (ctr_drbg_seed_ret != 0)
		return ctr_drbg_seed_ret;
	ret = mbedtls_ctr_drbg_random(&ctr_drbg_ctx, buf, buflen);
#elif HAVE_NETTLE
	int i=0;
	do {
		ret = gnutls_rnd(GNUTLS_RND_NONCE, buf, buflen);//This call is thread-safe
		i++;
	} while (ret != 0 && i < 10);
	if (ret != 0)
		rist_log_priv3(RIST_LOG_ERROR,
			"CSPRNG (gnutls_rnd) failed %d times in a row, returning %d\n",
			i, ret);
#endif
	return ret;
#else
	(void)buf; (void)buflen;
	return -1;
#endif
}

int _librist_crypto_random_get_string(char buf[], size_t len) {
	// 64 chars to keep the modulo bias-free (power of two)
	static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!?";
	const size_t charset_n = sizeof(charset) - 1;
	uint8_t rand_buf[128];
	if (len > sizeof(rand_buf))
		return -1;
	int ret = _librist_crypto_ramdom_get_bytes(rand_buf, len);
	if (ret != 0)
		return ret;
	for (size_t i = 0; i < len; i++)
		buf[i] = charset[rand_buf[i] % charset_n];
	return 0;
}
